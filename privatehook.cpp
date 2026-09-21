#include "privatehook.h"
#include "plugins.h"
#include "bsp_parser.h"
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <unordered_map>

private_funcs_t gPrivateFuncs = {};

#define NET_MAX_PAYLOAD 65536

cvar_t* imv_enabled = nullptr;
cvar_t* imv_log = nullptr;
cvar_t* imv_log_mode = nullptr;
cvar_t* imv_safety_level = nullptr;
cvar_t* imv_notify = nullptr;

static hook_t* g_pHookCRC_MapFile = nullptr;
static uint32_t g_ServerMapCRC = 0;
static bool g_bServerInfoActive = false;
static bool g_bPendingNotify = false;
static std::string g_PendingNotifyMap;

// Experimental: map name aliasing
static std::unordered_map<std::string, std::string> g_MapAliases;
static std::string g_ActiveAliasFrom;
static std::string g_ActiveAliasTo;

// IFileSystem::Open VFT hook for alias redirect
typedef FileHandle_t(__fastcall* fn_FS_Open_t)(void*, int, const char*, const char*, const char*);
static fn_FS_Open_t g_pfnOrig_FS_Open = nullptr;
static hook_t* g_pHookFS_Open = nullptr;

static uint32_t g_CandidateCRCMapFileRVA = 0;
static bool g_bCRCMapFileHooked = false;

// Session telemetry counters
static int g_SessionMismatchCount = 0;
static int g_SessionOverrideCount = 0;

// Engine global net buffer pointers resolved via pattern disassembly
// 8B 0D [imm32: &msg_readcount] -> imm32 is address of int variable msg_readcount
static int* g_pMsgReadCount = nullptr;
// A1 [imm32: &net_message.data] -> imm32 is address of uint8_t* pointer net_message.data
static uint8_t** g_pNetMessageData = nullptr;

struct IMVLastCheck
{
	std::string mapName;
	uint32_t clientCRC = 0;
	uint32_t serverCRC = 0;
	std::string action = "None";
};

static IMVLastCheck g_LastCheck;

int GetDeveloperLevel()
{
	if (gEngfuncs.pfnGetCvarFloat)
	{
		return (int)gEngfuncs.pfnGetCvarFloat("developer");
	}
	return 0;
}

void IMV_Log(bool isMismatch, const char* fmt, ...)
{
	if (!imv_log)
		return;

	int logType = (int)imv_log->value;
	if (logType <= 0)
		return;

	if (imv_log_mode && (int)imv_log_mode->value == 1 && !isMismatch)
		return;

	if (logType == 1 && GetDeveloperLevel() < 1)
		return;

	char szBuffer[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(szBuffer, sizeof(szBuffer), fmt, args);
	va_end(args);

	if (logType == 1)
	{
		gEngfuncs.Con_DPrintf("[IMV] %s", szBuffer);
	}
	else
	{
		gEngfuncs.Con_Printf("[IMV] %s", szBuffer);
	}
}

static std::string ExtractMapBaseName(const char* pszMapPath)
{
	if (!pszMapPath || !pszMapPath[0])
		return "";

	std::string path = pszMapPath;

	size_t lastSlash = path.find_last_of("/\\");
	if (lastSlash != std::string::npos)
		path = path.substr(lastSlash + 1);

	size_t dot = path.rfind(".bsp");
	if (dot != std::string::npos && dot == path.length() - 4)
		path = path.substr(0, dot);

	for (auto& c : path)
		c = (char)tolower((unsigned char)c);

	return path;
}

static FileHandle_t __fastcall Hooked_FS_Open(void* pThis, int edx,
	const char* pFileName, const char* pOptions, const char* pathID)
{
	if (!g_ActiveAliasFrom.empty() && pFileName &&
		!_stricmp(pFileName, g_ActiveAliasFrom.c_str()))
	{
		IMV_Log(true, "Alias redirect: '%s' -> '%s'\n", pFileName, g_ActiveAliasTo.c_str());
		return g_pfnOrig_FS_Open(pThis, edx, g_ActiveAliasTo.c_str(), pOptions, pathID);
	}
	return g_pfnOrig_FS_Open(pThis, edx, pFileName, pOptions, pathID);
}

static void Hooked_svc_serverinfo(void)
{
	g_bServerInfoActive = true;
	g_ServerMapCRC = 0;

	// Clear previous map alias
	g_ActiveAliasFrom.clear();
	g_ActiveAliasTo.clear();

	if (g_pMsgReadCount && g_pNetMessageData)
	{
		__try
		{
			if (*g_pNetMessageData)
			{
				int readCount = *g_pMsgReadCount;

				// Bounds check against max buffer length (65536) to prevent out-of-bounds read on truncated packet
				if (readCount >= 0 && readCount + 12 <= NET_MAX_PAYLOAD)
				{
					const uint8_t* pPayload = (*g_pNetMessageData) + readCount;

					// svc_serverinfo payload starts with:
					// int32_t protocol
					// int32_t servernumber
					// uint32_t mapcrc
					g_ServerMapCRC = *reinterpret_cast<const uint32_t*>(pPayload + 8);
					IMV_Log(true, "svc_serverinfo: extracted server Map CRC = 0x%08X (readCount=%d)\n", g_ServerMapCRC, readCount);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			g_ServerMapCRC = 0;
			IMV_Log(true, "svc_serverinfo: exception reading net_message payload (handled safely).\n");
		}
	}

	if (gPrivateFuncs.Orig_svc_serverinfo)
	{
		gPrivateFuncs.Orig_svc_serverinfo();
	}

	g_bServerInfoActive = false;
	g_ServerMapCRC = 0;
}

static int __cdecl Hooked_CRC_MapFile(uint32_t *ulCRC, const char *pszMapName)
{
	if (!gPrivateFuncs.CRC_MapFile)
		return 0;

	// Experimental: apply map name alias before CRC computation
	const char* effectiveName = pszMapName;
	std::string aliasedPath;

	if (g_bServerInfoActive && pszMapName && pszMapName[0] && !g_MapAliases.empty())
	{
		std::string baseName = ExtractMapBaseName(pszMapName);
		auto it = g_MapAliases.find(baseName);
		if (it != g_MapAliases.end())
		{
			aliasedPath = "maps/" + it->second + ".bsp";
			g_ActiveAliasFrom = pszMapName;
			g_ActiveAliasTo = aliasedPath;
			effectiveName = aliasedPath.c_str();
			IMV_Log(true, "Map alias applied: '%s' -> '%s'\n", pszMapName, effectiveName);
		}
	}

	int result = gPrivateFuncs.CRC_MapFile(ulCRC, effectiveName);

	// Gate by active svc_serverinfo handshake and valid server CRC to prevent stale override
	if (!g_bServerInfoActive || g_ServerMapCRC == 0 || !ulCRC)
		return result;

	// Reset handshake flag now that map check for this serverinfo has executed
	g_bServerInfoActive = false;

	uint32_t clientCRC = *ulCRC;
	const char* pMap = (effectiveName && effectiveName[0]) ? effectiveName : "(unknown)";

	g_LastCheck.mapName = pMap;
	g_LastCheck.clientCRC = clientCRC;
	g_LastCheck.serverCRC = g_ServerMapCRC;

	if (clientCRC == g_ServerMapCRC)
	{
		g_LastCheck.action = "CRC Matched";
		IMV_Log(false, "Map check passed: '%s' (CRC: 0x%08X)\n", pMap, clientCRC);
		return result;
	}

	// Mismatch branch
	g_SessionMismatchCount++;

	if (!imv_enabled || (int)imv_enabled->value <= 0)
	{
		g_LastCheck.action = "Mismatch (Disabled)";
		IMV_Log(true, "Mismatch detected for '%s' (Client: 0x%08X, Server: 0x%08X). Plugin disabled.\n",
			pMap, clientCRC, g_ServerMapCRC);
		return result;
	}

	int safetyLevel = imv_safety_level ? (int)imv_safety_level->value : 1;

	if (safetyLevel == 2) // Audit only
	{
		g_LastCheck.action = "Mismatch (Audit Only)";
		IMV_Log(true, "Mismatch detected for '%s' (Client: 0x%08X, Server: 0x%08X). Audit only, no override.\n",
			pMap, clientCRC, g_ServerMapCRC);
		return result;
	}
	else if (safetyLevel == 0) // Force mode - skip validation
	{
		IMV_Log(true, "Warning: Safety level is Force (0). Bypassing BSP validation for '%s'. Desync or crash risk!\n", pMap);
	}
	else if (safetyLevel == 1) // Safe validation
	{
		BSPValidationResult val = ValidateBSPFile(pMap);
		if (val.verdict != BSPSafetyVerdict::Valid)
		{
			g_LastCheck.action = std::string("Mismatch (Rejected: ") + GetBSPSafetyVerdictString(val.verdict) + ")";
			IMV_Log(true, "Safety check rejected '%s': %s. Aborting override to prevent crash.\n",
				pMap, GetBSPSafetyVerdictString(val.verdict));
			return result;
		}
	}

	// Apply override
	*ulCRC = g_ServerMapCRC;
	g_SessionOverrideCount++;
	g_LastCheck.action = "Mismatch (Override Applied)";

	IMV_Log(true, "Mismatch overridden for '%s': Client=0x%08X -> Server=0x%08X\n",
		pMap, clientCRC, g_ServerMapCRC);

	if (imv_notify && (int)imv_notify->value > 0)
	{
		gEngfuncs.Con_Printf("[IMV] WARNING: Map CRC mismatch overridden for '%s' (Client: 0x%08X, Server: 0x%08X). Potential desync risk!\n",
			pMap, clientCRC, g_ServerMapCRC);

		g_bPendingNotify = true;
		g_PendingNotifyMap = pMap;
	}

	return result;
}

void Command_Status(void)
{
	gEngfuncs.Con_Printf("\n==================== [IgnoreMapVersion Status] ====================\n");
	gEngfuncs.Con_Printf("  Plugin Version : %s\n", PLUGIN_VERSION);
	gEngfuncs.Con_Printf("  Engine Build   : %u\n", g_dwEngineBuildnum);
	gEngfuncs.Con_Printf("  Enabled        : %s\n", (imv_enabled && (int)imv_enabled->value > 0) ? "YES" : "NO");

	if (g_bCRCMapFileHooked)
	{
		gEngfuncs.Con_Printf("  CRC_MapFile    : HOOKED (Active at RVA 0x%X)\n", g_CandidateCRCMapFileRVA);
	}
	else
	{
		gEngfuncs.Con_Printf("  CRC_MapFile    : NOT HOOKED\n");
	}
	gEngfuncs.Con_Printf("  svc_serverinfo : %s\n", gPrivateFuncs.Orig_svc_serverinfo ? "HOOKED" : "NOT HOOKED");

	int safety = imv_safety_level ? (int)imv_safety_level->value : 1;
	const char* pszSafety = "Safe (1)";
	if (safety == 0) pszSafety = "Force (0)";
	else if (safety == 2) pszSafety = "Audit Only (2)";
	gEngfuncs.Con_Printf("  Safety Level   : %s\n", pszSafety);

	int logType = imv_log ? (int)imv_log->value : 1;
	const char* pszLog = "Developer Only (1)";
	if (logType == 0) pszLog = "Off (0)";
	else if (logType == 2) pszLog = "Console (2)";
	gEngfuncs.Con_Printf("  Log Target     : %s\n", pszLog);

	int logMode = imv_log_mode ? (int)imv_log_mode->value : 1;
	gEngfuncs.Con_Printf("  Log Mode       : %s\n", logMode == 0 ? "Always (0)" : "Only Diff (1)");

	gEngfuncs.Con_Printf("  Notify Alert   : %s\n", (imv_notify && (int)imv_notify->value > 0) ? "YES" : "NO");

	if (!g_MapAliases.empty())
	{
		gEngfuncs.Con_Printf("\n  Map Aliases (Experimental): %d loaded\n", (int)g_MapAliases.size());
		for (const auto& pair : g_MapAliases)
		{
			gEngfuncs.Con_Printf("    '%s' -> '%s'\n", pair.first.c_str(), pair.second.c_str());
		}
		if (!g_ActiveAliasFrom.empty())
		{
			gEngfuncs.Con_Printf("  Active Alias   : '%s' -> '%s'\n",
				g_ActiveAliasFrom.c_str(), g_ActiveAliasTo.c_str());
		}
		gEngfuncs.Con_Printf("  FS_Open Hook   : %s\n", g_pHookFS_Open ? "ACTIVE" : "NOT INSTALLED");
	}

	gEngfuncs.Con_Printf("\n  Session Telemetry:\n");
	gEngfuncs.Con_Printf("    Mismatches   : %d\n", g_SessionMismatchCount);
	gEngfuncs.Con_Printf("    Overrides    : %d\n", g_SessionOverrideCount);

	gEngfuncs.Con_Printf("\n  Last Map Check:\n");
	gEngfuncs.Con_Printf("    Map Name     : %s\n", g_LastCheck.mapName.empty() ? "(none)" : g_LastCheck.mapName.c_str());
	gEngfuncs.Con_Printf("    Client CRC   : 0x%08X\n", g_LastCheck.clientCRC);
	gEngfuncs.Con_Printf("    Server CRC   : 0x%08X\n", g_LastCheck.serverCRC);
	gEngfuncs.Con_Printf("    Action       : %s\n", g_LastCheck.action.c_str());
	gEngfuncs.Con_Printf("===================================================================\n\n");
}

void Command_Reset(void)
{
	g_LastCheck.mapName.clear();
	g_LastCheck.clientCRC = 0;
	g_LastCheck.serverCRC = 0;
	g_LastCheck.action = "None";

	g_SessionMismatchCount = 0;
	g_SessionOverrideCount = 0;
	g_bPendingNotify = false;
	g_PendingNotifyMap.clear();

	gEngfuncs.Con_Printf("[IMV] Session telemetry and last check data have been reset.\n");
}

void IMV_LoadAliases()
{
	g_MapAliases.clear();

	const char* pszGameDir = g_pMetaHookAPI->GetGameDirectory();
	if (!pszGameDir || !pszGameDir[0])
		pszGameDir = "svencoop";

	char szPath[MAX_PATH];
	snprintf(szPath, sizeof(szPath), "%s/ignoremapversion/aliases.txt", pszGameDir);

	FILE* fp = fopen(szPath, "rb");
	if (!fp)
		return;

	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (size <= 0 || size > NET_MAX_PAYLOAD)
	{
		fclose(fp);
		return;
	}

	char* pBuf = new char[size + 1];
	fread(pBuf, 1, size, fp);
	fclose(fp);
	pBuf[size] = 0;

	char token[MAX_PATH];
	bool wasquoted = false;
	char* pParse = pBuf;

	while (pParse && *pParse)
	{
		pParse = FILESYSTEM_ANY_PARSEFILE(pParse, token, &wasquoted);
		if (!pParse || !token[0]) break;
		std::string key = token;

		pParse = FILESYSTEM_ANY_PARSEFILE(pParse, token, &wasquoted);
		if (!pParse || !token[0]) break;
		std::string value = token;

		for (auto& c : key)
			c = (char)tolower((unsigned char)c);
		for (auto& c : value)
			c = (char)tolower((unsigned char)c);

		g_MapAliases[std::move(key)] = std::move(value);
	}

	delete[] pBuf;

	if (!g_MapAliases.empty())
	{
		IMV_Log(true, "Loaded %d map alias(es) from '%s'\n", (int)g_MapAliases.size(), szPath);
	}
}

void IMV_OnInit(void)
{
	static bool s_bInitialized = false;
	if (s_bInitialized)
		return;
	s_bInitialized = true;

	imv_enabled = gEngfuncs.pfnRegisterVariable("imv_enabled", "1", FCVAR_ARCHIVE | FCVAR_CLIENTDLL);
	imv_log = gEngfuncs.pfnRegisterVariable("imv_log", "1", FCVAR_ARCHIVE | FCVAR_CLIENTDLL);
	imv_log_mode = gEngfuncs.pfnRegisterVariable("imv_log_mode", "1", FCVAR_ARCHIVE | FCVAR_CLIENTDLL);
	imv_safety_level = gEngfuncs.pfnRegisterVariable("imv_safety_level", "1", FCVAR_ARCHIVE | FCVAR_CLIENTDLL);
	imv_notify = gEngfuncs.pfnRegisterVariable("imv_notify", "1", FCVAR_ARCHIVE | FCVAR_CLIENTDLL);

	gEngfuncs.pfnAddCommand("imv_status", Command_Status);
	gEngfuncs.pfnAddCommand("imv_reset", Command_Reset);

	IMV_LoadAliases();

	// Experimental: VFT hook on IFileSystem::Open for map name aliasing
	if (!g_MapAliases.empty())
	{
		void* pFS = g_pFileSystem ? (void*)g_pFileSystem : (void*)g_pFileSystem_HL25;
		if (pFS)
		{
			g_pHookFS_Open = g_pMetaHookAPI->VFTHook(pFS, 0, 10,
				(void*)Hooked_FS_Open, (void**)&g_pfnOrig_FS_Open);

			if (g_pHookFS_Open)
				IMV_Log(true, "IFileSystem::Open VFT hook installed for map aliasing.\n");
		}
	}
}

void IMV_OnVidInit(void)
{
	if (g_bPendingNotify && imv_notify && (int)imv_notify->value > 0)
	{
		if (gEngfuncs.pfnCenterPrint)
		{
			char szNotify[256];
			snprintf(szNotify, sizeof(szNotify), "[IMV] Warning: Map CRC mismatch overridden for '%s'!\nLocal map version differs from server.", g_PendingNotifyMap.c_str());
			gEngfuncs.pfnCenterPrint(szNotify);
		}
		g_bPendingNotify = false;
	}
}

// Verified 20-byte pattern from svenint for CRC_MapFile
static const char sig_CRC_MapFile[] = "\x81\xEC\x2A\x2A\x2A\x2A\xA1\x2A\x2A\x2A\x2A\x33\xC4\x89\x84\x24\x84\x04\x00\x00";

static bool MatchesCRCMapFilePattern(const void* addr)
{
	if (!addr)
		return false;

	const uint8_t* p = (const uint8_t*)addr;
	return (p[0] == 0x81 && p[1] == 0xEC &&
	        p[6] == 0xA1 &&
	        p[11] == 0x33 && p[12] == 0xC4 &&
	        p[13] == 0x89 && p[14] == 0x84 && p[15] == 0x24 &&
	        p[16] == 0x84 && p[17] == 0x04 && p[18] == 0x00 && p[19] == 0x00);
}

static bool IsEngineDataPointer(const void* p, const mh_dll_info_t& info)
{
	if (!p)
		return false;

	const ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(p);

	if (info.DataBase && info.DataSize)
	{
		const ULONG_PTR start = reinterpret_cast<ULONG_PTR>(info.DataBase);
		const ULONG_PTR end = start + info.DataSize;
		if (addr >= start && addr < end)
			return true;
	}

	if (info.RdataBase && info.RdataSize)
	{
		const ULONG_PTR start = reinterpret_cast<ULONG_PTR>(info.RdataBase);
		const ULONG_PTR end = start + info.RdataSize;
		if (addr >= start && addr < end)
			return true;
	}

	if (info.ImageBase && info.ImageSize)
	{
		const ULONG_PTR start = reinterpret_cast<ULONG_PTR>(info.ImageBase);
		const ULONG_PTR end = start + info.ImageSize;
		if (addr >= start && addr < end)
			return true;
	}

	return false;
}

void Engine_FillAddress(const mh_dll_info_t& DllInfo, const mh_dll_info_t& RealDllInfo)
{
	gPrivateFuncs.CRC_MapFile = nullptr;
	g_CandidateCRCMapFileRVA = 0;

	// 1. Primary: Verified RVA 0x41940 for Sven Co-op 5.26 (build 10257) from svenint gamedata
	const ULONG_PTR knownRVA = 0x41940;
	if (RealDllInfo.ImageSize > knownRVA + sizeof(sig_CRC_MapFile))
	{
		uint8_t* pKnown = (uint8_t*)RealDllInfo.ImageBase + knownRVA;
		if (MatchesCRCMapFilePattern(pKnown))
		{
			gPrivateFuncs.CRC_MapFile = reinterpret_cast<decltype(gPrivateFuncs.CRC_MapFile)>(pKnown);
			g_CandidateCRCMapFileRVA = static_cast<uint32_t>(knownRVA);
			IMV_Log(true, "CRC_MapFile resolved at verified RVA 0x%X (pattern matched).\n", g_CandidateCRCMapFileRVA);
		}
	}

	// 2. Secondary: Pattern scan across .text
	if (!gPrivateFuncs.CRC_MapFile && DllInfo.TextBase && DllInfo.TextSize)
	{
		void* pfnCRC = g_pMetaHookAPI->SearchPattern(DllInfo.TextBase, DllInfo.TextSize, sig_CRC_MapFile, sizeof(sig_CRC_MapFile) - 1);
		if (pfnCRC)
		{
			auto pResolved = (decltype(gPrivateFuncs.CRC_MapFile))ConvertDllInfoSpace(pfnCRC, DllInfo, RealDllInfo);
			if (MatchesCRCMapFilePattern(pResolved))
			{
				ULONG_PTR rva = (ULONG_PTR)pResolved - (ULONG_PTR)RealDllInfo.ImageBase;
				gPrivateFuncs.CRC_MapFile = pResolved;
				g_CandidateCRCMapFileRVA = static_cast<uint32_t>(rva);
				IMV_Log(true, "CRC_MapFile resolved via pattern scan (RVA: 0x%X).\n", g_CandidateCRCMapFileRVA);
			}
		}
	}

	if (!gPrivateFuncs.CRC_MapFile)
	{
		IMV_Log(true, "CRC_MapFile pattern not found in engine (build: %u). Hook disabled safely.\n", g_dwEngineBuildnum);
	}

	// 3. Resolve net_message and msg_readcount pointers directly via MSG_ReadByte signature
	// 8B 0D [imm32: &msg_readcount] 8D 51 01 3B 15 [imm32: &net_message.cursize] 7E
	const char sig_MSG_ReadByte[] = "\x8B\x0D\x2A\x2A\x2A\x2A\x8D\x51\x01\x3B\x15\x2A\x2A\x2A\x2A\x7E";
	uint8_t* pMSG_ReadByte = (uint8_t*)g_pMetaHookAPI->SearchPattern(DllInfo.TextBase, DllInfo.TextSize, sig_MSG_ReadByte, sizeof(sig_MSG_ReadByte) - 1);

	if (pMSG_ReadByte)
	{
		uint8_t* pMsgReadCountImm = *reinterpret_cast<uint8_t**>(pMSG_ReadByte + 2);
		int* pMsgReadCount = (int*)ConvertDllInfoSpace(pMsgReadCountImm, DllInfo, RealDllInfo);
		if (IsEngineDataPointer(pMsgReadCount, RealDllInfo))
		{
			g_pMsgReadCount = pMsgReadCount;
		}
		else
		{
			IMV_Log(true, "msg_readcount pointer %p is outside engine data bounds.\n", pMsgReadCount);
		}

		uint8_t* pNetCursizeImm = *reinterpret_cast<uint8_t**>(pMSG_ReadByte + 11);
		uint8_t* pNetCursizeReal = (uint8_t*)ConvertDllInfoSpace(pNetCursizeImm, DllInfo, RealDllInfo);
		if (pNetCursizeReal && IsEngineDataPointer(pNetCursizeReal - 8, RealDllInfo))
		{
			// In sizebuf_t, offsetof(cursize) == 16, offsetof(data) == 8.
			// Therefore, pointer to 'data' member (uint8_t*) is at (pNetCursizeReal - 8).
			g_pNetMessageData = reinterpret_cast<uint8_t**>(pNetCursizeReal - 8);
		}
		else
		{
			IMV_Log(true, "net_message.data pointer %p is outside engine data bounds.\n", pNetCursizeReal ? pNetCursizeReal - 8 : nullptr);
		}

		IMV_Log(true, "Network message pointers resolved: msg_readcount=%p, net_message.data=%p\n",
			g_pMsgReadCount, g_pNetMessageData);
	}
	else
	{
		IMV_Log(true, "Failed to locate signature for MSG_ReadByte in engine (build: %u).\n", g_dwEngineBuildnum);
	}
}

void Engine_InstallHooks()
{
	if (gPrivateFuncs.CRC_MapFile)
	{
		g_pHookCRC_MapFile = g_pMetaHookAPI->InlineHook(
			reinterpret_cast<void*>(gPrivateFuncs.CRC_MapFile),
			reinterpret_cast<void*>(Hooked_CRC_MapFile),
			reinterpret_cast<void**>(&gPrivateFuncs.CRC_MapFile));
		g_bCRCMapFileHooked = (g_pHookCRC_MapFile != nullptr);
	}
	else
	{
		g_pHookCRC_MapFile = nullptr;
		g_bCRCMapFileHooked = false;
	}

	fn_parsefunc pfnServerInfo = g_pMetaHookAPI->HookCLParseFuncByName("svc_serverinfo", Hooked_svc_serverinfo);
	if (!pfnServerInfo)
	{
		pfnServerInfo = g_pMetaHookAPI->HookCLParseFuncByOpcode(11, Hooked_svc_serverinfo);
	}

	if (pfnServerInfo)
	{
		gPrivateFuncs.Orig_svc_serverinfo = pfnServerInfo;
	}
	else
	{
		IMV_Log(true, "Failed to hook parsefunc for svc_serverinfo (by name or opcode 11, build: %u).\n", g_dwEngineBuildnum);
	}

}

void Engine_UninstallHooks()
{
	if (g_pHookFS_Open)
	{
		g_pMetaHookAPI->UnHook(g_pHookFS_Open);
		g_pHookFS_Open = nullptr;
		g_pfnOrig_FS_Open = nullptr;
	}

	if (g_pHookCRC_MapFile)
	{
		g_pMetaHookAPI->UnHook(g_pHookCRC_MapFile);
		g_pHookCRC_MapFile = nullptr;
		g_bCRCMapFileHooked = false;
	}

	if (gPrivateFuncs.Orig_svc_serverinfo)
	{
		if (!g_pMetaHookAPI->HookCLParseFuncByName("svc_serverinfo", gPrivateFuncs.Orig_svc_serverinfo))
		{
			g_pMetaHookAPI->HookCLParseFuncByOpcode(11, gPrivateFuncs.Orig_svc_serverinfo);
		}
		gPrivateFuncs.Orig_svc_serverinfo = nullptr;
	}
}
