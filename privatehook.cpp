#include "privatehook.h"
#include "plugins.h"
#include "bsp_parser.h"
#include <stdio.h>
#include <stdarg.h>
#include <string>
#include <set>
#include <unordered_map>

private_funcs_t gPrivateFuncs = {};

#define NET_MAX_PAYLOAD 65536

cvar_t* imv_enabled = nullptr;
cvar_t* imv_log = nullptr;
cvar_t* imv_notify = nullptr;
cvar_t* imv_crc_storage = nullptr;

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

// Engine global net buffer pointers resolved via pattern disassembly
// 8B 0D [imm32: &msg_readcount] -> imm32 is address of int variable msg_readcount
static int* g_pMsgReadCount = nullptr;
// A1 [imm32: &net_message.data] -> imm32 is address of uint8_t* pointer net_message.data
static uint8_t** g_pNetMessageData = nullptr;
static int* g_pNetCursize = nullptr;

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

void IMV_Log(bool printToConsole, const char* fmt, ...)
{
	if (!imv_log)
		return;

	int logType = (int)imv_log->value;
	if (logType <= 0)
		return; // 0: Disabled completely

	char szBuffer[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(szBuffer, sizeof(szBuffer), fmt, args);
	va_end(args);

	if (logType >= 2)
	{
		gEngfuncs.Con_Printf("IMV: %s", szBuffer);
	}
	else if (printToConsole)
	{
		gEngfuncs.Con_Printf("IMV: %s", szBuffer);
	}
	else
	{
		gEngfuncs.Con_DPrintf("IMV: %s", szBuffer);
	}
}

static void NormalizeSlashes(std::string& path)
{
	for (auto& c : path)
	{
		if (c == '\\') c = '/';
		c = (char)tolower((unsigned char)c);
	}
}

static bool IMV_FileExists(const char* pszPath)
{
	if (!pszPath || !pszPath[0])
		return false;

	if (g_pFileSystem_HL25)
		return g_pFileSystem_HL25->FileExists(pszPath);
	if (g_pFileSystem)
		return g_pFileSystem->FileExists(pszPath);

	const char* pszGameDir = g_pMetaHookAPI->GetGameDirectory();
	if (!pszGameDir || !pszGameDir[0]) pszGameDir = "svencoop";
	char szFullPath[MAX_PATH];
	snprintf(szFullPath, sizeof(szFullPath), "%s/%s", pszGameDir, pszPath);
	FILE* test = fopen(szFullPath, "rb");
	if (test) { fclose(test); return true; }
	return false;
}

static std::string GetMapBaseName(const char* pszMapPath)
{
	if (!pszMapPath || !pszMapPath[0])
		return "";

	std::string path = pszMapPath;
	NormalizeSlashes(path);

	size_t lastSlash = path.find_last_of('/');
	if (lastSlash != std::string::npos)
		path = path.substr(lastSlash + 1);

	size_t dot = path.rfind(".bsp");
	if (dot != std::string::npos && dot == path.length() - 4)
		path = path.substr(0, dot);

	return path;
}

static const char* IMV_FindFirst(const char* wildcard, FileFindHandle_t* handle)
{
	if (g_pFileSystem_HL25)
		return g_pFileSystem_HL25->FindFirst(wildcard, handle);
	if (g_pFileSystem)
		return g_pFileSystem->FindFirst(wildcard, handle);
	return nullptr;
}

static const char* IMV_FindNext(FileFindHandle_t handle)
{
	if (g_pFileSystem_HL25)
		return g_pFileSystem_HL25->FindNext(handle);
	if (g_pFileSystem)
		return g_pFileSystem->FindNext(handle);
	return nullptr;
}

static bool IMV_FindIsDirectory(FileFindHandle_t handle)
{
	if (g_pFileSystem_HL25)
		return g_pFileSystem_HL25->FindIsDirectory(handle);
	if (g_pFileSystem)
		return g_pFileSystem->FindIsDirectory(handle);
	return false;
}

static void IMV_FindClose(FileFindHandle_t handle)
{
	if (g_pFileSystem_HL25)
		g_pFileSystem_HL25->FindClose(handle);
	else if (g_pFileSystem)
		g_pFileSystem->FindClose(handle);
}

static FileHandle_t __fastcall Hooked_FS_Open(void* pThis, int edx,
	const char* pFileName, const char* pOptions, const char* pathID)
{
	if (!g_ActiveAliasFrom.empty() && pFileName &&
		!_stricmp(pFileName, g_ActiveAliasFrom.c_str()))
	{
		return g_pfnOrig_FS_Open(pThis, edx, g_ActiveAliasTo.c_str(), pOptions, pathID);
	}
	return g_pfnOrig_FS_Open(pThis, edx, pFileName, pOptions, pathID);
}

static void IMV_EnsureFSOpenHook(void)
{
	if (g_pHookFS_Open)
		return;

	bool bNeedOpenHook = (!g_MapAliases.empty()) || (imv_crc_storage && (int)imv_crc_storage->value > 0);
	if (!bNeedOpenHook)
		return;

	void* pFS = g_pFileSystem ? (void*)g_pFileSystem : (void*)g_pFileSystem_HL25;
	if (pFS)
	{
		g_pHookFS_Open = g_pMetaHookAPI->VFTHook(pFS, 0, 10,
			(void*)Hooked_FS_Open, (void**)&g_pfnOrig_FS_Open);

		if (g_pHookFS_Open)
			IMV_Log(false, "IFileSystem::Open hook installed.\n");
	}
}

static void Hooked_svc_serverinfo(void)
{
	g_bServerInfoActive = true;
	g_ServerMapCRC = 0;

	// Clear previous map alias
	g_ActiveAliasFrom.clear();
	g_ActiveAliasTo.clear();

	if (g_pMsgReadCount && g_pNetMessageData && g_pNetCursize)
	{
		__try
		{
			if (*g_pNetMessageData)
			{
				int readCount = *g_pMsgReadCount;
				int messageSize = *g_pNetCursize;

				if (messageSize >= 0 && messageSize <= NET_MAX_PAYLOAD &&
					readCount >= 0 && readCount <= messageSize - 12)
				{
					const uint8_t* pPayload = (*g_pNetMessageData) + readCount;

					// svc_serverinfo payload starts with:
					// int32_t protocol
					// int32_t servernumber
					// uint32_t mapcrc
					g_ServerMapCRC = *reinterpret_cast<const uint32_t*>(pPayload + 8);
					IMV_Log(false, "svc_serverinfo: extracted server Map CRC = 0x%08X\n", g_ServerMapCRC);
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

	// Experimental: apply map name alias or CRC-based storage resolution before CRC computation
	const char* effectiveName = pszMapName;
	std::string aliasedPath;
	bool bStorageCandidateApplied = false;

	if (g_bServerInfoActive && pszMapName && pszMapName[0])
	{
		// 1. Check static aliases.txt first
		if (!g_MapAliases.empty())
		{
			std::string serverPath = pszMapName;
			NormalizeSlashes(serverPath);

			auto it = g_MapAliases.find(serverPath);
			if (it != g_MapAliases.end())
			{
				aliasedPath = it->second;
				if (IMV_FileExists(aliasedPath.c_str()))
				{
					IMV_EnsureFSOpenHook();
					g_ActiveAliasFrom = pszMapName;
					g_ActiveAliasTo   = aliasedPath;
					effectiveName     = aliasedPath.c_str();
				IMV_Log(true, "Using map alias '%s' -> '%s'.\n", pszMapName, effectiveName);
				}
				else
				{
					IMV_Log(true, "Map alias target '%s' not found, ignoring alias.\n", aliasedPath.c_str());
					aliasedPath.clear();
				}
			}
		}

		// 2. If no static alias matched, try CRC-based storage: maps/<basename>_%08x.bsp (if enabled)
		if (aliasedPath.empty() && g_ServerMapCRC != 0 && (!imv_crc_storage || (int)imv_crc_storage->value > 0))
		{
			std::string baseName = GetMapBaseName(pszMapName);
			if (!baseName.empty())
			{
				char szCandidate[MAX_PATH];
				// Clean format: maps/<base>_%08x.bsp (lowercase and uppercase)
				snprintf(szCandidate, sizeof(szCandidate), "maps/%s_%08x.bsp", baseName.c_str(), g_ServerMapCRC);
				if (!IMV_FileExists(szCandidate))
					snprintf(szCandidate, sizeof(szCandidate), "maps/%s_%08X.bsp", baseName.c_str(), g_ServerMapCRC);

				// Fallback to legacy maps/<base>_crc%08x.bsp
				if (!IMV_FileExists(szCandidate))
					snprintf(szCandidate, sizeof(szCandidate), "maps/%s_crc%08x.bsp", baseName.c_str(), g_ServerMapCRC);
				if (!IMV_FileExists(szCandidate))
					snprintf(szCandidate, sizeof(szCandidate), "maps/%s_crc%08X.bsp", baseName.c_str(), g_ServerMapCRC);

				if (IMV_FileExists(szCandidate))
				{
					IMV_EnsureFSOpenHook();
					aliasedPath = szCandidate;
					g_ActiveAliasFrom = pszMapName;
					g_ActiveAliasTo   = aliasedPath;
					effectiveName     = aliasedPath.c_str();
					bStorageCandidateApplied = true;
					IMV_Log(true, "Using CRC map '%s' -> '%s'.\n", pszMapName, effectiveName);
				}
			}
		}
	}

	int result = gPrivateFuncs.CRC_MapFile(ulCRC, effectiveName);

	// If a storage candidate was used, verify its actual CRC matches server expectation
	if (bStorageCandidateApplied && (!result || !ulCRC || *ulCRC != g_ServerMapCRC))
	{
		if (result && ulCRC)
		{
			IMV_Log(true, "CRC storage candidate '%s' has CRC 0x%08X, expected 0x%08X (mismatch). Aborting alias.\n",
				effectiveName, *ulCRC, g_ServerMapCRC);
		}
		else
		{
			IMV_Log(true, "CRC storage candidate '%s' could not be read. Aborting alias.\n", effectiveName);
		}
		g_ActiveAliasFrom.clear();
		g_ActiveAliasTo.clear();
		effectiveName = pszMapName;
		result = gPrivateFuncs.CRC_MapFile(ulCRC, effectiveName);
	}

	if (!result || !ulCRC)
	{
		g_ActiveAliasFrom.clear();
		g_ActiveAliasTo.clear();
		g_bServerInfoActive = false;
		return result;
	}

	// Gate by active svc_serverinfo handshake and valid server CRC to prevent stale override
	if (!g_bServerInfoActive || g_ServerMapCRC == 0)
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

	if (!imv_enabled || (int)imv_enabled->value <= 0)
	{
		g_LastCheck.action = "Mismatch (Disabled)";
		IMV_Log(true, "Mismatch detected for '%s' (Client: 0x%08X, Server: 0x%08X). Plugin disabled.\n",
			pMap, clientCRC, g_ServerMapCRC);
		return result;
	}

	// Validate BSP file structure to prevent hard crashes on corrupted files
	BSPValidationResult val = ValidateBSPFile(pMap);
	if (val.verdict != BSPSafetyVerdict::Valid)
	{
		g_LastCheck.action = std::string("Mismatch (Rejected: ") + GetBSPSafetyVerdictString(val.verdict) + ")";
		IMV_Log(true, "BSP check rejected '%s': %s. Aborting override to prevent crash.\n",
			pMap, GetBSPSafetyVerdictString(val.verdict));
		return result;
	}

	// Apply override
	*ulCRC = g_ServerMapCRC;
	g_LastCheck.action = "Mismatch (Override Applied)";

	if (imv_notify && (int)imv_notify->value > 0)
	{
		gEngfuncs.Con_Printf("IMV: Warning: Map CRC mismatch overridden for '%s' (client 0x%08X, server 0x%08X). Map desynchronization is possible.\n",
			pMap, clientCRC, g_ServerMapCRC);

		g_bPendingNotify = true;
		g_PendingNotifyMap = pMap;
	}
	else
	{
		IMV_Log(true, "Mismatch overridden for '%s': Client=0x%08X -> Server=0x%08X\n",
			pMap, clientCRC, g_ServerMapCRC);
	}

	return result;
}

void Command_Status(void)
{
	bool bEnabled = (imv_enabled && (int)imv_enabled->value > 0);

	int logType = imv_log ? (int)imv_log->value : 1;
	const char* pszLog = "Standard";
	if (logType <= 0) pszLog = "Off";
	else if (logType >= 2) pszLog = "Verbose";

	const char* pArg = gEngfuncs.Cmd_Argv(1);
	bool bShowDebug = (pArg && (!_stricmp(pArg, "debug") || !_stricmp(pArg, "dev"))) || (GetDeveloperLevel() >= 1);

	if (bShowDebug)
		gEngfuncs.Con_Printf("\n============ [IgnoreMapVersion v%s (Debug)] ============\n", PLUGIN_VERSION);
	else
		gEngfuncs.Con_Printf("\n================ [IgnoreMapVersion v%s] ================\n", PLUGIN_VERSION);

	gEngfuncs.Con_Printf("  Status       : %s\n", bEnabled ? "Active" : "Disabled");
	gEngfuncs.Con_Printf("  Log Level    : %s\n", pszLog);
	gEngfuncs.Con_Printf("  CRC Storage  : %s\n", (imv_crc_storage && (int)imv_crc_storage->value > 0) ? "Enabled" : "Disabled");
	gEngfuncs.Con_Printf("  Notify Alert : %s\n", (imv_notify && (int)imv_notify->value > 0) ? "YES" : "NO");

	if (!g_MapAliases.empty() || !g_ActiveAliasFrom.empty())
	{
		gEngfuncs.Con_Printf("\n  Map Aliases  : %d loaded\n", (int)g_MapAliases.size());
		for (const auto& pair : g_MapAliases)
		{
			gEngfuncs.Con_Printf("    '%s' -> '%s'\n", pair.first.c_str(), pair.second.c_str());
		}
		if (!g_ActiveAliasFrom.empty())
		{
			gEngfuncs.Con_Printf("  Active Alias : '%s' -> '%s'\n",
				g_ActiveAliasFrom.c_str(), g_ActiveAliasTo.c_str());
		}
	}

	gEngfuncs.Con_Printf("\n  Last Map Check:\n");
	if (g_LastCheck.mapName.empty())
	{
		gEngfuncs.Con_Printf("    (no map checks performed in this session)\n");
	}
	else
	{
		gEngfuncs.Con_Printf("    Map Name   : %s\n", g_LastCheck.mapName.c_str());
		gEngfuncs.Con_Printf("    Client CRC : 0x%08X\n", g_LastCheck.clientCRC);
		gEngfuncs.Con_Printf("    Server CRC : 0x%08X\n", g_LastCheck.serverCRC);
		gEngfuncs.Con_Printf("    Action     : %s\n", g_LastCheck.action.c_str());
	}

	if (bShowDebug)
	{
		gEngfuncs.Con_Printf("\n  [Debug Diagnostics]:\n");
		gEngfuncs.Con_Printf("    Engine Build : %u\n", g_dwEngineBuildnum);
		gEngfuncs.Con_Printf("    CRC_MapFile  : %s (RVA 0x%X)\n", g_bCRCMapFileHooked ? "HOOKED" : "NOT HOOKED", g_CandidateCRCMapFileRVA);
		gEngfuncs.Con_Printf("    ServerInfo   : %s\n", gPrivateFuncs.Orig_svc_serverinfo ? "HOOKED" : "NOT HOOKED");
		gEngfuncs.Con_Printf("    FS_Open Hook : %s\n", g_pHookFS_Open ? "ACTIVE" : "NOT INSTALLED");
		gEngfuncs.Con_Printf("    Net Pointers : readcount=%p, data=%p, cursize=%p\n",
			(void*)g_pMsgReadCount, (void*)g_pNetMessageData, (void*)g_pNetCursize);
	}
	gEngfuncs.Con_Printf("==========================================================\n\n");
}

void Command_CRC(void)
{
	const char* pszMapArg = gEngfuncs.Cmd_Argv(1);
	std::string mapPath;

	if (pszMapArg && pszMapArg[0])
	{
		mapPath = pszMapArg;
		NormalizeSlashes(mapPath);
		if (mapPath.find('/') == std::string::npos)
			mapPath = "maps/" + mapPath;
		if (mapPath.length() < 4 || mapPath.substr(mapPath.length() - 4) != ".bsp")
			mapPath += ".bsp";
	}
	else
	{
		if (!g_ActiveAliasTo.empty())
		{
			mapPath = g_ActiveAliasTo;
		}
		else if (gEngfuncs.pfnGetLevelName)
		{
			const char* pszLevel = gEngfuncs.pfnGetLevelName();
			if (pszLevel && pszLevel[0])
				mapPath = pszLevel;
		}
	}

	if (mapPath.empty())
	{
		gEngfuncs.Con_Printf("Usage: imv_crc <mapname>\nExample: imv_crc rust\n");
		return;
	}

	if (!gPrivateFuncs.CRC_MapFile)
	{
		gEngfuncs.Con_Printf("IMV: CRC_MapFile is not available.\n");
		return;
	}

	const std::string baseName = GetMapBaseName(mapPath.c_str());
	if (baseName.empty())
	{
		gEngfuncs.Con_Printf("IMV: Invalid map name.\n");
		return;
	}
	const std::string wildcard = "maps/" + baseName + "*.bsp";
	std::set<std::string> variants;
	variants.insert(mapPath);

	FileFindHandle_t findHandle = FILESYSTEM_INVALID_FIND_HANDLE;
	const char* foundName = IMV_FindFirst(wildcard.c_str(), &findHandle);
	while (foundName)
	{
		if (!IMV_FindIsDirectory(findHandle))
		{
			std::string candidate = foundName;
			for (char& c : candidate)
			{
				if (c == '\\') c = '/';
			}
			if (candidate.find('/') == std::string::npos)
				candidate = "maps/" + candidate;

			NormalizeSlashes(candidate);
			const std::string& normalizedCandidate = candidate;
			const size_t slash = normalizedCandidate.find_last_of('/');
			const std::string filename = normalizedCandidate.substr(slash == std::string::npos ? 0 : slash + 1);
			const size_t extension = filename.rfind(".bsp");
			if (extension != std::string::npos && extension == filename.length() - 4)
			{
				const std::string stem = filename.substr(0, extension);
				if (stem == baseName || (stem.size() > baseName.size() &&
					stem.compare(0, baseName.size(), baseName) == 0 && stem[baseName.size()] == '_'))
				{
					variants.insert(normalizedCandidate);
				}
			}
		}
		foundName = IMV_FindNext(findHandle);
	}
	if (findHandle != FILESYSTEM_INVALID_FIND_HANDLE)
		IMV_FindClose(findHandle);

	gEngfuncs.Con_Printf("\nIMV: Map CRC variants for '%s'\n", mapPath.c_str());
	uint32_t requestedCRC = 0;
	bool requestedCRCFound = false;
	for (const std::string& variant : variants)
	{
		uint32_t variantCRC = 0;
		const int variantResult = gPrivateFuncs.CRC_MapFile(&variantCRC, variant.c_str());
		if (variantResult)
		{
			gEngfuncs.Con_Printf("  0x%08X  %s\n", variantCRC, variant.c_str());
			if (variant == mapPath)
			{
				requestedCRC = variantCRC;
				requestedCRCFound = true;
			}
		}
		else
			gEngfuncs.Con_Printf("  unreadable  %s\n", variant.c_str());
	}

	if (requestedCRCFound)
		gEngfuncs.Con_Printf("IMV: CRC storage name for the requested file: maps/%s_%08x.bsp\n\n", baseName.c_str(), requestedCRC);
	else
		gEngfuncs.Con_Printf("IMV: The requested map could not be read by the engine.\n\n");
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
		// Format: "local_path" "server_path"
		// e.g. "maps/insecure01a.bsp"  "maps/insecure_01a.bsp"
		pParse = FILESYSTEM_ANY_PARSEFILE(pParse, token, &wasquoted);
		if (!pParse || !token[0]) break;
		std::string localPath = token;

		pParse = FILESYSTEM_ANY_PARSEFILE(pParse, token, &wasquoted);
		if (!pParse || !token[0])
		{
			IMV_Log(true, "aliases.txt: unpaired entry '%s' at end of file, skipped.\n", localPath.c_str());
			break;
		}
		std::string serverPath = token;

		NormalizeSlashes(localPath);
		NormalizeSlashes(serverPath);

		if (localPath == serverPath)
		{
			IMV_Log(false, "aliases.txt: alias '%s' -> '%s' is a no-op, skipped.\n", localPath.c_str(), serverPath.c_str());
			continue;
		}

		// key = server path (what engine looks up), value = local path (what to open)
		g_MapAliases[std::move(serverPath)] = std::move(localPath);
	}

	delete[] pBuf;

	if (!g_MapAliases.empty())
	{
			IMV_Log(false, "Loaded %d map alias(es) from '%s'.\n", (int)g_MapAliases.size(), szPath);
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
	imv_notify = gEngfuncs.pfnRegisterVariable("imv_notify", "1", FCVAR_ARCHIVE | FCVAR_CLIENTDLL);
	imv_crc_storage = gEngfuncs.pfnRegisterVariable("imv_crc_storage", "1", FCVAR_ARCHIVE | FCVAR_CLIENTDLL);

	gEngfuncs.pfnAddCommand("imv_status", Command_Status);
	gEngfuncs.pfnAddCommand("imv_crc", Command_CRC);

	IMV_LoadAliases();

	// Experimental: VFT hook on IFileSystem::Open for map name aliasing and CRC-based map storage
	IMV_EnsureFSOpenHook();
}

void IMV_OnFrame(void)
{
	if (!g_bPendingNotify)
		return;
	if (!imv_notify || (int)imv_notify->value <= 0)
	{
		g_bPendingNotify = false;
		return;
	}
	if (!gEngfuncs.pfnCenterPrint)
	{
		g_bPendingNotify = false;
		return;
	}

	char szNotify[256];
	snprintf(szNotify, sizeof(szNotify), "IMV: Warning: Map CRC mismatch overridden for '%s'.\nLocal map version differs from the server.", g_PendingNotifyMap.c_str());
	gEngfuncs.pfnCenterPrint(szNotify);
	g_bPendingNotify = false;
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
	g_pMsgReadCount = nullptr;
	g_pNetMessageData = nullptr;
	g_pNetCursize = nullptr;

	// 1. Primary: Verified RVA 0x41940 for Sven Co-op 5.26 (build 10257) from svenint gamedata
	const ULONG_PTR knownRVA = 0x41940;
	if (RealDllInfo.ImageSize > knownRVA + sizeof(sig_CRC_MapFile))
	{
		uint8_t* pKnown = (uint8_t*)RealDllInfo.ImageBase + knownRVA;
		if (MatchesCRCMapFilePattern(pKnown))
		{
			gPrivateFuncs.CRC_MapFile = reinterpret_cast<decltype(gPrivateFuncs.CRC_MapFile)>(pKnown);
			g_CandidateCRCMapFileRVA = static_cast<uint32_t>(knownRVA);
			IMV_Log(false, "CRC_MapFile found at RVA 0x%X.\n", g_CandidateCRCMapFileRVA);
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
				IMV_Log(false, "CRC_MapFile found by pattern scan at RVA 0x%X.\n", g_CandidateCRCMapFileRVA);
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
		if (pNetCursizeReal && IsEngineDataPointer(pNetCursizeReal, RealDllInfo) &&
			IsEngineDataPointer(pNetCursizeReal - 8, RealDllInfo))
		{
			// In sizebuf_t, offsetof(cursize) == 16, offsetof(data) == 8.
			// Therefore, pointer to 'data' member (uint8_t*) is at (pNetCursizeReal - 8).
			g_pNetMessageData = reinterpret_cast<uint8_t**>(pNetCursizeReal - 8);
			g_pNetCursize = reinterpret_cast<int*>(pNetCursizeReal);
		}
		else
		{
			IMV_Log(true, "net_message pointer %p is outside engine data bounds.\n", pNetCursizeReal ? pNetCursizeReal - 8 : nullptr);
		}

		IMV_Log(false, "Network message pointers: readcount=%p, data=%p, cursize=%p.\n",
			g_pMsgReadCount, g_pNetMessageData, g_pNetCursize);
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
