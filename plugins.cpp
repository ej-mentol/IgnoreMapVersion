#include <metahook.h>
#include "plugins.h"
#include "exportfuncs.h"
#include "privatehook.h"

cl_exportfuncs_t gExportfuncs = { 0 };
cl_enginefunc_t gEngfuncs = { 0 };

mh_interface_t* g_pInterface = nullptr;
metahook_api_t* g_pMetaHookAPI = nullptr;
mh_enginesave_t* g_pMetaSave = nullptr;
IFileSystem* g_pFileSystem = nullptr;
IFileSystem_HL25* g_pFileSystem_HL25 = nullptr;

int g_iEngineType = 0;
DWORD g_dwEngineBuildnum = 0;

mh_dll_info_t g_EngineDLLInfo = { 0 };
mh_dll_info_t g_MirrorEngineDLLInfo = { 0 };

PVOID ConvertDllInfoSpace(PVOID addr, const mh_dll_info_t& SrcDllInfo, const mh_dll_info_t& TargetDllInfo)
{
	if ((ULONG_PTR)addr >= (ULONG_PTR)SrcDllInfo.ImageBase && (ULONG_PTR)addr < (ULONG_PTR)SrcDllInfo.ImageBase + SrcDllInfo.ImageSize)
	{
		auto addr_RVA = (ULONG_PTR)addr - (ULONG_PTR)SrcDllInfo.ImageBase;
		return (PVOID)((ULONG_PTR)TargetDllInfo.ImageBase + addr_RVA);
	}

	return addr;
}

void IPluginsV4::Init(metahook_api_t *pMetaHookAPI, mh_interface_t *pMetaInterface, mh_enginesave_t *pMetaSave)
{
	g_pInterface = pMetaInterface;
	g_pMetaHookAPI = pMetaHookAPI;
	g_pMetaSave = pMetaSave;
}

void IPluginsV4::Shutdown(void)
{
}

void IPluginsV4::LoadEngine(cl_enginefunc_t *pEngineFuncs)
{
	g_pFileSystem = g_pInterface->FileSystem;
	if (!g_pFileSystem)
	{
		g_pFileSystem_HL25 = g_pInterface->FileSystem_HL25;
	}

	g_iEngineType = g_pMetaHookAPI->GetEngineType();
	g_dwEngineBuildnum = g_pMetaHookAPI->GetEngineBuildnum();

	g_EngineDLLInfo.ImageBase = g_pMetaHookAPI->GetEngineBase();
	g_EngineDLLInfo.ImageSize = g_pMetaHookAPI->GetEngineSize();
	g_EngineDLLInfo.TextBase = g_pMetaHookAPI->GetSectionByName(g_EngineDLLInfo.ImageBase, ".text\x0\x0\x0", &g_EngineDLLInfo.TextSize);
	g_EngineDLLInfo.DataBase = g_pMetaHookAPI->GetSectionByName(g_EngineDLLInfo.ImageBase, ".data\x0\x0\x0", &g_EngineDLLInfo.DataSize);
	g_EngineDLLInfo.RdataBase = g_pMetaHookAPI->GetSectionByName(g_EngineDLLInfo.ImageBase, ".rdata\x0\x0", &g_EngineDLLInfo.RdataSize);

	g_MirrorEngineDLLInfo.ImageBase = g_pMetaHookAPI->GetMirrorEngineBase();
	g_MirrorEngineDLLInfo.ImageSize = g_pMetaHookAPI->GetMirrorEngineSize();

	if (g_MirrorEngineDLLInfo.ImageBase)
	{
		g_MirrorEngineDLLInfo.TextBase = g_pMetaHookAPI->GetSectionByName(g_MirrorEngineDLLInfo.ImageBase, ".text\x0\x0\x0", &g_MirrorEngineDLLInfo.TextSize);
		g_MirrorEngineDLLInfo.DataBase = g_pMetaHookAPI->GetSectionByName(g_MirrorEngineDLLInfo.ImageBase, ".data\x0\x0\x0", &g_MirrorEngineDLLInfo.DataSize);
		g_MirrorEngineDLLInfo.RdataBase = g_pMetaHookAPI->GetSectionByName(g_MirrorEngineDLLInfo.ImageBase, ".rdata\x0\x0", &g_MirrorEngineDLLInfo.RdataSize);
	}

	memcpy(&gEngfuncs, pEngineFuncs, sizeof(gEngfuncs));

	Engine_FillAddress(g_MirrorEngineDLLInfo.ImageBase ? g_MirrorEngineDLLInfo : g_EngineDLLInfo, g_EngineDLLInfo);
	Engine_InstallHooks();
}

void IPluginsV4::LoadClient(cl_exportfuncs_t *pExportFuncs)
{
	memcpy(&gExportfuncs, pExportFuncs, sizeof(gExportfuncs));

	pExportFuncs->HUD_Init = HUD_Init;
	pExportFuncs->HUD_VidInit = HUD_VidInit;
}

void IPluginsV4::ExitGame(int iResult)
{
	Engine_UninstallHooks();
}

const char *IPluginsV4::GetVersion(void)
{
	return "IgnoreMapVersion " PLUGIN_VERSION;
}

EXPOSE_SINGLE_INTERFACE(IPluginsV4, IPluginsV4, METAHOOK_PLUGIN_API_VERSION_V4);
