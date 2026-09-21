#pragma once

#include <metahook.h>
#include <cvardef.h>

extern cl_exportfuncs_t gExportfuncs;
extern cl_enginefunc_t gEngfuncs;

extern mh_interface_t* g_pInterface;
extern metahook_api_t* g_pMetaHookAPI;
extern mh_enginesave_t* g_pMetaSave;
extern IFileSystem* g_pFileSystem;
extern IFileSystem_HL25* g_pFileSystem_HL25;

extern int g_iEngineType;
extern DWORD g_dwEngineBuildnum;

extern mh_dll_info_t g_EngineDLLInfo;
extern mh_dll_info_t g_MirrorEngineDLLInfo;

#define PLUGIN_VERSION "0.0.1"

int GetDeveloperLevel();
PVOID ConvertDllInfoSpace(PVOID addr, const mh_dll_info_t& SrcDllInfo, const mh_dll_info_t& TargetDllInfo);
