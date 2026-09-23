#pragma once

#include <metahook.h>
#include <cvardef.h>
#include <stdint.h>
#include <unordered_map>
#include <string>

struct private_funcs_t
{
	int (__cdecl *CRC_MapFile)(uint32_t *ulCRC, const char *pszMapName);
	fn_parsefunc Orig_svc_serverinfo;
};

extern private_funcs_t gPrivateFuncs;

extern cvar_t* imv_enabled;
extern cvar_t* imv_log;
extern cvar_t* imv_notify;
extern cvar_t* imv_crc_storage;

void Engine_FillAddress(const mh_dll_info_t& DllInfo, const mh_dll_info_t& RealDllInfo);
void Engine_InstallHooks();
void Engine_UninstallHooks();

void Command_Status();
void Command_CRC();
void IMV_OnInit();
void IMV_OnFrame();
void IMV_Log(bool printToConsole, const char* fmt, ...);
void IMV_LoadAliases();
