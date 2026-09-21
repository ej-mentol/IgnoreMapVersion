#include <metahook.h>
#include "exportfuncs.h"
#include "plugins.h"
#include "privatehook.h"

void HUD_Init(void)
{
	if (gExportfuncs.HUD_Init)
	{
		gExportfuncs.HUD_Init();
	}
	IMV_OnInit();
}

int HUD_VidInit(void)
{
	int result = 0;
	if (gExportfuncs.HUD_VidInit)
	{
		result = gExportfuncs.HUD_VidInit();
	}
	IMV_OnVidInit();
	return result;
}
