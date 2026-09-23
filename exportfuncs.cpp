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

void HUD_Frame(double time)
{
	if (gExportfuncs.HUD_Frame)
		gExportfuncs.HUD_Frame(time);
	IMV_OnFrame();
}
