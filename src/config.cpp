/*
    Copyright © 2017-2025 AO Kaspersky Lab

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Author: Sergey.Belov at kaspersky.com
*/

#include "warn_off.h"
#include <pro.h>
#include <ida.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
#include <config.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "config.h"

config_t cfg;
static const char cfgNodeName[] = "$ hrt options";

static const cfgopt_t opts[] = {
	cfgopt_t("LOGGING_LEVEL", &cfg.logLevel),
	cfgopt_t("DISABLE_AUTORENAME", &cfg.disable_autorename, 1),
	cfgopt_t("MATCHED_BRACE_COLOR", (int*)&cfg.braceBgColor)
// !!! add new config_t fields here in arbitrary order
};

void configLoad()
{
	//load from IDB last used settings made by configDlg
	netnode nn(cfgNodeName);
	if(exist(nn)) {
		uint8 tmp[MAXSPECSIZE];
		CASSERT(sizeof(config_t) < MAXSPECSIZE);
		ssize_t valSize = nn.valobj(tmp, sizeof(config_t));// idb saved by older plugin version may have smaller size of config blob
		if(valSize > 0 && valSize <= sizeof(config_t) && nn.valobj(&cfg, valSize) > 0) {
			Log(llDebug, "config loaded from IDB (%d bytes)\n", valSize);
			return;
		}
	}

	//load user defined defaults from hrtng.cfg file
	if(!read_config_file("hrtng", opts, qnumber(opts), nullptr))
		Log(llWarning, "error on reading config file, use defaults\n");
	else
		Log(llDebug, "config file loaded, logging level %d\n", cfg.logLevel);
}

void configSave()
{
	QASSERT(100111, sizeof(config_t) < MAXSPECSIZE);
	netnode nn(cfgNodeName, 0, true);
	nn.set(&cfg, sizeof(config_t));
	Log(llDebug, "config saved in IDB\n");
}

void configDlg()
{
	qstrvec_t llNames;
	LogLevelNames(&llNames);
	const char format[] =
			//title
			"[hrt] Options\n\n"
			"<Logging level:b:0:>\n"
			"<#-1 to turn highlighting off#Matching brace color:l::8::>\n"
			"<#NOT RECOMMENDED#Disable auto~r~ename:C>>\n"
// !!! add new config_t fields here in arbitrary order
			"\n\n";
	if (1 != ask_form(format, &llNames, &cfg.logLevel, &cfg.braceBgColor, &cfg.disable_autorename))
		return;
	configSave();
}

