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

#include "config.h"

config_t cfg;
static const char cfgNodeName[] = "$ hrt options";

static const cfgopt_t opts[] = {
	cfgopt_t("DISABLE_AUTORENAME", &cfg.disable_autorename, 1)
// !!! add new config_t fields here in arbitrary order
};

void configLoad()
{
	//load from IDB last used settings made by configDlg
	netnode nn(cfgNodeName);
	if(exist(nn) && nn.valobj(&cfg, sizeof(config_t)) > 0)
		return;

	//load user defined defaults from hrtng.cfg file
	if(!read_config_file("hrtng", opts, qnumber(opts), nullptr))
		msg("[hrt] error on reading config file, use defaults\n");
}

void configSave()
{
	QASSERT(100111, sizeof(config_t) < MAXSPECSIZE);
	netnode nn(cfgNodeName, 0, true);
	nn.set(&cfg, sizeof(config_t));
}

void configDlg()
{
	const char format[] =
			//title
			"[hrt] Options\n\n"
			"<#NOT RECOMMENDED#Disable auto~r~ename:C>>\n"
// !!! add new config_t fields here in arbitrary order
			"\n\n";
	if (1 != ask_form(format, &cfg.disable_autorename))
		return;
	configSave();
}

