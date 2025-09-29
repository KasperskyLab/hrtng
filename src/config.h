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

#pragma once

#ifdef _MSC_VER
# pragma pack(push,1)
#else
# pragma pack(1)
#endif
#ifdef __GNUC__
# define ATTR_PACKED(al) __attribute__((__packed__)) __attribute__((__aligned__(al)))
#else
# define ATTR_PACKED(al)
#endif

struct config_t {
	// !!! here must be only simple scalar types inside because it saved/restored as a binary blob
	// !!! types of members must be compatible with types used by `ask_form` API
	ushort disable_autorename = 0;
	ushort unused = 0; //next checkboxes group may be inserted here
	int logLevel = llNotice;
	int64 align = 0; // new field(s) with zero default value may be put here
	int64 braceBgColor = 0x7f7f7fLL; //aligned to offset 0x10 to keep default value when part of config_t is overwritten by older struct version loading
	// !!! add new fields to the end of the struct to keep backward compatibility
	// !!! search "add new config_t fields" comment in `config.cpp`
} ATTR_PACKED(16);

#ifdef _MSC_VER
# pragma pack(pop)
#else
# pragma pack()
#endif

extern config_t cfg;

void configLoad();
void configDlg();

