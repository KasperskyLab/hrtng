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
void msig_reg_act();
void msig_unreg_act();
void msig_auto_load();
void msig_auto_save();
const char* msig_match(mbl_array_t* mba);
const char* msig_cached(ea_t ea);
extern const char msigMessage[];
bool isMsig(vdui_t *vu, qstring* name);

// returns new name; empty string to refuse renaming
typedef qstring msig_rename_cb_t(void* ctx, const char* name);
uint32 msig_rename(msig_rename_cb_t* cb, void* ctx);
