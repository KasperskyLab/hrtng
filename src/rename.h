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
void autorename_n_pull_comments(cfunc_t *cfunc);
bool getExpName(cfunc_t *func, cexpr_t* exp, qstring* name, bool derefPtr = false);
bool getVarName(lvar_t * var, qstring* name);
bool getUdtMembName(tinfo_t udt, uint32 offset, qstring* name);
bool renameExp(ea_t refea, cfunc_t *func, cexpr_t* exp, qstring* name, vdui_t *vdui = NULL, bool derefPtr = false);
bool renameVar(ea_t refea, cfunc_t *func, ssize_t varIdx, const qstring* name, vdui_t *vdui = NULL); //vdui->rename_lvar can rebuild all internal structures/ call later!!!
bool renameEa(ea_t refea, ea_t ea, const qstring* name);
bool isIdaInternalComment(const char* comment);
