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
bool deinline(mbl_array_t *mba);
void deinline_reset(ea_t entry_ea);
void deinline_reset(vdui_t *vu, bool closeWnd);
bool hasInlines(vdui_t *vu, bool* bEnabled);
bool is_nlib_inline(vdui_t *vu);
bool ren_inline(vdui_t *vu);
void XXable_inlines(ea_t entry_ea, bool bDisable);
int  deinline_hint(vdui_t *vu, qstring *result_hint, int *implines);
bool inl_create_from_whole_mba(mbl_array_t *mba, const char* name, qstring* errorStr);
void selection2inline(ea_t bgn, ea_t end);
int  deinline_hint(vdui_t *vu, qstring *result_hint, int *implines);
void save_inlines();
void deinline_init();
void deinline_done();

//set the same maturity used in gen_microcode and in deinline(mba) call at hxe_glbopt -- MMAT_GLBOPT1, MMAT_GLBOPT2.
//Care about code may be thrown away by optimization as not used outside snippet
#define DEINLINE_MATURITY MMAT_GLBOPT2
#define MIN_LEN_OF_1_BLOCK_INLINE 8
