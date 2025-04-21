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
void convert_offsetof_n_reincasts(cfunc_t *cfunc);
bool can_be_reincast(vdui_t *vu);
bool is_reincast(vdui_t *vu);
void reincast_reg_act();
void reincast_unreg_act();

#if IDA_SDK_VERSION <= 730
extern void convert_negative_offset_casts(cfunc_t *cfunc);
bool can_be_n_recast(vdui_t *vu);
bool is_n_recast(vdui_t *vu);
void ncast_reg_act();
void ncast_unreg_act();
#endif // IDA_SDK_VERSION <= 730

