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
bool decrypt_string(vdui_t *vu, ea_t dec_ea, const char* inBuf, int64 hint_len, ushort *itSz, qstring* result, bool immConst = false);
bool decr_init(int64 *itCnt, ushort *itSz);
bool decr_string_4appcall(ea_t dec_ea, const char *inBuf, int64 len, ea_t keyEa, size_t keyLen, qstring *result, qstring *error);
