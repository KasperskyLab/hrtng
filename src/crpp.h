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
typedef bool (*decr_proc_t)(uint8_t *data, size_t len, const uint8_t *key, size_t keyLen, const uint8_t *IV, size_t IVlen, std::string &err);
bool sosemanuk(uint8_t *data, size_t len, const uint8 *key, size_t keyLen, const uint8_t *IV, size_t IVlen, std::string &err);
bool chacha(uint8_t *data, size_t len, const uint8_t *key, size_t keyLen, const uint8_t *IV, size_t IVlen, std::string &err);
bool salsa(uint8_t *data, size_t len, const uint8_t *key, size_t keyLen, const uint8_t *IV, size_t IVlen, std::string &err);
bool des_decr(uint8_t *out, const uint8_t *in, size_t len, const uint8_t *key, std::string &err);
bool aes_decr(uint8_t* data, size_t len, const uint8_t* key, size_t keylen, const uint8_t* iv, bool isCBCMode, std::string &err);
bool tea_decr(uint8_t* data, size_t len, const uint8_t* key, size_t keylen, const uint8_t* iv, bool CBCMode, bool bXtea, std::string &err);
bool rc4(uint8_t* data, size_t len, const uint8_t* key, size_t keylen, std::string &err);
