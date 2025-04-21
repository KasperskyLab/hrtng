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

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/cryptlib.h"
#include "cryptopp/modes.h"
#include "cryptopp/arc4.h"
#include "cryptopp/aes.h"
#include "cryptopp/tea.h"
#include "cryptopp/sosemanuk.h"
#include "cryptopp/chacha.h"
#include "cryptopp/salsa.h"
#include "cryptopp/des.h"

bool rc4(uint8_t* data, size_t len, const uint8_t* key, size_t keylen, std::string &err)
{
	try {
		CryptoPP::Weak::ARC4 dec;
		dec.SetKey(key, keylen);
		dec.ProcessData(data, data, len);
		return true;
	}	catch (CryptoPP::Exception& e) {
		err = e.what();
		return false;
	}
}

bool aes_decr(uint8_t* data, size_t len, const uint8_t* key, size_t keylen, const uint8_t* iv, bool CBCMode, std::string &err)
{
	try {
		if(CBCMode) {
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec(key, keylen, iv);
			dec.ProcessData(data, data, len);
		} else {
			CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec(key, keylen);
			dec.ProcessData(data, data, len);
		}
		return true;
	}	catch (CryptoPP::Exception& e) {
		err = e.what();
		return false;
	}
}

bool tea_decr(uint8_t* data, size_t len, const uint8_t* key, size_t keylen, const uint8_t* iv, bool CBCMode, bool bXtea, std::string &err)
{
	try {
		if(bXtea) {
			if(CBCMode) {
				CryptoPP::CBC_Mode<CryptoPP::XTEA>::Decryption dec(key, keylen, iv);
				dec.ProcessData(data, data, len);
			} else {
				CryptoPP::ECB_Mode<CryptoPP::XTEA>::Decryption dec(key, keylen);
				dec.ProcessData(data, data, len);
			}
		} else {
			if(CBCMode) {
				CryptoPP::CBC_Mode<CryptoPP::TEA>::Decryption dec(key, keylen, iv);
				dec.ProcessData(data, data, len);
			} else {
				CryptoPP::ECB_Mode<CryptoPP::TEA>::Decryption dec(key, keylen);
				dec.ProcessData(data, data, len);
			}
		}
		return true;
	}	catch (CryptoPP::Exception& e) {
		err = e.what();
		return false;
	}
}

bool sosemanuk(uint8_t *data, size_t len, const uint8_t *key, size_t keyLen, const uint8_t *IV, size_t IVlen, std::string &err)
{
	try {
		CryptoPP::Sosemanuk::Decryption dec;
		dec.SetKeyWithIV(key, keyLen, IV, IVlen);
		dec.ProcessData(data, data, len);
		return true;
	} catch(CryptoPP::Exception &e) {
		err = e.what();
		return false;
	}
}

bool chacha(uint8_t *data, size_t len, const uint8_t *key, size_t keyLen, const uint8_t *IV, size_t IVlen, std::string &err)
{
	try {
		CryptoPP::ChaCha::Decryption dec;
		dec.SetKeyWithIV(key, keyLen, IV, IVlen);
		dec.ProcessData(data, data, len);
		return true;
	} catch(CryptoPP::Exception &e) {
		err = e.what();
		return false;
	}
}

bool salsa(uint8_t *data, size_t len, const uint8_t *key, size_t keyLen, const uint8_t *IV, size_t IVlen, std::string &err)
{
	try {
		CryptoPP::Salsa20::Decryption dec;
		dec.SetKeyWithIV(key, keyLen, IV, IVlen);
		dec.ProcessData(data, data, len);
		return true;
	} catch(CryptoPP::Exception &e) {
		err = e.what();
		return false;
	}
}

bool des_decr(uint8_t *out, const uint8_t *in, size_t len, const uint8_t *key, std::string &err)
{
	try {
		CryptoPP::DESDecryption dec(key);
		CryptoPP::ECB_Mode_ExternalCipher::Decryption mode(dec);
		mode.ProcessData(out, in, len);
		return true;
	}	catch (CryptoPP::Exception& e) {
		err = e.what();
		return false;
	}
}

