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
#include <hexrays.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "crpp.h"

#define MAXDECLEN 0x1000000 // in bytes

//!!! IMPORTANT: the order and values of enum eAlg must be same as ##Algo## in 'format' param of 'ask_form' call
//! 	const char format[] =
//!    "<##Algo##
enum eAlg {
  eAlg_Rol = 0,
  eAlg_Add,
  eAlg_Sub,
  eAlg_Xor,
  eAlg_Mul,
  eAlg_Custom,
  eAlg_XorStr,
  eAlg_SimpleSubst,
  eAlg_RC4,
  eAlg_Sosemanuk,
  eAlg_Chacha,
  eAlg_Salsa,
  eAlg_Tea,
  eAlg_XTea,
  eAlg_AES,
  eAlg_DES,
  eAlg_CustomBlk
};

static void addComment(vdui_t *vu, const char *comment) 
{
  if (!vu->item.is_citem())
    return;

  user_cmts_t *cmts = restore_user_cmts(vu->cfunc->entry_ea);
  if (!cmts)
    cmts = user_cmts_new();

  if (setComment4Exp(vu->cfunc, cmts, vu->item.e, comment))
    vu->cfunc->save_user_cmts();
  user_cmts_free(cmts);
}

//'algo' number is set by ask_form call below
template <class charType>
charType decrypt_char(charType v, eAlg algo, void *k, int32 idx)
{
  Log(llFlood, "decrypt_char(%x, %x, %x)\n", (uint)v, (uint)algo, (uint)*(charType*)k);
  switch(algo) {
  case eAlg_Rol:
    return qrotl(v, *(uint8*)k);
  case eAlg_Add:
    return v + *(charType*)k;
  case eAlg_Sub:
    return *(charType*)k - v;
  case eAlg_Xor:
  case eAlg_XorStr:
    return v ^ *(charType*)k;
  case eAlg_Mul:
    return v * *(charType*)k;
  case eAlg_SimpleSubst:
    return *(charType*)k;
  case eAlg_Custom:
		v = v ^ *(charType*)k; //!!! direction is chanded to backward below in decr_core
		*(uint32*)k = qrotl(*(uint32*)k, 1); //rotate left key
	  return v;
  }
  return 0;
}

typedef uint64 getNextChar_t(void* ctx, bool *stop, int size, bool bFwd);

static uint64 getNextCharEa(void* ctx, bool *stop, int size, bool bFwd)
{
  ea_t *ea = (ea_t*)ctx;
  if (!is_mapped(*ea))
    *stop = true;
  uint64 res;
  switch (size) {
  case 1:
    res = get_byte(*ea);
    break;
  case 2:
    res = get_word(*ea);
    break;
  case 4:
    res = get_dword(*ea);
    break;
  case 8:
    res = get_qword(*ea);
    break;
  default:
    res = -1;
  }
  if(bFwd)
    *ea += size;
  else
    *ea -= size;
  return res;
}

static uint64 getNextCharBuf(void* ctx, bool *stop, int size, bool bFwd)
{
  char** ptr = (char**)ctx;
  uint64 res;
  switch (size) {
  case 1:
    res = **ptr;
    break;
  case 2:
    res = *(uint16*)(*ptr);
    break;
  case 4:
    res = *(uint32*)(*ptr);
    break;
  case 8:
    res = *(uint64*)(*ptr);
    break;
  default:
    res = -1;
  }
  if(bFwd)
    *ptr += size;
  else
    *ptr -= size;
  return res;
}

template<class charType> 
int32 decrypt_str(charType* buf, int32 len, eAlg algo, bytevec_t &key, getNextChar_t *getNextChar, void* gncCtx, bool bFwd)
{
  int32 ir = 0;
  int32 iw = 0;
  int32 rlen = len;
  int32 wlen = len;
  if(!bFwd) {
    iw = len - 1;
    wlen = 0;
  }
  void* pkey = key.begin();
  for (;; ir++) {
    if (len != -1) {
      if (ir >= rlen)
        break;
      if (bFwd) {
        if (iw >= wlen)
          break;
      } else {
        if (iw < wlen)
          break;
      }
    }
    bool stop = false;
    charType v = (charType)getNextChar(gncCtx, &stop, sizeof(charType), bFwd);
    if (stop)
      break;
    if (len == -1 && (v == 0 || ir >= MAXDECLEN / sizeof(charType)))
      break;
    switch (algo) {
    case eAlg_Custom:
      break;
    case eAlg_XorStr:
			pkey = &key[ir % key.size()];
      break;
    case eAlg_SimpleSubst:
      pkey = &key[v % key.size()];
      break;
    }
    buf[iw] = decrypt_char(v, algo, pkey, ir);
    if (bFwd)
      iw++;
    else
      iw--;
  }
  if (bFwd) {
    buf[iw] = 0; // additional zeroterminator to print string
    return iw;
  }
  buf[len] = 0; // additional zeroterminator to print string
  return len;
}

static int idaapi decr_str_cb(int field_id, form_actions_t &fa)
{
  static ushort prevItSz = 0;
  if (field_id == 1 || field_id == -1) { // algo is changed and init

    fa.get_rbgroup_value(2, &prevItSz); // init prevItSz

    // set defaults first
    fa.enable_field(2, true);  // enable ItemSz
    fa.enable_field(3, true);  // enable Cnt
    fa.enable_field(4, true);  // enable Key
    fa.enable_field(5, false); // disable IV
    fa.enable_field(6, false); // disable bCbc

    ushort valA;
    fa.get_rbgroup_value(1, &valA);
    eAlg algo = (eAlg)valA;
    ushort itSz = 0;
    switch (algo) {
    case eAlg_Tea:
    case eAlg_XTea:
    case eAlg_AES:
      fa.enable_field(6, true);  // enable bCbc
      fa.enable_field(2, false); // disable ItemSz
      {
        ushort val;
        fa.get_rbgroup_value(6, &val);
        fa.enable_field(5, val != 0); // enable/disable IV
      }
      break;
    case eAlg_Sosemanuk:
    case eAlg_Chacha:
    case eAlg_Salsa: {
      ushort val = 1;
      fa.set_rbgroup_value(6, &val); // set bCbc
    }
      fa.enable_field(5, true); // enable IV
      // falldown
    case eAlg_RC4:
    case eAlg_DES:
		case eAlg_CustomBlk:
			// set ItemSz to bytes and disable
		{
			ushort ItemSz;
			fa.get_rbgroup_value(2, &ItemSz);
			if(ItemSz) {
				int64 cnt;
				fa.get_int64_value(3, &cnt);
				if (cnt != 0 && cnt != -1) {
					cnt = cnt * (1LL << prevItSz);
					fa.set_int64_value(3, &cnt);
				}
				prevItSz = 0;
				fa.set_rbgroup_value(2, &prevItSz);
			}
      fa.enable_field(2, false); // disable ItemSz
      break;
		}
    default:
      // defauls are set above
      break;
    }
  } else if (field_id == 2) { // ItemSz is changed
    ushort val;
    fa.get_rbgroup_value(field_id, &val);
    int64 cnt;
    fa.get_int64_value(3, &cnt);
    if (cnt != 0 && cnt != -1 && val != prevItSz) {
      cnt = cnt * (1LL << prevItSz) / (1LL << val);
      fa.set_int64_value(3, &cnt);
    }
    prevItSz = val;
  } else if (field_id == 6) { // bCbc is changed
    ushort val;
    fa.get_rbgroup_value(field_id, &val);
    fa.enable_field(5, val != 0); // enable/disable IV
  }
  return 1;
}

//globals
static ushort alg  = 0;
static ushort bCbc = 0;
static qstring keystr("key");
static qstring ivstr("iv");
bool   patchExactLen = true;
bool   patchZeroTerm = false;
static int itemSize = 1;

bool decr_init(int64 *itCnt, ushort *itSz)
{
  const char format[] =
      "STARTITEM 3\n"
      // title
      "[hrt] Decrypt string\n\n"
      "%/\n"                               // callback
      "<##Algo##~R~ol (rol val, key):R>\n" // eAlg_Rol
      "<~A~dd (res = val + key):R>\n"      // eAlg_Add
      "<~S~ub (res = key - val):R>\n"      // eAlg_Sub
      "<~X~or (res = val ^ key):R>\n"      // eAlg_Xor
      "<~M~ul (res = val * key):R>\n"      // eAlg_Mul
      "<C~u~stom:R>\n"                     // eAlg_Custom:
      "<Xor with string:R>\n"              // eAlg_XorStr
      "<Simple substitution:R>\n"          // eAlg_SimpleSubst
      "<RC4:R>\n"                          // eAlg_RC4
      "<Sosemanuk:R>\n"                    // eAlg_Sosemanuk
      "<Chacha20:R>\n"                     // eAlg_Chacha
      "<Salsa20:R>\n"                      // eAlg_Salsa
      "<Tea:R>\n"                          // eAlg_Tea
      "<XTea:R>\n"                         // eAlg_XTea
      "<AES:R>\n"                          // eAlg_AES
      "<DES:R>\n"                          // eAlg_DES
      "<CustomBlkCypher:R>1>\n"            // eAlg_CustomBlk
      "<##ItemSz##~B~yte:r> <~W~ord:r> <~D~word:r> <~Q~word:r>2>\n"
      "<#-1 for autodetect#~C~nt:l3:32:32::>\n"
      "<#value, address (name), 'string', hex-string#~K~ey:q4::32::>\n"
      "<#nothing, address (name), 'string', hex-string# ~I~V:q5::32::>\n"
      "<##Mode##ECB:r> <CBC:r>6>\n"
      "\n\n";
  if (1 != ask_form(format, decr_str_cb, &alg, itSz, itCnt, &keystr, &ivstr, &bCbc))
    return false;

  itemSize = 1 << *itSz;
  patchExactLen = true;
  patchZeroTerm = false;
  return true;
}

//convert key representation
static bool decr_set_key(bytevec_t &key, ea_t keyEa, size_t keyLen, qstring *error)
{
  eAlg algo = (eAlg)alg;

  switch(algo) {
  case eAlg_SimpleSubst:
    if((keyEa || str2ea(&keyEa, keystr.c_str(), BADADDR)) && is_mapped(keyEa)) {
      if(!keyLen)
        keyLen = get_item_end(keyEa) - keyEa;
      key.resize(keyLen);
      if(keyLen == get_bytes(key.begin(), keyLen, keyEa, GMB_READALL))
        break;
    }
    error->sprnt("bad key: '%s', address of substitution table is expected", keystr.c_str());
    return false;
  case eAlg_CustomBlk:
  case eAlg_XorStr:
  case eAlg_RC4:
  case eAlg_Sosemanuk:
  case eAlg_Chacha:
  case eAlg_Salsa:
  case eAlg_Tea:
  case eAlg_XTea:
  case eAlg_AES:
  case eAlg_DES:
    if((keyEa || str2ea(&keyEa, keystr.c_str(), BADADDR)) && is_mapped(keyEa)) {
      if(!keyLen)
        keyLen = get_item_end(keyEa) - keyEa;
      key.resize(keyLen);
      if(keyLen == get_bytes(key.begin(), keyLen, keyEa, GMB_READALL))
        break;
      }
    if(keystr.length() > 2 && keystr[0] == '\'' && keystr.last() == '\'') {
			key.qclear();
			key.append(keystr.c_str() + 1, keystr.length() - 2);
      break;
    }
    if(!keystr.empty()) {
      // mean key is string of hex without prefix
      key.resize(keystr.length() / 2);
      size_t i, j;
      for(i = 0, j = 0; i < keystr.length(); i += 2) {
				if(keystr[i] == ' ')
					++i;
        if(!strtobx(&keystr[i], &key[j++]))
          break;
      }
      if(i == keystr.length())
        break;
    }
    error->sprnt("bad key: '%s', expected: 0x_address_of_key or 'key_string' or key_hex_string", keystr.c_str());
    return false;
  default:
		key.resize(8);
		if(keyEa) {
			//mass string decr mode
			*(ea_t*)(key.begin()) = keyEa;
		} else {
			//parse key string, strip suffix first for easy copy/paste
			qstring s(keystr);
			if(s.length() >= 2) {
				stripNum(&s);
				if(s[s.length() - 1] == 'h') {
					s[s.length() - 1] = 0;
					s.insert(0, "0x");
				}
			}
			//first try to convert string to uint64 (it possible 64bit keys in 32bit app)
			char* end = nullptr;
			uint64 key64 = strtoull(s.c_str(), &end, (s[0] == '0' && s[1] == 'x') ? 16 : 10);
			if(key64 != 0 && key64 != ULLONG_MAX) {
				*(uint64*)(key.begin()) = key64;
			} else if (str2ea(&keyEa, keystr.c_str(), BADADDR)) {
				*(ea_t*)(key.begin()) = keyEa;
			} else {
				error->sprnt("bad key: '%s', numeric value is expected", keystr.c_str());
				return false;
			}
		}
  }
  return true;
}

//convert IV representation
static bool decr_set_iv(bytevec_t &iv, ea_t ivEa, size_t ivLen, qstring *error)
{
	if(bCbc == 0)
		return true;

  eAlg algo = (eAlg)alg;
  if(!ivLen) {
    if(algo == eAlg_Chacha || algo == eAlg_Salsa)
      ivLen = 8;
    else
      ivLen = 16;
  }

  switch(algo) {
  case eAlg_Sosemanuk:
  case eAlg_Chacha:
  case eAlg_Salsa:
  case eAlg_Tea:
  case eAlg_XTea:
  case eAlg_AES:
  case eAlg_DES:
    if((ivEa || str2ea(&ivEa, ivstr.c_str(), BADADDR)) && is_mapped(ivEa)) {
      iv.resize(ivLen);
      if(ivLen == get_bytes(iv.begin(), ivLen, ivEa, GMB_READALL))
        break;
    }
    if(ivstr.length() > 2 && ivstr[0] == '\'' && ivstr.last() == '\'') {
			iv.qclear();
      iv.append(ivstr.c_str() + 1, ivstr.length() - 2);
      break;
    }
    // mean empty iv string as zerofilled
    if(ivstr.empty()) {
      iv.resize(ivLen, 0);
      break;
    }
    {
      // mean iv is string of hex without prefix
      iv.resize(ivstr.length() / 2);
      size_t i, j;
      for(i = 0, j = 0; i < ivstr.length(); i += 2) {
				if(ivstr[i] == ' ')
					++i;
        if(!strtobx(&ivstr[i], &iv.at(j++)))
          break;
      }
      if(i == ivstr.length())
        break;
    }
    error->sprnt("bad iv: '%s', expected: 0x_address_of_iv or 'iv_string' or iv_hex_string", ivstr.c_str());
    return false;
  }
  return true;
}

//returns decrypted len, 0 if error
static int64 decr_core(ea_t ea, const char *inBuf, int64 itCnt, bytevec_t &key, bytevec_t &iv, bytevec_t &decrbuf,  qstring *result, qstring *error)
{
  if(ea == BADADDR && !inBuf) {
    error->sprnt("wrong inbuff");
    return false;
  }

	int64 blkInLen; // input len in bytes for block ciphers
	int64 outLen;   // decrypted len in bytes
	if(itCnt != -1) {
		outLen = blkInLen  = itCnt * itemSize;
		decrbuf.resize((itCnt + 1) * itemSize); // + zeroterminator!
  } else {
		outLen = blkInLen = 0;
    decrbuf.resize(MAXDECLEN);
	}
  uint8 * dec_bufA = &decrbuf[0];
  uint16 *dec_bufW = (uint16 *)&decrbuf[0];
  uint32 *dec_bufD = (uint32 *)&decrbuf[0];
  uint64 *dec_bufQ = (uint64 *)&decrbuf[0];

  // variables for next stage
  getNextChar_t *getNextChar   = NULL;
  void *         ctx           = NULL;
  const char *   bufptr        = NULL;
  bool           bFwd          = true;

  // 1:-----------------------
  // check blkInLen, ctx & bufptr
  eAlg algo = (eAlg)alg;
  switch(algo) {
  case eAlg_Tea:
  case eAlg_XTea:
  case eAlg_DES:
    blkInLen = align_down(blkInLen, 8);
    if(blkInLen < 8) {
      error->sprnt("too short len");
      return 0;
    }
    break;
  case eAlg_AES:
    blkInLen = align_down(blkInLen, 16);
    if(blkInLen < 16) {
      error->sprnt("too short len");
      return 0;
    }
    if(key.size() != 16 && key.size() != 24 && key.size() != 32) {
      error->sprnt("wrong key len (%d)", key.size());
      return 0;
    }
    break;
	case eAlg_Custom:
		bFwd = false; //!!!
		// fall down
  default:
    if(ea != BADADDR) {
      getNextChar = getNextCharEa;
      if (!bFwd)
        ea += (ea_t)((itCnt - 1) * itemSize);
      ctx = &ea;
    } else if(inBuf) {
      bufptr      = inBuf;
      getNextChar = getNextCharBuf;
      if(!bFwd)
        bufptr += (itCnt - 1) * itemSize;
      ctx = &bufptr;
    }
	}

  //-----------------------
  // read data

  switch(algo) {
  case eAlg_CustomBlk:
  case eAlg_Tea:
  case eAlg_XTea:
  case eAlg_RC4:
  case eAlg_Sosemanuk:
  case eAlg_Chacha:
  case eAlg_Salsa:
  case eAlg_AES:
  case eAlg_DES:
    if(blkInLen <= 0 || blkInLen > MAXDECLEN) {
      error->sprnt("wrong inlen %d", (int)blkInLen);
      return 0;
    }
    if(ea != BADADDR) {
      get_bytes(dec_bufA, blkInLen, ea, GMB_READALL);
    } else if(inBuf) {
      memcpy(dec_bufA, inBuf, blkInLen);
    }
    break;
  }
  //----------------------
  // decrypt, and post-decr fix
  std::string err;
  switch(algo) {
  case eAlg_RC4:
    show_hex(key.begin(), key.size(), "[hrt] RC4 key length %d :\n", (int)key.size());
    if(!rc4(dec_bufA, (size_t)blkInLen, key.begin(), key.size(), err)) {
      *error = err.c_str();
      return 0;
    }
    break;
  case eAlg_CustomBlk:
    show_hex(key.begin(), key.size(), "[hrt] key length %d :\n", (int)key.size());
    show_hex(iv.begin(),  iv.size(), "[hrt] iv  length %d :\n",  (int)iv.size());
    //customDecr(dec_bufA, (int)blkInLen, keybuf.begin(), (int)keybuf.size());
    break;
  case eAlg_Sosemanuk: {
    show_hex(key.begin(), key.size(), "[hrt] Sosemanuk key length %d :\n", (int)key.size());
    //show_hex(dec_bufA, blkInLen, "[hrt] data length %d :\n", (int)len);
    if(!sosemanuk(dec_bufA, blkInLen, key.begin(), key.size(), iv.begin(), iv.size(), err)) {
      *error = err.c_str();
      return 0;
    }
  } break;
  case eAlg_Chacha:
  case eAlg_Salsa:	{
    show_hex(key.begin(), key.size(), "[hrt] key length %d :\n", (int)key.size());
    show_hex( iv.begin(),  iv.size(), "[hrt] iv  length %d :\n",  (int)iv.size());
    //show_hex(dec_bufA, blkInLen, "[hrt] data length %d :\n", (int)len);
    decr_proc_t proc;
    if(algo == eAlg_Chacha)
      proc = chacha;
    else
      proc = salsa;
    if(!proc(dec_bufA, blkInLen, key.begin(), key.size(), iv.begin(), iv.size(), err)) {
      *error = err.c_str();
      return 0;
    }
  } break;
  case eAlg_Tea:
  case eAlg_XTea: {
    show_hex(key.begin(), key.size(), "[hrt] Tea key length %d :\n", (int)key.size());
		if(bCbc)
			show_hex( iv.begin(),  iv.size(), "[hrt] iv  length %d :\n",  (int)iv.size());
    if(!tea_decr(dec_bufA, (size_t)blkInLen, key.begin(), key.size(), iv.begin(), bCbc, algo == eAlg_XTea, err)) {
      *error = err.c_str();
      return 0;
    }
  }
  break;
  case eAlg_AES: {
    show_hex(key.begin(), key.size(), "[hrt] AES key length %d :\n", (int)key.size());
		if(bCbc)
			show_hex( iv.begin(),  iv.size(), "[hrt] iv  length %d :\n",  (int)iv.size());
    if(!aes_decr(dec_bufA, (size_t)blkInLen, key.begin(), key.size(), iv.begin(), bCbc, err)) {
      *error = err.c_str();
      return 0;
    }
  } break;
  case eAlg_DES:
    show_hex(key.begin(), key.size(), "[hrt] DES key length %d :\n", (int)key.size());
    if(!des_decr(dec_bufA, dec_bufA, (size_t)blkInLen, key.begin(), err)) {
      *error = err.c_str();
      return 0;
    }
    break;
  default:
    if(algo == eAlg_Custom || algo == eAlg_XorStr || algo == eAlg_SimpleSubst)
			show_hex(key.begin(), key.size(), "[hrt] key length %d :\n", (int)key.size());
		else
      show_hex(key.begin(), itemSize, "[hrt] key length %d :\n", itemSize);
    if(itemSize == 1) {
      outLen = decrypt_str(dec_bufA, (int32)itCnt, algo, key, getNextChar, ctx, bFwd);
    } else if(itemSize == 2) {
      outLen = decrypt_str(dec_bufW, (int32)itCnt, algo, key, getNextChar, ctx, bFwd) * 2;
    } else if(itemSize == 4) {
      outLen = decrypt_str(dec_bufD, (int32)itCnt, algo, key, getNextChar, ctx, bFwd) * 4;
    } else if(itemSize == 8) {
      outLen = decrypt_str(dec_bufQ, (int32)itCnt, algo, key, getNextChar, ctx, bFwd) * 8;
    }
    break;
  }

  if (outLen <= 0 || outLen > MAXDECLEN) {
    error->sprnt("bad out len: %d", (int)outLen);
    return 0;
  }

  if(dec_bufA[1] == 0 && outLen > 2)
    utf16_utf8(result, (const wchar16_t *)dec_bufA, (int)outLen / 2);
  else
    result->append((char *)dec_bufA, (size_t)outLen);
  return outLen;
}

bool decr_done(vdui_t *vu, ea_t ea, const uint8 * dec_bufA, int64 len, qstring *result, bool immConst)
{
  show_hex(dec_bufA, len > 32 ? 32 : len, "[hrt] decrypted %d :\n", (int)len);

  qstring ask_res;
  ask_res = "BUTTON YES";
  if(ea != BADADDR) {
    ask_res.cat_sprnt("* Patch at %a\nBUTTON NO", ea);
  } else {
    ask_res.append(" NONE\nBUTTON NO*");

		// display const decryption results
		if(immConst) {
			bool printable = true;
			for(size_t i = 0; i < result->length(); ++i ) {
				if(result->at(i) < ' ' || result->at(i) > '~') {
					printable = false;
					break;
				}
			}
			if(!printable)
				result->clear();
			switch(len) {
			case 1: result->cat_sprnt(" (0x%02X)", *(uint8*)dec_bufA); break;
			case 2: result->cat_sprnt(" (0x%04X)", *(uint16*)dec_bufA); break;
			case 4: result->cat_sprnt(" (0x%08X)", *(uint32*)dec_bufA); break;
			case 8: result->cat_sprnt(" (0x%016" FMT_64 "X)", *(uint64*)dec_bufA); break;
			default: result->cat_sprnt(" (0x?? - FIXME)"); break;
			}
		}
  }
  ask_res.append(" Comment\n"
                 "BUTTON CANCEL Cancel\n"
                 "[hrt] Decryption result is\n\n"
                 "%q");

  int answ = ask_form(ask_res.c_str(), result);
  if(ASKBTN_YES == answ && ea != BADADDR) {
    if(dec_bufA[1] == 0 && len > 2)
      patch_wstr(ea, (const wchar16_t *)dec_bufA, patchExactLen ? (sval_t)len / 2 : -1, patchZeroTerm);
    else
      patch_str(ea, (const char *)dec_bufA, patchExactLen ? (sval_t)len : -1, patchZeroTerm);
    return true;
  } else if(ASKBTN_NO == answ) {
    if(vu)
      addComment(vu, result->c_str());
    else
      set_cmt(ea, result->c_str(), true);
    return true;
  }

  return false;
}

bool decrypt_string(vdui_t *vu, ea_t dec_ea, const char *inBuf, int64 hint_itCnt, ushort *itSz, qstring *result, bool immConst)
{
  int64 maxLenBytes = hint_itCnt * (1LL << *itSz);
  int64 itCnt = hint_itCnt;
  qstring error;
  bytevec_t key;
  bytevec_t iv;
  while(1) {
    if(!decr_init(&itCnt, itSz))
      return false;
    if((itCnt != -1 && itCnt > MAXDECLEN / itemSize) || itCnt == 0) {
      warning("[hrt] bad in len: %d, max %d\n", (int)itCnt, MAXDECLEN / itemSize);
      continue;
    }
    if(dec_ea == BADADDR && inBuf && itCnt * itemSize > maxLenBytes) {
      warning("[hrt] bad in len: %d, max %d\n", (int)(itCnt * itemSize), (int)maxLenBytes);
      continue;
    }
    if(!decr_set_key(key, 0, 0, &error))
      warning("[hrt] set key error: %s\n", error.c_str());
    else if(!decr_set_iv(iv, 0, 0, &error))
      warning("[hrt] set iv error: %s\n", error.c_str());
    else
      break;
  }
	bytevec_t decrbuf;
  int64 len = decr_core(dec_ea, inBuf, itCnt, key, iv, decrbuf, result, &error);
  if(!len) {
    warning("[hrt] decrypt error: %s\n", error.c_str());
    return false;
  }
  return decr_done(vu, dec_ea, &decrbuf[0], len, result, immConst);
}

bool decr_string_4appcall(ea_t dec_ea, const char *inBuf, int64 itCnt, ea_t keyEa, size_t keyLen, qstring *result, qstring *error)
{
  if((itCnt != -1 && itCnt > MAXDECLEN / itemSize) || itCnt == 0) {
    error->sprnt("bad in len: %d, max %d", (int)itCnt, MAXDECLEN / itemSize);
    return false;
  }
  bytevec_t key;
  if(!decr_set_key(key, keyEa, keyLen, error))
    return false;

  bytevec_t iv;
  if(!decr_set_iv(iv, 0, 0, error))
    return false;

	bytevec_t decrbuf;
  int64 len = decr_core(dec_ea, inBuf, itCnt, key, iv, decrbuf, result, error);
  return len != 0;
}
