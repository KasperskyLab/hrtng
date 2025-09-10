/*
    Copyright © 2016-2025 AO Kaspersky Lab.

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

    Authors: Sergey.Belov at kaspersky.com
 */

#include "warn_off.h"
#include <pro.h>
#include <diskio.hpp>
#include "warn_on.h"

#include <map>
#include "helpers.h"

//IDA stores 32bit values in 64bit sign extended form, so store hashes the same way
typedef int64 hash_t;
#define HASH32to64(x) (hash_t)(int32)(x)

//------------------------------------------------------------
// 5f087e34ab6a470b9e46bcb7c6edfcc5
static hash_t	Custom_HashFunction(const char* libraryName, const char* name, int64 basis, int64 prime)
{
	uint32 h = (uint32)basis;
  uint8 c;
	while ((c = *name++) != 0) {
		h ^= c;
		h *= (uint32)prime;
		h ^= h >> 16;
		h *= (uint32)prime;
		h ^= h >> 16;
		h *= (uint32)prime;
	}
  return HASH32to64(h);
}
//------------------------------------------------------------
static hash_t Ror_HashFunction(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
	uint32	result	=	(uint32)basis;
	const char*	ptr	=	0;
	for (ptr = functionName; ; ptr++)
	{
		uint8_t	uc	=	(uint8_t)*ptr;
		if ( *ptr == 0x00 )
			break;
		result = qrotr(result, prime) + uc;
	}
	return HASH32to64(result);
}

//------------------------------------------------------------
static hash_t RorUp_HashFunction(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
	uint32	result	=	(uint32)basis;
	const char*	ptr	=	0;
	for (ptr = functionName; ; ptr++)
	{
		uint8_t	uc	=	(uint8_t)*ptr;
		if ( *ptr == 0x00 ) // check order!!!
			break;
		if ( uc >= 0x61 )
			uc -= 0x20;
		result = qrotr(result, prime) + uc;
	}
	return HASH32to64(result);
}

//------------------------------------------------------------
static uint32 Metasploit_HashLibName(const char* libname, int64 basis, int64 prime)
{
	uint32	libhash	=	(uint32)basis;
	const char*	ptr	=	0;
	for (ptr = libname; ; ptr++)
	{
		uint8_t	uc	=	(uint8_t)*ptr;
		if ( uc >= 0x61 )
			uc -= 0x20;
		libhash = qrotr(libhash, prime) + uc;
		libhash = qrotr(libhash, prime); /* for unicode */
		if ( uc == 0x00 )
			break;
	}
	return libhash;
}

static uint32 Metasploit_HashAPI(const char* name, int64 basis, int64 prime)
{
	uint32	result	=	(uint32)basis;
	const char*	ptr	=	0;
	for (ptr = name; ; ptr++)
	{
		uint8_t	uc	=	(uint8_t)*ptr;
		result = qrotr(result, prime) + uc;
		if ( *ptr == 0x00 )
			break;
	}
	return result;
}

static hash_t	Metasploit_HashFunction(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
	return HASH32to64(Metasploit_HashLibName(libraryName, basis, prime) + Metasploit_HashAPI(functionName, basis,prime));
}

//------------------------------------------------------------
static hash_t	RolXor_HashFunction(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
	uint32	result	=	(uint32)basis;
	const char*	ptr	=	0;

	for (ptr = functionName; ; ptr++)
	{
		uint8_t	uc	=	(uint8_t)*ptr;
		if ( *ptr == 0x00 )
			break;
		result = qrotl(result, prime) ^ uc;
	}

	return HASH32to64(result);
}

//------------------------------------------------------------
static hash_t	crc32_HashFunc(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
	uint32 crc = (uint32)basis;
	const unsigned char* ptr = (unsigned char*)functionName;
	while( *ptr != 0 ) {
		uint32 c = *ptr++;
		for(unsigned i = 0; i < 8; i++ ) {
			if (((crc ^ c) & 1) !=0 )
				crc = (crc >> 1) ^ (uint32)prime;
			else
				crc = crc >> 1;
			c >>= 1;
		}
	}
	return HASH32to64(~crc);
}

//------------------------------------------------------------
//sdbm                   hash = hash * 65599 + c
//Daniel Bernstein (djb) hash = hash * 33 + c
static hash_t	sdbm_djb_hash(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
  uint32 hash = (uint32)basis;
  uint32 c;
	while ((c = *functionName++) != 0) {
		hash = hash * (uint32)prime + c;
    //hash = c + (hash << 5) + hash; //djb fast
		//hash = c + (hash << 6) + (hash << 16) - hash;// sdbm fast
	}
  return HASH32to64(hash);
}

static hash_t	fnv1a_hash(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
  hash_t hash = basis;
  uint8 c;
	while ((c = *functionName++) != 0) {
		hash ^= c;
		hash *= prime;
	}
  return hash;
}

//------------------------------------------------------------
static hash_t	murmur3_HashFunc(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
  const uint8* key = (const uint8*)functionName;
  size_t len = qstrlen(key);
  uint32 h = (uint32)basis;
  if (len > 3) {
    const uint32* key_x4 = (const uint32*) key;
    size_t i = len >> 2;
    do {
      uint32 k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h = (h * 5) + 0xe6546b64;
    } while (--i);
    key = (const uint8*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32 k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return HASH32to64(h);
}

//------------------------------------------------------------
#include <md5.h>
static hash_t	halfMD5_HashFunc(const char* libraryName, const char* functionName, int64 basis, int64 prime)
{
	uint8 hash[16];
	MD5Context ctx;
	MD5Init(&ctx);
#if IDA_SDK_VERSION < 770
	MD5Update(&ctx, (const uchar *)functionName, qstrlen(functionName));
#else
	MD5Update(&ctx, functionName, qstrlen(functionName));
#endif //IDA_SDK_VERSION < 770
	MD5Final(hash, &ctx);
	return *(hash_t*)hash;
}
//------------------------------------------------------------

struct ida_local HashFunctionInfo
{
    const char* name;
    const char* hint;
    hash_t    (*HashFunctionPtr)(const char* libraryName, const char* functionName, int64 basis, int64 prime);
		int64      basis;
		int64      prime;
};

static const HashFunctionInfo	hashers[]	=	{
	{ "~M~etasploit", "Ror13hash(toupper(LibName)) + Ror13hash(FuncName)", Metasploit_HashFunction, 0, 13},
	{ "~R~or", "hash = ror(hash, prime) + c", Ror_HashFunction, 0, 13 },
	{ "Ror~U~pper", "hash = ror(hash, prime) + toupper(c)", RorUp_HashFunction, 0, 13},
	{ "Ro~l~Xor", "hash = rol(hash, prime) ^ c", RolXor_HashFunction, 0, 7},
	{ "Crc~3~2", "hash = crc32(str)", crc32_HashFunc, ~0, 0xEDB88320},
	{ "s~d~bm", "hash = hash * 65599 + c", sdbm_djb_hash, 0, 65599},
	{ "D ~B~ernstein (djb)", "hash = hash * 33 + c", sdbm_djb_hash, 5381, 33},
	{ "~F~NV1a", "hash ^= c; hash *= prime", fnv1a_hash, 0x811c9dc5, 0x01000193},
	{ "~M~urmur3_32", "en.wikipedia.org/wiki/MurmurHash", murmur3_HashFunc, 0xC5EDFA84, 0},
	{ "halfMD~5~", "MD5(str)", halfMD5_HashFunc, 0, 0},
  { "~C~ustom", "insert here your custom hash func", Custom_HashFunction, 0, 16777619}
};

//------------------------------------------------------------
std::map<hash_t, qstring> hashes;

static ssize_t idaapi make_code_callback(va_list va)
{
	insn_t*	cmdP = va_arg(va, insn_t*);
	ea_t	ea = cmdP->ea;

	for (size_t idx = 0; idx < UA_MAXOP; idx++)
	{
		if ( cmdP->ops[idx].type == o_void )
			break;
		if ( cmdP->ops[idx].type != o_imm )
			continue;
		if ( cmdP->ops[idx].value == 0x0 )
			continue;
		hash_t opValue = cmdP->ops[idx].value;
		auto it = hashes.find(opValue);
		if(it != hashes.end()) {
			Log(llInfo, "%a: Found API hash for %s\n", ea, it->second.c_str());
			set_cmt(ea, it->second.c_str(), false);
			break;
		}
	}

	return 0;
}

static ssize_t idaapi make_data_callback(va_list va)
{

	ea_t	ea = va_arg(va, ea_t);
	(void)va_arg(va, flags64_t);
	(void)va_arg(va, tid_t);
	asize_t	sz = va_arg(va, asize_t);
	hash_t	opValue;

	switch(sz)
	{
	case 4:
		opValue = HASH32to64(get_dword(ea));
		break;
	case 8:
		opValue = get_qword(ea);
		break;
	default:
		return 0;
	}
	if ( opValue == 0 )
		return 0;

	auto it = hashes.find(opValue);
	if(it != hashes.end()) {
		Log(llInfo, "%a: Found API hash for %s\n", ea, it->second.c_str());
		if (!set_name(ea, it->second.c_str(), SN_NOCHECK | SN_NOWARN | SN_FORCE)) {
			set_cmt(ea, it->second.c_str(), true);
		}
	}

	return 0;
}


//--------------------------------------------------------------------------
// This callback is called for IDP notification events
MY_DECLARE_LISTENER(make_callback)
{
	switch(ncode)
	{
	case idb_event::make_code:
		return make_code_callback(va);
	case idb_event::make_data:
		return make_data_callback(va);
	}
	return 0;
}

//--------------------------------------------------------------------------
struct ida_local ah_visitor_t : public ctree_visitor_t
{
	cfunc_t *func;
	bool cmtModified;
	user_cmts_t *cmts;

	ah_visitor_t(cfunc_t *cfunc) : ctree_visitor_t(CV_FAST), func(cfunc), cmtModified(false)
	{
		cmts = restore_user_cmts(cfunc->entry_ea);
		if(cmts == NULL)
			cmts = user_cmts_new();
	}

	~ah_visitor_t()
	{
		if (cmtModified)
			func->save_user_cmts();
		user_cmts_free(cmts);
	}
	void chkVal(hash_t val, citem_t *expr)
	{
		if(val) {
			auto it = hashes.find(val);
			if(it != hashes.end()) {
				Log(llInfo, "%a: Found API hash %" FMT_64 "x for %s\n", expr->ea, it->first, it->second.c_str());
				cmtModified |= setComment4Exp(func, cmts, expr, it->second.c_str());
			}
		}
	}
	virtual int idaapi visit_expr(cexpr_t *expr)
	{
		if(expr->op == cot_num) {
			hash_t v = expr->n->_value;
			switch(expr->n->nf.org_nbytes) {
			case 4:
				v = HASH32to64(v);
				//pass down
			case 8:
				chkVal(v, expr);
				break;
			}
		}
		return 0;
	}
	virtual int idaapi visit_insn(cinsn_t *insn)
	{
		if(insn->op == cit_switch) {
			ccases_t &cases = insn->cswitch->cases;
			for(size_t i = 0; i < cases.size(); i++)
				for(size_t j = 0; j < cases[i].size(); j++)
					chkVal(cases[i].value((int)j), &cases[i]);
		}
		return 0;
	}

};

static bool bApihashesInited = false;

void apihashes_scan(cfunc_t *cfunc)
{
	if(!bApihashesInited)
		return;
	ah_visitor_t lv(cfunc);
	lv.apply_to(&cfunc->body, NULL);
}

//--------------------------------------------------------------------------
static int idaapi dlg_cb(int field_id, form_actions_t &fa)
{
	bool firstInit = false;
	if(field_id == -1) {
		int64 basis;
		int64 prime;
		fa.get_int64_value(2, &basis);
		fa.get_int64_value(3, &prime);
		firstInit = basis == 0 && prime == 0;
	}
  if (field_id == 1 || firstInit ) {//algo is changed or first init
    ushort algo;
    fa.get_rbgroup_value(1, &algo);
		if(algo < qnumber(hashers)) {
			fa.set_int64_value(2, &hashers[algo].basis);
      fa.set_int64_value(3, &hashers[algo].prime);
		}
	}
  return 1;
}

void apihashes_init()
{
	static ushort alg = 0;
	static int64 basis = 0;
	static int64 prime = 0;
	char buf[4096];
	getsysfile(buf, 4096, "apilist.txt", PLG_SUBDIR);
	qstring format =
		"STARTITEM 1\n"
		//title
		"[hrt] Init API hashes\n\n"
		"%/\n"                        // callback
		"<##Algo##";
	for(size_t i = 0; i < qnumber(hashers); i++) {
		if(i == 0)
			format.cat_sprnt("<#%s#Algo##", hashers[i].hint);
		else
			format.cat_sprnt("<#%s#", hashers[i].hint);
		format.append(hashers[i].name);
		if(i == qnumber(hashers) - 1)
			format.append(":r>1>\n");
		else
			format.append(":r>\n");
	}
	format.append("<#Initial hash value#~B~asis:l2::20::>\n"
								"<#Hash modifier value#~P~rime:l3::20::>\n"
								"<API list file:f::32::>\n\n\n");

	if(1 != ask_form(format.c_str(), dlg_cb, &alg, &basis, &prime, buf))
		return;

	FILE* file = fopenRT(buf);
	if(!file) {
		warning("[hrt] '%s' not found\n", buf);
		return;
	}

	show_wait_box("[hrt] Calculating...");
	hashes.clear();
	qstring dllName;
	bool bNextIsDll = true;
	int lines = 0;
	int collisions = 0;
	while(NULL != qfgets(buf, 4096, file)) {
		lines++;
		size_t len;
		//trim right
		do {
			len = qstrlen(buf);
			if(!len || (buf[len - 1] != '\n' && buf[len - 1] != '\r' && buf[len - 1] != ' ' && buf[len - 1] != '\t'))
				break;
			buf[len - 1] = 0;
		} while(1);

		if(!len) {
			bNextIsDll = true;
			continue;
		}

		if(bNextIsDll) {
			dllName = buf;
			bNextIsDll = false;
		}
		hash_t hash = hashers[alg].HashFunctionPtr(dllName.c_str(), buf, basis, prime);
		Log(llFlood, "hash %" FMT_64 "x %s\n", (int64)hash, buf);

		auto it = hashes.find(hash);
		if(it != hashes.end() && strcmp(it->second.c_str(), buf)) {
			Log(llWarning, "hash collision %" FMT_64 "x '%s' and '%s'\n", (int64)hash, it->second.c_str(), buf);
			++collisions;
		} else {
			hashes[hash] = buf;
		}
		if(user_cancelled()) {
			hide_wait_box();
			return;
		}
	}
	hide_wait_box();
	Log(llNotice, "%d lines, %d hashes, %d collisions\n", lines, (int)hashes.size(), collisions);

	if(!bApihashesInited) {
		HOOK_CB(HT_IDB, make_callback);
		bApihashesInited = true;
	}
}

//--------------------------------------------------------------------------
void apihashes_done()
{
	if(bApihashesInited) {
		UNHOOK_CB(HT_IDB, make_callback);
		hashes.clear();
		bApihashesInited = false;
	}
}

