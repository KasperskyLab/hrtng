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

// Evolution of helpers.cpp from https://github.com/nihilus/hexrays_tools
// there is almost no original code left

#include "warn_off.h"
#include <hexrays.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <pro.h>
#include "warn_on.h"

#include "helpers.h"
#include "config.h"

bool at_atoea(const char * str, ea_t * pea )
{
	while(*str && isspace(*str))
		str++;
	if(str[0] == '@' && str[1] == '0' && str[2] == 'x')
		return atoea(pea, str + 1);
	return false;
}

bool strtobx(const char *str, uint8 *b)
{
  uint8 val;

  uint8 c = *str;
  if (c >= '0' && c <= '9')
      val = c - '0';
  else if (c >= 'A' && c <= 'F')
      val = c - 'A' + 10;
  else if (c >= 'a' && c <= 'f')
      val = c - 'a' + 10;
  else
    return false;
  val <<= 4;
  c = *(str + 1);
  if (c >= '0' && c <= '9')
      val += c - '0';
  else if (c >= 'A' && c <= 'F')
      val += c - 'A' + 10;
  else if (c >= 'a' && c <= 'f')
      val += c - 'a' + 10;
  else
    return false;

  *b = val;
  return true;
}

size_t get_idx_of_lvar(vdui_t &vu, lvar_t *lvar)
{
	return get_idx_of(vu.cfunc->get_lvars(), lvar);
}

tinfo_t getType4Name(const char *name, bool funcType /*= false*/)
{
	qstring newName = name;
	stripName(&newName, funcType);
	bool isPtr = false;
	bool isDblPtr = false;

	if(!funcType) {
		isPtr = true;
		if(newName.last() == '_') {
			isPtr = false;
			newName.remove_last();
		} else if(newName.length() > 2 && newName.at(0) == 'p' && newName.at(1) == '_') {
			isDblPtr = true;
			newName.remove(0, 2);
		}
	}

	const type_t *type;
	const p_list *fields;
	tinfo_t       t; 
	if(get_named_type(NULL, newName.c_str(), NTF_TYPE, &type, &fields)) {
		if(is_type_struct(*type)) 
			t = create_typedef(newName.c_str());
		else
			t.deserialize(NULL, &type, &fields);
	} else if(/*(funcType || isPtr) && */get_named_type(NULL, newName.c_str(), 0, &type, &fields) && is_type_func(*type)) { // zero flag for functions
		t.deserialize(NULL, &type, &fields);
	}
	if(!t.empty() && isPtr) {
		t = make_pointer(t);
		if(isDblPtr)
			t = make_pointer(t);
	}
	return t;
}


bool is_ea(flags64_t flg)
{
	if(is64bit() && !isIlp32())
		return is_qword(flg);
	return is_dword(flg);
}

ea_t get_ea(ea_t ea)
{
	if(is64bit() && !isIlp32())
		ea = (ea_t)get_qword(ea);
	else
		ea = (ea_t)get_dword(ea);

	if(isARM() && is_tail(get_flags(ea)))
		ea = ea & ~1;
	return ea;
}

void create_type_from_size(tinfo_t* t, asize_t size)
{
	t->clear();
	switch (size) {
	case 1:
		t->create_simple_type(BT_INT8);
		break;
	case 2:
		t->create_simple_type(BT_INT16);
		break;
	case 4:
		t->create_simple_type(BT_INT32);
		break;
	case 8:
		t->create_simple_type(BT_INT64);
		break;
	case 16:
		t->create_simple_type(BT_INT128);
		break;
	default:
		tinfo_t byteType;
		byteType.create_simple_type(BT_INT8);
		t->create_array(byteType, (uint32)size);
	}
}

void stripName(qstring* name, bool funcSuffixToo /*= false*/)
{
	size_t len = name->length();
	if(funcSuffixToo) {
		if (len > 6 && !strncmp(name->c_str(), "__imp_", 6)) {
			name->remove(0, 6);
			len -= 6;
		}
		while (len > 2 && !strncmp(name->c_str(), "j_", 2)) {
			name->remove(0, 2);
			len -= 2;
		}
	}

	if (len > 2) {
		char last = name->at(len - 1);
		if(last >= '0' && last <= '9') {
			last = name->at(len - 2);
			if(last == '_') {
				name->remove_last(2);
			} else if (len > 3 && last >= '0' && last <= '9' && name->at(len - 3) == '_') {
				name->remove_last(3);
			}
		}
	}
}

void stripNum(qstring* name)
{
	size_t l = name->length();
#if IDA_SDK_VERSION < 830
	//strip "i64" suffix
	if(l > 3 && !qstrcmp(name->begin() + l - 3, "i64")) {
		l -= 3;
		name->remove_last(3);
	}
#else //IDA_SDK_VERSION >= 830
	//strip "LL" suffix
	if(l > 2 && !qstrcmp(name->begin() + l - 2, "LL")) {
		l -= 2;
		name->remove_last(2);
	}
#endif //IDA_SDK_VERSION < 830
	//strip "u" suffix
	if(l > 1 && name->at(l - 1) == 'u') {
		name->remove_last(1);
	}
}

int namecmp(const char* name, const char* cmpWith)
{
	size_t len = qstrlen(name);
	if (len > 2) {
		char last = name[len - 1];
		if(last >= '0' && last <= '9') {
			last = name[len - 2];
			if(last == '_') {
				len -= 2;
			} else if (len > 3 && last >= '0' && last <= '9' && name[len - 3] == '_') {
				len -= 3;
			}
		}
	}
	if(qstrlen(cmpWith) != len)
		return -1;
	return strncmp(name, cmpWith, len);
}

qstring good_udm_name(const tinfo_t &struc, uint64 offInBits, const char *format, ...)
{
	qstring name;
	va_list va;
	va_start(va, format);
	name.vsprnt(format, va);
	va_end(va);

	if (name.size() > MAX_NAME_LEN - 3)
		name.resize(MAX_NAME_LEN - 3);
	validate_name(&name, VNT_UDTMEM);

	return unique_name(name.c_str(), "_",
										 [&struc, offInBits](const qstring &n)
	{
		udm_t m;
		m.name = n;
		return struc.find_udm(&m, STRMEM_NAME) < 0 || (m.offset == offInBits && struc.is_struct()); 		// the same name in the same position is ok for struct
	});
}

#if IDA_SDK_VERSION < 850
qstring good_smember_name(const struc_t* sptr, ea_t offset, const char *format, ...)
{
	qstring name;
	va_list va;
	va_start(va, format);
	name.vsprnt(format, va);
	va_end(va);

	if(name.size() > MAX_NAME_LEN)
		name.resize(MAX_NAME_LEN);
	//validate_name(&name, VNT_UDTMEM);

	return unique_name(name.c_str(), "_",
										 [&sptr, offset](const qstring &n)
	{

		member_t *m = get_member_by_name(sptr, n.c_str());
		return !m || (m->soff == offset && !sptr->is_union());
	});
}
#endif //IDA_SDK_VERSION < 850


void patch_str(ea_t ea, const char *str, sval_t len, bool bZeroTerm)
{
	if (!len)
		return;
	if(len == -1)
		len = (sval_t)qstrlen(str) + 1;
	patch_bytes(ea, str, len);

	//zero-terminate string, if here is one more unused byte
	if(bZeroTerm && str[len - 1] && !has_xref(get_flags(ea + len))) {
		patch_byte(ea + len, 0);
		len++;
	}
	if(len < 1024)
		create_strlit(ea, len, STRTYPE_C);
	add_extra_cmt(ea, true, "; patched 0x%x", len);
}

void patch_wstr(ea_t ea, const char *str, sval_t len)
{
	if(len == -1)
		len = (sval_t)qstrlen(str) + 1;
	ea_t start = ea;
	for(sval_t i = 0; i < len; i++, ea += 2)
		patch_word(ea, str[i]);
	//patch_bytes(ea, str, len);
	if(len < 1024)
		create_strlit(start, len * 2, STRTYPE_C_16);
	add_extra_cmt(ea, true, "; patched 0x%x", len * 2);
}

void patch_wstr(ea_t ea, const wchar16_t *str, sval_t len, bool bZeroTerm)
{
	if(len == -1)
		len = (sval_t)qstrlen(str) + 1;
	sval_t len2 = len * 2;
	patch_bytes(ea, str, len2);

	//zero-terminate string, if here is one more unused byte
	if(bZeroTerm && str[len - 1] &&
		 !has_xref(get_flags(ea + len2)) &&
		 !has_xref(get_flags(ea + len2 + 2))) {
		patch_word(ea + len2, 0);
		len++;
	}
	if(len < 1024)
		create_strlit(ea, len * 2, STRTYPE_C_16);
	add_extra_cmt(ea, true, "; patched 0x%x", len * 2);
}

bool isWnd()
{
	filetype_t ft = inf_get_filetype();
	if (ft == f_PE)
		return true;
	if (ft != f_BIN)
		return false;
	if (default_compiler() == COMP_MS)
		return true;
	//TODO: check til
	return false;
}

bool appendComment(qstring &comments, qstring &newCmt, bool bDuplicable)
{
	if (!newCmt.empty()) {
		if (comments.length())
			comments.append('\n');
		else if(!bDuplicable)
			comments.append(';'); //!! this comment will not processed by var renamer  (see autorename_n_pull_comments cblock_visitor_t::rename_asgn_sides)
		comments.append(newCmt);
		return true;
	}
	return false;
}

bool setComment4Exp(cfunc_t* func, user_cmts_t *cmts, citem_t *expr, const char* comment, bool bDisasmOnly, bool bSemicolonCmt, bool bOverride)
{
	if (!expr || !qstrlen(comment))
		return false;

	const citem_t *p = expr;
	while (p && p->op <= cot_last) {
		p = func->body.find_parent_of(p);
	}
	if (!p)
		p = expr;

	ea_t cmtEA = expr->ea;
	if(cmtEA == BADADDR)
		cmtEA = p->ea;
	if (cmtEA != BADADDR && (bOverride || !has_cmt(get_flags(cmtEA)))) {
		set_cmt(cmtEA, comment, false);
	}
	if (bDisasmOnly)
		return false; // pseudocode comments aren't changed

	treeloc_t loc;
	loc.ea = p->ea;
	if(bSemicolonCmt)
		loc.itp = (p->op == cit_expr) ? ITP_BLOCK1 : ITP_SEMI;
	else
		loc.itp = ITP_BLOCK1;
	if (bOverride) {
		func->set_user_cmt(loc, comment);
		return true;
	}
	user_cmts_iterator_t it = user_cmts_find(cmts, loc);//get existing comments
	if (it == user_cmts_end(cmts)) {
		func->set_user_cmt(loc, comment);
		return true;
	}
	const char* existCmt = func->get_user_cmt(loc, RETRIEVE_ALWAYS);
	if(!qstrstr(existCmt, comment)) {
		qstring s;
		s.sprnt("%s %s", existCmt, comment); // join old and new comment
		func->set_user_cmt(loc, s.c_str());
		return true;
	}
	Log(llDebug, "%a not join comments '%s' and '%s'\n", expr->ea, existCmt, comment);
	return false;
}

tinfo_t getCallInfo(cexpr_t *call, ea_t* dstea)
{
	tinfo_t tif;
	if (call->x->op == cot_obj) {
		*dstea = call->x->obj_ea;
		get_tinfo(&tif, *dstea);
	} else {
		*dstea = BADADDR;
	}
	if (tif.empty()) {
		tif = call->x->type;
		if (tif.empty()) {
			call->x->calc_type(true);
			tif = call->x->type;
		}
	}
	return tif;
}

void replace_colortag_inplace(char *line, int pos, char prefix, char find, char replace)
{
  line = (char*)tag_advance(line, pos);
  while(*line) {
    if(*line++ == prefix && *line++ == find) {
      *(--line) = replace;
      return;
    }
  }
}

qstring printExp(const cfunc_t *func, cexpr_t *expr)
{
	qstring sExp;
	expr->print1(&sExp, func);
	tag_remove(&sExp);
	return sExp;
}

void printExp2Msg(const cfunc_t *func, cexpr_t *expr, const char* mesg)
{
	qstring SExp = printExp(func, expr);
	qstring funcname;
	get_short_name(&funcname, func->entry_ea);
	Log(llInfo, "%a %s: %s '%s'\n", expr->ea, funcname.c_str(), mesg, SExp.c_str());
}

void replaceExp(const cfunc_t *func, cexpr_t *expr, cexpr_t *newExp, bool clean)
{
	qstring SoldExp = printExp(func, expr);
	qstring SnewExp = printExp(func, newExp);;
	qstring funcname;
	get_short_name(&funcname, func->entry_ea);
	Log(llInfo, "%a %s: '%s' was replaced to '%s'\n", expr->ea, funcname.c_str(), SoldExp.c_str(), SnewExp.c_str());

	if (clean)
		expr->cleanup();
	expr->replace_by(newExp);
}

void dump_ctree(cfunc_t* func, const char* fname)
{
	qstring dumpFileName;
	if (!qgetenv("IDA_DUMPDIR", &dumpFileName))
		return;
	dumpFileName += '/';
	dumpFileName += fname;
	FILE* file = qfopen(dumpFileName.c_str(), "w");
	if (!file)
		return;

	qstring body;
	qstring_printer_t p(func, body, false);
	func->print_func(p);
	qfwrite(file, body.c_str(), body.length());
	qfclose(file);
}

//------------------------------------------------

bool jump_custom_viewer(TWidget* custom_viewer, int line, int x, int y)
{
	place_t* place;
	place = get_custom_viewer_place(custom_viewer, false, NULL, NULL);
	simpleline_place_t* newplace = (simpleline_place_t*)place->clone();
	newplace->n = line;
	return jumpto(custom_viewer, newplace, x, y);
}

//------------------------------------------------

void LogLevelNames(qstrvec_t *v)
{
	v->clear();
	v->push_back("Error");
	v->push_back("Warning");
	v->push_back("Notice");
	v->push_back("Info");
	v->push_back("Debug");
	v->push_back("Flood");
}

static char LogLevelName(LogLevel level)
{
	switch(level) {
	case llError: return 'e';
	case llWarning: return 'w';
	case llNotice: return 'n';
	case llInfo: return 'i';
	case llDebug: return 'd';
	case llFlood: return 'f';
	default: return 'u';
	}
}

int Log(LogLevel level, const char *fmt, ...)
{
	if(level > cfg.logLevel)
		return 0;
	qstring s;
	s.sprnt("[hrt %c] ", LogLevelName(level));
	va_list va;
  va_start(va, fmt);
	s.cat_vsprnt(fmt, va);
	va_end(va);
  return msg(s.c_str());
}

int LogTail(LogLevel level, const char *fmt, ...)
{
	if(level > cfg.logLevel)
		return 0;
	va_list va;
  va_start(va, fmt);
	int res = vmsg(fmt, va);
	va_end(va);
  return res;
}
