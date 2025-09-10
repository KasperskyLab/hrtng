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

// Evolution of helpers.h from https://github.com/nihilus/hexrays_tools

#pragma once
#include "warn_off.h"
#include <hexrays.hpp>
#if IDA_SDK_VERSION < 850
#include <struct.hpp>
#endif //IDA_SDK_VERSION < 850
#include "warn_on.h"

#define AST_ENABLE_ALW return AST_ENABLE_ALWAYS
#define AST_ENABLE_FOR_PC return ((ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET)
#define AST_ENABLE_FOR(check) vdui_t *vu = get_widget_vdui(ctx->widget); return ((vu == NULL) ? AST_DISABLE_FOR_WIDGET : ((check) ? AST_ENABLE : AST_DISABLE))

#define ACT_NAME(name) "hrt:" # name
#define ACT_DESC(label, shortcut, name) ACTION_DESC_LITERAL(ACT_NAME(name), label, &name, shortcut, NULL, -1)
#define ACT_DESC1(label, shortcut, name) static const action_desc_t action_ ## name = ACT_DESC(label, shortcut, name);
#define ACT_DEF(name) int idaapi name ## _t::activate(action_activation_ctx_t *ctx)
#define ACT_REG(name) register_action(action_ ## name)
#define ACT_UNREG(name) unregister_action(ACT_NAME(name))
#define ACT_DECL(name, update_res) \
	struct ida_local name ## _t : public action_handler_t \
	{ \
	virtual int idaapi activate(action_activation_ctx_t *); \
	virtual action_state_t idaapi update(action_update_ctx_t *ctx) { update_res; }\
	};\
	static name ## _t name;


#if IDA_SDK_VERSION < 920
  #define MY_DECLARE_LISTENER(name) static ssize_t idaapi name(void *ud, int ncode, va_list va)
  #define HOOK_CB(ht, cb) hook_to_notification_point(ht, cb)
  #define UNHOOK_CB(ht, cb) unhook_from_notification_point(ht, cb)
#else
  #define MY_DECLARE_LISTENER(name) \
	  struct ida_local name ## _t : public event_listener_t { virtual ssize_t idaapi on_event(ssize_t code, va_list va) override; }; name ## _t name; \
    ssize_t idaapi name ## _t::on_event(ssize_t ncode, va_list va)
  #define HOOK_CB(ht, cb) hook_event_listener(ht, &cb, nullptr)
  #define UNHOOK_CB(ht, cb) unhook_event_listener(ht, &cb)
#endif //IDA_SDK_VERSION >= 920

#if IDA_SDK_VERSION < 910
  #define isIlp32() false
#else
  #define isIlp32() inf_is_ilp32()
#endif // IDA_SDK_VERSION < 910

#if IDA_SDK_VERSION >= 850 && IDA_SDK_VERSION <= 900
 #define BWN_TICSR BWN_TILVIEW
#endif // IDA_SDK_VERSION >= 850 && IDA_SDK_VERSION <= 900

#if IDA_SDK_VERSION < 850
	#define interactive_graph_t mutable_graph_t
	#define get_named_type_tid(x) get_struc_id(x)
	#define get_tid_name(x, y) get_struc_name(x, y)
	#define merge_blocks combine_blocks
	#define BWN_TICSR BWN_LOCTYPS
#endif // IDA_SDK_VERSION < 850

#if IDA_SDK_VERSION < 840
	#define udm_t udt_member_t
	#define find_udm find_udt_member
	#define NTF_NO_NAMECHK 0
	#define tinfo_errstr(err) ""
	#define TERR_BAD_TYPE ((tinfo_code_t)-5)
	#define BWN_TILIST BWN_STRUCTS // not the same, just to decrease number of ifdefs
	#define TERR_SAVE_ERROR TERR_SAVE
#endif // IDA_SDK_VERSION < 840

#if IDA_SDK_VERSION < 830
	#define flags64_t flags_t
#endif // IDA_SDK_VERSION < 830

#if IDA_SDK_VERSION < 760
	inline ssize_t idaapi get_ida_notepad_text(qstring *buf) { return root_node.supstr(buf, RIDX_NOTEPAD); }
	inline void idaapi set_ida_notepad_text(const char *text, size_t size=0) { root_node.supset(RIDX_NOTEPAD, text); }
#endif //IDA_SDK_VERSION < 760

#if IDA_SDK_VERSION < 750
	#define COMPAT_register_and_attach_to_menu(a,b,c,d,e,f,g) register_and_attach_to_menu(a,b,c,d,e,f,g)
	#define COMPAT_open_pseudocode_REUSE(a) open_pseudocode(a, 0);
	#define COMPAT_open_pseudocode_REUSE_ACTIVE(a) open_pseudocode(a, -1);
	#define COMPAT_open_pseudocode_NEW(a) open_pseudocode(a, 1);
	#define PH ph
	#define CHCOL_INODENAME 0
#else //IDA_SDK_VERSION < 750
	#define COMPAT_register_and_attach_to_menu(a,b,c,d,e,f,g) register_and_attach_to_menu(a,b,c,d,e,f,g, ADF_OT_PLUGIN)
	#define COMPAT_open_pseudocode_REUSE(a) open_pseudocode(a, OPF_REUSE);
	#define COMPAT_open_pseudocode_REUSE_ACTIVE(a) open_pseudocode(a, OPF_REUSE_ACTIVE);
	#define COMPAT_open_pseudocode_NEW(a) open_pseudocode(a, OPF_NEW_WINDOW);
#endif //IDA_SDK_VERSION < 750

#if IDA_SDK_VERSION < 740
	#define PRTYPE_COLORED 0
	#define DECOMP_ALL_BLKS 0
#endif //IDA_SDK_VERSION < 740

#define MAX_NAME_LEN 63 //inf.max_autoname_len (inf_get_max_autoname_len)

bool at_atoea(const char * str, ea_t * pea );
bool strtobx(const char *str, uint8 *b);

template <typename T> bool safe_advance(T & iter, const T & end, uval_t count)
{
	while(count-- > 0)
	{
		if (iter == end)
			return false;
		iter++;		
	}
	if (iter == end)
			return false;
	return true;
}

//BEWARE: these are dangerous (but qasserted)!
template <typename T> size_t get_idx_of(qvector<T> * vec, T *item)
{
	QASSERT(100101, vec);
	QASSERT(100102, item);
	size_t idx = ((size_t)(item) - (size_t)&vec->front())/sizeof(T);
	QASSERT(100103, (idx<vec->size()) && (idx>=0));
	return idx;
}


size_t get_idx_of_lvar(vdui_t &vu, lvar_t *lvar);
tinfo_t getType4Name(const char *name, bool funcType = false);

#define is64bit()  inf_is_64bit()
#define ea_size  ((is64bit() && !isIlp32()) ? 8 : 4)
#define isX86() (PH.id == PLFM_386)
#define isARM() (PH.id == PLFM_ARM)

bool is_ea(flags64_t flg);
ea_t get_ea(ea_t ea);
void create_type_from_size(tinfo_t* t, asize_t size);
void stripName(qstring* name, bool funcSuffixToo = false);
void stripNum(qstring* name);
int namecmp(const char* name, const char* cmpWith);
qstring good_udm_name(const tinfo_t &struc, uint64 offInBits, const char *format, ...);
#if IDA_SDK_VERSION < 850
qstring good_smember_name(const struc_t* sptr, ea_t offset, const char *format, ...);
#endif

void patch_str(ea_t ea, const char *str, sval_t len, bool forceZeroTerm = false);
void patch_wstr(ea_t ea, const char *str, sval_t len);
void patch_wstr(ea_t ea, const wchar16_t *str, sval_t len, bool forceZeroTerm = false);

bool jump_custom_viewer(TWidget *custom_viewer, int line, int x, int y);

bool isWnd();
bool appendComment(qstring &comments, qstring &newCmt, bool bDuplicable = false);
bool setComment4Exp(cfunc_t* func, user_cmts_t *cmts, citem_t *expr, const char* comment, bool bDisasmOnly = false, bool bSemicolonCmt = false, bool bOverride = false);
tinfo_t getCallInfo(cexpr_t *call, ea_t* dstea);
void replace_colortag_inplace(char *line, int pos, char prefix, char find, char replace);
void replaceExp(const cfunc_t *func, cexpr_t *expr, cexpr_t *newExp, bool clean = true);
qstring printExp(const cfunc_t *func, cexpr_t *expr);
void printExp2Msg(const cfunc_t *func, cexpr_t *expr, const char* mesg);
void dump_ctree(cfunc_t* func, const char* fname);
inline THREAD_SAFE bool isRegOvar(mopt_t mop) { return mop == mop_r || mop == mop_S /*|| mop == mop_l*/; }
inline THREAD_SAFE cexpr_t* skipCast(cexpr_t* e) {if(e->op == cot_cast) return e->x; return e;}
inline THREAD_SAFE bool isRenameble(ctype_t ct) {	return (ct == cot_var || ct == cot_obj || ct == cot_memptr || ct == cot_memref);}
inline THREAD_SAFE bool isDummyType(type_t t) { return is_type_partial(t) ||  get_full_type(t) == ((is64bit() ? BT_INT64 : BT_INT32) | BTMT_UNKSIGN);}

struct qstr_printer_t : public vd_printer_t
{
	bool strip_tags;
	size_t cnt = 0;
	size_t maxcnt;
	qstring &s;
	qstr_printer_t(qstring &_s, bool _strip_tags = true, size_t _maxcnt = 0) : strip_tags(_strip_tags), maxcnt(_maxcnt), s(_s) {}
	virtual ~qstr_printer_t() {}
	AS_PRINTF(3, 4) int hexapi print(int indent, const char *format, ...)
	{
		if(maxcnt && ++cnt > maxcnt)
			return 0;

		va_list va;
		va_start(va, format);
		size_t oldsz = s.size();
		if(indent)
			s.resize(s.size() + indent, ' ');
		if (strip_tags) {
			qstring curline;
			curline.vsprnt(format, va);
			tag_remove(&curline);
			s.append(curline);
		} else {
			s.cat_vsprnt(format, va);
		}
		va_end(va);
		return (int)(s.size() - oldsz);
	}
};

enum LogLevel {
	llError,
	llWarning,
	llNotice,
	llInfo,
	llDebug,
	llFlood
};
void LogLevelNames(qstrvec_t *v);
int Log(LogLevel level, const char *fmt, ...);
int LogTail(LogLevel level, const char *fmt, ...);

template< class IsUniqueFunc >
qstring unique_name(const char* name, const char* separator, IsUniqueFunc isUnique)
{
	qstring uName = name;
	for(int i = 1; i < 1000; i++) {
		if(isUnique(uName))
			return uName;
		uName = name;
		uName.cat_sprnt("%s%d", separator, i);
	}
	Log(llError, "FIXME! unique_name '%s' is not unique\n", uName.c_str());
	return uName;
}

