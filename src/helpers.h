/*
    Copyright © 2017-2024 AO Kaspersky Lab

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
#if IDA_SDK_VERSION < 900
#include <struct.hpp>
#endif
#include "warn_on.h"


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

#if IDA_SDK_VERSION < 900
#define interactive_graph_t mutable_graph_t
#define get_named_type_tid(x) get_struc_id(x)
#define get_tid_name(x, y) get_struc_name(x, y)
#endif // IDA_SDK_VERSION < 900

#if IDA_SDK_VERSION < 840
  #define udm_t udt_member_t
  #define find_udm find_udt_member
#endif // IDA_SDK_VERSION < 840

#if IDA_SDK_VERSION < 830
#define flags64_t flags_t
#endif // IDA_SDK_VERSION < 830

#if IDA_SDK_VERSION < 750
#define COMPAT_register_and_attach_to_menu(a,b,c,d,e,f,g) register_and_attach_to_menu(a,b,c,d,e,f,g)
#define COMPAT_open_pseudocode_REUSE(a) open_pseudocode(a, 0);
#define COMPAT_open_pseudocode_REUSE_ACTIVE(a) open_pseudocode(a, -1);
#define COMPAT_open_pseudocode_NEW(a) open_pseudocode(a, 1);
#define PH ph
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

#if IDA_SDK_VERSION < 730
#define inf_set_appcall_options(x) inf.appcall_options = x
#define inf_is_64bit()             inf.is_64bit()
#define inf_get_start_ea()         inf.start_ea
#define inf_get_min_ea()           inf.min_ea
#define inf_get_max_ea()           inf.max_ea
#define inf_get_omin_ea()          inf.omin_ea
#define inf_get_omax_ea()          inf.omax_ea
#define inf_show_xref_fncoff()     (inf.s_xrefflag & SW_XRFFNC)
#define inf_show_xref_seg()        (inf.s_xrefflag & SW_SEGXRF)
#define inf_get_filetype()         ((filetype_t)(inf.filetype))
#define inf_get_cc_defalign()      inf.cc.defalign
#define WOPN_DP_TAB                WOPN_TAB
#define REFRESH_FUNC_CTEXT(pvu)    pvu->refresh_view(false)
#else //IDA_SDK_VERSION >= 730
#define REFRESH_FUNC_CTEXT(pvu)    pvu->cfunc->refresh_func_ctext()
#endif //IDA_SDK_VERSION < 730

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
tinfo_t getType4Name(const char *name);

#define is64bit()  inf_is_64bit()
#define is32bit()  inf_is_32bit()
#define ea_size  (is64bit() ? 8 : 4)


bool isX86();

bool is_ea(flags64_t flg);
ea_t get_ea(ea_t ea);
void create_type_from_size(tinfo_t* t, asize_t size);
void stripName(qstring* name);
void stripNum(qstring* name);
int namecmp(const char* name, const char* cmpWith);

void patch_str(ea_t ea, const char *str, sval_t len, bool forceZeroTerm = false);
void patch_wstr(ea_t ea, const char *str, sval_t len);
void patch_wstr(ea_t ea, const wchar16_t *str, sval_t len, bool forceZeroTerm = false);

bool jump_custom_viewer(TWidget *custom_viewer, int line, int x, int y);

bool isWnd();
bool appendComment(qstring &comments, qstring &newCmt, bool bDuplicable = false);
bool setComment4Exp(cfunc_t* func, user_cmts_t *cmts, cexpr_t *expr, const char* comment, bool bDisasmOnly = false, bool bSemicolonCmt = false, bool bOverride = false);
tinfo_t getCallInfo(cexpr_t *call, ea_t* dstea);
void replace_colortag_inplace(char *line, int pos, char prefix, char find, char replace);
void replaceExp(const cfunc_t *func, cexpr_t *expr, cexpr_t *newExp, bool clean = true);
qstring printExp(const cfunc_t *func, cexpr_t *expr);
void printExp2Msg(const cfunc_t *func, cexpr_t *expr, const char* mesg);
void dump_ctree(cfunc_t* func, const char* fname);
inline THREAD_SAFE bool isRegOvar(mopt_t mop) { return mop == mop_r || mop == mop_S /*|| mop == mop_l*/; }
