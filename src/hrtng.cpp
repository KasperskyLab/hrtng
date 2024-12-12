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

// Evolution of hexrays_tools.cpp from https://github.com/nihilus/hexrays_tools
// there is almost no original code left

#include "warn_off.h"
#include <pro.h>
#include <prodir.h>
#include <hexrays.hpp>
#include <kernwin.hpp>
#include <frame.hpp>
#include <dbg.hpp>
#include <diskio.hpp>
#include <strlist.hpp>
#include <intel.hpp>
#include <graph.hpp>
#include <offset.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "structures.h"
#include "cast.h"
#include "lit.h"
#include "decr.h"
#include "appcall.h"
#include "appcall_view.h"
#include "rename.h"
#include "comhelper.h"
#include "apihashes.h"
#include "deinline.h"
#include "deob.h"
#include "unflat.h"
#include "opt.h"
#include "MicrocodeExplorer.h"
#include "msig.h"

#if IDA_SDK_VERSION >= 750
#include "microavx.h"
#endif // IDA_SDK_VERSION >= 750

#if IDA_SDK_VERSION < 760
hexdsp_t *hexdsp = NULL;
#endif //IDA_SDK_VERSION < 760

bool is_call(vdui_t *vu, cexpr_t **call);
bool is_recastable(vdui_t *vu, tinfo_t * ts);
bool is_stack_var_assign(vdui_t *vu, int* varIdx, ea_t *ea, sval_t* size);
bool is_array_char_assign(vdui_t *vu, int* varIdx, ea_t *ea);
bool is_decryptable_obj(vdui_t *vu, ea_t *ea);
bool is_number(vdui_t *vu);
bool is_gap_field(vdui_t *vu, tinfo_t *ts, udm_t* memb);
bool is_patched();
bool create_dec_file();
bool is_VT_assign(vdui_t *vu, tid_t *struc_id, ea_t *vt_ea);
bool has_if42blocks(ea_t funcea);

//-------------------------------------------------------------------------
// action_handler_t declarations
#define AST_ENABLE_ALW return AST_ENABLE_ALWAYS
#define AST_ENABLE_FOR_PC return ((ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET)
#define AST_ENABLE_FOR(check) vdui_t *vu = get_widget_vdui(ctx->widget); return ((vu == NULL) ? AST_DISABLE_FOR_WIDGET : ((check) ? AST_ENABLE : AST_DISABLE))

//actions attached to main menu
ACT_DECL(create_dummy_struct, AST_ENABLE_ALW)
ACT_DECL(offsets_tbl, return ((ctx->widget_type == BWN_DISASM) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(fill_nops, return ((ctx->widget_type == BWN_DISASM) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(searchNpatch, return ((ctx->widget_type == BWN_DISASM) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(dbg_patch, return ((ctx->widget_type != BWN_DISASM) ? AST_DISABLE_FOR_WIDGET : (is_debugger_on() ? AST_ENABLE : AST_DISABLE)))
ACT_DECL(file_patch, return ((ctx->widget_type == BWN_DISASM) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(msigLoad, AST_ENABLE_ALW)
ACT_DECL(msigSave, AST_ENABLE_ALW)
ACT_DECL(apihashes, AST_ENABLE_ALW)
ACT_DECL(create_dec, return (is_patched() ? AST_ENABLE : AST_DISABLE))
ACT_DECL(clear_hr_cache, AST_ENABLE_ALW)
ACT_DECL(decomp_obfus, return ((ctx->widget_type == BWN_DISASM || ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(jmp2xref, return ((ctx->widget_type == BWN_DISASM || ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
//ACT_DECL(kill_toolbars, AST_ENABLE_ALW)

//dynamically attached actions
#if IDA_SDK_VERSION < 900
ACT_DECL(convert_to_golang_call , AST_ENABLE_FOR(vu->item.citype == VDI_FUNC))
#endif // IDA_SDK_VERSION < 900
ACT_DECL(convert_to_usercall , AST_ENABLE_FOR(vu->item.citype == VDI_FUNC))
ACT_DECL(jump_to_indirect_call  , AST_ENABLE_FOR(is_call(vu, NULL)))
ACT_DECL(zeal_doc_help       , AST_ENABLE_FOR(is_call(vu, NULL)))
ACT_DECL(add_VT              , AST_ENABLE_FOR(is_VT_assign(vu, NULL, NULL)));
ACT_DECL(add_VT_struct       , return ((ctx->widget_type != BWN_DISASM) ? AST_DISABLE_FOR_WIDGET : (((is_data(get_flags(ctx->cur_ea)) && is_func(get_flags(get_ea(ctx->cur_ea))))) ? AST_ENABLE : AST_DISABLE)))
ACT_DECL(recast_item             ,  AST_ENABLE_FOR(is_recastable(vu, NULL)))
ACT_DECL(scan_stack_string       , AST_ENABLE_FOR(is_stack_var_assign(vu, NULL, NULL, NULL)))
ACT_DECL(scan_stack_string_n_decr, AST_ENABLE_FOR(is_stack_var_assign(vu, NULL, NULL, NULL)))
ACT_DECL(scan_array_string       , AST_ENABLE_FOR(is_array_char_assign(vu, NULL, NULL)))
ACT_DECL(decrypt_string_obj      , AST_ENABLE_FOR(is_decryptable_obj(vu, NULL)))
ACT_DECL(decrypt_const           , AST_ENABLE_FOR(is_number(vu)))
ACT_DECL(decrypt_data, flags64_t flg; return ((ctx->widget_type != BWN_DISASM) ? AST_DISABLE_FOR_WIDGET : ((flg = get_flags(ctx->cur_ea), /*has_value(flg) &&*/ (is_data(flg) || is_unknown(flg))) ? AST_ENABLE : AST_DISABLE)))
ACT_DECL(do_appcall              , AST_ENABLE_FOR(is_appcallable(vu, NULL, NULL)))
ACT_DECL(convert_gap             , AST_ENABLE_FOR(is_gap_field(vu, NULL, NULL)))
ACT_DECL(disable_inlines         , AST_ENABLE_FOR(hasInlines(vu, NULL)))
ACT_DECL(enable_inlines          , AST_ENABLE_FOR(hasInlines(vu, NULL)))
ACT_DECL(rename_inline           , AST_ENABLE_FOR(is_nlib_inline(vu)))
ACT_DECL(create_inline_gr        , return ((ctx->widget_type != BWN_DISASM) ? AST_DISABLE_FOR_WIDGET : ((get_view_renderer_type(ctx->widget) == TCCRT_GRAPH) ? AST_ENABLE : AST_DISABLE)))
ACT_DECL(create_inline_sel       , return ((ctx->widget_type != BWN_PSEUDOCODE && ctx->widget_type != BWN_DISASM) ?  AST_DISABLE_FOR_WIDGET : (ctx->has_flag(ACF_HAS_SELECTION) ?  AST_ENABLE : AST_DISABLE)))
ACT_DECL(uf_enable               , AST_ENABLE_FOR(ufIsInGL(vu->mba->entry_ea)))
ACT_DECL(uf_disable              , AST_ENABLE_FOR(ufIsInWL(vu->mba->entry_ea)))
#if IDA_SDK_VERSION >= 750
ACT_DECL(mavx_enable             , AST_ENABLE_FOR(isMicroAvx_avail() && !isMicroAvx_active()))
ACT_DECL(mavx_disable            , AST_ENABLE_FOR(isMicroAvx_avail() &&  isMicroAvx_active()))
#endif //IDA_SDK_VERSION >= 750
ACT_DECL(msigAdd                 , AST_ENABLE_FOR_PC)
ACT_DECL(selection2block         , return (ctx->widget_type != BWN_PSEUDOCODE ? AST_DISABLE_FOR_WIDGET : (ctx->has_flag(ACF_HAS_SELECTION) ? AST_ENABLE : AST_DISABLE)))
ACT_DECL(clear_if42blocks         , AST_ENABLE_FOR(has_if42blocks(vu->cfunc->entry_ea)))

#undef AST_ENABLE_FOR
#undef AST_ENABLE_FOR_PC
#undef AST_ENABLE_ALW

//-------------------------------------------------------------------------
// action_desc_t descriptions
static const action_desc_t actions[] =
{
#if IDA_SDK_VERSION < 900
	ACT_DESC("[hrt] Convert to __usercall golang",   "Shift-G", convert_to_golang_call),
#endif //IDA_SDK_VERSION < 900
	ACT_DESC("[hrt] Convert to __usercall",          "U", convert_to_usercall),
	ACT_DESC("[hrt] Jump to indirect call",          "J", jump_to_indirect_call),
	ACT_DESC("[hrt] Zeal offline API help (zealdocs.org)",  "Ctrl-F1", zeal_doc_help),
	ACT_DESC("[hrt] Add VT",                         NULL, add_VT),
	ACT_DESC("[hrt] Add VT struct",                  NULL, add_VT_struct),
	ACT_DESC("[hrt] Recast item",                    "R", recast_item),
	ACT_DESC("[hrt] Build stack string",             "B", scan_stack_string),
	ACT_DESC("[hrt] Build stack string and decrypt", "Shift-B", scan_stack_string_n_decr),
	ACT_DESC("[hrt] Build array string and decrypt", "A", scan_array_string),
	ACT_DESC("[hrt] Decrypt string",                 "D", decrypt_string_obj),
  ACT_DESC("[hrt] Decrypt imm const",              "D", decrypt_const),
  ACT_DESC("[hrt] Decrypt data",                   "Shift-D", decrypt_data),
	ACT_DESC("[hrt] Mass strings decryption",        "A", do_appcall),
	ACT_DESC("[hrt] Fix field at struct gap",         "F", convert_gap),
	ACT_DESC("[hrt] Disable inlines",                NULL, disable_inlines),
	ACT_DESC("[hrt] Enable inlines",                 NULL, enable_inlines),
	ACT_DESC("[hrt] Rename inline...",                "N", rename_inline),
	ACT_DESC("[hrt] Create 'inline' from grouped nodes",  NULL, create_inline_gr),
	ACT_DESC("[hrt] Create 'inline' from selection",  NULL, create_inline_sel),
	ACT_DESC("[hrt] Enable Unflattener",              NULL, uf_enable),
	ACT_DESC("[hrt] Disable Unflattener",             NULL, uf_disable),
#if IDA_SDK_VERSION >= 750
  ACT_DESC("[hrt] Enable AVX lifter",              NULL, mavx_enable),
	ACT_DESC("[hrt] Disable AVX lifter",             NULL, mavx_disable),
#endif //IDA_SDK_VERSION >= 750
	ACT_DESC("[hrt] Create MSIG for the function",    NULL, msigAdd),
	ACT_DESC("[hrt] ~C~ollapse selection",              NULL, selection2block),
	ACT_DESC("[hrt] Remove collapsible 'if(42) ...' blocks",  NULL, clear_if42blocks),
};

//-------------------------------------------------------------------------

void add_hrt_popup_items(TWidget *view, TPopupMenu *p, vdui_t* vu)
{
	if (vu->item.citype == VDI_FUNC) {
		attach_action_to_popup(view, p, ACT_NAME(convert_to_usercall));
#if IDA_SDK_VERSION < 900
		attach_action_to_popup(view, p, ACT_NAME(convert_to_golang_call));
#endif //IDA_SDK_VERSION < 900
	}
	if(is_call(vu, NULL))
		attach_action_to_popup(view, p, ACT_NAME(zeal_doc_help));
	if(is_VT_assign(vu, NULL, NULL))
		attach_action_to_popup(view, p, ACT_NAME(add_VT));

	if (can_be_reincast(vu))
		attach_action_to_popup(view, p, ACT_NAME(insert_reinterpret_cast));
	else if (is_reincast(vu))
		attach_action_to_popup(view, p, ACT_NAME(delete_reinterpret_cast));

	if (is_recastable(vu, NULL))
		attach_action_to_popup(view, p, ACT_NAME(recast_item));
	
	if (is_stack_var_assign(vu, NULL, NULL, NULL)) {
		attach_action_to_popup(view, p, ACT_NAME(scan_stack_string));
		attach_action_to_popup(view, p, ACT_NAME(scan_stack_string_n_decr));
	} else if (is_array_char_assign(vu, NULL, NULL)) {
		attach_action_to_popup(view, p, ACT_NAME(scan_array_string));
	}

	if (is_decryptable_obj(vu, NULL))
		attach_action_to_popup(view, p, ACT_NAME(decrypt_string_obj));
	if (is_appcallable(vu, NULL, NULL))
		attach_action_to_popup(view, p, ACT_NAME(do_appcall));
	if (is_number(vu)) {
		attach_action_to_popup(view, p, ACT_NAME(decrypt_const));
	}
	else if (is_gap_field(vu, NULL, NULL))
		attach_action_to_popup(view, p, ACT_NAME(convert_gap));
	attach_action_to_popup(view, p, ACT_NAME(jump_to_indirect_call));
	bool bEnabled;
	if (hasInlines(vu, &bEnabled)) {
		if (bEnabled) {
			if(is_nlib_inline(vu))
				attach_action_to_popup(view, p, ACT_NAME(rename_inline));
			attach_action_to_popup(view, p, ACT_NAME(disable_inlines));
		} else {
			attach_action_to_popup(view, p, ACT_NAME(enable_inlines));
		}
	}
	attach_action_to_popup(view, p, ACT_NAME(create_inline_sel));
	if(ufIsInGL(vu->mba->entry_ea))
		attach_action_to_popup(view, p, ACT_NAME(uf_enable));
	else if (ufIsInWL(vu->mba->entry_ea))
		attach_action_to_popup(view, p, ACT_NAME(uf_disable));
	attach_action_to_popup(view, p, ACT_NAME(msigAdd));
#if IDA_SDK_VERSION >= 750
	if(isMicroAvx_avail()) {
		if(isMicroAvx_active())
			attach_action_to_popup(view, p, ACT_NAME(mavx_disable));
		else
			attach_action_to_popup(view, p, ACT_NAME(mavx_enable));
	}
#endif //IDA_SDK_VERSION >= 750
	attach_action_to_popup(view, p, ACT_NAME(selection2block));
	if (has_if42blocks(vu->cfunc->entry_ea))
		attach_action_to_popup(view, p, ACT_NAME(clear_if42blocks));
}

void hrt_reg_act()
{
	COMPAT_register_and_attach_to_menu("Edit/Structs/Create struct from selection", ACT_NAME(create_dummy_struct), "[hrt] Create dummy struct...", "Shift+S", SETMENU_INS, &create_dummy_struct, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Edit/Operand type/Offset/Offset (data segment)", ACT_NAME(offsets_tbl), "[hrt] Offsets table", "Shift+O", SETMENU_INS, &offsets_tbl, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Edit/Patch program/Assemble...", ACT_NAME(fill_nops), "[hrt] Fill nops...", NULL, SETMENU_INS, &fill_nops, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Edit/Patch program/Assemble...", ACT_NAME(searchNpatch), "[hrt] Search & Patch...", NULL, SETMENU_INS, &searchNpatch, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Edit/Patch program/Assemble...", ACT_NAME(dbg_patch), "[hrt] Patch from debugger...", NULL, SETMENU_INS, &dbg_patch, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Edit/Patch program/Assemble...", ACT_NAME(file_patch), "[hrt] Patch from file...", NULL, SETMENU_INS, &file_patch, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Edit/Other/", ACT_NAME(apihashes), "[hrt] Turn on API~h~ashes scan...", NULL, SETMENU_INS, &apihashes, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Edit/Other/", ACT_NAME(clear_hr_cache), "[hrt] Clear cached decompilation results", "`", SETMENU_INS, &clear_hr_cache, &PLUGIN);
	COMPAT_register_and_attach_to_menu("File/Produce file/Create MAP file...", ACT_NAME(create_dec), "[hrt] Create DEC file...", NULL, SETMENU_INS, &create_dec, &PLUGIN);
	COMPAT_register_and_attach_to_menu("File/Produce file/Create MAP file...", ACT_NAME(msigSave), "[hrt] Create MSIG file...", NULL, SETMENU_INS, &msigSave, &PLUGIN);
	COMPAT_register_and_attach_to_menu("File/Load file/PDB file...", ACT_NAME(msigLoad), "[hrt] MSIG file...", NULL, SETMENU_INS, &msigLoad, &PLUGIN);
	//COMPAT_register_and_attach_to_menu("View/Toolbars", ACT_NAME(kill_toolbars), "[hrt] Kill toolbars", NULL, SETMENU_INS, &kill_toolbars, &PLUGIN);
	COMPAT_register_and_attach_to_menu("View/Open subviews/Generate pseudocode", ACT_NAME(decomp_here), "[hrt] Decompile obfuscated code", "Alt-F5", SETMENU_APP, &decomp_obfus, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Jump/Jump to xref to operand...", ACT_NAME(jmp2xref), "[hrt] Jump to xref Ex...", "Shift-X", SETMENU_APP, &jmp2xref, &PLUGIN);

	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		register_action(actions[i]);

	//kill duplicating shortcut, we will call it directly on same shortcut in appropriate cases
	qstring shortcut;
	if(get_action_shortcut(&shortcut, "hx:JumpGlobalXref") && !qstrcmp("Shift-X", shortcut.c_str()))
		update_action_shortcut("hx:JumpGlobalXref", NULL);
}

void hrt_unreg_act()
{
	detach_action_from_menu("Edit/Structs/[hrt] Create dummy struct...", ACT_NAME(create_dummy_struct));
	detach_action_from_menu("Edit/Operand type/Offset/[hrt] Offsets table", ACT_NAME(offsets_tbl));
	detach_action_from_menu("Edit/Patch program/[hrt] Fill nops...", ACT_NAME(fill_nops));
	detach_action_from_menu("Edit/Patch program/[hrt] Search & Patch...", ACT_NAME(searchNpatch));
	detach_action_from_menu("Edit/Patch program/[hrt] Patch from debugger...", ACT_NAME(dbg_patch));
	detach_action_from_menu("Edit/Patch program/[hrt] Patch from file...", ACT_NAME(file_patch));
	detach_action_from_menu("Edit/Other/[hrt] Turn on APIhashes scan...", ACT_NAME(apihashes));
	detach_action_from_menu("Edit/Other/[hrt] Clear cached decompilation results", ACT_NAME(clear_hr_cache));
	detach_action_from_menu("File/Produce file/[hrt] Create DEC file...", ACT_NAME(create_dec));
	detach_action_from_menu("File/Produce file/[hrt] Create MSIG file...", ACT_NAME(msigSave));
	detach_action_from_menu("File/Load file/[hrt] MSIG file...", ACT_NAME(msigLoad));
	//detach_action_from_menu("View/[hrt] Kill toolbars", ACT_NAME(kill_toolbars));
	detach_action_from_menu("View/Open subviews/[hrt] Decompile obfuscated code", ACT_NAME(decomp_obfus));
	detach_action_from_menu("Jump/[hrt] Jump to xref Ex...", ACT_NAME(jmp2xref));

	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		unregister_action(actions[i].name);
	//unregister_action(ACT_NAME(kill_toolbars));
	unregister_action(ACT_NAME(create_dec));
	unregister_action(ACT_NAME(apihashes));
	unregister_action(ACT_NAME(msigLoad));
	unregister_action(ACT_NAME(msigSave));
	unregister_action(ACT_NAME(dbg_patch));
	unregister_action(ACT_NAME(file_patch));
	unregister_action(ACT_NAME(searchNpatch));
	unregister_action(ACT_NAME(fill_nops));
	unregister_action(ACT_NAME(offsets_tbl));
	unregister_action(ACT_NAME(create_dummy_struct));
}
//-------------------------------------------------------------------------

static int idaapi jump_to_call_dst(vdui_t *vu)
{
	if(!vu->item.is_citem())
		return 0;

	// call => cast => memptr/obj/var
	const citem_t *call = vu->cfunc->body.find_parent_of(vu->item.e);
	if(call && call->op == cot_cast)
		call = vu->cfunc->body.find_parent_of(call);
	if(!call || call->op != cot_call)
		return 0;

	// jump to VT address in struct comment
	ea_t dst_ea = BADADDR;
	cexpr_t *e = vu->item.e;
	if (e->op == cot_memptr || e->op == cot_memref) {
		int offset = e->m;
		if (e->x->op == cot_idx)
			e = e->x;
		cexpr_t *var = e->x;
		tinfo_t t = var->type;
		while (t.is_ptr_or_array())
			t.remove_ptr_or_array();
		if (t.is_struct()) {
#if IDA_SDK_VERSION >= 900
			// actually get_vftable_ea is appeared in ida 7.6 but here will be used from ida9 becouse it probably depends on TAUDT_VFTABLE flag has been set in create_VT_struc
			// get destination from vftable_ea
			auto tid = t.get_tid();
			if(tid != BADADDR) {
				auto vt_ea = get_vftable_ea(get_tid_ordinal(tid));
				if (vt_ea != BADADDR) {
					ea_t fnc = get_ea(vt_ea + offset);
					if (is_func(get_flags(fnc))) {
						dst_ea = fnc;
					}
				}
			}
#endif //IDA_SDK_VERSION > 760
			// get destination from structure comment
			qstring sname;
			if(dst_ea == BADADDR && t.get_type_name(&sname)) {
#if IDA_SDK_VERSION < 900
				tid_t id = get_struc_id(sname.c_str());
				if(id != BADNODE) {
					qstring comment;
					get_struc_cmt(&comment, id, true);
#else //IDA_SDK_VERSION >= 900
				qstring comment;
				if (t.get_type_rptcmt(&comment)) {
#endif //IDA_SDK_VERSION < 900
					ea_t vt_ea;
					if (at_atoea(comment.c_str(), &vt_ea)) {
						ea_t fnc = get_ea(vt_ea + offset);
						// it may be structure has been imported from another idb (when looking another malware version)
						// so addresses in comments may be wrong
						if (is_func(get_flags(fnc))) {
							dst_ea = fnc;
						}
					}
				}
			}
		}
	}

	// jump to name, if callee is clicked. But pass globals handling to IDA because getExpName may strips suffix of name and jump to wrong dest
	cexpr_t *callee = ((cexpr_t*)call)->x;
	if(callee->op == cot_cast)
		callee = callee->x;
	if(dst_ea == BADADDR && vu->item.e == callee && callee->op != cot_obj) {
		qstring callname;
		if(getExpName(vu->cfunc, callee, &callname))
			dst_ea = get_name_ea(BADADDR, callname.c_str());
	}

	if (dst_ea != BADADDR && is_func(get_flags(dst_ea))) {
		if(call->ea != BADADDR)
			add_cref(call->ea, dst_ea, fl_CN);
		COMPAT_open_pseudocode_REUSE_ACTIVE(dst_ea);
		return 1;
	}
	//pass unhandled action to IDA
	return 0;
}

ACT_DEF(jump_to_indirect_call)
{
	return jump_to_call_dst(get_widget_vdui(ctx->widget));
}

//-------------------------------------------------------------------------

static const char create_dec_idc_args[] = { 0 };
static error_t idaapi create_dec_idc(idc_value_t *argv, idc_value_t *res)
{
	msg("[hrt] create_dec is called \n");
	if(create_dec_file())
		return eOk;
	return eOS;
}
static const ext_idcfunc_t create_dec_desc = { "create_dec", create_dec_idc, create_dec_idc_args, NULL, 0, EXTFUN_BASE };

static const char dump_strings_idc_args[] = { 0 };
static error_t idaapi dump_strings_idc(idc_value_t *argv, idc_value_t *res)
{
#if IDA_SDK_VERSION < 760
	strwinsetup_t *strwinsetup = get_strlist_options();
	if(strwinsetup) {
		strwinsetup->only_7bit = 1;
		strwinsetup->display_only_existing_strings = 1;
		strwinsetup->minlen = 5;
		strwinsetup->strtypes.clear();
		strwinsetup->strtypes.push_back(STRTYPE_C);
		strwinsetup->strtypes.push_back(STRTYPE_C_16);
#endif //IDA_SDK_VERSION < 760
		build_strlist();
		size_t qty = get_strlist_qty();
		uint32 cnt = 0;
		for(size_t i = 0; i < qty; i++) {
			string_info_t si;
			if(get_strlist_item(&si, i) && si.ea != BADADDR && si.length) {
				qstring str;
				if( 0 < get_strlit_contents(&str, si.ea, si.length, si.type, NULL, STRCONV_ESCAPE)) {
					//msg("[hrt] dump_strings: %a: %s\n", si.ea, str.c_str());
					cnt++;
					qprintf("%s\n", str.c_str());
				}
			}
		}
		msg("[hrt] dump_strings: %u of %u printed\n", cnt, (uint32)qty);
		return eOk;
#if IDA_SDK_VERSION < 760
	}
	msg("[hrt] dump_strings: err\n");
	return eOS;
#endif //IDA_SDK_VERSION < 760
}
static const ext_idcfunc_t dump_strings_desc = { "dump_strings", dump_strings_idc, dump_strings_idc_args, NULL, 0, EXTFUN_BASE };

static const char dump_comments_idc_args[] = { 0 };

#if IDA_SDK_VERSION < 830
bool idaapi isCommented(flags64_t flags, void *ud)
#else
bool idaapi isCommented(flags64_t flags, void *ud)
#endif //IDA_SDK_VERSION < 830
{
	return has_cmt(flags);
}
static error_t idaapi dump_comments_idc(idc_value_t *argv, idc_value_t *res)
{
	//msg("[hrt] dump_comments is called \n");
	for(ea_t ea = inf_get_min_ea(); ea < inf_get_max_ea(); ea = next_that(ea, inf_get_max_ea(), isCommented)) {
		qstring str;
		//color_t cmttype;
		if(0 < get_cmt(&str, ea, false) || 0 < get_cmt(&str, ea, true)) {
			qprintf("%a: %s\n", ea, str.c_str());
			//qprintf("%s\n", str.c_str());
		}
	}
	return eOk;
}
static const ext_idcfunc_t dump_comments_desc = { "dump_comments", dump_comments_idc, dump_comments_idc_args, NULL, 0, EXTFUN_BASE };

static const char dump_names_idc_args[] = { 0 };
static error_t idaapi dump_names_idc(idc_value_t *argv, idc_value_t *res)
{
	qprintf("\n[hrt] <<<<<<<<<<          IDB NAMES          >>>>>>>>>>\n");
	//rebuild_nlist();
	size_t qty = get_nlist_size();
	uint32 cnt = 0;
	for(size_t i = 0; i < qty; i++) {
		ea_t ea =  get_nlist_ea(i);
		flags64_t f = get_flags(ea);
		if(!has_user_name(f)
			 || is_strlit(f)                // skip string autogenerated names
			 )
			 continue;

		// library and thunk funcs and local labels inside
		if(is_code(f)) {
			func_t* f = get_func(ea);
			if(f && (f->flags & (FUNC_LIB | FUNC_THUNK)))
				continue;
		}

		// dummy prefix
		const char* name = get_nlist_name(i);
		if(!is_uname(name)
			 || !strncmp(name, "jpt_", 4)   // jump table
			 || !strncmp(name, "def_", 4)   // jump table default case
			 || !strncmp(name, "__imp_", 6) // import
			 || !strncmp(name, "??_R", 4)   // RTTI
			 || !strncmp(name, "__TI", 4)   // ThrowInfo
			 || !strncmp(name, "__CT", 4)   // catchable type addresses
			 )
			continue;

		// IAT and other function pointers
		if(is_ea(f)) {
			qstring nn = name;
			stripName(&nn);
			const type_t *type;
			if(get_named_type(NULL, nn.c_str(), 0, &type) && is_type_func(*type))
				continue;
		}

		cnt++;
		qprintf("%s\n", name);
	}
	msg("[hrt] dump_names: %u of %u printed\n", cnt, (uint32)qty);
	return eOk;
}
static const ext_idcfunc_t dump_names_desc = { "dump_names", dump_names_idc, dump_names_idc_args, NULL, 0, EXTFUN_BASE };
void register_idc_functions()
{
	add_idc_func(create_dec_desc);
	add_idc_func(dump_strings_desc);
	add_idc_func(dump_comments_desc);
	add_idc_func(dump_names_desc);
}

void unregister_idc_functions()
{
	del_idc_func(create_dec_desc.name);
	del_idc_func(dump_strings_desc.name);
	del_idc_func(dump_comments_desc.name);
	del_idc_func(dump_names_desc.name);
}

//-------------------------------------------------------------------------
//be aware, is_call returns true if the cursor is inside call's arguments zone too, as well as in callee expression
bool is_call(vdui_t *vu, cexpr_t **call)
{
	if (!vu->item.is_citem())
		return false;

	citem_t *it = vu->item.it;
	while (it && it->op <= cot_last) {
		if(it->op == cot_call) {
			if(call)
				*call = (cexpr_t *)it;
			return true;
		}
		it = vu->cfunc->body.find_parent_of(it);
	}
	return false;
}

ACT_DEF(zeal_doc_help)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	cexpr_t *call;
	qstring name;
	if(!is_call(vu, &call) || !getExpName(vu->cfunc, call->x, &name) || name.length() < 3)
		return 0;

	stripName(&name);
	if (name.last() == 'A' || name.last() == 'W')
		name.remove_last();

	name.insert(0, "zeal ");

  launch_process_params_t lpp;
  lpp.flags = LP_USE_SHELL;
  lpp.args = name.c_str();

  qstring errbuf;
  if(launch_process(lpp, &errbuf) == NULL) {
    msg("[hrt] launch_process(%s) error: %s\n", lpp.args, errbuf.c_str());
    return 0;
  }
  return 1;
}

bool is_VT_assign(vdui_t *vu, tid_t *struc_id, ea_t *vt_ea)
{
	if (!vu->item.is_citem())
		return false;

	tid_t sid;
#if IDA_SDK_VERSION < 900
	struc_t *sptr;
	member_t * member = vu->item.get_memptr(&sptr);
	if(!member || member->soff != 0)
		return false;
	sid = sptr->id;
#else //IDA_SDK_VERSION >= 900
	tinfo_t parentTi;
	uint64 offset;
	if (vu->item.get_udm(NULL, &parentTi, &offset) == -1 || offset != 0)
		return false;
	sid = parentTi.get_tid();
	if (sid == BADADDR)
		return false; //parent.force_tid()
#endif //IDA_SDK_VERSION < 900

	citem_t* parent = vu->cfunc->body.find_parent_of(vu->item.i);
	if(parent->op != cot_asg)
		return false;

	cexpr_t *asg = (cexpr_t *)parent;
	cexpr_t *vt = asg->y;
	if(vt->op == cot_cast)
		vt = vt->x;
	if(vt->op == cot_ref)
		vt = vt->x;
	if (vt->op != cot_obj)
		return false;

	if(struc_id)
		*struc_id = sid;
	if(vt_ea)
		*vt_ea = vt->obj_ea;
	return true;
}

ACT_DEF(add_VT)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	tid_t struc_id;
	ea_t vt_ea;
	if(is_VT_assign(vu, &struc_id, &vt_ea) && create_VT(struc_id, vt_ea))
		REFRESH_FUNC_CTEXT(vu);
	return 0;
}

ACT_DEF(add_VT_struct)
{
	tid_t VT_struct= create_VT_struc(ctx->cur_ea, NULL);
	if(VT_struct != BADNODE)
#if IDA_SDK_VERSION < 900
		open_structs_window(VT_struct);
#else //IDA_SDK_VERSION >= 900
		open_loctypes_window(get_tid_ordinal(VT_struct));
#endif //IDA_SDK_VERSION < 900
	return 0;
}

static bool convert_cc_to_special(func_type_data_t & fti)
{
	switch(fti.cc & CM_CC_MASK)
	{
	case CM_CC_CDECL:
	case CM_CC_UNKNOWN:
		fti.cc = CM_CC_SPECIAL;
		break;
	case CM_CC_STDCALL:
	case CM_CC_PASCAL:
	case CM_CC_FASTCALL:
	case CM_CC_THISCALL:
		fti.cc = CM_CC_SPECIALP;
		break;
	case CM_CC_ELLIPSIS:
		fti.cc = CM_CC_SPECIALE;
		break;
	default:
		msg("[hrt] convert to __usercall: Unknown function cc, %x\n", fti.cc & CM_CC_MASK);
	case CM_CC_SPECIAL:
	case CM_CC_SPECIALE:
	case CM_CC_SPECIALP:
		//do nothing but return true
		break;
	}
	return true;
}

struct ida_local undef_var_locator_t : public ctree_visitor_t
{
	std::set<int> indices;
	undef_var_locator_t(): ctree_visitor_t(CV_FAST) {}
	int idaapi visit_expr(cexpr_t * e)
	{
		if(e->op == cot_var && e->is_undef_val()) {
			//msg("[hrt] undefined var (%a '%d')\n", e->ea, e->v.idx);
			indices.insert(e->v.idx);
		}
		return 0;
	}
};

void undefRegs2args(cfuncptr_t cfunc, func_type_data_t *fti)
{
	// find undefined variables (is_undef_val)
	hexwarns_t warns = cfunc->get_warnings();
	for(hexwarns_t::iterator it = warns.begin(); it != warns.end(); it++) {
		if(it->id != WARN_UNDEF_LVAR)
			continue;
		undef_var_locator_t locator;
		locator.apply_to(&cfunc->body, NULL);
		if(!locator.indices.empty()) {
			//update function typeinfo
			lvars_t* lvars = cfunc->get_lvars();
			std::set<int> registers;
			for(auto rit = fti->begin(); rit != fti->end(); rit++) {
				funcarg_t *arg = rit;
				if(arg->argloc.is_reg())
					registers.insert(arg->argloc.reg1());
				if(arg->argloc.is_reg2())
					registers.insert(arg->argloc.reg2());
			}
			for(auto it = locator.indices.begin(); it != locator.indices.end(); it++) {
				lvar_t* var= &lvars->at(*it);
				if (var->is_reg_var()) {
					int reg = str2reg(var->location.dstr());
					if(reg != -1 && registers.find(reg) == registers.end()) {
						registers.insert(reg);
						funcarg_t arg;
						arg.argloc.set_reg1(reg);
						arg.type = var->type();
						arg.name = var->name;
						var->defea = BADADDR;
						var->set_arg_var();
						fti->push_back(arg);
						msg("[hrt] undefined var '%s' is converted to function argument\n", var->name.c_str());
					}
				}
			}
		}
		break;
	}
}

void declSpoiledRegs(cfuncptr_t cfunc, func_type_data_t *fti)
{
	if(fti->is_noret() || !cfunc->mba || !isX86())
		return;

#if 0
	// simple get maybdef.reg list from block-0

	// MMAT_LOCOPT is lowest possible level where maybdef of zero block is calculated
	// !!! some temporary regs definitions may be optimized away by the local optimization
	// but the main goal here is to recognize unspoiled registers that may be used in code surrounding this function call
	// and results are better then searching spoiled registers by eyes
  mbl_array_t *mba = gen_microcode(cfunc->mba->mbr, NULL, NULL, DECOMP_NO_CACHE | DECOMP_WARNINGS, MMAT_LOCOPT);
  if(!mba || !mba->qty)
    return;
	mblock_t *blk0 = mba->get_mblock(0);
	if(blk0->type != BLT_1WAY || (blk0->flags & MBL_FAKE) == 0 || blk0->maybdef.reg.empty()) {
		delete mba;
		return;
	}
	const rlist_t &rlist = blk0->maybdef.reg;

#else
	// collect all defined registers in early mba then remove from the list registers have been save-restored

	mbl_array_t *mba = gen_microcode(cfunc->mba->mbr, NULL, NULL, DECOMP_NO_CACHE | DECOMP_WARNINGS, MMAT_PREOPTIMIZED);
  if(!mba || !mba->qty || mba->build_graph() != MERR_OK)
    return;
  mba->analyze_calls(ACFL_GUESS);

	// collect all defined registers
	rlist_t rlist;
	for (int i = 0; i < mba->qty; i++) {
		const mblock_t *blk = mba->get_mblock(i);
		for (const minsn_t *ins = blk->head; ins != NULL; ins = ins->next) {
			mlist_t def = blk->build_def_list(*ins, MUST_ACCESS);
			rlist.add(def.reg);
		}
	}
	// remove from the list registers have been save-restored
	// according ida/plugins/hexrays_sdk/verifier/showmic.cpp mblock_t::print_block_header
	// this informnation is stored in mba->procinf->sregs NOT publicly declared part of mba_t structure
	// so, the only way I've found to get it - parse full mba dump
	qstring s;
	qstr_printer_t p(s, false, 2); // need only second line of the dump
	mba->print(p); //mba->get_mblock(0)->print(p); //single block print skips header
	//msg("[hrt] %a mba:\n%s\n", cfunc->entry_ea, s.c_str());

  size_t srb = s.find("SAVEDREGS: ");
	if(srb != qstring::npos) {
		qstring sr = s.substr(srb + 11, s.find('\n', srb));
		tag_remove(&sr, 1);
		qstrvec_t rnames;
		const char *from = sr.begin();
		const char *end = sr.end();
		while(from < end) {
			const char *to =  qstrchr(from, ',');
			if(!to)
				to = end;
			rnames.push_back().append(from, to - from);
			from = to + 1;
		}
		for(size_t i = 0; i < rnames.size(); i++) {
			size_t dot = rnames[i].find('.');
			if(dot != qstring::npos) {
				qstring rname = rnames[i].substr(0, dot);
				int rsize = atoi(rnames[i].c_str() + dot + 1);
				int ireg = str2reg(rname.c_str());
				//msg("[hrt] %a : %s.%d (%d)\n", cfunc->entry_ea, rname.c_str(), rsize, ireg);
				if(ireg != -1)
					rlist.sub(reg2mreg(ireg), rsize);
			}
		}
	}
#endif

	//msg("[hrt] %a def regs: %s\n", cfunc->entry_ea, rlist.dstr());
	fti->spoiled.clear();

	//"for" below iterates each bit in bitset, I need iterate by whole registers
	//for(auto it = rlist.begin(); it != rlist.end(); rlist.inc(it))

	int rsize = ea_size;
	mreg_t mregLast = reg2mreg(R_es); //HACK: mregLast is x86 specific
	if(mregLast == mr_none)
		mregLast = is64bit() ? 128 : 100;
	for(mreg_t mreg = mr_first; mreg < mregLast; mreg += rsize) {
		if(rlist.has_any(mreg, rsize)) {
			int reg = mreg2reg(mreg, rsize);
			if(reg != -1 && reg != R_sp) { //HACK: R_sp is x86 specific
				reg_info_t ri;
				ri.size = rsize;
				ri.reg =  reg;
				fti->spoiled.push_back(ri);
			}
		}
	}
	if(fti->spoiled.empty())
		fti->flags &= ~FTI_SPOILED;
	else
		fti->flags |= FTI_SPOILED;
	delete mba;
}

ACT_DEF(convert_to_usercall)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if (!vu || !vu->cfunc || vu->cfunc->entry_ea == BADADDR)
		return 0;
	tinfo_t type;
	if (!vu->cfunc->get_func_type(&type))
		return 0;

	func_type_data_t fti;
	type.get_func_details(&fti);
	if (!convert_cc_to_special(fti))
		return 0;

	undefRegs2args(vu->cfunc, &fti);
	declSpoiledRegs(vu->cfunc, &fti);
	qstring funcname;
	get_func_name(&funcname, vu->cfunc->entry_ea);
	type.clear();
	if (!type.create_func(fti)) {
		msg("[hrt] %a %s: create func type error!\n", vu->cfunc->entry_ea, funcname.c_str());
		return 0;
	}
	qstring typestr;
	type.print(&typestr);
	if(!apply_tinfo(vu->cfunc->entry_ea, type, TINFO_DEFINITE)) {
		msg("[hrt] %a %s: apply func type error! (%s)\n", vu->cfunc->entry_ea, funcname.c_str(), typestr.c_str());
		return 0;
	}
	msg("[hrt] %a %s: converted to '%s'\n", vu->cfunc->entry_ea, funcname.c_str(), typestr.c_str());
	vu->refresh_view(true);
	return 0;
}

#if IDA_SDK_VERSION < 900
static const char GO_NETNODE_HASH_IDX[] = "hrt_golang";
static const nodeidx_t GO_NETNODE_VAL = 0xC01AC01A;
void golang_add(ea_t ea)
{
	netnode node(ea);
	node.hashdel(GO_NETNODE_HASH_IDX);
	node.hashset(GO_NETNODE_HASH_IDX, GO_NETNODE_VAL);
	msg("[hrt] %a: golang mode on\n", ea);
	
}

void golang_check(mbl_array_t *mba)
{
	netnode node(mba->entry_ea);
	if (GO_NETNODE_VAL == node.hashval_long(GO_NETNODE_HASH_IDX)) {
		mba->nodel_memory.add(mba->get_args_region());
		if(mba->mbr.pfn)
			set_func_cmt(mba->mbr.pfn, "Golang mode is on. To turn it off remove this comment and refresh view", false);
		msg("[hrt] %a: golang mode\n", mba->entry_ea);
	}
}

void golang_del(ea_t ea)
{
	netnode node(ea);
	if (GO_NETNODE_VAL == node.hashval_long(GO_NETNODE_HASH_IDX)) {
		node.hashdel(GO_NETNODE_HASH_IDX);
		msg("[hrt] %a: golang mode off\n", ea);
	}
}

ACT_DEF(convert_to_golang_call)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if (!vu.cfunc)
		return 0;
	if ( vu.cfunc->entry_ea == BADADDR )
		return 0;
	tinfo_t type;
	if (!vu.cfunc->get_func_type(&type))
		return 0;

	func_type_data_t fti;
	type.get_func_details(&fti);
	fti.cc = CM_CC_SPECIAL;
	fti.rettype.clear();
	fti.rettype.create_simple_type(BTF_VOID);

	//remove all arguments, add undefined registers
	fti.clear();
	undefRegs2args(vu.cfunc, &fti);

	//variant to work with mbl_array_t stack frame (argbase)
	bool bArgs = false;
	struc_t *fr = get_frame(vu.cfunc->entry_ea);
	ea_t argsOff = 0;
	for (uint32 i = 0; i < fr->memqty; i++) {
		member_t* m = fr->members + i;
		qstring mname = get_member_name(m->id);
		if(bArgs /*&& --stkArgs < 0*/) {
			sval_t stkoff = m->soff - argsOff;
			if(fti.size()) {
				//fix prev elem size!
				funcarg_t &prev = fti.back();
				sval_t prevBgn = prev.argloc.stkoff();
				sval_t prevEnd = prevBgn + (sval_t)prev.type.get_size();
				if(stkoff > prevEnd) {
					create_type_from_size(&prev.type, stkoff - prevBgn);
					msg("[hrt] fix arg '%s' size %a\n", prev.name.c_str(), stkoff - prevBgn);
				}
			}
			msg("[hrt] add arg '%s' at stkoff %a\n", mname.c_str(), stkoff);
			funcarg_t arg;
			arg.argloc.set_stkoff(stkoff);
			if (!get_member_type(m, &arg.type)) {
				if (is64bit())
					arg.type.create_simple_type(BT_INT64);
				else
					arg.type.create_simple_type(BT_INT32);
			}
			arg.name = mname;
			fti.push_back(arg);
		}
		if(!bArgs && mname == " r") {
			bArgs = true;
			argsOff = m->eoff;
		}
	}

	//FIXME: intel specific
	if (!isX86()) {
		msg("[hrt] FIXME: 'mark all registers as spoiled' is x86 specific\n");
	} else {
		//mark all registers as spoiled
		fti.spoiled.clear();
		reg_info_t ri; ri.size = is64bit() ? 8 : 4;
		ri.reg = R_ax; fti.spoiled.push_back(ri); // = vu.cfunc->mba->idb_spoiled;
		ri.reg = R_bx; fti.spoiled.push_back(ri);
		ri.reg = R_cx; fti.spoiled.push_back(ri);
		ri.reg = R_dx; fti.spoiled.push_back(ri);
		ri.reg = R_si; fti.spoiled.push_back(ri);
		ri.reg = R_di; fti.spoiled.push_back(ri);
		if (is64bit()) {
			ri.reg = R_r8; fti.spoiled.push_back(ri);
			ri.reg = R_r9; fti.spoiled.push_back(ri);
			ri.reg = R_r10; fti.spoiled.push_back(ri);
			ri.reg = R_r11; fti.spoiled.push_back(ri);
			ri.reg = R_r12; fti.spoiled.push_back(ri);
			ri.reg = R_r13; fti.spoiled.push_back(ri);
			ri.reg = R_r14; fti.spoiled.push_back(ri);
			ri.reg = R_r15; fti.spoiled.push_back(ri);
		}
		fti.flags |= FTI_SPOILED;

		type.clear();
		type.create_func(fti);
		if (!apply_tinfo(vu.cfunc->entry_ea, type, TINFO_DEFINITE))
			return 0;
	}

	golang_add(vu.cfunc->entry_ea);
#if 1
	vu.refresh_view(true);

	bool changed;
	show_wait_box("Maping vars...");
	do {
		changed = false;
		if (vu.cfunc) {
			lvars_t *vars = vu.cfunc->get_lvars();
			if (vars->size() > 1) {
				for (int i = (int)vars->size() - 1; i >= 0; i--) {
					lvar_t *var = &vars->at(i);
					if (var->is_stk_var() && var->used() && !var->is_mapdst_var()) {
						int dup = vars->find_lvar(var->location, var->width);
						if (dup != i && dup != -1) {
							//msg("[hrt] Map var '%s' to '%s'\n", var->name.c_str(), vars->at(dup).name.c_str());
							replace_wait_box("[hrt] Map var '%s' to '%s'\n", var->name.c_str(), vars->at(dup).name.c_str());
							if (vu.map_lvar(var, &vars->at(dup))) {
								changed = true;
								break;
							}
						}
					}
				}
			}
		}
	} while (changed && !user_cancelled());
	hide_wait_box();
	//vu.map_lvar refreshes view!
#else
	hexrays_failure_t hf;
	cfuncptr_t func = decompile(vu.mba->mbr, &hf, DECOMP_NO_CACHE);
	if (func) {
		lvars_t *vars = func->get_lvars();
		lvar_uservec_t lvinf;
		if (vars->size() > 1) {
			if (!restore_user_lvar_settings(&lvinf, func->entry_ea))
				lvinf.stkoff_delta = func->get_stkoff_delta();
			bool changed = false;
			for (int i = (int)vars->size() - 1; i >= 0; i--) {
				lvar_t *var = &vars->at(i);
				if (var->is_stk_var()) {
					int dup = vars->find_lvar(var->location, var->width);
					if (dup != i && dup != -1) {
						//vu.map_lvar(var, &vars->at(dup));
						if (lvinf.lmaps.find(*var) == lvinf.lmaps.end()) {
							msg("[hrt] map var '%s' to '%s'\n", var->name.c_str(), vars->at(dup).name.c_str());
							lvinf.lmaps[*var] = vars->at(dup);
							changed = true;
						}
					}
				}
			}
			if(changed)
				save_user_lvar_settings(func->entry_ea, lvinf);
		}
	}
	vu.refresh_view(true);
#endif
	return 0;
}
#endif //IDA_SDK_VERSION < 900

//-----------------------------------------------------
bool is_number(vdui_t *vu)
{
	if (!vu->item.is_citem())
		return false;
	cexpr_t *e = vu->item.e;
	if (e->op != cot_num)
		return false;
	return true;
}

bool is_like_assign(cexpr_t *asg)
{
  ctype_t op = asg->op;
  return op == cot_asg || op == cot_eq || op == cot_ne;
}
/*
 var_of_type_type = (cast to type)something;

 //cursor is on var
 asg -> x -> var with type A
     -> y -> cast to type A -> x -> something with type B
	 =>
 asg -> x -> var with type B
     -> y -> something with type B

*/
static bool is_cast_assign(vdui_t *vu, tinfo_t * ts)
{
	if (!vu->item.is_citem())
		return false;

	cexpr_t * var = vu->item.e;
	if (var->op != cot_var && var->op != cot_obj &&
		var->op != cot_memptr && var->op != cot_memref)
		return false;
		
	citem_t * asg_ci = vu->cfunc->body.find_parent_of(var);
	if(!asg_ci->is_expr())
		return false;

	bool bDerefPtr = false;
	cexpr_t * asg = (cexpr_t *)asg_ci;
	if(!is_like_assign(asg)) {
		if(asg->op != cot_ptr || asg->x != var)
			return false;
		bDerefPtr = true;
		asg_ci = vu->cfunc->body.find_parent_of(asg);
		if(!asg_ci->is_expr() || !is_like_assign((cexpr_t *)asg_ci))
			return false;
		asg = (cexpr_t *)asg_ci;
	} else if(asg->x != var)
		return false;

	tinfo_t yType;
	cexpr_t * y = asg->y;
	if(y->op == cot_cast)
		yType = y->x->type;
	else if(y->op == cot_var) //TODO: global, struc member
		yType = y->type; //??? use getExpType(cfunc_t *func, cexpr_t* exp)
	else
		return false;

	if(ts) {
		if(bDerefPtr)
			yType = make_pointer(yType);
		*ts = yType;
	}
	return true;
}

/*
 (cast to type)var;
 or
 LOBYTE(var)
 //cursor is on var
*/
static bool is_cast_var(vdui_t *vu, tinfo_t * ts)
{
	if (!vu->item.is_citem())
		return false;

	cexpr_t * var = vu->item.e;
	if (var->op != cot_var && var->op != cot_obj &&
		var->op != cot_memptr && var->op != cot_memref)
		return false;

	citem_t * cast_ci = vu->cfunc->body.find_parent_of(var);
	if(!cast_ci->is_expr())
		return false;

	cexpr_t * exp = (cexpr_t *)cast_ci;

	//check helper first;
	if(exp->op == cot_call && exp->x->op == cot_helper) {
		char* helper = exp->x->helper;
		tinfo_t t;
		if(qstrstr(helper, "BYTE"))
			t.create_simple_type(BT_INT8);
		else if(qstrstr(helper, "DWORD"))
			t.create_simple_type(BT_INT32);
		else if(qstrstr(helper, "QWORD"))
			t.create_simple_type(BT_INT64);
		else if(qstrstr(helper, "WORD"))
			t.create_simple_type(BT_INT16);
		if(!t.empty()) {
			if(ts)
				*ts = t;
			return true;
		}
	}

	bool ref = false;
	if(exp->op == cot_ref) {
		ref = true;
		cast_ci = vu->cfunc->body.find_parent_of(exp);
		if(cast_ci->is_expr())
			exp = (cexpr_t *)cast_ci;
	} 
	
	if(exp->op != cot_cast)
		return false;

	//check for ptr deref, ex: *(_OWORD *)var
	citem_t *pitm = vu->cfunc->body.find_parent_of(exp);
	if(pitm->op == cot_ptr)
		ref = true;

	if(ts) {
		*ts = exp->type;
		if(ref)
			ts->remove_ptr_or_array();
	}
	return true;
}

bool set_var_type(vdui_t *vu, lvar_t *lv, tinfo_t *ts)
{
	if(lv->accepts_type(*ts)) {
		if(lv->has_user_type()) {
			qstring typestr;
			ts->print(&typestr);
			int answer = ask_yn(ASKBTN_NO, "[hrt] Change type of '%s' to '%s'?", lv->name.c_str(), typestr.c_str());
			if(answer == ASKBTN_NO || answer == ASKBTN_CANCEL)
				return false;
		}
		if (vu->set_lvar_type(lv, *ts))
			return true;
	}
	qstring typestr;
	ts->print(&typestr);
	warning("[hrt] '%s' var type '%s' not accepted by IDA!\n\nTrick: go to \"Stack Variables\" view and change type of stack var to something simply like BYTE\n",
		lv->name.c_str(), typestr.c_str());
	return false;
}

bool set_ea_type(ea_t ea, tinfo_t *ts)
{
  if (!is_mapped(ea))
		return false;

	tinfo_t oldType;
	if(get_tinfo(&oldType, ea)) {
		qstring typestr;
		ts->print(&typestr);
		qstring name;
    if (has_any_name(get_flags(ea)))
			name = get_short_name(ea);
		else
			name.sprnt("0x%a", ea);
		int answer = ask_yn(ASKBTN_NO, "[hrt] Change type of '%s' to '%s'?", name.c_str(), typestr.c_str());
		if(answer == ASKBTN_NO || answer ==ASKBTN_CANCEL)
			return false;
	}
	return set_tinfo(ea, ts);
}

#if IDA_SDK_VERSION < 900
bool set_membr_type(struc_t * struc, member_t * member, tinfo_t *ts, bool bSilent = false)
{
	tinfo_t oldType;
	if(!bSilent && get_member_tinfo(&oldType, member)) {
		qstring oldtype;
		oldType.print(&oldtype);
		qstring typestr;
		ts->print(&typestr);
		qstring name;
		get_member_fullname(&name, member->id);
		int answer = ask_yn(ASKBTN_NO, "[hrt] Change type of '%s'\nfrom '%s' to '%s'?", name.c_str(), oldtype.c_str(), typestr.c_str());
		if(answer == ASKBTN_NO || answer ==ASKBTN_CANCEL)
			return false;
	}

	asize_t mbsz = member->eoff - member->soff;
	asize_t nsz = 0;
	if(!struc->from_til()) {
		//if new type is smaller then old one - do delete member and re-create field
		flags64_t ft;
		switch(ts->get_decltype()) {
		case BT_UNK_OWORD:
		case BTF_INT128:
		case BTF_UINT128:
		case BT_INT128: nsz =16; ft = oword_flag(); break;
		case BT_UNK_QWORD:
		case BTF_INT64:
		case BTF_UINT64:
		case BT_INT64: nsz = 8; ft = qword_flag(); break;
		case BT_UNK_DWORD:
		case BTF_INT32:
		case BTF_UINT32:
		case BT_INT32: nsz = 4; ft = dword_flag(); break;
		case BT_UNK_WORD:
		case BTF_INT16:
		case BTF_UINT16:
		case BT_INT16: nsz = 2; ft = word_flag(); break;
		case BT_UNK_BYTE:
		case BTF_INT8:
		case BTF_UINT8:
		case BTF_CHAR:
		case BT_INT8:  nsz = 1; ft = byte_flag(); break;
		default:        nsz = 0; break;
		}
		if(nsz && nsz < mbsz && (mbsz % nsz == 0)) {
			asize_t fo = member->soff;
			qstring fname = get_member_name(member->id);

			if(del_struc_member(struc, fo)) {
				while(1) {
					if(STRUC_ERROR_MEMBER_OK != add_struc_member(struc, fname.c_str(), fo, ft, NULL, nsz))
						break;
					mbsz -= nsz;
					if (mbsz <= 0)
						break;
					fo   += nsz;
					fname.sprnt("field_%a", fo);
				}
				return true;
			}
		}
	}

	//preserve whole struct size, but allow to destroy members inside
	int flags = SET_MEMTI_MAY_DESTROY;
	nsz = (asize_t)ts->get_size();
	if(nsz != mbsz) { //new size is not equal old
		member_t* lastMemb = struc->members + (struc->memqty - 1);
		if(member->soff == lastMemb->soff  ||    //modified member is last one,  or
			 (member->soff + nsz > lastMemb->soff &&
				member->soff + nsz != lastMemb->eoff)) {//modified member tail destroys last field
			flags = SET_MEMTI_COMPATIBLE;
			qstring typeStr, membName;
			ts->print(&typeStr);
			get_member_fullname(&membName,  member->id);
			msg("[hrt] forcing type '%s' on '%s' can lead changing structure size\n", typeStr.c_str(), membName.c_str());
		}
	}
	return (SMT_OK == set_member_tinfo(struc, member, 0, *ts, flags));
}

bool set_membr_type(vdui_t * vu, tinfo_t *ts)
{
	struc_t * struc = 0;
	member_t * member = vu->item.get_memptr(&struc);
	if(!member)
		return false;
	return set_membr_type(struc, member, ts);
}
#else //IDA_SDK_VERSION >= 900
bool set_membr_type(vdui_t* vu, tinfo_t* t)
{
	udm_t udm;
	tinfo_t parent;
	uint64 offset;
	int idx = vu->item.get_udm(&udm, &parent, &offset);
	if (idx < 0)
		return false;
	return parent.set_udm_type(idx, *t, ETF_MAY_DESTROY) == TERR_OK;
}
#endif //IDA_SDK_VERSION < 900

static int idaapi cast_var2(vdui_t *vu, tinfo_t *ts)
{
	if (!vu->item.is_citem())
		return false;
	cexpr_t * var = vu->item.e;
	if (var->op == cot_var) {
		lvar_t * lv = vu->item.get_lvar();
		return set_var_type(vu, lv, ts);
	} else if(var->op == cot_obj) {
		ea_t ea = vu->item.get_ea();
		if(set_ea_type(ea, ts)) {
			vu->refresh_view(false);
		}
	} else if(var->op == cot_memref || var->op == cot_memptr) {
		if(set_membr_type(vu, ts)) {
			vu->refresh_view(false);
		}
	}
	return 0;
}

bool is_recastable(vdui_t *vu, tinfo_t * ts)
{
	return is_cast_var(vu, NULL) || is_cast_assign(vu, NULL);
}

ACT_DEF(recast_item)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	tinfo_t ts;
	if (is_cast_var(vu, &ts) || is_cast_assign(vu, &ts))
		return cast_var2(vu, &ts);
	return 0;
}

bool is_gap_field(vdui_t *vu, tinfo_t *ts, udm_t* memb)
{
	if (!vu->item.is_citem())
		return false;

	cexpr_t * membacc = vu->item.e;
	if (membacc->op != cot_memptr && membacc->op != cot_memref)
		return false;

	tinfo_t type = membacc->x->type;
	type.remove_ptr_or_array();
	if(!type.is_struct()) //t->is_decl_struct()
		return false;

	udm_t tmemb;
	if(!memb)
		memb = &tmemb;
	memb->offset = membacc->m;
	if(-1 == type.find_udm(memb, STRMEM_AUTO))
		return false;

	if(strncmp(memb->name.c_str(), "fld_gap",7) && strncmp(memb->name.c_str(), "gap",3))
		return false;

	if(ts)
		*ts = type;
	return true;
}

ACT_DEF(convert_gap)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	tinfo_t ts;
	udm_t memb;
	if(!is_gap_field(vu, &ts, &memb))
		return 0;

	cexpr_t * exp = vu->item.e;
	ea_t fldOff = exp->m;
	ea_t gapOff = exp->m;
	tinfo_t fldType;

	citem_t * ci = vu->cfunc->body.find_parent_of(exp);
	if(ci->op == cot_idx) {
		cexpr_t * idx = ((cexpr_t *)ci)->y;
		if(idx->op != cot_num)
			return 0;
		fldOff += (ea_t)idx->numval();
		ci = vu->cfunc->body.find_parent_of(ci);
	}
	if(ci->op == cot_ref)
		ci = vu->cfunc->body.find_parent_of(ci);
	if(ci->op == cot_cast && ((cexpr_t *)ci)->type.is_ptr() &&
		 vu->cfunc->body.find_parent_of(ci)->op == cot_ptr)
	{
		fldType = ((cexpr_t *)ci)->type;
		fldType.remove_ptr_or_array();
	}

	if(fldType.empty())
		fldType.create_simple_type(BT_INT8);

#if IDA_SDK_VERSION < 900
	qstring sname;
	if(!ts.get_type_name(&sname))
		return 0;

	tid_t tid = get_struc_id(sname.c_str());
	if(tid == BADNODE)
		return 0;

	qstring fldname;
	struc_t* struc = get_struc(tid);
	member_t *gapM = get_member(struc, gapOff);
	if(gapM) {
		//gap member may not exists, if it created by ida struct syncro
		asize_t gapSz = get_member_size(gapM);
		if (del_struc_member(struc, gapOff)) {
			if (fldOff > gapOff) {
				fldname.sprnt("gap%X", gapOff);
				add_struc_member(struc, fldname.c_str(), gapOff, byte_flag(), NULL, fldOff - gapOff);
			}
			asize_t fldSz = (asize_t)fldType.get_size();
			if (fldOff + fldSz < gapOff + gapSz) {
				gapSz = gapOff + gapSz - (fldOff + fldSz);
				gapOff = fldOff + fldSz;
				fldname.sprnt("gap%X", gapOff);
				add_struc_member(struc, fldname.c_str(), gapOff, byte_flag(), NULL, gapSz);
			}
		}
	}

	fldname.sprnt("field_%X", fldOff);
	if(STRUC_ERROR_MEMBER_OK == add_struc_member(struc, fldname.c_str(), fldOff, byte_flag(), NULL, 1)) {
		member_t *fldM = get_member(struc, fldOff);
		set_membr_type(struc, fldM, &fldType, true);
	}
#else //IDA_SDK_VERSION >= 900
	{
		//??? gap member may not exists, but ida provides fake one
		asize_t gapSz = memb.size / 8;
		if (ts.del_udm(ts.find_udm(memb.offset)) == TERR_OK) {
			if (fldOff > gapOff) {
				udm_t udm;
				udm.offset = gapOff * 8;
				udm.size = (fldOff - gapOff) * 8;
				udm.name.sprnt("gap%X", gapOff);
				create_type_from_size(&udm.type, fldOff - gapOff);
				ts.add_udm(udm);
			}
			asize_t fldSz = (asize_t)fldType.get_size();
			if (fldOff + fldSz < gapOff + gapSz) {
				gapSz = gapOff + gapSz - (fldOff + fldSz);
				gapOff = fldOff + fldSz;
				udm_t udm;
				udm.offset = gapOff * 8;
				udm.size = gapSz * 8;
				udm.name.sprnt("gap%X", gapOff);
				create_type_from_size(&udm.type, gapSz);
				ts.add_udm(udm);
			}
		}
	}
	udm_t udm;
	udm.offset = fldOff * 8;
	udm.size = fldType.get_size() * 8;
	udm.name.sprnt("field_%X", fldOff);
	udm.type = fldType;
	ts.add_udm(udm, ETF_MAY_DESTROY);
#endif //IDA_SDK_VERSION < 900
	vu->refresh_view(false);
	return 0;
}

//-----------------------------------------------------
ACT_DEF(disable_inlines)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	XXable_inlines(vu->mba->entry_ea, true);
	vu->refresh_view(true);
	return 0;
}

ACT_DEF(enable_inlines)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	XXable_inlines(vu->mba->entry_ea, false);
	vu->refresh_view(true);
	return 0;
}

ACT_DEF(rename_inline)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if (ren_inline(vu))
		REFRESH_FUNC_CTEXT(vu);
	return 0;
}

ACT_DEF(create_inline_gr)
{
	if (ctx->widget_type != BWN_DISASM || get_view_renderer_type(ctx->widget) != TCCRT_GRAPH || !ctx->cur_func)
		return 0;

	graph_viewer_t *gv = ctx->widget; //get_graph_viewer(ctx->widget);
	interactive_graph_t *gr = get_viewer_graph(gv);
	if (!gr)
		return 0;

	int curnode = viewer_get_curnode(gv);

#if 0 //doesnt work: viewer_create_groups modifies graph too late - when control is returned to GUI
	if (!gr->is_group_node(curnode)) {
		screen_graph_selection_t sgs;
		if (viewer_get_selection(gv, &sgs) && sgs.size() > 1) {
			groups_crinfos_t gis;
			group_crinfo_t &gi = gis.push_back();
			gi.text = "inline";
			for (size_t i = 0; i < sgs.size(); ++i)
				if (sgs[i].is_node)
					gi.nodes.push_back(sgs[i].node);
			intvec_t out_group_nodes;
			if (viewer_create_groups(gv, &out_group_nodes, gis)) {
				gr = get_viewer_graph(gv);
				curnode = viewer_get_curnode(gv);
			}
		}
	}
#endif

	if (curnode == -1 || !gr->is_group_node(curnode)) {
		warning("[hrt] no currently selected node or curnode is not 'group'");// or there are not selected items in the graph");
		return 0;
	}

	int group = gr->get_node_group(curnode);
	int head = gr->get_first_subgraph_node(group);
	if (head == -1 || gr->nsucc(group) != 1) {
		warning("[hrt] to be 'inline' group must have single exit node (not part of 'group')");
		return 0;
	}

#if IDA_SDK_VERSION < 740 // at least from ida7.4 (maybe early) gr->org_preds is broken, and this check always fails
	//check if all predecessors of group is included into original group head predecessors,
	//so there are no predecessors targeted to other group memners
	const intvec_t &grp_preds = gr->predset(group);
	const intvec_t &head_preds = gr->org_preds[head];
	bool preds_ok = true;

#if 0
	msg("group %d preds :", group);
	for (size_t i = 0; i < grp_preds.size(); i++)
		msg("%d ", grp_preds[i]);
	msg("\nhead %d preds :", head);
	for (size_t i = 0; i < head_preds.size(); i++)
		msg("%d ", head_preds[i]);
	msg("\n");
#endif

	for (size_t i = 0; i < grp_preds.size(); i++) {
		if (!head_preds.has(grp_preds[i])) {
			preds_ok = false;
			break;
		}
	}
	if (!preds_ok) {
		warning("[hrt] to be 'inline' group must have single entry node (head of 'group')");
		return 0;
	}
#endif //IDA_SDK_VERSION < 740

	//How to correctly get group title?
	node_info_t ni;
	if (get_node_info(&ni, gr->gid, group)) {
		msg("[hrt] converting group '%s' to inline\n", ni.text.c_str());
		qflow_chart_t fc;
		fc.create("tmpfc", ctx->cur_func, ctx->cur_func->start_ea, ctx->cur_func->end_ea, FC_NOEXT);
		if (fc.size() == gr->org_succs.size()) {
			rangevec_t ranges;
			for (int node = gr->get_first_subgraph_node(group); node != -1; node = gr->get_next_subgraph_node(group, node)) {
				QASSERT(100202, node < fc.size());
				const qbasic_block_t* bb = &fc.blocks[node];
				msg("[hrt]    %d: %a-%a\n", node, bb->start_ea, bb->end_ea);
				ranges.push_back(range_t(bb->start_ea, bb->end_ea));
			}
			mba_ranges_t mbr(ranges);
			hexrays_failure_t hf;
			ea_t 	entry_ea = ranges.front().start_ea;
			XXable_inlines(entry_ea, true);
			mbl_array_t *mba = gen_microcode(mbr, &hf, NULL, DECOMP_NO_WAIT | DECOMP_NO_FRAME /*| DECOMP_NO_CACHE*/, DEINLINE_MATURITY);
			XXable_inlines(entry_ea, false);
			if (mba && hf.code == MERR_OK) {
				qstring err;
				if(!inl_create_from_whole_mba(mba, ni.text.c_str(), &err) && err.length())
					warning("[hrt] %s\n", err.c_str());
			} else {
				warning("[hrt] gen_microcode error %d: %s\n", hf.code, hf.desc().c_str());
			}
			delete mba;
		}
	}
	return 0;
}

ACT_DEF(create_inline_sel)
{
	ea_t eaBgn = BADADDR;
	ea_t eaEnd = BADADDR;
	if (!ctx->has_flag(ACF_HAS_SELECTION) || !read_range_selection(ctx->widget, &eaBgn, &eaEnd))
		return 0;

	if (ctx->widget_type == BWN_DISASM) {
		mba_ranges_t mbr;
		mbr.ranges.push_back(range_t(eaBgn, eaEnd));
		hexrays_failure_t hf;
		qstring err;
		XXable_inlines(eaBgn, true);
		mbl_array_t *mba = gen_microcode(mbr, &hf, NULL, DECOMP_NO_WAIT | DECOMP_NO_FRAME /*| DECOMP_NO_CACHE*/, DEINLINE_MATURITY);
		XXable_inlines(eaBgn, false);
		if (mba && hf.code == MERR_OK) {
			qstring name;
			name.cat_sprnt("inline_%a_%a", eaBgn, eaEnd);
			if (inl_create_from_whole_mba(mba, name.c_str(), &err)) {
				unmark_selection();
			}
		} else {
			err.sprnt("gen_microcode error %d: %s\n", hf.code, hf.desc().c_str());
		}
		delete mba;
		if (err.length())
			warning("[hrt] %s\n", err.c_str());
		return 0;
	}

	QASSERT(100204, ctx->widget_type == BWN_PSEUDOCODE);
	vdui_t *vu = get_widget_vdui(ctx->widget);

	//align eaBgn/eaEnd to blocks boundaries 
	//msg("[hrt] %a-%a: range selected for inline\n", eaBgn, eaEnd);
	qflow_chart_t fc;
	fc.create("tmpfc", ctx->cur_func, ctx->cur_func->start_ea, ctx->cur_func->end_ea, 0);
	for (int n = 0; n < fc.size(); n++) {
		const qbasic_block_t* blk = &fc.blocks[n];
		msg("[hrt]    %d: %a-%a\n", n, blk->start_ea, blk->end_ea);
		if (blk->start_ea <= eaBgn && eaBgn < blk->end_ea)
			eaBgn = blk->start_ea;
		else if (blk->start_ea < eaEnd && eaEnd < blk->end_ea)
			eaEnd = blk->start_ea;
	}
	//msg("[hrt] %a-%a: inline applicant aligned to basic block boundaries\n", eaBgn, eaEnd);

	selection2inline(eaBgn, eaEnd);
	XXable_inlines(vu->mba->entry_ea, false);
	vu->refresh_view(true);
	return 0;
}

//-----------------------------------------------------
static bool save_if42blocks(ea_t funcea, const rangevec_t& ranges)
{
	bytevec_t buffer;
	for (const auto& r : ranges) {
#if IDA_SDK_VERSION < 730
		append_ea(buffer, r.start_ea);
		append_ea(buffer, r.end_ea);
#else //IDA_SDK_VERSION >= 730
		buffer.pack_ea(r.start_ea);
		buffer.pack_ea(r.end_ea);
#endif //IDA_SDK_VERSION < 730
	}
	if (buffer.size() > MAXSPECSIZE) {
		msg("[hrt] too many if42blocks\n");
		return false;
	}
	netnode n(funcea);
	return n.setblob(&buffer.front(), buffer.size(), 0, 'i');
}

bool has_if42blocks(ea_t funcea)
{
	netnode n(funcea);
	if (n == BADNODE)
		return false;
	return n.blobsize(0, 'i') != 0;
}

static bool load_if42blocks(ea_t funcea, rangevec_t& ranges)
{
	netnode n(funcea);
	if (n == BADNODE)
		return false;

	size_t sz;
	void* buff = n.getblob(NULL, &sz, 0, 'i');
	if (!buff)
		return false;

	const uchar* ptr = (const uchar*)buff;
	const uchar* end = (const uchar*)buff + sz;
	while (ptr < end) {
		range_t& r = ranges.push_back();
		r.start_ea = unpack_ea(&ptr, end);
		r.end_ea   = unpack_ea(&ptr, end);
	}
	qfree(buff);
	return true;
}

static bool del_if42blocks(ea_t funcea)
{
	netnode n(funcea);
	if (n == BADNODE)
		return false;
	return n.delblob(0, 'i') != 0;
}

bool makeif42block(cfunc_t* cfunc, ea_t eaBgn, ea_t eaEnd)
{
	eamap_t &eamap = cfunc->get_eamap();
	eamap_iterator_t itBgn = eamap_find(&eamap, eaBgn);
	eamap_iterator_t itEnd = eamap_find(&eamap, eaEnd);
	if (itBgn == eamap_end(&eamap) || itEnd == eamap_end(&eamap)) {
		msg("[hrt] makeif42block: bad selection2 %a-%a\n", eaBgn, eaEnd);
		return false;
	}

	cinsnptrvec_t& ivBgn = eamap_second(itBgn);
	cinsnptrvec_t& ivEnd = eamap_second(itEnd);
	if (!ivBgn.size() || !ivEnd.size()) {
		msg("[hrt] makeif42block: bad selection3 %a-%a\n", eaBgn, eaEnd);
		return false;
	}

	cinsn_t *iFirst = ivBgn[0];
	cinsn_t *iLast  = ivEnd[0];

	citem_t *paBgn = cfunc->body.find_parent_of(iFirst);
	citem_t *paEnd = cfunc->body.find_parent_of(iLast);
	if (paBgn != paEnd || !paBgn || paBgn->op != cit_block) {
		msg("[hrt] makeif42block: selection %a-%a is not inside same block\n", eaBgn, eaEnd);
		return false;
	}

	cblock_t* pBlk = ((cinsn_t*)paBgn)->cblock;
	cexpr_t* cond = new cexpr_t();
	cond->ea = eaBgn;
	cond->put_number(cfunc, 42, 1);
	cif_t& cif = ((cinsn_t*)paBgn)->create_if(cond);
	cinsn_t& insIf = pBlk->back(); //create_if append statement to end of block
	cif.ithen = new cinsn_t();
	cif.ithen->op = cit_block;
	cif.ithen->ea = eaBgn;
	cif.ithen->cblock = new cblock_t();

	cinsn_t* insertedIf = NULL;
	for (auto it = pBlk->begin(); it != pBlk->end(); ) {
		if (&(*it) == iFirst) {
			it = pBlk->insert(it, insIf);
			insertedIf = &(*it);
			it++;
		} else if (&(*it) == iLast) {
			break;
		}
		if (insertedIf) {
			//qstring s; it->print1(&s, cfunc); tag_remove(&s);
			//msg("[hrt] move %a: %s\n", it->ea, s.c_str());
			insertedIf->cif->ithen->cblock->push_back(*it);
			it = pBlk->erase(it);
		} else {
			it++;
		}
	}
	pBlk->pop_back(); //create_if append statement to end of block
	return true;
}

void make_if42blocks(cfunc_t *cfunc)
{
	rangevec_t rv;
	if (!load_if42blocks(cfunc->entry_ea, rv) || rv.empty())
		return;
	for (auto r : rv) 
		makeif42block(cfunc, r.start_ea, r.end_ea);
}

ACT_DEF(selection2block)
{
	QASSERT(100107, ctx->widget_type == BWN_PSEUDOCODE && ctx->has_flag(ACF_HAS_SELECTION));
	ea_t eaBgn = BADADDR;
	ea_t eaEnd = BADADDR;
	if (!read_range_selection(ctx->widget, &eaBgn, &eaEnd) || eaBgn >= eaEnd) {
		warning("[hrt] Bad selection %a - %a", eaBgn, eaEnd);
		return 0;
	}

	vdui_t* vu = get_widget_vdui(ctx->widget);
	if (makeif42block(vu->cfunc, eaBgn, eaEnd)) {
		rangevec_t rv;
		load_if42blocks(vu->cfunc->entry_ea, rv);
		rv.push_back(range_t(eaBgn, eaEnd));
		save_if42blocks(vu->cfunc->entry_ea, rv);
		user_iflags_insert(vu->cfunc->user_iflags, citem_locator_t(eaBgn, cit_if), CIT_COLLAPSED);
		save_user_iflags(vu->cfunc->entry_ea, vu->cfunc->user_iflags);
		vu->cfunc->verify(ALLOW_UNUSED_LABELS, false);
		REFRESH_FUNC_CTEXT(vu);
#if IDA_SDK_VERSION < 810 || IDA_SDK_VERSION > 830
		unmark_selection();                //TODO: IDA 8.1 crash sometimes randomly on these calls, check with other IDA versions
		jumpto(eaBgn, -1, UIJMP_DONTPUSH); //TODO: IDA 8.3 also
#endif //IDA_SDK_VERSION < 810 || IDA_SDK_VERSION > 830
		return 0;
	}
	warning("[hrt] Bad selection %a - %a\nStart and End addresses must belong to the same block", eaBgn, eaEnd);
	return 0;
}

ACT_DEF(clear_if42blocks)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	if (del_if42blocks(vu->cfunc->entry_ea))
		vu->refresh_view(false);
	return 0;
}

//-----------------------------------------------------
ACT_DEF(uf_enable)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	ufDelGL(vu->mba->entry_ea);
	vu->refresh_view(true);
	return 0;
}

ACT_DEF(uf_disable)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	ufAddGL(vu->mba->entry_ea);
	vu->refresh_view(true);
	return 0;
}

//-----------------------------------------------------
#if IDA_SDK_VERSION >= 750
ACT_DEF(mavx_enable)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	MicroAvx_init();
	vu->refresh_view(true);
	return 0;
}

ACT_DEF(mavx_disable)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	MicroAvx_done();
	vu->refresh_view(true);
	return 0;
}
#endif //IDA_SDK_VERSION >= 750
//-----------------------------------------------------

static cexpr_t* get_assign_or_helper(vdui_t *vu, citem_t* expr, bool check4helper)
{
	//go up until statement
	while(expr && expr->is_expr()) {
		expr = vu->cfunc->body.find_parent_of(expr);
	}
	if(!expr || expr->op != cit_expr)
		return NULL;

	cexpr_t *e = (cexpr_t *)expr;
	if(e->x->op == cot_asg || (check4helper && e->x->op == cot_call && e->x->x->op == cot_helper))
		return e->x;
	return NULL;
}

static qstring dummy_struct_prefix;
qstring dummy_struct_name(size_t size, const char* sprefix)
{
	if(sprefix && *sprefix)
		dummy_struct_prefix = sprefix;
	else if(dummy_struct_prefix.empty())
		dummy_struct_prefix = "s";

	qstring name;
	if(size)
		name.sprnt("%s%X", dummy_struct_prefix.c_str(), size);
	else
		name = dummy_struct_prefix;
	qstring basename = name;
	for (char i = 'z'; i > 'f'; i--) {
		if (get_named_type_tid(name.c_str()) == BADADDR)
			break;
		name = basename;
		name.cat_sprnt("%c", i);
	}
	return name;
}

static int idaapi dummy_struct_cb(int field_id, form_actions_t &fa)
{
	qstring sprefix;
	fa.get_string_value(4, &sprefix);
	if (field_id == -1 || field_id == 4) {
		if(sprefix.empty()) {
			sprefix = "s";
			fa.set_string_value(4, &sprefix);
		}
		field_id = 1;
	}
	if (field_id == -1 || field_id == 1) {//Size field
		uint64 val;
		if (fa.get_uint64_value(1, &val) && val >= 1) {
			qstring name = dummy_struct_name(val, sprefix.c_str());
			fa.set_string_value(2, &name); //set Name
			ushort empty = 0;
			if(val >= 0x400)
				empty = 1;
			fa.set_checkbox_value(3, &empty); //set Empty checkbox
		}
	}
	return 1;
}

ACT_DEF(create_dummy_struct)
{
	uint64 size = 0;
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if(vu && vu->item.is_citem())
		vu->item.e->get_const_value(&size);

	qstring name;
	static ushort empty = 1;
	const char format[] =
		//title
		"[hrt] Create struct\n\n"
		"%/\n" // callback
		"<~S~ize  :L1:32:16::>\n"
		"<~N~ame  :q2::16::>\n"
	  "<~P~refix:q4::16::>\n"
		"<###create only last field#~E~mpty:c3>>\n"
		"\n\n";
	do {
		if (1 != ask_form(format, dummy_struct_cb, &size, &name, &dummy_struct_prefix, &empty))
			return 0;
		if (get_named_type_tid(name.c_str()) != BADADDR) {
			msg("[hrt] struct '%s' already exists\n", name.c_str());
		} else if (size != 0) {
			break;
		}
	} while (1);

#if IDA_SDK_VERSION < 900
	tid_t id = add_struc(0, name.c_str());
	struc_t* s = get_struc(id);
	if (!s)
		return 0;
#else //IDA_SDK_VERSION >= 900
	udt_type_data_t s;
	s.taudt_bits |= TAUDT_UNALIGNED;
	s.total_size = s.unpadded_size = size;
	//s.pack = 1;
#endif //IDA_SDK_VERSION < 900

	if (empty || size > 10240) {
#if IDA_SDK_VERSION < 900
		add_struc_member(s, "gap", 0, byte_flag(), NULL, (ea_t)(size-1));
		add_struc_member(s, "field_last", (ea_t)(size - 1), byte_flag(), NULL, 1);
#else //IDA_SDK_VERSION >= 900
		udm_t &m0 = s.push_back();
		//m.make_gap(0, size - 1);
		m0.name = "gap";
		m0.size = 8 * (size - 1); //in bits
		m0.offset = 0;
		create_type_from_size(&m0.type, size - 1);

		udm_t& m1 = s.push_back();
		m1.name = "field_last";
		m1.size = 8; //in bits
		m1.offset = 8 * (size - 1); //in bits
		create_type_from_size(&m1.type, 1);
#endif //IDA_SDK_VERSION < 900
	} else {
		ea_t fo = 0;
		while (size > 0) {
			flags64_t ft;
			asize_t fsz;
			if (size >= 8 && is64bit()) {
				ft = qword_flag();
				fsz = 8;
			}
			else if (size >= 4) {
				ft = dword_flag();
				fsz = 4;
			}
			else if (size >= 2) {
				ft = word_flag();
				fsz = 2;
			}
			else {
				ft = byte_flag();
				fsz = 1;
			}
			qstring fname;
			fname.sprnt("field_%a", fo);
#if IDA_SDK_VERSION < 900
			add_struc_member(s, fname.c_str(), fo, ft, NULL, fsz);
#else //IDA_SDK_VERSION >= 900
			udm_t& m = s.push_back();
			m.name = fname;
			m.size = 8 * fsz; //in bits
			m.offset = 8 * fo; //in bits
			create_type_from_size(&m.type, fsz);
#endif //IDA_SDK_VERSION < 900
			size -= fsz;
			fo += fsz;
		}
	}
#if IDA_SDK_VERSION < 900
#else //IDA_SDK_VERSION >= 900
	//not sure is need to set_fixed for a dummy_struct that will be modified many times during further reversing
	//s.set_fixed(true);
	tinfo_t ti;
	if (!ti.create_udt(s) || ti.set_named_type(NULL, name.c_str()) != TERR_OK)
		return 0;
#endif //IDA_SDK_VERSION < 900
	msg("[hrt] struct '%s' was created\n", name.c_str());

	if(vu) {
		qstring callname;
		cexpr_t *call;
		if(is_call(vu, &call) && getExpName(vu->cfunc, call->x, &callname)) {
			cexpr_t* asgn = get_assign_or_helper(vu, call, false);
			if(asgn && (stristr(callname.c_str(), "alloc") || callname == "??2@YAPAXI@Z")) {
				if(renameExp(asgn->ea, "", vu->cfunc, asgn->x, &name, vu)) {
					return 1;//vu->refresh_view(true);
				}
			}
		}
	}
	return 0;
}

//------------------------------------------------
ACT_DEF(offsets_tbl)
{
	int changed = 0;
	ea_t ea = get_screen_ea();
	flags64_t flags = get_flags(ea);
	while (is_unknown(flags) || is_data(flags))
	{
		ea_t dstea = get_ea(ea);
		if (!is_mapped(dstea))
			break;

		del_items(ea, DELIT_SIMPLE, ea_size);
		op_plain_offset(ea, 0, 0); //set_op_type(ea, off_flag(), 0);

		changed = 1;
		ea += ea_size;//next_head
		flags = get_flags(ea);
		if (has_any_name(flags) || has_xref(flags))
			break;
	}

	return changed;
}

//------------------------------------------------
ACT_DEF(fill_nops)
{
	if (!isX86()) {
		warning("[hrt] FIXME: fill_nops is x86 specific\n");
		return 0;
	}

	ea_t eaBgn = get_screen_ea();
	ea_t eaEnd = eaBgn + 1;
	if(ctx->has_flag(ACF_HAS_SELECTION))
		read_range_selection(NULL, &eaBgn, &eaEnd);
	const char format[] =
		"[hrt] Fill by NOPs\n\n"
		"<~F~rom:$:32:16::>\n"
		"<#Last address is not included in the patch range#~T~o  :$:32:16::>\n"
		"\n\n";
	if (!ask_form(format, &eaBgn, &eaEnd))
		return 0;

	uval_t len = eaEnd - eaBgn;

	if (eaBgn > eaEnd || !is_mapped(eaBgn) || !is_mapped(eaEnd) || len > 0x100000)
	{
		msg("[hrt] fill_nops: bad range %a - %a\n", eaBgn, eaEnd);
		return 0;
	}

	unmark_selection();
	add_extra_cmt(eaBgn, true, "; patched 0x%x", len);
	for (uval_t i = 0; i < len; i++) {
		del_items(eaBgn);
		patch_byte(eaBgn, 0x90);
		create_insn(eaBgn++);
	}

	return 1;
}

//------------------------------------------------
ACT_DEF(searchNpatch)
{
	ea_t eaBgn = inf_get_min_ea();
	ea_t eaEnd = inf_get_max_ea();
	static qstring keystr;
	static qstring repstr;
	read_range_selection(NULL, &eaBgn, &eaEnd);

	const char format[] =
		"STARTITEM 2\n"
		"@0:528[]\n"
		//title
		"[hrt] Search & Patch\n\n"
		"In range: <~F~rom:$:32:16::> <#Last address is not included in the patch range#~T~o:$:32:16::>\n"
		"<#Format is the same as in IDA 'Binary Search'#~S~earch  hex string:q::40::>\n"
		"<#Format is the same as in IDA 'Binary Search'#~R~eplace hex string:q::40::>\n"
		"\n\n";
	if (!ask_form(format, &eaBgn, &eaEnd, &keystr, &repstr))
		return 0;

	if (eaBgn > eaEnd || !is_mapped(eaBgn) /*|| !is_mapped(eaEnd - 1)*/) {
		msg("[hrt] searchNpatch: bad range %a - %a\n", eaBgn, eaEnd);
		return 0;
	}
	qstring errbuf;
	compiled_binpat_vec_t key;
	if(!parse_binpat_str(&key, eaBgn, keystr.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
		msg("[hrt] searchNpatch: error in Search string '%s': %s\n", keystr.c_str(), errbuf.c_str());
		return 0;
	}
	compiled_binpat_vec_t rep;
	if(!parse_binpat_str(&rep, eaBgn, repstr.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
		msg("[hrt] searchNpatch: error in Replace string '%s': %s\n", repstr.c_str(), errbuf.c_str());
		return 0;
	}
	size_t keySize = key.front().bytes.size();
	if (key.size() != rep.size() || rep.size() != 1 ||
			keySize != rep.front().bytes.size()) {
		msg("[hrt] searchNpatch: Search and Replace strings have different size\n");
		return 0;
	}
	//unmark_selection();//check, is this need
	uint32 cnt = 0;
	for (ea_t found_ea = eaBgn; found_ea < eaEnd; found_ea++) {
#if IDA_SDK_VERSION < 900
		found_ea = bin_search2(found_ea, eaEnd, key, BIN_SEARCH_CASE | BIN_SEARCH_FORWARD);
#else //IDA_SDK_VERSION >= 900
		found_ea = bin_search(found_ea, eaEnd, key, BIN_SEARCH_CASE | BIN_SEARCH_FORWARD);
#endif //IDA_SDK_VERSION < 900
		if(found_ea == BADADDR)
			break;
		qvector<uint8> found;
		found.resize(keySize);
		if(keySize != get_bytes(&found[0], found.size(), found_ea)) {
			msg("[hrt] searchNpatch: get_bytes error at %a len %d\n", found_ea, found.size());
			continue;
		}
		//show_hex(&key.front().bytes[0], key.front().bytes.size(), "[hrt] key bytes\n");
		//show_hex(&key.front().mask[0], key.front().mask.size(), "[hrt] key mask\n");
		//show_hex(&found[0], found.size(), "[hrt] found\n");
		//example
		//key      : FF 25 ?  10 00 01
		//key bytes: FF 25 FF 10 00 01
		//key mask : FF FF 00 FF FF FF

		cnt++;
		jumpto(found_ea); //refresh_idaview();

		qvector<uint8> repl;
		repl.resize(keySize);
		for(size_t i = 0; i < keySize; i++) {
			uint8 m = rep.front().mask[i];
			uint8 r = rep.front().bytes[i] & m;
			uint8 f = found[i] & ~m;
			repl[i] = r | f;
		}

		char foundStr[MAXSTR];
		char replStr[MAXSTR];
		get_hex_string(foundStr, MAXSTR, &found[0], found.size());
		get_hex_string(replStr, MAXSTR, &repl[0], repl.size());

		//set_highlight(TWidget *viewer, const char *str, int flags)
		int answer = ask_yn(ASKBTN_NO, "[hrt] Replace at %a?\n\n%s\nto:\n%s", found_ea, foundStr, replStr);
		if(answer ==ASKBTN_CANCEL)
			break;
		if(answer == ASKBTN_NO)
			continue;

		show_hex(&repl[0], repl.size(), "[hrt] %a: searchNpatch:", found_ea);
		add_extra_cmt(found_ea, true, "; patched 0x%x", repl.size());
		patch_bytes(found_ea, &repl[0], repl.size());
	}

	if(!cnt)
		msg("[hrt] searchNpatch: '%s' is not found\n", keystr.c_str());

	return 1;
}

//------------------------------------------------
#if 0 // ida hangs on exit after toolbars killing
voif kill_toolbar(const char *toolbar_name,	const char *act_name)
{
	detach_action_from_toolbar(toolbar_name, act_name);
	delete_toolbar(toolbar_name);
}
ACT_DEF(kill_toolbars)
{
	//kill_toolbar("NavigatorToolBar");
	kill_toolbar("FileToolBar");
	kill_toolbar("JumpToolBar");
	kill_toolbar("SearchToolBar");
	kill_toolbar("AnalysisToolBar");
	kill_toolbar("EditToolBar");
	kill_toolbar("DebugToolBar");
	kill_toolbar("BreakpointsToolBar");
	//I cant count how many hours of my life I spend turning off these toolbar checkboxes
	return 1;
}
#endif
//------------------------------------------------
#define MAXPATCHSZ (10 * 1024 * 1024)

struct ida_local sDbgPatch {
	ea_t   eaBgn;
	uval_t len;
	qvector<uint8> buf;
};
qvector<sDbgPatch> dbgPatches;

ACT_DEF(dbg_patch)
{
	if(!is_debugger_on())
		return 0;
	ea_t eaBgn = get_screen_ea();
	ea_t eaEnd = BADADDR;
	read_range_selection(NULL, &eaBgn, &eaEnd);
	const char format[] =
	  "[hrt] Patch IDB with debugger memory\n\n"
	  "<~F~rom:$:32:16::>\n"
	  "<#Last address is not included in the patch range#~T~o  :$:32:16::>\n"
		"\n\n";
	if (!ask_form(format, &eaBgn, &eaEnd))
		return 0;

	uval_t len = eaEnd - eaBgn;

	if (eaBgn > eaEnd || !is_loaded(eaBgn) || !is_loaded(eaEnd) || len > MAXPATCHSZ)
	{
		msg("[hrt] dbg_patch: bad range %a - %a\n", eaBgn, eaEnd);
		return 0;
	}
	//unmark_selection();//check, is this need

	sDbgPatch patch;
	patch.eaBgn = eaBgn;
	patch.len = 0;
  patch.buf.resize(len);
  ssize_t rdLen = get_bytes(&patch.buf[0], len, eaBgn);
	if (rdLen > 0) {
		patch.len = (uval_t)rdLen;
		dbgPatches.push_back(patch);
		msg("[hrt] dbg_patch: add range from %a len %d to patch after debugger exit\n", eaBgn, patch.len);
	}

  return 1;
}

void apply_dbg_patches()
{
	for (qvector<sDbgPatch>::iterator it = dbgPatches.begin(); it < dbgPatches.end(); it++) {
		msg("[hrt] apply dbg_patch at %a len %d\n", it->eaBgn, it->len);
		invalidate_dbgmem_contents(it->eaBgn, it->len);
		add_extra_cmt(it->eaBgn, true, "; patched 0x%x", it->len);
		patch_bytes(it->eaBgn, &it->buf[0], it->len);
	}
	dbgPatches.clear();
}

//------------------------------------------------
#define QMAXPATH2 4096
ACT_DEF(file_patch)
{
  ea_t eaBgn = get_screen_ea();
  char dir[QMAXPATH2];
  get_input_file_path(dir, QMAXPATH2);
  qdirname(dir, QMAXPATH2, dir);
  //qstrncat(dir, SDIRCHAR, QMAXPATH2);

  char* fname = ask_file(false, dir, "Load binary file for patch at %a", eaBgn); //IDABUG! defval dir not shown on linux
  if(!fname)
    return 0;


  qvector<uint8> buf;
  FILE * file = fopenRB(fname);
  if (!file)
    return 0;

  qfseek(file, 0, SEEK_END);
  qoff64_t fsz = qftell(file);
  if(fsz > MAXPATCHSZ) {
    warning("[hrt] too big file for patch, max %d\n", MAXPATCHSZ);
    qfclose(file);
    return 0;
  }

  show_wait_box("HIDECANCEL\npatching %d bytes at %a from %s", (int32)fsz, eaBgn, fname);
  qfseek(file, 0, SEEK_SET);
  buf.resize(fsz);
  if(fsz != qfread(file, &buf[0], fsz)) {
    warning("[hrt] read error");
    qfclose(file);
    return 0;
  }
  add_extra_cmt(eaBgn, true, "; patched 0x%x", buf.size());
  if(fsz > 10240)
    put_bytes(eaBgn, &buf[0], buf.size());
  else
    patch_bytes(eaBgn, &buf[0], buf.size());
  qfclose(file);
  hide_wait_box();
  return 1;
}

//------------------------------------------------
ACT_DEF(apihashes)
{
	apihashes_init();
	return 1;
}

//------------------------------------------------
ACT_DEF(msigLoad)
{
	msig_load();
	return 1;
}

ACT_DEF(msigSave)
{
	msig_save();
	return 1;
}

ACT_DEF(msigAdd)
{
	vdui_t& vu = *get_widget_vdui(ctx->widget);
	if (has_cached_cfunc(vu.cfunc->entry_ea))
		vu.refresh_view(true);

	msig_add(vu.mba);
	return 1;
}

//------------------------------------------------
bool is_patched()
{
	//TODO
	return true;
}

int idaapi create_dec_cb(ea_t ea, qoff64_t fpos, uint64 orig, uint64 patched, void *ud)
{
	if(fpos != -1) {
		FILE* f = (FILE*)ud;
		qfseek(f, fpos, 0);
		qfwrite(f, &patched, 1);
	}
	return 0;
}

bool create_dec_file()
{
	char filename[QMAXPATH2];
	get_input_file_path(filename, QMAXPATH2);

	if(!qfileexist(filename)) {
		qgetcwd(filename, QMAXPATH2);
		size_t dirlen = qstrlen(filename);
		filename[dirlen] = DIRCHAR;
		get_root_filename(filename + dirlen + 1, QMAXPATH2);
		if(!qfileexist(filename)) {
			msg("[hrt] '%s' is not exist\n", filename);
			return false;
		}
	}
	qstring newFilename = filename;
	newFilename.append(".dec");
	show_wait_box("HIDECANCEL\nCreating %s", newFilename.c_str());

	bool res = false;
	if (qcopyfile(filename, newFilename.c_str()) >= 0) {
		FILE * file = fopenM(newFilename.c_str());
		if (file) {
			ea_t startEa = inf_get_min_ea(); //inf_get_omin_ea(); wrong values for rebased
			ea_t endEa   = inf_get_max_ea(); //inf_get_omax_ea();
			visit_patched_bytes(startEa, endEa, create_dec_cb, file);
			qfclose(file);
			res = true;
			msg("[hrt] '%s' (%a-%a) is created\n", newFilename.c_str(), startEa, endEa);
		}
	} else {
		msg("[hrt] copyfile(\"%s\", \"%s\") failed\n", filename, newFilename.c_str());
	}
	hide_wait_box();
	return res;
}

ACT_DEF(create_dec)
{
	create_dec_file();
	return 1;
}

//------------------------------------------------
ACT_DEF(clear_hr_cache)
{ // "Jump to xref globally" does not works correctly if search target was renamed
	clear_cached_cfuncs();
	msg("[hrt] Clear all cached decompilation results\n");
	return 1;
}

//------------------------------------------------

ACT_DEF(decomp_obfus)
{
	try {
		if (ctx->widget_type == BWN_DISASM)
			return decompile_obfuscated(get_screen_ea());
		vdui_t *vu = get_widget_vdui(ctx->widget);
		if (vu)
			return decompile_obfuscated(vu->mba->entry_ea);
	} catch (interr_exc_t &e) {
		warning("[hrt] unhandled IDA internal error %d", e.code);
	} catch (vd_failure_t &e) {
		warning("[hrt] unhandled Hexrays internal error at %a: %d (%s)\n", e.hf.errea, e.hf.code, e.hf.desc().c_str());
	}

	return 0;
}

//------------------------------------------------

struct ida_local href_t
{
  qstring text;
  ea_t ea;
};
DECLARE_TYPE_AS_MOVABLE(href_t);
typedef qvector<href_t> hrefvec_t;

struct ida_local helpers_locator_t : public ctree_visitor_t
{
	cfunc_t *func;
	const char* helper;
	hrefvec_t *list;
	helpers_locator_t(cfunc_t *func_, const char* helper_, hrefvec_t *list_): ctree_visitor_t(CV_FAST), func(func_), helper(helper_), list(list_) {}
	int idaapi visit_expr(cexpr_t * e)
	{
		if(e->op == cot_call && e->x->op == cot_helper && !qstrcmp(helper, e->x->helper)) {
			href_t &entry = list->push_back();
			entry.ea = e->ea;
			const strvec_t &sv = func->get_pseudocode();
			int y;
			if (func->find_item_coords(e, NULL, &y)) {
				entry.text = sv[y].line;
				tag_remove(&entry.text);
				entry.text.ltrim();
			}
		}
		return 0; //continue
	}
};

struct ida_local href_chooser_t : public chooser_t
{
protected:
  ea_t cur_ea;
  const hrefvec_t &list;
	static const int widths_[];
	static const char *const header_[];
public:
  href_chooser_t(uint32 flags_, ea_t cur_ea_, const hrefvec_t &list_, const char *title_);
  ea_t choose(ea_t ea)
	{
		ea_t pos_ea = ea;
		ssize_t n = ::choose(this, &pos_ea);
		if ( n < 0 || n >= (ssize_t)list.size() )
			return BADADDR;
		const href_t &entry = list[n];
		return entry.ea;
	}
	virtual size_t idaapi get_count() const { return list.size(); }
  virtual void idaapi get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const
	{
		const href_t &href = list[n];
		qstrvec_t &cols = *cols_;
		cols[0] = cur_ea > href.ea ? "Up" : cur_ea < href.ea ? "Down" : "";
		cols[1].cat_sprnt("%a", href.ea);
		cols[2] = href.text;
	}
  virtual ssize_t idaapi get_item_index(const void *item_data) const
	{
		if(!list.empty()) {
			ea_t ea = *(const ea_t *)item_data;
			if(ea != BADADDR) {
				for(auto it = list.begin(); it != list.end(); ++it)
					if(it->ea == ea)
						return it - list.begin();
			}
		}
		return NO_SELECTION;
	}
};
const         int href_chooser_t::widths_[] = { 6,           15,        50};
const char *const href_chooser_t::header_[] = {"Direction", "Address", "Text"};
href_chooser_t::href_chooser_t(uint32 flags_, ea_t cur_ea_, const hrefvec_t &list_, const char *title_)
	: chooser_t(flags_, qnumber(widths_), widths_, header_, title_), cur_ea(cur_ea_), list(list_)
{
	CASSERT(qnumber(widths_) == qnumber(header_));
	deflt_col = 2;
}

bool jump_to_helper(vdui_t *vu, cexpr_t *helper)
{
  if(helper->op != cot_helper)
    return false;

  hrefvec_t list;
  helpers_locator_t loc(vu->cfunc, helper->helper, &list);
  loc.apply_to(&vu->cfunc->body, NULL);

  qstring title = "[hrt] xrefs to ";
	title.append(helper->helper);
  citem_t *call = vu->cfunc->body.find_parent_of(helper);

  href_chooser_t xrefch(CH_MODAL | CH_KEEP, call->ea, list, title.c_str());
  ea_t target = xrefch.choose(call->ea);
  if ( target == BADADDR )
    return false;

  citem_t *item = vu->cfunc->body.find_closest_addr(target);
  if (!item)
    return false;

  int x, y;
  if (!vu->cfunc->find_item_coords(item, &x, &y))
    return false;
  return jump_custom_viewer(vu->ct, y, x, 0);
}
//------------------------------------------------

ACT_DEF(jmp2xref)
{
	if (ctx->widget_type == BWN_PSEUDOCODE) {
		vdui_t *vu = get_widget_vdui(ctx->widget);
		if(vu) {
			if (vu->item.is_citem()) {
				switch(vu->item.e->op) {
				case cot_helper:
					return jump_to_helper(vu, vu->item.e);
				case cot_memptr:
				case cot_memref:
				case cot_num:
					{
						action_state_t state;
						if(get_action_state("hx:JumpGlobalXref", &state) && is_action_enabled(state))
							return process_ui_action("hx:JumpGlobalXref");// fallback to the built-in action
						break;
					}
				}
			}
		}
		return process_ui_action("hx:JmpXref");// fallback to the built-in action
	}
	return process_ui_action("JumpOpXref"); // fallback to the built-in action
}

//--------------------------------------------------------------------------
//stack strings
static bool idaapi is_stack_var_assign_int(const cexpr_t * stmt, const lvars_t* lvars, int* varIdx, cexpr_t** val, sval_t* size)
{
	cexpr_t *left = nullptr;
	cexpr_t *right = nullptr;
	if(stmt->op == cot_asg) {
		left = stmt->x;
		right = stmt->y;
	} else if(stmt->op == cot_call && stmt->x->op == cot_helper) {
		if(!qstrcmp("qmemcpy", stmt->x->helper)) {
			carglist_t &args = *stmt->a;
			if(args.size() >= 2) {
				left = &args[0];
				right = &args[1];
			}
		}
	} else
		return false;
	if(!left || !right)
		return false;

	//skip (cast)cost
	if(right->op == cot_cast && right->x->op == cot_num)
		right = right->x;

	if(right->op != cot_num && right->op != cot_obj && right->op != cot_str)
		return false;

	int vIdx;
	if(left->op == cot_var) {
		vIdx = left->v.idx;
	} else if(left->op == cot_ptr &&
						left->x->op == cot_cast &&
						left->x->x->op == cot_var) {
		// *(DWORD*)var = 0xC0NST
		vIdx = left->x->x->v.idx;
	} else
		return false;

	const lvar_t* var= &lvars->at(vIdx);
	if(!var->is_stk_var())
		return false;

	if(varIdx)
		*varIdx = vIdx;
	if (val)
		*val = right;
	if(size) {
		*size = BADADDR;
		if(left->op == cot_var)
			*size = (sval_t)var->tif.get_size();
		else if(left->op == cot_ptr)
			*size = (sval_t)left->ptrsize;
	}

	return true;
}

bool is_stack_var_assign(vdui_t *vu, int* varIdx, ea_t *asgn_ea, sval_t* size)
{
	if (!vu->item.is_citem())
		return false;

	citem_t* expr = vu->item.e;
	cexpr_t *asgn = get_assign_or_helper(vu, expr, true);
	if(asgn && is_stack_var_assign_int(asgn, vu->cfunc->get_lvars(), varIdx, NULL, size)) {
		if(asgn_ea)
			*asgn_ea = asgn->ea;
		return true;
	}

	//If the cursor placed over variable usage, try find definition
	lvar_t *var = vu->item.get_lvar();
	if(var && var->defea != BADADDR && var->defea != vu->cfunc->entry_ea) {
		expr = vu->cfunc->body.find_closest_addr(var->defea);
		//msg("[hrt] is_stack_var_assign var %s defea: %a\n", var->name.c_str(), var->defea, expr->ea, printExp(vu->cfunc, (cexpr_t *)expr).c_str());
		asgn = get_assign_or_helper(vu, expr, true);
	}
	return asgn && is_stack_var_assign_int(asgn, vu->cfunc->get_lvars(), varIdx, NULL, size);
	//Do not set *asgn_ea. This address is the first definition of variable. Nnot the use-def chain
}

struct ida_local valNsize1_t
{
	cexpr_t* val;
	sval_t sz;
};

typedef std::map<int, valNsize1_t> var_asgn_map1_t;

struct ida_local stack_char_assign_locator_t : public ctree_visitor_t
{
	cfunc_t *func;
	var_asgn_map1_t varVal;
	ea_t skipBeforeEa;
	bool skip;
	stack_char_assign_locator_t(cfunc_t *func_, ea_t skipBeforeEa_, bool skipEarlyAssignment = true): ctree_visitor_t(CV_FAST), func(func_), skipBeforeEa(skipBeforeEa_), skip(skipEarlyAssignment)
	{
		//msg("[hrt] build stack string: skipBeforeEa %a\n", skipBeforeEa);
	}
	int idaapi visit_expr(cexpr_t * e)
	{
		int varIdx;
		cexpr_t* val;
		valNsize1_t vs;
		if(is_stack_var_assign_int(e, func->get_lvars(), &varIdx, &val, &vs.sz))
		{
			if(skip && e->ea == skipBeforeEa) // check if (e->ea < skipBeforeEa) works wrong when blocks are not address orderdered
				skip = false;
			if (skip) {
				//msg("[hrt] %a: build stack string: skip early writing assignment '%s'\n", e->ea, printExp(func, e).c_str());
				return 0;
			}
			auto it = varVal.find(varIdx);
			if(it != varVal.end()) {
				//msg("[hrt] %a: build stack string: skip overwriting assignment '%s'\n", e->ea, printExp(func, e).c_str());
				return 0;
			}
			//msg("[hrt] %a: build stack string: use assignment '%s'\n", e->ea, printExp(func, e).c_str());
			vs.val = val;
			varVal[varIdx] = vs;
		}
		return 0;
	}
};

static void assign2wstr(qvector<wchar16_t> &wstr, uint64 _value, sval_t size)
{
	wstr.push_back((wchar16_t)_value);
	if(size > 2)
		wstr.push_back((wchar16_t)(_value >> 16));
	if(size > 4) {
		wstr.push_back((wchar16_t)(_value >> 32));
		wstr.push_back((wchar16_t)(_value >> 48));
	}
}

static void assign2astr(qvector<char> &str, uint64 _value, sval_t size)
{
	str.push_back((char)_value);
	if(size > 1)
		str.push_back((char)(_value >> 8));
	if(size > 2) {
		str.push_back((char)(_value >> 16));
		str.push_back((char)(_value >> 24));
	}
	if(size > 4) {
		str.push_back((char)(_value >> 32));
		str.push_back((char)(_value >> 40));
		str.push_back((char)(_value >> 48));
		str.push_back((char)(_value >> 56));
	}
}

static int scan_stack_string2(action_activation_ctx_t *ctx, bool bDecrypt)
{
	int varIdx, vi;
	ea_t asgn_ea = BADADDR;
	sval_t char_size;
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if(!is_stack_var_assign(vu, &varIdx, &asgn_ea, &char_size))
		return 0;
	if(asgn_ea == BADADDR && vu->item.is_citem()) {
		cexpr_t* asgn = get_assign_or_helper(vu, vu->item.e, true);
		if(asgn)
			asgn_ea = asgn->ea;
	}
	if(asgn_ea == BADADDR)
		asgn_ea = ctx->cur_ea;

	ushort single = 1;
	if(char_size != 1 && char_size != 2) {
		ushort strType_ = 0;
		const char format[] =
		  "[hrt] Scan stack string\n\n"
		  "<##char size?##~B~yte:R>\n"
		  "<~W~ord:r>>\n"
			"<###Clear checkbox for the multiple string re-assignment. "
			"This option disables look for assignments before current statement#~S~ingle:c>>\n";
		if(!ask_form(format, &strType_, &single))
			return false;
		char_size = strType_ + 1;
	}

	user_numforms_t *numForms = NULL;
	if(!bDecrypt) {
		numForms = restore_user_numforms(vu->cfunc->entry_ea);
		if(!numForms)
			numForms = user_numforms_new();
	}

	lvars_t* lvars = vu->cfunc->get_lvars();
	stack_char_assign_locator_t loc(vu->cfunc, asgn_ea, single == 0);
	loc.apply_to(&vu->cfunc->body, NULL);

	qvector<char> astr;
	qvector<wchar16_t> wstr;
	uint32 nVarsFound = 0;
	lvar_t* var= &lvars->at(varIdx);
	vi = varIdx;
	sval_t last_asgn_size = char_size;
	for(sval_t spoff = var->location.stkoff(); vi != -1; spoff += last_asgn_size) {
		vi =  lvars->find_stkvar(spoff, (int)char_size);
		var_asgn_map1_t::iterator it = loc.varVal.find(vi);
		if(it == loc.varVal.end())
			break;
		nVarsFound++;
		if(!bDecrypt && !it->second.val) //zeroterminate
			break;

		cexpr_t* val = it->second.val;
		last_asgn_size = it->second.sz;

		if(val->op == cot_str) {
			last_asgn_size = (decltype(last_asgn_size))qstrlen(val->string);
			if(char_size == 2) {
				qwstring qws;
				utf8_utf16(&qws, val->string, (int)last_asgn_size);
				wstr.insert(wstr.end(), qws.begin(), qws.end());
				last_asgn_size *= 2;
			} else {
				astr.insert(astr.end(), val->string, val->string + last_asgn_size);
			}
			continue;
		}

		QASSERT(100108, last_asgn_size > 0 && last_asgn_size <= 16);
		uint64 _value;
		if(val->op == cot_obj) {
			switch(last_asgn_size) {
			case 1: _value = get_byte(val->obj_ea); break;
			case 2: _value = get_word(val->obj_ea); break;
			case 4: _value = get_dword(val->obj_ea); break;
			case 8: _value = get_qword(val->obj_ea); break;
			case 16:
				if(char_size == 2) {
					assign2wstr(wstr, get_qword(val->obj_ea), 8);
				} else {
					assign2astr(astr, get_qword(val->obj_ea), 8);
				}
				_value = get_qword(val->obj_ea + 8); break;
				break;
			default:
				QASSERT(100109, last_asgn_size);
			}
		} else {
			QASSERT(100104, val->op == cot_num);
			_value = val->n->_value;
		}

		//val->op == cot_num && cot_obj
		if(char_size == 2) {
			assign2wstr(wstr, _value, last_asgn_size);
		} else {
			assign2astr(astr, _value, last_asgn_size);
		}

		if(!bDecrypt && val->op == cot_num) { //set char representation flag
			ea_t insEa = it->second.val->ea;
			if(insEa != BADADDR && is_code(get_flags(insEa))) {
				insn_t cmd;
				decode_insn(&cmd, insEa);
				int opnum = 1;
				if(cmd.Op2.type == o_void) //push
					opnum = 0;
				operand_locator_t valOp(insEa, opnum);
				user_numforms_iterator_t fmtIt = user_numforms_find(numForms, valOp);
				if (fmtIt == user_numforms_end(numForms)) {
					number_format_t valFmt;
					valFmt.flags = char_flag();
					user_numforms_insert(numForms, valOp, valFmt);
				}
			}
		}
	}

	if(nVarsFound) {
		if(bDecrypt) {
			const char* inBuf;
			size_t len;
			ushort hint_itSz = (ushort)char_size - 1;
			if(char_size == 2) {
				inBuf = (const char*)wstr.begin();
				len = wstr.size();
			} else {
				inBuf = (const char*)astr.begin();
				len = astr.size();
			}
			qstring result;
			if(!decrypt_string(vu, BADADDR, inBuf, len, &hint_itSz, &result))
				return 0;
		} else {
			// make comment for statement
			qstring str;
			if(char_size == 2) {
				utf16_utf8(&str, wstr.begin(), (int)wstr.size());
			} else {
				str = qstring(astr.begin(), astr.size());
			}
			set_cmt(asgn_ea, str.c_str(), true);
		}

		if(!bDecrypt) {
			if(user_numforms_size(numForms))
				save_user_numforms(vu->cfunc->entry_ea, numForms);
			user_numforms_free(numForms);
		}

		if(single) {
			// make array type for var
			tinfo_t charType, arrType;
			if(char_size == 2) {
				charType.create_simple_type(BT_INT16);
				arrType.create_array(charType, (uint32)wstr.size());
			} else {
				charType.create_simple_type(BT_INT8 | BTMT_CHAR);
				arrType.create_array(charType, (uint32)astr.size());
			}
			set_var_type(vu, var, &arrType);
		}

#if 0 // var will be renamed by comment
		qstring funcname;
		get_func_name(&funcname, vu->cfunc->entry_ea);
		renameVar(asgn_ea, funcname.c_str(), vu->cfunc, varIdx, &str, vu);
#endif
		//msg("[hrt] %a: build stack string for var '%s' - '%s'\n", vu.cfunc->entry_ea, var->name.c_str(), str.c_str());
		REFRESH_FUNC_CTEXT(vu);
	}
	return 0;
}

ACT_DEF(scan_stack_string)
{
	return scan_stack_string2(ctx, false);
}

ACT_DEF(scan_stack_string_n_decr)
{
	return scan_stack_string2(ctx, true);
}

//--------------------------------------------------------------------------
//array strings
static bool idaapi is_array_char_assign_int(cexpr_t * asg, int* varIdx, int* arrIdx, cexpr_t** val)
{
	if (asg->op != cot_asg || asg->y->op != cot_num)
		return false;

	uint64 idx = 0;
	if (asg->x->op == cot_idx)
		idx = asg->x->y->n->_value;
	else if (asg->x->op != cot_ptr)
		return false;

	if(asg->x->x->op != cot_var) //TODO: global
		return false;

	if (varIdx)
		*varIdx = asg->x->x->v.idx;
	if (val) {
		*val = asg->y;
		*arrIdx = (int)idx;
	}
	return true;
}

bool is_array_char_assign(vdui_t *vu, int* varIdx, ea_t *ea)
{
	if (!vu->item.is_citem())
		return false;

	citem_t* expr = vu->item.e;
	while (expr && expr->op <= cot_last) {
		expr = vu->cfunc->body.find_parent_of(expr);
	}
	if (!expr || expr->op != cit_expr)
		return false;

	if (ea)
		*ea = ((cexpr_t *)expr)->x->ea;
	return is_array_char_assign_int(((cexpr_t *)expr)->x, varIdx, NULL, NULL);
}

struct ida_local valNsize2_t
{
	uint64 val;
	ea_t ea;
	sval_t sz;
};

typedef std::map<int, valNsize2_t> var_asgn_map2_t;

struct ida_local array_char_assign_locator_t : public ctree_visitor_t
{
	cfunc_t *func;
	int varIdx;
	var_asgn_map2_t varVal;
	ea_t skipBeforeEa;
	array_char_assign_locator_t(cfunc_t *func_, int varIdx_, ea_t skipBeforeEa_) : 
		ctree_visitor_t(CV_FAST), func(func_), varIdx(varIdx_), skipBeforeEa(skipBeforeEa_) {}
	int idaapi visit_expr(cexpr_t * e)
	{
		valNsize2_t vs;
		int varI;
		int arrIdx;
		cexpr_t* val;
		if (is_array_char_assign_int(e, &varI, &arrIdx, &val) && varI == varIdx)
		{
			if (e->ea < skipBeforeEa) {
				msg("[hrt] %a: build array string: skip early writing assignment '%s'\n", val->ea, printExp(func, e).c_str());
				return 0;
			}
			auto it = varVal.find(arrIdx);
			if (it != varVal.end()) {
				msg("[hrt] %a: build array string: skip overwriting assignment '%s'\n", val->ea, printExp(func, e).c_str());
				return 0;
			}
			QASSERT(100105, val->op == cot_num);
			vs.val = val->n->_value;
			vs.ea = val->ea;
			vs.sz = 0;
			varVal[arrIdx] = vs;
		}
		return 0;
	}
};

ACT_DEF(scan_array_string)
{
	int varIdx;
	ea_t ea;
	sval_t char_size;
	sval_t asgn_size;
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if (!is_array_char_assign(vu, &varIdx, &ea))
		return 0;

	lvars_t* lvars = vu->cfunc->get_lvars();
	lvar_t* var = &lvars->at(varIdx);
	tinfo_t t = var->tif;
	t.remove_ptr_or_array();
	asgn_size = char_size = (sval_t)t.get_size();

	while (char_size != 1 && char_size != 2 && char_size != 4) {
		if (!ask_long(&char_size, "Please specify item size (1/2/4)"))
			return 0;
	}

	array_char_assign_locator_t loc(vu->cfunc, varIdx, ctx->cur_ea);
	loc.apply_to(&vu->cfunc->body, NULL);

	qvector<char> tmpbuf;
	uint32 len = 0;
	//TODO: check array indexes 0..max
	for (var_asgn_map2_t::iterator it = loc.varVal.begin(); it != loc.varVal.end(); it++) {
		len++;
		//no zeroterminate for decryption
		//if (!it->second.val) //zeroterminate
		//	break;
		uint64 _value = it->second.val;

		assign2astr(tmpbuf, _value, asgn_size);
	}
	if (!len)
		return 0;

	const char* inBuf = &tmpbuf[0];
	ushort hint_itSz = (ushort)(char_size <= 2 ? char_size - 1 : 2);
	qstring result;
	if (!decrypt_string(vu, BADADDR, inBuf, len, &hint_itSz, &result)) //do not decrypt last zero
		return 0;

	qstring funcname;
	get_func_name(&funcname, vu->cfunc->entry_ea);
	renameVar(ea, funcname.c_str(), vu->cfunc, varIdx, &result, vu);

	vu->refresh_view(true);
	//not return true because refresh it here
	return 0;
}

//--------------------------------------------------------------------------

ACT_DEF(decrypt_const)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if (!vu->item.is_citem())
		return 0;
	cexpr_t *e = vu->item.e;
	if (e->op != cot_num)
		return 0;

	qvector<char> tmpbuf;
	tmpbuf.resize(16);
	*(uint64*)&tmpbuf[0] = e->n->_value;

	const char* inBuf = &tmpbuf[0];
	ushort hint_itSz = 2; // 0 - BYTE, 1 - WORD, 2 - DWORD, 3 - QWORD
	switch(e->n->nf.org_nbytes) {
	case 8: hint_itSz = 3;break;
	case 4: hint_itSz = 2;break;
	case 2: hint_itSz = 1;break;
	case 1: hint_itSz = 0;break;
	}

	qstring result;
	if (!decrypt_string(vu, BADADDR, inBuf, 1, &hint_itSz, &result)) //do not decrypt last zero
		return 0;

	vu->refresh_view(false);
	//not return true because refresh it here
	return 0;
}

//--------------------------------------------------------------------------

bool is_decryptable_obj(vdui_t *vu, ea_t* pea)
{
	if (!vu->item.is_citem())
		return false;

	cexpr_t * var = vu->item.e;
	if (var->op == cot_str) {
		if(pea)
			*pea = BADADDR;
		return true;
	}

	if (var->op != cot_obj)
		return false;

	ea_t ea = var->obj_ea;
  flags64_t flg = get_flags(ea);
  if (!is_data(flg) && !is_unknown(flg))
    return false;
  if (!is_mapped(ea))
    return false;

	if(pea)
		*pea = ea;

	return true;
}

ACT_DEF(decrypt_string_obj)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	ea_t ea;
	if (!is_decryptable_obj(vu, &ea))
		return 0;

	static ushort itSz = 0;
	qstring result;
	if(ea == BADADDR && vu->item.e->op == cot_str) {
		if(qstrchr(vu->item.e->string, '\\'))
			warning("[hrt] FIXME: de-escape cot_str at %a\n%s", vu->item.e->ea, vu->item.e->string);
		itSz = 0;
		if (decrypt_string(vu, ea, vu->item.e->string, qstrlen(vu->item.e->string), &itSz, &result))
			vu->refresh_view(false);
		return 0;
	}

  flags64_t flg = get_flags(ea);
  ea_t ea_end = get_item_end(ea);
	int64 len = ea_end - ea;
	if(is_strlit(flg)) {
		opinfo_t oi;
		if (get_opinfo(&oi, ea, 0, flg)) {
			itSz = get_str_type_code(oi.strtype) & STRWIDTH_MASK;
			len = len / (1LL << itSz);
		}
	} else if (is_byte(flg)) {
		itSz = 0;
	}	else if (is_word(flg)) {
		len /= 2;
		itSz = 1;
	}	else if (is_dword(flg)) {
		len /= 4;
		itSz = 2;
	}	else if (is_qword(flg)) {
		len /= 8;
		itSz = 3;
	}

	//'len' from data may be incorrect, try to get it from call args
	if(len <= 1 && vu->item.is_citem()) {
		citem_t * expr = vu->item.it;
		//go up until statement
		while(expr && expr->op <= cot_last) {
			if(expr->op == cot_call)
				break;
			expr = vu->cfunc->body.find_parent_of(expr);
		}
		if(expr && expr->op == cot_call) {
			cexpr_t *call = (cexpr_t*)expr;
			carglist_t &args = *call->a;
			for(size_t i = 0; i < args.size(); i++) {
				cexpr_t *arg = &args[i];
				if(arg->op == cot_num) {
					int64 l = arg->numval();
					if(!l || l > 0x1000)
						continue;
					len = l / (1LL << itSz);
					//break; //scan until last
				}
			}
		}
	}

	if (decrypt_string(vu, ea, NULL, len, &itSz, &result))
		vu->refresh_view(false);
	return 0;
}

ACT_DEF(decrypt_data)
{
	ea_t ea = ctx->cur_ea;
	flags64_t flg = get_flags(ea);
	if (!is_data(flg) && !is_unknown(flg))
		return 0;

	ea_t ea_end = get_item_end(ea);
	bool fromSel = false;
	if(ctx->has_flag(ACF_HAS_SELECTION) && read_range_selection(NULL, &ea, &ea_end))
	{
		fromSel = true;
	} else {
		if(is_unknown(flg)) {
			for(;;) {
				flags64_t f = get_full_flags(ea_end);
				if(!is_unknown(f)
					 || has_xref(f)
					 || !has_value(f)
					 || (uint8)f == 0)
					break;
				++ea_end;
			}
		}
	}

	int64 len = ea_end - ea;
	static ushort itSz = 0; //static keep previous selection for unknown type
	if(is_strlit(flg)) {
		opinfo_t oi;
		if (get_opinfo(&oi, ea, 0, flg)) {
			itSz = get_str_type_code(oi.strtype) & STRWIDTH_MASK;
			len = len / (1LL << itSz);
		}
	} else if (is_byte(flg)) {
		itSz = 0;
	} else if (is_word(flg)) {
		len /= 2;
		itSz = 1;
	}	else if (is_dword(flg)) {
		len /= 4;
		itSz = 2;
	}	else if (is_qword(flg)) {
		len /= 8;
		itSz = 3;
	}

	qstring result;
	if (decrypt_string(NULL, ea, NULL, len, &itSz, &result)) {
		if (fromSel)
			unmark_selection();
		//request_refresh(IWID_DISASMS);
	}
	return 0;
}

//--------------------------------------------------------------------------

ACT_DEF(do_appcall)
{
	return do_appcall2(get_widget_vdui(ctx->widget));
}

//--------------------------------------------------------------------------
// brackets matching
#define BR_BG_COLOR 0x7f7f7f
struct ida_local bracketsMatching {
	bool Safe;
	bgcolor_t OldBg[2];
	int OldYpos[2];
	int TheOtherLine;
	qstring oldLine;
	int oldLineIdx;

	bracketsMatching() { clr(); }
	void clr() {
		Safe = true;
		OldBg[0] = 0;
		OldBg[1] = 0;
		OldYpos[0] = 0;
		OldYpos[1] = 0;
		TheOtherLine = 0;
		oldLine.qclear();
		oldLineIdx = 0;
	}
	bool restoreOldBg(vdui_t &vu, strvec_t &ps, bool refresh = true)
	{
		bool clear = false;
		for (int i = 0; i < 2; i++) {
			if (OldYpos[i]) {
				ps[OldYpos[i]].bgcolor = OldBg[i];
				clear = true;
			}
			OldYpos[i] = 0;
		}
		TheOtherLine = 0;
		if(oldLine.length()) {
			ps[oldLineIdx] = oldLine;
			oldLine.qclear();
			clear = true;
		}
		if (clear && refresh)
			refresh_custom_viewer(vu.ct); //refresh_idaview_anyway();
		return clear;
	}
	void refresh(vdui_t &vu)
	{
		ctext_position_t *pos = &vu.cpos;
		int ypos = pos->lnnum;
		if (ypos < 0)
			return;
		vu.cfunc->get_pseudocode(); //regenerate pseudocoide if it neees, but this call returns const reference to pseudocode
		strvec_t &ps = vu.cfunc->sv;
		if (ypos >= (int)ps.size() || strpbrk(ps[ypos].line.c_str(), "{}()") == NULL) {
			restoreOldBg(vu, ps);
			return;
		}
		bool needRefresh = restoreOldBg(vu, ps, false);

		qstring curline;
		tag_remove(&curline, ps[ypos].line); //it will be problem with X position if color tags were not removed
		size_t idxO = curline.find('{');
		size_t idxC = curline.find('}');
		if ((idxO == qstring::npos && idxC == qstring::npos) ||
		    (idxO != qstring::npos && idxC != qstring::npos))
		{
#if IDA_SDK_VERSION <= 730
			//no any curve braces or both
			if(pos->x < curline.length()) {
				char ch = curline.at(pos->x);
				if(ch == '(' || ch == ')') {

					if(0) {
						qstring out;
						idb_utf8(&out, ps[ypos].line.c_str(), -1, IDBDEC_ESCAPE);
						msg("[hrt] got '%c' at %d \n'%s'\n", ch, pos->x, out.c_str());
					}

					int dir;
					int bgn, end;
					char bracechar;
					if(ch == '(') {
						dir = 1;
						bracechar = ')';
						bgn = pos->x;
					} else {
						dir = -1;
						bracechar = '(';
						end = pos->x;
					}
					int cnt = 0;
					for (int j = pos->x + dir; j >= 0 && j < (int)curline.length(); j += dir) {
						if(curline[j] == ch)
							cnt++;
						if(curline[j] == bracechar && cnt-- == 0) {
							if(dir > 0)
								end = j;
							else
								bgn = j;

							oldLineIdx = ypos;
							oldLine = ps[ypos].line;
							char *line = ps[ypos].line.begin();
							replace_colortag_inplace(line, end + 1, COLOR_OFF, COLOR_SYMBOL, COLOR_ERROR);
							replace_colortag_inplace(line, end    , COLOR_ON , COLOR_SYMBOL, COLOR_ERROR);
							replace_colortag_inplace(line, bgn + 1, COLOR_OFF, COLOR_SYMBOL, COLOR_ERROR);
							replace_colortag_inplace(line, bgn    , COLOR_ON , COLOR_SYMBOL, COLOR_ERROR);
							needRefresh = true;

							if(0) {
								qstring out;
								idb_utf8(&out, ps[ypos].line.c_str(), -1, IDBDEC_ESCAPE);
								msg("[hrt] got pair '%c' at %d\n'%s'\n", bracechar, j, out.c_str());
							}
							break;
						}
					}
				}
			}
			if(0) {
				qstring out;
				idb_utf8(&out, ps[ypos].line.c_str(), -1, IDBDEC_ESCAPE);
				msg("[hrt] cur line '%s'\n", out.c_str());
			}
#endif //IDA_SDK_VERSION <= 730
			if(needRefresh)
				refresh_custom_viewer(vu.ct);
			return;
		}

		//curve brace found in line
		int dir;
		char bracechar;
		size_t xpos;
		if (idxO != qstring::npos) {
			OldBg[0] = ps[ypos].bgcolor;
			OldYpos[0] = ypos;
			dir = 1;
			bracechar = '}';
			xpos = idxO;
		}
		else {
			OldBg[1] = ps[ypos].bgcolor;
			OldYpos[1] = ypos;
			dir = -1;
			bracechar = '{';
			xpos = idxC;
		}
		ps[ypos].bgcolor = BR_BG_COLOR;

		for (int j = ypos + dir; j >= 0 && j < (int)ps.size(); j += dir) {
			qstring line;
			tag_remove(&line, ps[j].line);
			size_t idx = line.find(bracechar);
			if (idx != qstring::npos && xpos == idx) {
				if (idxO != qstring::npos) {
					OldBg[1] = ps[j].bgcolor;
					OldYpos[1] = j;
				}
				else {
					OldBg[0] = ps[j].bgcolor;
					OldYpos[0] = j;
				}
				ps[j].bgcolor = BR_BG_COLOR;
				TheOtherLine = j;
				break;
			}
		}
		refresh_custom_viewer(vu.ct); //refresh_idaview_anyway();
	}
};

std::map<TWidget *, bracketsMatching*> brMap;
bracketsMatching* getBr(TWidget * form)
{
	std::map<TWidget *, bracketsMatching*>::iterator it = brMap.find(form);
	if (it != brMap.end())
		return it->second;
	return NULL;
}

void safeBr(TWidget * form, bool bSafe)
{
	std::map<TWidget *, bracketsMatching*>::iterator it = brMap.find(form);
	if (it != brMap.end()) {
		if (bSafe)
			it->second->clr();
		else
			it->second->Safe = false;
	}
	else if (bSafe) {
		bracketsMatching* br = new bracketsMatching;
		brMap[form] = br;
	}
}

void delBr(TWidget * form)
{
	std::map<TWidget *, bracketsMatching*>::iterator it = brMap.find(form);
	if (it == brMap.end())
		return;
	delete it->second;
	brMap.erase(it);
}

int brJump(TWidget *ct, int line)
{
	int x,y, oldline;
	place_t * pl = get_custom_viewer_place(ct, false, &x, &y);
	simpleline_place_t * newplace = (simpleline_place_t*)pl->clone();
	oldline = newplace->n;
	newplace->n = line;
	jumpto(ct, newplace, x, y);
	return oldline;
}


//--------------------------------------------------------------------------
// This callback handles various hexrays events.
static ssize_t idaapi callback(void *, hexrays_event_t event, va_list va)
{
	static ea_t last_globopt_ea = BADADDR;
#ifdef _DEBUG
	if (1) { // dump_mba at each stage
		mbl_array_t *mba = NULL;
		const char* evName = "";
		va_list vac;
		va_copy(vac, va);
		switch (event) {
		case hxe_flowchart:        ///< Flowchart has been generated.
		{
			qflow_chart_t *fc = va_arg(vac, qflow_chart_t *);
			break;
		}
		case hxe_stkpnts:          ///< SP change points have been calculated.
		{
			mba = va_arg(vac, mbl_array_t *);
			stkpnts_t * stkpnts = va_arg(vac, stkpnts_t *);
			mba = NULL; //mba is empty now
			break;
		}
		case hxe_prolog:           ///< Prolog analysis has been finished.
		{
			mba = va_arg(vac, mbl_array_t *);
			qflow_chart_t *fc = va_arg(vac, qflow_chart_t *);
			bitset_t *reachable_blocks = va_arg(vac, bitset_t *);
			int decomp_flags = va_arg(vac, int);
			mba = NULL; //mba is empty now
			break;
		}
		case hxe_microcode:        ///< Microcode has been generated.
			evName = "hxe_microcode";
			mba = va_arg(vac, mbl_array_t*);
			break;
		case hxe_preoptimized:     ///< Microcode has been preoptimized.
			evName = "hxe_preoptimized";
			mba = va_arg(vac, mbl_array_t*);
			break;
		case hxe_locopt:           ///< Basic block level optimization has been finished.
			evName = "hxe_locopt";
			mba = va_arg(vac, mbl_array_t*);
			break;
		case hxe_prealloc:         ///< Local variables: preallocation step begins.
			evName = "hxe_prealloc";
			mba = va_arg(vac, mbl_array_t*);
			break;
		case hxe_glbopt:           ///< Global optimization has been finished.
			evName = "hxe_glbopt";
			mba = va_arg(vac, mbl_array_t*);
			break;
		//case hxe_structural:       ///< Structural analysis has been finished.
		//case hxe_combine:          ///< Trying to combine instructions of basic block.
		case hxe_resolve_stkaddrs: ///< The optimizer is about to resolve stack addresses.
			evName = "hxe_resolve_stkaddrs";
			mba = va_arg(vac, mbl_array_t *);
			break;
		}
		va_end(vac);
		if (mba) {
			mba->dump_mba(false, "[hrt] callback%d %s", event, evName);
		}
	}
#endif

	switch ( event ) {
#if IDA_SDK_VERSION < 900
	case hxe_resolve_stkaddrs:
		{
			mbl_array_t *mba = va_arg(va, mbl_array_t *);
			golang_check(mba);
			break;
		}
#endif //IDA_SDK_VERSION < 900
	case hxe_microcode:
		{
			mbl_array_t *mba = va_arg(va, mbl_array_t *);
			deinline_reset(mba);
			deob_preprocess(mba);
			ufCurr = BADADDR;
			return MERR_OK;
		}
	case hxe_preoptimized:
	{
		mbl_array_t *mba = va_arg(va, mbl_array_t *);
		deob_preoptimized(mba);
		return MERR_OK;
	}
	case hxe_glbopt:
		{
			mbl_array_t *mba = va_arg(va, mbl_array_t *);
			last_globopt_ea = mba->entry_ea;
			bool changed = deinline(mba);
			changed |= deob_postprocess(mba, NULL);
			changed |= unflattening(mba);
			if (changed)
				return MERR_LOOP;
			return MERR_OK;
		}
	case hxe_close_pseudocode:
		{
			vdui_t *vu = va_arg(va, vdui_t *);
			delBr(vu->ct);
			deinline_reset(vu, true);
			break;
		}
	case hxe_func_printed:
		{
			cfunc_t* cfunc = va_arg(va, cfunc_t*);
			if(ufCurr == cfunc->entry_ea) {
				//has been sucessfuly unflattened first time
				ufDelGL(ufCurr);
				ufAddWL(ufCurr);
			}
			if (ufIsInGL(cfunc->entry_ea))
				cfunc->sv.insert(cfunc->sv.begin(), simpleline_t("// The function may be unflattened"));
			else if (ufIsInWL(cfunc->entry_ea))
				cfunc->sv.insert(cfunc->sv.begin(), simpleline_t("// The function seems has been flattened"));

			if (last_globopt_ea == cfunc->entry_ea) { //avoid mba restored from cache
				const char* msigName = msig_match(cfunc->mba);
				if (msigName) {
					qstring cmt; cmt.sprnt("// The function matches msig '%s'", msigName);
					cfunc->sv.insert(cfunc->sv.begin(), simpleline_t(cmt));
#if 1
					cmt = get_name(cfunc->entry_ea);
					if(!is_uname(cmt.c_str()))
						set_name(cfunc->entry_ea, msigName);
#endif
				}
			}
			break;
		}
#if IDA_SDK_VERSION < 760
	case hxe_text_ready:
		//marked as obsolete in ida 7.6, tring to move into hxe_refresh_pseudocode
#else //IDA_SDK_VERSION >= 760
	  case hxe_refresh_pseudocode:
#endif //IDA_SDK_VERSION < 760
		{
			vdui_t &vu = *va_arg(va, vdui_t *);
			safeBr(vu.ct, true);
			break;
		}	
	case hxe_switch_pseudocode:
		{
			vdui_t *vu = va_arg(va, vdui_t *);
			safeBr(vu->ct, false);
			deinline_reset(vu, false); //FIXME: it seems new entry_ea here, I need the old one
			break;
		}
	case hxe_create_hint:
	{
		vdui_t *vu = va_arg(va, vdui_t *);
		qstring *result_hint = va_arg(va, qstring *);
		int *implines = va_arg(va, int *);
#if IDA_SDK_VERSION < 760
		///< Possible return values:
		///<  0: the event has not been handled
		///<  1: hint has been created (should set *implines to nonzero as well)
		///<  2: hint has been created but the standard hints must be
		///<     appended by the decompiler
#else //IDA_SDK_VERSION >= 760
    ///< Possible return values:
    ///< \retval 0 continue collecting hints with other subscribers
    ///< \retval 1 stop collecting hints
#endif //IDA_SDK_VERSION < 760
		if (vu->item.is_citem() && vu->item.e->op == cot_helper)
			return deinline_hint(vu, result_hint, implines);
		return 0;
	}
	case hxe_curpos:
		{
			vdui_t &vu = *va_arg(va, vdui_t *);
			if (vu.cfunc->maturity == CMAT_FINAL && vu.visible()) {
				bracketsMatching* br = getBr(vu.ct);
				if(br && br->Safe && vu.refresh_cpos(USE_KEYBOARD)) {
					br->refresh(vu);
				}
			}
			break;
		}
	case hxe_populating_popup:
		{
			TWidget *form = va_arg(va, TWidget *);
			TPopupMenu *popup = va_arg(va, TPopupMenu *);
			vdui_t *vu = va_arg(va, vdui_t *);
			add_hrt_popup_items(form, popup, vu);
		}
		break;
	case hxe_keyboard:
		{
			vdui_t &vu = *va_arg(va, vdui_t *);
			int key_code  = va_arg(va, int);
			int shift_state = va_arg(va, int);
			//msg("[hrt] key %x/%x (%c)\n", shift_state, key_code, key_code);
			if (shift_state == 0)
			{
				switch (key_code)
				{
				case ']':
				case '[':
				case 0x425: // crutch for ida64 + wine, sometimes send wrong codes instead []
				case 0x42a: 
				{
					bracketsMatching* br = getBr(vu.ct);
					if(br && br->Safe && br->TheOtherLine) {
						br->TheOtherLine = brJump(vu.ct, br->TheOtherLine);
						return 1;
					}
				}
					break;
#if 0
				case IK_RETURN: //Doesnt work now! Ida steals this keypress before callback
					{
						vu.get_current_item(USE_KEYBOARD);
						return jump_to_call_dst(&vu); // Should return: 1 if the event has been handled
					}
#endif
				}
			}
		}
		break;
	case hxe_double_click:
		{
			vdui_t &vu = *va_arg(va, vdui_t *);
			vu.get_current_item(USE_MOUSE);
			return jump_to_call_dst(&vu); // Should return: 1 if the event has been handled
		}
		break;
	case hxe_maturity:
		{
			cfunc_t *cfunc = va_arg(va, cfunc_t *);
			ctree_maturity_t new_maturity = va_argi(va, ctree_maturity_t);
#if _DEBUG
			{
				const char* fname = "UNK";
				switch (new_maturity) {
				case CMAT_ZERO:   fname = "0CMAT_ZERO"; break;
				case CMAT_BUILT:	fname = "1CMAT_BUILT"; break;
				case CMAT_TRANS1:	fname = "2CMAT_TRANS1"; break;
				case CMAT_NICE:		fname = "3CMAT_NICE"; break;
				case CMAT_TRANS2:	fname = "4CMAT_TRANS2"; break;
				case CMAT_CPA:		fname = "5CMAT_CPA"; break;
				case CMAT_TRANS3:	fname = "6CMAT_TRANS3"; break;
				case CMAT_CASTED:	fname = "7CMAT_CASTED"; break;
				case CMAT_FINAL:	fname = "8CMAT_FINAL"; break;
				}
				dump_ctree(cfunc, fname);
			}
#endif
			if(new_maturity == CMAT_BUILT) {
			} else if(new_maturity == CMAT_CPA) {
				convert_offsetof_n_reincasts(cfunc);
			} else if(new_maturity == CMAT_TRANS3) {
				com_scan(cfunc);
			}	else if(new_maturity == CMAT_FINAL)	{
				apihashes_scan(cfunc);// before autorename_n_pull_comments: so comments be used for renaming
				autorename_n_pull_comments(cfunc);
				lit_scan(cfunc); // after autorename_n_pull_comments: to search literals in renamed indirect calls
				make_if42blocks(cfunc);
			}
			//cfunc->verify(ALLOW_UNUSED_LABELS, false);
		}
		break;
	case lxe_lvar_name_changed:
		{
			vdui_t *vu = va_arg(va, vdui_t *);
			lvar_t *v = va_arg(va, lvar_t *);
			const char *name = va_arg(va, const char *);
			int is_user_name = va_arg(va, int);
			if (qstrcmp(name, v->name.c_str())) {
				msg("[hrt] IDA bug: lxe_lvar_name_changed is sent for wrong variable ('%s' instead of '%s')\n", v->name.c_str(), name);
				lvars_t *vars = vu->cfunc->get_lvars();
				auto it = vars->begin();
				for(; it != vars->end(); it++)
					if(it->name == name)
						break;
				if(it == vars->end())
					break;
				v = it;
			}
			if (is_user_name && !v->has_user_type()) {
			  tinfo_t t = getType4Name(name);
				if(!t.empty() && set_var_type(vu, v, &t))
					msg("[hrt] %a: type of var '%s' refreshed\n", vu->cfunc->entry_ea, name);
			}
			break;
		}
	  case lxe_lvar_type_changed:
		{
		 //for Hex-Rays Decompiler plugin version >= "v7.1.0.180528" / else crash
			vdui_t *vu = va_arg(va, vdui_t *);
			lvar_t *v = va_arg(va, lvar_t *);
			tinfo_t *tinfo = va_arg(va, tinfo_t *);
			if(getVarName(v, NULL))
				break;
			tinfo_t t = *tinfo;
			bool isPtr = false;
			if (t.is_ptr_or_array()) {//do not recurse pounters, else lxe_lvar_name_changed callback change type back to tname*
				t.remove_ptr_or_array();
				isPtr = true;
			}
			qstring tname;
			if(t.get_type_name(&tname)) {
				cfunc_t *func = vu->cfunc;
				ssize_t varIdx = func->get_lvars()->index(*v);
				if(varIdx != -1) {
					if(!isPtr)
						tname.append('_');
					qstring funcname;
					get_func_name(&funcname, func->entry_ea);
					if(renameVar(func->entry_ea, funcname.c_str(), func, varIdx, &tname, vu))
						REFRESH_FUNC_CTEXT(vu);
				}
			}
			break;
		}
	}
	return 0;
}

//turn on func window synchronization
static TWidget *StartWdg = NULL;
#if IDA_SDK_VERSION < 840
const char* FunctionsToggleSync = "FuncSwitchSync";
#else
const char* FunctionsToggleSync = "FunctionsToggleSync";
#endif

bool idaapi runFuncSwitchSync()
{
    TWidget *wdg = find_widget("Functions window");
    if(wdg && get_widget_type(wdg) == BWN_FUNCS) {
      activate_widget(wdg, true);
    } else {
      msg("[hrt] no funcs wnd\n");
      return false; //  remove the request from the queue
    }

#if 0
		TWidget * curw = get_current_widget();
		if(!curw)
			msg("[hrt] `get_current_widget` does't work\n");
		else if(curw != wdg)
			msg("[hrt] `activate_widget` does't work\n");
#endif

#if defined __LINUX__ && IDA_SDK_VERSION >= 740 && IDA_SDK_VERSION <= 750
    //ida 7.7 works without crutches
    //on ida 7.6 this trick does not works anymore
    //linux IDA 7.4 & 7.5 does not activate widget immediately
    for(int i = 10; i > 0; i--) {
      show_wait_box("This message is workaround of \"IDA for linux\" bug \n activate_widget() call does not work without this waitbox");
      qsleep(100);
      hide_wait_box();
      TWidget * curw = get_current_widget();
      if(curw == wdg)
        break;
      qstring title;
      if(curw)
        get_widget_title(&title, curw);
      msg("[hrt] %d %p '%s'\n", i, curw, title.c_str());
      activate_widget(wdg, true);
    }
#endif //defined __LINUX__  && IDA_SDK_VERSION >= 740 && IDA_SDK_VERSION <= 750

    bool checkable;
    bool bb = get_action_checkable(FunctionsToggleSync, &checkable);
    if(bb && !checkable) {
			update_action_checkable(FunctionsToggleSync, true);
			bb = get_action_checkable(FunctionsToggleSync, &checkable);
		}
		qstring lbl;
		bool bl = get_action_label(&lbl, FunctionsToggleSync);
#if 0
    action_state_t state;
    bool bs = get_action_state(FunctionsToggleSync, &state);
    if(bs && state == AST_DISABLE_FOR_WIDGET) {
      msg("[hrt] AST_DISABLE_FOR_WIDGET\n");
      //update_action_state(FunctionsToggleSync, AST_ENABLE_FOR_WIDGET);
    }
....bool checked;
    bool bc = get_action_checked(FunctionsToggleSync, &checked);
    bool visibility;
    bool bv = get_action_visibility(FunctionsToggleSync, &visibility);
    msg("[hrt] FuncSwitchSync %d-%d, %d-%d, %d-%d, %d-%d, %d-%s\n", bs, state, bb, checkable, bc, checked, bv, visibility, bl, lbl.c_str());
#endif
		if(bl && strneq(lbl.c_str(), "Turn on", 7)) { //"Turn on synchronization"
			if(process_ui_action(FunctionsToggleSync))
				msg("[hrt] turn on %s\n", FunctionsToggleSync);
			else
				msg("[hrt] fail to turn on %s\n", FunctionsToggleSync);
		}

    if(!StartWdg)
      StartWdg = find_widget("Pseudocode-A");
    if(!StartWdg)
      StartWdg = find_widget("IDA View-A");
    if(StartWdg) {
      activate_widget(StartWdg, true);
#if defined __LINUX__  && IDA_SDK_VERSION >= 740 && IDA_SDK_VERSION <= 750
    //linux IDA does not activate widget immediately
      show_wait_box("Second waitbox to activate back main window\n after turning on synchronization in Functions window");
      qsleep(100);
      hide_wait_box();
#endif //defined __LINUX__  && IDA_SDK_VERSION >= 740 && IDA_SDK_VERSION <= 750
    }
		return false; //  remove the request from the queue
}

int idaapi cbRunFuncSwitchSync(void *ud)
{
	runFuncSwitchSync();
	return -1;
}

class ida_local FuncSwitchSync_t : public ui_request_t
{
public:
  virtual bool idaapi run()
  {
		return runFuncSwitchSync();
	};
};

//-----------
// Callback for ui notifications
static ssize_t idaapi ui_callback(void *user_data, int ncode, va_list va)
{
	ui_notification_t notification_code = (ui_notification_t)ncode;
	if(notification_code == ui_populating_widget_popup) {
		TWidget * widget = va_arg(va, TWidget *);
		TPopupMenu *p = va_arg(va, TPopupMenu *);
		const action_activation_ctx_t* ctx = va_arg(va, const action_activation_ctx_t*);
		if(get_widget_type(widget) == BWN_DISASM) {
			attach_action_to_popup(widget, p, ACT_NAME(decrypt_data));
			attach_action_to_popup(widget, p, ACT_NAME(add_VT_struct));
			if (get_view_renderer_type(widget) == TCCRT_GRAPH) {
				attach_action_to_popup(widget, p, ACT_NAME(create_inline_gr), "Group nodes", SETMENU_APP);
			} else {
				attach_action_to_popup(widget, p, ACT_NAME(create_inline_sel));
			}
		}
	} else if( notification_code == ui_ready_to_run) {
		//msg("[hrt] ui_ready_to_run\n");
		StartWdg = get_current_widget();
#if IDA_SDK_VERSION < 900 //FIXME: find exact IDA version number where switch to timer
		execute_ui_requests(new FuncSwitchSync_t(), NULL);
#else
		register_timer(1000, cbRunFuncSwitchSync, NULL);
#endif
	}
	return 0;
}

static ea_t funcRenameEa;
static qstring funcRename;

// Callback for IDP notifications
static ssize_t idaapi idp_callback(void *user_data, int ncode, va_list va)
{
	processor_t::event_t code = (processor_t::event_t)ncode;
	switch (code) {
#if 0
	case processor_t::ev_auto_queue_empty:
		{
			atype_t at = va_arg(va, atype_t);
			if (at == AU_FINAL) {
				int dbgBreakHere = 0;
			}
		}
		break;
#endif
	case processor_t::ev_rename:
		{
			ea_t ea = va_arg(va, ea_t);
			//const char *new_name = va_arg(va, const char *);
			//int flags = va_arg(va, int);
			if(is_func(get_flags(ea))) {
				get_ea_name(&funcRename, ea);
				if(!funcRename.empty())
					funcRenameEa = ea;
			}
		}
	}
	return 0;
}

#if IDA_SDK_VERSION < 900
//return true to continue struc search for duplicates
typedef bool idaapi enumStrucMembersCB_t(struc_t * struc, member_t *member, void *user_data);
void enumStrucMembers(const char* memberName, enumStrucMembersCB_t cb,  void *user_data)
{
	for(uval_t idx = get_first_struc_idx(); idx != BADNODE; idx = get_next_struc_idx(idx)) {
		tid_t id = get_struc_by_idx(idx);
		struc_t * struc = get_struc(id);
		if(!struc || is_union(id))
			continue;
		asize_t off = 0;
		while (off != BADADDR) {
			member_t *member = get_member(struc, off);
			if (!member)
				break;
			qstring membName;
			get_member_name(&membName, member->id);
			if(membName == memberName || (membName[0] == 'p' && 0 == qstrcmp(membName.c_str()+1, memberName))) {
				if(!cb(struc, member, user_data))
					break;
			}
			off = get_struc_next_offset(struc, off);
		}
	}
}

bool idaapi countStrucMembersCB(struc_t * struc, member_t *member, void *cnt)
{
	(*(int*)cnt)++;
	return false;
}

bool idaapi renameStrucMembersCB(struc_t * struc, member_t *member, void *new_name)
{
	qstring oldname;
	get_member_fullname(&oldname, member->id);
	if (set_member_name(struc, member->soff, (const char*)new_name))
		msg("[hrt] struc member '%s' renamed to '%s'\n", oldname.c_str(), new_name);
	return false;
}

bool idaapi recastStrucMembersCB(struc_t * struc, member_t *member, void *user_data)
{
	if(member->eoff - member->soff == ea_size) {
		tinfo_t *tif = (tinfo_t *)user_data;
		if (SMT_OK == set_member_tinfo(struc, member, 0, *tif, SET_MEMTI_COMPATIBLE)) {
			  qstring oldname;
				qstring newType;
				tif->print(&newType);
				get_member_fullname(&oldname, member->id);
				msg("[hrt] struc member '%s' recasted to '%s'\n", oldname.c_str(), newType.c_str());
		  }
	}
	return false;
}
#else //IDA_SDK_VERSION >= 900
//return true to continue struc search for duplicates
typedef bool idaapi enumStrucMembersCB_t(tinfo_t t, qstring& fullname, size_t index, void* user_data);
void enumStrucMembers(const char* memberName, enumStrucMembersCB_t cb, void* user_data)
{
	uint32 limit = get_ordinal_limit();
	if (limit == -1)
		return;
	for (uint32 ord = 1; ord < limit; ++ord) {
		tinfo_t t;
		if (t.get_numbered_type(ord, BTF_STRUCT, false) && t.is_decl_struct()) {
			udt_type_data_t udt;
			if (t.get_udt_details(&udt)) {
				for (size_t i = 0; i < udt.size(); ++i) {
					udm_t& member = udt.at(i);
					if (member.name == memberName || (member.name[0] == 'p' && 0 == qstrcmp(member.name.c_str() + 1, memberName))) {
						qstring fullname;
						t.get_type_name(&fullname); // get_numbered_type_name
						fullname.append('.');
						fullname.append(member.name);
						if (!cb(t, fullname, i, user_data))
							break;
					}
				}
			}
		}
	}
}

bool idaapi countStrucMembersCB(tinfo_t t, qstring& fullname, size_t index, void* cnt)
{
	(*(int*)cnt)++;
	return false;
}

bool idaapi renameStrucMembersCB(tinfo_t t, qstring& fullname, size_t index, void* new_name)
{
	if (t.rename_udm(index, (const char*)new_name) == TERR_OK)
		msg("[hrt] struc member '%s' renamed to '%s'\n", fullname.c_str(), new_name);
	return false;
}

bool idaapi recastStrucMembersCB(tinfo_t t, qstring& fullname, size_t index, void* user_data)
{
	tinfo_t* tif = (tinfo_t*)user_data;
	if (t.set_udm_type(index, *tif) == TERR_OK) {
		qstring newType;
		tif->print(&newType);
		msg("[hrt] struc member '%s' recasted to '%s'\n", fullname.c_str(), newType.c_str());
	}
	return false;
}
#endif //IDA_SDK_VERSION < 900

// Callback for IDB notifications
static ssize_t idaapi idb_callback(void *user_data, int ncode, va_list va)
{
	static bool bLitTypesOverridden = false;

	idb_event::event_code_t code = (idb_event::event_code_t)ncode;
	switch (code) {
#if IDA_SDK_VERSION < 900
	case idb_event::changing_range_cmt:
	{
		range_kind_t kind = (range_kind_t)va_arg(va, int);
		const range_t *a = va_arg(va, const range_t *);
		const char* newcmt = va_arg(va, const char *);
		bool repeatable_cmt = va_arg(va, int);
		if (kind == RANGE_KIND_FUNC && !repeatable_cmt && qstrlen(newcmt) == 0) {
			golang_del(a->start_ea);
		}
		break;
	}
	case idb_event::renaming_struc_member:
		{
			struc_t  *sptr = va_arg(va, struc_t *);
			member_t *mptr = va_arg(va, member_t *);
			const char *newname = va_arg(va, const char *);
			//msg("[hrt] renaming_struc_member %s\n", newname);

			//rename VT method impl together with VT member
			if(qstrlen(newname) &&
				 strncmp(newname, "sub_", 4) &&
				 strncmp(newname, "field_", 6)) {
				qstring struCmt;
				get_struc_cmt(&struCmt, sptr->id, true);
				ea_t vt_ea;
				if (at_atoea(struCmt.c_str(), &vt_ea)) {
					ea_t subEA = get_ea(vt_ea + mptr->get_soff());
					if (is_func(get_flags(subEA))) {
						if(subEA == funcRenameEa) {
							funcRenameEa = 0; //avoid ping-pong renaming
						} else if(set_name(subEA, newname, SN_FORCE)) {
							qstring newGblName = get_name(subEA);
							//set_member_cmt(mptr, newGblName.c_str(), true);
							msg("[hrt] %a renamed to %s\n", subEA, newGblName.c_str());
						}
					}
				}
			}
		}
		break;
	case idb_event::struc_member_renamed:
		{
		  struc_t * strct = va_arg(va, struc_t *);
		  member_t *memb  = va_arg(va, member_t *);
			if(strct->is_frame())
				break;

			//if(strucname.size() && strucname[0] != '$') { // do not modify service structs
			qstring membName = get_member_name(memb->id);
			tinfo_t t        = getType4Name(membName.c_str());
			if (!t.empty()) {
				qstring strucname = get_struc_name(strct->id);
				smt_code_t code = set_member_tinfo(strct, memb, 0, t, SET_MEMTI_COMPATIBLE | SET_MEMTI_USERTI);
				if(code != SMT_OK) {
					//msg("[hrt] set_member_tinfo of '%s.%s' err %d\n", strucname.c_str(), membName.c_str(), code);
					if(ASKBTN_YES == ask_yn(ASKBTN_NO, "[hrt] Set member type of '%s.%s' may destroy other members,\nConfirm?", strucname.c_str(), membName.c_str())) {
						code = set_member_tinfo(strct, memb, 0, t, SET_MEMTI_MAY_DESTROY | SET_MEMTI_USERTI);
						//msg("[hrt] set_member_tinfo of '%s.%s' err %d\n", strucname.c_str(), membName.c_str(), code);
					}
				}
				if(code == SMT_OK)
					msg("[hrt] type of '%s.%s' refreshed\n", strucname.c_str(), membName.c_str());
			}
			//}
		  break;
		}
#else //IDA_SDK_VERSION >= 900
	//case idb_event::lt_udm_changed:
	case idb_event::lt_udm_renamed:
	{
		const char* udtname = va_arg(va, const char*);
		const udm_t* udm    = va_arg(va, const udm_t*);
		const char* oldname = va_arg(va, const char*);
		if (udm->is_special_member())
			break;

		const char* newname = udm->name.c_str();
		if (udm->name.empty() || !strncmp(newname, "sub_", 4) || !strncmp(newname, "field_", 6))
			break;

		tinfo_t struc;
		if (!struc.get_named_type(udtname))
			break;

		//rename VT method impl together with VT member
		qstring struCmt;
		if (struc.get_type_rptcmt(&struCmt)) {
			ea_t vt_ea;
			if (at_atoea(struCmt.c_str(), &vt_ea)) {
				ea_t subEA = get_ea(vt_ea + udm->offset / 8);
				if (is_func(get_flags(subEA))) {
					if (subEA == funcRenameEa) {
						funcRenameEa = 0; //avoid ping-pong renaming
					}	else if (set_name(subEA, newname, SN_FORCE)) {
						qstring newGblName = get_name(subEA);
						msg("[hrt] %a renamed to %s\n", subEA, newGblName.c_str());
					}
				}
			}
		}

		// set type for new name if new member name is same as lib function or structure
		tinfo_t t = getType4Name(newname);
		if (!t.empty()) {
			int index = struc.find_udm(udm->offset);
			if (index  != -1) {
				tinfo_code_t code = struc.set_udm_type(index, t, ETF_COMPATIBLE | ETF_BYTIL);
				if (code != TERR_OK && ASKBTN_YES == ask_yn(ASKBTN_NO, "[hrt] Set member type of '%s.%s' may destroy other members,\nConfirm?", udtname, newname))
					code = struc.set_udm_type(index, t, ETF_MAY_DESTROY | ETF_BYTIL);
				if (code == TERR_OK)
					msg("[hrt] type of '%s.%s' refreshed\n", udtname, newname);
			}
		}
		break;
	}
#endif //IDA_SDK_VERSION < 900
		//case idb_event::auto_empty:
		//FIXME: check ui_ready_to_run
	case idb_event::compiler_changed:
	case idb_event::auto_empty_finally:
		if (isWnd()) {
			if (!bLitTypesOverridden)
				bLitTypesOverridden = lit_overrideTypes();
			//com_init(); //too late here
		}
		break;
	case idb_event::closebase: //doesnt works!
		bLitTypesOverridden = false;
		break;
	case idb_event::savebase:
		save_inlines();
		break;
	case idb_event::make_data:
		{
		ea_t ea = va_arg(va, ea_t);
		flags64_t flags = va_arg(va, flags64_t);
		tid_t tid = va_arg(va, tid_t);
		asize_t len = va_arg(va, asize_t);
		com_make_data_cb(ea, flags, tid, len);
		  break;
		}
	  case idb_event::renamed:
		{
			ea_t ea = va_arg(va, ea_t);
			const char *new_name = va_arg(va, const char *);
			int local_name = va_arg(va, int);
			// appeared in ida 7.6
			//< \param old_name    (const char *) can be nullptr
			if(local_name || new_name == nullptr)
				break;
			flags64_t ea_fl = get_flags(ea);
			if(is_data(ea_fl) || is_unknown(ea_fl)) {
				//Grr! IDA made itsown implementation of the same, but set non pointer type
				//So, now force to overwrite wrong typenfo
				tinfo_t oldType;
				//if(!get_tinfo(&oldType, ea) || oldType.is_decl_func())
				{
					tinfo_t t = getType4Name(new_name);
					if(!t.empty() && set_tinfo(ea, &t)) {
						qstring str;
						t.print(&str);
						msg("[hrt] %a: set glbl '%s' type '%s'\n", ea, new_name, str.c_str());
					}
				}
			} else if(is_func(ea_fl)) {
				const char* ctor = qstrstr(new_name, "::ctor");
				if(ctor) {
					tinfo_t tif;
					uint32 haveType = TINFO_GUESSED;
					if(get_tinfo(&tif, ea))
						haveType = TINFO_DEFINITE;
					else if(guess_tinfo(&tif, ea) == GUESS_FUNC_FAILED)
						break;
					func_type_data_t fi;
					if(tif.is_decl_func() && tif.get_func_details(&fi)) {
						qstring retTname;
						retTname.append(new_name, ctor - new_name);
						fi.rettype = make_pointer(create_typedef(retTname.c_str()));
						tinfo_t newFType;
						newFType.create_func(fi);
						if (newFType.is_correct() && apply_tinfo(ea, newFType, haveType)) {
							msg("[hrt] Function %a %s ret type changed to \"%s*\"\n", ea, new_name, retTname.c_str());
						}
					}
				}
				if(funcRenameEa == ea && !funcRename.empty()) {
					//rename VT members too
					int cnt = 0;
					enumStrucMembers(funcRename.c_str(), countStrucMembersCB, &cnt);
					if(!cnt)
						break;
					if(cnt > 1 && ASKBTN_YES != ask_yn(ASKBTN_NO, "[hrt] Rename %d struc members?\n%s\nto\n%s", cnt, funcRename.c_str(), new_name))
						break;
					enumStrucMembers(funcRename.c_str(), renameStrucMembersCB, (void*)new_name);
				}
			}
			break;
		}
	  case idb_event::ti_changed:
		{
			ea_t ea = va_arg(va, ea_t);
			const type_t *type = va_arg(va, type_t *);
			const p_list *fnames = va_arg(va, p_list *);
			tinfo_t tif;
			flags64_t ea_fl = get_flags(ea);
			if(type && is_func(ea_fl) && is_type_func(*type) && tif.deserialize(NULL, &type, &fnames) && tif.is_func()) {
				qstring funcName = get_name(ea);
				//set type for VT members too
				int cnt = 0;
				enumStrucMembers(funcName.c_str(), countStrucMembersCB, &cnt);
				if(!cnt)
					break;
				tif = make_pointer(tif);
				if(cnt > 1) {
					qstring newType;
					tif.print(&newType);
					if(ASKBTN_YES != ask_yn(ASKBTN_NO, "[hrt] Recast %d struc members\n%s\nto\n%s\n?", cnt, funcName.c_str(), newType.c_str()))
						break;
				}
				enumStrucMembers(funcName.c_str(), recastStrucMembersCB, &tif);
			}
			break;
		}
		case idb_event::op_ti_changed:
		{
		//FIXME: only 32bit is affected
			ea_t ea = va_arg(va, ea_t);
			int n  = va_arg(va, int);
			const type_t* type = va_arg(va, type_t *);
			const p_list* fnames = va_arg(va, p_list *);
			if(type && is_type_ptr(*type) && is_type_func(*(type+1)) &&
				n == 0 && ea != BADADDR && is_code(get_flags(ea))) {
				insn_t cmd;
				decode_insn(&cmd, ea);
				if (NN_callni == cmd.itype) {
					tinfo_t ti;
					if (ti.deserialize(NULL, &type) && ti.is_funcptr() && ti.is_purging_cc()) {
						int purged = ti.calc_purged_bytes();
						func_t *func = get_func(ea);
						ea_t stkpnt = cmd.ea + cmd.size;
						sval_t delta = get_sp_delta(func, stkpnt);
						if (delta != purged) {
							msg("[hrt] %a: fix call stack pointer delta at from %d to %d\n", cmd.ea, delta, purged);
							add_user_stkpnt(stkpnt, purged);
							//refresh pseudocode?
							//recalc_spd()
						}
					}
				}
			}
			break;
		}
	}
	return 0;
}

static ssize_t idaapi dbg_callback(void *user_data, int ncode, va_list va)
{
	dbg_notification_t code = (dbg_notification_t)ncode;
	switch (code) {
	case dbg_process_exit:
	case dbg_process_detach:
		apply_dbg_patches();
		break;
	}
	return 0;
}

//--------------------------------------------------------------------------
static bool inited = false;

#if IDA_SDK_VERSION < 750
int
#else //IDA_SDK_VERSION >= 750
plugmod_t*
#endif //IDA_SDK_VERSION < 750
 idaapi init(void)
{
	if(inited)
		return PLUGIN_KEEP;

	if ( !init_hexrays_plugin() )
		return PLUGIN_SKIP; // no decompiler

	install_hexrays_callback(callback, NULL);
	//const char *hxver = get_hexrays_version();
	msg("%s ready to use\n", PLUGIN.wanted_name);
	hook_to_notification_point(HT_UI, ui_callback, NULL);	
	hook_to_notification_point(HT_IDB, idb_callback, NULL);
	hook_to_notification_point(HT_DBG, dbg_callback, NULL);
	hook_to_notification_point(HT_IDP, idp_callback, NULL);

	inited = true;

	appcall_view_reg_act();
	reincast_reg_act();
	registerMicrocodeExplorer();
	hrt_reg_act();
	register_idc_functions();
	lit_init();
	deinline_init();
	opt_init();

	addon_info_t addon;
	addon.id = "hrtng";
	addon.name = "bes's tools collection";
	addon.producer = "Sergey Belov and Milan Bohacek, Rolf Rolles, Takahiro Haruyama," \
									 " Karthik Selvaraj, Ali Rahbar, Ali Pezeshk, Elias Bachaalany, Markus Gaasedelen";
	addon.url = "https://github.com/KasperskyLab/hrtng";
	addon.version = "1.1.10";
	register_addon(&addon);	

	return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
	if ( inited )
	{
		appcall_view_unreg_act();
		reincast_unreg_act();
		unregisterMicrocodeExplorer();
		hrt_unreg_act();

		remove_hexrays_callback(callback, NULL);
		unhook_from_notification_point(HT_IDP, idp_callback, NULL);
		unhook_from_notification_point(HT_DBG, dbg_callback, NULL);
		unhook_from_notification_point(HT_IDB, idb_callback, NULL);
		unhook_from_notification_point(HT_UI, ui_callback);
		unregister_idc_functions();
		opt_done();
		deinline_done();
		apihashes_done();
		lit_done();
		term_hexrays_plugin();
		inited = false;
	}
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{
	// should not be called because of PLUGIN_HIDE
	return true;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_HIDE,          // plugin flags
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	"\n[hrt] Useful tools for IDA and Hex-Rays decompiler",  // long comment about the plugin it could appear in the status line or as a hint
	"",                   // multiline help about the plugin
	"[hrt] bes's compilation of hexrays tools collection", // the preferred short name of the plugin
	""                    // the preferred hotkey to run the plugin
};
//--------------------------------------------------------------------------
