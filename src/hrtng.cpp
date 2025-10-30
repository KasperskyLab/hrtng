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

// Evolution of hexrays_tools.cpp from https://github.com/nihilus/hexrays_tools
// there is almost no original code left

#include "warn_off.h"
#include <pro.h>
#include <prodir.h>
#include <hexrays.hpp>
#include <kernwin.hpp>
#include <fpro.h>
#include <nalt.hpp>
#include <bytes.hpp>
#include <segregs.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <expr.hpp>
#include <frame.hpp>
#include <dbg.hpp>
#include <diskio.hpp>
#include <strlist.hpp>
#include <intel.hpp>
#include <graph.hpp>
#include <offset.hpp>
#include <demangle.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "config.h"
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
#include "refactoring.h"
#include "new_struct.h"
#include "new_struc_view.h"
#include "new_struc_place.h"
#include "invert_if.h"
#include "varval.h"
#include "callrefs.h"
#include "regrefs.h"
#include "ctreeg.h"
#include "idb2pat.h"

#if IDA_SDK_VERSION >= 750
#include "microavx.h"
#endif // IDA_SDK_VERSION >= 750

#if IDA_SDK_VERSION < 760
hexdsp_t *hexdsp = NULL;
#endif //IDA_SDK_VERSION < 760

bool set_var_type(vdui_t *vu, lvar_t *lv, tinfo_t *ts);
bool is_arg_var(vdui_t *vu, lvar_t **var = nullptr);
bool is_call(vdui_t *vu, cexpr_t **call = nullptr, bool argsDeep = false);
bool is_recastable(vdui_t *vu, tinfo_t *ts);
bool is_stack_var_assign(vdui_t *vu, int* varIdx, ea_t *ea, sval_t* size);
bool is_array_char_assign(vdui_t *vu, int* varIdx, ea_t *ea);
bool is_decryptable_obj(vdui_t *vu, ea_t *ea);
bool is_number(vdui_t *vu);
bool is_gap_field(vdui_t *vu, tinfo_t *ts = nullptr, ea_t *gapMembOff  = nullptr, 	ea_t* accessOff = nullptr, tinfo_t *accessType = nullptr);
bool is_patched();
bool create_dec_file();
bool is_VT_assign(vdui_t *vu, tid_t *struc_id, ea_t *vt_ea);
bool has_if42blocks(ea_t funcea);

//-------------------------------------------------------------------------
// action_handler_t declarations

//actions attached to main menu
ACT_DECL(create_dummy_struct, AST_ENABLE_ALW)
ACT_DECL(offsets_tbl, return ((ctx->widget_type == BWN_DISASM) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(fill_nops, return ((ctx->widget_type == BWN_DISASM) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(searchNpatch, return ((ctx->widget_type == BWN_DISASM) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(dbg_patch, return ((ctx->widget_type != BWN_DISASM) ? AST_DISABLE_FOR_WIDGET : (is_debugger_on() ? AST_ENABLE : AST_DISABLE)))
ACT_DECL(file_patch, return ((ctx->widget_type == BWN_DISASM) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(apihashes, AST_ENABLE_ALW)
ACT_DECL(create_dec, return (is_patched() ? AST_ENABLE : AST_DISABLE))
ACT_DECL(clear_hr_cache, AST_ENABLE_ALW)
ACT_DECL(decomp_obfus, return ((ctx->widget_type == BWN_DISASM || ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(decomp_recur, return (((ctx->widget_type == BWN_DISASM && get_func(ctx->cur_ea)) || ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(jmp2xref, return ((ctx->widget_type == BWN_DISASM || ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(idb2pat, AST_ENABLE_ALW)
//ACT_DECL(kill_toolbars, AST_ENABLE_ALW)

//dynamically attached actions
ACT_DECL(scan_var         , AST_ENABLE_FOR(can_be_converted_to_ptr(*vu, false)))
ACT_DECL(show_struct_bld     , AST_ENABLE_FOR(fi.size() != 0))
ACT_DECL(fin_struct          , AST_ENABLE_FOR(fi.size() != 0 && can_be_converted_to_ptr(*vu, false)))
ACT_DECL(recognize_shape     , AST_ENABLE_FOR(vu->item.get_lvar()))
ACT_DECL(possible_structs_for_one_offset, AST_ENABLE_FOR(is_number(vu)))
ACT_DECL(structs_with_this_size, AST_ENABLE_FOR(is_number(vu)))
ACT_DECL(var_reuse             , AST_ENABLE_FOR(vu->item.get_lvar()))
#if IDA_SDK_VERSION < 850
ACT_DECL(convert_to_golang_call, AST_ENABLE_FOR(vu->item.citype == VDI_FUNC))
#endif // IDA_SDK_VERSION < 850
ACT_DECL(convert_to_usercall , AST_ENABLE_FOR(vu->item.citype == VDI_FUNC))
ACT_DECL(jump_to_indirect_call  , AST_ENABLE_FOR(is_call(vu)))
ACT_DECL(zeal_doc_help       , AST_ENABLE_FOR(is_call(vu)))
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
ACT_DECL(convert_gap             , AST_ENABLE_FOR(is_gap_field(vu)))
ACT_DECL(disable_inlines         , AST_ENABLE_FOR(hasInlines(vu, NULL)))
ACT_DECL(enable_inlines          , AST_ENABLE_FOR(hasInlines(vu, NULL)))
ACT_DECL(rename_inline           , AST_ENABLE_FOR(is_nlib_inline(vu)))
ACT_DECL(create_inline_gr        , return ((ctx->widget_type != BWN_DISASM) ? AST_DISABLE_FOR_WIDGET : ((get_view_renderer_type(ctx->widget) == TCCRT_GRAPH) ? AST_ENABLE : AST_DISABLE)))
ACT_DECL(create_inline_sel       , return ((ctx->widget_type != BWN_PSEUDOCODE && ctx->widget_type != BWN_DISASM) ?  AST_DISABLE_FOR_WIDGET : (ctx->has_flag(ACF_HAS_SELECTION) ?  AST_ENABLE : AST_DISABLE)))
ACT_DECL(uf_enable               , AST_ENABLE_FOR(ufIsInGL(vu->cfunc->entry_ea)))
ACT_DECL(uf_disable              , AST_ENABLE_FOR(ufIsInWL(vu->cfunc->entry_ea)))
#if IDA_SDK_VERSION >= 750
ACT_DECL(mavx_enable             , AST_ENABLE_FOR(isMicroAvx_avail() && !isMicroAvx_active()))
ACT_DECL(mavx_disable            , AST_ENABLE_FOR(isMicroAvx_avail() &&  isMicroAvx_active()))
#endif //IDA_SDK_VERSION >= 750
ACT_DECL(selection2block         , return (ctx->widget_type != BWN_PSEUDOCODE ? AST_DISABLE_FOR_WIDGET : (ctx->has_flag(ACF_HAS_SELECTION) ? AST_ENABLE : AST_DISABLE)))
ACT_DECL(clear_if42blocks        , AST_ENABLE_FOR(has_if42blocks(vu->cfunc->entry_ea)))
ACT_DECL(rename_func             , AST_ENABLE_FOR_PC)
#if IDA_SDK_VERSION < 750
ACT_DECL(remove_rettype      , AST_ENABLE_FOR(vu->item.citype == VDI_FUNC))
ACT_DECL(remove_argument     , AST_ENABLE_FOR(is_arg_var(vu)))
#endif //IDA_SDK_VERSION < 750
ACT_DECL(import_unf_types        , return ((ctx->widget_type == BWN_TICSR || ctx->widget_type == BWN_TILIST) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(refactoring             , return (ctx->widget_type == BWN_PSEUDOCODE || ctx->widget_type == BWN_DISASM || ctx->widget_type == BWN_TILIST ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))

//-------------------------------------------------------------------------
// action_desc_t descriptions
static const action_desc_t actions[] =
{
	ACT_DESC("[hrt] Scan variable",                  "S", scan_var),
	ACT_DESC("[hrt] Open structure builder",         NULL, show_struct_bld),
	ACT_DESC("[hrt] Finalize structure",             NULL, fin_struct),
	ACT_DESC("[hrt] Recognize var type shape",       "T", recognize_shape),
	ACT_DESC("[hrt] Which structs have this offset?","O", possible_structs_for_one_offset),
	ACT_DESC("[hrt] Which structs have this size?",  "S", structs_with_this_size),
	ACT_DESC("[hrt] Unite var reuse",                NULL, var_reuse),
	ACT_DESC("[hrt] Convert to __usercall",          "U", convert_to_usercall),
	ACT_DESC("[hrt] Jump to indirect call",          "J", jump_to_indirect_call),
	ACT_DESC("[hrt] Zeal offline API help (zealdocs.org)",  "Alt-F1", zeal_doc_help),
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
	ACT_DESC("[hrt] Rename func...",             "Ctrl-N", rename_func),
	ACT_DESC("[hrt] Create 'inline' from grouped nodes",  NULL, create_inline_gr),
	ACT_DESC("[hrt] Create 'inline' from selection",  NULL, create_inline_sel),
	ACT_DESC("[hrt] Enable Unflattener",              NULL, uf_enable),
	ACT_DESC("[hrt] Disable Unflattener",             NULL, uf_disable),
#if IDA_SDK_VERSION >= 750
  ACT_DESC("[hrt] Enable AVX lifter",              NULL, mavx_enable),
	ACT_DESC("[hrt] Disable AVX lifter",             NULL, mavx_disable),
#else // IDA_SDK_VERSION < 750
	ACT_DESC("[hrt] Remove return type",             NULL, remove_rettype),
	ACT_DESC("[hrt] Remove this argument",           "A", remove_argument),
#endif //IDA_SDK_VERSION >= 750
	ACT_DESC("[hrt] ~C~ollapse selection",            NULL, selection2block),
	ACT_DESC("[hrt] Remove collapsible 'if(42) ...' blocks",  NULL, clear_if42blocks),
#if IDA_SDK_VERSION < 850
	ACT_DESC("[hrt] Convert to __usercall golang",   "Shift-G", convert_to_golang_call),
#endif //IDA_SDK_VERSION < 850
	ACT_DESC("[hrt] Import user-named func types",    NULL, import_unf_types),
	ACT_DESC("[hrt] Refactoring...",             "Shift-R", refactoring),
};

//-------------------------------------------------------------------------

void add_hrt_popup_items(TWidget *view, TPopupMenu *p, vdui_t* vu)
{
	bool isVar = vu->item.get_lvar() != NULL;
	if (isVar) {
		attach_action_to_popup(view, p, ACT_NAME(scan_var));
		attach_action_to_popup(view, p, ACT_NAME(show_struct_bld));
		attach_action_to_popup(view, p, ACT_NAME(fin_struct));
		attach_action_to_popup(view, p, ACT_NAME(recognize_shape));
		attach_action_to_popup(view, p, ACT_NAME(var_reuse));
		attach_action_to_popup(view, p, ACT_NAME(insert_varval));
	}
	if (has_varvals(vu->cfunc->entry_ea))
		attach_action_to_popup(view, p, ACT_NAME(clear_varvals));
	if (vu->item.citype == VDI_FUNC) {
		attach_action_to_popup(view, p, ACT_NAME(convert_to_usercall));
#if IDA_SDK_VERSION < 850
		attach_action_to_popup(view, p, ACT_NAME(convert_to_golang_call));
#endif //IDA_SDK_VERSION < 850
#if IDA_SDK_VERSION < 750
		attach_action_to_popup(view, p, ACT_NAME(remove_rettype));
	}
	if (is_arg_var(vu))
		attach_action_to_popup(view, p, ACT_NAME(remove_argument));
#else // IDA_SDK_VERSION >= 750
	}
#endif // IDA_SDK_VERSION < 750
	if(is_call(vu)) {
		attach_action_to_popup(view, p, ACT_NAME(zeal_doc_help));
		attach_action_to_popup(view, p, ACT_NAME(jump_to_indirect_call));
	}
	if(is_VT_assign(vu, NULL, NULL))
		attach_action_to_popup(view, p, ACT_NAME(add_VT));

#if IDA_SDK_VERSION <= 730
	bool nrecast = is_n_recast(vu);
	if (can_be_n_recast(vu) || nrecast)
		attach_action_to_popup(view, p, ACT_NAME(use_CONTAINER_OF_callback));
	if (nrecast)
		attach_action_to_popup(view, p, ACT_NAME(destroy_CONTAINER_OF_callback));
#endif // IDA_SDK_VERSION <= 730
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
		attach_action_to_popup(view, p, ACT_NAME(possible_structs_for_one_offset));
		attach_action_to_popup(view, p, ACT_NAME(structs_with_this_size));
		attach_action_to_popup(view, p, ACT_NAME(decrypt_const));
	}
	else if (is_gap_field(vu))
		attach_action_to_popup(view, p, ACT_NAME(convert_gap));
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
	if(ufIsInGL(vu->cfunc->entry_ea))
		attach_action_to_popup(view, p, ACT_NAME(uf_enable));
	else if (ufIsInWL(vu->cfunc->entry_ea))
		attach_action_to_popup(view, p, ACT_NAME(uf_disable));

	attach_action_to_popup(view, p, ACT_NAME(msigAdd));
	if(isMsig(vu, nullptr)) {
		attach_action_to_popup(view, p, ACT_NAME(msigEdit));
		attach_action_to_popup(view, p, ACT_NAME(msigAccept));
	}
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
	attach_action_to_popup(view, p, ACT_NAME(rename_func));
	attach_action_to_popup(view, p, ACT_NAME(refactoring));
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
	//COMPAT_register_and_attach_to_menu("View/Toolbars", ACT_NAME(kill_toolbars), "[hrt] Kill toolbars", NULL, SETMENU_INS, &kill_toolbars, &PLUGIN);
	COMPAT_register_and_attach_to_menu("View/Open subviews/Generate pseudocode", ACT_NAME(decomp_recur), "[hrt] Decompile recursively", "Shift-Alt-F5", SETMENU_APP, &decomp_recur, &PLUGIN);
	COMPAT_register_and_attach_to_menu("View/Open subviews/Generate pseudocode", ACT_NAME(decomp_obfus), "[hrt] Decompile obfuscated code", "Alt-F5", SETMENU_APP, &decomp_obfus, &PLUGIN);
	COMPAT_register_and_attach_to_menu("Jump/Jump to xref to operand...", ACT_NAME(jmp2xref), "[hrt] Jump to xref Ex...", "Shift-X", SETMENU_APP, &jmp2xref, &PLUGIN);
	COMPAT_register_and_attach_to_menu("File/Produce file/Create MAP file...", ACT_NAME(idb2pat), "[hrt] Create PAT file...", NULL, SETMENU_INS, &idb2pat, &PLUGIN);

	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		register_action(actions[i]);

	//kill duplicating shortcut
	qstring shortcut;
#if IDA_SDK_VERSION < 920
	// we will call it directly on same shortcut in appropriate cases
	if(get_action_shortcut(&shortcut, "hx:JumpGlobalXref") && !qstrcmp("Shift-X", shortcut.c_str()))
		update_action_shortcut("hx:JumpGlobalXref", NULL);
#else
	// XrefsTree is not so convenient to left it on a such habitual shortcut
	if(get_action_shortcut(&shortcut, "OpenXrefsTree") && !qstrcmp("Shift-X", shortcut.c_str()))
		update_action_shortcut("OpenXrefsTree", NULL);
#endif // IDA_SDK_VERSION < 920
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
	//detach_action_from_menu("View/[hrt] Kill toolbars", ACT_NAME(kill_toolbars));
	detach_action_from_menu("View/Open subviews/[hrt] Decompile obfuscated code", ACT_NAME(decomp_obfus));
	detach_action_from_menu("View/Open subviews/[hrt] Decompile recursively", ACT_NAME(decomp_recur));
	detach_action_from_menu("Jump/[hrt] Jump to xref Ex...", ACT_NAME(jmp2xref));
	detach_action_from_menu("File/Produce file/[hrt] Create PAT file...", ACT_NAME(idb2pat));

	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		unregister_action(actions[i].name);
	//unregister_action(ACT_NAME(kill_toolbars));
	unregister_action(ACT_NAME(idb2pat));
	unregister_action(ACT_NAME(create_dec));
	unregister_action(ACT_NAME(apihashes));
	unregister_action(ACT_NAME(dbg_patch));
	unregister_action(ACT_NAME(file_patch));
	unregister_action(ACT_NAME(searchNpatch));
	unregister_action(ACT_NAME(fill_nops));
	unregister_action(ACT_NAME(offsets_tbl));
	unregister_action(ACT_NAME(create_dummy_struct));
}
//-------------------------------------------------------------------------

static ea_t idaapi get_call_dst(cfunc_t* cfunc, cexpr_t *call)
{
	if(call->op != cot_call)
		return BADADDR;

	ea_t dst_ea = BADADDR;
	cexpr_t *callee = skipCast(call->x);

	if(callee->op == cot_obj) {
		flags64_t flg = get_flags(callee->obj_ea);
		if(is_func(flg))
			return callee->obj_ea;
		if(is_data(flg)) {
			dst_ea = get_ea(callee->obj_ea);
			if(is_func(get_flags(dst_ea)))
				return dst_ea;
		}
		return BADADDR;
	}

	// jump to address in struct member-to-proc-xref (or by VT/comment/name)
	if(callee->op == cot_memptr || callee->op == cot_memref) {
		cexpr_t *e = callee;
		int offset = e->m;
		if (e->x->op == cot_idx)
			e = e->x;
		cexpr_t *var = e->x;
		tinfo_t t = var->type;
		if(t.is_ptr_or_array())
			t.remove_ptr_or_array();
		if(t.is_struct()) {
#if IDA_SDK_VERSION < 850
			qstring sname;
			if(t.get_type_name(&sname)) {
				tid_t sid = get_struc_id(sname.c_str());
				if(sid != BADNODE) {
					struc_t* s = get_struc(sid);
					if(s) {
						member_t *m = get_member(s, offset);
						if(m)
							dst_ea = get_memb2proc_ref(s, m);
					}
				}
			}
#else
			dst_ea = get_memb2proc_ref(t, offset);
#endif
		}
	}

	if(dst_ea == BADADDR) {
		//last hope, jump to name
		qstring callname;
		if(getExpName(cfunc, callee, &callname))
			dst_ea = get_name_ea(BADADDR, callname.c_str());
	}
	return dst_ea;
}

static int idaapi jump_to_call_dst(vdui_t *vu)
{
	cexpr_t *call;
	if(!is_call(vu, &call))
		return 0;

	ea_t dst_ea = get_call_dst(vu->cfunc, call);
	if(dst_ea != BADADDR && is_func(get_flags(dst_ea))) {
		if(call->ea != BADADDR)
			add_cref(call->ea, dst_ea, (cref_t)(fl_CN | XREF_USER));
		jumpto(dst_ea);
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
	//Log(llDebug, "create_dec is called \n");
	if(create_dec_file())
		return eOk;
	return eOS;
}
static const ext_idcfunc_t create_dec_desc = { "create_dec", create_dec_idc, create_dec_idc_args, NULL, 0, EXTFUN_BASE };

static const char dump_strings_idc_args[] = { 0 };
static error_t idaapi dump_strings_idc(idc_value_t *argv, idc_value_t *res)
{
	// !!! Attention: crash possibility in future IDA version !!!
	// beginning from IDA 7.6 `get_strlist_options` returns `cosnt strwinsetup_t *`
	// but in fact it allowed to modify strwinsetup_t content when `cosnt` stripped
	strwinsetup_t *strwinsetup = (strwinsetup_t *)get_strlist_options();
	if(strwinsetup) {
		strwinsetup->only_7bit = 0;
		strwinsetup->display_only_existing_strings = 1;
		strwinsetup->minlen = 1;
		strwinsetup->strtypes.clear();
		strwinsetup->strtypes.push_back(STRTYPE_C);
		strwinsetup->strtypes.push_back(STRTYPE_C_16);
		strwinsetup->strtypes.push_back(STRTYPE_C_32);
		strwinsetup->strtypes.push_back(STRTYPE_PASCAL);
		strwinsetup->strtypes.push_back(STRTYPE_PASCAL_16);
		strwinsetup->strtypes.push_back(STRTYPE_LEN2);
		strwinsetup->strtypes.push_back(STRTYPE_LEN2_16);
		strwinsetup->strtypes.push_back(STRTYPE_LEN4);
		strwinsetup->strtypes.push_back(STRTYPE_LEN4_16);
#if IDA_SDK_VERSION >= 840
		strwinsetup->strtypes.push_back(STRTYPE_PASCAL_32);
		strwinsetup->strtypes.push_back(STRTYPE_LEN2_32);
		strwinsetup->strtypes.push_back(STRTYPE_LEN4_32);
#endif // IDA_SDK_VERSION >= 840
		build_strlist();
		size_t qty = get_strlist_qty();
		uint32 cnt = 0;
		for(size_t i = 0; i < qty; i++) {
			string_info_t si;
			if(get_strlist_item(&si, i) && si.ea != BADADDR && si.length) {
				qstring str;
				if( 0 < get_strlit_contents(&str, si.ea, si.length, si.type, NULL, STRCONV_ESCAPE)) {
					Log(llFlood, "dump_strings: %a: %s\n", si.ea, str.c_str());
					cnt++;
					qprintf("%s\n", str.c_str());
				}
			}
		}
		Log(llNotice, "dump_strings: %u of %u printed\n", cnt, (uint32)qty);
		return eOk;
	}
	Log(llError, "dump_strings: err\n");
	return eOS;
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
	//Log(llDebug, "dump_comments is called \n");
	qprintf("\n[hrt] <<<<<<<<<<          IDB comments          >>>>>>>>>>\n");
#if 0 //too much autogenerated comments
	for(ea_t ea = inf_get_min_ea(); ea < inf_get_max_ea(); ea = next_that(ea, inf_get_max_ea(), isCommented)) {
		qstring str;
		//color_t cmttype;
		if(0 < get_cmt(&str, ea, false) || 0 < get_cmt(&str, ea, true)) {
			if (!isIdaInternalComment(str.c_str()) && str[0] != ';')
				qprintf("%a: %s\n", ea, str.c_str());
		}
	}
#endif
	size_t funcqty = get_func_qty();
	for (size_t i = 0; i < funcqty; i++) {
		func_t* func = getn_func(i);
		if(!func)
			continue;
		user_cmts_t *cmts = restore_user_cmts(func->start_ea);
		if(cmts) {
			for(auto it = user_cmts_begin(cmts); it != user_cmts_end(cmts); it = user_cmts_next(it)) {
				citem_cmt_t &c = user_cmts_second(it);
#if 1
				qstring::iterator b = c.begin();
				qstring::iterator e = c.end() - 1;
				while(b < e && qisspace(*b))
					b++;
				if(b > c.begin()) {
					memmove(c.begin(), b, e - b + 1);
					c.resize(e - b);
				}
#else
				c.ltrim('\n');
				c.ltrim();
#endif
				c.rtrim();
				if(c.length() > 0)
					qprintf("%s\n", c.c_str());
			}
			user_cmts_free(cmts);
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
			stripName(&nn, true);
			const type_t *type;
			if(get_named_type(NULL, nn.c_str(), 0, &type) && is_type_func(*type))
				continue;
		}

		cnt++;
		qprintf("%s\n", name);
	}
	Log(llNotice, "dump_names: %u of %u printed\n", cnt, (uint32)qty);
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

bool is_call(vdui_t *vu, cexpr_t **call /*= nullptr*/, bool argsDeep /*= false*/)
{
	if (!vu->item.is_citem())
		return false;

	citem_t *it = vu->item.it;
	if(argsDeep) {
		//in this mode is_call returns true if the cursor is inside call's arguments zone too, as well as in callee expression
		while (it && it->op <= cot_last && it->op != cot_call)
			it = vu->cfunc->body.find_parent_of(it);
	} else {
		// if cursor stay on callee expression
		// call => cast => memptr/obj/var
		it = vu->cfunc->body.find_parent_of(it);
		if(it && it->op == cot_cast)
			it = vu->cfunc->body.find_parent_of(it);
	}
	if(it && it->op == cot_call &&
		 (argsDeep || skipCast(((cexpr_t *)it)->x) == vu->item.e)) // cursor stay on callee expression
	{
		if(call)
			*call = (cexpr_t *)it;
		return true;
	}
	return false;
}

ACT_DEF(zeal_doc_help)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	cexpr_t *call;
	qstring name;
	if(!is_call(vu, &call) || !getExpName(vu->cfunc, call->x, &name))
		return 0;

	stripName(&name, true);
	qstring dname;
	if(demangle_name(&dname, name.c_str(), MNG_NODEFINIT) >= 0)
		name = dname;
	if (name.length() > 1 && (name.last() == 'A' || name.last() == 'W'))
		name.remove_last();

	name.insert(0, "zeal \"");
	name.append('"');

  launch_process_params_t lpp;
  lpp.flags = LP_USE_SHELL;
  lpp.args = name.c_str();

  qstring errbuf;
  if(launch_process(lpp, &errbuf) == NULL) {
    Log(llError, "launch_process(%s) error: %s\n", lpp.args, errbuf.c_str());
    return 0;
  }
  return 1;
}

bool is_VT_assign(vdui_t *vu, tid_t *struc_id, ea_t *vt_ea)
{
	if (!vu->item.is_citem())
		return false;

	tid_t sid;
#if IDA_SDK_VERSION < 850
	struc_t *sptr;
	member_t * member = vu->item.get_memptr(&sptr);
	if(!member || member->soff != 0)
		return false;
	sid = sptr->id;
#else //IDA_SDK_VERSION >= 850
	tinfo_t parentTi;
	uint64 offset;
	if (vu->item.get_udm(NULL, &parentTi, &offset) == -1 || offset != 0)
		return false;
	sid = parentTi.get_tid();
	if (sid == BADADDR)
		return false; //parent.force_tid()
#endif //IDA_SDK_VERSION < 850

	citem_t* parent = vu->cfunc->body.find_parent_of(vu->item.i);
	if(parent->op != cot_asg)
		return false;

	cexpr_t *asg = (cexpr_t *)parent;
	cexpr_t *vt = skipCast(asg->y);
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
		vu->refresh_view(false);
	return 0;
}

ACT_DEF(add_VT_struct)
{
	tid_t VT_struct= create_VT_struc(ctx->cur_ea, NULL);
	if(VT_struct != BADADDR)
#if IDA_SDK_VERSION < 850
		open_structs_window(VT_struct);
#else //IDA_SDK_VERSION >= 850
		open_loctypes_window(get_tid_ordinal(VT_struct));
#endif //IDA_SDK_VERSION < 850
	return 0;
}

#if IDA_SDK_VERSION < 920
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
		Log(llError, "convert to __usercall: Unknown function cc, %x\n", fti.cc & CM_CC_MASK);
	case CM_CC_SPECIAL:
	case CM_CC_SPECIALE:
	case CM_CC_SPECIALP:
		//do nothing but return true
		break;
	}
	return true;
}
#else
static bool convert_cc_to_special(func_type_data_t & fti)
{
	switch(fti.get_cc())
	{
	case CM_CC_CDECL:
	case CM_CC_UNKNOWN:
		fti.set_cc(CM_CC_SPECIAL);
		break;
	case CM_CC_STDCALL:
	case CM_CC_PASCAL:
	case CM_CC_FASTCALL:
	case CM_CC_THISCALL:
		fti.set_cc(CM_CC_SPECIALP);
		break;
	case CM_CC_ELLIPSIS:
		fti.set_cc(CM_CC_SPECIALE);
		break;
	default:
		Log(llError, "convert to __usercall: Unknown function cc, %x\n", fti.get_cc());
	case CM_CC_SPECIAL:
	case CM_CC_SPECIALE:
	case CM_CC_SPECIALP:
		//do nothing but return true
		break;
	}
	return true;
}
#endif //IDA_SDK_VERSION < 920

//-------------------------------------------------------------------------------------------------------------------------
ACT_DEF(scan_var)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	can_be_converted_to_ptr(vu, true);
	return 0;
}

ACT_DEF(show_struct_bld)
{
	show_new_struc_view();
	return 0;
}

ACT_DEF(fin_struct)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	ea_t ea = BADADDR;
	lvar_t * lvar = vu.item.get_lvar();
	if(!lvar) {
		if(vu.item.is_citem() && vu.item.it->op == cot_obj)
			ea = vu.item.e->obj_ea;
		else
			return 0;
	}

	tinfo_t fitype;
	if (!fi.to_type(fitype))
		return 0;
	tinfo_t restype = make_pointer(fitype);

	//start from currently visible window
	if(lvar) {
		set_var_type(&vu, lvar, &restype);
	} else {
		if(is_mapped(ea))
			apply_tinfo(ea, fitype, TINFO_DEFINITE);
		for(global_pointers_t::iterator iter = fi.global_pointers.begin(); iter!=fi.global_pointers.end(); iter++) {
			if(*iter != ea && is_mapped(*iter))
				apply_tinfo(*iter, fitype, TINFO_DEFINITE);
		}
	}
	
	//process other funcs
	ea_t save_ea = vu.cfunc->entry_ea;
	for(auto it = fi.scanned_variables.begin(); it !=  fi.scanned_variables.end(); it++) {
		if(it->first == save_ea)
			continue; //skip currently visible

		Log(llInfo, "decompile and set var types for %a\n", it->first);
#if 0
		//this works not well, becouse var->set_lvar_type changes is not permanent
		//TODO: for permanent changes see modify_user_lvars()
		func_t * func = get_func(p.first);
		if (!func)
			return false;
		hexrays_failure_t failure;
		cfuncptr_t decompilation = decompile_func(func, &failure);
#else
		vdui_t * ui = COMPAT_open_pseudocode_REUSE(it->first);
		if (!ui)
			break;

		if (1) { //wait for visible and valid ui
			const int wait = 50;
			int i = wait;
			for(; i > 0; i--) {
				if(ui->visible() && ui->valid())
					break;
				qsleep(100);
			}
			if(i == 0)
				break;
		}

		cfuncptr_t decompilation = ui->cfunc;
#endif
		if(!decompilation)
			break;
		//decompilation->verify(ALLOW_UNUSED_LABELS, true);

		lvars_t * lvars = decompilation->get_lvars();
		if(!lvars)
			break;

		for(auto it2 = it->second.begin(); it2 != it->second.end(); it2++) {
	    scanned_variables_t::mapped_type::value_type x = *it2;
			lvar_t * var = lvars->find(x.second);
			if (var) {
				if (x.first == 0) {
					if (var->accepts_type(restype))
						ui->set_lvar_type(var, restype);//var->set_lvar_type(restype);
				} else {
					tinfo_t tt;
					
					if (fi.types_cache.find(x.first) != fi.types_cache.end()) {
						tt = fi.types_cache[x.first];
					} else {
						udm_t memb;
						memb.offset = x.first * 8;
						if(-1 != fitype.find_udm(&memb, STRMEM_AUTO))
							fi.types_cache[x.first] = tt = memb.type;
					}
					if(!tt.empty()) {
						tt = make_pointer(tt);
						if (var->accepts_type(tt))
							ui->set_lvar_type(var, tt);//var->set_lvar_type(restype);
					}
				}
			}
		}
	}

	fi.clear();
	close_new_struc_view();

	//restore old visible func
	COMPAT_open_pseudocode_REUSE(save_ea);
	return 1;
}

ACT_DEF(rename_func)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if(!vu || vu->cfunc->entry_ea == BADADDR)
		return 0;

	tinfo_t ftype;
	if(!vu->cfunc->get_func_type(&ftype))
		return 0;

	qstring newName;
	func_type_data_t fti;
	ftype.get_func_details(&fti);
	if(fti.size()) {
		tinfo_t argt;
		lvar_t *var = nullptr;
		if(is_arg_var(vu, &var))
			argt = var->tif.get_pointed_object();
		else
			argt = fti[0].type.get_pointed_object();
		if(argt.is_struct() && argt.get_type_name(&newName))
			newName.append("::");
	}

	qstring oldname = get_short_name(vu->cfunc->entry_ea);
	qstring highlight;
	uint32 hlflg;
	if(vu->item.citype != VDI_FUNC && !is_arg_var(vu) && get_highlight(&highlight, ctx->widget, &hlflg))
		newName.append(highlight);
	else if(has_user_name(get_flags(vu->cfunc->entry_ea)))
		newName.append(oldname);

	while (1) {
		if(!ask_ident(&newName, "[hrt] Rename %s:", oldname.c_str()))
			return 0;

		if(!validate_name(&newName, VNT_IDENT, SN_CHECK))
			continue;

		if(set_name(vu->cfunc->entry_ea, newName.c_str(), SN_NOCHECK | SN_NOWARN /*| SN_FORCE*/))
			break;

		// manually implement SN_FORCE like behavior because numeric suffix like "_12" is stripped by the plugin on a type-to-name and name-to-type checks
		// but the functions with such names may have different prototypes, so need to add different suffix, for example without "_"

		newName = unique_name(newName.c_str(), "", [](const qstring& n) { return get_name_ea(BADADDR, n.c_str()) == BADADDR; });
	}

	vu->refresh_view(true);
	return 0;
}

bool is_arg_var(vdui_t *vu, lvar_t **var)
{
	if(vu->item.citype != VDI_LVAR)
		return false;
	lvar_t *v = vu->item.get_lvar();
	if(!v || !v->is_arg_var())
		return false;
	if(var)
		*var = v;
	return true;
}

#if IDA_SDK_VERSION < 750
ACT_DEF(remove_argument)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if(!is_arg_var(&vu))
		return 0;

	if(vu.cfunc->entry_ea==BADADDR)
		return 0;

	tinfo_t type;
	if(!vu.cfunc->get_func_type(&type))
		return 0;
	
	lvar_t* lvar =  vu.item.get_lvar();
	int answer = ask_yn(ASKBTN_NO, "[hrt] Delete arg '%s'?",lvar->name.c_str());
	if(answer == ASKBTN_NO || answer ==ASKBTN_CANCEL)
		return 0;

	func_type_data_t fti;
	type.get_func_details(&fti);
	if (!convert_cc_to_special(fti))
		return 0;	

	for(func_type_data_t::iterator i =  fti.begin(); i!=fti.end(); i++) {
		if(i->name.size() && i->name == lvar->name) {
			fti.erase(i);			
			break;
		}	
	}
	type.clear();
	type.create_func(fti);

	if(!apply_tinfo(vu.cfunc->entry_ea, type, TINFO_DEFINITE))
		return 0;
	
	vu.refresh_view(true);
	return 0;
}

ACT_DEF(remove_rettype)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if(vu.item.citype != VDI_FUNC)
		return 0;

	if(vu.cfunc->entry_ea == BADADDR)
		return 0;

	tinfo_t type;
	if(!vu.cfunc->get_func_type(&type))
		return 0;

	func_type_data_t fti;
	type.get_func_details(&fti);

	int answer = ask_yn(ASKBTN_NO, "[hrt] Make func return type VOID");
	if (answer == ASKBTN_NO || answer == ASKBTN_CANCEL)
		return 0;
	if (!convert_cc_to_special(fti))
		return 0;

	fti.rettype.clear();
	fti.rettype.create_simple_type(BTF_VOID);
	type.clear();
	type.create_func(fti);
	if (!apply_tinfo(vu.cfunc->entry_ea, type, TINFO_DEFINITE))
		return 0;

	vu.refresh_view(true);
	return 0;
}
#endif //IDA_SDK_VERSION < 750

//------------------------------------------------
ACT_DEF(idb2pat)
{
	run_idb2pat();
	return 1;
}

//-------------------------------------------------------------------------------------------------------------------------
struct ida_local types_locator_t : public ctree_parentee_t
{
	cfunc_t* func;
	lvars_t* lvars;
	intvec_t   vidxs;
	tinfovec_t types;

	types_locator_t(cfunc_t* func_, lvars_t* lvars_, int varIdx) : func(func_), lvars(lvars_)
	{
		vidxs.add_unique(varIdx);
		types.add_unique(lvars->at(varIdx).type());
	}

	int idaapi visit_expr(cexpr_t * e)
	{
		if(e->op == cot_asg) {
			cexpr_t* x = skipCast(e->x);
			cexpr_t* y = skipCast(e->y);
			if(x->op == cot_var && y->op == cot_var) {
				if(vidxs.has(x->v.idx))
					vidxs.add_unique(y->v.idx);
				else if(vidxs.has(y->v.idx))
					vidxs.add_unique(x->v.idx);
			}
			return 0;
		}
		if(e->op != cot_var || !vidxs.has(e->v.idx))
			return 0;

		int i = (int)parents.size() - 1;
		if(i < 0 || !parents[i]->is_expr())
			return 0;

		bool bDerefPtr = false;
		cexpr_t* parent = (cexpr_t*)parents[i];
		switch(parent->op) {
		case cot_cast:
			Log(llDebug, "var cast: %s [%s]\n", printExp(func, parent).c_str(), parent->type.dstr());
			types.add_unique(parent->type);
			break;
		case cot_ref:
			if(i > 1 /*&& parents[i - 1]->op == cot_cast*/) {
				parent = (cexpr_t*)parents[i - 1];
				Log(llDebug, "var ref: %s [%s]\n", printExp(func, parent).c_str(), parent->type.dstr());
				if(parent->type.is_ptr())
					types.add_unique(remove_pointer(parent->type));
				else
					Log(llDebug, " not pointer\n");
			}
			break;
		case cot_ptr:
			if(i <= 1 || parents[i - 1]->op != cot_asg)
				return 0;
			bDerefPtr = true;
			parent = (cexpr_t*)parents[i - 1];
			//fall down to cot_asg handler
		case cot_asg:
		{
			cexpr_t *y = skipCast(parent->y);
			tinfo_t yType = y->type; //??? getExpType
			if(bDerefPtr)
				yType = make_pointer(yType);
			Log(llDebug, "var assign cast: %s [%s]\n", printExp(func, parent).c_str(), yType.dstr());
			types.add_unique(yType);
			break;
		}
		default:
			Log(llDebug, "unhandled var use: %s\n", printExp(func, parent).c_str());
		}
		return 0;
	}
};

ACT_DEF(var_reuse)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	lvar_t* var = vu->item.get_lvar();
	if(!var)
		return 0;
	lvars_t* lvars = vu->cfunc->get_lvars();
	ssize_t vi = lvars->index(*var);
	if(vi == -1)
		return 0;

	types_locator_t tl(vu->cfunc, lvars, (int)vi);
	tl.apply_to(&vu->cfunc->body, NULL);
	if(tl.types.size() < 2) {
		Log(llWarning, "There is no stack var reusing found (%s)\n", var->name.c_str());
		return 0;
	}

	udt_type_data_t utd;
	utd.is_union = true;
	utd.taudt_bits |= TAUDT_UNALIGNED;
	utd.effalign = 1;

	size_t total_size = 0;
	for(size_t i = 0; i < tl.types.size(); i++) {
		size_t tsz = tl.types[i].get_size();
		if(tsz == BADSIZE) //ignore "void" and bad types
			continue;
		udm_t &udm = utd.push_back();
		udm.offset = 0; // i ?
    udm.type = tl.types[i];
		udm.name = create_field_name(udm.type);
    udm.size = tsz * 8;
		if(total_size < tsz)
			total_size = tsz;
	}


	utd.unpadded_size = utd.total_size = total_size;
	tinfo_t restype;
	restype.create_udt(utd, BTF_UNION);

	//TODO: sort tl.types vector just after filling,
	//TODO: and then enum all existing unions to check if the same type was already created

	tinfo_t ts;
	qstring tname;
	if (!confirm_create_struct(ts, tname, restype, "u"))
		return 0;
	tname.append('_');
	vu->set_lvar_type(var, ts);
	renameVar(vu->cfunc->entry_ea, vu->cfunc, vi, &tname, vu); //force to rename var, it usually has a wrong name at this time

#if 0
	// (???) it may be probably better for older IDA versions
	//with IDA 9.0 may cause second (wrong) rename by autorenamer
	vu->refresh_view(false);
	return 0;
#else
	return 1;
#endif
}

//------------------------------------------------
struct ida_local undef_var_locator_t : public ctree_visitor_t
{
	std::set<int> indices;
	undef_var_locator_t(): ctree_visitor_t(CV_FAST) {}
	int idaapi visit_expr(cexpr_t * e)
	{
		if(e->op == cot_var && e->is_undef_val()) {
			Log(llDebug, "undefined var (%a '%d')\n", e->ea, e->v.idx);
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
						Log(llInfo, "undefined var '%s' is converted to function argument\n", var->name.c_str());
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
	Log(llDebug, "%a mba:\n%s\n", cfunc->entry_ea, s.c_str());

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
				Log(llDebug, "%a : %s.%d (%d)\n", cfunc->entry_ea, rname.c_str(), rsize, ireg);
				if(ireg != -1)
					rlist.sub(reg2mreg(ireg), rsize);
			}
		}
	}
#endif

	Log(llDebug, "%a def regs: %s\n", cfunc->entry_ea, rlist.dstr());
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
	get_short_name(&funcname, vu->cfunc->entry_ea);
	type.clear();
	if (!type.create_func(fti)) {
		Log(llError, "%a %s: create func type error!\n", vu->cfunc->entry_ea, funcname.c_str());
		return 0;
	}
	qstring typestr;
	type.print(&typestr);
	if(!apply_tinfo(vu->cfunc->entry_ea, type, TINFO_DEFINITE)) {
		Log(llError, "%a %s: apply func type error! (%s)\n", vu->cfunc->entry_ea, funcname.c_str(), typestr.c_str());
		return 0;
	}
	Log(llInfo, "%a %s: converted to '%s'\n", vu->cfunc->entry_ea, funcname.c_str(), typestr.c_str());
	vu->refresh_view(true);
	return 0;
}

#if IDA_SDK_VERSION < 850
static const char GO_NETNODE_HASH_IDX[] = "hrt_golang";
static const nodeidx_t GO_NETNODE_VAL = 0xC01AC01A;
void golang_add(ea_t ea)
{
	netnode node(ea);
	node.hashdel(GO_NETNODE_HASH_IDX);
	node.hashset(GO_NETNODE_HASH_IDX, GO_NETNODE_VAL);
	Log(llDebug, "%a: golang mode on\n", ea);
	
}

void golang_check(mbl_array_t *mba)
{
	netnode node(mba->entry_ea);
	if (GO_NETNODE_VAL == node.hashval_long(GO_NETNODE_HASH_IDX)) {
		mba->nodel_memory.add(mba->get_args_region());
		if(mba->mbr.pfn)
			set_func_cmt(mba->mbr.pfn, "Golang mode is on. To turn it off remove this comment and refresh view", false);
		Log(llDebug, "%a: golang mode\n", mba->entry_ea);
	}
}

void golang_del(ea_t ea)
{
	netnode node(ea);
	if (GO_NETNODE_VAL == node.hashval_long(GO_NETNODE_HASH_IDX)) {
		node.hashdel(GO_NETNODE_HASH_IDX);
		Log(llDebug, "%a: golang mode off\n", ea);
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
					Log(llDebug, "fix arg '%s' size %a\n", prev.name.c_str(), stkoff - prevBgn);
				}
			}
			Log(llDebug, "add arg '%s' at stkoff %a\n", mname.c_str(), stkoff);
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
		Log(llWarning, "FIXME: 'mark all registers as spoiled' is x86 specific\n");
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
	show_wait_box("[hrt] Maping vars...");
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
							Log(llDebug, "Map var '%s' to '%s'\n", var->name.c_str(), vars->at(dup).name.c_str());
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
							Log(llDebug, "map var '%s' to '%s'\n", var->name.c_str(), vars->at(dup).name.c_str());
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
#endif //IDA_SDK_VERSION < 850

//-------------------------------------------------------------------------------------------------------------------------
struct ida_local offset_locator_t : public ctree_parentee_t
{
	lvars_t * lvars;
	intvec_t  vidxs;
	std::map<uint64, tinfo_t> offNtypes;

	offset_locator_t(lvars_t * lvars_, int varIdx) : lvars(lvars_)
	{
		vidxs.add_unique(varIdx);
	}

	void addOffType(uint64 off, const tinfo_t& type) {
		auto it = offNtypes.find(off);
		if (it != offNtypes.end()) {
			size_t oldSz = it->second.get_size();
			size_t newSz = type.get_size();
			if (oldSz != BADSIZE && (newSz == BADSIZE || oldSz > newSz)) {
				Log(llDebug, "    addOffType skip: %s > %s\n", it->second.dstr(), type.dstr());
				return;
			}
		}
		offNtypes[off] = type;
	}

	int idaapi visit_expr(cexpr_t * e)
	{
		if (e->op == cot_asg && e->x->op == cot_var && e->y->op == cot_var) {
			if(vidxs.has(e->x->v.idx))
				vidxs.add_unique(e->y->v.idx);
			else if(vidxs.has(e->y->v.idx))
				vidxs.add_unique(e->x->v.idx);
			return 0;
		}
		if (e->op == cot_memptr && e->x->op == cot_var) {
			cexpr_t *var = e->x;
			if (vidxs.has(var->v.idx)) {
				Log(llDebug, "%a var ref1: %s.%x [%s]\n", e->ea, lvars->at(var->v.idx).name.c_str(), e->m, e->type.dstr());
				addOffType(e->m, e->type);
			}
			return 0;
		}

		if (e->op == cot_var && vidxs.has(e->v.idx)) {
			// found our var. are we inside a pointer expression?
			uint64 delta = 0;
			uint64 delta2 = 0;
			bool delta_defined = true;
			bool delta2_defined = false;
			int i = (int)parents.size() - 1;
			if (i >= 0 && parents[i]->op == cot_add) {
				// possible delta
				cexpr_t *d = ((cexpr_t*)parents[i])->theother(e);
				delta_defined = d->get_const_value(&delta);
				i--;
				if (i >= 0 && parents[i]->op == cot_add) {
					//possible array indexing
					cexpr_t *d = ((cexpr_t*)parents[i])->theother((cexpr_t*)parents[i+1]);
					delta2_defined = d->get_const_value(&delta2);
					i--;
				}
			}

			if (delta2_defined)
				delta = delta2;
			if (delta_defined || delta2_defined) {
				// skip casts
				tinfo_t t;
				while(i >= 0 && parents[i]->op == cot_cast) {
					t = ((cexpr_t*)parents[i])->type;
					i--;
				}
				t = remove_pointer(t);
				if(i >= 0 && parents[i]->op == cit_return) {
					Log(llDebug, "%a ignore var ref %s.%x [%s] in return statement\n", e->ea, lvars->at(e->v.idx).name.c_str(), (uint32)delta, t.dstr());
					return 0;
				}
				Log(llDebug, "%a var ref2: %s.%x [%s]\n", e->ea, lvars->at(e->v.idx).name.c_str(), (uint32)delta, t.dstr());
				addOffType(delta, t);
			}
			return 0;
		}
#if 0
		//*(_DWORD *)(var + 16)
		if (e->op == cot_ptr && e->x->op == cot_cast) {
			cexpr_t * cast = e->x;
			if(cast->x->op == cot_add) {
				cexpr_t * add = cast->x;
				if (add->x->op == cot_var) {
					cexpr_t * var = add->x;
					if (add->y->op == cot_num) {
						cexpr_t * num = add->y;
						if(vidxs.has(var->v.idx)) {
							tinfo_t t = remove_pointer(cast->type);
							Log(llDebug, "var ref3: %s.%x [%s]\n", lvars->at(var->v.idx).name.c_str(), (uint32)num->numval(), t.dstr());
							offNtypes[num->numval()] = t;
						}
					}
				}
			} else if(cast->x->op == cot_var) { //*(_DWORD *)(var)
				cexpr_t * var = cast->x;
				if(vidxs.has(var->v.idx)) {
					tinfo_t t = remove_pointer(cast->type);
					Log(llDebug, "var ref4: %s [%s]\n", lvars->at(var->v.idx).name.c_str(), t.dstr());
					offNtypes[0] = t;
				}
			}
		}
#endif
		return 0;
	}
};

static bool struct_matches(offset_locator_t &ifi, tid_t strucId)
{
	for(auto it = ifi.offNtypes.begin(); it != ifi.offNtypes.end(); ++it) {
		auto offset = it->first;
		size_t accSz = it->second.get_size();
		if(offset == 0) {
			//it may be the type been looking for
			size_t strucSz = type_by_tid(strucId).get_size();
			if (accSz != BADSIZE && strucSz != BADSIZE && accSz == strucSz)
				continue; //continue check other offsets
		}
		tid_t membId = BADNODE;
		if(struct_get_member(strucId, (asize_t)offset, &membId) != 0 || membId == BADNODE)
			return false;
#if IDA_SDK_VERSION < 850
		member_t* member = get_member_by_id(membId);
		if(!member)
			return false;
		size_t membSz;
		tinfo_t membtype;
		if(get_member_type(member, &membtype) && membtype.present())
			membSz = membtype.get_size();
		else
			membSz = member->eoff - member->soff;
#else
		udm_t udm;
		tinfo_t membStrucType;
		ssize_t membIdx = membStrucType.get_udm_by_tid(&udm, membId);
		if(membIdx < 0)
			return false;
		size_t membSz;
		if(udm.type.present())
			membSz = udm.type.get_size();
		else
			membSz = udm.size / 8;
		tinfo_t membtype = udm.type;
#endif //IDA_SDK_VERSION < 850
		if(accSz != BADSIZE && membSz != BADSIZE && accSz != membSz && !membtype.is_union()) {
			bool ok = false;
			while(membSz > accSz && membtype.is_struct()) {
				//it probably may be the first member of a bigger structure
				udm_t submemb;
				submemb.offset = 0;
				if(membtype.find_udm(&submemb, STRMEM_AUTO) < 0)
					break;
				membtype = submemb.type;
				membSz = membtype.get_size();
				if((membSz != BADSIZE && accSz == membSz) || membtype.is_union()) {
					ok = true;
					break;
				}
			}
			if(!ok) {
				//Log(llFlood, "!struct_matches %s at %x: %s <-sz-> %s\n", membStrucType.dstr(), (uint32)offset, it->second.dstr(), membtype.dstr());
				return false;
			}
		}
	}
	return true;
}

//-----------------------------------------------------
struct ida_local structs_shape_t : public chooser_t
{
	asize_t offset;
	tidvec_t list;
	static const int widths[];
	static const char* const header[];

	structs_shape_t(asize_t off) : chooser_t(CH_KEEP | CH_MODAL, 3, widths, header, "[hrt] Matched structs"), offset(off) {}
	virtual size_t idaapi get_count() const { return list.size() + 1; }
	virtual void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const;
};

const int structs_shape_t::widths[] = {40, 32, CHCOL_HEX | 8};
const char* const structs_shape_t::header[] = {"struct.member", "member type", "struct size"};

void idaapi structs_shape_t::get_row(qstrvec_t* cols_, int* , chooser_item_attrs_t* , size_t n) const
{
	qstrvec_t& cols = *cols_;
	if (n == 0) {
		cols[0] = "<create new>";
		return;
	}
	tid_t id = list[n - 1];
	uint32 col = 0;
	if (offset) {
		print_struct_member_name(id, offset, &cols[col++]);

		tid_t membId = BADNODE;
		if (0 == struct_get_member(id, offset, &membId) && membId != BADNODE)
			print_struct_member_type(membId, &cols[col]);
	} else {
		get_tid_name(&cols[col++], id);
	}
	++col;
#if IDA_SDK_VERSION >= 850
	tinfo_t struc;
	struc.get_type_by_tid(id);
	size_t size = struc.get_size();
#else
	asize_t size = get_struc_size(id);
#endif //IDA_SDK_VERSION >= 850
	cols[col].sprnt("0x%x", size);
}

ACT_DEF(recognize_shape)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	lvar_t* var = vu.item.get_lvar();
	if(!var)
		return 0;
	lvars_t* lvars = vu.cfunc->get_lvars();
	ssize_t vi = lvars->index(*var);
	if(vi == -1)
		return 0;

	// additionally display details of the field the cursor is staying at
	uint64 offset = 0;
	if(vu.item.is_citem()) {
		citem_t * ci = vu.cfunc->body.find_parent_of(vu.item.it);
		if(ci->is_expr()) {
			cexpr_t *exp = (cexpr_t *)ci;
			if(exp->op == cot_add && exp->y->op == cot_num)
				offset = exp->y->numval();
		}
	}
		
	offset_locator_t ifi(lvars, (int)vi);
	ifi.apply_to(&vu.cfunc->body, NULL);

	structs_shape_t rs((asize_t)offset);
	if(!ifi.offNtypes.empty()) {
#if IDA_SDK_VERSION < 850
		for(uval_t idx = get_first_struc_idx(); idx != BADNODE; idx = get_next_struc_idx(idx)) {
			tid_t id = get_struc_by_idx(idx);
			if (is_union(id))
				continue;
#else
		uint32 limit = get_ordinal_limit();
		if (limit == uint32(-1))
			return 0;
		for (uint32 ord = 1; ord < limit; ++ord) {
			tinfo_t t;
			if (!t.get_numbered_type(ord, BTF_STRUCT, true) || !t.is_struct())
					continue;
			tid_t id = t.get_tid();
#endif //IDA_SDK_VERSION < 850
			if(id != BADADDR && struct_matches(ifi, id))
				rs.list.push_back(id);
		}
	}

	ssize_t choosed = rs.choose();
	if (choosed > 0) {
		qstring name;
		get_tid_name(&name, rs.list[choosed-1]);

		tinfo_t ts = create_typedef(name.c_str());
		vu.set_lvar_type(var, make_pointer(ts));
		//if(!getVarName(var, NULL))
		//	renameVar(var->defea, vu.cfunc, vi, &name, &vu);
		vu.refresh_view(false);
		return 0;
	}
	if (choosed == 0) {
		//create new
		udt_type_data_t utd;
		vu.cfunc->gather_derefs(vu.item, &utd);
		if(utd.is_union)
			return 0;

		//gather_derefs + create_udt does not respect gaps, so manually add gaps before create_udt
		//probably need to sort members by offset before the loop
		uint64 off = 0;
#if 0
		// not compatible with older SDK
		for(;;) {
			udm_t memb;
			memb.offset = off;
			ssize_t i = utd.find_member(&memb, STRMEM_LOWBND);
			if(i < 0)
				break;
#else
		std::sort(utd.begin(), utd.end());
		for(size_t i = 0; i < utd.size(); i++) {
			Log(llFlood, "%d: off %x-%x, name %s, type %s (%x)\n", i, int(off/8), int(utd[i].offset/8), utd[i].name.c_str(), utd[i].type.dstr(), utd[i].size / 8);
#endif
			//make field auto-renameble
			utd[i].name.sprnt("field_%X", utd[i].offset / 8);

			if(off < utd[i].offset) {
				udm_t udm;
				udm.name.sprnt("gap%X", off / 8);
				udm.offset = off;
				udm.size = utd[i].offset - off;
				create_type_from_size(&udm.type, (asize_t)(udm.size / 8));
				off = utd[i].offset + utd[i].size;
				utd.insert(utd.begin() + i, udm);
				i++;
			} else {
				off += utd[i].size;
			}
		}
		utd.unpadded_size = utd.total_size = (size_t)(off / 8);
		utd.effalign = 1;
		utd.taudt_bits = TAUDT_UNALIGNED;
		tinfo_t restype;
		restype.create_udt(utd, BTF_STRUCT);
		tinfo_t ts;
		qstring tname;
		if (!confirm_create_struct(ts, tname, restype, NULL))
			return 0;
		vu.set_lvar_type(var, make_pointer(ts));
		//if(!getVarName(var, NULL))
		//	renameVar(var->defea, vu.cfunc, vi, &tname, &vu);
		vu.refresh_view(false);
	}
	return 0;
}

//--------------------------------------------------
struct ida_local matched_structs_with_offsets_t : public chooser_t
{
	asize_t offset;
	tidvec_t list;
	static const int widths[];
	static const char* const header[];

	matched_structs_with_offsets_t(asize_t off) : chooser_t(CH_KEEP | CH_MODAL, 3, widths, header, "[hrt] Structs with offset"), offset(off) {}
	virtual size_t idaapi get_count() const { return list.size(); }
	virtual void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const;
};

const int matched_structs_with_offsets_t::widths[] = {40, 32, CHCOL_HEX | 8};
const char* const matched_structs_with_offsets_t::header[] = {"struct.member", "member type", "struct size"};

void idaapi matched_structs_with_offsets_t::get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const
{
	qstrvec_t& cols_ = *cols;
	qstring name;
	qstring type_str;
	tid_t id = list[n];
	print_struct_member_name(id, offset, &cols_[0]);
	tid_t membId = BADNODE;
	if (0 == struct_get_member(id, offset, &membId) && membId != BADNODE)
		print_struct_member_type(membId, &cols_[1]);
#if IDA_SDK_VERSION >= 850
	tinfo_t struc;
	struc.get_type_by_tid(id);
	size_t size = struc.get_size();
#else
	asize_t size = get_struc_size(id);
#endif //IDA_SDK_VERSION >= 850
	cols_[2].sprnt("0x%x", size);
}

ACT_DEF(possible_structs_for_one_offset)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if (!vu.item.is_citem())
		return 0;

	cexpr_t *e = vu.item.e;
	if (e->op != cot_num)
		return 0;

	asize_t offset = (asize_t)e->numval();
	matched_structs_with_offsets_t m(offset);
#if IDA_SDK_VERSION < 850
	for(uval_t idx = get_first_struc_idx(); idx!=BADNODE; idx=get_next_struc_idx(idx)) {
		tid_t id = get_struc_by_idx(idx);
		if (is_union(id))
			continue;
		if(struct_has_member(id, offset))
			m.list.push_back(id);
	}
	ssize_t choosed = m.choose();
	if (choosed >= 0)
		open_structs_window(m.list[choosed], offset);
#else
		uint32 limit = get_ordinal_limit();
		if (limit == uint32(-1))
			return 0;
		for (uint32 ord = 1; ord < limit; ++ord) {
			tinfo_t t;
			if (!t.get_numbered_type(ord, BTF_STRUCT, true) || !t.is_struct())
					continue;
			tid_t id = t.get_tid();
			if(id != BADADDR && struct_has_member(id, offset))
				m.list.push_back(id);
		}

		ssize_t choosed = m.choose();
		if (choosed >= 0)
			open_loctypes_window(get_tid_ordinal(m.list[choosed]));
#endif //IDA_SDK_VERSION < 850
	return 0;
}

//-----------------------------------------------------
ACT_DEF(structs_with_this_size)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if (!vu.item.is_citem())
		return 0;
	cexpr_t *e = vu.item.e;
	if (e->op != cot_num)
		return 0;
	asize_t size = (asize_t)e->numval();
	matched_structs_t m;

#if IDA_SDK_VERSION < 850
	for (uval_t idx = get_first_struc_idx(); idx != BADNODE; idx = get_next_struc_idx(idx)) {
		tid_t id = get_struc_by_idx(idx);
		struc_t * struc = get_struc(id);
		if (!struc)
			continue;
		if (is_union(id))
			continue;
		if (get_struc_size(struc) == size)
			m.list.push_back(id);
	}

	ssize_t choosed = m.choose();
	if (choosed >= 0)
		open_structs_window(m.list[choosed], 0);
#else //IDA_SDK_VERSION >= 850
	uint32 limit = get_ordinal_limit();
	if (limit == uint32(-1))
		return 0;
	for (uint32 ord = 1; ord < limit; ++ord) {
		tinfo_t t;
		if (t.get_numbered_type(ord, BTF_STRUCT, true) && t.is_struct() && t.get_size() == size) {
			tid_t tid = t.get_tid();
			if (tid != BADADDR)
				m.list.push_back(tid);
		}
	}

	ssize_t choosed = m.choose();
	if (choosed >= 0)
		open_loctypes_window(get_tid_ordinal(m.list[choosed]));
#endif //IDA_SDK_VERSION < 850
	return 0;
}

//-----------------------------------------------------
bool is_number(vdui_t *vu)
{
	if (vu->item.is_citem() && vu->item.it->op == cot_num)
		return true;
	return false;
}

static inline THREAD_SAFE bool is_like_assign(ctype_t op)
{
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
static bool is_cast_assign(cfuncptr_t cfunc, cexpr_t * var, tinfo_t * ts)
{
	if (!isRenameble(var->op))
		return false;
		
	citem_t * asg_ci = cfunc->body.find_parent_of(var);
	if(!asg_ci->is_expr())
		return false;

	bool bDerefPtr = false;
	cexpr_t * asg = (cexpr_t *)asg_ci;
	if(!is_like_assign(asg->op)) {
		if(asg->op != cot_ptr || asg->x != var)
			return false;
		bDerefPtr = true;
		asg_ci = cfunc->body.find_parent_of(asg);
		if(!asg_ci->is_expr() || !is_like_assign(asg_ci->op))
			return false;
		asg = (cexpr_t *)asg_ci;
	} else if(asg->x != var)
		return false;

	cexpr_t* y = skipCast(asg->y);
	tinfo_t yType = y->type; //??? use getExpType(cfunc_t *func, cexpr_t* exp)
	if(bDerefPtr)
		yType = make_pointer(yType);

	if(asg->x->type == yType)
		return false;

	if(ts)
		*ts = yType;
	return true;
}

/*
 (cast to type)var;
 or
 LOBYTE(var)
 //cursor is on var
*/
static bool is_cast_var(cfuncptr_t cfunc, cexpr_t * var, tinfo_t * ts)
{
	if(!isRenameble(var->op))
		return false;

	citem_t * cast_ci = cfunc->body.find_parent_of(var);
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
		cast_ci = cfunc->body.find_parent_of(exp);
		if(cast_ci->is_expr())
			exp = (cexpr_t *)cast_ci;
	} 
	
	if(exp->op != cot_cast)
		return false;

	//check for ptr deref, ex: *(_OWORD *)var
	citem_t *pitm = cfunc->body.find_parent_of(exp);
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
		qstring name;
    if (has_any_name(get_flags(ea)))
			name = get_short_name(ea);
		else
			name.sprnt("0x%a", ea);
		int answer = ask_yn(ASKBTN_NO, "[hrt] Change type of '%s' to '%s'?", name.c_str(), ts->dstr());
		if(answer == ASKBTN_NO || answer ==ASKBTN_CANCEL)
			return false;
	}
	return apply_tinfo(ea, *ts, TINFO_DEFINITE | TINFO_STRICT | TINFO_DELAYFUNC);
}

#if IDA_SDK_VERSION < 850
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
			Log(llWarning, "forcing type '%s' on '%s' can lead changing structure size\n", typeStr.c_str(), membName.c_str());
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
#else //IDA_SDK_VERSION >= 850
bool set_membr_type(tinfo_t& struc, int idx, udm_t& member, tinfo_t *newType)
{
	asize_t mbsz = member.size / 8;
	asize_t nsz = 0;
	if(!struc.is_from_subtil()) {
		//if new type is smaller then old one - do delete member and re-create field
		switch(newType->get_decltype()) {
		case BT_UNK_OWORD:
		case BTF_INT128:
		case BTF_UINT128:
		case BT_INT128: nsz =16; break;
		case BT_UNK_QWORD:
		case BTF_INT64:
		case BTF_UINT64:
		case BT_INT64: nsz = 8; break;
		case BT_UNK_DWORD:
		case BTF_INT32:
		case BTF_UINT32:
		case BT_INT32: nsz = 4; break;
		case BT_UNK_WORD:
		case BTF_INT16:
		case BTF_UINT16:
		case BT_INT16: nsz = 2; break;
		case BT_UNK_BYTE:
		case BTF_INT8:
		case BTF_UINT8:
		case BTF_CHAR:
		case BT_INT8:  nsz = 1; break;
		default:       nsz = 0; break;
		}
		if(nsz && nsz < mbsz && (mbsz % nsz == 0)) {
			asize_t fo = member.offset / 8;
			qstring fname = member.name;
			if (struc.del_udm(struc.find_udm(member.offset)) == TERR_OK) {
				while(1) {
					udm_t udm;
					udm.offset = fo * 8;
					udm.size =  nsz * 8;
					udm.name = fname;
					create_type_from_size(&udm.type, nsz);
					if(TERR_OK != struc.add_udm(udm))
						break;
					mbsz -= nsz;
					if (mbsz <= 0)
						break;
					fo   += nsz;
					fname = good_udm_name(struc, fo * 8, "field_%a", fo);
				}
				return true;
			}
		}
	}
	if(TERR_OK == struc.set_udm_type(idx, *newType))
		return true;

	qstring oldtype; member.type.print(&oldtype);
	qstring newTypeS; newType->print(&newTypeS);
	qstring sname; struc.get_type_name(&sname);
	int answer = ask_yn(ASKBTN_NO, "[hrt] Change type of '%s.%s'\n from '%s' to '%s'\n may destroy other members.\n Confirm?", sname.c_str(), member.name.c_str(), oldtype.c_str(), newTypeS.c_str());
	if(answer == ASKBTN_NO || answer ==ASKBTN_CANCEL)
		return false;

	return (TERR_OK == struc.set_udm_type(idx, *newType, ETF_MAY_DESTROY));
}

bool set_membr_type(vdui_t* vu, tinfo_t* t)
{
	udm_t udm;
	tinfo_t parent;
	uint64 offset;
	int idx = vu->item.get_udm(&udm, &parent, &offset);
	if (idx < 0)
		return false;
	return set_membr_type(parent, idx, udm, t);
}
#endif //IDA_SDK_VERSION < 850

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

bool is_recastable(vdui_t *vu, tinfo_t *ts)
{
	if (!vu->item.is_citem())
		return false;
	return is_cast_var(vu->cfunc, vu->item.e, ts) || is_cast_assign(vu->cfunc, vu->item.e, ts);
}

ACT_DEF(recast_item)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	tinfo_t ts;
	if (is_recastable(vu, &ts))
		return cast_var2(vu, &ts);
	return 0;
}

bool is_gap_field(vdui_t *vu, tinfo_t *ts/*= nullptr*/, ea_t *gapMembOff/*= nullptr*/, 	ea_t* accessOff/*= nullptr*/, tinfo_t *accessType/*= nullptr*/)
{
	if(!vu->item.is_citem())
		return false;

	cexpr_t *membacc = vu->item.e;
	if(membacc->op != cot_memptr && membacc->op != cot_memref)
		return false;

	tinfo_t st = membacc->x->type;
	st.remove_ptr_or_array();
	if(!st.is_struct())
		return false;

	udm_t memb;
	memb.offset = membacc->m;
	if(st.find_udm(&memb, STRMEM_AUTO) < 0)
		return false;

	if(!strncmp(memb.name.c_str(), "fld_gap",7) || !strncmp(memb.name.c_str(), "gap",3)) {
		if(ts && gapMembOff && accessOff && accessType) {
			*ts = st;
			*gapMembOff = membacc->m;
			*accessOff = membacc->m;
			*accessType = memb.type;
			citem_t *parent = vu->cfunc->body.find_parent_of(membacc);
			if(parent->op == cot_idx) {
				cexpr_t *idx = ((cexpr_t *)parent)->y;
				if(idx->op != cot_num)
					return false;
				if(accessType->is_array())
					accessType->remove_ptr_or_array();
				*accessOff += (ea_t)(idx->numval() * accessType->get_size());
				parent = vu->cfunc->body.find_parent_of(parent);
			}
			if(parent->op == cot_ref)
				parent = vu->cfunc->body.find_parent_of(parent);
			if(parent->op == cot_cast && ((cexpr_t *)parent)->type.is_ptr() &&
				 vu->cfunc->body.find_parent_of(parent)->op == cot_ptr)
			{
				*accessType = ((cexpr_t *)parent)->type;
				accessType->remove_ptr_or_array();
			}
		}
		return true;
	}
#if IDA_SDK_VERSION >= 850
	//ida9 doesn't provide fake "gap" field for "fixed" struct
	citem_t *ref = vu->cfunc->body.find_parent_of(membacc);
	if(ref && ref->op == cot_ref) {
		citem_t *cast_or_add = vu->cfunc->body.find_parent_of(ref);
		cexpr_t* cast = nullptr;
		if(cast_or_add && cast_or_add->op == cot_cast) {
			cast = (cexpr_t*)cast_or_add;
			cast_or_add = vu->cfunc->body.find_parent_of(cast_or_add);
		}
		if(cast_or_add && cast_or_add->op == cot_add && ((cexpr_t*)cast_or_add)->y->op == cot_num) {
			cexpr_t* add = (cexpr_t*)cast_or_add;
			if(ts && gapMembOff && accessOff && accessType) {
				*ts = st;
				*gapMembOff = BADADDR;
				*accessType = cast ? cast->type : make_pointer(memb.type);
				citem_t *ptr = vu->cfunc->body.find_parent_of(add);
				if(ptr && ptr->op == cot_ptr)
					accessType->remove_ptr_or_array();
				*accessOff = membacc->m + (ea_t)(add->y->numval() * accessType->get_size());
			}
			return true;
		}
	}
#endif
	return false;
}

ACT_DEF(convert_gap)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	tinfo_t ts;
	ea_t gapOff;
	ea_t fldOff;
	tinfo_t fldType;
	if(!is_gap_field(vu, &ts, &gapOff, &fldOff, &fldType))
		return 0;

	if(fldType.empty())
		fldType.create_simple_type(BT_INT8);

#if IDA_SDK_VERSION < 850
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
#else //IDA_SDK_VERSION >= 850
	if(gapOff != BADADDR) {
		udm_t memb;
		memb.offset = gapOff;
		if(ts.find_udm(&memb, STRMEM_AUTO) < 0)
			return 0;
		//??? gap member may not exists, but ida provides fake one
		asize_t gapSz = memb.size / 8;
		if (ts.del_udm(ts.find_udm(memb.offset)) == TERR_OK) {
			if (fldOff > gapOff) {
				udm_t udm;
				udm.offset = gapOff * 8;
				udm.size = (fldOff - gapOff) * 8;
				udm.name = good_udm_name(ts, udm.offset, "gap%X", gapOff);
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
				udm.name = good_udm_name(ts, udm.offset, "gap%X", gapOff);
				create_type_from_size(&udm.type, gapSz);
				ts.add_udm(udm);
			}
		}
	}
	udm_t udm;
	udm.offset = fldOff * 8;
	udm.size = fldType.get_size() * 8;
	udm.name = good_udm_name(ts, udm.offset, "field_%X", fldOff);
	udm.type = fldType;
	//may cause INTERR 821 for "fixed" struct with zero align (zero effalign returned by type.get_size(&effalign))
	tinfo_code_t c = ts.add_udm(udm, ETF_MAY_DESTROY);
	if(c != TERR_OK)
		Log(llError, "convert_gap %s err %d\n", udm.name.c_str(), c);
#endif //IDA_SDK_VERSION < 850
	vu->refresh_view(false);
	return 0;
}

//-----------------------------------------------------
ACT_DEF(disable_inlines)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	XXable_inlines(vu->cfunc->entry_ea, true);
	vu->refresh_view(true);
	return 0;
}

ACT_DEF(enable_inlines)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	XXable_inlines(vu->cfunc->entry_ea, false);
	vu->refresh_view(true);
	return 0;
}

ACT_DEF(rename_inline)
{
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if (ren_inline(vu))
		vu->cfunc->refresh_func_ctext();
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
	Log(llDebug, "group %d preds :", group);
	for (size_t i = 0; i < grp_preds.size(); i++)
		LogTail(llDebug, "%d ", grp_preds[i]);
	LogTail(llDebug, "\nhead %d preds :", head);
	for (size_t i = 0; i < head_preds.size(); i++)
		LogTail(llDebug, "%d ", head_preds[i]);
	LogTail(llDebug, "\n");
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
		Log(llDebug, "converting group '%s' to inline\n", ni.text.c_str());
		qflow_chart_t fc;
		fc.create("tmpfc", ctx->cur_func, ctx->cur_func->start_ea, ctx->cur_func->end_ea, FC_NOEXT);
		if (fc.size() == gr->org_succs.size()) {
			rangevec_t ranges;
			for (int node = gr->get_first_subgraph_node(group); node != -1; node = gr->get_next_subgraph_node(group, node)) {
				QASSERT(100202, node < fc.size());
				const qbasic_block_t* bb = &fc.blocks[node];
				Log(llDebug, "   %d: %a-%a\n", node, bb->start_ea, bb->end_ea);
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
	Log(llDebug, "%a-%a: range selected for inline\n", eaBgn, eaEnd);
	qflow_chart_t fc;
	fc.create("tmpfc", ctx->cur_func, ctx->cur_func->start_ea, ctx->cur_func->end_ea, 0);
	for (int n = 0; n < fc.size(); n++) {
		const qbasic_block_t* blk = &fc.blocks[n];
		Log(llDebug, "   %d: %a-%a\n", n, blk->start_ea, blk->end_ea);
		if (blk->start_ea <= eaBgn && eaBgn < blk->end_ea)
			eaBgn = blk->start_ea;
		else if (blk->start_ea < eaEnd && eaEnd < blk->end_ea)
			eaEnd = blk->start_ea;
	}
	Log(llDebug, "%a-%a: inline applicant aligned to basic block boundaries\n", eaBgn, eaEnd);

	selection2inline(eaBgn, eaEnd);
	XXable_inlines(vu->cfunc->entry_ea, false);
	vu->refresh_view(true);
	return 0;
}

//-----------------------------------------------------
static bool save_if42blocks(ea_t funcea, const rangevec_t& ranges)
{
	bytevec_t buffer;
	for (const auto& r : ranges) {
		buffer.pack_ea(r.start_ea);
		buffer.pack_ea(r.end_ea);
	}
	if (buffer.size() > MAXSPECSIZE) {
		Log(llWarning, "too many if42blocks\n");
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
		Log(llError, "makeif42block: bad selection2 %a-%a\n", eaBgn, eaEnd);
		return false;
	}

	cinsnptrvec_t& ivBgn = eamap_second(itBgn);
	cinsnptrvec_t& ivEnd = eamap_second(itEnd);
	if (!ivBgn.size() || !ivEnd.size()) {
		Log(llError, "makeif42block: bad selection3 %a-%a\n", eaBgn, eaEnd);
		return false;
	}

	cinsn_t *iFirst = ivBgn[0];
	cinsn_t *iLast  = ivEnd[0];

	citem_t *paBgn = cfunc->body.find_parent_of(iFirst);
	citem_t *paEnd = cfunc->body.find_parent_of(iLast);
	if (paBgn != paEnd || !paBgn || paBgn->op != cit_block) {
		Log(llError, "makeif42block: selection %a-%a is not inside same block\n", eaBgn, eaEnd);
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
			//Log(llDebug, "move %a: %s\n", it->ea, s.c_str());
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
		vu->cfunc->refresh_func_ctext();
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
	ufDelGL(vu->cfunc->entry_ea);
	vu->refresh_view(true);
	return 0;
}

ACT_DEF(uf_disable)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	ufAddGL(vu->cfunc->entry_ea);
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
	if(!sprefix || !*sprefix) {
		if(dummy_struct_prefix.empty())
			sprefix = "s";
		else
			sprefix = dummy_struct_prefix.c_str();
	}

	qstring name = sprefix;
	if(size)
		name.sprnt("%s%X", sprefix, size);

	qstring bn = name;
	for (char j = 'z'; j > 'f'; j--) {
		qstring basename = name;
		for (char i = 'z'; i > 'f'; i--) {
			if(!isNamedTypeExists(name.c_str()))
				return name;
			name = basename;
			name.cat_sprnt("%c", i);
		}
		name = bn;
		name.cat_sprnt("%c", j);
	}
	QASSERT(100110, !"oops");
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
		"STARTITEM 1\n"
		//title
		"[hrt] Create struct\n\n"
		"%/\n" // callback
		"<~P~refix:q4::16::>\n"
		"<~S~ize  :L1:32:16::>\n"
		"<~N~ame  :q2::16::>\n"
		"<###create only last field#~E~mpty:c3>>\n"
		"\n\n";
	do {
		if (1 != ask_form(format, dummy_struct_cb, &dummy_struct_prefix, &size, &name, &empty))
			return 0;
		if(isNamedTypeExists(name.c_str())) {
			Log(llError, "struct '%s' already exists\n", name.c_str());
		} else if (size != 0) {
			break;
		}
	} while (1);

#if IDA_SDK_VERSION < 850
	tid_t id = add_struc(0, name.c_str());
	struc_t* s = get_struc(id);
	if (!s)
		return 0;
#else //IDA_SDK_VERSION >= 850
	udt_type_data_t s;
	s.taudt_bits |= TAUDT_UNALIGNED;
	s.total_size = s.unpadded_size = size;
	s.effalign = 1;
	//s.pack = 1;
	//not sure is need to set_fixed for a dummy_struct that will be modified many times during further reversing
	//s.set_fixed(true);
#endif //IDA_SDK_VERSION < 850

	if (empty || size > 10240) {
#if IDA_SDK_VERSION < 850
		add_struc_member(s, "gap", 0, byte_flag(), NULL, (ea_t)(size-1));
		add_struc_member(s, "field_last", (ea_t)(size - 1), byte_flag(), NULL, 1);
#else //IDA_SDK_VERSION >= 850
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
#endif //IDA_SDK_VERSION < 850
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
#if IDA_SDK_VERSION < 850
			add_struc_member(s, fname.c_str(), fo, ft, NULL, fsz);
#else //IDA_SDK_VERSION >= 850
			udm_t& m = s.push_back();
			m.name = fname;
			m.size = 8 * fsz; //in bits
			m.offset = 8 * fo; //in bits
			create_type_from_size(&m.type, fsz);
#endif //IDA_SDK_VERSION < 850
			size -= fsz;
			fo += fsz;
		}
	}
#if IDA_SDK_VERSION < 850
#else //IDA_SDK_VERSION >= 850
	tinfo_t ti;
	if (!ti.create_udt(s) || ti.set_named_type(NULL, name.c_str()) != TERR_OK) {
		Log(llError, "create_udt() || set_named_type(\"%s\") error\n", name.c_str());
		return 0;
	}
#endif //IDA_SDK_VERSION < 850
	Log(llNotice, "struct '%s' was created\n", name.c_str());

	if(vu) {
		cexpr_t *call;
		if(is_call(vu, &call, true)) {
			qstring callname;
			if(getExpName(vu->cfunc, call->x, &callname)) {
				cexpr_t* asgn = get_assign_or_helper(vu, call, false);
				if(asgn && (stristr(callname.c_str(), "alloc") || callname == "??2@YAPAXI@Z")) { // "??2@YAPEAX_KAEBUnothrow_t@std@@@Z"  "??2@YAPEAX_K@Z"
					if(vu->item.is_citem() && vu->item.it->op == cot_num && vu->item.e->ea != BADADDR && !vu->item.e->n->nf.is_fixed()) {
#if IDA_SDK_VERSION < 850
						size = get_struc_size(s);
#else //IDA_SDK_VERSION >= 850
						size = ti.get_size();
#endif //IDA_SDK_VERSION < 850
						if(vu->item.e->numval() == size) {
							//make size argument look like "sizeof(structName)"
							user_numforms_t *numForms = restore_user_numforms(vu->cfunc->entry_ea);
							if(!numForms)
								numForms = user_numforms_new();
							number_format_t &nf = vu->item.e->n->nf;
							nf.type_name = name;
							nf.flags = stroff_flag();
							//nf.props = NF_FIXED | NF_VALID;
							operand_locator_t valOp(vu->item.e->ea, nf.opnum);
							user_numforms_insert(numForms, valOp, nf);
							if(user_numforms_size(numForms))
								save_user_numforms(vu->cfunc->entry_ea, numForms);
							user_numforms_free(numForms);
						}
					}
					renameExp(asgn->ea, vu->cfunc, asgn->x, &name, vu);
					vu->refresh_view(true);
					return 0;
				}
			}
		}
		qstring n;
		if(vu->item.is_citem() &&
			 isRenameble(vu->item.e->op) &&
			 !getExpName(vu->cfunc, vu->item.e, &n) &&
			 renameExp(vu->item.e->ea, vu->cfunc, vu->item.e, &name, vu))
			return 1;//vu->refresh_view(true);
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
		Log(llError, "fill_nops: bad range %a - %a\n", eaBgn, eaEnd);
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
		Log(llError, "searchNpatch: bad range %a - %a\n", eaBgn, eaEnd);
		return 0;
	}
	qstring errbuf;
	compiled_binpat_vec_t key;
	if(!parse_binpat_str(&key, eaBgn, keystr.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
		Log(llError, "searchNpatch: error in Search string '%s': %s\n", keystr.c_str(), errbuf.c_str());
		return 0;
	}
	compiled_binpat_vec_t rep;
	if(!parse_binpat_str(&rep, eaBgn, repstr.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
		Log(llError, "searchNpatch: error in Replace string '%s': %s\n", repstr.c_str(), errbuf.c_str());
		return 0;
	}
	size_t keySize = key.front().bytes.size();
	if (key.size() != rep.size() || rep.size() != 1 ||
			keySize != rep.front().bytes.size()) {
		Log(llError, "searchNpatch: Search and Replace strings have different size\n");
		return 0;
	}
	//unmark_selection();//check, is this need
	uint32 cnt = 0;
	for (ea_t found_ea = eaBgn; found_ea < eaEnd; found_ea++) {
#if IDA_SDK_VERSION < 850
		found_ea = bin_search2(found_ea, eaEnd, key, BIN_SEARCH_CASE | BIN_SEARCH_FORWARD);
#else //IDA_SDK_VERSION >= 850
		found_ea = bin_search(found_ea, eaEnd, key, BIN_SEARCH_CASE | BIN_SEARCH_FORWARD);
#endif //IDA_SDK_VERSION < 850
		if(found_ea == BADADDR)
			break;
		qvector<uint8> found;
		found.resize(keySize);
		if(keySize != get_bytes(&found[0], found.size(), found_ea)) {
			Log(llWarning, "searchNpatch: get_bytes error at %a len %d\n", found_ea, found.size());
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
		Log(llWarning, "searchNpatch: '%s' is not found\n", keystr.c_str());

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
		Log(llError, "dbg_patch: bad range %a - %a\n", eaBgn, eaEnd);
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
		Log(llNotice, "dbg_patch: add range from %a len %d to patch after debugger exit\n", eaBgn, patch.len);
	}

  return 1;
}

void apply_dbg_patches()
{
	for (qvector<sDbgPatch>::iterator it = dbgPatches.begin(); it < dbgPatches.end(); it++) {
		Log(llInfo, "apply dbg_patch at %a len %d\n", it->eaBgn, it->len);
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
			Log(llError, "'%s' is not exist\n", filename);
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
			Log(llNotice, "'%s' (%a-%a) is created\n", newFilename.c_str(), startEa, endEa);
		}
	} else {
		Log(llError, "copyfile(\"%s\", \"%s\") failed\n", filename, newFilename.c_str());
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
	Log(llNotice, "Clear all cached decompilation results\n");
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
			return decompile_obfuscated(vu->cfunc->entry_ea);
	} catch (interr_exc_t &e) {
		warning("[hrt] unhandled IDA internal error %d", e.code);
	} catch (vd_failure_t &e) {
		warning("[hrt] unhandled Hexrays internal error at %a: %d (%s)\n", e.hf.errea, e.hf.code, e.hf.desc().c_str());
	}
	return 0;
}

//------------------------------------------------
struct ida_local call_dst_locator_t : public ctree_visitor_t
{
	cfunc_t* cfunc;
	easet_t callees;
	call_dst_locator_t(cfunc_t* func): ctree_visitor_t(CV_FAST), cfunc(func) {}
	int idaapi visit_expr(cexpr_t * e)
	{
		if(e->op == cot_call) {
			ea_t callDst = get_call_dst(cfunc, e);
			if(callDst != BADADDR)
				callees.insert(callDst);
		}
		return 0; //continue
	}
};

static volatile uint32 g_typeChanged = 0;
struct ida_local decompile_recursive_t
{
	easet_t visited;

	void decompile(ea_t entry, uint32 level)
	{
		if(level > 100) {
			Log(llFlood, "decompile_recursive %a: too deep\n", entry);
			return;
		}
		func_t* func = get_func(entry);
		if(!func || func->flags & (FUNC_LIB | FUNC_LUMINA)) {
			Log(llFlood, "decompile_recursive: no or lib func at %a\n", entry);
			return;
		}
		if(!visited.insert(entry).second) {
			Log(llFlood, "decompile_recursive %a: visited\n", entry);
			return;
		}

		//replace_wait_box("[hrt] Decompiling depth %d", level);
		qstring funcName = get_short_name(func->start_ea);

		bool userti = true;
		int decomp_flags = DECOMP_NO_WAIT;
		tinfo_t t1;
		if(!is_userti(func->start_ea)) {
			userti = false;
			decomp_flags |= DECOMP_NO_CACHE;
			get_tinfo(&t1, func->start_ea);
			Log(llDebug, "%a decompile_recursive(%s): 1st pass NO_CACHE for type %s\n", entry, funcName.c_str(), t1.dstr());
		} else {
			Log(llDebug, "%a decompile_recursive(%s): 1st pass USE_CACHE\n", entry, funcName.c_str());
		}

		hexrays_failure_t hf;
		cfuncptr_t cf = decompile_func(func, &hf, decomp_flags);
		if(!cf || hf.code != MERR_OK) {
			Log(llDebug, "%a: 1 decompile_func(\"%s\") failed with '%s'\n", func->start_ea, funcName.c_str(), hf.desc().c_str());
			return;
		}

		//decompile again if decompile_func changes func type
		if(!userti) {
			tinfo_t t2;
			if(get_tinfo(&t2, func->start_ea) && t1 != t2) {
				Log(llFlood, "%a decompile_recursive(%s): type changed from %s to %s\n", entry, funcName.c_str(), t1.dstr(), t2.dstr());
				cf = decompile_func(func, &hf, DECOMP_NO_WAIT | DECOMP_NO_CACHE);
				if(!cf || hf.code != MERR_OK) {
					Log(llDebug, "%a: 2 decompile_func(\"%s\") failed with '%s'\n", func->start_ea, funcName.c_str(), hf.desc().c_str());
					return;
				}
			}
		}

		//find calls
		call_dst_locator_t cloc(cf);
		cloc.apply_to(&cf->body, NULL);
		if(!cloc.callees.size()) {
			Log(llFlood, "%a decompile_recursive(%s): no calls\n", entry, funcName.c_str());
			return;
		}

		uint32 typeChanged = g_typeChanged;
		for(ea_t callee : cloc.callees) {
			decompile(callee, level + 1);
			if(user_cancelled()) {
				Log(llDebug, "decompile_recursive %a: user_cancelled\n", entry);
				return;
			}
		}

		if(typeChanged == g_typeChanged) {
			Log(llDebug, "decompile_recursive %a: no changes\n", entry);
			return;
		}
		Log(llDebug, "%a: on recursive decompile(\"%s\", %d) %d types changed\n", func->start_ea, funcName.c_str(), level, g_typeChanged - typeChanged);

		// force decompile again if changed
		cf = decompile_func(func, &hf, DECOMP_NO_WAIT | DECOMP_NO_CACHE);
		if(!cf || hf.code != MERR_OK) {
			Log(llDebug, "%a: 3 decompile_func(\"%s\") failed with '%s'\n", func->start_ea, funcName.c_str(), hf.desc().c_str());
		}
	}
};

bool decompile_recursive(ea_t entry)
{
	uint32 typeChanged = g_typeChanged;
	decompile_recursive_t d;
	show_wait_box("[hrt] Decompiling...");
	try {
		d.decompile(entry, 0);
	} catch (interr_exc_t &e) {
		warning("[hrt] unhandled IDA internal error %d", e.code);
	} catch (vd_failure_t &e) {
		warning("[hrt] unhandled Hexrays internal error at %a: %d (%s)\n", e.hf.errea, e.hf.code, e.hf.desc().c_str());
	}
	hide_wait_box();
	Log(llNotice, "%a: === on recursive decompile %d types changed by decompiling %d procs ===\n", entry, g_typeChanged - typeChanged, d.visited.size());
	return g_typeChanged != typeChanged;
}

ACT_DEF(decomp_recur)
{
	if (ctx->widget_type == BWN_DISASM) {
		func_t *f = get_func(ctx->cur_ea);
		if(f) {
			decompile_recursive(f->start_ea);
			COMPAT_open_pseudocode_REUSE(f->start_ea);
		}
		return 0;
	}
	vdui_t *vu = get_widget_vdui(ctx->widget);
	if (vu && decompile_recursive(vu->cfunc->entry_ea))
		vu->refresh_view(false);
	return 0;
}

//------------------------------------------------

ACT_DEF(jmp2xref)
{
	if (ctx->widget_type == BWN_DISASM) {
		ea_t ea = get_screen_ea();
		flags64_t F = get_flags(ea);
		if (is_code(F)) {
			func_t *pfn = get_func(ea);
			if (pfn && pfn->start_ea != ea) {
				gco_info_t gco;
				if (get_current_operand(&gco)) {
					return regrefs(ea, pfn, gco);
				}
			}
		}
		if (is_func(F) || is_data(F))
			return jump_to_call_or_glbl(ea);
	}
	
	if (ctx->widget_type == BWN_PSEUDOCODE) {
		vdui_t *vu = get_widget_vdui(ctx->widget);
		if(vu) {
			if (vu->item.is_citem()) {
				switch(vu->item.e->op) {
				case cot_obj:
					return jump_to_call_or_glbl(vu->item.e->obj_ea);
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
			} else if (vu->item.citype == VDI_FUNC && vu->cfunc) {
				return jump_to_call_or_glbl(vu->cfunc->entry_ea);
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
		//Log(llFlood, "is_stack_var_assign var %s defea: %a\n", var->name.c_str(), var->defea, expr->ea, printExp(vu->cfunc, (cexpr_t *)expr).c_str());
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
		Log(llInfo, "build stack string: skipBeforeEa %a\n", skipBeforeEa);
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
				Log(llInfo, "%a: build stack string: skip early writing assignment '%s'\n", e->ea, printExp(func, e).c_str());
				return 0;
			}
			auto it = varVal.find(varIdx);
			if(it != varVal.end()) {
				Log(llInfo, "%a: build stack string: skip overwriting assignment '%s'\n", e->ea, printExp(func, e).c_str());
				return 0;
			}
			Log(llInfo, "%a: build stack string: use assignment '%s'\n", e->ea, printExp(func, e).c_str());
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
		vi =  lvars->find_stkvar((int32)spoff, (int)char_size);
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
		// var will be renamed by comment
		//renameVar(asgn_ea, vu->cfunc, varIdx, &str, vu);
		vu->cfunc->refresh_func_ctext();
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
				Log(llInfo, "%a: build array string: skip early writing assignment '%s'\n", val->ea, printExp(func, e).c_str());
				return 0;
			}
			auto it = varVal.find(arrIdx);
			if (it != varVal.end()) {
				Log(llInfo, "%a: build array string: skip overwriting assignment '%s'\n", val->ea, printExp(func, e).c_str());
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

	renameVar(ea, vu->cfunc, varIdx, &result, vu);
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
	if (!decrypt_string(vu, BADADDR, inBuf, 1, &hint_itSz, &result, true)) //do not decrypt last zero
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

ACT_DEF(refactoring)
{
	return do_refactoring(ctx);
}

//--------------------------------------------------------------------------

ACT_DEF(import_unf_types)
{
	size_t impCnt  = 0;
	size_t funcqty = get_func_qty();

	show_wait_box("[hrt] importing...");
	for (size_t i = 0; i < funcqty; i++) {
		if (user_cancelled()) {
			hide_wait_box();
			Log(llWarning, "import_unf_types is canceled\n");
			return 0;
		}

		func_t* funcstru = getn_func(i);
		if(funcstru && 0 == (funcstru->flags & (FUNC_LIB | FUNC_THUNK))) {
			qstring funcName = get_name(funcstru->start_ea);
			if (is_uname(funcName.c_str())) {
				tinfo_t tif;
				if(get_tinfo(&tif, funcstru->start_ea) && tif.is_func()) {
					stripName(&funcName, true);
#if 1
					//CHECKME: without NTF_NO_NAMECHK ida creates partially unmangled names probably not suitable for reapplying with signatures, and a lot of "bad name" errors
					tinfo_code_t err = tif.set_named_type(nullptr, funcName.c_str() , NTF_REPLACE | NTF_NO_NAMECHK);
#else
					// 1) a lot of error -1: "failed to save"
					// 2) imported types are not appears in "local types list" nor exported to "C header file"
					tinfo_code_t err = tif.set_symbol_type(nullptr, funcName.c_str() , NTF_SYMM);
#endif
					if(TERR_OK == err)
						++impCnt;
					else
						Log(llError, "%a: import func '%s' type error %d %s\n", funcstru->start_ea, funcName.c_str(), err, tinfo_errstr(err));
				}
			}
		}
	}
	hide_wait_box();
	Log(llNotice, "%d user named function types imported\n", impCnt);
	return 0;
}
//--------------------------------------------------------------------------
// brackets matching
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
						Log(llFlood, "got '%c' at %d \n'%s'\n", ch, pos->x, out.c_str());
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
								Log(llFlood, "got pair '%c' at %d\n'%s'\n", bracechar, j, out.c_str());
							}
							break;
						}
					}
				}
			}
			if(0) {
				qstring out;
				idb_utf8(&out, ps[ypos].line.c_str(), -1, IDBDEC_ESCAPE);
				Log(llFlood, "cur line '%s'\n", out.c_str());
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
		ps[ypos].bgcolor = (bgcolor_t)cfg.braceBgColor;

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
				ps[j].bgcolor = (bgcolor_t)cfg.braceBgColor;
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
	static bool msigRenamed = false;
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
#if IDA_SDK_VERSION < 850
	case hxe_resolve_stkaddrs:
		{
			mbl_array_t *mba = va_arg(va, mbl_array_t *);
			golang_check(mba);
			break;
		}
#endif //IDA_SDK_VERSION < 850
	case hxe_microcode:
		{
			mbl_array_t *mba = va_arg(va, mbl_array_t *);
			vv_insert_assertions(mba);
			deinline_reset(mba->entry_ea);
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

			if (has_varvals(cfunc->entry_ea))
				cfunc->sv.insert(cfunc->sv.begin(), simpleline_t("// The function is modified by hidden variable assignment(s)"));

			// hxe_func_printed is not called in packet decompiling mode
			const char* msigName = msig_cached(cfunc->entry_ea);
			if(msigName) {
				qstring cmt(msigMessage); cmt.append(msigName);
				cfunc->sv.insert(cfunc->sv.begin(), simpleline_t(cmt));
				if(msigRenamed)
					cfunc->sv.front().line.append(". Press F5 to refresh pseudocode.");
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
			if (find_if_statement(vu))
				attach_action_to_popup(form, popup, INV_IF_ACTION_NAME);
			add_hrt_popup_items(form, popup, vu);
		}
		break;
	case hxe_keyboard:
		{
			vdui_t &vu = *va_arg(va, vdui_t *);
			int key_code  = va_arg(va, int);
			int shift_state = va_arg(va, int);
			Log(llFlood, "key %x/%x (%c)\n", shift_state, key_code, key_code);
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
			vdui_t* vu = va_arg(va, vdui_t *);
			vu->get_current_item(USE_MOUSE);
			if(isMsig(vu, nullptr)) {
				//it possible to directly call msig_accept internals, but there is no API to create undo point, so this double click will be un-undo-able
				process_ui_action(ACT_NAME(msigAccept));
				return 1; // force return 1 to IDA don't catch handled double click
			}
			return jump_to_call_dst(vu); // Should return: 1 if the event has been handled
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
			switch (new_maturity) {
			//case CMAT_ZERO:			break;
			case CMAT_BUILT: // just generated
#if IDA_SDK_VERSION <= 730
				convert_negative_offset_casts(cfunc);
#endif //IDA_SDK_VERSION <= 730
				break;
			//case CMAT_TRANS1:		break;
			//case CMAT_NICE:			break;
			//case CMAT_TRANS2:		break;
			case CMAT_CPA:
				convert_offsetof_n_reincasts(cfunc);
				break;
			case CMAT_TRANS3:
				com_scan(cfunc);
				break;
			//case CMAT_CASTED:
			//	break;
			case CMAT_FINAL:
				auto_create_vtbls(cfunc); //before all, virtual calls may appear as result of vtbl creation when constructor is inlined into caller proc
				apihashes_scan(cfunc);// before autorename_n_pull_comments: so comments be used for renaming
				if(!cfg.disable_autorename)
					autorename_n_pull_comments(cfunc);
				lit_scan(cfunc); // after autorename_n_pull_comments: to search literals in renamed indirect calls
				convert_marked_ifs(cfunc);
				make_if42blocks(cfunc);

				//there is not found a better place that called once after microcode is completed
				msigRenamed = false;
				if(last_globopt_ea == cfunc->entry_ea) { //avoid mba restored from cache
					const char* msigName = msig_match(cfunc->mba);
					if(msigName &&
						 !qstrchr(msigName, ' ') && //check if the msig has multiple names
						 !has_user_name(get_flags(cfunc->entry_ea)) &&
						 set_name(cfunc->entry_ea, msigName, SN_NOWARN | SN_FORCE))
						msigRenamed = true;
				}
				break;
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
			if(!is_user_name)
				break;
			if(v->is_arg_var() && qstrcmp(name, v->name.c_str())) { // only arg vars are affected
				Log(llWarning, "IDA bug: lxe_lvar_name_changed is sent for wrong variable ('%s' instead of '%s')", v->name.c_str(), name);
				lvars_t *vars = vu->cfunc->get_lvars();
				auto it = vars->begin();
				for(; it != vars->end(); it++) {
					if(it->name == name)
						break;
				}
				if(it == vars->end()) {
					LogTail(llWarning, " -- not found\n");
					//variable may not renamed at all (and listed in 'vars' with old name). But the function prototype is changed
					//try find right var in func prototype
					tinfo_t ft;
					//if(vu->cfunc->get_func_type(&ft)) { // this type has the old name too (not renamed)
					if(get_tinfo(&ft, vu->cfunc->entry_ea)) { // this type is ok (argument is renamed)
						func_type_data_t fi;
						if(ft.get_func_details(&fi)) {
							for(size_t i = 0; i < fi.size(); ++i) {
								if(fi[i].name == name) {
									tinfo_t newType = getType4Name(name);
									if(!newType.empty()) {
										fi[i].type = newType;
										tinfo_t newFType;
										if(newFType.create_func(fi) && apply_tinfo(vu->cfunc->entry_ea, newFType, is_userti(vu->cfunc->entry_ea) ? TINFO_DEFINITE : TINFO_GUESSED)) {
											qstring typeStr;
											newFType.print(&typeStr);
											Log(llWarning, "lxe_lvar_name_changed wa %a: Function type was recasted for change arg%d into \"%s\"\n", vu->cfunc->entry_ea, i, typeStr.c_str());
											vu->refresh_view(true);
										}
									}
									break;
								}
							}
						}
					}
					break;
				}
				v = it;
				LogTail(llWarning, " -- fixed\n");
			}
			if (!v->has_user_type()) {
			  tinfo_t t = getType4Name(name);
				if(!t.empty() && set_var_type(vu, v, &t))
					Log(llInfo, "%a: type of var '%s' refreshed\n", vu->cfunc->entry_ea, name);
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
			if (t.is_ptr_or_array()) {//do not recourse pointers, else lxe_lvar_name_changed callback change type back to tname*
				t.remove_ptr_or_array();
				isPtr = true;
			}
			qstring tname;
			if(!t.is_scalar() && t.get_type_name(&tname)) {
				cfunc_t *func = vu->cfunc;
				ssize_t varIdx = func->get_lvars()->index(*v);
				if(varIdx != -1) {
					if(!isPtr)
						tname.append('_');
					if(renameVar(func->entry_ea, func, varIdx, &tname, vu))
						vu->cfunc->refresh_func_ctext();
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
      Log(llDebug, "no funcs wnd\n");
      return false; //  remove the request from the queue
    }

#if 0
		TWidget * curw = get_current_widget();
		if(!curw)
			Log(llDebug, "`get_current_widget` does't work\n");
		else if(curw != wdg)
			Log(llDebug, "`activate_widget` does't work\n");
#endif

#if defined __LINUX__ && IDA_SDK_VERSION >= 740 && IDA_SDK_VERSION <= 750
    //ida 7.7 works without crutches
    //on ida 7.6 this trick does not works anymore
    //linux IDA 7.4 & 7.5 does not activate widget immediately
    for(int i = 10; i > 0; i--) {
      show_wait_box("[hrt] This message is workaround of \"IDA for linux\" bug \n activate_widget() call does not work without this waitbox");
      qsleep(100);
      hide_wait_box();
      TWidget * curw = get_current_widget();
      if(curw == wdg)
        break;
      qstring title;
      if(curw)
        get_widget_title(&title, curw);
      Log(llDebug, "%d %p '%s'\n", i, curw, title.c_str());
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
      Log(llDebug, "AST_DISABLE_FOR_WIDGET\n");
      //update_action_state(FunctionsToggleSync, AST_ENABLE_FOR_WIDGET);
    }
		bool checked;
    bool bc = get_action_checked(FunctionsToggleSync, &checked);
    bool visibility;
    bool bv = get_action_visibility(FunctionsToggleSync, &visibility);
    Log(llDebug, "FuncSwitchSync %d-%d, %d-%d, %d-%d, %d-%d, %d-%s\n", bs, state, bb, checkable, bc, checked, bv, visibility, bl, lbl.c_str());
#endif
		if(bl && strneq(lbl.c_str(), "Turn on", 7)) { //"Turn on synchronization"
			if(process_ui_action(FunctionsToggleSync))
				Log(llInfo, "turn on %s\n", FunctionsToggleSync);
			else
				Log(llWarning, "fail to turn on %s\n", FunctionsToggleSync);
		}

    if(!StartWdg)
      StartWdg = find_widget("Pseudocode-A");
    if(!StartWdg)
      StartWdg = find_widget("IDA View-A");
    if(StartWdg) {
      activate_widget(StartWdg, true);
#if defined __LINUX__  && IDA_SDK_VERSION >= 740 && IDA_SDK_VERSION <= 750
    //linux IDA does not activate widget immediately
      show_wait_box("[hrt] Second waitbox to activate back main window\n after turning on synchronization in Functions window");
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
MY_DECLARE_LISTENER(ui_callback)
{
	ui_notification_t notification_code = (ui_notification_t)ncode;
	if(notification_code == ui_populating_widget_popup) {
		TWidget * widget = va_arg(va, TWidget *);
		TPopupMenu *p = va_arg(va, TPopupMenu *);
		const action_activation_ctx_t* ctx = va_arg(va, const action_activation_ctx_t*);
		switch (get_widget_type(widget)) {
		case BWN_TILIST: // is redefined as BWN_STRUCTS for IDA_SDK_VERSION < 850
#if IDA_SDK_VERSION < 850
			add_structures_popup_items(widget, p);
#endif // IDA_SDK_VERSION < 850
#if IDA_SDK_VERSION >= 840
			attach_action_to_popup(widget, p, ACT_NAME(import_unf_types));
#endif // IDA_SDK_VERSION >= 840
			attach_action_to_popup(widget, p, ACT_NAME(refactoring));
			break;
		case BWN_TICSR:
			attach_action_to_popup(widget, p, ACT_NAME(import_unf_types), "Export to header file", SETMENU_INS);
			break;
		case BWN_DISASM:
			attach_action_to_popup(widget, p, ACT_NAME(decrypt_data));
			attach_action_to_popup(widget, p, ACT_NAME(add_VT_struct));
			attach_action_to_popup(widget, p, ACT_NAME(refactoring));
			if (get_view_renderer_type(widget) == TCCRT_GRAPH) {
				attach_action_to_popup(widget, p, ACT_NAME(create_inline_gr), "Group nodes", SETMENU_APP);
			} else {
				attach_action_to_popup(widget, p, ACT_NAME(create_inline_sel));
			}
			func_t* func = get_func(ctx->cur_ea);
			if (func) {
				if (func->start_ea != ctx->cur_ea && is_code(get_flags(ctx->cur_ea))) {
					gco_info_t gco;
					if (get_current_operand(&gco))
						attach_action_to_popup(widget, p, ACT_NAME(insert_varval));
				}
				if(has_varvals(func->start_ea))
					attach_action_to_popup(widget, p, ACT_NAME(clear_varvals));
			}
			break;
		}
	} else if( notification_code == ui_ready_to_run) {
		Log(llDebug, "ui_ready_to_run\n");
		StartWdg = get_current_widget();
#if IDA_SDK_VERSION < 850 //FIXME: find exact IDA version number where switch to timer
		execute_ui_requests(new FuncSwitchSync_t(), NULL);
#else
		register_timer(1000, cbRunFuncSwitchSync, NULL);
#endif
	}
	return 0;
}

static ea_t      funcRenameEa = BADADDR;
static flags64_t funcRenameFlg;
static qstring   funcRename;

// Callback for IDP notifications
MY_DECLARE_LISTENER(idp_callback)
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
			 flags64_t f = get_flags(ea);
			if(is_func(f)) {
				get_ea_name(&funcRename, ea);
				//stripName(&funcRename, true);
				if(!funcRename.empty()) {
					funcRenameEa = ea;
					funcRenameFlg = f;
				}
			}
		}
	}
	return 0;
}

static void progress(const char *new_name)
{
	size_t funcqty = get_func_qty();
	if(!funcqty)
		return;

	uint32 total = 0;
	uint32 done = 0;
	for (size_t i = 0; i < funcqty; i++) {
		func_t* func = getn_func(i);
		if(!func || (func->flags & FUNC_LIB))
			continue;
		total++;
		if(has_user_name(get_flags(func->start_ea)))
			done++;
	}
	if(!total)
		return;
	Log(llNotice, "--------------- progress: %.2f%% (done %d of %d, left %d) on '%s' ---------------\n", done * 100.0 / total, done, total, total - done, new_name);

	//if(done == total) TODO congratulation firework
}

#if IDA_SDK_VERSION < 850
void findStrucMembersByName(const char* memberName, tidvec_t* tids)
{
	for(uval_t idx = get_first_struc_idx(); idx != BADNODE; idx = get_next_struc_idx(idx)) {
		tid_t id = get_struc_by_idx(idx);
		struc_t * struc = get_struc(id);
		if(!struc || is_union(id))
			continue;
		for (uint32 i = 0; i < struc->memqty; i++) {
			qstring membName;
			get_member_name(&membName, struc->members[i].id);
			const char* mn = membName.c_str();
			if(*mn == 0)
				continue; // skip members w/o name
			if(!namecmp(mn, memberName))
				tids->push_back(struc->members[i].id);
		}
	}
}
#else //IDA_SDK_VERSION >= 850
void findStrucMembersByName(const char* memberName, tidvec_t* tids)
{
	uint32 limit = get_ordinal_limit();
	if (limit == uint32(-1))
		return;
	for (uint32 ord = 1; ord < limit; ++ord) {
		tinfo_t t;
		if (t.get_numbered_type(ord, BTF_STRUCT, true) && t.is_struct()) {
			udt_type_data_t udt;
			if (t.get_udt_details(&udt)) {
				for (size_t i = 0; i < udt.size(); ++i) {
					udm_t& member = udt.at(i);
					const char* mn = member.name.c_str();
					if(*mn == 0)
						continue; // skip members w/o name
					if(!namecmp(mn, memberName)) {
						tid_t tid = t.get_udm_tid(i);
						if(tid != BADADDR)
							tids->push_back(tid);
					}
				}
			}
		}
	}
}
#endif //IDA_SDK_VERSION < 850

// Callback for IDB notifications
MY_DECLARE_LISTENER(idb_callback)
{
	static bool bLitTypesOverridden = false;

	idb_event::event_code_t code = (idb_event::event_code_t)ncode;
	switch (code) {
#if IDA_SDK_VERSION < 850
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
			if(sptr->is_frame())
				break;

			//rename VT method impl together with VT member
			if(qstrlen(newname) &&
				 strncmp(newname, "sub_", 4) &&
				 strncmp(newname, "field_", 6)) {
				ea_t dstEA = get_memb2proc_ref(sptr, mptr);
				//avoid recursive renaming
				if(dstEA != BADADDR && dstEA != funcRenameEa && !set_name(dstEA, newname, SN_FORCE))
					Log(llWarning, "%a: rename to '%s' failed\n", dstEA, newname);
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
					Log(llDebug, "set_member_tinfo of '%s.%s' err %d\n", strucname.c_str(), membName.c_str(), code);
					if(ASKBTN_YES == ask_yn(ASKBTN_NO, "[hrt] Set member type of '%s.%s' may destroy other members,\nConfirm?", strucname.c_str(), membName.c_str())) {
						code = set_member_tinfo(strct, memb, 0, t, SET_MEMTI_MAY_DESTROY | SET_MEMTI_USERTI);
						Log(llDebug, "set_member_tinfo of '%s.%s' err %d\n", strucname.c_str(), membName.c_str(), code);
					}
				}
				if(code != SMT_OK)
					Log(llWarning, "set type \"%s\"  on rename of '%s.%s' error %d\n", t.dstr(), strucname.c_str(), membName.c_str(), code);
				else
					Log(llInfo, "type of '%s.%s' updated\n", strucname.c_str(), membName.c_str());
			}
			//}
		  break;
		}
#else //IDA_SDK_VERSION >= 850
	//case idb_event::lt_udm_changed:
	case idb_event::lt_udm_renamed:
	{
		const char* udtname = va_arg(va, const char*);
		const udm_t* udm    = va_arg(va, const udm_t*);
		//const char* oldname = va_arg(va, const char*);
		if (udm->is_special_member())
			break;

		const char* newname = udm->name.c_str();
		if (udm->name.empty() || !strncmp(newname, "sub_", 4) || !strncmp(newname, "field_", 6))
			break;

		tinfo_t struc;
		if (!struc.get_named_type(udtname))
			break;

		//rename VT method impl together with VT member
		ea_t dstEA = get_memb2proc_ref(struc, (uint32)(udm->offset / 8));
		if (dstEA != BADADDR && dstEA != funcRenameEa) {//avoid recursive renaming
			if(set_name(dstEA, newname, SN_FORCE))
				Log(llInfo, "%a renamed to '%s'\n", dstEA, newname);
			else
				Log(llWarning, "%a: rename to '%s' failed\n", dstEA, newname);
		}

		// set type for new name if new member name is same as lib function or structure
		tinfo_t t = getType4Name(newname);
		if (!t.empty()) {
			//int index = struc.find_udm(udm->offset); //returns wrong index for union
			int index = struc.find_udm(udm->name.c_str());
			if (index  != -1) {
				tinfo_code_t code = struc.set_udm_type(index, t, ETF_COMPATIBLE);
				if (code != TERR_OK && (!auto_is_ok() || ASKBTN_YES == ask_yn(ASKBTN_NO, "[hrt] Set member type '%s'\nof '%s.%s'\nmay destroy other members. Confirm?", t.dstr(), udtname, newname)))
					code = struc.set_udm_type(index, t, ETF_MAY_DESTROY);
				if (code != TERR_OK)
					Log(llWarning, "set type \"%s\" on rename of '%s.%s' error %d %s\n", t.dstr(), udtname, newname, code, tinfo_errstr(code));
				else Log(llInfo, "type of '%s.%s' updated\n", udtname, newname);
			}
		}
		break;
	}
#endif //IDA_SDK_VERSION < 850
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
		msig_auto_save();
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
			if(local_name || new_name == nullptr)
				break;
#if IDA_SDK_VERSION >= 760
			const char *old_name = va_arg(va, const char *); // appeared in ida 7.6
			if(old_name && !qstrcmp(old_name, new_name)) {
				Log(llDebug, "%a: dup rename '%s'\n", ea, new_name);
				break;
			}
#endif
			flags64_t ea_fl = get_flags(ea);
			tinfo_t oldType;
			if(!is_userti(ea) || // if there is no type info by user, or
				 (is_ea(ea_fl) && get_tinfo(&oldType, ea) && oldType.is_func())) // func-type instead pointer-to-func (TODO: it was very old IDA bug, probably already fixed. Check it!)
			{
				tinfo_t t = getType4Name(new_name, is_func(ea_fl));
				if(!t.empty()) {
					if(apply_tinfo(ea, t, TINFO_DEFINITE | TINFO_DELAYFUNC | TINFO_STRICT)) //set_tinfo(ea, &t) left unnecessary arguments in func type, even "t" has not such
						Log(llInfo, "%a: set glbl '%s' type '%s'\n", ea, new_name, t.dstr());
					else
						Log(llWarning, "%a: fail set glbl '%s' type '%s'\n", ea, new_name, t.dstr());
				}
			}

#if 0 // disabled because it works now much faster
			// user invoked applying FLIRT signatures, loading pdb files are also autoanalysis
			// suddenly wait_box too?!!
			if (!auto_is_ok()) // disable time-consuming operations during initial autoanalysis
				break;
#endif

			if(is_func(ea_fl)) {
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
						qstring retTname(new_name, ctor - new_name);
						fi.rettype = make_pointer(create_typedef(retTname.c_str()));
						tinfo_t newFType;
						if(newFType.create_func(fi) && apply_tinfo(ea, newFType, haveType))
							Log(llInfo, "%a: '%s' ret type changed to \"%s*\"\n", ea, new_name, retTname.c_str());
						else
							Log(llWarning, "%a: '%s' fail ret type change to \"%s*\"\n", ea, new_name, retTname.c_str());
					}
				}

				if(funcRenameEa == ea && !funcRename.empty()) {
					if(!has_user_name(funcRenameFlg) && auto_is_ok())
						progress(new_name);

					//rename VT members and callbacks too
					tidvec_t tids;
#if 0			// enable the next line to compatibility with old IDBs without proc2memb_refs
					findStrucMembersByName(funcRename.c_str(), &tids);
#endif
					get_proc2memb_refs(ea, &tids);
					if(tids.size() > 0) {
						if(tids.size() == 1 || !auto_is_ok() || ASKBTN_YES == ask_yn(ASKBTN_NO, "[hrt] Rename %d struc members?\n%s\nto\n%s", tids.size(), funcRename.c_str(), new_name)) {
							for (size_t i = 0; i < tids.size(); i++) {
								qstring fullname;
								//FIXME: ??? do double check with namecmp(funcRename.c_str(), memb->name)
#if IDA_SDK_VERSION < 850
								struc_t *struc;
								member_t * memb = get_member_by_id(&fullname, tids[i], &struc);
								if(memb) {
									qstring nn = good_smember_name(struc, memb->soff, new_name);
									if(!set_member_name(struc, memb->soff, nn.c_str()))
										Log(llWarning, "struc member '%s' rename to '%s' error\n", fullname.c_str(), nn.c_str());
									else
										Log(llInfo, "struc member '%s' renamed to '%s'\n", fullname.c_str(), nn.c_str());
								}
#else //IDA_SDK_VERSION >= 850
								udm_t udm;
								tinfo_t struc;
								ssize_t idx = struc.get_udm_by_tid(&udm, tids[i]);
								if(idx < 0) {
									Log(llDebug, "get_proc2memb_refs returns bad memb tid %a\n", tids[i]);
								} else {
									struc.get_type_name(&fullname); // get_numbered_type_name
									fullname.append('.');
									fullname.append(udm.name);
									qstring nn = good_udm_name(struc, udm.offset, new_name);
									if(struc.rename_udm(idx, nn.c_str()) != TERR_OK)
										Log(llWarning, "fail rename struc member '%s' to '%s'\n", fullname.c_str(), nn.c_str());
									else
										Log(llInfo, "struc member '%s' renamed to '%s'\n", fullname.c_str(), nn.c_str());
								}
#endif //IDA_SDK_VERSION < 850
							}
						}
						Log(llDebug, "%a %s renaming %d members\n", funcRenameEa, funcRename.c_str(), tids.size());
					}
					funcRenameEa = BADADDR; //avoid recursive renaming
				}
			}
			break;
		}
#if 0 // for debugging recursive decompile mode to find repeating type changes.
	case idb_event::changing_ti:
	  {
			ea_t ea = va_arg(va, ea_t);
			const type_t *new_type = va_arg(va, type_t *);
			if(!new_type)
				break;
			const p_list *new_fnames = va_arg(va, p_list *);

			tinfo_t oldTi;
			tinfo_t newTi;
			if(!get_tinfo(&oldTi, ea) || !newTi.deserialize(nullptr, &new_type, &new_fnames) || !oldTi.compare_with(newTi, TCMP_IGNMODS)) {
				Log(llDebug, "%a: changing_ti+", ea);
			} else {
				Log(llDebug, "%a: changing_ti-", ea);
			}
			qstring name = get_short_name(ea);
			Log(llDebug, " %s: from '%s' to '%s'\n", name.c_str(), oldTi.dstr(), newTi.dstr());
			break;
	  }
#endif
  case idb_event::ti_changed:
		{
			ea_t ea = va_arg(va, ea_t);
			const type_t *type = va_arg(va, type_t *);
			const p_list *fnames = va_arg(va, p_list *);
			++g_typeChanged;

			flags64_t ea_fl = get_flags(ea);
			tinfo_t tif;
			if(type && is_func(ea_fl) && is_type_func(*type) && tif.deserialize(NULL, &type, &fnames) && tif.is_func()) {
				qstring funcName = get_name(ea);
				//stripName(&funcName, true);
				//set type for VT members too
				tidvec_t tids;
#if 0		// enable the next line to compatibility with old IDBs without proc2memb_refs
				findStrucMembersByName(funcRename.c_str(), &tids);
#endif
				get_proc2memb_refs(ea, &tids);
				if(!tids.size())
					break;
				tif = make_pointer(tif);
				qstring newType; tif.print(&newType);
				if(tids.size() > 1 && auto_is_ok() && ASKBTN_YES != ask_yn(ASKBTN_NO, "[hrt] Recast %d struc members\n%s\nto\n%s\n?", tids.size(), funcName.c_str(), newType.c_str()))
					break;
				for (size_t i = 0; i < tids.size(); i++) {
					qstring fullname;
#if IDA_SDK_VERSION < 850
					struc_t *struc;
					member_t * memb = get_member_by_id(&fullname, tids[i], &struc);
					if(memb && SMT_OK == set_member_tinfo(struc, memb, 0, tif, SET_MEMTI_COMPATIBLE))
						Log(llInfo, "struc member '%s' recasted to '%s'\n", fullname.c_str(), newType.c_str());
					else
						Log(llWarning, "struc member '%s' recast to '%s' error\n", fullname.c_str(), newType.c_str());
#else //IDA_SDK_VERSION >= 850
					udm_t udm;
					tinfo_t struc;
					ssize_t idx = struc.get_udm_by_tid(&udm, tids[i]);
					if(idx < 0) {
						Log(llDebug, "get_proc2memb_refs returns bad memb tid %a\n", tids[i]);
					} else {
						struc.get_type_name(&fullname); // get_numbered_type_name
						fullname.append('.');
						fullname.append(udm.name);
						if(struc.set_udm_type(idx, tif) == TERR_OK)
							Log(llInfo, "struc member '%s' recasted to '%s'\n", fullname.c_str(), newType.c_str());
						else
							Log(llWarning, "struc member '%s' recast to '%s' error\n", fullname.c_str(), newType.c_str());
					}
#endif //IDA_SDK_VERSION < 850
				}
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
							Log(llInfo, "%a: fix call stack pointer delta at from %d to %d\n", cmd.ea, delta, purged);
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

MY_DECLARE_LISTENER(dbg_callback)
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
	qstring motd;
	addon_info_t addon;
	addon.id = "hrtng";
	addon.name = "bes's tools collection";
	addon.producer = "Sergey Belov and Hex-Rays SA, Milan Bohacek, J.C. Roberts, Alexander Pick, Rolf Rolles, Takahiro Haruyama," \
									 " Karthik Selvaraj, Ali Rahbar, Ali Pezeshk, Elias Bachaalany, Markus Gaasedelen";
	addon.url = "https://github.com/KasperskyLab/hrtng";
	addon.version = "3.7.73";
	msg("[hrt] %s (%s) v%s for IDA%d\n", addon.id, addon.name, addon.version, IDA_SDK_VERSION);

	if(inited) {
		Log(llWarning, "already inited\n");
		return PLUGIN_KEEP;
	}

	if (!init_hexrays_plugin()) {
		msg("[hrt] %s does not work without decompiler, sorry\n", addon.id);
		return PLUGIN_SKIP;
	}
	configLoad();

	install_hexrays_callback(callback, NULL);
	HOOK_CB(HT_UI,  ui_callback);
	HOOK_CB(HT_IDB, idb_callback);
	HOOK_CB(HT_DBG, dbg_callback);
	HOOK_CB(HT_IDP, idp_callback);

	appcall_view_reg_act();
	reincast_reg_act();
	hrt_reg_act();
	register_idc_functions();
	varval_reg_act();
	registerCtreeGraph();
	init_invert_if();
#if IDA_SDK_VERSION <= 730
	ncast_reg_act();
#endif //IDA_SDK_VERSION <= 730
#if IDA_SDK_VERSION < 850
	structs_reg_act();
#endif //IDA_SDK_VERSION < 850
	registerMicrocodeExplorer();
	register_new_struc_place();
	new_struct_view_reg_act();
	lit_init();
	deinline_init();
	opt_init();
	msig_reg_act();
	msig_auto_load();

	if(register_addon(&addon) < 0)
		Log(llError, "error on register_addon()\n");
	inited = true;
	return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
	if ( inited )
	{
		unregisterMicrocodeExplorer();
#if IDA_SDK_VERSION < 850
		structs_unreg_act();
#endif //IDA_SDK_VERSION < 850
#if IDA_SDK_VERSION <= 730
		ncast_unreg_act();
#endif //IDA_SDK_VERSION <= 730
		new_struct_view_unreg_act();
		varval_unreg_act();
		unregisterCtreeGraph();
		msig_unreg_act();
		appcall_view_unreg_act();
		reincast_unreg_act();
		hrt_unreg_act();

		remove_hexrays_callback(callback, NULL);
		UNHOOK_CB(HT_IDP, idp_callback);
		UNHOOK_CB(HT_DBG, dbg_callback);
		UNHOOK_CB(HT_IDB, idb_callback);
		UNHOOK_CB(HT_UI,  ui_callback);

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
	configDlg();
	return true;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,                    // plugin flags
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	"\n[hrt] Useful tools for IDA and Hex-Rays decompiler",  // long comment about the plugin it could appear in the status line or as a hint
	"",                   // multiline help about the plugin
	"[hrt] hrtng options",// the preferred short name of the plugin
	""                    // the preferred hotkey to run the plugin
};

#ifdef _DEBUG
//--------------------------------------------------------------------------
// ida-sdk\src\plugins\vds18\hexrays_sample18.cpp
//--------------------------------------------------------------------------
// Code for making debugging easy
// Ensure that the debug helper functions are linked in.
// With them it is possible to print microinstructions like this:
//      insn->dstr()
//      operand->dstr()
// in your favorite debugger. Having these functions greatly
// simplifies debugging.

//lint -e{413} Likely use of null pointer
void refs_for_linker(void)
{
#define CALL_DSTR(type) ((type*)0)->dstr()
	CALL_DSTR(bitset_t);
	CALL_DSTR(rlist_t);
	CALL_DSTR(ivl_t);
	CALL_DSTR(ivlset_t);
	CALL_DSTR(mlist_t);
	CALL_DSTR(valrng_t);
	CALL_DSTR(chain_t);
	CALL_DSTR(block_chains_t);
	CALL_DSTR(tinfo_t);
	CALL_DSTR(mcases_t);
	CALL_DSTR(lvar_t);
	CALL_DSTR(mop_t);
	CALL_DSTR(minsn_t);
	CALL_DSTR(mcallarg_t);
	CALL_DSTR(vdloc_t);

	CALL_DSTR(lvar_locator_t);
	CALL_DSTR(fnumber_t);
	CALL_DSTR(mcallinfo_t);
	CALL_DSTR(vivl_t);
	CALL_DSTR(cexpr_t);
	CALL_DSTR(cinsn_t);
	CALL_DSTR(ctree_item_t);
	dstr((tinfo_t*)0);
	((mbl_array_t*)0)->dump();
	((mblock_t*)0)->dump();
#undef CALL_DSTR
}
#endif // _DEBUG
//--------------------------------------------------------------------------
