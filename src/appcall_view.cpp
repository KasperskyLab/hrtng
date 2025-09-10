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

/*
  This feature is inspired by ideas of Krypton plugin by Karthik Selvaraj(https://www.hex-rays.com/contests/2012/Krypton_2012_Hex-Rays_Contest.zip)
  that uses IDA's powerful Appcall feature(https://hex-rays.com/wp-content/uploads/2019/12/debugging_appcall.pdf) - call functions inside the debugged program
  The main problem of Krypton - it can't deal with mixed registers/stack arguments because tries to analyze low level assembler code.
  This implementation takes everything from Hex-Rays generated pseudocode.
 */

#include "warn_off.h"
#include <ida.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include "warn_on.h"

#include "appcall_view.h"
#include "appcall.h"
#include "helpers.h"

struct ida_local appcall_view_info_t
{
	TWidget *cv;
	strvec_t sv;
	appcall_view_info_t() : cv(NULL) {}
};
appcall_view_info_t *acv = NULL;

//-------------------------------------------------------------------------
ACT_DECL(show_appcall_view, return (appcaller.funcea == BADADDR ? AST_DISABLE : AST_ENABLE))

#define AST_ENABLE_FOR_ME return ((acv && ctx->widget == acv->cv) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET)
ACT_DECL(jump_disasm, AST_ENABLE_FOR_ME)
ACT_DECL(jump_pseudocode, AST_ENABLE_FOR_ME)
ACT_DECL(jump_patch, AST_ENABLE_FOR_ME)
ACT_DECL(write_cmt, AST_ENABLE_FOR_ME)
ACT_DECL(write_ptch, AST_ENABLE_FOR_ME)
ACT_DECL(write_2fil, AST_ENABLE_FOR_ME)
ACT_DECL(reExecAppcall, return ((acv && ctx->widget == acv->cv && appcaller.bDbgEngine) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
#undef AST_ENABLE_FOR_ME

static const action_desc_t actions[] =
{
	ACT_DESC("[hrt] jump to disasm", "D", jump_disasm),
	ACT_DESC("[hrt] jump to pseudocode", "Enter", jump_pseudocode),
	ACT_DESC("[hrt] jump to patch location", "J", jump_patch),
	ACT_DESC("[hrt] write comments", "C", write_cmt),
	ACT_DESC("[hrt] write patches", "P", write_ptch),
	ACT_DESC("[hrt] write to file", NULL, write_2fil),
	ACT_DESC("[hrt] re-execute appcall with another proc...", NULL, reExecAppcall)
};

void appcall_view_reg_act()
{
	COMPAT_register_and_attach_to_menu("View/Open subviews/Function calls", ACT_NAME(show_appcall_view), "[hrt] Last mass-decr results", NULL, SETMENU_APP, &show_appcall_view, &PLUGIN);
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		register_action(actions[i]);
}

void appcall_view_unreg_act()
{
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		unregister_action(actions[i].name);
	detach_action_from_menu("View/Open subviews/[hrt] Last mass-decr results", ACT_NAME(show_appcall_view));
	unregister_action(ACT_NAME(show_appcall_view));
}
//-------------------------------------------------------------------------

static int get_idx(TWidget* wi)
{
	simpleline_place_t *place = (simpleline_place_t *)get_custom_viewer_place(wi, false, NULL, NULL);
	if (place && place->n < appcaller.calls.size())
		return place->n;
	return -1;
}

ACT_DEF(jump_disasm)
{
	int idx = get_idx(ctx->widget);
	if(idx < 0) 
		return 0;
	jumpto(appcaller.calls[idx].ea, -1, UIJMP_ACTIVATE | UIJMP_IDAVIEW);
	return 1;
}

ACT_DEF(jump_pseudocode)
{
	int idx = get_idx(ctx->widget);
	if(idx < 0) 
		return 0;
	COMPAT_open_pseudocode_REUSE(appcaller.calls[idx].ea);
	return 1;
}

static bool idaapi write_comments(size_t start, size_t end)
{
	for(size_t i = start; i < appcaller.calls.size() && i < end; i++) {
		if(!appcaller.calls[i].decrResult.empty()) {
			if(appcaller.multilineCmt) {
				append_cmt(appcaller.calls[i].ea, appcaller.calls[i].decrResult.c_str(), true);
			} else {
				set_cmt(appcaller.calls[i].ea, appcaller.calls[i].decrResult.c_str(), true);
			}
		}
	}
	return true;
}

static bool idaapi write_patches(size_t start, size_t end)
{
	for(size_t i = start; i < appcaller.calls.size() && i < end; i++) {
		if(!appcaller.calls[i].decrResult.empty() && appcaller.calls[i].patchea != BADADDR) {
			if(appcaller.strtype == STRTYPE_C_16) {
				patch_wstr(appcaller.calls[i].patchea, appcaller.calls[i].decrResult.c_str(), -1);
			} else {
				patch_str(appcaller.calls[i].patchea, appcaller.calls[i].decrResult.c_str(), -1);
			}
		}
	}
	return true;
}

static bool idaapi write_2file(size_t start, size_t end)
{
	qstring filename = get_path(PATH_TYPE_IDB);
	size_t pos = filename.rfind('.');
	if(pos != qstring::npos && pos != 0)
		filename = filename.substr(0, pos);
	filename.append(".txt");

	FILE * file = fopenA(filename.c_str());
	if(!file) {
		Log(llError, "failed open '%s'\n", filename.c_str());
		return false;
	}

	int cnt = 0;
	for(size_t i = start; i < appcaller.calls.size() && i < end; i++) {
		if(!appcaller.calls[i].decrResult.empty()) {
			qstring line;
			line.sprnt("%a %a %s\n", appcaller.calls[i].patchea, appcaller.calls[i].ea, appcaller.calls[i].decrResult.c_str());
			qfputs(line.c_str(), file);
			++cnt;
		}
	}
	qfclose(file);
	Log(llNotice, "%d decrypted strings are appended to '%s'\n", cnt, filename.c_str());
	return true;
}

static bool idaapi reExec(size_t start, size_t end)
{
	qvector<reappcall_t> reacs;
	for(size_t i = start; i < appcaller.calls.size() && i < end; i++) {
		if(appcaller.calls[i].patchea != BADADDR) {
			reacs.push_back(appcaller.calls[i]);
		}
	}
	if(!reacs.size())
		return false;
	re_do_appcall(reacs);
	return true;
}


enum appcall_write_type {
	ePatch,
	eComment,
	eFile,
	eReExec
};

static bool idaapi write_cmt_or_ptch(TWidget *wi, appcall_write_type wt)
{
	size_t start = 0;
	size_t end  = appcaller.calls.size();
	twinpos_t s,e;
	if (read_selection(wi, &s, &e)) {
		simpleline_place_t* ps = (simpleline_place_t *)s.at;
		simpleline_place_t* pe = (simpleline_place_t *)e.at;
		start = ps->n;
		end = pe->n;
		if(e.x != 0)
			end++;
		Log(llDebug, "selected(%u, %u)\n", (uint32_t)start, (uint32_t)end);
	} //else no selection

	switch (wt) {
	case ePatch:
		return write_patches(start, end);
	case eComment:
		return write_comments(start, end);
	case eFile:
		return write_2file(start, end);
	case eReExec:
		return reExec(start, end);
	}
	return false;
}

ACT_DEF(write_cmt)
{
	return write_cmt_or_ptch(ctx->widget, eComment);
}

ACT_DEF(write_ptch)
{
	return write_cmt_or_ptch(ctx->widget, ePatch);
}

ACT_DEF(write_2fil)
{
	return write_cmt_or_ptch(ctx->widget, eFile);
}

ACT_DEF(reExecAppcall)
{
	return write_cmt_or_ptch(ctx->widget, eReExec);
}

ACT_DEF(jump_patch)
{
	int idx = get_idx(ctx->widget);
	if(idx < 0) 
		return 0;
	jumpto(appcaller.calls[idx].patchea, -1, UIJMP_ACTIVATE | UIJMP_IDAVIEW);
	return 1;
}

//------------------------------------------------------------
static bool idaapi ct_dblclick(TWidget *cv, int shift, void *ud)
{
	int idx = get_idx(cv);
	if (idx < 0)
		return false;
	COMPAT_open_pseudocode_REUSE(appcaller.calls[idx].ea);
	return true;
}

static bool idaapi ct_keyboard(TWidget * /*v*/, int key, int shift, void *ud)
{
  if(shift == 0) {
    appcall_view_info_t *si = (appcall_view_info_t *)ud;
    switch ( key )
    {
		case IK_ESCAPE:
			close_widget(si->cv, WCLS_SAVE | WCLS_CLOSE_LATER);
			return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
MY_DECLARE_LISTENER(appcall_ui_callback)
{
	if(!acv)
		return 0;

	switch(ncode) {
	case ui_get_custom_viewer_hint:
	{
		qstring &hint = *va_arg(va, qstring *);
		TWidget *viewer = va_arg(va, TWidget *);
		place_t *place         = va_arg(va, place_t *);
		int *important_lines   = va_arg(va, int *);
		if(acv->cv == viewer) {
			if(!place)
				return 0;
			simpleline_place_t *spl = (simpleline_place_t *)place;
			if(spl->n < appcaller.calls.size()) {
				hint = appcaller.calls[spl->n].callStr;
				ea_t patchea = appcaller.calls[spl->n].patchea;
				if(patchea != BADADDR) {
					if(!hint.empty())
						hint.append('\n');
					hint.cat_sprnt("patch addr %a ", patchea);
					text_t disasm;
					gen_disasm_text(disasm, patchea, get_item_end(patchea) + 64, false);
					if(disasm.size()) {
						for(size_t i = 0; i < disasm.size(); i++) {
							hint.append('\n');
							hint += disasm[i].line;
						}
						if(disasm.size() > 3)
							*important_lines = 5;
						else
							*important_lines = (int)disasm.size() + 2;
					} else {
						hint += get_short_name(patchea);
						*important_lines = 2;
					}
				} else {
					*important_lines = 1;
				}
			} else {
				*important_lines = 0;
			}
			return 1;
		}
		break;
	}
	case ui_widget_invisible:
	{
		TWidget *f = va_arg(va, TWidget *);
		if(f == acv->cv) {
			delete acv;
			acv = NULL;
			UNHOOK_CB(HT_UI, appcall_ui_callback);
		}
		break;
	}
	case ui_populating_widget_popup:
	{
		TWidget *f = va_arg(va, TWidget *);
		if(f == acv->cv && appcaller.calls.size()) {
			for (size_t i = 0, n = qnumber(actions); i < n; ++i)
				attach_action_to_popup(f, NULL, actions[i].name);
		}
		break;
	}
	}
	return 0;
}

//-------------------------------------------------------------------------
static const custom_viewer_handlers_t handlers(
        ct_keyboard,
        NULL,
        NULL, // mouse_moved
        NULL, // click
        ct_dblclick,
        NULL, // ct_curpos,
        NULL, // close
        NULL, // help
        NULL);// adjust_place

ACT_DEF(show_appcall_view)
{
	if(appcaller.funcea == BADADDR) {
		Log(llNotice, "not yet appcall results\n");
		return 0;
	}

	qstring caption = "Mass strings decryption results for ";
	caption.cat_sprnt("0x%a %s", appcaller.funcea, get_short_name(appcaller.funcea).c_str());

	TWidget *widget = find_widget(caption.c_str());
  if (widget) {
		activate_widget(widget, true);
    return 1;
  }

  acv = new appcall_view_info_t();

	for(size_t i = 0; i < appcaller.calls.size(); i++) {
		qstring line;
		qstring sanitized;
		tag_remove(&sanitized, appcaller.calls[i].decrResult);
		line.cat_sprnt(COLSTR("%a",SCOLOR_NUMBER) "  " COLSTR("%s",SCOLOR_STRING), appcaller.calls[i].ea, sanitized.c_str());
		if(!appcaller.calls[i].error.empty())
			line.cat_sprnt(COLSTR(" error: %s",SCOLOR_ERROR), appcaller.calls[i].error.c_str());
		acv->sv.push_back(simpleline_t(line));
	}

  simpleline_place_t s1;
  simpleline_place_t s2((int)acv->sv.size() - 1);
	acv->cv = create_custom_viewer(caption.c_str(), &s1, &s2, &s1, NULL, &acv->sv, &handlers, acv);
  HOOK_CB(HT_UI, appcall_ui_callback);

	display_widget(acv->cv, WOPN_DP_TAB, "IDA View-A");
	return 1;
}

bool open_appcall_view()
{
	return show_appcall_view.activate(NULL) != 0;
}

bool close_appcall_view()
{
	if(appcaller.funcea == BADADDR)
		return false;

	qstring caption = "Mass strings decryption results for ";
	caption.cat_sprnt("0x%a %s", appcaller.funcea, get_short_name(appcaller.funcea).c_str());

	TWidget *widget = find_widget(caption.c_str());
	if (widget) {
		close_widget(widget, WCLS_SAVE);
		return true;
	}
	return false;
}

