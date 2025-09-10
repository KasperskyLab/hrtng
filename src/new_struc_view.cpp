//Evolution of new_struc_view.cpp from https://github.com/nihilus/hexrays_tools

/* Custom viewer sample plugin.
* Copyright (c) 2007 by Ilfak Guilfanov, ig@hexblog.com
* Feel free to do whatever you want with this code.
*
* This sample plugin demonstates how to create and manipulate a simple
* custom viewer in IDA Pro v5.1
*
* Custom viewers allow you to create a view which displays colored lines.
* These colored lines are dynamically created by callback functions.
*
* Custom viewers are used in IDA Pro itself to display
* the disassembly listng, structure, and enumeration windows.
*
* This sample plugin just displays several sample lines on the screen.
* It displays a hint with the current line number.
* The right-click menu contains one sample command.
* It reacts to one hotkey.
*
* This plugin uses the simpleline_place_t class for the locations.
* Custom viewers can use any decendant of the place_t class.
* The place_t is responsible for supplying data to the viewer.
*/

//---------------------------------------------------------------------------
#include "warn_off.h"
#include <hexrays.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "new_struct.h"
#include "new_struc_place.h"
#include "new_struc_view.h"

TWidget *stBld = NULL;
//-------------------------------------------------------------------------
#define AST_ENABLE_FOR_ME return ((ctx->widget == stBld) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET)
ACT_DECL(remove_one, AST_ENABLE_FOR_ME)
ACT_DECL(insert_one, AST_ENABLE_FOR_ME)
ACT_DECL(jump_to_next_function_cb, AST_ENABLE_FOR_ME)
ACT_DECL(show_function_list_cb, AST_ENABLE_FOR_ME)
ACT_DECL(make_array_cb, AST_ENABLE_FOR_ME)
ACT_DECL(change_item_type_cb, AST_ENABLE_FOR_ME)
ACT_DECL(pack_cb, AST_ENABLE_FOR_ME)
ACT_DECL(clear_var_scan, AST_ENABLE_FOR_ME)
#undef AST_ENABLE_FOR_ME

//FIXME: shortcuts
ACT_DESC1("[hrt] remove member", "Del" , remove_one)
ACT_DESC1("[hrt] insert member", "Ins" , insert_one)
ACT_DESC1("[hrt] show pseudocode of next function", "G" , jump_to_next_function_cb)
ACT_DESC1("[hrt] show functions list", "X" , show_function_list_cb)
ACT_DESC1("[hrt] make array", "R" , make_array_cb)
ACT_DESC1("[hrt] change item type", "Y" , change_item_type_cb)
ACT_DESC1("[hrt] build substructures", "P" , pack_cb)
ACT_DESC1("[hrt] clear scan results", "", clear_var_scan)

void new_struct_view_reg_act()
{
	ACT_REG(remove_one);
	ACT_REG(insert_one);
	ACT_REG(jump_to_next_function_cb);
	ACT_REG(show_function_list_cb);
	ACT_REG(make_array_cb);
	ACT_REG(change_item_type_cb);
	ACT_REG(pack_cb);
	ACT_REG(clear_var_scan);
}

void new_struct_view_unreg_act()
{
	ACT_UNREG(remove_one);
	ACT_UNREG(insert_one);
	ACT_UNREG(jump_to_next_function_cb);
	ACT_UNREG(show_function_list_cb);
	ACT_UNREG(make_array_cb);
	ACT_UNREG(change_item_type_cb);
	ACT_UNREG(pack_cb);
	ACT_UNREG(clear_var_scan);
}

//---------------------------------------------------------------------------
ACT_DEF(remove_one)
{
	new_struc_place_t * place; 
	place = (new_struc_place_t *)get_custom_viewer_place(ctx->widget, false, NULL, NULL);
	if(!place || !fi.flip_enabled_status(place->idx, place->subtype))
		return 0;
	return 1;
}

ACT_DEF(insert_one)
{
	new_struc_place_t * place; 
	place = (new_struc_place_t *)get_custom_viewer_place(ctx->widget, false, NULL, NULL);
	if(!place)
		return 0;
	
	sval_t offset = fi.max_adjustments[fi.current_offset];
	auto b = fi.begin();
	if(fi.size() > place->idx) {
		if(safe_advance(b, fi.end(), place->idx))
			offset = b->first;
	}

	ea_t addr = offset;
	if(ask_addr(&addr, "[hrt] Enter offset of new field") == 0)
		return 0;
	offset = addr;

	scan_info_t &sif  = fi[fi.current_offset + offset];
	fi.update_max_offset(fi.current_offset, offset);
	typerecord_t tr;
	tr.type.create_simple_type(BT_INT8);
	sif.types.add_unique(tr);
	return 1;
}

static bool idaapi adjust_substruct(TWidget *vi, bool add, bool fine)
{
	new_struc_place_t * place; 
	place = (new_struc_place_t *)get_custom_viewer_place(vi, false, NULL, NULL);
	if(!place)
		return false;

	auto iter =  fi.begin();
	if (!safe_advance(iter, fi.end(), place->idx))
		return false;

	//cannot have negative nesting counter
	if (!add) {
		auto iter2 = iter;
		while(iter2!= fi.end()) {
			if(iter2->second.nesting_counter == 0)
				return false;
			if(fine)
				break;
			++iter2;
		}
	}

	while(iter != fi.end()) {
		if(add)
			++iter->second.nesting_counter;
		else
			--iter->second.nesting_counter;	
		if(fine)
			break;
		++iter;
	}
	refresh_custom_viewer(vi);
	return true;
}


static bool idaapi set_current_offset(TWidget *vi)
{
	new_struc_place_t * place; 
	place = (new_struc_place_t *)get_custom_viewer_place(vi, false, NULL, NULL);
	if(!place)
		return false;

	field_info_t::iterator iter =  fi.begin();
	if (!safe_advance(iter, fi.end(), place->idx))
		return false;

	fi.current_offset = iter->first;
	refresh_custom_viewer(vi);
	return true;
}

//---------------------------------------------------------------------------
// Keyboard callback
static bool idaapi ct_keyboard(TWidget * /*v*/, int key, int shift, void *ud)
{
	//if ( shift == 0 )
	{
		TWidget *vi = (TWidget *)ud;
		switch ( key )    
		{
		case IK_ADD:
		//case '+':
			return adjust_substruct(vi, true, shift != 0 );
			break;

		case IK_MULTIPLY:
			return set_current_offset(vi);
			break;

		case IK_SUBTRACT:  
		//case '-':
			return adjust_substruct(vi, false, shift != 0);
			break;

		case IK_ESCAPE:
			close_widget(vi, WCLS_SAVE | WCLS_CLOSE_LATER);
			return true;

/*
		case IK_DELETE:
				return remove_one(si);

		case IK_INSERT:
			return insert_one(si);

		case IK_RETURN:
			break;
*/
		}
	}
	return false;
}

//----------------------------------------------------------------------------------------------------
struct ida_local function_list_t : public chooser_t
{
	eavec_t functions;
	static const int widths[];
	static const char* const header[];

	function_list_t(const char* title) : chooser_t(CH_KEEP | CH_MODAL, 2, widths, header, title) {}
	virtual size_t idaapi get_count() const { return functions.size(); }
	virtual void idaapi get_row(qstrvec_t* cols, int* icon_, chooser_item_attrs_t* attrs, size_t n) const
	{
		qstrvec_t& cols_ = *cols;
		ea_t ea = functions[n];
		cols_[0].sprnt("%a", ea);
		cols_[1] = get_short_name(ea);

		func_t* f = get_func(ea);
		if (f)
			get_func_cmt(&cols_[2], f, true);
	}
};
const int function_list_t::widths[] = { CHCOL_HEX | 8, 32, 32 };
const char* const function_list_t::header[] = { "Address", "Function name", "Comment" };

//------------------------------------------------

ACT_DEF(show_function_list_cb)
{
	function_list_t fl("[hrt] Detected functions");
	for(auto i = fi.function_adjustments.begin(); i != fi.function_adjustments.end(); i++)
		fl.functions.add_unique(i->first);

	if(!fl.functions.size())
		return 0;

	ssize_t choosed = fl.choose();
	if (choosed >= 0)
		COMPAT_open_pseudocode_NEW(fl.functions[choosed]);
	return 0;
}

//----------------------------------------------------------------------------------------------------
struct ida_local glob_vars_locator_t : public ctree_visitor_t
{
	field_info_t * fields;
	cexpr_t * found_expr;
	bool is_our(ea_t idx)
	{
		return fields->global_pointers.find(idx) != fields->global_pointers.end();
	}
	int idaapi visit_expr(cexpr_t *e)
	{
		if(e->op == cot_obj && is_our(e->obj_ea)) {
			found_expr = e;
			return 1;
		}			
		return 0;
	}
	glob_vars_locator_t(field_info_t * fi) : ctree_visitor_t(0), fields(fi), found_expr(NULL)
	{
	}
};

ACT_DEF(jump_to_next_function_cb)
{
	ea_t fnc_ea = BADADDR;
	for(auto i = fi.function_adjustments.begin(); i != fi.function_adjustments.end(); i++) {
		ea_t ea = i->first;
		if (fi.visited_functions.find(ea) == fi.visited_functions.end()) {
			fnc_ea = ea;
			break;
		}
	}
	if((fnc_ea == BADADDR) || !is_mapped(fnc_ea))
		return 0;

	vdui_t * ui = COMPAT_open_pseudocode_NEW(fnc_ea);
	if(!ui)
		return 0;
	fi.visited_functions.insert(fnc_ea);

	auto argnum = fi.argument_numbers.find(fnc_ea);
	if(argnum != fi.argument_numbers.end()) {
		uval_t argcnt = -1;
		func_type_data_t fti;
		tinfo_t type;
		if(ui->cfunc->get_func_type(&type)) {
			if(type.get_func_details(&fti, GTD_NO_ARGLOCS)) {
				argcnt = (uval_t)fti.size();
				Log(llDebug, "%s\n", fti[(size_t)argnum->second.arg_num].name.c_str());
			}
		}
		if(argnum->second.arg_cnt == argcnt)
			Log(llDebug, "function @ %08a argument nr %d\n", argnum->first, argnum->second.arg_num);
		else
			Log(llDebug, "function @ %08a has different arguments count\n", argnum->first);
	}
	
	//jump to global variable
	if(fi.global_pointers.size() > 0) {
		glob_vars_locator_t locator(&fi);
		if(locator.apply_to((citem_t*)&ui->cfunc->body, NULL) == 1 && locator.found_expr) {
			qstring ptr;
			ptr.sprnt("%08X", locator.found_expr->ea);
			{
				const strvec_t& strvec = ui->cfunc->get_pseudocode();
				for (unsigned int i = 0; i < strvec.size(); i++) {
					size_t position;
					const simpleline_t & SV = strvec[i];
					if ((position = SV.line.find(ptr, 0)) != SV.line.npos) {
						char buff[MAXSTR];
						memset(buff, 0, sizeof(buff));
						//-1 because of COLOR_ADDR tag, we want to skip
						qstrncpy(buff, SV.line.c_str(), position - 1);
						jump_custom_viewer(ui->ct, i, (int)tag_strlen(buff), 0);
					}
				}
			}
			
		}
	}
	
	return 1;
}

//---------------------------------------------------------------------------
ACT_DEF(change_item_type_cb)
{
	new_struc_place_t * place; 
	place = (new_struc_place_t *)get_custom_viewer_place(ctx->widget, false, NULL, NULL);
	if(!place)
		return 0;

	if(fi.size() <= place->idx)
		return 0;

	auto b = fi.begin();
	if(!safe_advance(b, fi.end(), place->idx))
		return 0;
	
	typevec_t& types = b->second.types;
	if(!types.size())
		return 0;
	
	auto iter1 = types.begin();
	if(!safe_advance(iter1, types.end(), place->subtype))
		return 0;

	tinfo_t type = iter1->type;
	qstring declaration;
	type.print(&declaration);
	declaration.append(" field;");
	while(ask_str(&declaration, HIST_TYPE, "[hrt] Enter type")) {
		if(declaration.last() != ';')
			declaration.append(';');
		if(parse_decl(&type, NULL, NULL, declaration.c_str(), PT_VAR)) {
			iter1->type = type;
			return 1;			
		}
	}
	return 0;
}

//---------------------------------------------------------------------------
ACT_DEF(make_array_cb)
{
	new_struc_place_t * place; 
	place = (new_struc_place_t *)get_custom_viewer_place(ctx->widget, false, NULL, NULL);
	if(!place)
		return 0;

	if(fi.size() <= place->idx)
		return 0;

	field_info_t::iterator b = fi.begin();
	if(!safe_advance(b, fi.end(), place->idx))
		return 0;
	
	b->second.is_array = !b->second.is_array;
	return 1;
}

//---------------------------------------------------------------------------
ACT_DEF(pack_cb)
{
	new_struc_place_t * place; 
	place = (new_struc_place_t *)get_custom_viewer_place(ctx->widget, false, NULL, NULL);
	if(!place)
		return 0;

	if(fi.size() <= place->idx)
		return 0;

	auto b = fi.begin();
	if(!safe_advance(b, fi.end(), place->idx))
		return 0;	

	uint32 cnt = b->second.nesting_counter;
	auto last = b;
	while((b != fi.end()) && (b != fi.begin())  && (b->second.nesting_counter == cnt)) {
		last = b;
		--b;
	}
	
	b = last;
	auto e = b;
	while(e != fi.end() && e->second.nesting_counter == cnt)
		++e;

	tinfo_t outtype;
	if (!fi.to_type(outtype, &b, &e))
		return 0;

	scan_info_t & sci = b->second;
	sci.types.clear();
	typerecord_t tr;
	tr.type = outtype;
	tr.enabled = true;
	fi.types_cache[b->first] = outtype;
	sci.types.add_unique(tr);
	--sci.nesting_counter;

	++b;
	if(b != fi.end() && b != e)
		fi.erase(b, e);

	return 1;
}

//---------------------------------------------------------------------------
ACT_DEF(clear_var_scan)
{
	fi.clear();
	close_new_struc_view();
	return 1;
}

//--------------------------------------------------------------------------
MY_DECLARE_LISTENER(ns_ui_callback)
{
	switch (ncode) {
	case ui_widget_invisible:
		{
			TWidget *f = va_arg(va, TWidget *);
			if (f == stBld) {
				stBld = NULL;
				UNHOOK_CB(HT_UI, ns_ui_callback);
			}
		}
		break;
	case ui_widget_visible:
	{
		TWidget *f = va_arg(va, TWidget *);
		if (f == stBld) {
			attach_action_to_popup(f, NULL, ACT_NAME(pack_cb));
			attach_action_to_popup(f, NULL, ACT_NAME(change_item_type_cb));
			attach_action_to_popup(f, NULL, ACT_NAME(make_array_cb));
			attach_action_to_popup(f, NULL, ACT_NAME(remove_one));
			attach_action_to_popup(f, NULL, ACT_NAME(insert_one));
			attach_action_to_popup(f, NULL, ACT_NAME(clear_var_scan));
		}
	}
	break;
	case ui_populating_widget_popup:
		{
			TWidget *f = va_arg(va, TWidget *);
			if (f == stBld) {
				TPopupMenu *p = va_arg(va, TPopupMenu *);
				// Create right-click menu on the fly
				if(fi.function_adjustments.size())
					attach_action_to_popup(f, p, ACT_NAME(show_function_list_cb));
				if(fi.function_adjustments.size() > fi.visited_functions.size())
					attach_action_to_popup(f, p, ACT_NAME(jump_to_next_function_cb));
			}
		}
		break;
	}
	return 0;
}

const char * new_struc_view_form = "[hrt] new structure";
//---------------------------------------------------------------------------
// Create a custom view window
bool show_new_struc_view()
{	
	if (!fi.size())
		return false;

	stBld = find_widget(new_struc_view_form);
	if (stBld) {
		activate_widget(stBld, true);
		return true;
	}
	// create two place_t objects: for the minimal and maximal locations
	new_struc_place_t s1;  
	new_struc_place_t s2((uval_t)fi.size() - 1);
	stBld = create_custom_viewer(new_struc_view_form, &s1, &s2, &s1, 0, &fi, NULL, NULL);

	custom_viewer_handlers_t cvh;
	cvh.keyboard = ct_keyboard;
	set_custom_viewer_handlers(stBld, &cvh, stBld);

	HOOK_CB(HT_UI, ns_ui_callback);
	display_widget(stBld, WOPN_RESTORE);
	return true;
}

extern bool idaapi close_new_struc_view()
{
	TWidget *form = find_widget(new_struc_view_form);
	if ( form != NULL ) {
		close_widget(form, WCLS_SAVE | WCLS_CLOSE_LATER);
		return true;
	}
	return false;
}

