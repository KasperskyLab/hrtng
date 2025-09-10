/*
  ida-sdk\src\plugins\vds18\hexrays_sample18.cpp
  modified for:
  * works with stack variables too
  * store microcode modification in the database
  * delete microcode modification
  * integration into pseudocode and disasm view
*/

/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2025 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It shows how to specify a register value at a desired location.
 *      Such a functionality may be useful when the code to decompile is
 *      obfuscated and uses opaque predicates.
 *
 *      The basic idea of this plugin is very simple: we add assertions like
 *
 *        mov #VALUE, reg
 *
 *      at the specified addresses in the microcode. The decompiler will use this
 *      info during the microcode optimization phase. However, the assertion
 *      will not appear in the output listing.
 *
 *      Usage: use Edit, Plugins, Specify register value.
 */

#include "warn_off.h"
#include <hexrays.hpp>
#include "warn_on.h"

#include "helpers.h"

struct ida_local varval_info_t
{
	ea_t ea;      // address in the decompiled function
	vivl_t var;   // register or stack var
	uint64 value; // user-specified value
	varval_info_t() : ea(BADADDR), value(0) {}
};
DECLARE_TYPE_AS_MOVABLE(varval_info_t);
typedef qvector<varval_info_t> varvals_info_t;

//-------------------------------------------------------------------------
static bool save_varvals(ea_t funcea, const varvals_info_t& vvals)
{
	bytevec_t buffer;
	for (const auto& vv : vvals) {
		buffer.pack_ea(vv.ea);
		buffer.pack_ea(vv.var.off);
		buffer.pack_db(vv.var.type);
		buffer.pack_dd(vv.var.size);
		buffer.pack_dq(vv.value);
	}
	if (buffer.size() > MAXSPECSIZE) {
		Log(llError, "too many varvals\n");
		return false;
	}
	netnode n(funcea);
	return n.setblob(&buffer.front(), buffer.size(), 0, 'v');
}

bool has_varvals(ea_t funcea)
{
	netnode n(funcea);
	if (n == BADNODE)
		return false;
	return n.blobsize(0, 'v') != 0;
}

static bool load_varvals(ea_t funcea, varvals_info_t& vvals)
{
	netnode n(funcea);
	if (n == BADNODE)
		return false;

	size_t sz;
	void* buff = n.getblob(NULL, &sz, 0, 'v');
	if (!buff)
		return false;

	const uchar* ptr = (const uchar*)buff;
	const uchar* end = (const uchar*)buff + sz;
	while (ptr < end) {
		varval_info_t& vv = vvals.push_back();
		vv.ea = unpack_ea(&ptr, end);
		vv.var.off = unpack_ea(&ptr, end);
		vv.var.type = unpack_db(&ptr, end);
		vv.var.size = unpack_dd(&ptr, end);
		vv.value = unpack_dq(&ptr, end);
	}
	qfree(buff);
	return true;
}

static bool del_varvals(ea_t funcea)
{
	netnode n(funcea);
	if (n == BADNODE)
		return false;
	return n.delblob(0, 'v') != 0;
}

//--------------------------------------------------------------------------
static minsn_t* create_mov(mbl_array_t* mba, const varval_info_t& vv)
{
	minsn_t* m = new minsn_t(vv.ea);
	m->opcode = m_mov;
	m->l.make_number(vv.value, vv.var.size, vv.ea);
	if (vv.var.is_reg()) {
		m->d.make_reg(vv.var.get_reg(), vv.var.size);
	} else {
		m->d.size = vv.var.size;
		m->d._make_stkvar(mba, vv.var.get_stkoff());
	}
	// declare this 'mov' as an assertion.
	// assertions are deleted before generating ctree and don't
	// appear in the output
	m->iprops |= IPROP_ASSERT;
	// Just for debugging let us print the constructed assertion:
	Log(llInfo, "%a: inserted hidden variable assignment: '%s'\n", vv.ea, m->dstr());
	return m;
}

//--------------------------------------------------------------------------
void vv_insert_assertions(mbl_array_t* mba)
{
	func_t* pfn = mba->get_curfunc();
	if (pfn == NULL)
		return; // currently only functions are supported, not snippets

	// filter out the addresses outside of the decompiled function
	varvals_info_t varvals;
	if(!load_varvals(pfn->start_ea, varvals) || varvals.empty())
		return; // no addresses inside our function

	struct ida_local assertion_inserter_t : public minsn_visitor_t
	{
		varvals_info_t& varvals;
		virtual int idaapi visit_minsn(void) override
		{
			for (size_t i = 0; i < varvals.size(); i++) {
				varval_info_t& fri = varvals[i];
				if (curins->ea == fri.ea) {
					if (fri.var.is_reg() || fri.var.is_stkoff()) {
						// create "mov #value, reg"
						minsn_t* m = create_mov(mba, fri);
						// insert it before the current instruction
						blk->insert_into_block(m, curins->prev);
					}
					// remove this fixed regval from consideration
					varvals.erase(varvals.begin() + i);
					--i;
				}
			}
			return varvals.empty(); // stop if regvals becomes empty
		}
		assertion_inserter_t(varvals_info_t& fr) : varvals(fr) {}
	};
	assertion_inserter_t ai(varvals);

	// find the specified addresses in mba and insert assertions.
	// note: if the address specified by the user has the 'nop' instruction, it
	// won't be translated into mircocode. we may fail to add an assertion because
	// of this. the user should not specify the address of a 'nop' instruction
	// or the logic in visit_minsn() should be improved to handle the situation
	// when the specified address is not present in the microcode.
	mba->for_all_topinsns(ai);

	//mba->verify(true);
}

/*-------------------------------------------------------------------------------------------------------------------------*/

ACT_DECL(insert_varval, return ((ctx->widget_type == BWN_DISASM || ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))
ACT_DECL(clear_varvals, return ((ctx->widget_type == BWN_DISASM || ctx->widget_type == BWN_PSEUDOCODE) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET))

static const action_desc_t actions[] =
{
	ACT_DESC("[hrt] Insert variable value assingment...", "", insert_varval),
	ACT_DESC("[hrt] Clear variable value assingments", "", clear_varvals),
};

void varval_reg_act()
{
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		register_action(actions[i]);
}

void varval_unreg_act()
{
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		unregister_action(actions[i].name);
}

ACT_DEF(insert_varval)
{
	varval_info_t fri;
	CASSERT(sizeof(fri.ea) == sizeof(ea_t));
	CASSERT(sizeof(fri.value) == sizeof(uint64));
	ea_t proc_ea;
	qstring varname;
	vdui_t* vu = NULL;

	if (ctx->widget_type == BWN_DISASM) {
		bool ok = false;
		mbl_array_t* mba = NULL;
		do {
			ea_t ea = get_screen_ea();
			if (!is_code(get_flags(ea)))
				break;
			func_t* pfn = get_func(ea);
			if (!pfn || pfn->start_ea == ea)
				break;
			gco_info_t gco;
			if (!get_current_operand(&gco))
				break;

			//There is no way to convert IDA stack offset to hexrays stackvar offset without decompiling
			//from hexrays.hpp "because they are based on the lowest value of sp in the function"
			hexrays_failure_t hf;
			mba_ranges_t mbr(pfn);
			mba = gen_microcode(mbr, &hf, NULL, DECOMP_NO_CACHE, MMAT_PREOPTIMIZED);
			if (!mba)
				break;

			//convert IDA reg/stkoff numbers to hexrays based
			mlist_t list;
			if (!gco.append_to_list(&list, mba))
				break;

			mop_t op;
			if (!op.create_from_mlist(mba, list, mba->fullsize))
				break;

			if (op.is_reg()) {
				fri.var.set_reg(op.r, op.size);
			} else {
				fri.var.set_stkoff(op.s->off, op.size);
			}
			proc_ea = pfn->start_ea;
			fri.ea = ea;
			varname = gco.name;
			ok = true;
		} while (0);
		if (mba)
			delete mba;
		if (!ok) {
				warning("[hrt] Somthing went wrong");
				return 0;
		}
	} else if (ctx->widget_type == BWN_PSEUDOCODE) {
		vu = get_widget_vdui(ctx->widget);
		lvar_t* var = vu->item.get_lvar();
		if (!var || !vu->item.is_citem())
			return 0;

		proc_ea = vu->cfunc->entry_ea;
		fri.ea = vu->item.get_ea();
		if (fri.ea == BADADDR) {
			citem_t* prnt = vu->cfunc->body.find_parent_of(vu->item.it);
			if (prnt)
				fri.ea = prnt->ea;
		}

		if (var->location.is_stkoff()) {
			fri.var.set_stkoff(var->location.stkoff(), var->width);
		} else if (var->location.is_reg1()) {
			fri.var.set_reg(var->location.reg1(), var->width);
		} else {
			warning("[hrt] Sorry, only register or stack vars : %s", var->location.dstr(var->width));
			return 0;
		}
		varname.sprnt("%s at %s", var->name.c_str(), var->location.dstr(var->width));
	} else {
		return 0;
	}

	static const char form[] =
		"[hrt] Insert variable assignment\n\n"
		"Before instruction at <#Address# :$::16::>\n"
		"Insert: %q = <#Value# :l::16::>\n\n";
	if (1 == ask_form(form, &fri.ea, &varname, &fri.value)) {
		varvals_info_t vvs;
		load_varvals(proc_ea, vvs);
		vvs.push_back(fri);
		if (save_varvals(proc_ea, vvs)) {
			Log(llInfo, "%a: Variable %s is considered to be equal to 0x%" FMT_64 "X\n", fri.ea, varname.c_str(), fri.value);
			if(vu)
				vu->refresh_view(true);
		}
	}
	return 0;
}

ACT_DEF(clear_varvals)
{
	vdui_t* vu = NULL;
	ea_t proc_ea;
	if (ctx->widget_type == BWN_DISASM) {
		func_t* func = get_func(get_screen_ea());
		if (!func)
			return 0;
		proc_ea = func->start_ea;
	} else if (ctx->widget_type == BWN_PSEUDOCODE) {
		vu = get_widget_vdui(ctx->widget);
		proc_ea = vu->cfunc->entry_ea;
	} else {
		return 0;
	}

	if(del_varvals(proc_ea)) {
		Log(llInfo, "%a: no more hidden variables assignments\n", proc_ea);
		if(vu)
			vu->refresh_view(true);
	}
	return 0;
}
