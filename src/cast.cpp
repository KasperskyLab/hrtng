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

#include "warn_off.h"
#include <hexrays.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "cast.h"
#include "structures.h"

/*-------------------------------------------------------------------------------------------------------------------------*/

#define AST_ENABLE_FOR(check) vdui_t *vu = get_widget_vdui(ctx->widget); return ((vu == NULL) ? AST_DISABLE_FOR_WIDGET : ((check) ? AST_ENABLE : AST_DISABLE))
ACT_DECL(insert_reinterpret_cast, AST_ENABLE_FOR(can_be_reincast(vu)))
ACT_DECL(delete_reinterpret_cast, AST_ENABLE_FOR(is_reincast(vu)))
#undef AST_ENABLE_FOR

static const action_desc_t actions[] =
{
	ACT_DESC("[hrt] reinterpret_cast...", "I", insert_reinterpret_cast),
	ACT_DESC("[hrt] Remove reinterpret_cast", "I", delete_reinterpret_cast),
};

void reincast_reg_act()
{
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		register_action(actions[i]);
}

void reincast_unreg_act()
{
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		unregister_action(actions[i].name);
}
//-------------------------------------------------------------------------

static const char reincast_HELPERNAME[] = "reinterpret_cast";
static const char reincast_NETNODE_HASH_IDX[] = "hrt_reincast";

static void add_cached_reincast(ea_t ea, tid_t cast_to)
{
	netnode node(ea);
	node.hashdel(reincast_NETNODE_HASH_IDX);
	node.hashset(reincast_NETNODE_HASH_IDX, &cast_to, sizeof(cast_to));
}

static bool find_cached_reincast(ea_t ea, tid_t *cast_to)
{
	netnode node(ea);
	return sizeof(tid_t) == node.hashval(reincast_NETNODE_HASH_IDX, cast_to, sizeof(tid_t));
}

static void del_cached_reincast(ea_t ea)
{
	netnode node(ea);
	node.hashdel(reincast_NETNODE_HASH_IDX);
}

static bool is_reincast(cexpr_t *e)
{
	if (e->op == cot_cast)
		e = e->x;
	if (e->op == cot_ref) {
		cexpr_t *x = e->x;
		while(x->op == cot_memref)
			x = x->x;
		if(x->op == cot_memptr)
			e = x->x;
	}
	if (e->op == cot_call)
		e = e->x;
	if (e->op == cot_helper)
		return strncmp(reincast_HELPERNAME, e->helper, sizeof(reincast_HELPERNAME) - 1) == 0;
	return false;
}

bool is_reincast(vdui_t *vu)
{
	if ( !vu->item.is_citem() )
		return false;
	return is_reincast(vu->item.e);
}

static bool is_reincastable(cexpr_t *e)
{
	if (e->ea == BADADDR)
		return false;
	if (e->op == cot_cast)
		e = e->x;
	switch (e->op) {
	case cot_ptr:
		break;
	case cot_add:
	case cot_idx:
		if (e->y->op != cot_num)
			return false;
		break;
	case cot_memptr:
		if (e->x->type.is_union())
			return false;
		break;
	default:
		return false;
	}
	return !is_reincast(e->x);
}

//returns exp be used as anchor
static cexpr_t *can_be_reincasted(cfunc_t *cfunc, cexpr_t *e)
{
	cexpr_t *prnt = (cexpr_t *)cfunc->body.find_parent_of(e);
	if (!prnt->is_expr())
		return NULL;
	if (prnt->op == cot_cast)
		return can_be_reincasted(cfunc, prnt);
	if (is_reincastable(prnt))
		return prnt;
	return NULL;
}

bool can_be_reincast(vdui_t *vu)
{
	if(!vu->item.is_citem() || !vu->item.it->is_expr())
		return false;
	cexpr_t *e = vu->item.e;
	return can_be_reincasted(vu->cfunc, e) != NULL;
}

void convert_offsetof_n_reincasts(cfunc_t *cfunc)
{
	struct ida_local conv_offsetof_reincasts_t : public ctree_parentee_t
	{
		bool bDoRestart;
		cfunc_t *func;

		conv_offsetof_reincasts_t(cfunc_t *cfunc) : ctree_parentee_t(true), func(cfunc) { bDoRestart = false;}

		//converts 
		//	"x + n"
		//to 
		//  "&((struc*)x)->member.submemb1.submemb2" or "(char*)&((struc*)x)->member + remainder"
		// or 
		//  "&(reinterpret_cast<struc*>x)->member.submemb1.submemb2" "(char*)&(reinterpret_cast<struc*>x)->member + remainder"
		//where "n" - can be zero
		cexpr_t* convert(cexpr_t *x, uint64 n, tid_t strucId, ea_t ea, bool reinterpret, bool chkXptrSz)
		{
			if (n && chkXptrSz) {
				if (x->type.is_ptr_or_array()) {
					tinfo_t tif = x->type.get_ptrarr_object();
					size_t sz = tif.get_size();
					if (!sz || sz == BADSIZE)
						return NULL;
					n *= sz;
				} else if (!x->type.is_integral())
					return NULL;
			}

			tidvec_t trace;
			tid_t last_member = BADNODE;
			asize_t remainder = struct_get_member(strucId, (asize_t)n, &last_member, &trace);
			if (last_member == BADNODE) {
				//msg("[hrt] reincast convert: no member at %d\n", n);
				return NULL;
			}

			cexpr_t *cast;
			qstring struc_name;
			if (!get_tid_name(&struc_name, strucId))
				return NULL;
			tinfo_t ti_cast_to = make_pointer(create_typedef(struc_name.c_str()));
			if (reinterpret) {
				carglist_t* arglist = new carglist_t();
				carg_t& arg = arglist->push_back();
				arg.assign(*x); 
				tinfo_t t; t.create_simple_type(BTF_VOID); 
				arg.formal_type = make_pointer(t);
				cast = call_helper(ti_cast_to, arglist, "%s<%s*>", reincast_HELPERNAME, struc_name.c_str());
				cast->x->ea = ea; //save anchor for delete_reinterpret_cast
			} else {
				cast = new cexpr_t(cot_cast, new cexpr_t(*x));
				cast->type = ti_cast_to;
			}
			cexpr_t *res = new cexpr_t(cot_memptr, cast);
			res->ea = ea;

			if (trace.size() <= 1) {
				res->type = cast->type;//make_pointer(create_typedef(num->nf.type_name.c_str()));
				res->m = (uint32_t)n;
				//res->ptrsize = 8; //is it need?
			} else {
				for (size_t i = 0; i < trace.size(); i++) {
#if IDA_SDK_VERSION < 900
					member_t * smem = get_member_by_id(trace[i]);
					res->m = (uint32)smem->soff; // set offset 
					if (!get_member_type(smem, &res->type)) {
						res->cleanup();
						delete res;
						return NULL;
					}
#else //IDA_SDK_VERSION < 900
					udm_t udm;
					tinfo_t imembStrucType;
					ssize_t imembIdx = imembStrucType.get_udm_by_tid(&udm, trace[i]);
					if(imembIdx == -1) {
						res->cleanup();
						delete res;
						return NULL;
					}
					res->m = (uint32)(udm.offset / 8);
					res->type = udm.type;
#endif //IDA_SDK_VERSION < 900
					if (res->type.is_array()) {
						tinfo_t elemT = res->type;
						elemT = elemT.get_array_element();
						asize_t elSz = (asize_t)elemT.get_size();
						asize_t idx = 0;
						if (remainder >= elSz) {
							idx = remainder / elSz;
							remainder = remainder % elSz;
						}
						res = new cexpr_t(cot_idx, res, make_num(idx, func, ea, 0, no_sign, 4));
						res->type = elemT;
						res->ea = ea;
					}
#if 0
					qstring mesg;
					qstring typestr;
					res->type.print(&typestr);
					mesg.cat_sprnt("%s %x res", typestr.c_str(), (uint32)smem->soff);
					printExp2Msg(func, res, mesg.c_str());
#endif
					if (i + 1 < trace.size()) {
						res = new cexpr_t(cot_memref, res);
						res->ea = ea;
					}
				}
			}
			res = new cexpr_t(cot_ref, res);
			res->type = make_pointer(res->x->type);
			if (remainder) {
				res = new cexpr_t(cot_cast, res);
				tinfo_t t; t.create_simple_type(BTMT_CHAR | BT_INT8);
				res->type = make_pointer(t); //dummy_ptrtype(1, false); //ida dislike unk types in final code
				res = new cexpr_t(cot_add, res, make_num(remainder));
				res->type = res->x->type;//same pointer type as left side arg //get_unk_type(1);
				res->ea = ea;
			}
			return res;
		}

		bool offsetof_test(cexpr_t *add_exp)
		{
			if (add_exp->op != cot_add || add_exp->y->op != cot_num)
				return false;

			cnumber_t *num = add_exp->y->n;
			if (!num->nf.is_stroff())// || add_exp->x->op == cot_cast)
				return false;

			tid_t strucId = get_named_type_tid(num->nf.type_name.c_str());
			if (strucId == BADNODE)
				return false;

			cexpr_t *res = convert(add_exp->x, num->_value, strucId, add_exp->ea, false, true);
			if (!res)
				return false;
			replaceExp(func, add_exp, res);
			return true;
		}

		bool reincast(cexpr_t *exp)
		{
			if (!is_reincastable(exp))
				return false;

			tid_t cast_to;
			if (!find_cached_reincast(exp->ea, &cast_to))
				return false;
			//printExp2Msg(func, exp, "cached_reincast");

			cexpr_t *x;
			uint64 n = 0;
			bool ptr = false;
			bool chkXptrSz = true;
			switch (exp->op) {
			case cot_add:
			case cot_idx:
				if (exp->y->op != cot_num)
					return false;
				x = exp->x;
				n = exp->y->numval();
				break;
			case cot_ptr:
				x = exp->x;
				n = 0;
				ptr = true;
				break;
			case cot_memptr:
				x = exp->x;
				if (x->type.is_union())
					return false;
				n = exp->m;
				ptr = true;
				chkXptrSz = false;
				break;
			default:
				return false;
			}

			//casted = new cexpr_t(var->v.mba,  vars->at(var->v.idx)); //IDABUG: this constructor declared but doesnt exist
			//IDABUG: manually copy var becouse cexpr_t::assign() (and copy constructor) does 
			//casted->type = var->type; //IDABUG: "typeinfo leak detected and fixed" causes heap corruption
			cexpr_t *res = convert(x, n, cast_to, exp->ea, true, chkXptrSz);
			if (!res)
				return false;
			if (ptr) {
				res = new cexpr_t(cot_ptr, res);
				res->ptrsize = exp->ptrsize;
				res->type = exp->type;
			}
			replaceExp(func, exp, res);
			return true;
		}

		//modify expression on leave to avoid recursion
		int idaapi leave_expr(cexpr_t *e)
		{
			if ((offsetof_test(e) || reincast(e)) && recalc_parent_types()) {
				//msg("[hrt] restart reincast\n");
				bDoRestart = true;
				return 1;
			}
			return 0;
		}
	};

	for(uint32 i = 0; i < 10; i++) {
		conv_offsetof_reincasts_t conv(cfunc);
		conv.apply_to_exprs(&cfunc->body, NULL);
		if(!conv.bDoRestart)
			break;
	}
	//cfunc->verify(ALLOW_UNUSED_LABELS, false);
	//dump_ctree(cfunc, "-AFT_REIN");
}

//--------------------------------------------------------------------------

ACT_DEF(insert_reinterpret_cast)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if (!vu.item.is_citem() || !vu.item.e->is_expr())
		return 0;
	cexpr_t *e = vu.item.e;
	cexpr_t *anchor = can_be_reincasted(vu.cfunc, e);
	if (!anchor)
		return false;

	//choose_local_tinfo
	qstring title;
	title.sprnt("[hrt] %s of \"%s\"", reincast_HELPERNAME, printExp(vu.cfunc, e).c_str());
#if IDA_SDK_VERSION < 900
	struc_t * struc = choose_struc(title.c_str());
	if(!struc)
		return 0;
	tid_t tid = struc->id;
#else //IDA_SDK_VERSION >= 900
	tinfo_t ti;
	if (!choose_struct(&ti, title.c_str()))
		return 0;
	tid_t tid = ti.force_tid();
	if (tid == BADADDR)
		return 0;
#endif //IDA_SDK_VERSION < 900

	add_cached_reincast(anchor->ea, tid);
	//msg("[hrt] add_cached_reincast at %a\n", anchor->ea);
	vu.refresh_view(false);
	return 0;
}

ACT_DEF(delete_reinterpret_cast)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if (!vu.item.is_citem())
		return 0;
	cexpr_t *e = vu.item.e;
	if (e->op != cot_helper)
		return 0;
	if (strncmp(reincast_HELPERNAME, e->helper, sizeof(reincast_HELPERNAME) - 1) != 0)
		return 0;
	del_cached_reincast(e->ea);
	vu.refresh_view(false);
	return 0;
}

