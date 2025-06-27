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

// Evolution of negative_cast.cpp from https://github.com/nihilus/hexrays_tools
// there is almost nothing left from the original code

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
	e = skipCast(e);
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
	e = skipCast(e);
	switch (e->op) {
	case cot_ptr:
		break;
	case cot_add:
	case cot_idx:
		if (e->y->op != cot_num)
			return false;
		break;
	case cot_memptr:
		if (remove_pointer(e->x->type).is_union())
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
				Log(llDebug, "reincast convert: no member at %d\n", n);
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
				res->ptrsize = static_cast<decltype(res->ptrsize)>(res->type.get_size()); //is it need?
			} else {
				for (size_t i = 0; i < trace.size(); i++) {
#if IDA_SDK_VERSION < 850
					member_t* smem = get_member_by_id(trace[i]);
					if(!smem || !get_member_type(smem, &res->type)) {
						res->cleanup();
						delete res;
						return NULL;
					}
					res->m = (uint32)smem->soff; // set offset
#else //IDA_SDK_VERSION >= 850
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
#endif //IDA_SDK_VERSION < 850
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
				if (remove_pointer(x->type).is_union())
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
				res->type = exp->type;
				res->ptrsize = static_cast<decltype(res->ptrsize)>(res->type.get_size());
			}
			replaceExp(func, exp, res);
			return true;
		}

		//modify expression on leave to avoid recursion
		int idaapi leave_expr(cexpr_t *e)
		{
			if ((offsetof_test(e) || reincast(e)) && recalc_parent_types()) {
				Log(llDebug, "restart reincast\n");
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
#if IDA_SDK_VERSION < 850
	struc_t * struc = choose_struc(title.c_str());
	if(!struc)
		return 0;
	tid_t tid = struc->id;
#else //IDA_SDK_VERSION >= 850
	tinfo_t ti;
	if (!choose_struct(&ti, title.c_str()))
		return 0;
	tid_t tid = ti.force_tid();
	if (tid == BADADDR)
		return 0;
#endif //IDA_SDK_VERSION < 850

	add_cached_reincast(anchor->ea, tid);
	Log(llDebug, "add_cached_reincast at %a\n", anchor->ea);
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

//----------------------- CONTAINER_OF --------------------------------------------------------------------------------------------------
#if IDA_SDK_VERSION <= 730 //IDA 7.4 has a better feature ("Pointer shift value" in a "Convert to struct*" dialog)
													 //https://www.hex-rays.com/products/ida/support/idadoc/1695.shtml

#define DEBUG_NEG_CAST 0

bool can_be_n_recast(vdui_t *vu);
bool is_n_recast(vdui_t *vu);

#define AST_ENABLE_FOR(check) vdui_t *vu = get_widget_vdui(ctx->widget); return ((vu == NULL) ? AST_DISABLE_FOR_WIDGET : ((check) ? AST_ENABLE : AST_DISABLE))
ACT_DECL(use_CONTAINER_OF_callback, AST_ENABLE_FOR(can_be_n_recast(vu)))
ACT_DECL(destroy_CONTAINER_OF_callback, AST_ENABLE_FOR(is_n_recast(vu)))
#undef AST_ENABLE_FOR
#undef AST_ENABLE_FOR_ME

static const action_desc_t actions_nc[] =
{
	ACT_DESC("[hrt] Use CONTAINER_OF here", NULL, use_CONTAINER_OF_callback),
	ACT_DESC("[hrt] Destroy CONTAINER_OF", NULL, destroy_CONTAINER_OF_callback),
};

void ncast_reg_act()
{
	for (size_t i = 0, n = qnumber(actions_nc); i < n; ++i)
		register_action(actions_nc[i]);
}

void ncast_unreg_act()
{
	for (size_t i = 0, n = qnumber(actions_nc); i < n; ++i)
		unregister_action(actions_nc[i].name);
}
//-------------------------------------------------------------------------

static const char HELPERNAME[] = "CONTAINER_OF";

class ida_local negative_cast_t
{
public:
	tid_t cast_to;
	uint32 from;
	int32 diff;
	bool disabled;

	negative_cast_t(void)
	{		
		cast_to = BADNODE;
		from = 0;
		diff = 0;
		disabled = false;
	}

	negative_cast_t(tid_t to, uint32 from_, int32 off)
	{
		from = from_;
		cast_to = to;
		diff = off;
		disabled = false;
	}

};

static const char NC_NETNODE_HASH_IDX[] = "hrt_contof";
void add_cached_cast(ea_t ea, tid_t cast_to, uint32 from, int32 diff)
{
	negative_cast_t cast(cast_to, from, diff);
	netnode node(ea);
	node.hashdel(NC_NETNODE_HASH_IDX);
	node.hashset(NC_NETNODE_HASH_IDX, &cast, sizeof(negative_cast_t));
}

bool find_cached_cast(ea_t ea, negative_cast_t * cast)
{
	netnode node(ea);
	return sizeof(negative_cast_t) == node.hashval(NC_NETNODE_HASH_IDX, cast, sizeof(negative_cast_t));
}

void del_cached_cast(ea_t ea)
{
	negative_cast_t cast;
	netnode node(ea);
	size_t bufSz = sizeof(negative_cast_t);
	if(sizeof(negative_cast_t) == node.hashval(NC_NETNODE_HASH_IDX, &cast, sizeof(negative_cast_t))) {
		cast.disabled = true;
		node.hashdel(NC_NETNODE_HASH_IDX);
		node.hashset(NC_NETNODE_HASH_IDX, &cast, sizeof(negative_cast_t));
	}
}

bool can_be_n_recast(vdui_t *vu)
{
	if ( !vu->item.is_citem() )
		return false;
	cexpr_t *e = vu->item.e;

	if(e->op == cot_var || e->op == cot_num) {
		citem_t * prnt = vu->cfunc->body.find_parent_of(e);
		if(!prnt->is_expr())
			return false;
		if ((prnt->op == cot_cast && e->op == cot_var) ||
			(prnt->op == cot_neg && e->op == cot_num)) {
			prnt = vu->cfunc->body.find_parent_of(prnt);
			if(!prnt->is_expr())
				return false;
		}
		e = (cexpr_t*)prnt;
	}

	if (e->op != cot_sub && e->op != cot_add && e->op != cot_idx)
		return false;

	cexpr_t *var = skipCast(e->x);
	cexpr_t * num = e->y;
	if(num->op == cot_neg)
		num = num->x;

	if(var->op != cot_var || num->op != cot_num)
		return false;
	
	if(e->op == cot_idx) {
		tinfo_t vartype = var->type;
		if (!vartype.is_ptr())
			return false;
	}
	return true;	
}

struct ida_local nc_memb_t {
	tid_t strucId;
	uint32 memb_off;
	nc_memb_t(): memb_off(0){}
	nc_memb_t(tid_t t, uint32 off): strucId(t), memb_off(off) {}
};

typedef std::map<int, nc_memb_t> var_asgn_memb_t;

void convert_negative_offset_casts(cfunc_t *cfunc)
{
	struct ida_local nc_converter_t : public ctree_parentee_t
	{
		var_asgn_memb_t var_asgn_memb;
		bool bDoRestart;
		cfunc_t *func;
		ea_t insideHelper;
		
		nc_converter_t(cfunc_t *cfunc) : ctree_parentee_t(true), func(cfunc) { bDoRestart = false; insideHelper = BADADDR; }

		void cache_var_asgn_memb(cexpr_t * asg)
		{
			if(asg->op != cot_asg || asg->x->op != cot_var)
				return;
			//Is it need to check cot_cast and cot_ref on CMAT_BUILT?

			// for CMAT_BUILT maturity (preferred for auto-replacing "container_of() + num" to "container_of()->memptr")
			// check: "var = smth + num" where smth type is pointer to struct
			if(asg->y->op == cot_add && asg->y->y->op == cot_num) {
				tinfo_t t = asg->y->x->type;
				if(t.is_ptr()) {
					t = t.get_ptrarr_object();
					qstring sname;
					if(t.is_struct() && t.get_type_name(&sname)) {
						tid_t struct_id = get_struc_id(sname.c_str());
						if(struct_id != BADNODE) {
							uint32 membOff = (uint32)asg->y->y->numval();
//							if (struct_has_member(struct_id, membOff)) {
								var_asgn_memb[asg->x->v.idx] = nc_memb_t(struct_id, membOff);
#if DEBUG_NEG_CAST
								qstring expStr;
								asg->print1(&expStr, func); tag_remove(&expStr);
								Log(llDebug, "%a: cache assign %s (type '%s', off %x)\n", asg->ea, expStr.c_str(), sname.c_str(), (uint32)membOff);
#endif
//							}
						}
					}
				}
			}
		}

		bool convert_test(cexpr_t *e)
		{
			if (e->op != cot_sub && e->op != cot_add /*&& e->op != cot_idx*/)
				return false;
			
			cexpr_t *var = skipCast(e->x);
			cexpr_t * num = e->y;
			if(var->op != cot_var || num->op != cot_num)
				return false;

			//avoid recursion
			if (num->ea == insideHelper) {
#if DEBUG_NEG_CAST
				qstring expStr;
				e->print1(&expStr, func); tag_remove(&expStr);
				Log(llFlood, "insideHelper (%a '%s')\n", insideHelper, expStr.c_str());
#endif
				return false;
			}

			int32 diff = (int32)num->numval();
			if(e->op == cot_sub)
				diff = -diff;
			uint32 from_off;
			tid_t cast_to;

			negative_cast_t cache; 
			if (find_cached_cast(num->ea, &cache)) {
				if (cache.disabled) {
#if DEBUG_NEG_CAST
					qstring expStr;
					e->print1(&expStr, func); tag_remove(&expStr);
					Log(llFlood, "disabled (%a '%s')\n", num->ea, expStr.c_str());
#endif
					return false;
				}
				cast_to = cache.cast_to;
				diff = cache.diff;
				from_off = cache.from;
			} else {
				var_asgn_memb_t::iterator it = var_asgn_memb.find(var->v.idx);
				if(it == var_asgn_memb.end())
					return false;
				from_off = it->second.memb_off;
				if(diff < 0 && (int32)from_off < -diff) {
					Log(llWarning, "CONTAINER_OF casts substruct, pls select right type\n");
					return false;
				}
				cast_to = it->second.strucId;
				add_cached_cast(num->ea, cast_to, from_off, diff);
			}			

			qstring struc_name = get_struc_name(cast_to);
			tinfo_t ti_cast_to = make_pointer(create_typedef(struc_name.c_str()));
#if DEBUG_NEG_CAST
			if (!ti_cast_to.is_correct()) {
				qstring tstr;
				ti_cast_to.print(&tstr);
				Log(llDebug, "incorrect type for CONTAINER_OF (%s)\n", tstr.c_str());
				return false;
			}
#endif
			//make  helper call arguments
			carglist_t * arglist = new carglist_t();
#if 0 //crashes on memory corruption
			carg_t * arg0 = new carg_t();
			//e->type = make_pointer(create_typedef("converted_expression"));
			arg0->consume_cexpr(new cexpr_t(*e));
			arglist->push_back(*arg0);
#endif
			qstring member_text;
			carg_t * arg2 = new carg_t();
			print_struct_member_name(cast_to, from_off, &member_text);
			tinfo_t t2 = make_pointer(create_typedef("base_struct_member"));
			arg2->consume_cexpr( create_helper(true, t2, member_text.c_str()));
			arglist->push_back(*arg2);

			cexpr_t * call = call_helper(ti_cast_to, arglist, "%s", HELPERNAME);
			call->ea = num->ea;
			call->x->ea = e->ea;
			call->type = ti_cast_to;
			if (from_off == -diff) {
				replaceExp(func, e, call);// , false);
			} else {
				cexpr_t * mptr = new cexpr_t(cot_add, call, make_num(from_off + diff));
				replaceExp(func, e, mptr);// , false);
			}
			return true;
		}

		int idaapi visit_expr(cexpr_t *e)
		{
			if (e->op == cot_asg)
				cache_var_asgn_memb(e);
			else if (e->op == cot_call && e->x->op == cot_helper)
				insideHelper = e->ea;
			return 0; // continue walking the tree
		}

		//modify expression on leave to avoid recursion
		int idaapi leave_expr(cexpr_t *e) 
		{
			if (e->op == cot_call && e->x->op == cot_helper && insideHelper == e->ea)
				insideHelper = BADADDR;
			else if (e->op == cot_sub || e->op == cot_add /*|| e->op == cot_idx*/) {
				if (convert_test(e) && recalc_parent_types()) {
#if DEBUG_NEG_CAST
					Log(llDebug, "restart nc_converter\n");
#endif
					bDoRestart = true;
					return 1;
				}
			}
			return 0; // continue walking the tree
		}
	};

	for(uint32 i = 0; i < 10; i++) {
		nc_converter_t nc(cfunc);
		nc.apply_to(&cfunc->body, NULL);
		if(!nc.bDoRestart)
			break;
	}
}

//--------------------------------------------------------------------------
bool get_member_offset_by_fullname_r(struc_t** struc, asize_t* offset, const char* fullname)
{
	struc_t* ss;
	member_t* memb = get_member_by_fullname(&ss, fullname);
	if (memb) {
		if (!*struc)
			*struc = ss;
		*offset += memb->soff;
		return true;
	}
	const char* first = qstrchr(fullname, '.');
	if (!first)
		return false;
	const char* second = qstrchr(first + 1, '.');
	if (!second)
		return false;
	qstring name(fullname, second - fullname);
	memb = get_member_by_fullname(&ss, name.c_str());
	if (!memb)
		return false;

	struc_t* membstr = get_sptr(memb);
	if (!membstr)
		return false;

	if (!*struc)
		*struc = ss;
	*offset += memb->soff;


	get_struc_name(&name, membstr->id);
	name.append(second);

	return get_member_offset_by_fullname_r(struc, offset, name.c_str());
}

bool get_member_offset_by_fullname(struc_t** struc, asize_t* offset, const char* fullname)
{
	*struc = NULL;
	*offset = 0;
	return get_member_offset_by_fullname_r(struc, offset, fullname);
}

//--------------------------------------------------------------------------
ACT_DEF(use_CONTAINER_OF_callback)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if (!vu.item.is_citem())
		return false;

	cexpr_t *e = vu.item.e;

	//go level up to add, sub or idx
	if (e->op == cot_var || e->op == cot_num) {
		citem_t * prnt = vu.cfunc->body.find_parent_of(e);
		if (!prnt->is_expr())
			return 0;
		e = (cexpr_t*)prnt;
		if (e->op == cot_cast) {
			citem_t * prnt = vu.cfunc->body.find_parent_of(e);
			if (!prnt || !prnt->is_expr())
				return 0;
			e = (cexpr_t*)prnt;
		}
	}

		if (e->op != cot_sub && e->op != cot_add && e->op != cot_idx)
			return 0;
	
		cexpr_t * cast = 0;
		cexpr_t *var = e->x;
		if (var->op == cot_cast) {
			cast = var;
			var = var->x;
		}

		cexpr_t * num = e->y;
		if(var->op != cot_var || num->op != cot_num)
			return 0;
		
		int32 offset = (int32)num->numval();
		if (e->op == cot_sub)
			offset = -offset;
		ea_t ea = num->ea; //because cot_idx have not valid ea

		if(e->op == cot_idx) {
			if(!var->type.is_ptr())
				return 0;
			tinfo_t t = var->type;
			t.remove_ptr_or_array();
			offset *= (int32)t.get_size();
			citem_t * prnt = vu.cfunc->body.find_parent_of(e);
			if (prnt->op == cot_memref) {
				e = (cexpr_t*)prnt;
				offset += e->m;
			}
		}
		else // Is it possible cot_cast and cot_idx together?
		if (cast) {
			tinfo_t t = cast->type;
			t.remove_ptr_or_array();
			offset *= (int32)t.get_size();
		} 


	qstring definition;
	negative_cast_t cache;
	if (find_cached_cast(ea, &cache) && cache.cast_to != BADNODE)
		print_struct_member_name(cache.cast_to, cache.from, &definition);

	struc_t *struc;
	asize_t memboff;
	do {
		if(!ask_str(&definition, HIST_SEG, "[hrt] Enter base struct member (%d):\n'struc.member'\n or \n'struc + offset'", offset))
			return 0;

		size_t plus = definition.find('+');
		if (plus != qstring::npos && plus != 0) {

			qstring strname = definition.substr(0, plus).trim2();
			tid_t tid = get_struc_id(strname.c_str());
			if (tid == BADNODE) {
				Log(llDebug, "no such struct: '%s'\n", strname.c_str());
				continue;
			}
			qstring stroff = definition.substr(plus + 1);
			ea_t convea;
			if (!atoea(&convea, stroff.c_str())) {
				Log(llDebug, "bad offset: '%s'\n", stroff.c_str());
				continue;
			}
			memboff = (asize_t)convea;
			struc = get_struc(tid);

		} else if(!get_member_offset_by_fullname(&struc, &memboff, definition.c_str())) {
			Log(llDebug, "no such struct member: '%s'\n", definition.c_str());
			continue;
		} 

		if (offset > 0 || -offset <= (int32)memboff)
			break;

		Log(llDebug, "struct member's '%s' offset 0x%x is less then subtract 0x%x", definition.c_str(), (uint32)memboff, -offset);
		if(e->op == cot_idx)
			LogTail(llDebug, ", try to 'reset pointer type' for base variable\n");
		else 
			LogTail(llDebug, "\n");
	} while(1);

	add_cached_cast(ea, struc->id, (uint32)memboff, offset);

	vu.refresh_view(false);
	return 0;
}

bool is_n_recast(vdui_t *vu)
{
	if ( !vu->item.is_citem() )
		return false;
	cexpr_t *e = vu->item.e;
	if (e->op == cot_helper)
		return qstrcmp(HELPERNAME, e->helper) == 0;
	return false;
}

ACT_DEF(destroy_CONTAINER_OF_callback)
{
	vdui_t &vu = *get_widget_vdui(ctx->widget);
	if (!vu.item.is_citem())
		return 0;
	cexpr_t *e = vu.item.e;
	if (e->op != cot_helper)
		return 0;
	if (qstrcmp(HELPERNAME, e->helper) != 0)
		return 0;
	const citem_t *p = vu.cfunc->body.find_parent_of(e);
	if (p->op != cot_call)
		return 0;
	cexpr_t * call = (cexpr_t *)p;

	//this really not need, just del_cached_cast and refres view is enought
#if 0
	carglist_t & arglist = *call->a;
	if (arglist.size() < 2)
		return 0;
	//take both arguments as is, num representation may be modified by user
	cexpr_t * subexp = new cexpr_t(cot_add, new cexpr_t(arglist[0]), new cexpr_t(arglist[1]));
	subexp->calc_type(false);
	replaceExp(vu.cfunc, call, subexp);
#endif
	del_cached_cast(call->ea);
	vu.refresh_view(true);
	return 0;
}
#endif //IDA_SDK_VERSION <= 730

