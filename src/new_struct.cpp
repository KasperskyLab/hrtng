//Evolution of new_struct.cpp from https://github.com/nihilus/hexrays_tools

#include "warn_off.h"
#include <hexrays.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <algorithm>
#include <pro.h>
#include <auto.hpp>
#include <funcs.hpp>
#include <expr.hpp>//for VT_LONG
#include <frame.hpp>//for recalc_spd
#include "warn_on.h"

#include "helpers.h"
#include "structures.h"
#include "new_struct.h"


//---------------------------------------------------------------------------------
struct ida_local ptr_checker_t : public ctree_parentee_t
{
	std::set<ea_t> idxs; //var index or ea of global
	std::map<ea_t, uval_t> offsets;//idx -> offset
	lvars_t * lvars;

	bool is_our(ea_t idx)
	{		
		return idxs.find(idx) != idxs.end();
	}

	bool collect_scanned_vars(cfunc_t *cfunc)
	{
		if(!cfunc)
			return false;
		
		lvars_t* lvars = cfunc->get_lvars();
		for(auto p : idxs) {
			if (p < lvars->size()) {
				scanned_variable_t sv;
				sv.first = offset_for_var_idx(p);
				sv.second = (*lvars)[(size_t)p];
				fi.scanned_variables[cfunc->entry_ea].add_unique(sv);
			} else {
				//TODO: deal with global pointers
			}
		}
		return true;
	}

	//var with index idx is ptr to struct+returned_value
	uval_t offset_for_var_idx(ea_t idx)
	{
		auto i = offsets.find(idx);
		if (i == offsets.end())
			return fi.current_offset;
		else
			return i->second;
	}

	void handle_vtables(bool &is_ptr, uint64 &delta, int i, tinfo_t & t)
	{		
		int j = i;
		while (j >= 0 && parents[j]->op == cot_cast )
			j--;

		if (j >= 1 && parents[j]->op == cot_ptr && parents[j-1]->op == cot_asg ) {
			cexpr_t * asg = ((cexpr_t*)parents[j-1]);
			cexpr_t * obj = NULL;
			if (asg->y->op == cot_ref && asg->y->x->op == cot_obj)
				obj = (cexpr_t*)asg->y->x;
			else if (asg->y->op == cot_obj)
				obj = (cexpr_t*)asg->y;

			if(obj && is_mapped(obj->obj_ea)) {
				unsigned int vt_len = 0;
				qstring vtsname;
				tid_t tid = create_VT_struc(obj->obj_ea, NULL, BADADDR, &vt_len);
				if(tid != BADADDR && get_tid_name(&vtsname, tid)) {
					t = make_pointer(create_typedef(vtsname.c_str()));
					for(unsigned int k = 0; k < vt_len; k++) {
						ea_t fncea = get_ea(obj->obj_ea + k * ea_size);
						if(is_func(get_flags(fncea))) {
							//filter out nullsubs
							func_t * f = get_func(fncea);
							if (f->empty())
								continue;
							fi.function_adjustments[fncea] = uval_t(delta) + fi.current_offset;
						}
					}
					is_ptr = true;
				}
			}
		}
	}

	int idaapi visit_expr(cexpr_t *e)
	{
		// varL = varR;
		if (e->op == cot_asg && e->x->op == cot_var && e->y->op == cot_var) {
			if(e->y->type == e->x->type) {//same type
				int lft_var_idx = e->x->v.idx;
				int rgt_var_idx = e->y->v.idx;
				bool left  = is_our(lft_var_idx);
				bool right = is_our(rgt_var_idx);
				bool swaped = false;
				if(left && !right) {
					std::swap(lft_var_idx, rgt_var_idx);
					swaped = true;
				}
				if(swaped || (!left && right)) {
					 idxs.insert(lft_var_idx);
					 offsets[lft_var_idx] = offset_for_var_idx(rgt_var_idx);
					 Log(llNotice, "scanning also var '%s'\n", (*lvars)[(size_t)lft_var_idx].name.c_str());
				}
			}
			return 0;
		}

		bool is_lvar = (e->op == cot_var && is_our(e->v.idx));
		bool is_glob_obj_ptr = (e->op == cot_obj && is_our(e->obj_ea));
		if(!is_lvar && !is_glob_obj_ptr)
			return 0;

		ea_t index = 0;
		if (is_lvar)
			index = e->v.idx;
		else
			index = e->obj_ea;

		// found our var. are we inside a pointer expression?
		bool is_ptr = false;
		bool is_array = false;
		uint64 delta = 0;
		uval_t cur_var_offset = offset_for_var_idx(index);
		bool delta_defined = true;

		int i = (int)parents.size() - 1;
		if(i >= 0 && parents[i]->op == cot_add) { // possible delta
			cexpr_t *d = ((cexpr_t*)parents[i])->theother(e);
			delta_defined = d->get_const_value(&delta);
			i--;
			if(i >= 0 && parents[i]->op == cot_add) {
				cexpr_t *d = ((cexpr_t*)parents[i])->theother((cexpr_t*)parents[i+1]);
				delta_defined = d->get_const_value(&delta);
				is_array = true;
				i--;
			}
		}

		tinfo_t tvtbl;
		handle_vtables(is_ptr, delta, i, tvtbl);

		if(!delta_defined)
			return 0;

		typerecord_t type;
		if(!tvtbl.empty()) {
			type.type = tvtbl;
			is_ptr = true;
		} else {
			while (i >= 0 && parents[i]->op == cot_cast) {
				type.type = ((cexpr_t*)parents[i])->type;
				i--;
			}
			is_ptr = type.type.is_ptr();
			type.type = remove_pointer(type.type);
		}

		//add_type
		scan_info_t &sif  = fi[uval_t(delta) + cur_var_offset];
		sif.is_array |= is_array;
		fi.update_max_offset(cur_var_offset, uval_t(delta) + cur_var_offset);
		if (!is_ptr || type.type.is_void()) {
			type.type.clear();
			type.type.create_simple_type(BT_INT8);
		}
		sif.types.add_unique(type);

		//check if parent is assign or call statement
		if(!is_ptr && i >= 0) {
			if (parents[i]->op == cot_asg ) {
				cexpr_t * ex = (cexpr_t *)parents[i];
				if ( ex->x->op == cot_var) {
					int new_var_idx = ex->x->v.idx;
					if(!is_our(new_var_idx)) {
						idxs.insert(new_var_idx);
						offsets[new_var_idx] = cur_var_offset + uval_t(delta);
						Log(llNotice, "scanning also var '%s' + %a\n", (*lvars)[(size_t)ex->x->v.idx].name.c_str(), uval_t(delta) );
					}
				}
			} else if (parents[i]->op == cot_call) {
				cexpr_t * call = (cexpr_t *)parents[i];
				if( call->x->op == cot_obj ) {
					ea_t fncea = call->x->obj_ea;
					if (is_func(get_flags(fncea))) {
						fi.function_adjustments[fncea] = uval_t(delta) + cur_var_offset;
						size_t idx;
						if (parents.size() == i + 1)
							idx = get_idx_of(call->a, (carg_t*)e);
						else
							idx = get_idx_of(call->a, (carg_t*)parents[i + 1]);
						argument_t a;
						a.arg_num  = (uval_t)idx;
						a.arg_cnt = (uval_t)call->a->size();
						fi.argument_numbers[fncea] = a;
						Log(llNotice, "consider also scanning func %a '%s' arg%u\n", fncea, get_name(fncea).c_str(), a.arg_num);
					}
				}
			}
		}
		return 0;
	}

	ptr_checker_t(ea_t i, lvars_t *vars) : lvars(vars)
	{
		idxs.insert(i);
	}
};

//-------------------------------------------------------------------------
static bool idx_for_struct_crawler(ctree_item_t & item, vdui_t &vu, ea_t & idx, bool & is_global)
{
	lvar_t * lvar =  item.get_lvar();
	idx = -1;
	if(lvar)
	{		
		idx = (ea_t)get_idx_of_lvar(vu, lvar);
		is_global = false;
		return true;
	}
	if (item.is_citem() && item.it->op == cot_obj)
	{
		citem_t * parent = vu.cfunc->body.find_parent_of(item.e);
		if (!parent)
			return false;
		if (parent->op == cot_call && ((cexpr_t*)parent)->x == item.e )
			return false;		
		idx = vu.item.e->obj_ea;
		is_global = true;
		return true;
	}
	return false;
}

bool can_be_converted_to_ptr(vdui_t &vu, bool bVarTesting)
{
	ctree_item_t & item = vu.item;
	cfunc_t *cfunc = vu.cfunc;
	ea_t varidx;
	bool is_global;
	if (!idx_for_struct_crawler(item, vu, varidx, is_global))
		return false;

	lvars_t * lvars = cfunc->get_lvars();
	if(!lvars)
		return false;

	if (!is_global) {
		lvar_t & lv = (*lvars)[(size_t)varidx] ;
		if ( lv.type().is_ptr() )
			return false; // already ptr
		if(lv.width != ea_size)
			return false;
	}
	if (!bVarTesting)
		return true;

	//TODO: check for global symbol at ea varidx
	if (is_global) {
		fi.global_pointers.add_unique(varidx);
		for(ea_t ea = get_first_dref_to(varidx); ea!=BADADDR; ea = get_next_dref_to(varidx, ea)) {
			func_t * fnc = get_func(ea);
			if(fnc)
				fi.function_adjustments[fnc->start_ea] = 0;
		}
	}

	function_adjustments_t::iterator i = fi.function_adjustments.find(cfunc->entry_ea) ;
	if ( i !=  fi.function_adjustments.end()) {
		if (i->second != fi.current_offset) {
			int answer = ask_yn(ASKBTN_NO, "[hrt] Do you want to set master offset to %d ? (instead of %d)", i->second, fi.current_offset);
			if (answer == ASKBTN_CANCEL)
				return false;
			if ( answer == ASKBTN_YES)
				fi.current_offset = i->second;
			else
				i->second = fi.current_offset;
		}
	} else {
		fi.function_adjustments[ cfunc->entry_ea ]  = fi.current_offset;
	}

	if (!is_global) {
		lvar_t & lv = (*lvars)[(size_t)varidx];
		Log(llNotice, "%a: scanning var '%s'\n", vu.cfunc->entry_ea, lv.name.c_str());
	} else {
		Log(llNotice, "%a: scanning glbl '%s'\n", vu.cfunc->entry_ea, get_short_name(varidx).c_str());
	}

	ptr_checker_t pc(varidx, lvars);
	pc.apply_to((citem_t*)&cfunc->body, NULL);
	pc.collect_scanned_vars(cfunc);
	for(scanned_variables_t::iterator p = fi.scanned_variables.begin(); p != fi.scanned_variables.end(); p++) {
		for(qvector<scanned_variable_t>::iterator x = p->second.begin(); x != p->second.end(); x++) {
			Log(llNotice, "%a: scanned var at defea: %a offset: %a\n", p->first, x->second.defea, x->first);
		}
	}
	if (fi.empty())
		return false;

	return true;
}

struct ida_local meminfo_t
{
	qstring name;
	uval_t offset;
	tinfo_t type;
	uval_t size;
};

bool field_info_t::to_type(tinfo_t& out_type, field_info_t::iterator* bgn, field_info_t::iterator* end_)
{
	qvector<meminfo_t> sti;

	field_info_t::iterator b = begin();
	field_info_t::iterator e = end();
	uval_t offset_delta = 0;
	if(bgn) {
		b = *bgn;
		offset_delta = b->first;
	}
	if(end_)
		e = *end_;

	uval_t off = 0;
	int minalign = inf_get_cc_defalign();
	if(minalign == 0)
		minalign = 1;

	//TODO: check second.nesting_counter;
	for (field_info_t::iterator p = b; p != e; ++p) {
		if ( p->first < off )
			continue; // skip overlapping fields

		tinfo_t t;
		if (!p->second.types.get_first_enabled(t))
			continue; //skip completely disabled fields

		meminfo_t &mi = sti.push_back();
		mi.offset = p->first - offset_delta;
		while ((mi.offset & (minalign-1)) != 0 &&  minalign)
			minalign >>= 1;
		mi.type = t;
		if (p->second.is_array) {
			field_info_t::iterator  q = p;
			bool enabled=false;
			while(!enabled && ++q != e) {
				tinfo_t tmp;
				enabled = q->second.types.get_first_enabled(tmp);
			}
			if (q != e)
				mi.type.create_array(mi.type, (uint32)((q->first - p->first)/t.get_size()));
		}
		mi.size = (uval_t)mi.type.get_size();
		mi.name.sprnt("field_%X", mi.offset);
		//mi.name += create_field_name(mi.type, (uval_t)mi.offset);

		off = (uval_t)(mi.offset + mi.size + offset_delta);
	}

	if(sti.empty())
		return false;

	// add_gaps
	{
		uval_t offset = 0;
		for (unsigned int i = 0; i < sti.size(); i++ ) {
			const meminfo_t &mi = sti[i];
			if ( mi.offset != offset ) {
				uval_t gapsize = mi.offset - offset;
				QASSERT(100301, gapsize < 0xffffffff);
				meminfo_t gap;
				gap.size = gapsize;
				gap.offset = offset;
				tinfo_t byteType;
				byteType.create_simple_type(BT_INT8);
				gap.type.create_array(byteType, (uint32)gapsize);
				gap.name.sprnt("gap%X", offset);
				sti.insert(sti.begin() + i, gap);
				offset += gapsize;
			} else {
				offset = mi.offset + mi.size;
			}
		}
	}

	tinfo_t restype;
	// build_struct_type
	// this functions assumes that the structure fields come one after another without gaps
	{
		udt_type_data_t dt;
		size_t total_size = 0;
		for (unsigned int i=0; i < sti.size(); i++ ) {
			const meminfo_t &mi = sti[i];
			udm_t member;
			member.name = mi.name;
			member.type = mi.type;
			member.offset = mi.offset * 8;
			member.size = mi.size * 8;
			dt.push_back(member);

			QASSERT(100302, mi.offset == total_size);
			total_size = mi.offset + mi.size;
		}
		dt.unpadded_size = dt.total_size = total_size;
		dt.effalign = 1;
		dt.taudt_bits = TAUDT_UNALIGNED;
		restype.create_udt(dt, BTF_STRUCT);
	}
	qstring tname;
	return confirm_create_struct(out_type, tname, restype, NULL);
}

bool field_info_t::flip_enabled_status(uval_t idx, uval_t position)
{
	if(size()==0)
		return false;
	field_info_t::iterator iter =  begin();
	if (iter == end())
		return false;
	if (!safe_advance(iter, end(), idx))
		return false;	

	scan_info_t& si = iter->second;
	if(si.types.size() > 0) {
		typevec_t::iterator iter1 = si.types.begin();
		if (!safe_advance(iter1, si.types.end(), position))
			return false;
		
		if(iter1->enabled) {
			iter1->enabled = false;
			++si.types.disabled_count;
		} else {
			iter1->enabled = true;
			--si.types.disabled_count;		
		}
	} else {
		this->erase(iter);
	}
	return true;
}

void field_info_t::clear()
{
	std::map<uval_t, scan_info_t>::clear();
	current_offset = 0;
	max_adjustments.clear();
	function_adjustments.clear();
	visited_functions.clear();	
	argument_numbers.clear();
	global_pointers.clear();
	scanned_variables.clear();
	types_cache.clear();
}

uval_t field_info_t::types_at_idx_qty(uval_t idx) const
{
	if(size() == 0)
		return 0;
	field_info_t::const_iterator iter =  begin();
	if(iter == end())
		return 0;
	if(!safe_advance(iter, end(), idx))
		return 0;	
	if(iter == end())
		return 0;
	return (uval_t)(iter->second).types.size();
}


void field_info_t::update_max_offset(uval_t current, uval_t max_)
{
	if(find(current) == end()) {
		max_adjustments[current] = max_;
	} else {
		uval_t lastmax = max_adjustments[current];
		max_adjustments[current] = std::max(lastmax, max_);
	}	
}

field_info_t fi;

