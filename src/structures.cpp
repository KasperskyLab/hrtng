//Evolution of structures.cpp from https://github.com/nihilus/hexrays_tools
// + structures and classes related parts are moved here

#include "warn_off.h"
#include <hexrays.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <pro.h>
#include "warn_on.h"

#include "helpers.h"
#include "structures.h"

//-------------------------------------------------------------------------
#if IDA_SDK_VERSION < 900
#define AST_ENABLE_FOR_ME return ((ctx->widget_type == BWN_STRUCTS) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET)
ACT_DECL(extract_substruct_callback, AST_ENABLE_FOR_ME)
ACT_DECL(unpack_this_member_callback, AST_ENABLE_FOR_ME)
ACT_DECL(which_struct_matches_here_callback, AST_ENABLE_FOR_ME)
ACT_DECL(create_VT_callback, AST_ENABLE_FOR_ME)
#undef AST_ENABLE_FOR_ME

static const action_desc_t actions[] =
{
	ACT_DESC("[hrt] Extract substruct", NULL, extract_substruct_callback),
	ACT_DESC("[hrt] Unpack substruct", NULL, unpack_this_member_callback),
	ACT_DESC("[hrt] Which struct matches here?", NULL, which_struct_matches_here_callback),
	ACT_DESC("[hrt] Add VT", NULL, create_VT_callback)
};

void structs_reg_act()
{
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		register_action(actions[i]);
}

void structs_unreg_act()
{
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		unregister_action(actions[i].name);
}

void add_structures_popup_items(TWidget *view, TPopupMenu *p)
{
	attach_action_to_popup(view, p, ACT_NAME(extract_substruct_callback));
	attach_action_to_popup(view, p, ACT_NAME(unpack_this_member_callback));
	attach_action_to_popup(view, p, ACT_NAME(which_struct_matches_here_callback));
	attach_action_to_popup(view, p, ACT_NAME(create_VT_callback));
}
//-------------------------------------------------------------------------

int extract_substruct(uval_t idx, uval_t begin, uval_t end)
{
	tid_t id = get_struc_by_idx( idx );
	if (is_union(id))
		return 0;
	struc_t * struc = get_struc(id);
	if(!struc)
		return 0;

	qstring struc_name;
	get_struc_name(&struc_name, id);

	qstring new_struc_name;
	const char *nsn = NULL;
	int i = 1;
	do {
		new_struc_name = struc_name;
		new_struc_name.cat_sprnt("_obj_%d",i);
		i++;
	} while ((get_name_ea(BADADDR, new_struc_name.c_str()) != BADADDR) && i < 100);

	if (i < 100)
		nsn = new_struc_name.c_str();

	tid_t newid = add_struc(idx+1, nsn);
	struc_t * newstruc = get_struc(newid);
	asize_t delta = begin;
	asize_t off = begin;
	while(off < end) {
		member_t * member = get_member(struc, off);
		if(member) {
			qstring name = get_member_name(member->id);
			opinfo_t mt;
			retrieve_member_info(&mt, member);

			asize_t size = get_member_size(member);
			struc_error_t err = add_struc_member(newstruc, name.c_str(), off - delta, member->flag, &mt, size);
			if (err != STRUC_ERROR_MEMBER_OK) {
				msg("[hrt] add_struc_member(%s, %s, %a) error %d\n", new_struc_name.c_str(), name.c_str(), off - delta, err);
			}

			tinfo_t type;
			if(get_or_guess_member_tinfo(&type, member)) {
				member_t * newmember = get_member(newstruc, off-delta);
				set_member_tinfo(newstruc, newmember, 0, type, SET_MEMTI_COMPATIBLE /*| SET_MEMTI_MAY_DESTROY*/);
			}
		}
		off = get_struc_next_offset(struc, off);
	}

	//reset original member type
	tinfo_t type;
	qstring qname;
	qstring tmpname2;
	get_struc_name(&tmpname2, newid);
	tmpname2 += " dummy;";
	parse_decl(&type, &qname, NULL, tmpname2.c_str(),  PT_VAR);
	member_t * member = get_member(struc, begin);
	set_member_tinfo(struc, member, 0, type, SET_MEMTI_MAY_DESTROY);
	return 1;
}
#endif //IDA_SDK_VERSION < 900

//-------------------------------------------------------------------------
#if IDA_SDK_VERSION < 900
asize_t struct_get_member(tid_t strId, asize_t offset, tid_t* last_member, tidvec_t* trace, asize_t adjust)
{
	struc_t *str = get_struc(strId);
	if(!str)
		return 0;
	asize_t strctSz = get_struc_size(str);
	if (strctSz <= offset) {
		member_t* lm = get_member_by_id(*last_member);
		if (*last_member != BADNODE && (lm = get_member_by_id(*last_member)) != NULL && strctSz < lm->eoff - lm->get_soff()) {
			//Struct size not greater then offset. This possible then last_member is array of structs. Adjust offset
			asize_t newoff = offset % strctSz;
			adjust += offset - newoff;
			offset = newoff;
		} else {
			return offset + adjust;
		}
	}

	member_t * member = get_member(str, offset);	
	if (!member)
		return offset + adjust;
	*last_member = member->id;

#if 1// dont dive into substruct to check first member, returns struct
	if (member->get_soff() == offset) {
		if (trace)
			trace->push_back(member->id);
		return adjust;
	}
#endif
	struc_t * membstr = get_sptr(member);
	if (!membstr) {
#if 0 // this variant dives into substruct to check first member of substruct
		if (member->get_soff() == offset) {
			if (trace)
				trace->push_back(member->id);
			return adjust;
		}
#endif
		*last_member = BADNODE; // offset is in the middle of member
		return offset + adjust;
	}

	if (trace)
		trace->push_back(member->id);
	return struct_get_member(membstr->id, offset - member->get_soff(), last_member, trace);
}
#else //IDA_SDK_VERSION < 900
asize_t struct_get_member(tid_t strId, asize_t offset, tid_t* last_member, tidvec_t* trace, asize_t adjust)
{
	tinfo_t str;
	if (strId == BADNODE || !str.get_type_by_tid(strId) || !str.is_struct()) {
		*last_member = BADNODE;
		return -1;
	}
	asize_t strctSz = str.get_size();
	if (strctSz <= offset) {
		tinfo_t tms;
		udm_t udm;
		if (*last_member != BADNODE && tms.get_udm_by_tid(&udm, *last_member) != -1 && strctSz < udm.size / 8) {
			//Struct size not greater then offset. This possible then last_member is array of structs. Adjust offset
			asize_t newoff = offset % strctSz;
			adjust += offset - newoff;
			offset = newoff;
		}	else {
			return offset + adjust;
		}
	}

	udm_t member;
	member.offset = offset; // in bytes for STRMEM_AUTO
	int midx = str.find_udm(&member, STRMEM_AUTO);
	if (-1 == midx)
		return offset + adjust;
	*last_member = str.get_udm_tid(midx);

#if 1// dont dive into substruct to check first member, returns struct
	if (member.offset == offset * 8) {
		if (trace)
			trace->push_back(*last_member);
		return adjust;
	}
#endif
	tid_t tmsid = BADNODE;
	if (member.type.is_struct()) {
		tmsid = member.type.get_tid();
	}	else if (member.type.is_array()) {
		tinfo_t arrItem = member.type.get_ptrarr_object();
		if(arrItem.is_struct())
			tmsid = arrItem.get_tid();
	}
	if (tmsid == BADNODE) {
#if 0 // this variant dives into substruct to check first member of substruct
		if (member.offset == offset * 8) {
			if (trace)
				trace->push_back(*last_member);
			return adjust;
		}
#endif
		*last_member = BADNODE; // offset is in the middle of member
		return offset + adjust;
	}

	if (trace)
		trace->push_back(*last_member);
	return struct_get_member(tmsid, offset - member.offset / 8, last_member, trace);
}
#endif //IDA_SDK_VERSION < 900

bool struct_has_member(tid_t strId, asize_t offset)
{	
	tid_t last_member = BADNODE;
	return struct_get_member(strId, offset, &last_member) == 0 && last_member != BADNODE;
}

#if IDA_SDK_VERSION < 900
bool print_struct_member_name(tid_t strId, asize_t offset, qstring * name, bool InRecur)
{
	struc_t *str = get_struc(strId);
	if(!str)
		return false;
	member_t * member = get_member(str, offset);
	if (member) {
		if (member->get_soff() == offset) {
			if (InRecur)
				get_member_name(name, member->id);
			else
				get_member_fullname(name, member->id);
			return true;
		}

		struc_t * membstr = get_sptr(member);
		if (membstr) {
			qstring subname;
			if (InRecur)
				get_member_name(name, member->id);
			else {
				get_struc_name(name, str->id);
				name->append('.');
				get_member_name(&subname, member->id);
				name->append(subname);
			}
			if (print_struct_member_name(membstr->id, offset - member->get_soff(), &subname, true)) {
				name->append('.');
				name->append(subname);
				return true;
			}
		}
	}
	if (!InRecur) {
		get_struc_name(name, str->id);
		name->cat_sprnt(" + 0x%x", offset);
	}
	return false;
}
bool print_struct_member_type(tid_t membId, qstring *tname)
{
	member_t* member = get_member_by_id(membId);
	tinfo_t type;
	if(member && get_member_type(member, &type))
		return type.print(tname);
	return false;
}
#else
bool print_struct_member_name(tid_t strId, asize_t offset, qstring * name, bool InRecur)
{
	tinfo_t str;
	if (strId == BADNODE || !str.get_type_by_tid(strId) || !str.is_struct())
		return false;
	udm_t member;
	member.offset = offset; // in bytes for STRMEM_AUTO
	int midx = str.find_udm(&member, STRMEM_AUTO);
	if(midx >= 0) {
		if(member.offset == offset * 8) {
			if (InRecur) {
				*name = member.name;
			} else {
				str.get_type_name(name);
				name->append('.');
				name->append(member.name);
			}
			return true;
		}

		tid_t tmsid = BADNODE;
		if (member.type.is_struct()) {
			tmsid = member.type.get_tid();
		}	else if (member.type.is_array()) {
			tinfo_t arrItem = member.type.get_ptrarr_object();
			if(arrItem.is_struct())
				tmsid = arrItem.get_tid();
		}

		if (tmsid != BADNODE) {
			if (InRecur)
				*name = member.name;
			else {
				str.get_type_name(name);
				name->append('.');
				name->append(member.name);
			}
			qstring subname;
			if (print_struct_member_name(tmsid, offset - member.offset/8, &subname, true)) {
				name->append('.');
				name->append(subname);
				return true;
			}
		}
	}
	if (!InRecur) {
		get_tid_name(name, strId);
		name->cat_sprnt(" + 0x%x", offset);
	}
	return false;
}
bool print_struct_member_type(tid_t membId, qstring *tname)
{
	udm_t udm;
	tinfo_t imembStrucType;
	ssize_t imembIdx = imembStrucType.get_udm_by_tid(&udm, membId);
	if(imembIdx >= 0)
		return udm.type.print(tname);
	return false;
}
#endif //IDA_SDK_VERSION < 900

const int matched_structs_t::widths[] = { 40 };
const char* const matched_structs_t::header[] = { "Type" };
void idaapi matched_structs_t::get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attrs, size_t n) const
{
	// assert: n < list.size()
	qstrvec_t& cols = *cols_;
	get_tid_name(&cols[0], list[n]);
}

#if IDA_SDK_VERSION < 900
//----------------------------------------------------
bool compare_structs(struc_t * str1, asize_t begin, struc_t * str2)
{
	asize_t off = 0;
	while (off != BADADDR)
	{
		member_t * member2 = get_member(str2, off);
		member_t * member1 = get_member(str1, off + begin);
		if (!member2)
			break;
		if (!member1)
			return false;
		if (member1->get_soff() != off + begin)
			return false;
		if (get_member_size(member1) != get_member_size(member2))
			return false;
		off = get_struc_next_offset(str2, off);
	}
	return true;
}

int which_struct_matches_here(uval_t idx1, uval_t begin, uval_t end)
{
	tid_t id = get_struc_by_idx(idx1);
	if (is_union(id))
		return 0;

	struc_t * struc = get_struc(id);
	if(!struc)
		return 0;

	uval_t last = get_struc_prev_offset(struc, end);
	if(last == BADADDR || last > end)
		return 0;

	asize_t size = last + get_member_size(get_member(struc, last)) - begin;
	matched_structs_t m;	
	for(uval_t idx = get_first_struc_idx(); idx!=BADNODE; idx=get_next_struc_idx(idx)) {
		tid_t id = get_struc_by_idx(idx);
		struc_t * struc_candidate = get_struc(id);
		if(!struc_candidate)
			continue;
		if(is_union(id))
			continue;
		if(get_struc_size(struc_candidate) != size)
			continue;
		if(compare_structs(struc, begin, struc_candidate))
			m.list.push_back(id);
	}
	ssize_t choosed = m.choose();	
	if(choosed >= 0)
		open_structs_window(m.list[choosed], 0);
	return 0;
}

int unpack_this_member(uval_t idx, uval_t offset)
{
	tid_t id = get_struc_by_idx( idx );
	if(is_union(id))
		return 0;

	struc_t * struc = get_struc(id);
	if(!struc)
		return 0;

	member_t * member = get_member( struc, offset);
	if (!member || member->get_soff() != offset)
		return 0;

	struc_t * membstr = get_sptr(member);
	if(!membstr)
		return 0;

	if (is_union(membstr->id))
		return 0;

	asize_t delta = offset;
	asize_t off = 0;
	asize_t end = get_struc_size(membstr);
	del_struc_member(struc, offset);
	while(off <= end) {
		member_t * member = get_member(membstr, off);
		if(member) {
			qstring name = get_member_name(member->id);
			opinfo_t mt;
			retrieve_member_info(&mt, member);

			asize_t size = get_member_size(member);			
			add_struc_member(struc, name.c_str(), off + delta, member->flag, &mt, size);
			
			tinfo_t type;
			if(get_or_guess_member_tinfo(&type, member))
			{
				member_t * newmember = get_member(struc, off + delta);
				set_member_tinfo(struc, newmember, 0, type, /*SET_MEMTI_COMPATIBLE | */SET_MEMTI_MAY_DESTROY);
			}
		}
		off = get_struc_next_offset(membstr, off);
	}
	return 1;
}

ACT_DEF(extract_substruct_callback)
{
	if (ctx->has_flag(ACF_HAS_SELECTION) && get_viewer_place_type(ctx->widget) == TCCPT_STRUCTPLACE) {
		structplace_t * sb = (structplace_t *)ctx->cur_sel.from.at;
		structplace_t * se = (structplace_t *)ctx->cur_sel.to.at;
		if (sb->idx == se->idx && extract_substruct(sb->idx, sb->offset, se->offset)) {
			unmark_selection();
			return 1;
		}
	}
	warning("[hrt] Please select part of structure to extract substruct\n");
	return 0;
}

ACT_DEF(unpack_this_member_callback)
{
	if(get_viewer_place_type(ctx->widget) != TCCPT_STRUCTPLACE)
		return 0;
	structplace_t * place;
	int x, y;
	place = (structplace_t *)get_custom_viewer_place(ctx->widget, false, &x, &y);
	if (!place)
		return 0;

	//msg("%d, %d\n", place->idx, place->offset);
	return unpack_this_member(place->idx, place->offset);
}


ACT_DEF(which_struct_matches_here_callback)
{
	if (ctx->has_flag(ACF_HAS_SELECTION) && get_viewer_place_type(ctx->widget) == TCCPT_STRUCTPLACE) {
		structplace_t * sb = (structplace_t *)ctx->cur_sel.from.at;
		structplace_t * se = (structplace_t *)ctx->cur_sel.to.at;
		if (sb->idx == se->idx)
			return which_struct_matches_here(sb->idx, sb->offset, se->offset);
	}
	warning("[hrt] Please select part of structure to match substruct\n");
	return 0;
}

ACT_DEF(create_VT_callback)
{
	structplace_t* place;
	int x, y;
	place = (structplace_t*)get_custom_viewer_place(ctx->widget, false, &x, &y);
	if (!place)
		return false;

	return create_VT(get_struc_by_idx(place->idx), BADADDR);
}
#endif // IDA_SDK_VERSION < 900

#if IDA_SDK_VERSION < 900
void add_vt_member(struc_t* sptr, ea_t offset, const char* name, const tinfo_t& type, const char* comment)
{
	flags64_t flag;
	asize_t nbytes;
	if(is64bit()) {
		flag = qword_flag();
		nbytes = 8;
	} else {
		flag = dword_flag();
		nbytes = 4;
	}
	add_struc_member(sptr, NULL, offset, flag, NULL, nbytes); //ifnore error, member may exists

	if (!set_member_name(sptr, offset, name)) {
		for (int i = 1; i < 100; i++) {
			qstring newName = name;
			newName.cat_sprnt("_%d", i);
			if (!get_member_by_name(sptr, newName.c_str())) {
				set_member_name(sptr, offset, newName.c_str());
				break;
			}
		}
	}
	member_t* memb = get_member(sptr, offset);
	set_member_tinfo(sptr, memb, 0, type, SET_MEMTI_COMPATIBLE);
	set_member_cmt(memb, comment, true);
}

#else //IDA_SDK_VERSION >= 900

void add_vt_member(tinfo_t &struc, ea_t offset, const char* name, const tinfo_t &type, const char* comment)
{
	udm_t udm;
	udm.offset = offset * 8;
	udm.size = is64bit() ? 8 * 8 : 4 * 8;
	udm.type = type;
	udm.name = good_udm_name(struc, name);
	udm.cmt = comment;
	if (struc.add_udm(udm, ETF_AUTONAME) != TERR_OK) {
		// probably already exist
		int index = struc.find_udm(udm.offset);
		if (index < 0)
			return;
		struc.rename_udm(index, udm.name.c_str());
		struc.set_udm_type(index, udm.type);
		struc.set_udm_cmt(index, comment);
	}
}
#endif //IDA_SDK_VERSION < 900

tid_t create_VT_struc(ea_t VT_ea, const char * basename, uval_t idx /*= BADADDR*/, unsigned int * vt_len /*= NULL*/)
{
	qstring name_vt(basename);
	if (!basename) {
		if(has_user_name(get_flags(VT_ea))) {
			name_vt = get_name(VT_ea);
			if(name_vt.length() > 9 && !strncmp(name_vt.c_str(), "??_7", 4)) {
				//remove everything except main class name
				name_vt.remove(0, 4);
				name_vt = name_vt.substr(0, name_vt.find("@@6B"));
			}
			if(!strnicmp(name_vt.c_str(), "vtbl_", 5))
				name_vt.remove(0, 5);
			name_vt.remove(name_vt.find(VTBL_SUFFIX "_"), 6);
			if(name_vt[0] >= '0' && name_vt[0] <= '9')
				name_vt.insert(0, '_');
		} else {
			name_vt.sprnt("_%a", VT_ea);
		}
	}
	qstring name_VT_ea = name_vt;
	name_VT_ea += VTBL_SUFFIX "_";
	name_vt += VTBL_SUFFIX;

	{//TODO: do this better
		ea_t fncea = get_ea(VT_ea);
		flags64_t fnc_flags = get_flags(fncea);
		if (!is_func(fnc_flags)) {
			msg("[hrt] scan VT at %a failed, !is_func(%a)\n", VT_ea, fncea);
			return BADNODE;
		}
	}

	qstring struccmt;
	struccmt.sprnt("@0x%a", VT_ea);

#if IDA_SDK_VERSION < 900
	tid_t newid = get_struc_id(name_vt.c_str());
	if (newid != BADADDR) {
		warning("[hrt] struct '%s' already exist,\n rename VTBL global name or remove/rename conflicting type and try again\n", name_vt.c_str());
		return BADNODE;
	}
		newid = add_struc(idx, name_vt.c_str());
	if (newid == BADADDR) {
		msg("[hrt] add_struc(%d, \"%s\") failed\n", idx, name_vt.c_str());
		return BADNODE;
	}

	struc_t * newstruc = get_struc(newid);
	if (!newstruc)
		return BADNODE;
	set_struc_cmt(newid, struccmt.c_str(), true);
#else //IDA_SDK_VERSION >= 900
	tid_t newid = get_named_type_tid(name_vt.c_str());
	if (newid != BADADDR) {
		warning("[hrt] type '%s' already exist,\n rename VTBL global name or remove/rename conflicting type and try again\n", name_vt.c_str());
		return BADNODE;
	}

	tinfo_t newstruc;
		udt_type_data_t s;
	tinfo_code_t err = TERR_BAD_TYPE;
		s.taudt_bits |= TAUDT_UNALIGNED;
		s.set_vftable(true);
	if (!newstruc.create_udt(s) || (err = newstruc.set_named_type(NULL, name_vt.c_str())) != TERR_OK) {
		msg("[hrt] error %d (%s) on create vtbl stuct\n", err, tinfo_errstr(err));
			return BADNODE;
	}
	newid = newstruc.get_tid();
	newstruc.set_type_cmt(struccmt.c_str());

	// actually set_vftable_ea is appeared in ida 7.6 but here will be used from ida9 becouse it probably depends on TAUDT_VFTABLE flag has been set few lines above
	uint32 ord = get_tid_ordinal(newid);
	if(ord)
		set_vftable_ea(ord, VT_ea);
#endif //IDA_SDK_VERSION >= 900
	set_name(VT_ea, name_VT_ea.c_str(), SN_FORCE);

	ea_t ea = VT_ea;
	ea_t offset = 0;
	int len = 0;
	while (1)
	{
		offset = ea - VT_ea;
		qstring funcname;
		ea_t fncea = get_ea(ea);

		//there are no holes in vftables (I hope)
		if (fncea == 0)
			break;
		//there are also no false pointers in vftables
		if (!is_mapped(fncea))
			break;

		flags64_t fnc_flags = get_flags(fncea);
		if(is_data(fnc_flags))
			break;

		if (!is_func(fnc_flags) || !get_func_name(&funcname, fncea)) //get_func_name returns mangled name
			if(!get_ea_name(&funcname, fncea))
				funcname.sprnt("func_%a", fncea);

		tinfo_t t;
		if(get_tinfo(&t, fncea) && t.is_func()) {
			t = make_pointer(t);
		} else {
			t = dummy_ptrtype(0, false); //make_pointer & (get_int_type_by_width_and_sign | create_simple_type)
			msg("[hrt] %a: set dummy ptr type for VTBL member \"%s\"\n", fncea, funcname.c_str());
		}

		qstring cmt;
		cmt.sprnt("0x%a", fncea);
		add_vt_member(newstruc, offset, funcname.c_str(), t, cmt.c_str());

		len++;
		ea += ea_size;
		flags64_t ea_flags = get_flags(ea);
		if (has_any_name(ea_flags))
			break;
	}
	if (vt_len)
		*vt_len = len;

	return newid;
}

int create_VT(tid_t parent, ea_t VT_ea)
{
	qstring name;
	uval_t vtstruc_idx = 0;
#if IDA_SDK_VERSION < 900
	struc_t * struc = get_struc(parent);
	if (!struc || !get_struc_name(&name, parent))
		return 0;
	vtstruc_idx = get_struc_idx(parent) + 1;
#else //IDA_SDK_VERSION >= 900
	tinfo_t struc;
	if (!struc.get_type_by_tid(parent)
		|| !struc.is_struct()
		|| !struc.get_type_name(&name))
		return 0;
#endif //IDA_SDK_VERSION < 900

	qstring name_VT = name + VTBL_SUFFIX;
	if(VT_ea == BADADDR)
		VT_ea = get_name_ea(BADADDR, name_VT.c_str());

	if (VT_ea == BADADDR) {
		name_VT = "??_7";
		name_VT += name + "@@6B@";
		VT_ea = get_name_ea(BADADDR, name_VT.c_str());
	}

	if (VT_ea == BADADDR) {
		msg("[hrt] create_VT: bad VT_ea\n");
			return 0;
	}

	tid_t vt_struc_id = create_VT_struc(VT_ea, name.c_str(), vtstruc_idx);
	if ( vt_struc_id == BADNODE)
		return 0;

#if IDA_SDK_VERSION < 900
	qstring name_of_vt_struct = get_struc_name(vt_struc_id);
	tinfo_t type = create_typedef(name_of_vt_struct.c_str());
#else //IDA_SDK_VERSION >= 900
	tinfo_t type;
	type.get_type_by_tid(vt_struc_id);
#endif //IDA_SDK_VERSION < 900
	type = make_pointer(type);
	add_vt_member(struc, 0, VTBL_MEMNAME, type, NULL);
	return 1;
}

qstring dummy_struct_name(size_t size, const char* sprefix);

bool confirm_create_struct(tinfo_t &out_type, tinfo_t &in_type, const char* sprefix)
{
	qstring strucname = dummy_struct_name(in_type.get_size(), sprefix);
	qstring in_type_decl;
	if(!in_type.print(&in_type_decl, strucname.c_str(), PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_PRAGMA | PRTYPE_SEMI, 5, 40, NULL, NULL)
		 || in_type_decl.empty())
		return false;

	qstring answer = in_type_decl;
	while(1)
	{
		if(!ask_text(&answer, 0, in_type_decl.c_str(), "[hrt] The following new type %s will be created", strucname.c_str()))
			return false;

		tinfo_t new_type;
		if (!parse_decl(&new_type, &strucname, NULL, answer.c_str(), PT_TYP))
			continue;

		tinfo_code_t err = new_type.set_named_type(NULL, strucname.c_str(), NTF_TYPE);
		if (TERR_OK != err) {
			warning("[hrt] Could not create %s, maybe it already exists? (tinfo_code_t = %d)", strucname.c_str(), err);
			continue;
		}
#if IDA_SDK_VERSION < 900
		import_type(get_idati(), -1, strucname.c_str());
#endif //IDA_SDK_VERSION < 900
		break;
	}
	out_type = create_typedef(strucname.c_str());
	return true;
}

