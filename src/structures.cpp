//Evolution of structures.cpp from https://github.com/nihilus/hexrays_tools
// + structures and classes related parts are moved here

#include "warn_off.h"
#include <hexrays.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>
#include <pro.h>
#include <auto.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "structures.h"
#include "rename.h"

//-------------------------------------------------------------------------
#if IDA_SDK_VERSION < 850
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
	struc_name = unique_name(struc_name.c_str(), "_obj", [](const qstring& n) { return get_name_ea(BADADDR, n.c_str()) == BADADDR; });

	tid_t newid = add_struc(idx+1, struc_name.c_str());
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
				Log(llWarning, "add_struc_member(%s, %s, %a) error %d\n", struc_name.c_str(), name.c_str(), off - delta, err);
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
#endif //IDA_SDK_VERSION < 850

//-------------------------------------------------------------------------
#if IDA_SDK_VERSION < 850
asize_t struct_get_member(tid_t strId, asize_t offset, tid_t* last_member, tidvec_t* trace, asize_t adjust)
{
	struc_t *str = get_struc(strId);
	if(!str)
		return 0;
	asize_t strctSz = get_struc_size(str);
	if (strctSz <= offset) {
		member_t* lm;
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
#else //IDA_SDK_VERSION < 850
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
#endif //IDA_SDK_VERSION < 850

bool struct_has_member(tid_t strId, asize_t offset)
{	
	tid_t last_member = BADNODE;
	return struct_get_member(strId, offset, &last_member) == 0 && last_member != BADNODE;
}

#if IDA_SDK_VERSION < 850
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
#endif //IDA_SDK_VERSION < 850

const int matched_structs_t::widths[] = { 40 };
const char* const matched_structs_t::header[] = { "Type" };
void idaapi matched_structs_t::get_row(qstrvec_t* cols_, int* icon_, chooser_item_attrs_t* attrs, size_t n) const
{
	// assert: n < list.size()
	qstrvec_t& cols = *cols_;
	get_tid_name(&cols[0], list[n]);
}

#if IDA_SDK_VERSION < 850
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

	//Log(llDebug, "%d, %d\n", place->idx, place->offset);
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
#endif // IDA_SDK_VERSION < 850

#if IDA_SDK_VERSION < 850
void add_vt_member(struc_t* sptr, ea_t offset, const char* name, const tinfo_t& type, ea_t ref)
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

	set_member_name(sptr, offset, good_smember_name(sptr, offset, name).c_str());
	member_t* memb = get_member(sptr, offset);
	set_member_tinfo(sptr, memb, 0, type, SET_MEMTI_COMPATIBLE);
	add_proc2memb_ref(ref, memb->id);
}

#else //IDA_SDK_VERSION >= 850

void add_vt_member(tinfo_t &struc, ea_t offset, const char* name, const tinfo_t &type, ea_t ref)
{
	udm_t udm;
	udm.offset = offset * 8;
	udm.size = (is64bit() && !isIlp32()) ? 8 * 8 : 4 * 8;
	udm.type = type;
	udm.name = good_udm_name(struc, udm.offset, name);
	tinfo_code_t err = struc.add_udm(udm, ETF_AUTONAME);
	int index = struc.find_udm(udm.offset);
	if (index < 0)
		return;
	if (err != TERR_OK) {
		// probably already exist
		struc.rename_udm(index, udm.name.c_str());
		struc.set_udm_type(index, udm.type);
	}
	tid_t tid = struc.get_udm_tid(index);
	if(tid != BADADDR)
		add_proc2memb_ref(ref, tid);
}
// member offset to func addr mapping to temporary store xrefs instead of add_proc2memb_ref cant be created for detached udt
typedef std::map<ea_t, ea_t, std::less<ea_t> > refmap_t;
#endif //IDA_SDK_VERSION < 850

tinfo_t type_by_tid(tid_t tid)
{
#if IDA_SDK_VERSION < 850
	qstring name_of_vt_struct = get_struc_name(tid);
	tinfo_t type = create_typedef(name_of_vt_struct.c_str());
#else //IDA_SDK_VERSION >= 850
	tinfo_t type;
	type.get_type_by_tid(tid);
#endif //IDA_SDK_VERSION < 850
	return type;
}

bool compare_struct(const tinfo_t& left, const tinfo_t& right)
{
	udt_type_data_t l, r;
	if(!left.get_udt_details(&l) || !right.get_udt_details(&r))
		return false;
	if(l.total_size != r.total_size ||
		l.unpadded_size != r.unpadded_size ||
		l.effalign != r.effalign ||
		l.taudt_bits != r.taudt_bits ||
		l.sda != r.sda ||
		l.pack != r.pack ||
		l.is_union != r.is_union ||
		l.size() != r.size())
		return false;

	for (size_t i = 0; i < l.size(); ++i) {
		const udm_t& lm = l.at(i);
		const udm_t& rm = r.at(i);
		if(lm.offset != rm.offset ||
			 lm.size != rm.size ||
			 lm.effalign != rm.effalign ||
			 lm.tafld_bits != rm.tafld_bits ||
			 lm.fda != rm.fda ||
			 lm.name != rm.name ||
			 //lm.cmt != rm.cmt ||
			 lm.type != rm.type)
			return false;
	}
	return true;
}

tid_t create_VT_struc(ea_t VT_ea, const char * basename, uval_t idx /*= BADADDR*/, unsigned int * vt_len /*= NULL*/, bool autoScan /*= false*/)
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
	name_vt += VTBL_SUFFIX;

	ea_t fncea = get_ea(VT_ea);
	if (!is_mapped(fncea)) {
		Log(llWarning, "scan VT at %a failed, !is_mapped(%a)\n", VT_ea, fncea);
		return BADADDR;
	}

	qstring struccmt;
	struccmt.sprnt("@0x%a", VT_ea);

	name_vt.rtrim('_'); // avoid names ending like "_12" to not exec name-to-type conversion
	name_vt = unique_name(name_vt.c_str(), "", [](const qstring& n) { return get_named_type_tid(n.c_str()) == BADADDR; });

	tid_t newid = BADADDR;
#if IDA_SDK_VERSION < 850
	newid = add_struc(idx, name_vt.c_str());
	if (newid == BADADDR) {
		Log(llError, "add_struc(%d, \"%s\") failed\n", idx, name_vt.c_str());
		return BADADDR;
	}
	struc_t * newstruc = get_struc(newid);
	if (!newstruc)
		return BADADDR;
	set_struc_cmt(newid, struccmt.c_str(), true);
	tinfo_t newType = type_by_tid(newid);
#else //IDA_SDK_VERSION >= 850
	tinfo_t newstruc;
	udt_type_data_t s;
	tinfo_code_t err = TERR_BAD_TYPE;
	s.taudt_bits |= TAUDT_UNALIGNED;
	s.effalign = 1;
	s.set_vftable(true);
	if (!newstruc.create_udt(s)) {
		Log(llError, "error %d (%s) on create vtbl stuct\n", err, tinfo_errstr(err));
		return BADADDR;
	}
	tinfo_t &newType = newstruc;
	refmap_t refmap;
#endif //IDA_SDK_VERSION >= 850

	ea_t ea = VT_ea;
	ea_t offset = 0;
	int len = 0;
	bool ok = true;
	while (1)
	{
		offset = ea - VT_ea;
		qstring funcname;
		ea_t fncea = get_ea(ea);

		//there are also no false pointers in vftables
		if (!is_mapped(fncea))
			break;

		flags64_t fnc_flags = get_flags(fncea);
		if(is_data(fnc_flags) || is_tail(fnc_flags)) {
			Log(llWarning, "%a: please check data bytes instead code in vtbl at %a\n", VT_ea, fncea);
			break;
		}

		if(is_unknown(fnc_flags) || (is_code(fnc_flags) && !is_func(fnc_flags)))
			auto_make_proc(fncea);

		if (!is_func(fnc_flags) || !get_func_name(&funcname, fncea)) //get_func_name returns mangled name
			funcname.sprnt("sub_%a", fncea);

		if(autoScan && funcname.find("purecall") != qstring::npos) {
			// do not create unnecessary union types for vtables. Wrong selection of union member may offends right virtual call target search
			Log(llDebug, "%a: ignore abstract class vtbl in auto-scan mode (\"%s\")\n", VT_ea, funcname.c_str());
			ok = false;
			newid = BADADDR;
			break;
		}

		tinfo_t t;
		if(get_tinfo(&t, fncea) && t.is_func()) {
			t = make_pointer(t);
		} else {
			t = dummy_ptrtype(0, false); //make_pointer & (get_int_type_by_width_and_sign | create_simple_type)
			Log(llDebug, "%a: set dummy ptr type for VTBL member \"%s\"\n", fncea, funcname.c_str());
		}

		add_vt_member(newstruc, offset, funcname.c_str(), t, fncea);
#if IDA_SDK_VERSION >= 850
		//for detached types proc2memb xrefs aren't created, store it in refmap
		refmap[offset] = fncea;
#endif

		len++;
		ea += ea_size;
		flags64_t ea_flags = get_flags(ea);
		if (has_any_name(ea_flags))
			break;
	}
	if (vt_len)
		*vt_len = len;

	if(ok && !len) {
		ok = false;
		newid = BADADDR;
		Log(llWarning, "%a: please check an empty vtbl\n", VT_ea);
	}
	if(ok) {
		// compare new struc with existing one to avoid duplicates
		tinfo_t oldType;
		if(get_tinfo(&oldType, VT_ea) && oldType.is_struct()) {
			if(compare_struct(oldType, newType)) { //if(oldType.compare_with(newType, TCMP_EQUAL)) { // always returns false
				ok = false;
				newid = BADADDR;
				qstring oldTname;
				if(oldType.get_type_name(&oldTname)) {
					newid = get_named_type_tid(oldTname.c_str());
					Log(llDebug, "%a: new VTBL struc type is equal to existing '%s'\n", VT_ea, oldTname.c_str());
				}
			} else {
				Log(llInfo, "%a create_VT_struc: existing type '%s' is not equal to current state '%s', updating\n", VT_ea, oldType.dstr(), newType.dstr());
			}
		}
	}

	if(!ok) {
#if IDA_SDK_VERSION < 850
		del_struc(newstruc);
		//del_named_type(nullptr, name_vt.c_str(), NTF_TYPE);
#endif //IDA_SDK_VERSION < 850
		return newid;
	}

#if IDA_SDK_VERSION >= 850
	// store type later to not produce deleted types
	err = newstruc.set_named_type(NULL, name_vt.c_str());
	if(err != TERR_OK) {
		Log(llError, "error %d (%s) on create vtbl stuct\n", err, tinfo_errstr(err));
		return BADADDR;
	}
	newstruc.set_type_cmt(struccmt.c_str());
	newid = newstruc.get_tid();
	uint32 ord = get_tid_ordinal(newid);
	// actually set_vftable_ea is appeared in ida 7.6 but here will be used from ida9 becouse it probably depends on TAUDT_VFTABLE flag has been set few lines above
	if(ord)
		set_vftable_ea(ord, VT_ea);

	// for detached types proc2memb xrefs aren't created
	for(auto ref : refmap) {
		int idx = newstruc.find_udm(ref.first * 8);
		if (idx >= 0) {
			tid_t tid = newstruc.get_udm_tid(idx);
			if(tid != BADADDR)
				add_proc2memb_ref(ref.second, tid);
		}
	}
	newType = newstruc;
#endif //IDA_SDK_VERSION >= 850

	name_vt.append('_');
	set_name(VT_ea, name_vt.c_str(), SN_FORCE);
	//VT_ea type should be set by set-type-on-rename on set_name above,
	//but in case of redefinition of incomplete VTBL it doesn't work because of checks is_userti(). So force it
	apply_tinfo(VT_ea, newType, TINFO_DEFINITE | TINFO_DELAYFUNC | TINFO_STRICT);
	return newid;
}

int create_VT(tid_t parent, ea_t VT_ea, bool autoScan/*= false*/)
{
	qstring name;
	uval_t vtstruc_idx = 0;
#if IDA_SDK_VERSION < 850
	struc_t * struc = get_struc(parent);
	if (!struc || !get_struc_name(&name, parent))
		return 0;
	vtstruc_idx = get_struc_idx(parent) + 1;
#else //IDA_SDK_VERSION >= 850
	tinfo_t struc;
	if (!struc.get_type_by_tid(parent)
		|| !struc.is_struct()
		|| !struc.get_type_name(&name))
		return 0;
#endif //IDA_SDK_VERSION < 850

	qstring name_VT = name + VTBL_SUFFIX;
	if(VT_ea == BADADDR)
		VT_ea = get_name_ea(BADADDR, name_VT.c_str());
	if (VT_ea == BADADDR) {
		name_VT = "??_7";
		name_VT += name + "@@6B@";
		VT_ea = get_name_ea(BADADDR, name_VT.c_str());
	}
	if (VT_ea == BADADDR) {
		Log(llError, "create_VT: bad VT_ea\n");
		return 0;
	}

	tid_t mtid = BADADDR;
	tinfo_t vtblType;
	eavec_t eav;
#if IDA_SDK_VERSION < 850
	member_t* vtbl = get_member(struc, 0);
	if(vtbl) {
		mtid = vtbl->id;
		if(get_member_tinfo(&vtblType, vtbl)) {
#else //IDA_SDK_VERSION >= 850
	udm_t vtbl;
	vtbl.offset = 0;
	int idx = struc.find_udm(&vtbl, STRMEM_AUTO);
	if (idx >= 0) {
		mtid = struc.get_udm_tid(idx);
		vtblType = vtbl.type;
		if (mtid != BADADDR) {
#endif //IDA_SDK_VERSION < 850
			vtblType.remove_ptr_or_array();
			get_memb2proc_refs(mtid, &eav);
			if(autoScan) {
				// disable update/duplicate VTBL creation in autoScan mode
				for(auto vtea: eav)
					if(vtea == VT_ea)
						return 0;
			}
		}
	}

	tid_t vt_struc_id = create_VT_struc(VT_ea, name.c_str(), vtstruc_idx, NULL, autoScan);
	if(vt_struc_id == BADADDR)
		return 0;

	switch (eav.size()) {
	case 0:
		// first VTBL adding, do nothing and fall down
		break;
	case 1:
		if (VT_ea == eav.front()) {
			// updating the existing VTBL, do nothing and fall down
			break;
		}	else {
			// second VTBL adding, create union
			udt_type_data_t utd;
			utd.is_union = true;
			size_t total_size = 0;
			for(int i = 0; i < 2; ++i) {
				udm_t& udm = utd.push_back();
				if (i == 0)
					udm.type = vtblType;
				else
					udm.type = type_by_tid(vt_struc_id);
				if(udm.type.get_type_name(&udm.name))
					udm.name.append('_');
				else
					udm.name.cat_sprnt("VT_%a", i == 0 ? eav.front(): VT_ea);
				size_t sz = udm.type.get_size();
				udm.size = sz * 8;
				if (sz > total_size)
					total_size = sz;
			}
			utd.unpadded_size = utd.total_size = total_size;
			tinfo_t utype;
			if (!utype.create_udt(utd, BTF_UNION)) {
				Log(llError, "create union for VTBLs error\n");
				return 0;
			}
			enable_numbered_types(nullptr, true);// is it need???
			uint32 ord = alloc_type_ordinal(nullptr);
			qstring utname("u"); utname.append(name_VT);
			utname = unique_name(utname.c_str(), "", [](const qstring& n) { return get_named_type_tid(n.c_str()) == BADADDR; });
			tinfo_code_t err = utype.set_numbered_type(nullptr, ord, 0, utname.c_str());
			if (err == TERR_OK) {
#if IDA_SDK_VERSION < 850
				import_type(get_idati(), vtstruc_idx, utname.c_str());
				smt_code_t e = set_member_tinfo(struc, vtbl, 0, make_pointer(utype), 0);
				if(e < SMT_OK) {
					Log(llError, "save or set union VTBLs type error %d on set_member_tinfo\n", e);
					return 0;
				} else {
#else //IDA_SDK_VERSION >= 850
				err = struc.set_udm_type(idx, make_pointer(utype));
				if (err == TERR_OK) {
#endif //IDA_SDK_VERSION < 850
					add_proc2memb_ref(VT_ea, mtid);
					return 1;
				}
			}
			Log(llError, "save or set union VTBLs type error %d %s\n", err, tinfo_errstr(err));
			return 0;
		}
		break;
	default:
		// add one more VTBL to union
		tinfo_code_t err = TERR_BAD_TYPE;
		if(vtblType.is_union()) {
#if IDA_SDK_VERSION < 850
			qstring utname;
			if(!vtblType.get_type_name(&utname)) {
				Log(llError, "adding %a to union VTBLs type error on get_type_name\n", VT_ea);
				return 0;
			}
			tid_t utid = get_struc_id(utname.c_str());
			if(utid == BADNODE) {
				Log(llError, "adding %a to union VTBLs type error on get_struc_id(%s)\n", VT_ea, utname.c_str());
				return 0;
			}
			struc_t* uts = get_struc(utid);
			if(!uts) {
				Log(llError, "adding %a to union VTBLs type error on get_struc(%a)\n", VT_ea, utid);
				return 0;
			}
			qstring fname;
			if(get_struc_name(&fname, vt_struc_id))
				fname.append('_');
			else
				fname.sprnt("VT_%a", VT_ea);
			opinfo_t oi; oi.tid = vt_struc_id;
			struc_error_t e = add_struc_member(uts, fname.c_str(), 0, stru_flag(), &oi, get_struc_size(vt_struc_id));
			if (e != STRUC_ERROR_MEMBER_OK) {
				Log(llError, "adding %s to union VTBLs type error %d on add_struc_member\n", fname.c_str(), e);
				return 0;
			} else {
#else //IDA_SDK_VERSION >= 850
			udm_t udm;
			udm.type = type_by_tid(vt_struc_id);
			if(udm.type.get_type_name(&udm.name))
				udm.name.append('_');
			else
				udm.name.cat_sprnt("VT_%a", VT_ea);
			udm.size = udm.type.get_size() * 8;
			err = vtblType.add_udm(udm, ETF_AUTONAME);
			if (err == TERR_OK) {
#endif //IDA_SDK_VERSION < 850
				add_proc2memb_ref(VT_ea, mtid);
				return 1;
			}
		}
		Log(llError, "adding to union VTBLs type error %d %s\n", err, tinfo_errstr(err));
		return 0;
	}
	
	//create or update first VTBL
	tinfo_t type = type_by_tid(vt_struc_id);
	add_vt_member(struc, 0, VTBL_MEMNAME, make_pointer(type), VT_ea);
	return 1;
}

void auto_create_vtbls(cfunc_t *cfunc)
{
	struct ida_local vtbl_assign_locator_t : public ctree_visitor_t
	{
		vtbl_assign_locator_t(): ctree_visitor_t(CV_FAST){}
		int idaapi visit_expr(cexpr_t * asg)
		{
			if(asg->op != cot_asg)
				return 0;

			cexpr_t *right = skipCast(asg->y);
			if(right->op == cot_ref)
				right = right->x;
			if (right->op != cot_obj)
				return 0;
			ea_t vtea = right->obj_ea;
			if(!is_mapped(get_ea(vtea)))
				return 0;

			cexpr_t *left = asg->x;
			if(left->op != cot_memptr && left->op != cot_memref)
				return 0;

			if(left->m != 0) // vtbl member at zero offset only!
				return 0;

			tinfo_t classType = left->x->type;
			classType.remove_ptr_or_array();
			if(!classType.is_struct())
				return 0;

			//do not overwrite well named first field, probably a wrong type was pushed to arg/var
			if(getUdtMembName(classType, 0, nullptr))
				return 0;

#if IDA_SDK_VERSION < 850
			qstring className;
			if(!classType.get_type_name(&className))
				return 0;
			tid_t tid = get_struc_id(className.c_str());
#else //IDA_SDK_VERSION >= 850
			tid_t tid = classType.get_tid();
#endif //IDA_SDK_VERSION < 850
			if(tid == BADADDR)
				return 0; //classType.force_tid()

			create_VT(tid, vtea, true);
			return 0; // ignore type changes (?)
			//return create_VT(tid, vtea, true);
		}
	};
	vtbl_assign_locator_t l;
	l.apply_to_exprs(&cfunc->body, nullptr);
}

qstring dummy_struct_name(size_t size, const char* sprefix);

bool confirm_create_struct(tinfo_t &out_type, qstring& strucname, tinfo_t &in_type, const char* sprefix)
{
	if(strucname.empty())
		strucname = dummy_struct_name(in_type.get_size(), sprefix);
	while(1) {
		qstring tdecl;
		if(!in_type.print(&tdecl, strucname.c_str(), PRTYPE_MULTI | PRTYPE_TYPE | PRTYPE_PRAGMA | PRTYPE_SEMI, 5, 40, NULL, NULL))
			return false;

		if(!ask_text(&tdecl, 0, tdecl.c_str(), "[hrt] The following new type %s will be created", strucname.c_str()))
			return false;

		tinfo_t new_type;
		if (!parse_decl(&new_type, &strucname, NULL, tdecl.c_str(), PT_TYP))
			continue;

		tinfo_code_t err = new_type.set_named_type(NULL, strucname.c_str(), NTF_TYPE);
		if (TERR_OK != err) {
			qstring hint;
			if(err == TERR_SAVE_ERROR)
				hint = dummy_struct_name(0, strucname.c_str());

			warning("[hrt] Could not create '%s' (error %d %s) try '%s'", strucname.c_str(), err, tinfo_errstr(err), hint.c_str());
			if(err == TERR_SAVE_ERROR)
				strucname = hint;
			continue;
		}
#if IDA_SDK_VERSION < 850
		import_type(get_idati(), -1, strucname.c_str());
#endif //IDA_SDK_VERSION < 850
		break;
	}
	out_type = create_typedef(strucname.c_str());
	return true;
}

//-------------------------------------------------------------------------
//these data xrefs works as just a cache, search by VTBL and name still supported

bool add_proc2memb_ref(ea_t proc, tid_t memb)
{
	return add_dref(proc, memb, (dref_t)(dr_I | XREF_USER));
}

void get_proc2memb_refs(ea_t proc, tidvec_t* membs)
{
	xrefblk_t x;
	if(x.first_from(proc, XREF_DATA)) do {
		if(x.user && x.type == dr_I && !is_mapped(x.to))
			membs->push_back(x.to);
	} while(x.next_from());
}

void get_memb2proc_refs(tid_t memb, eavec_t* eav)
{
	xrefblk_t x;
	if (x.first_to(memb, XREF_DATA)) do {
		if (x.user && x.type == dr_I && is_mapped(x.from))
			eav->push_back(x.from);
	} while (x.next_to());
}

#if IDA_SDK_VERSION < 850
ea_t get_memb2proc_ref(struc_t* s, member_t *m)
{
	tid_t mtid = m->id;
#else
ea_t get_memb2proc_ref(tinfo_t& s, uint32 offInBytes)
{
	tid_t mtid;
	udm_t memb;
	memb.offset = offInBytes;
	int index = s.find_udm(&memb, STRMEM_AUTO);
	if(index < 0 || (mtid = s.get_udm_tid(index)) == BADADDR) {
		Log(llError, "get_memb2proc_ref no memb tid at offset 0x%x in %s\n", offInBytes, s.dstr());
		return BADADDR;
	}
#endif

	//search in cache, for now it can be only one member to proc ref on the member
	eavec_t eav;
	ea_t dstEA = BADADDR;
	get_memb2proc_refs(mtid, &eav);
	if (eav.size() && (dstEA = eav.front()) != BADADDR && is_func(get_flags(dstEA)))
		return dstEA;

	//find target proc and add ref to it
	ea_t vt_ea;
	qstring struCmt;
#if IDA_SDK_VERSION < 850
	if (get_struc_cmt(&struCmt, s->id, true) > 0 && at_atoea(struCmt.c_str(), &vt_ea)) {
		dstEA = get_ea(vt_ea + m->get_soff());
	} else {
		qstring mname = get_member_name(m->id);
		stripName(&mname);
		dstEA = get_name_ea(BADADDR, mname.c_str());
	}
#else
	// actually get_vftable_ea is appeared in ida 7.6 but here will be used from ida9 because it probably depends on TAUDT_VFTABLE flag has been set in create_VT_struc
	// get destination from vftable_ea
	tid_t stid = s.get_tid();
	if(stid != BADADDR) {
		uint32 ord = get_tid_ordinal(stid);
		if(ord) {
			vt_ea = get_vftable_ea(ord); // in ida9.0 - 9.1 returns zero instead BADADDR
			if(vt_ea != 0 && vt_ea != BADADDR)
				dstEA = get_ea(vt_ea + offInBytes);
		}
	}
	if(dstEA == BADADDR && s.get_type_rptcmt(&struCmt) && at_atoea(struCmt.c_str(), &vt_ea)) {
		dstEA = get_ea(vt_ea + offInBytes);
	}
	if(dstEA == BADADDR) {
		qstring mname = memb.name.c_str();
		stripName(&mname);
		dstEA = get_name_ea(BADADDR, mname.c_str());
	}
	Log(llDebug, "get_memb2proc_ref: dstEA %a for %s.%s\n", dstEA, s.dstr(), memb.name.c_str());
#endif //IDA_SDK_VERSION < 850

	if(dstEA != BADADDR && is_func(get_flags(dstEA))) {
		add_proc2memb_ref(dstEA, mtid);
		return dstEA;
	}
	return BADADDR;
}
