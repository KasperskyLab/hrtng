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
asize_t struct_get_member(tid_t strId, asize_t offset, tid_t* last_member, tidvec_t* trace, asize_t adjust)
{
	struc_t *str = get_struc(strId);
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

	struc_t * membstr = get_sptr(member);
	if (!membstr) {
		if (member->get_soff() == offset) {
			if (trace)
				trace->push_back(member->id);
			return adjust;
		}
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

	tid_t tmsid = BADNODE;
	if (member.type.is_struct()) {
		tmsid = member.type.get_tid();
	}	else if (member.type.is_array()) {
		tinfo_t arrItem = member.type.get_ptrarr_object();
		if(arrItem.is_struct())
			tmsid = arrItem.get_tid();
	}
	if (tmsid == BADNODE) {
		if (member.offset == offset * 8) {
			if (trace)
				trace->push_back(*last_member);
			return adjust;
		}
		*last_member = BADNODE; // offset is in the middle of member
		return offset + adjust;
	}

	if (trace)
		trace->push_back(*last_member);
	return struct_get_member(tmsid, offset - member.offset / 8, last_member, trace);
}
#endif //IDA_SDK_VERSION < 900

//-------------------------------------------------------------------------
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

void add_vt_member(tinfo_t struc, ea_t offset, const char* name, const tinfo_t &type, const char* comment)
{
	udm_t udm;
	udm.offset = offset * 8;
	udm.size = is64bit() ? 8 * 8 : 4 * 8;
	udm.type = type;
	udm.name = name;
	udm.cmt = comment;
	if (struc.add_udm(udm, ETF_AUTONAME | ETF_MAY_DESTROY) != TERR_OK) {
		int index = struc.find_udm((uint64)offset);
		if (index == -1)
			return;
		if (struc.rename_udm(index, name) != TERR_OK) {
			for (int i = 1; i < 100; i++) {
				qstring newName = name;
				newName.cat_sprnt("_%d", i);
				if (struc.find_udm(newName.c_str()) == -1) {
					struc.rename_udm(index, newName.c_str());
					break;
				}
			}
		}
		struc.set_udm_type(index, type, ETF_COMPATIBLE);
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
				name_vt.remove(0, 4);
				name_vt.remove(name_vt.find("@@6B@"), 5); //"@@6B@" on the end may be followed by "_0" suffix
			}
			if(!strnicmp(name_vt.c_str(), "vtbl_", 5))
				name_vt.remove(0, 5);
			if(name_vt.length() > 5 && !stricmp(&name_vt[name_vt.length() - 5], "_vtbl"))
				name_vt.remove_last(5);
			if(name_vt[0] >= '0' && name_vt[0] <= '9')
				name_vt.insert(0, '_');
		} else {
			name_vt.sprnt("_%a", VT_ea);
		}
	}
	qstring name_vtbl = name_vt;
	name_vtbl += VTBL_SUFFIX "_";
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
	if (newid == BADADDR)
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
	tinfo_t newstruc;
	if (newid == BADADDR) {
		udt_type_data_t s;
		s.taudt_bits |= TAUDT_UNALIGNED;
		s.set_vftable(true);
		if(!newstruc.create_udt(s) || newstruc.set_named_type(NULL, name_vt.c_str()) != TERR_OK)
			return BADNODE;
		newid = newstruc.get_tid();
	}	else {
		if(!get_type_by_tid(&newstruc, newid) || !newstruc.is_decl_struct())
			return BADNODE;
	}
	newstruc.set_type_cmt(struccmt.c_str());

	// actually set_vftable_ea is appeared in ida 7.6 but here will be used from ida9 becouse it probably depends on TAUDT_VFTABLE flag has been set few lines above
	uint32 ord = get_tid_ordinal(newid);
	if(ord)
		set_vftable_ea(ord, VT_ea);
#endif //IDA_SDK_VERSION >= 900
	set_name(VT_ea, name_vtbl.c_str(), SN_FORCE);

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

		if (!is_func(fnc_flags) || !get_func_name(&funcname, fncea))
			get_ea_name(&funcname, fncea);

		tinfo_t t;
		if(get_tinfo(&t, fncea) && t.is_func()) {
			t = make_pointer(t);
		} else {
			t = dummy_ptrtype(0, false); //make_pointer & (get_int_type_by_width_and_sign | create_simple_type)
			msg("[hrt] %a: no type for VTBL member \"%s\"\n", fncea, funcname.c_str());
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

