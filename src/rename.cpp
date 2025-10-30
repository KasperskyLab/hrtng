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

#include "warn_off.h"
#include <hexrays.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "rename.h"

//if number of code xrefs to proc is geater - the proc will not be target for name & type propagation
#define TOO_POPULAR_CNT 5

bool isIdaInternalComment(const char* comment)
{
	if (!strncmp(comment, "jumptable", 9)) //jumptable 0040D4DD case 1
		return true;
	if (!strncmp(comment, "Exception filter", 16)) //Exception filter 0 for function 40AA7D
		return true;
	if (!strncmp(comment, "Exception handler", 17)) //Exception handler 0 for function 40AA7D
		return true;
	if (!strncmp(comment, "Finally handler", 15)) //Finally handler 0 for function 40B547
		return true;
	if (!strncmp(comment, "Microsoft VisualC", 17)) //Microsoft VisualC 2-14/net runtime
		return true;
	if (!strcmp(comment, "CRYPTO"))
		return true;
	return false;
}

static const char* badVarNames[] = {
  "inited", "started", "result", "data", "Mem", "Memory", "Block", "String", "ProcName", "ProcAddress", "LibFileName", "ModuleName", "LibraryA", "LibraryW"
};

//for Vars and Args only (globals and struct members have own checks)
static bool isVarNameGood(const char* name)
{
	if(*name == 0)
		return false;

	// names like: arg10, a10, arg_10, a_10, a2a
	//             var10, v10, var_10, v_10
	// (with and without '_')
	if ((name[0] == 'a' || name[0] == 'v')) {
		const char* vname = name + 1;
		if((name[0] == 'a' && name[1] == 'r' && name[2] == 'g') ||
			 (name[0] == 'v' && name[1] == 'a' && name[2] == 'r' ))
			vname = name + 3;
		if(*vname == '_')
			vname++;
		if(
	  (vname[0] == 0 ||   (vname[0] >= '0' && vname[0] <= '9' &&
		(vname[1] == 0 || (((vname[1] >= '0' && vname[1] <= '9') || vname[1] == 'a') && //smth like 'a22' or 'a2a'
		(vname[2] == 0 ||   (vname[2] >= '0' && vname[2] <= '9' &&
	   vname[3] == 0)))))))
		return false;
	}

#if IDA_SDK_VERSION == 760
	//annoing p_fld_xx renaming with ida 7.6
	if(name[0] == 'p' && name[1] == '_')
		name += 2;
	if(!strncmp(name, "fld_", 4))
		return false;
#endif // IDA_SDK_VERSION == 760

	//register name with optional suffix (ex: ecx0)
	size_t nlen = qstrlen(name);
	if(nlen > 1 && nlen <= 4) {
		const char* n = name;
		if(n[0] == 'e' || (is64bit() && n[0] == 'r' && !qisdigit(n[1]))) {
			n++; //PH.reg_names doesnt contain rax, eax form
			nlen--;
		}
		for(int32 i = 0; i < PH.regs_num; i++) {
			const char *r = PH.reg_names[i];
			size_t rlen = qstrlen(r);
			if(nlen >= rlen && strneq(n, r, rlen) &&
			   (n[rlen] == 0 ||
			    (qisdigit(n[rlen]) && n[rlen + 1] == 0) ||
			    (qisdigit(n[rlen]) && qisdigit(n[rlen + 1]) && n[rlen + 2] == 0)))
				return false;
		}
	}

	if((name[0] == 'F' || name[0] == 'B') && !qstrcmp(name + 1, "link"))
		return false;

	// names beginning from 'lp'
	if(name[0] == 'l' && name[1] == 'p' && name[2] != 0)
		name += 2;

	for(size_t i = 0; i < qnumber(badVarNames); i++)
		if(!qstrcmp(name, badVarNames[i]))
			return false;
	return true;
}

//there are additianal restrictions for names in call arguments
static const char* badArgNames[] = {
	"this", "Str", "Src", "Dst", "dwBytes"
};
static bool isArgNameGood(const char* name)
{
	if (!isVarNameGood(name))
		return false;

	for(size_t i = 0; i < qnumber(badArgNames); i++)
		if(!qstrcmp(name, badArgNames[i]))
			return false;
	return true;
}

// consider "call(a, b)" is equal to assingment "a = b"
static bool isCallAssignName(const char* name, size_t* left, size_t* right)
{
	if (!qstrcmp(name, "strcpy") ||
			!qstrcmp(name, "wcscpy") ||
			!qstrcmp(name, "lstrcpy") ||
			!qstrcmp(name, "qmemcpy")
			) {
		*left = 0; *right = 1;
		return true;
	}
	return false;
}

static bool getCallName(cfunc_t *func, cexpr_t* call, qstring* name)
{
	if (call->op != cot_call)
		return false;

	qstring funcname;
	if (!getExpName(func, call->x, &funcname))
		return false;

	stripName(&funcname, true);
	size_t get = funcname.find("get");
	if(get != qstring::npos
		 //&& get != 0 // ignore "get" in the beginning
		 && funcname.length() > get + 5 ) { //  strlen("get") + 2
		size_t cnt = 3;
		if(funcname[get + cnt] == '_') // strip '_' after "get" too
			++cnt;
		if(name)
			*name = funcname.substr(get + cnt);
		return true;
	}

	size_t ctor = funcname.find("::ctor");
	if(ctor != qstring::npos && ctor != 0) {
		if(name)
			*name = funcname.substr(0, ctor);
		return true;
	}

	carglist_t &args = *call->a;
	if (args.size() == 0 && funcname == "GetLastError") {
		if(name)
			*name = "err";
		return true;
	}

	if (!args.size())
		return false;

	// non zero args below //////////////////

	if (args.size() >= 1 && (funcname == "LoadLibrary" || funcname == "GetModuleHandle" || funcname == "dlopen")) {
		qstring argName;
		if (getExpName(func, &args[0], &argName)) {
			if(name) {
				*name = "h";
				*name += argName;
			}
			return true;
		}
		return false;
	}

	if (args.size() >= 2 && (funcname == "GetProcAddress" || funcname == "dlsym"))
		return getExpName(func, &args[1], name);

	if (args.size() == 1 &&
			(funcname == "strdup"
			 || funcname == "wcsdup"
			 || (funcname.length() == 16 && !qstrcmp(funcname.c_str() + 4, "code_pointer"))
			 || (funcname.length() == 13 && !qstrcmp(funcname.c_str() + 2, "codePointer"))))
		return getExpName(func, &args[0], name);

	return false;
}

static bool getEaName(ea_t ea, qstring* name)
{
	flags64_t flg = get_flags(ea);
	if(is_tail(flg) && isARM()) {
		ea = ea & ~1;
		flg = get_flags(ea);
	}

	if(!has_user_name(flg) && is_strlit(flg)) {
		if (name) {
			opinfo_t oi;
			if (!get_opinfo(&oi, ea, 0, flg))
				oi.strtype = STRTYPE_C;
			if(get_strlit_contents(name, ea, (size_t)(get_item_end(ea) - ea), oi.strtype, NULL, STRCONV_ESCAPE) > 0 ) {
				if (name->size() > MAX_NAME_LEN)
					name->resize(MAX_NAME_LEN);
				if(!validate_name(name, VNT_IDENT)) {
					Log(llWarning, "FIXME: getEaName(%a, \"%s\")\n", ea, name->c_str());
					return false;
				}
			}
		}
		return true;
	}
		
	if (has_user_name(flg) || has_auto_name(flg)) {
		qstring n;
		get_ea_name(&n, ea);
		if(!stristr(n.c_str(), VTBL_SUFFIX)) { // avoid renaming derived class vtbl to base one by the redundant assignment in ctor/dtor
			if (name) {
				*name = n;
				stripName(name, is_func(flg));
			}
			return true;
		}
	}

	//get sub_xxx as well
	if(is_code(flg) && has_dummy_name(flg)) {
		qstring n = get_name(ea);
		if(!strncmp(n.c_str(), "sub_", 4)) {
			if(name) {
				*name = n;
			}
			return true;
		}
	}
	return false;
}

bool renameEa(ea_t refea, ea_t ea, const qstring* name)
{
	if(!is_mapped(ea)) {
		Log(llDebug, "%a: renameEa(%a) - not mapped\n", refea, ea);
		return false;
	}
  qstring newName = name->c_str();
	if (newName.size() > MAX_NAME_LEN)
		newName.resize(MAX_NAME_LEN);
	if(!validate_name(&newName, VNT_IDENT)) {
		Log(llWarning, "%a: bad name for renameEa(%a, \"%s\")\n", refea, ea, newName.c_str());
		return false;
	}
	if (!has_cmt(get_flags(ea)) && newName != *name)
		set_cmt(ea, name->c_str(), true);

	if(!strncmp(newName.c_str(), "sub_", 4))
			newName.insert('p');

	if (!set_name(ea, newName.c_str(), SN_NOCHECK | /*SN_AUTO |*/ SN_NOWARN | SN_FORCE)) {
		Log(llWarning, "%a: fail to rename %a to \"%s\"\n", refea, ea, newName.c_str());
		return false;
	}
	//make_name_auto(ea);
	Log(llInfo, "%a: Global at %a was renamed to \"%s\"\n", refea, ea, newName.c_str());
	return true;
}

bool getVarName(lvar_t * var, qstring* name)
{
	if (!var->has_user_name() && !var->has_nice_name())
		return false;
	if(!isVarNameGood(var->name.c_str()))
		return false;
	if (name) {
		*name = var->name;
		stripName(name);
	}
	return true;
}

bool renameVar(ea_t refea, cfunc_t *func, ssize_t varIdx, const qstring* name, vdui_t *vdui)
{
	lvars_t *vars = func->get_lvars();
	lvar_t * var= &vars->at(varIdx);
	qstring newName = *name;
	if (newName.size() > MAX_NAME_LEN)
		newName.resize(MAX_NAME_LEN);
	if(!validate_name(&newName, VNT_IDENT)) {
		Log(llDebug, "FIXME: renameVar(%a, \"%s\")\n", refea, newName.c_str());
		return false;
	}

	//check if proc doesnt already has such name
	newName = unique_name(newName.c_str(), "_",
												[&refea, &vars, &var](const qstring &n)
	{
		for(auto it = vars->begin(); it != vars->end(); it++) {
			if(it->name == n) {
				if(it == var) {//old name is equal to new, why?
					Log(llDebug, "FIXME: renameVar(%a, \"%s\") dup\n", refea, n.c_str());
					return true;
				}
				return false;
			}
		}
		// it seems ida donsnt allow renaming local var to the name of existing proc, but OK with global var
		ea_t nnea = get_name_ea(BADADDR, n.c_str());
		if(nnea == BADADDR || !is_func(get_flags(nnea)))
			return true;
		Log(llDebug, "FIXME: renameVar(%a, \"%s\") not accepted\n", refea, n.c_str());
		return false;
	});

	bool res = true;
	qstring oldname = var->name;
	if (vdui) {
		res = vdui->rename_lvar(var, newName.c_str(), true); // vdui->rename_lvar can rebuild all internal structures/ call later!!!
	} else {
		//this way of renaming/retyping is not stored in database. And don't need, it's temporary renaming
		var->name = newName;
		var->set_user_name();

		tinfo_t newType;
		if(!var->has_user_type()) {
			tinfo_t t = getType4Name(newName.c_str());
			if(!t.empty() && var->accepts_type(t))
				if(var->set_lvar_type(t, true)) {
					Log(llInfo, "%a: type of var '%s' refreshed\n", refea, newName.c_str());
					newType = t;
				}
		}

		//if var is arg it will be useful to rename argument inside function type
		if(var->is_arg_var()) {
			int vIdx = (int)varIdx;
			ssize_t argIdx = func->argidx.index(vIdx);
			if(argIdx != -1) {
				tinfo_t funcType;
#if 1
				if(get_tinfo(&funcType, func->entry_ea)) {
#else
				//get_func_type may returns wrong (cached?) type, where already unamed arg is still named.
				//Reproduce: "N"->"Del"->"Enter" on arg then "F5" to rename arg by autorenamer
				//Also seen strange side effect of incorrect "name" param on lxe_lvar_name_changed callback then get_func_type is used. Why???
				if(func->get_func_type(&funcType)) {
#endif
					func_type_data_t fi;
					if(funcType.get_func_details(&fi) && fi.size() > (size_t)argIdx) {
						Log(llDebug, "%a: Rename arg%d \"%s\" to \"%s\"\n", refea, argIdx + 1, fi[argIdx].name.c_str(), newName.c_str());
						if(!isVarNameGood(fi[argIdx].name.c_str())) {
							fi[argIdx].name = newName;
							stripName(&fi[argIdx].name);
							if(!newType.empty() && isDummyType(fi[argIdx].type.get_decltype()))
								fi[argIdx].type = newType;
							tinfo_t newFType;
							if(newFType.create_func(fi) && apply_tinfo(func->entry_ea, newFType, is_userti(func->entry_ea) ? TINFO_DEFINITE : TINFO_GUESSED)) {
								qstring typeStr;
								newFType.print(&typeStr);
								Log(llInfo, "%a: Function type was recasted for change arg%d into \"%s\"\n", refea, argIdx, typeStr.c_str());
							}
						}
					}
				}
			}
		}
	}
	if(!res)
		Log(llWarning, "%a: Var \"%s\" rename to \"%s\" failed\n", refea, oldname.c_str(), newName.c_str());
	else Log(llInfo, "%a: Var \"%s\" was renamed to \"%s\"\n", refea, oldname.c_str(), newName.c_str());

	return res;
}

static bool isStructOffOver(cexpr_t* memref, const cfunc_t *func)
{
	if(memref->op == cot_memref) {
		while(memref->x->op == cot_memref)
			memref = memref->x;
		if(memref->x->op == cot_idx && memref->x->y->op == cot_num && memref->x->y->numval() > 0 /*&& memref->x->type.is_struct()*/) {//is it possible case for union?
			printExp2Msg(func, memref, "probably invalid struct member access");
			return true;
		}
	}
	return false;
}

bool getUdtMembName(tinfo_t udt, uint32 offset, qstring* name)
{
	udt.remove_ptr_or_array();
	udm_t memb;
	memb.offset = offset;
	if(-1 == udt.find_udm(&memb, STRMEM_AUTO))
		return false;

	if(memb.name[0] == 'f') {
		if(!strncmp(memb.name.c_str(), "field_",6))
			return false;
		if(!strncmp(memb.name.c_str(), "fld_",4))
			return false;
	} else if(!strncmp(memb.name.c_str(), "gap",3)) {
			return false;
	} else if(!strncmp(memb.name.c_str(), "VT_", 3) || memb.name == VTBL_MEMNAME)
		return false;

	if (name) {
		*name = memb.name;
		stripName(name);
	}
	return true;
}

static bool renameUdtMemb(ea_t refea, tinfo_t udt, uint32 offset, qstring* name)
{
	udt.remove_ptr_or_array();
	udm_t memb;
	memb.offset = offset;
	int midx = udt.find_udm(&memb, STRMEM_AUTO);
	if(-1 == midx) {
		Log(llDebug, "renameUdtMemb no %x offset inside \"%s\"\n", offset, udt.dstr());
		return false;
	}

	//"VT" handled in getUdtMembName as bad for name source, so disable "VT" autorenaming
	if(!strncmp(memb.name.c_str(), "VT_", 3) || memb.name == VTBL_MEMNAME)
		return false;

#ifdef _DEBUG
	if (memb.name == *name) {
		Log(llDebug, "%a: renameUdtMemb %s to self\n", refea, name->c_str());
		return false;
	}
#endif

	qstring newName = good_udm_name(udt, memb.offset, name->c_str());
	qstring oldName;
	udt.get_type_name(&oldName);
	oldName.append('.');
	oldName.append(memb.name);
#if IDA_SDK_VERSION >= 850
	if(TERR_OK == udt.rename_udm(midx, newName.c_str())) {
#else //IDA_SDK_VERSION < 850
	struc_t* st = get_member_struc(oldName.c_str());
	if(st && set_member_name(st, offset, newName.c_str())) {
#endif //IDA_SDK_VERSION >= 850
		Log(llInfo, "%a: struct member \"%s\" at 0x%x was renamed to %s\n", refea, oldName.c_str(), offset, newName.c_str());
		return true;
	}
	Log(llWarning, "%a: fail rename struct member \"%s\" at 0x%x to %s\n", refea, oldName.c_str(), offset, newName.c_str());
	return false;
}

//must return stripped name
bool getExpName(cfunc_t *func, cexpr_t* exp, qstring* name, bool derefPtr /* =false */)
{
	exp = skipCast(exp);//ignore typecast
	bool res = false;
	switch (exp->op)
	{
	case cot_helper:
		if(name)
			*name = exp->helper;
		res = true;
		break;
	case cot_str:
		if(name)
			*name = exp->string;
		res = true;
		break;
	case cot_var:
		return getVarName(&func->get_lvars()->at(exp->v.idx), name);
	case cot_obj:
		return getEaName(exp->obj_ea, name);
	case cot_memptr:
	case cot_memref:
		return !isStructOffOver(exp, func) && getUdtMembName(exp->x->type, exp->m, name);
	case cot_call:
		return getCallName(func, exp, name);
	//case cot_fnum:
	case cot_num:
		{
			uint64 val = exp->numval();
			bool en = false;
			bool ok = false;
			if(exp->n->nf.is_enum()) {
				qstring &tn = exp->n->nf.type_name;
				if(tn != "MACRO_ERROR" && tn != "MACRO_STRSAFE") {
					en = true;
					Log(llFlood, "%a: enum name '%s'\n", exp->ea, tn.c_str());
				}
			} else if (/*val != 0*/ val > 1 && val < (uint64)0x80000000) {
				ok = true;
			}
			if(name) {
				if (en || ok) {
					tinfo_t t = exp->type;
					exp->n->print(name, t);
					tag_remove(name);
				}
				if(ok) {
					stripNum(name); //strip "i64"/"ui64","LL"/"uLL" suffix
					name->insert('n');
					//name->append('_');
				}
			}
			res = en || ok;
			break;
		}
	case cot_ref:
		if (derefPtr) {
			qstring ref;
			if(getExpName(func, exp->x, &ref)) {
				if(ref.length() > 1 && ref.last() == '_') {
					if(name) {
						ref.remove_last();
						*name = ref;
					}
					res = true;
				} else {
					qstring tname;
					if(!exp->x->type.get_type_name(&tname) || tname != ref) {
						if(name) {
							*name = "p_";
							name->append(ref);
						}
						res = true;
					}
				}
			}
		}
		break;
	case cot_ptr:
		if (derefPtr) {
#if 0
			if(exp->x->op == cot_cast){
				//here is not deref, check is it looks like type recast
				if(exp->x->type.is_ptr())
					return getExpName(func, exp->x->x, name);
			} else {
#endif
				qstring deref;
				if(getExpName(func, exp->x, &deref)) {
					if(deref.length() > 2 && deref[0] == 'p' && deref[1] == '_') {
						if(name)
							*name = deref.substr(2);
						res = true;
					}
				}
			//}
		}
		break;
	}
	if (res && name) {
		stripName(name);
		return name->length() != 0;
	}
	return res;
}

bool renameExp(ea_t refea, cfunc_t *func, cexpr_t* exp, qstring* name, vdui_t *vdui, bool derefPtr /*= false*/)
{
	exp = skipCast(exp);
	if(derefPtr && exp->op == cot_ptr && isRenameble(exp->x->op) && exp->x->type.is_scalar() && !getExpName(func, exp->x, nullptr)) {
		name->insert(0,"p_");
		return renameExp(refea, func, exp->x, name);
	}
	if(derefPtr && exp->op == cot_ref && isRenameble(exp->x->op)) {
		qstring xname;
		if(!getExpName(func, exp->x, &xname) || xname == *name) {
			if(name->length() > 2 && name->at(0) == 'p' && name->at(1) == '_') {
				name->remove(0, 2);
			} else {
				name->append('_');
			}
			return renameExp(refea, func, exp->x, name);
		}
	}

	//dirty hack for case when structure is placed on stack, and pointer to this struct is passed to func arg
	// ex:
	// strucA sA;
	// func(&sA);
	if(derefPtr && exp->op == cot_var) {
		lvars_t *vars = func->get_lvars();
		lvar_t * var = &vars->at(exp->v.idx);
		if(var->type().is_array()) {
			const type_t *namedType;
			if(get_named_type(NULL, name->c_str(), NTF_TYPE, &namedType) && is_type_struct(*namedType)) { // for structs NTF_TYPE flag req
				name->append('_');
				return renameVar(refea, func, exp->v.idx, name, vdui);
			}
		}
	}

	if(exp->op == cot_var)
		return renameVar(refea, func, exp->v.idx, name, vdui);
	if(exp->op == cot_obj)
		return renameEa(refea, exp->obj_ea, name);
	if(exp->op == cot_memptr || exp->op == cot_memref)
		return !isStructOffOver(exp, func) && renameUdtMemb(refea, exp->x->type, exp->m, name);
	return false;
}

static tinfo_t getExpType(cfunc_t *func, cexpr_t* exp)
{
	if(!exp->type.empty())
		return exp->type;

	switch (exp->op)
	{
	case cot_var: 
		{
			lvars_t *vars = func->get_lvars();
			lvar_t * var = &vars->at(exp->v.idx);
			return var->type();
		}
	case cot_obj:
		{
			tinfo_t t;
			if(get_tinfo(&t, exp->obj_ea))
				return t;
			break;
		}
	case cot_memptr:
	case cot_memref:
		{
			tinfo_t struc = exp->x->type;
			struc.remove_ptr_or_array();
			if(struc.is_decl_struct()) {//is_struct())
				udm_t memb;
				memb.offset = exp->m;
				if(-1 != struc.find_udm(&memb, STRMEM_AUTO))
					return memb.type;
			}
			break;
		}
	case cot_ref:
		{
			tinfo_t t = getExpType(func, exp->x);
			if(!t.empty())
				return make_pointer(t);
			break;
		}
	case cot_ptr:
		{
			tinfo_t t = getExpType(func, exp->x);
			t = t.get_pointed_object();
			if(!t.empty())
				return t;
			break;
		}
	case cot_call:
		//TODO: not need now
		break;
	}

	exp->calc_type(false); //this doesn't work
	return exp->type;
}

#if 0
void dumpUserComments(ea_t entry_ea)
{
	user_cmts_t *cmts = restore_user_cmts(entry_ea);
	if ( cmts != NULL )
	{
		Log(llFlood, "------- %" FMT_Z " user defined comments\n", user_cmts_size(cmts));
		user_cmts_iterator_t p;
		for ( p=user_cmts_begin(cmts); p != user_cmts_end(cmts); p=user_cmts_next(p) )
		{
			const treeloc_t &tl = user_cmts_first(p);
			citem_cmt_t &cmt = user_cmts_second(p);
			Log(llFlood, "Comment at %a, preciser %x:\n%s\n\n", tl.ea, tl.itp, cmt.c_str());
		}
		user_cmts_free(cmts);
	} else {
		Log(llFlood, "------- no user defined comments\n");
	}
}
#endif

#if 0 //def _DEBUG
	#define DEBUG_COMMENTS(args) {msg args;}
#else
	#define DEBUG_COMMENTS(args) {}
#endif

void autorename_n_pull_comments(cfunc_t *cfunc)
{
	struct ida_local cblock_visitor_t : public ctree_visitor_t
	{
		ea_t startea;
		qstring funcname;
		bool isProlog;
		cfunc_t *func;
		user_cmts_t *cmts;
		bool cmtModified;
		volatile bool varRenamed;
		bool scanCmts;
		uval_t stmtCnt;
		uval_t callCnt;
		qstring callProcName;

		cblock_visitor_t(cfunc_t *cfunc) : ctree_visitor_t(CV_PARENTS)
		{
			get_short_name(&funcname, cfunc->entry_ea);
			func = cfunc;
			cmts = restore_user_cmts(cfunc->entry_ea);
			if(cmts == NULL)
				cmts = user_cmts_new();
			cmtModified = false;
			startea = func->entry_ea; //BADADDR;
			isProlog = true;
			varRenamed = false;
			scanCmts = true;
			stmtCnt = 0;
			callCnt = 0;
		}

		~cblock_visitor_t()
		{
			//if(modified && user_cmts_size(cmts))
			//	save_user_cmts(func->entry_ea, cmts);
			if (cmtModified)
				func->save_user_cmts();
			user_cmts_free(cmts);
			//dumpUserComments(func->entry_ea);
		}

		//find comments in disasm and copy it 2 hexray
		int idaapi visit_insn(cinsn_t *ins)
		{
			if(!scanCmts) //only one pass
				return 0;

			if ( ins->op == cit_block && !isProlog) {//first block of proc
				DEBUG_COMMENTS(("block %a: %d\n", ins->ea, ins->op));
				startea = ins->ea;
				return 0;
			}
			//ida first block started from address of first operator, so we need skip first block startea override
			isProlog = false; 
			if(ins->op <= cit_block || //chks statements only
				ins->ea == BADADDR ) { // some statements have no address (ex: cit_break)
				DEBUG_COMMENTS(("skip %a: %d\n", ins->ea, ins->op));
				return 0;
			}
			stmtCnt++;

			if(startea > ins->ea)//ida doesn't make block statement after jump to return and startea is return
				startea = ins->ea;
			DEBUG_COMMENTS(("start %a ins %a: %d\n", startea, ins->ea, ins->op));
			ea_t ea = startea;
			treeloc_t loc;
			loc.ea = ins->ea;
			loc.itp = (ins->op == cit_expr)? ITP_SEMI : ITP_BLOCK1;
			DEBUG_COMMENTS(("%a: %d\n", ins->ea, ins->op));
			user_cmts_iterator_t it = user_cmts_find(cmts, loc);//get existing comments
			bool alredyCommented = it != user_cmts_end(cmts);

			//collect comments from disasm of statement
			//do not skip this loop if alredyCommented, because ea chain can be lost
			qstring comments;
			while (ea != BADADDR && ea <= ins->ea
#if IDA_SDK_VERSION >= 750
						 && func->mba->mbr.range_contains(ea)
#endif
						 ) {
				if(!alredyCommented && has_cmt(get_flags(ea))) {
					qstring cmt;
					if(get_cmt(&cmt, ea, true) != -1) {
						DEBUG_COMMENTS(("cmt at %a (ins %a) %s\n", ea, ins->ea, cmt.c_str()));
						if (!isIdaInternalComment(cmt.c_str()) && cmt[0] != ';') {
							if(comments.length())
								comments += "\n";
							comments += cmt;
						}
					}
				}
				ea = next_head(ea, BADADDR);
			}

			//set comments to hexrays
			if (!alredyCommented && comments.length()) {
				DEBUG_COMMENTS(("-- %a: %s\n", ins->ea, comments.c_str()));
				//citem_cmt_t c = comments.c_str();
				//user_cmts_insert(cmts, loc, c);
				func->set_user_cmt(loc, comments.c_str());
				cmtModified = true;
			}
			startea = ea;
			return 0;
		}

		//rename simple assignment parts
		int idaapi rename_asgn_sides(cexpr_t *asgn)
		{
			if(asgn->op != cot_asg && !is_relational(asgn->op))
				return 0;

			// find comments on this ea
			qstring comments;
			treeloc_t loc;
			loc.ea = asgn->ea;
			loc.itp = ITP_SEMI;
			user_cmts_iterator_t it = user_cmts_find(cmts, loc);//get existing comments
			if(it != user_cmts_end(cmts)) {
				comments = user_cmts_second(it);
			} else {
				loc.itp = ITP_BLOCK1;
				it = user_cmts_find(cmts, loc);
				if(it != user_cmts_end(cmts))
					comments = user_cmts_second(it);
			}
			//do not use comments been set by enum detector (see helpers.cpp appendComment)
			if (comments.length() && comments[0] == ';')
				comments.clear();

			//get name from right side of assignment
			qstring rname;
			cexpr_t* right = asgn->y;
			getExpName(func, right, &rname, true);

			//have some name on right side?
			bool renameLeft = false;
			if (comments.length() || rname.length()) {
				renameLeft = true;
				if(rname.length()) //assume rname more important then comments
					comments = rname;
			}

			//take name of left side assigned var
			//and rename it if possible
			qstring lname;
			cexpr_t* left = asgn->x;
			bool hasLeft = getExpName(func, left, &lname);
			if(hasLeft && skipCast(right)->op == cot_ref && lname[0] == 'p' && lname[1] == '_' && strncmp(comments.c_str(), "p_", 2)) // overwrite unbalanced with type annoying IDA's renaming to "p_something"
				hasLeft = false;
			if(!hasLeft && renameLeft)
				varRenamed |= renameExp(asgn->ea, func, left, &comments);

			//rename right if have good name on left side
			if(!rname.length() && (hasLeft || renameLeft)) {
				if(lname.length())//assume lname more important then comments
					comments = lname;
				varRenamed |= renameExp(asgn->ea, func, right, &comments);
			}
			return 0;
		}

		int idaapi rename_call_params(cexpr_t *call)
		{
			if(call->op != cot_call)
				return 0;
			callCnt++;

			ea_t dstea;
			tinfo_t tif = getCallInfo(call, &dstea);
			bool bAllowTypeChange =  false;
			if(dstea != BADADDR && !tif.is_from_subtil()) {
				func_t *f = get_func(dstea);
				if(f && !(f->flags & FUNC_LIB)) {
#if TOO_POPULAR_CNT
					//do check number of crefs for avoid renaming args in popular funcs like memcpy, alloc, etc
					uint32 nref = 0;
					for(ea_t xrefea = get_first_cref_to(dstea); xrefea != BADADDR && ++nref <= TOO_POPULAR_CNT; xrefea = get_next_cref_to(dstea, xrefea))
						;
					if(nref > TOO_POPULAR_CNT)
						Log(llFlood, "%a %s: too many crefs to %a %s, do not change proto\n", call->ea, funcname.c_str(), dstea, get_short_name(dstea).c_str());
					else
#endif
						bAllowTypeChange = true;
				}
			}

			if(!getExpName(func, call->x, &callProcName)) {
				//fix call to "off_xxx" (exports in debugger memory)
				cexpr_t *callDst = skipCast(call->x);
				if(callDst->op == cot_obj) {
					flags64_t flg = get_flags(callDst->obj_ea);
					if(has_dummy_name(flg)) {
						qstring n = get_name(callDst->obj_ea);
						if(!strncmp(n.c_str(), "off_", 4)) {
							ea_t dest = get_ea(callDst->obj_ea);
							if(getEaName(dest, &callProcName)) {
								renameEa(call->ea, callDst->obj_ea, &callProcName);
							}
						}
					}
				}
			}

			carglist_t &args = *call->a;
			if(!args.size())
				return 0;

			bool bCallAssign = false;
			qstring anL, anR;
			size_t  iL, iR;
			if(!callProcName.empty()) {
				stripName(&callProcName, true);
				if(isCallAssignName(callProcName.c_str(), &iL, &iR))
					bCallAssign = true;
			}

			tif.remove_ptr_or_array();
			if(tif.is_decl_func()) {
				func_type_data_t fi;
				//get_func_details(&fi, GTD_CALC_ARGLOCS) may cause INTERR 50689 on call cot_helper
				if(tif.get_func_details(&fi, bAllowTypeChange ? GTD_CALC_ARGLOCS : GTD_NO_ARGLOCS)) {
					size_t nArgs = fi.size();//??? check vararg(,...)
					if(nArgs > args.size()) 
						return 0;
					bool fiChanged = false;
					for(size_t i = 0; i < fi.size(); i++) {
						cexpr_t *arg = &args[i];
						qstring fiIname = fi[i].name;
						stripName(&fiIname);
						qstring argVarName;
						bool argNamed = getExpName(func, arg, &argVarName, true);

						if(argNamed && bCallAssign) {
							if(i == iL) anL = argVarName;
							if(i == iR) anR = argVarName;
						}

						if(!argNamed && isArgNameGood(fiIname.c_str())) {
								varRenamed |= renameExp(call->ea, func, arg, &fiIname, nullptr, true);
						} else if(argNamed && bAllowTypeChange && !isVarNameGood(fiIname.c_str())) {
								Log(llDebug, "%a %s: In function %a %s rename arg%d \"%s\" to \"%s\"\n", call->ea, funcname.c_str(), dstea, get_short_name(dstea).c_str(), i + 1, fi[i].name.c_str(), argVarName.c_str());
								fi[i].name = argVarName;
								fiChanged = true;
								if(isDummyType(fi[i].type.get_decltype())) {
									tinfo_t argType = getType4Name(argVarName.c_str());
									if(argType.empty())
										argType = getExpType(func, skipCast(arg));
									if(!isDummyType(argType.get_decltype()) && argType.is_scalar()) {
										Log(llDebug, "%a %s: In function %a %s recasted arg%d `%s` from \"%s\" to \"%s\"\n", 	call->ea, funcname.c_str(), dstea, get_short_name(dstea).c_str(), i + 1, fi[i].name.c_str(), fi[i].type.dstr(), argType.dstr());
										fi[i].type = argType;
									}
								} //else Log(llDebug, "arg%d `%s` (%d - %s) of %s\n", i + 1, fi[i].name.c_str(), fi[i].type.get_decltype(), fi[i].type.dstr(), get_short_name(dstea).c_str());
						}
					}
					if(bCallAssign) {
						if(!anL.length() && anR.length())
							varRenamed |= renameExp(call->ea, func, &args[iL], &anR, nullptr, true);
						else if(anL.length() && !anR.length())
							varRenamed |= renameExp(call->ea, func, &args[iR], &anL, nullptr, true);
					}
					if(fiChanged) {
						//TODO: some name cleanup, remove duplicates (?)
						tinfo_t newFType;
						newFType.create_func(fi);
						if(newFType.is_correct() && apply_tinfo(dstea, newFType, TINFO_DELAYFUNC | (is_userti(dstea) ? TINFO_DEFINITE : TINFO_GUESSED))) // apply_callee_tinfo
							Log(llInfo, "%a %s: Function %a %s recasted to \"%s\"\n", call->ea, funcname.c_str(), dstea, get_short_name(dstea).c_str(), newFType.dstr());
					}
				}
			} else if(!tif.empty()){
				qstring typeStr;
				tif.print(&typeStr);
				Log(llDebug, "%a: type \"%s\" is not function\n", call->ea, typeStr.c_str());
			}
			return 0;
		}

		//check for strings in data section, make comments
		int idaapi set_cmt_for_hidden_strings(cexpr_t *obj)
		{
			if (obj->op != cot_obj || obj->is_cstr()) //FIXME: is_cstr sometimes is true even if here is a "hidden string"
				return 0;

			ea_t ea = obj->obj_ea;
			flags64_t flg = get_flags(ea);
			if (!is_strlit(flg) && is_ea(flg)) {
				ea = get_ea(ea);
				flg = get_flags(ea);
			}
			if (!is_strlit(flg))
				return 0;

			treeloc_t loc;
			loc.ea = obj->ea;
			loc.itp = ITP_BLOCK1;
			citem_t *p = parent_expr();
			while (p && p->op <= cot_last && p->op != cot_call) {
				p = func->body.find_parent_of(p);
			}
			if (!p)
				p = parent_expr();
			if (p->op == cot_call) {
				carglist_t &args = *((cexpr_t*)p)->a;
				if (args.size() > 1) {
					for (size_t i = 0; i < args.size(); i++) {
						cexpr_t *arg = &args[i];
						if (arg == obj || 
							(arg->op == cot_cast && arg->x == obj)
							/*arg->contains_expr((cexpr_t const *)obj)*/) {
							if (args.size() != i + 1 && i < 63)
								loc.itp = item_preciser_t(ITP_ARG1 + i); //this doesnt works for last arg
							break;
						}
					}
				}
				if (loc.itp == ITP_BLOCK1) { //arg not found or last arg
					while (p && p->op <= cot_last)  p = func->body.find_parent_of(p);
					if (!p) p = parent_expr();
				}
			}
			if(p->op == cit_expr)
				loc.itp = ITP_SEMI;
			else if(p->op == cit_if)
				loc.itp = ITP_BRACE2;

			if (p->ea != BADADDR)
				loc.ea = p->ea;

			user_cmts_iterator_t it = user_cmts_find(cmts, loc);
			if (it != user_cmts_end(cmts)) 
				return 0;

			opinfo_t oi;
			qstring strcontent;
			if (!get_opinfo(&oi, ea, 0, flg))
				oi.strtype = STRTYPE_C;
			if (get_strlit_contents(&strcontent, ea, (size_t)(get_item_end(ea) - ea), oi.strtype, NULL, STRCONV_ESCAPE) > 0) {
				strcontent.insert('"');
				strcontent.append('"');
				func->set_user_cmt(loc, strcontent.c_str());
				cmtModified = true;
			}
			return 0;
		}
		
		int idaapi visit_expr(cexpr_t *exp)
		{
			if(exp->op == cot_call)
				return rename_call_params(exp);
			if(exp->op == cot_asg || is_relational(exp->op))
				return rename_asgn_sides(exp);
			if (exp->op == cot_obj)
				return set_cmt_for_hidden_strings(exp);
			return 0;
		}

		void apply_loop()
		{
			uint32 i = 0;
			for(; i < 10; ++i)
			{
				varRenamed = false;
				apply_to(&func->body, NULL);
				if(!varRenamed)
					break;
				scanCmts = false;
			}
			if(i >= 10) {
				Log(llWarning, "%a %s WARNING: rename looping...\n", func->entry_ea, funcname.c_str());
			}
			
			//rename func itself if it has dummy name and only one statement inside
			//and mark as a wrapper by "_w" or "_ww" or "_www" .... suffix
			// unlike "j_" jump functions, wrapper can have some additional code, like set values for args of callee
			if (stmtCnt <= 1 && callCnt == 1 && has_dummy_name(get_flags(func->entry_ea))) {
				if (!callProcName.empty() && strncmp(callProcName.c_str(), "sub_", 4) && callProcName != "JUMPOUT") {
					qstring newName = callProcName;
					if (newName.size() > MAX_NAME_LEN - 2)
						newName.resize(MAX_NAME_LEN - 2);
					if(validate_name(&newName, VNT_IDENT)) {
						bool already_w = false;
						size_t w = newName.length() - 1;
						if(newName[w] == 'w') {
							while (newName[w] == 'w' && w > 0) --w;
							if(newName[w] == '_') {
								newName.append('w');
								already_w = true;
							}
						}
						if(!already_w)
							newName.append("_w");
						if(set_name(func->entry_ea, newName.c_str(), SN_AUTO | SN_NOWARN | SN_FORCE)) {
							make_name_auto(func->entry_ea);
							Log(llInfo, "'%s' was renamed to '%s'\n", funcname.c_str(), newName.c_str());
						} else {
							Log(llWarning, "%a: rename '%s' to '%s' error\n", func->entry_ea, funcname.c_str(), newName.c_str());
						}
					}
				}
			}
		}

	};
	cblock_visitor_t cbv(cfunc);
	cbv.apply_loop();
	//cfunc->verify(ALLOW_UNUSED_LABELS, false);
}
