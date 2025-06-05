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
#include <diskio.hpp>
#if IDA_SDK_VERSION < 850
#include <enum.hpp>
#endif // IDA_SDK_VERSION < 850
#include "warn_on.h"

#include "helpers.h"
#include "lit.h"
#include "rename.h"

/* Format of literal database is simple:
; 1) 'FunctionName' or STRUCT 'StructName' in line begginning (no spaces or tabs before)
; 2) <space> [FuncArgumentNumber | StructFieldName] <space> [Type] : Where FuncArgumentNumber started from 1. 0 means return value. Type is 'enum' for exclusive values or 'bits' for values may be combined with bitwise OR
; 3) <space> <space> [LiteralName] <space> [Value]
;    .....
; 4) empty line
 */

typedef std::map<uint64, qstring> literals_t; // value to literal name map

struct ida_local lit_arg_t
{
	uint32 n; // number of this argument for function
	bool  exclusive;
	literals_t refs;
};
typedef qvector<lit_arg_t> lit_args_t;
typedef std::map<qstring, lit_args_t> lit_funcs_t;
typedef lit_funcs_t::const_iterator lit_func_t;

struct ida_local lit_field_t
{
	qstring name;
	bool  exclusive;
	literals_t refs;
};
typedef qvector<lit_field_t> lit_fields_t;
typedef std::map<qstring, lit_fields_t> lit_structs_t;
typedef lit_structs_t::const_iterator lit_struct_t;

class ida_local literal_db
{
	lit_funcs_t m_functions;
	lit_structs_t m_structures;

public:

	lit_func_t find_func(const char* funcname) const {
		return m_functions.find(funcname); 
	}
	bool is_func(const lit_func_t& f) const { 
		return f != m_functions.end(); 
	}
	const lit_arg_t* find_arg (const lit_func_t& lfunc, uint32 argN) const
	{
		for(size_t i = 0; i < lfunc->second.size(); i++)
			if (lfunc->second[i].n == argN)
				return &lfunc->second[i];
		return NULL;
	}

	lit_struct_t find_struct(const char* strucname) const { 
		return m_structures.find(strucname); 
	}
	bool is_struct(const lit_struct_t& s) const {
		return s != m_structures.end();
	}
	const lit_field_t* find_field (const lit_struct_t& s, const char* fieldname) const
	{
		for(size_t i = 0; i < s->second.size(); i++)
			if(s->second[i].name == fieldname)
				return &s->second[i];
		return NULL;
	}

	enum eLoadStage {
		ldFuncOrStruc,
		ldArg,
		ldFld,
		ldLit
	};

	void ll_error(uint32 line, const char* s)
	{
		Log(llError, "literal loading error on line %d: %s\n", line, s);
	}

	bool load(linput_t* file)
	{
		char buf[4096];

		eLoadStage stage = ldFuncOrStruc;
		eLoadStage aOf = stage;
		qstring funOrStruc;
		literals_t* refs = NULL;
		uint32 line = 0;
		while (NULL != qlgets(buf, 4096, file)) {
			++line;
			//skip comments
			if (buf[0] == ';')
				continue;

			size_t len;
			do {
				len = qstrlen(buf);
				if (!len || (buf[len - 1] != '\n' && buf[len - 1] != '\r'))
					break;
				buf[len - 1] = 0;
			} while (1);

			if (!len) {
				stage = ldFuncOrStruc;
				continue;
			}

			//reset stage for next arg or field after literals
			if (stage == ldLit && len >= 7 && buf[0] == ' ' && buf[1] != ' ')
				stage = aOf;

			switch (stage) {
			case ldFuncOrStruc:
				if (!strncmp("STRUCT ", buf, 7)) {
					funOrStruc = &buf[7];
					stage = ldFld;
				} else if (buf[0] != ' ') {
					funOrStruc = buf;
					stage = ldArg;
					char last = funOrStruc.last();
					if(last == 'A' || last == 'W')
						ll_error(line, "Use func names without A or W in the end");
				} else {
					ll_error(line, "Func or struct name expected");
					return false;
				}
				break;
			case ldArg:
			case ldFld:
				if (len >= 7 && buf[0] == ' ') {
					char* sp = qstrchr(&buf[1], ' ');
					if (sp) {
						bool excl = false;
						if (!qstrcmp(sp + 1, "enum"))
							excl = true;
						else if (qstrcmp(sp + 1, "bits")) {
							ll_error(line, "Func arg or struct field type is not cpecified");
							return false;
						}
						if (stage == ldArg) {
							ea_t n;
							*sp = 0;
							if (atoea(&n, buf + 1)) {
								aOf = stage;
								stage = ldLit;
								lit_arg_t& a = m_functions[funOrStruc].push_back();
								a.exclusive = excl;
								a.n = (uint32)n;
								refs = &a.refs;
								break;
							}
						} else {
							aOf = stage;
							stage = ldLit;
							lit_field_t& f = m_structures[funOrStruc].push_back();
							f.exclusive = excl;
							f.name = qstring(buf + 1, sp - buf - 1);
							refs = &f.refs;
							break;
						}
					}
				}
				ll_error(line, "Func arg or struct field expected");
				return false;
			case ldLit:
				if (len >= 5 && buf[0] == ' ' && buf[1] == ' ') {
					const char* sp = qstrchr(&buf[2], ' ');
					if (sp) {
						ea_t n;
						if (atoea(&n, sp + 1)) {
							refs->insert(std::pair<uint64, qstring>(uint64(n), qstring(&buf[2], sp - &buf[2])));
							break;
						}
					}
				}
				ll_error(line, "literal expected");
				return false;
			}
		}
		return true;
	}
};

/*--------------------------------------------------------------------------*/
static literal_db* lit = NULL;
static const char* WINERROR = "WINERROR";

struct ida_local lit_visitor_t : public ctree_visitor_t
{
	cfunc_t *func;
	bool cmtModified;
	user_cmts_t *cmts;

	lit_visitor_t(cfunc_t *cfunc) : ctree_visitor_t(CV_FAST), func(cfunc), cmtModified(false) 
	{
		cmts = restore_user_cmts(cfunc->entry_ea);
		if(cmts == NULL)
			cmts = user_cmts_new();
	}

	~lit_visitor_t()
	{
		if (cmtModified)
			func->save_user_cmts();
		user_cmts_free(cmts);
	}
	virtual int idaapi visit_expr(cexpr_t *expr);
	bool chkCallArg(cexpr_t *expr, qstring &comment);
	bool chkStrucMemb(cexpr_t *memb, cexpr_t *cons, qstring &comment);
	bool chkConstType(cexpr_t *expr, cexpr_t *cons, qstring &comment);
	cexpr_t* getLiteralExp(cexpr_t *constexp, const literals_t& l, bool exclusive);
	cexpr_t* makeEnumExpr(const char* name, uint64 val, cexpr_t *constexp);
};

static qstring getLiteralString(uint64 val, const literals_t& l, bool exclusive)
{
	uint64 n = val;
	qstring str;
	auto i = l.find(val);
	if (i != l.end()) {
		str = i->second;
		n = 0;
	} else if (!exclusive) {
		for (auto j = l.begin(); j != l.end(); j++) {
			if (j->first && (n & j->first) == j->first) { //do not append zero value, possible in some flags-set
				n &= ~ j->first;
				if (!str.empty())
					str += " | ";
				str += j->second;
			}
		}
	}

	if(!str.empty()) {
		qstring prep;
		prep.sprnt("0x%x -> ", val);
		str.insert(prep);
		if(n)
			str.cat_sprnt(" | 0x%x", n);
	}
	return str;
}

static const char* importEnumFromTil(til_t *til, const char* name, uint64 val)
{
	enable_numbered_types(til, true);

#if IDA_SDK_VERSION < 840
	uint32 limit = get_ordinal_qty(til) + 1;
	if (limit == 0)
		return NULL;
#else //IDA_SDK_VERSION >= 840
	uint32 limit = get_ordinal_limit(til);
	if (limit == (uint32)-1)
		return NULL;
#endif //IDA_SDK_VERSION < 840
	for(uint32 ordinal = 1; ordinal < limit; ++ordinal)	{
		const type_t *type;
		const p_list *fields;
		if(get_numbered_type(til, ordinal, &type, &fields) && type && is_type_enum(*type) && fields) {
			tinfo_t t;
			if (t.deserialize(til, &type, &fields)) {
				enum_type_data_t ed;
				if (t.get_enum_details(&ed)) {
					for (auto memb = ed.begin(); memb != ed.end(); memb++) {
						if (val == memb->value && !qstrcmp(name, memb->name.c_str())) {
							const char* typeName = get_numbered_type_name(til, ordinal);
							if (typeName) {
#if IDA_SDK_VERSION < 850
								import_type(til, -1, typeName);
								Log(llInfo, "import enum \"%s\" from til \"%s\"\n", typeName, til->name);
#endif //IDA_SDK_VERSION < 850
								return typeName;
							}
							Log(llWarning, "not named enum for \"%s\" 0x%x \n", name, val);
							return NULL;
						}
					}
				}
			}
		}
	}
	return NULL;
}

static const char* importEnumFromTils(const char* name, uint64 val)
{
	Log(llDebug, "find enum memb %s (0x%x) in tils\n", name, val);
	til_t *til = (til_t *)get_idati();
	const char* typeName = importEnumFromTil(til, name, val);
	if(typeName)
		return typeName;

	for (int i = 0; i < til->nbases; i++) {
			const char* typeName = importEnumFromTil(til->base[i], name, val);
			if (typeName)
				return typeName;
	}

	//load_til,	load_til2, add_base_tils

	//TODO: cache not found names, to not search again
	return NULL;
}

cexpr_t* lit_visitor_t::makeEnumExpr(const char* name, uint64 val, cexpr_t *constexp)
{
#if IDA_SDK_VERSION < 850
	const_t memb = get_enum_member_by_name(name);
	if(memb == BADNODE) {
		if(!importEnumFromTils(name, val)) 
			return NULL;
		memb = get_enum_member_by_name(name);
		if(memb == BADNODE)
			return NULL;
	}

	enum_t en = get_enum_member_enum(memb);
	if(en == BADNODE)
		return NULL;
	qstring enName = get_enum_name(en);
	if(enName.empty())
		return NULL;
	auto serial = get_enum_member_serial(memb);
#else //IDA_SDK_VERSION >= 850
	//FIXME: I've not found fast way to get enum type-name from member-name, maybe need to implement some cashing?
	const char* typeName = importEnumFromTils(name, val);
	if(!typeName)
		return NULL;
	uchar serial = 0; //FIXME: does it matter???
	qstring enName = typeName;
#endif //IDA_SDK_VERSION < 850

	cexpr_t* newexp = new cexpr_t();
	newexp->ea = constexp->ea;
	newexp->put_number(func, val, constexp->n->nf.org_nbytes); //PH.get_default_enum_size(inf.cc.cm);
	newexp->n->nf.org_nbytes = constexp->n->nf.org_nbytes;
	newexp->n->nf.flags = enum_flag();
	newexp->n->nf.serial = serial;
	newexp->n->nf.type_name = enName;
#if IDA_SDK_VERSION >= 750
	newexp->n->nf.props |= NF_VALID; // no any other way to set enum, but ida 7.5 raise INTERR 52381 w/o NF_VALID flag
	newexp->type = create_typedef(enName.c_str()); // ida 7.5 raise INTERR 52378 w/o this
#endif // IDA_SDK_VERSION >= 750
	return newexp;
}

cexpr_t* lit_visitor_t::getLiteralExp(cexpr_t *constexp, const literals_t& l, bool exclusive)
{
	uint64 n = constexp->n->_value;
	cexpr_t* exp = NULL;
	auto i = l.find(n);
	if (i != l.end()) {
		exp = makeEnumExpr(i->second.c_str(), i->first, constexp);
		n = 0;
	}	else if (!exclusive) {
		for (auto j = l.begin(); j != l.end(); j++) {
			if (j->first && (n & j->first) == j->first) { //do not append zero value, possible in some flags-set
				cexpr_t* newexp = makeEnumExpr(j->second.c_str(), j->first, constexp);
				if (newexp) {
					if (exp)
						exp = new cexpr_t(cot_bor, exp, newexp);
					else
						exp = newexp;
					n &= ~j->first;
				}
			}
		}
	}

	if(exp) {
		if(n) {
			cexpr_t* newexp = new cexpr_t();
			newexp->put_number(func, n, 4);
			exp = new cexpr_t(cot_bor, exp, newexp);
		}
		exp->calc_type(true);
	}
	return exp;
}

//check func args
bool lit_visitor_t::chkCallArg(cexpr_t *expr, qstring &comment)
{
	if(expr->op != cot_call)
		return false;
	carglist_t &args = *expr->a;
	if(!args.size())
		return false;

	qstring funcname;
	if(!getExpName(func, expr->x, &funcname))
		return false;
	if(funcname.length() < 2)
		return false;
	lit_func_t lfunc = lit->find_func(funcname.c_str());
	if(!lit->is_func(lfunc)) {
		char lastChar = funcname.last();
		if(lastChar != 'A' && lastChar != 'W') 
			return false;
		funcname.remove_last();
		lfunc = lit->find_func(funcname.c_str());
		if (!lit->is_func(lfunc))
			return false;
	}

	bool res = false;
	for(size_t i = 0; i < args.size(); i++) {
		cexpr_t *arg = skipCast(&args[i]);//ignore typecast
		if(arg->op == cot_num && !arg->n->nf.is_enum() && !(arg->n->nf.flags & NF_FIXED)) {
			const lit_arg_t* larg = lit->find_arg(lfunc, (uint32)i + 1);
			if (larg) {
				uint64 val = arg->n->_value; // numval()
				qstring s = getLiteralString(val, larg->refs, larg->exclusive);
				appendComment(comment, s);
				cexpr_t* newExp = getLiteralExp(arg, larg->refs, larg->exclusive);
				if (newExp) {
					replaceExp(func, arg, newExp);
					res = true;
				}
			}
		}
	}
	return res;
}

//check struct members
bool lit_visitor_t::chkStrucMemb(cexpr_t *memb, cexpr_t *cons, qstring &comment)
{
	tinfo_t type = memb->x->type;
	type.remove_ptr_or_array();
	if(!type.is_struct() && !type.is_union()) //t->is_decl_struct()
		return false;

	qstring typeName;
	if(!type.get_type_name(&typeName))
		type.print(&typeName);

	if(!typeName.length())
		return false;

	// remove first underlining from struct typename
	if (typeName[0] == '_') 
		typeName.remove(0, 1);

	lit_struct_t ls = lit->find_struct(typeName.c_str());
	if (!lit->is_struct(ls)) {
		char lastChar = typeName.last();
		if (lastChar != 'A' && lastChar != 'W')
			return false;
		typeName.remove_last();
		ls = lit->find_struct(typeName.c_str());
		if (!lit->is_struct(ls)) 
			return false;
	}

	udm_t m;
	m.offset = memb->m;
	if (-1 == type.find_udm(&m, STRMEM_AUTO))
		return false;

	const lit_field_t* f = lit->find_field(ls, m.name.c_str());
	if (!f)
		return false;

	uint64 val = cons->n->_value; // numval()
	qstring s = getLiteralString(val, f->refs, f->exclusive);
	appendComment(comment, s);
	cexpr_t *newExp = getLiteralExp(cons, f->refs, f->exclusive);
	if(newExp) {
		replaceExp(func, cons, newExp);
		return true;
	}
	return false;
}

bool lit_visitor_t::chkConstType(cexpr_t *expr, cexpr_t *cons, qstring &comment)
{
	tinfo_t type;
	if (expr->op == cot_cast)
		type = expr->type;
	else
		type = expr->theother(cons)->type;

	qstring typeName;
	if (!type.get_type_name(&typeName)) {
		//type.print(&typeName); // for debugging only
		return false;
	}

	if (!typeName.length())
		return false;

	const literals_t* l = NULL;
	bool exclusive;
	if (typeName == WINERROR) {
		lit_func_t flit = lit->find_func("RtlGetLastWin32Error");
		if (!lit->is_func(flit))
			return false;
		const lit_arg_t *la = lit->find_arg(flit, 0);
		if (!la)
			return false;
		l = &la->refs;
		exclusive = la->exclusive;
	}
#if IDA_SDK_VERSION < 750  //ida 7.5 raise INTERR 52378 (type name conflict? "HANDLE" & "MACRO_INVALID_HANDLE")
	else if (typeName == "HANDLE") {
		uint64 val = cons->n->_value; // numval()
		const char* name;
		switch (val) {
		case (uint64)-1:  name = "INVALID_HANDLE_VALUE";  break;
		case (uint64)-10: name = "STD_INPUT_HANDLE";      break;
		case (uint64)-11: name = "STD_OUTPUT_HANDLE";     break;
		case (uint64)-12: name = "STD_ERROR_HANDLE";      break;
		default:
			return false;
		}
		cexpr_t *newExp = makeEnumExpr(name, val, cons);
			//IDA bug: prints INVALID_FILE_SIZE instead INVALID_HANDLE_VALUE
		if (newExp) {
			newExp->type = expr->type;
			replaceExp(func, expr, newExp);
			return true;
		}		
		return false;
	}	else {
		//TODO: add more typenames here
		return false;
	}
#endif // IDA_SDK_VERSION < 750
	if (!l)
		return false;

	uint64 val = cons->n->_value; // numval()
	qstring s = getLiteralString(val, *l, exclusive);
	appendComment(comment, s);
	cexpr_t *newExp = getLiteralExp(cons, *l, exclusive);
	if (newExp) {
		replaceExp(func, cons, newExp);
		return true;
	}
	return false;
}

int idaapi lit_visitor_t::visit_expr(cexpr_t *expr)
{
	qstring comment;
	bool changed = false;
	if(expr->op == cot_call) {
		changed |= chkCallArg(expr, comment);
	} else if((expr->op >= cot_asg && expr->op <= cot_ult)) {
		cexpr_t *cons = expr->find_op(cot_num);
		if(cons) {
			cexpr_t *memb = expr->theother(cons);
			if(memb->op == cot_memref || memb->op == cot_memptr)
				changed |= chkStrucMemb(memb, cons, comment);
			else 
				changed |= chkConstType(expr, cons, comment);
		}
	}	else if (expr->op == cot_cast && expr->x->op == cot_num) {
		changed |= chkConstType(expr, expr->x, comment);
	}

	cmtModified |= setComment4Exp(func, cmts, expr, comment.c_str(), changed);
	return 0;
}

void lit_scan(cfunc_t *cfunc)
{
	if(!lit)
		return;
	lit_visitor_t lv(cfunc);
	lv.apply_to(&cfunc->body, NULL);
}

//create_typedef
//set_type
//ctree_parentee_t or cfunc_parentee_t

bool lit_overrideTypes()
{
	if (!lit)
		return true;

	if (get_named_type(NULL, WINERROR, NTF_TYPE | NTF_NOBASE))
		return true;

	uint32 ord = alloc_type_ordinal(NULL);
	if (!ord)
		return false;

	tinfo_t t;
	t.create_simple_type(BT_INT32);
	t.set_named_type(NULL, WINERROR, 0);

	const char* const funcnames[] = {"GetLastError", "__imp_GetLastError", "RtlGetLastWin32Error", "RegOpenKey"};
	for(size_t i = 0, n = qnumber(funcnames); i < n; i++) {
		ea_t ea = get_name_ea(BADADDR, funcnames[i]);
		if (ea == BADADDR /*|| is_func(get_flags(ea))*/)
			continue;
		tinfo_t ft;
		get_tinfo(&ft, ea);
		bool ptr = ft.remove_ptr_or_array();
		if (ft.is_decl_func()) {
			func_type_data_t fi;
			if (ft.get_func_details(&fi)) {
				fi.rettype = t;
				tinfo_t newFType;
				newFType.create_func(fi);
				if (ptr)
					newFType = make_pointer(newFType);
				if (apply_tinfo(ea, newFType, TINFO_DEFINITE | TINFO_STRICT)) {
					qstring typeStr;
					newFType.print(&typeStr);
					Log(llInfo, "Function %a %s was recast to \"%s\"\n", ea, funcnames[i], typeStr.c_str());
				}
			}
		}
	}
	return true;
}

void lit_init()
{
	char litfname[QMAXPATH];
	if(getsysfile(litfname, QMAXPATH, "literal.txt", PLG_SUBDIR)) {
		linput_t *litfile = open_linput(litfname, false);
		if (litfile) {
			lit = new literal_db();
			bool ld = lit->load(litfile);
			close_linput(litfile);
			if (ld)
				return;
			delete lit;
			lit = NULL;
		}
	}
	Log(llWarning, "Error loading '%s', enum autoresolve is turned off\n", litfname);
}

void lit_done()
{
	if (lit) {
		delete lit;
	}
	lit = NULL;
}
