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

/*
 * Search and rename the following entities:
 * func and arg names
 * global and local vars
 * type and udt member names
 * msig names
 */


#include "warn_off.h"
#include <pro.h>
#include <hexrays.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <regex.h>
#if IDA_SDK_VERSION >= 770
#include <dirtree.hpp>
#endif // IDA_SDK_VERSION >= 770
#include "warn_on.h"

#include "helpers.h"
#include "msig.h"
#include "rename.h"
#include "structures.h"
#include "refactoring.h"

enum eRF_kind_t {
	eRF_funcName,
	eRF_funcArg,
	eRF_glblVar,
	eRF_loclVar,
	eRF_usrCmts,
	eRF_numFmt,
	eRF_typeName,
	eRF_udmName,
	eRF_msigName,
	eRF_notepad,
	eRF_last
};

const char* eRFkindName(eRF_kind_t kind)
{
	switch(kind) {
	case eRF_funcName: return "func";
	case eRF_funcArg:  return "farg";
	case eRF_glblVar:  return "gvar";
	case eRF_loclVar:  return "lvar";
	case eRF_usrCmts:  return "cmts";
	case eRF_numFmt:   return "nfmt";
	case eRF_typeName: return "type";
	case eRF_udmName:  return "udm";
	case eRF_msigName: return "msig";
	case eRF_notepad:  return "note";
	default:           return "unk";
	}
}

eRF_kind_t eRFname2kind(const char* n)
{
	if(!qstrcmp(n, "func")) return eRF_funcName;
	if(!qstrcmp(n, "farg")) return eRF_funcArg;
	if(!qstrcmp(n, "gvar")) return eRF_glblVar;
	if(!qstrcmp(n, "lvar")) return eRF_loclVar;
	if(!qstrcmp(n, "cmts")) return eRF_usrCmts;
	if(!qstrcmp(n, "nfmt")) return eRF_numFmt;
	if(!qstrcmp(n, "type")) return eRF_typeName;
	if(!qstrcmp(n, "udm"))  return eRF_udmName;
	if(!qstrcmp(n, "msig")) return eRF_msigName;
	if(!qstrcmp(n, "note")) return eRF_notepad;
	return eRF_last;
}

struct refac_t;

struct ida_local rf_match_t {
	qstring name;
	ea_t ea;
	eRF_kind_t kind;
	bool deleted;
	bool validateReplace(const refac_t* rf, qstring* repl) const;
};
DECLARE_TYPE_AS_MOVABLE(rf_match_t);
typedef qvector<rf_match_t> rf_matches_t;

//--------------------------------------------------------------------------

#if IDA_SDK_VERSION >= 770
struct ida_local rf_dirspec_t : public dirspec_t
{
	refac_t* rf;
	dirvec_t dirvec;
	rf_dirspec_t(refac_t* rf_) : dirspec_t(nullptr, 0/*DSF_ORDERABLE*/), rf(rf_) {}
	virtual ~rf_dirspec_t() {}
	virtual bool get_name(qstring* out, inode_t inode, uint32 name_flags = DTN_FULL_NAME);
	virtual inode_t get_inode(const char* dirpath, const char* name);
  virtual qstring get_attrs(inode_t) const 	{	return qstring("attrs");	}
  virtual bool rename_inode(inode_t, const char *) {	return false;	}
};
#endif //IDA_SDK_VERSION >= 770

//--------------------------------------------------------------------------
qstring msig_search(void* ctx, const char* name);
qstring msig_replace(void* ctx, const char* name);

// !!! these flags below depend on order of checkboxes in the open_form below
//"<Case sensitive:c><|><Whole words only:c><|><Use regular expression:c>4>\n\n";
#define RFF_CASESN 1
#define RFF_WWORDS 2
#define RFF_REGEXP 4

struct ida_local refac_t {
	TWidget* rfform = nullptr;
	qstring searchFor;
	qstring replaceWith;
	ushort flags = RFF_WWORDS; // see RFF_* above
	rf_matches_t matches;
	regex_ptr_t re;
#if IDA_SDK_VERSION >= 770
	rf_dirspec_t ds;
	dirtree_t dt;
#endif //IDA_SDK_VERSION >= 770

	refac_t(const char *sname) : searchFor(sname), replaceWith(sname), re(NULL)
#if IDA_SDK_VERSION >= 770
	, ds(this), dt(&ds)
#endif //IDA_SDK_VERSION >= 770
	{
		searchFor.trim2();
		replaceWith.trim2();
	}

	void clear()
	{
#if IDA_SDK_VERSION >= 770
		for(size_t i = 0; i < matches.size(); i++) {
			qstring path;
			path.sprnt("/%s/%s", eRFkindName(matches[i].kind), matches[i].name.c_str());
			//if(dt.resolve_path(path.c_str()).valid())
				dt.unlink(path.c_str());
		}
		for (int i = 0; i < eRF_last; i++)
			dt.rmdir(eRFkindName((eRF_kind_t)i));
#endif //IDA_SDK_VERSION >= 770
		matches.clear();
	}

	bool isWord(char c) const
	{
		if((c >= 'a' && c <= 'z') ||
			 (c >= 'A' && c <= 'Z') ||
			 (c >= '0' && c <= '9'))
				return true;
		return false;
	}

	size_t find_ex(const qstring &s, const qstring &searchFor, size_t pos, bool casesn) const
  {
    if(pos <= s.length()) {
      const char *bgn = s.c_str();
      const char *fnd;
			if(casesn)
				fnd = qstrstr(bgn + pos, searchFor.c_str());
			else
				fnd = stristr(bgn + pos, searchFor.c_str());
      if ( fnd != nullptr )
        return fnd - bgn;
    }
    return qstring::npos;
  }

	bool match(const qstring &s, qstring *r = nullptr) const
	{
		if(s.empty())
			return false;
		if(r)
			r->reserve(s.size());

		bool res = false;
		size_t so = 0;
		size_t prev = 0;
		while(1) {
			prev = so;
			if(prev >= s.length())
				break;
			size_t eo;
			if(re != NULL && (flags & RFF_REGEXP)) {
				regmatch_t m;
				if(re->exec(s.c_str() + so, 1, &m, 0))
					break;
				eo = so + m.rm_eo;
				so = so + m.rm_so;
			} else {
				so = find_ex(s, searchFor, so, (flags & RFF_CASESN) != 0);
				if(so == qstring::npos)
					break;
				eo = so + searchFor.length();
			}

			//check word boundaries, '_' is excluded from the set of word chars
			if((flags & RFF_WWORDS) != 0 &&
				 ((so > 0 && isWord(s[so - 1])) ||
					(eo < s.length() && isWord(s[eo])))) {
				Log(llFlood, "unmatch `%s %d %d`\n", s.c_str(), so, eo);
				if(r && eo > prev)
					r->append(s.c_str() + prev, eo - prev);
				so = eo;
				continue;
			}
			//qstring match(s.c_str() + so, eo - so);
			//Log(llFlood, "match `%s` in %s\n", match.c_str(), s.c_str());

			res = true;
			if(!r) // find once if not replace
				break;
			if(so > prev)
				r->append(s.c_str() + prev, so - prev);
			r->append(replaceWith);
			so = eo;
		}
		if(r && res && s.length() > prev)
			r->append(s.c_str() + prev, s.length() - prev);
		return res && (!r || r->length());
	}
	void add(const char* name, eRF_kind_t kind, ea_t ea)
	{
		rf_match_t &m = matches.push_back();
		m.name = name;
		m.kind = kind;
		m.ea = ea;
		m.deleted = false;

#if IDA_SDK_VERSION >= 770
		//mkdir if not exist
		const char* dir = eRFkindName(kind);
		//if(!dt.resolve_path(dir).valid())
			dt.mkdir(dir);

		qstring path;
		path.sprnt("/%s/%s", dir, name);
		//if(!dt.resolve_path(path.c_str()).valid())
		dt.link(path.c_str());
		Log(llDebug, "add match `%s` (%a)\n", path.c_str(), ea);
#endif //IDA_SDK_VERSION >= 770
	}

	bool search()
	{
		clear();

		if(searchFor.empty())
			return false;
		Log(llDebug, "search '%s', flags %d\n", searchFor.c_str(), flags);

		if((flags & RFF_REGEXP) != 0) {
			//check and cache regexp
			qstring errmsg;
      re = regex_ptr_t(refcnted_regex_t::create(searchFor, !(flags & RFF_CASESN), &errmsg));
			if(re == NULL) {
				warning("[hrt] regexp error '%s'", errmsg.c_str());
				return false;
			}
		}

		// func name, type, local vars and comments
		size_t funcqty = get_func_qty();
		for (size_t i = 0; i < funcqty; i++) {
			func_t* func = getn_func(i);
			if(!func || (func->flags & FUNC_LIB))
				continue;
			ea_t ea = func->start_ea;
			qstring eaname = get_name(ea);

			//match name of functions an global vars
			if(match(eaname))
				add(eaname.c_str(), eRF_funcName, ea);

			//match func type args
			tinfo_t tif;
			if(/*is_userti(ea) &&*/ get_tinfo(&tif, ea)) {
				tif.remove_ptr_or_array();
				if(/*!tif.is_from_subtil() &&*/ tif.is_decl_func()) {
					func_type_data_t fi;
					if(tif.get_func_details(&fi, GTD_NO_ARGLOCS)) {
						for(size_t i = 0; i < fi.size(); i++) {
							if(match(fi[i].name)) {
								qstring t;
								if(!tif.print(&t, eaname.c_str()))
									t = tif.dstr();
								add(t.c_str(), eRF_funcArg, ea);
								break;
							}
						}
					}
				}
			}

#ifndef _DEBUG // restore_user_lvar_settings may cause crash somewhere deep inside decompiler on access nullptr exception on Windows in Debug mode (prbbl because of std::map)
			//match func local vars
			lvar_uservec_t lvinf;
			if(restore_user_lvar_settings(&lvinf, ea)) {
				qstring nn;
				for(size_t i = 0; i < lvinf.lvvec.size(); i++) {
					if(match(lvinf.lvvec[i].name)) {
						if(!nn.empty())
							nn.append(' ');
						nn.append(lvinf.lvvec[i].name);
					}
				}
				if(!nn.empty()) {
					nn.append(" @ ");
					nn.append(eaname);
					add(nn.c_str(), eRF_loclVar, ea);
				}
			}
#endif

			//match func local comments
			user_cmts_t *cmts = restore_user_cmts(ea);
			if(cmts) {
				for(auto it = user_cmts_begin(cmts); it != user_cmts_end(cmts); it = user_cmts_next(it)) {
					citem_cmt_t &c = user_cmts_second(it);
					if(match(c)) {
						if(c.find('\n') == qstring::npos) {
							add(c.c_str(), eRF_usrCmts, user_cmts_first(it).ea);
						} else {
							//split multiline comment to lines (qstring::split is not exist in older ida)
							qstrvec_t lines;
							const char *from = c.begin();
							const char *end  = c.end();
							while(from < end) {
								const char *to =  qstrchr(from, '\n');
								if(!to)
									to = end;
								lines.push_back().append(from, to - from);
								from = to + 1;
							}
							for(size_t i = 0; i < lines.size(); i++) {
								if(match(lines[i])) {
									add(lines[i].c_str(), eRF_usrCmts, user_cmts_first(it).ea);
									break; // one is enough
								}
							}
						}
					}
				}
				user_cmts_free(cmts);
			}

			//match number formats
			user_numforms_t *nfs = restore_user_numforms(ea);
			if(nfs) {
				for(auto it = user_numforms_begin(nfs); it != user_numforms_end(nfs); it = user_numforms_next(it)) {
					number_format_t &nf = user_numforms_second(it);
					if(match(nf.type_name))
						add(nf.type_name.c_str(), eRF_numFmt, user_numforms_first(it).ea);
				}
				user_numforms_free(nfs);
			}
		} // end of proc list loop

		//match name of global var
		size_t nqty = get_nlist_size();
		for(size_t i = 0; i < nqty; i++) {
			ea_t ea = get_nlist_ea(i);
			flags64_t flg = get_flags(ea);
			if(is_data(flg) && has_any_name(flg)) {
				qstring eaname = get_name(ea);
				if(match(eaname))
					add(eaname.c_str(), eRF_glblVar, ea);
			}
		}

		//struct/union names amd members
#if IDA_SDK_VERSION < 850
		for(uval_t idx = get_first_struc_idx(); idx != BADNODE; idx = get_next_struc_idx(idx)) {
			tid_t id = get_struc_by_idx(idx);
			qstring strucname = get_struc_name(id);
			if(match(strucname))
				add(strucname.c_str(), eRF_typeName, id);

			struc_t * struc = get_struc(id);
			if(!struc)
				continue;
			for(uint32 i = 0; i < struc->memqty; i++) {
				qstring membName;
				get_member_name(&membName, struc->members[i].id);
				if (match(membName)) {
					qstring fullname(strucname);
					fullname.append('.');
					fullname.append(membName);
					add(fullname.c_str(), eRF_udmName, struc->members[i].id);
				}
			}
		}
#else //IDA_SDK_VERSION < 850
		//type and udm names
		uint32 limit = get_ordinal_limit();
		if (limit != uint32(-1)) {
			for(uint32 ord = 1; ord < limit; ++ord) {
				tinfo_t t;
				if(t.get_numbered_type(nullptr, ord)) {
					qstring tname;
					if(t.get_type_name(&tname)) {
						if(match(tname))
							add(tname.c_str(), eRF_typeName, t.get_tid());
					}
					if(t.is_udt()) {
						udt_type_data_t udt;
						if (t.get_udt_details(&udt)) {
							for (size_t i = 0; i < udt.size(); ++i) {
								udm_t& member = udt.at(i);
								if(match(member.name)) {
									qstring fullname = tname;
									fullname.append('.');
									fullname.append(member.name);
									add(fullname.c_str(), eRF_udmName, t.get_udm_tid(i));
								}
							}
						}
					}
				}
			}
		}
#endif //IDA_SDK_VERSION < 850

		msig_rename(msig_search, this);

		//notepad
		qstring notes;
		if(get_ida_notepad_text(&notes)) {
			//split to lines (qstring::split is not exist in older ida)
			qstrvec_t lines;
			const char *from = notes.begin();
			const char *end  = notes.end();
			while(from < end) {
				const char *to =  qstrchr(from, '\n');
				if(!to)
					to = end;
				lines.push_back().append(from, to - from);
				from = to + 1;
			}
			for(size_t i = 0; i < lines.size(); i++) {
				if(match(lines[i]))
					add(lines[i].c_str(), eRF_notepad, i);
			}
		}
		return true;
	}

	bool validateReplace() const
	{
		qstring repl;
		for(size_t i = 0; i < matches.size(); i++) {
			repl.qclear();
			if(!matches[i].validateReplace(this, &repl))
				 return false;
		}
		return true;
	}

	void replace()
	{
		Log(llDebug, "Refactoring '%s' -> '%s': replace %d matches \n", searchFor.c_str(), replaceWith.c_str(), matches.size());
		uint32 count = 0;
		uint32 failc = 0;
		uint32 msigcount = 0;
		uint32 notecount = 0;
		for(size_t i = 0; i < matches.size(); i++) {
			const rf_match_t &m = matches[i];
			if(m.deleted) {
				Log(llDebug, "Refactoring %a: skip deleted %s - '%s'\n", m.ea, eRFkindName(m.kind), m.name.c_str());
				continue;
			}
			switch(m.kind) {
			case eRF_funcName:
			case eRF_glblVar:
			{
				flags64_t flg = get_flags(m.ea);
				if(is_func(flg) || (is_data(flg) && has_any_name(flg))) {
					qstring eaname = get_name(m.ea);
					qstring newname;
					if(match(eaname, &newname)) {
						stripName(&newname, is_func(flg));
						if(renameEa(m.ea, m.ea, &newname))
							++count;
						else
							++failc;
					}
				}
				break;
			}
			case eRF_funcArg:
			{
				tinfo_t tif;
				if(/*is_userti(ea) &&*/ get_tinfo(&tif, m.ea)) {
					tif.remove_ptr_or_array();
					if(/*!tif.is_from_subtil() &&*/ tif.is_decl_func()) {
						func_type_data_t fi;
						if(tif.get_func_details(&fi)) {
							bool changed = false;
							for(size_t i = 0; i < fi.size(); i++) {
								qstring newname;
								if(match(fi[i].name, &newname)) {
									stripName(&newname);
									newname = unique_name(newname.c_str(), "_", [&fi, i](const qstring &n)
									{
										for(size_t j = 0; j < fi.size(); j++){
											if(fi[i].name == n) {
												if(i == j)
													return true;
												else
													return false;
											}
										}
										return true;
									});
									changed = true;
									fi[i].name = newname;
									++count;
								}
							}
							if(changed) {
								tinfo_t newFType;
								if(newFType.create_func(fi) && newFType.is_correct() && apply_tinfo(m.ea, newFType, is_userti(m.ea) ? TINFO_DEFINITE : TINFO_GUESSED)) {
									Log(llInfo, "Refactoring %a: function args type changed to \"%s\"\n", m.ea, newFType.dstr());
									break;
								}
							}
						}
					}
				}
				++failc;
				Log(llWarning, "Refactoring %a: fail function args type change '%s'\n", m.ea, m.name.c_str());
				break;
			}
			case eRF_loclVar:
			{
#ifndef _DEBUG   // restore_user_lvar_settings may cause crash somewhere deep inside decompiler on access nullptr exception on Windows in Debug mode
			  // save_user_lvar_settings cause internal error 1099 on the same sample
				lvar_uservec_t lvinf;
				if(is_func(get_flags(m.ea)) && restore_user_lvar_settings(&lvinf, m.ea)) {
					uint32 changed = 0;
					for(size_t i = 0; i < lvinf.lvvec.size(); i++) {
						qstring newname;
						if(match(lvinf.lvvec[i].name, &newname)) {
							stripName(&newname);
							newname = unique_name(newname.c_str(), "_", [&lvinf, i](const qstring &n)
							{
								for(size_t j = 0; j < lvinf.lvvec.size(); j++){
									if(lvinf.lvvec[j].name == n) {
										if(i == j)
											return true;
										else
											return false;
									}
								}
								return true;
							});
							lvinf.lvvec[i].name = newname;
							++changed;
						}
					}
					if(changed) {
						save_user_lvar_settings(m.ea, lvinf);
						count += changed;
						Log(llInfo, "Refactoring %a: %d local var%s renamed\n", m.ea, changed, changed > 1 ? "s" : "");
						break;
					}
				}
				++failc;
				Log(llWarning, "Refactoring %a: fail local vars renaming '%s'\n", m.ea, m.name.c_str());
#endif
				break;
			}
			case eRF_usrCmts:
			{
				user_cmts_t *cmts = nullptr;
				func_t *fn = get_func(m.ea);
				if(fn && (cmts = restore_user_cmts(fn->start_ea)) != nullptr) {
					uint32 changed = 0;
					for(auto it = user_cmts_begin(cmts); it != user_cmts_end(cmts); it = user_cmts_next(it)) {
						if(user_cmts_first(it).ea == m.ea) {
							citem_cmt_t &c = user_cmts_second(it);
							qstring newcmt;
							if(match(c, &newcmt)) {
								c.qclear(); c.append(newcmt);
								++changed;
							}
						}
					}
					if(changed) {
						save_user_cmts(fn->start_ea, cmts);
						user_cmts_free(cmts);
						count += changed;
						Log(llInfo, "Refactoring %a: %d local comments replaced\n", m.ea, changed);
						break;
					}
					user_cmts_free(cmts);
				}
				++failc;
				Log(llWarning, "Refactoring %a: fail local comments replace '%s'\n", m.ea, m.name.c_str());
				break;
			}
			case eRF_numFmt:
			{
				user_numforms_t *nfs = nullptr;
				func_t *fn = get_func(m.ea);
				if(fn && (nfs = restore_user_numforms(fn->start_ea)) != nullptr) {
					uint32 changed = 0;
					for(auto it = user_numforms_begin(nfs); it != user_numforms_end(nfs); it = user_numforms_next(it)) {
						if(user_numforms_first(it).ea == m.ea) {
							number_format_t &nf = user_numforms_second(it);
							qstring newtn;
							if(match(nf.type_name, &newtn)) {
								nf.type_name = newtn;
								++changed;
							}
						}
					}
					if(changed) {
						save_user_numforms(fn->start_ea, nfs);
						user_numforms_free(nfs);
						count += changed;
						Log(llInfo, "Refactoring %a: %d user defined number formats replaced\n", m.ea, changed);
						break;
					}
					user_numforms_free(nfs);
				}
				++failc;
				Log(llWarning, "Refactoring %a: fail user defined number format replace '%s'\n", m.ea, m.name.c_str());
				break;
			}
			case eRF_typeName:
			{
				qstring oldname;
				qstring newname;
#if IDA_SDK_VERSION < 850
				oldname = get_struc_name(m.ea);
				if(match(oldname, &newname)) {
					 stripName(&newname);
					 if(set_struc_name(m.ea, newname.c_str())) {
#else //IDA_SDK_VERSION < 850
				tinfo_t t;
				if(t.get_type_by_tid(m.ea) && t.get_type_name(&oldname) && match(oldname, &newname)) {
					stripName(&newname);
					if(TERR_OK == t.rename_type(newname.c_str(), NTF_NO_NAMECHK)) {
#endif //IDA_SDK_VERSION < 850
						++count;
						Log(llInfo, "Refactoring %a: type '%s' renamed to '%s'\n", m.ea, oldname.c_str(), newname.c_str());
						break;
					}
				}
				++failc;
				Log(llWarning, "Refactoring %a: fail type renaming '%s'\n", m.ea, m.name.c_str());
				break;
			}
			case eRF_udmName:
			{
				qstring newname;
#if IDA_SDK_VERSION < 850
				qstring oldname;
				struc_t *struc;
				member_t *memb = get_member_by_id(&oldname, m.ea, &struc);
				qstring mname = get_member_name(m.ea);
				if(memb && match(mname, &newname)) {
					newname = good_smember_name(struc, memb->soff, newname.c_str());
					if(set_member_name(struc, memb->soff, newname.c_str())) {
#else //IDA_SDK_VERSION < 850
				udm_t udm;
				tinfo_t t;
				ssize_t idx = t.get_udm_by_tid(&udm, m.ea);
				if(idx >= 0 && match(udm.name, &newname)) {
					stripName(&newname);
					newname = good_udm_name(t, udm.offset, newname.c_str());
					qstring oldname; t.get_type_name(&oldname); oldname.append('.'); oldname.append(udm.name);
					if(TERR_OK == t.rename_udm(idx, newname.c_str())) {
#endif //IDA_SDK_VERSION < 850
						++count;
						Log(llInfo, "Refactoring %a: struct member '%s' renamed to '%s'\n", m.ea, oldname.c_str(), newname.c_str());
						break;
					}
				} else {
					//vtbl member may already be renamed by idb_event::renamed callback
					eavec_t eav;
					get_memb2proc_refs(m.ea, &eav);
					if(eav.size() && get_name(eav.front()).find(replaceWith) != qstring::npos)
						break;
				}
				++failc;
				Log(llWarning, "Refactoring %a: fail struct member renaming '%s'\n", m.ea, m.name.c_str());
				break;
			}
			case eRF_msigName:
				++msigcount;
				break;
			case eRF_notepad:
				++notecount;
				break;
			default:
				Log(llError, "Refactoring %a: unk kind %d\n", m.ea, m.kind);
			}
		}
		if(msigcount) {
			//all MSIGs are renamed at once
			uint32 cnt = msig_rename(msig_replace, this);
			Log(llInfo, "Refactoring: %d msigs renamed\n", cnt);
			count += cnt;
			failc += msigcount - cnt;
		}
		if(notecount) {
			qstring notes;
			if(get_ida_notepad_text(&notes)) {
				qstring newnotes;
				if(match(notes, &newnotes)) {
					set_ida_notepad_text(newnotes.c_str());
					count += notecount;
				}
			}
		}

		Log(llNotice, "Refactoring '%s' -> '%s': %d changes, %d fails\n", searchFor.c_str(), replaceWith.c_str(), count, failc);
		if(count)
			clear_cached_cfuncs();
	}
};

//--------------------------------------------------------------------------
bool rf_match_t::validateReplace(const refac_t* rf, qstring* repl) const
{
	if(deleted)
		return true;

	if(!rf->match(name, repl) || repl->empty())
		return false;

	if(kind == eRF_typeName) {
		tinfo_t t = getType4Name(repl->c_str(), true);
		if(!t.empty() && !t.is_func()) {
#if IDA_SDK_VERSION < 850
			qstring tName;
			tid_t tid = BADNODE;
			if(t.get_type_name(&tName))
				tid = get_struc_id(tName.c_str());
#else //IDA_SDK_VERSION >= 850
			tid_t tid = t.get_tid()	;
#endif //IDA_SDK_VERSION < 850
			if(tid != BADNODE && tid != ea) {
				Log(llWarning, "Refactoring: type conflict '%s' - '%s' (%a - %a)\n", t.dstr(), repl->c_str(), tid, ea);
				return false;
			}
		}
		if(!validate_name(repl, VNT_TYPE, SN_CHECK | SN_NOWARN))
			return false;
	}
	return true;
}

//--------------------------------------------------------------------------
qstring msig_search(void* ctx, const char* name)
{
	refac_t* rf = (refac_t*)ctx;
	if(rf->match(qstring(name)))
		rf->add(name, eRF_msigName, BADADDR);
	return qstring();
}
qstring msig_replace(void* ctx, const char* name)
{
	refac_t* rf = (refac_t*)ctx;
	qstring newname;
	if(rf->match(qstring(name), &newname))
		return newname;
	return qstring();
}

//--------------------------------------------------------------------------
static const int rcwidths[] = { 45 | CHCOL_PLAIN | CHCOL_INODENAME, 45  | CHCOL_PLAIN, 16 | CHCOL_EA | CHCOL_DEFHIDDEN, 4 | CHCOL_PLAIN
#if IDA_SDK_VERSION >= 770
																| CHCOL_DEFHIDDEN
#endif //IDA_SDK_VERSION >= 770
															};
static const char *const rcheader[] = { "Found", "#The real result may vary#Replace to (*)", "Address/TypeID", "Kind"};

struct ida_local rf_chooser_t : public chooser_t
{
	refac_t* rf;
	int problemIcon = -1;

	rf_chooser_t(refac_t* rf_) : chooser_t(
#if IDA_SDK_VERSION >= 770
																 CH_HAS_DIRTREE | CH_TM_FULL_TREE | CH_NON_PERSISTED_TREE |
#endif //IDA_SDK_VERSION >= 770
																 CH_CAN_DEL, qnumber(rcwidths), rcwidths, rcheader, "[hrt] Refactoring"), rf(rf_)
	{
		get_action_icon("OpenProblems", &problemIcon);
	}
	virtual ~rf_chooser_t() {}
#if IDA_SDK_VERSION >= 770
	virtual dirtree_t *idaapi get_dirtree() newapi { return &rf->dt;}
	virtual inode_t idaapi index_to_inode(size_t n) const newapi
	{
		if(n < rf->matches.size())
			return inode_t(n);
		return inode_t(BADADDR);
	}
#endif //IDA_SDK_VERSION >= 770
	virtual size_t idaapi get_count() const 	{	return rf->matches.size();	}
	virtual ea_t idaapi get_ea(size_t n) const { return rf->matches[n].ea;}
	virtual void idaapi get_row(qstrvec_t* cols, int* icon, chooser_item_attrs_t* attrs, size_t n) const
	{
		const rf_match_t &m = rf->matches[n];
		cols->at(0) = m.name;
		cols->at(2).sprnt("%a", m.ea);
		cols->at(3) = eRFkindName(m.kind);

		if(m.deleted) {
			attrs->flags |= CHITEM_STRIKE;
			return;
		}

		//no checks on search only mode
		if(rf->searchFor == rf->replaceWith) {
			cols->at(1) = m.name;
			return;
		}

		if(!m.validateReplace(rf, &cols->at(1))) {
			attrs->color = 255; //red
			*icon = problemIcon;
		}
	}
	virtual cbret_t idaapi enter(size_t n)
	{
		const rf_match_t &m = rf->matches[n];

		switch (m.kind) {
#if IDA_SDK_VERSION < 850
		case eRF_typeName:
			open_structs_window(m.ea);
			return cbret_t();
		case eRF_udmName:
		{
			struc_t *struc;
			member_t *memb = get_member_by_id(m.ea, &struc);
			if(memb && struc)
				open_structs_window(struc->id, memb->soff);
			return cbret_t();
		}
#else //IDA_SDK_VERSION >= 850
		case eRF_udmName:
		{
			udm_t udm;
			tinfo_t membStrucType;
			ssize_t membIdx = membStrucType.get_udm_by_tid(&udm, m.ea);
			uint32 ord = get_tid_ordinal(m.ea);
			if(ord)
				open_loctypes_window(ord, membIdx < 0 ? nullptr : (const tif_cursor_t *)&membIdx);
			return cbret_t();
		}
#endif //IDA_SDK_VERSION < 850
		case eRF_funcArg:
		case eRF_usrCmts:
		case eRF_numFmt:
		case eRF_loclVar:
			COMPAT_open_pseudocode_REUSE(m.ea);
			return cbret_t();
		case eRF_msigName:
			return cbret_t();
		case eRF_notepad:
			//TWidget *w =
			open_notepad_window();
			//get_custom_viewer_place get_custom_viewer_location don't work with notepad
			return cbret_t();
		}
		return chooser_t::enter(n);
	}
	virtual cbret_t idaapi del(size_t n)
	{
		// no real delete because `matches` vector indexes are inodes moving and dirtree became inadequate
		const rf_match_t &m = rf->matches[n];
		bool moveCursor = true;
		if(m.kind == eRF_msigName || m.kind == eRF_notepad) {
			//these processed all together, so mark all of them
			for(size_t i = 0; i < rf->matches.size(); i++) {
				if(rf->matches[i].kind == m.kind)
					rf->matches[i].deleted ^= true;
			}
			moveCursor = false;
		} else {
			rf->matches[n].deleted ^= true;
		}
		return cbret_t(moveCursor? new_sel_after_del(n) : n);
	}
};

//--------------------------------------------------------------------------
#if IDA_SDK_VERSION >= 770
bool rf_dirspec_t::get_name(qstring* out, inode_t inode, uint32 name_flags)
{
	if(inode < rf->matches.size()) {
		*out = rf->matches[inode].name;
		return true;
	}
	return false;
}

inode_t rf_dirspec_t::get_inode(const char* dirpath, const char* name)
{
	qstring dir(dirpath);
	dir.trim2('/');
	if(dir.empty()) // return diridx (the root has the index 0)
		return eRFname2kind(name) + 1;

	eRF_kind_t kind = eRFname2kind(dir.c_str());
	if(kind < eRF_last) {
		for(size_t i = 0; i < rf->matches.size(); i++)
			if(rf->matches[i].kind == kind && !qstrcmp(name, rf->matches[i].name.c_str()))
				return inode_t(i);
	}
	return direntry_t::BADIDX;
}
#endif //IDA_SDK_VERSION >= 770

//--------------------------------------------------------------------------
static int idaapi callback(int fid, form_actions_t &fa)
{
	refac_t *rf = (refac_t *)fa.get_ud();
	switch ( fid )
	{
	case CB_INIT:
		rf->search();
		fa.refresh_field(0);
		break;
	case CB_YES:
		rf->searchFor.trim2();
		rf->replaceWith.trim2();
		if(rf->searchFor == rf->replaceWith) {
			Log(llNotice, "Refactoring: nothing to do, SearchFor is equal to ReplaceWith\n");
		} else if(!rf->validateReplace()) {
			warning("[hrt] bad replace: '%s'", rf->replaceWith.c_str());
			break;
		} else {
			rf->replace();
		}
		close_widget(rf->rfform, 0);
		break;
#if IDA_SDK_VERSION >= 800
	case CB_CANCEL:
		close_widget(rf->rfform, 0);
		break;
#endif //IDA_SDK_VERSION >= 800
	case CB_CLOSE:
		//rf->rfform = nullptr;
		break;
	case CB_DESTROYING:
		//delete rf; // on cause crash in dirtree_t::~dirtree_t -> rf_dirspec_t::`scalar deleting destructor'(unsigned int)
		break;
	case 1: //"Search for" changes
	{
		qstring n;
		fa.get_string_value(fid, &n);
		if(n != rf->searchFor) {
			if(rf->searchFor == rf->replaceWith) {
				//the refactoring may be used for search only
				//keep searchFor and replaceWith in sync to avoid accidental renaming
				rf->replaceWith = n;
				rf->replaceWith.trim2();
				fa.set_string_value(2, &rf->replaceWith);
			}
			rf->searchFor = n;
			rf->searchFor.trim2();
			//fa.set_string_value(fid, &rf->searchFor);
			rf->search();
			fa.refresh_field(0);
		}
		break;
	}
	case 2: //"Replace with" changes
	{
		qstring n;
		fa.get_string_value(fid, &n);
		if(n != rf->replaceWith) {
			rf->replaceWith = n;
			rf->replaceWith.trim2();
			//fa.set_string_value(fid, &rf->replaceWith);
			fa.refresh_field(0);
		}
		break;
	}
	case 3: //check boxes changes
	{
		ushort f;
		fa.get_checkbox_value(fid, &f);
		if(f != rf->flags) {
			rf->flags = f;
			rf->search();
			fa.refresh_field(0);
		}
		break;
	}
	}
	return 1;
}

int do_refactoring(action_activation_ctx_t *ctx)
{
	TWidget *widget = find_widget("[hrt] Refactoring");
  if(widget) {
		activate_widget(widget, true);
    return 0;
  }

	qstring highlight;
	uint32 hlflg;
	get_highlight(&highlight, ctx->widget, &hlflg);

	refac_t* refac = new refac_t(highlight.c_str());
	rf_chooser_t* rfch = new rf_chooser_t(refac);
  sizevec_t selected;
  selected.push_back(0);  // first item by default
	
	static const char form[] =
//		"STARTITEM 2\n" // to put the cursor on replaceWith field
		"BUTTON YES* ~R~eplace\n"
#if IDA_SDK_VERSION < 800
    // has no action callback in early IDA versions
	  "BUTTON CANCEL NONE\n"
#endif //IDA_SDK_VERSION < 800
		"[hrt] Refactoring\n"   // title
		"\n"
		"%/%*"                    // callback
		"\n"
		"<~L~ist:E0:0:100:::>\n"
		"<~S~earch for:q1:::><|><Re~p~lace with:q2:::>\n"
		"<~C~ase sensitive:c><|><Whole words onl~y~:c><|><Use re~g~ular expression:c>3>\n\n"; //!!! check RFF_ flags in case of changes in this line
	refac->rfform = open_form(form, WOPN_RESTORE, callback, refac, rfch, &selected, &refac->searchFor, &refac->replaceWith, &refac->flags);
	return 0;
}
