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
#include <md5.h>
#include <kernwin.hpp>
#include "warn_on.h"

#include <set>
#include <map>

#include "helpers.h"
#include "msig.h"

#ifdef __GNUC__
	#pragma GCC diagnostic ignored "-Wformat"
	#pragma GCC diagnostic ignored "-Wpragmas"
#endif

#define MSIGHASHLEN 16
static uval_t minMsigLen = 15;
static const char msigNodeName[] = "$ hrt last MSIG filename";
const char msigMessage[] = "// The function matches msig: ";

struct ida_local msig_t {
	uint8 hash[MSIGHASHLEN];
	qstring name;
	bool tooShort;
	bool strictMode;
	bool reqRelaxed;

	void SerializeOp(const mop_t& op, bytevec_t& buf)
	{
		//consider any kind of variable (register, global, stack) as a local var even in strictMode
		mopt_t opt = op.t;
		if (opt == mop_r || opt == mop_v || opt == mop_S)
			opt = mop_l;
		buf.pack_db(opt);

		//ignore size in relaxed mode
		if(strictMode)
			buf.append(&op.size, sizeof(op.size));

		switch (op.t) {
		case mop_n:
			buf.append(&op.nnn->value, sizeof(op.nnn->value));
			break;
		case mop_d:
			if(!strictMode &&
				 (op.d->opcode == m_low || op.d->opcode == m_xdu || op.d->opcode == m_xds) &&
				 op.d->l.t == mop_d) {
				//skip resizing in relaxed mode, it may be result of a call with wrong returning size on applying
				 SerializeInsn(op.d->l.d, buf);
				 break;
			}
			SerializeInsn(op.d, buf);
			break;
		case mop_b:
			buf.append(&op.b, sizeof(op.b));
			break;
		case mop_f:
			if (strictMode && op.f->solid_args) {
				reqRelaxed = true; // request relaxed mode if call have arguments, it may be incorrectly recognized number of call's args on a msig applying
				for (size_t i = 0; i < op.f->args.size(); i++)
					SerializeOp(op.f->args[i], buf);
			}
			break;
		case mop_a:
			SerializeOp(*op.a, buf);
			break;
		case mop_h:
			buf.append(op.helper, qstrlen(op.helper));
			break;
		case mop_str:
			buf.append(op.cstr, qstrlen(op.cstr));
			break;
		case mop_c:
			for(size_t i = 0; i < op.c->targets.size(); i++)
				buf.append(&op.c->targets[i], sizeof(int));
			break;
		case mop_fn:
		{
			const char* str = op.fpc->dstr();
			buf.append(str, qstrlen(str));
			break;
		}
		case mop_p:
			SerializeOp(op.pair->lop, buf);
			SerializeOp(op.pair->hop, buf);
			break;
		case mop_sc:
			break;
		}
	}
	void SerializeInsn(const minsn_t* insn, bytevec_t& buf)
	{
		mcode_t op = insn->opcode;

		if(!strictMode) {
			//top level resizing in relaxed mode become mov
			if(op == m_low || op == m_xdu || op == m_xds)
				op = m_mov;
			if(op == m_mov) {
				//consider func like returning void, ignore mov to return var
				if(insn->d.t == mop_l && insn->d.l->idx == insn->d.l->mba->retvaridx) {
					//TODO: check if (insn->d) is not used anywhere else
					if(insn->l.t == mop_d)
						SerializeInsn(insn->l.d, buf);
					return;
				}
				// ignore strange (not combinable) var-to-var move
				// mov arg.4{2}, arg_1.4{2} ; 180055988 not_combinable split4 u=edx.4 d=ebx.4
				if(!insn->is_combinable() && insn->d.t == mop_l && insn->l.t == mop_l)
					return;
			}
		}
		buf.pack_db(op);
		SerializeOp(insn->l, buf);
		SerializeOp(insn->r, buf);
		SerializeOp(insn->d, buf);
	}
	void SerializeMba(mbl_array_t* mba, bytevec_t& buf)
	{
		for (int i = 0; i < mba->qty; i++) {
			mblock_t* blk = mba->get_mblock(i);
			for (minsn_t* insn = blk->head; insn != NULL; insn = insn->next) {
				SerializeInsn(insn, buf);
			}
		}
	}
	msig_t(mbl_array_t* mba, bool _strictMode)
	{
		strictMode = _strictMode;
		reqRelaxed = false;
		name = get_name(mba->entry_ea); //get_visible_name(mba->entry_ea);
		stripName(&name); //use clear name and strip suffix like "_12", that may be caused by msig applying during msig generation decompiling
		if(!strictMode)
			name.insert("r "); // invalidate name of msig created in relaxed mode to not renaming proc on matching

		bytevec_t buf;
		SerializeMba(mba, buf);
		tooShort = buf.size() < minMsigLen;
		if(tooShort)
			return;

		MD5Context ctx;
		MD5Init(&ctx);
		MD5Update(&ctx, &buf[0], buf.size());
		MD5Final(hash, &ctx);
	}
	msig_t(const char* s)
	{
		memset(hash, 0, MSIGHASHLEN);
		uint32 i;
		for ( i = 0; i < MSIGHASHLEN; i++) {
			if (!strtobx(s + (i << 1), hash + i))
				break;
		}
		name = s + i * 2 + 1;
		name.rtrim('\n');
		name.trim2();
		tooShort = false;
		strictMode = !(name[0] == 'r' && name[1] != ' ');
		reqRelaxed = false;
	}
	qstring print()
	{
		qstring line;
		line.sprnt("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X %s",
			hash[0], hash[1], hash[2],  hash[3],  hash[4],  hash[5],  hash[6],  hash[7],
			hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
			name.c_str());
		return line;
	}
	bool chk()
	{
		if (name.empty())
			return false;
		if(tooShort) {
			Log(llFlood, "too short msig: %s!\n", name.c_str());
			return false;
		}
		for (uint32 i = 0; i < MSIGHASHLEN; i++)
			if (hash[i])
				return true;
		return false;
	}
	DECLARE_COMPARISONS(msig_t)
  {
    return memcmp(hash, r.hash, MSIGHASHLEN);
  }
};

class ida_local lessMsig_t {
public:
	bool operator()(const msig_t* x, const msig_t* y) const
	{
		return memcmp(x->hash, y->hash, MSIGHASHLEN) < 0;
	}
};

// set of msig sorted by hash
class ida_local msigs_t : public std::set<msig_t*, lessMsig_t>
{
	std::map<ea_t, msig_t*, std::less<ea_t>> cache;
public:
	bool modified = false;

	~msigs_t()
	{
		for (auto i : *this)
			delete i;
	}
	bool add(msig_t* s)
	{
		if (!s->chk()) {
			Log(llFlood, "Bad or too short msig: %s\n", s->name.c_str());
			delete s;
			return false;
		}
		auto it = find(s);
		if(it != end()) {
			qstring sname = s->name;
			if(sname[0] == 'r' && sname[1] == ' ')
				sname.remove(0, 2); 			// strip "relaxed" prefix if exist

			size_t pos = (*it)->name.find(sname);
			if(pos != qstring::npos
				 && (pos == 0 || (*it)->name[pos-1] == ' ')
				 && (pos + sname.length() == (*it)->name.length() || (*it)->name[pos + sname.length()] == ' '))
			{
				Log(llDebug, "Duplicate msig `%s` skipped\n", s->name.c_str());
			} else if((*it)->name.length() > 300) {
				if((*it)->name.last() != '.')          // ATTN !!!
					(*it)->name.append(" and more ..."); // ATTN !!! this line must be ended by the same letter as above
				Log(llDebug, "Duplicate msig `%s` not merged\n", s->name.c_str());
			} else {
				Log(llDebug, "Duplicate msig `%s` merged with '%s'\n", s->name.c_str(), (*it)->name.c_str());
				(*it)->name.append(' ');
				(*it)->name.append(sname);
			}

			//poison *it to be also relaxed
			if(!s->strictMode) {
				(*it)->strictMode = false;
				if(!((*it)->name[0] == 'r' && (*it)->name[1] == ' '))
					(*it)->name.insert("r ");
			}
			delete s;
			return false;
		}
		insert(s);
		Log(llFlood, "msig '%s' has been added\n", s->name.c_str());
		return true;
	}
	bool add(mbl_array_t* mba)
	{
		if (!mba)
			return false;
		msig_t* s = new msig_t(mba, true);
		bool res = add(s);
		if(res && s->reqRelaxed) {
			msig_t* r = new msig_t(mba, false);
			if(*r == *s) {
				Log(llWarning, "FIXME! Strict msig '%s' is equal to relaxed!\n", s->name.c_str());
				delete r;
			} else {
				add(r);
			}
		}
		return res;
	}
	msig_t* match(msig_t* m)
	{
		auto i = find(m);
		if (i == end())
			return NULL;
		return *i;
	}
	const char* match(mbl_array_t* mba)
	{
		msig_t m(mba, true);
		msig_t* matched = match(&m);
		if(!matched && m.reqRelaxed) {
			msig_t mr(mba, false);
			matched = match(&mr);
		}
		if(matched) {
			cache[mba->entry_ea] = matched;
			return matched->name.c_str();
		}
		cache.erase(mba->entry_ea);
		return nullptr;
	}
	const char* cached(ea_t ea)
	{
		auto it = cache.find(ea);
		if(it != cache.end())
			return it->second->name.c_str();
		return nullptr;
	}
	bool rename(ea_t ea, const char* newname)
	{
		auto it = cache.find(ea);
		if(it == cache.end())
			return false;

		if(!newname || !qstrlen(newname)) {
			erase(it->second);
			cache.erase(it);
		} else {
			//TODO: check if newname is valid
			it->second->name = newname;
		}
		modified = true;
		return true;
	}
	uint32 rename(msig_rename_cb_t* cb, void* ctx)
	{
		uint32 count = 0;
		for(auto it = begin(); it != end(); it++) {
			qstring newName = cb(ctx, (*it)->name.c_str());
			if(!newName.empty()) {
				(*it)->name = newName;
				modified = true;
				++count;
			}
		}
		return count;
	}
	void save(const char* filename)
	{
		FILE* f = qfopen(filename, "w");
		if (!f) {
			Log(llError, "Could not open '%s' for writing!\n", filename);
			return;
		}
		uint32 cnt = 0;
		for (auto i : *this) {
			qstring line = i->print();
			line.append('\n');
			if(qfputs(line.c_str(), f) >= 0)
				cnt++;
		}
		qfclose(f);
		Log(llNotice, "%d msigs are saved to %s\n", cnt, filename);
		modified = false;
	}
	void load(const char* filename)
	{
		FILE* f = qfopen(filename, "r");
		if (!f) {
			Log(llError, "Could not open %s for reading!\n", filename);
			return;
		}
		uint32 cnt = 0;
		char buf[4096];
		while (qfgets(buf, 4096, f)) {
			if (add(new msig_t(buf)))
				cnt++;
		}
		qfclose(f);
		Log(llNotice, "%d msigs are loaded from %s\n", cnt, filename);
	}
};
msigs_t msigs;

inline bool msig_add(mbl_array_t* mba)
{
	return msigs.add(mba);
}

const char* msig_match(mbl_array_t* mba)
{
	if (!mba || !msigs.size())
		return NULL;
	const char* name = msigs.match(mba);
	if(name) Log(llFlood, "%a: msig '%s' found\n", mba->entry_ea, name);
	return name;
}

const char* msig_cached(ea_t ea)
{
	if(ea == BADADDR || !msigs.size())
		return NULL;
	return msigs.cached(ea);
}

inline bool msig_rename(ea_t ea, const char* newname)
{
	return msigs.rename(ea, newname);
}

uint32 msig_rename(msig_rename_cb_t* cb, void* ctx)
{
	return msigs.rename(cb, ctx);
}

inline qstring msig_auto_filename()
{
	qstring filename;
	netnode nn(msigNodeName);
	if(exist(nn))
		nn.valstr(&filename);
	return filename;
}

void msig_auto_load()
{
	qstring filename = msig_auto_filename();
	if(filename.empty())
		return;
	msigs.load(filename.c_str());
}

void msig_auto_save()
{
	if(!msigs.modified)
		return;
	qstring filename = msig_auto_filename();
	if(filename.empty())
		return;
	msigs.save(filename.c_str());
}

bool isMsig(vdui_t *vu, qstring* name)
{
	ctext_position_t &pos = vu->cpos;
	if (pos.lnnum < 0)
		return false;
	size_t ypos = pos.lnnum;
	const strvec_t &sv = vu->cfunc->get_pseudocode();
	if(ypos >= sv.size())
		return false;
	if(sv[ypos].line.length() <= qnumber(msigMessage) || strncmp(sv[ypos].line.c_str(), msigMessage, qnumber(msigMessage) - 1))
		return false;
	if(name)
		*name = sv[ypos].line.substr(qnumber(msigMessage) - 1);
	return true;
}

/*-------------------------------------------------------------------------------------------------------------------------*/
ACT_DECL(msigLoad  , AST_ENABLE_ALW)
ACT_DECL(msigSave  , AST_ENABLE_ALW)
ACT_DECL(msigAdd   , AST_ENABLE_FOR_PC)
ACT_DECL(msigEdit  , AST_ENABLE_FOR(isMsig(vu, nullptr)))
ACT_DECL(msigAccept, AST_ENABLE_FOR(isMsig(vu, nullptr)))

static const action_desc_t actions[] =
{
	ACT_DESC("[hrt] Create MSIG for the function",  "", msigAdd),
	ACT_DESC("[hrt] Edit MSIG"                   ,  "E", msigEdit),
	ACT_DESC("[hrt] Accept MSIG"                 ,  "A", msigAccept),
};

void msig_reg_act()
{
	COMPAT_register_and_attach_to_menu("File/Produce file/Create MAP file...", ACT_NAME(msigSave), "[hrt] Create MSIG file...", NULL, SETMENU_INS, &msigSave, &PLUGIN);
	COMPAT_register_and_attach_to_menu("File/Load file/PDB file...", ACT_NAME(msigLoad), "[hrt] MSIG file...", NULL, SETMENU_INS, &msigLoad, &PLUGIN);
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		register_action(actions[i]);
}

void msig_unreg_act()
{
	detach_action_from_menu("File/Produce file/[hrt] Create MSIG file...", ACT_NAME(msigSave));
	detach_action_from_menu("File/Load file/[hrt] MSIG file...", ACT_NAME(msigLoad));
	unregister_action(ACT_NAME(msigLoad));
	unregister_action(ACT_NAME(msigSave));
	for (size_t i = 0, n = qnumber(actions); i < n; ++i)
		unregister_action(actions[i].name);
}

//------------------------------------------------
ACT_DEF(msigLoad)
{
	qstring filename = get_path(PATH_TYPE_IDB);
	filename.append(".msig");
	filename = ask_file(0, filename.c_str(), "FILTER MSIG files|*.msig\n[hrt] Load MSIG file:");
	if(filename.empty())
		return 0;

	msigs.load(filename.c_str());
	netnode nn(msigNodeName, 0, true);
	nn.set(filename.c_str(), filename.size());
	return 1;
}

ACT_DEF(msigSave)
{
	qstring filename;
	filename += get_path(PATH_TYPE_IDB);
	filename += ".msig";

	ushort rbtn = 0;
	char buf[QMAXPATH * 2];
	qstrncpy(buf, filename.c_str(), QMAXPATH * 2);

	const char     format[] =
		"[hrt] Create MSIG file\n\n"
		"<All user named functions:R>\n"
		"<Manually selected functions:R>>\n"
		"<Minimal signature length:u:4:::>\n"
		"<File name:f:1:64::>\n\n";
	if (1 != ask_form(format, &rbtn, &minMsigLen, buf))
		return 0;
	filename = buf;

	if (rbtn == 0) {

		// not clearing already generated signatures makes possible to create MSIG file
		// containing manually added and all requested MSIG generation
		//msigs.clear();

		show_wait_box("[hrt] Decompiling...");

		size_t skipCnt = 0;
		size_t funcqty = get_func_qty();
		for (size_t i = 0; i < funcqty; i++) {
			if (user_cancelled()) {
				hide_wait_box();
				Log(llWarning, "msig save is canceled\n");
				return 0;
			}

			func_t* funcstru = getn_func(i);
			if (!funcstru || (funcstru->flags & (FUNC_LIB | FUNC_THUNK)) ||
					(!funcstru->tailqty && funcstru->end_ea - funcstru->start_ea < minMsigLen)) {
				++skipCnt;
				continue;
			}

			qstring funcName = get_name(funcstru->start_ea);
			if (!is_uname(funcName.c_str())) {
				++skipCnt;
				continue;
			}

			replace_wait_box("[hrt] Decompiling %d/%d", i, funcqty);
			hexrays_failure_t hf;
#if 1
			mark_cfunc_dirty(funcstru->start_ea);
			cfuncptr_t cf = decompile_func(funcstru, &hf, DECOMP_NO_WAIT);
			if (cf && hf.code == MERR_OK) {
				if(!msig_add(cf->mba))
					++skipCnt;
			}
#else
			mba_t* mba = gen_microcode(funcstru, &hf, NULL, DECOMP_NO_WAIT | DECOMP_NO_CACHE, MMAT_LVARS);
			if (mba /*&& hf.code == MERR_OK*/) {
				if(!msig_add(mba))
					++skipCnt;
			}
#endif
			else {
				Log(llWarning, "%a: decompile_func(\"%s\") failed with '%s'\n", funcstru->start_ea, funcName.c_str(), hf.desc().c_str());
			}
		}
		hide_wait_box();
		if(skipCnt)
			Log(llNotice, "%d lib func or bad msigs skipped\n", skipCnt);
	}

	if (!msigs.size()) {
		Log(llNotice, "No any msigs are defined\n");
		return 0;
	}
	msigs.save(filename.c_str());
	return 0;
}

ACT_DEF(msigAdd)
{
	vdui_t& vu = *get_widget_vdui(ctx->widget);
	if(has_cached_cfunc(vu.cfunc->entry_ea))
		vu.refresh_view(true); // force rebuild mba if cached
	msig_add(vu.mba);
	return 1;
}

ACT_DEF(msigEdit)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	qstring name;
	if(!vu || !isMsig(vu, &name))
		return 0;
	if(!ask_str(&name, HIST_CMT, "[hrt] edit msig\nempty name to delete"))
		return 0;
	name.trim2();
	if(msig_rename(vu->cfunc->entry_ea, name.c_str()))
		vu->refresh_view(false);
	return 0;
}

ACT_DEF(msigAccept)
{
	vdui_t* vu = get_widget_vdui(ctx->widget);
	qstring name;
	if(!vu || !isMsig(vu, &name))
		return 0;
	// get_highlight(&name, ctx->widget, &out_flags); //does not take names with '::' inside

	vu->get_current_item(USE_KEYBOARD); // vu->cpos  is valid after get_current_item
	int pos = vu->cpos.x - (qnumber(msigMessage) - 1);

	//skip "relaxed" prefix
	if(name[0] == 'r' && name[1] == ' ') {
		name.remove(0, 2);
		pos -= 2;
	}
	if(pos < 0 || pos >= (int)name.length() || name[pos] == ' ')
		return 0;

	const char* n = name.c_str();
	const char* bgn = n + pos;
	for(; bgn > n && *(bgn - 1) != ' '; --bgn)
		;

	const char* end = qstrchr(bgn, ' ');
	if(end)
		name = qstring(bgn, end - bgn);
	else
		name = qstring(bgn);
	if(set_name(vu->cfunc->entry_ea, name.c_str(), SN_FORCE)) {
		Log(llDebug, "%a: msig name accepted '%s'\n",vu->cfunc->entry_ea, name.c_str());
		vu->refresh_view(true);
	}
	return 0;
}
