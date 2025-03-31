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
#include <md5.h>
#include "warn_on.h"

#include <set>

#include "helpers.h"
#include "msig.h"

#ifdef __GNUC__
	#pragma GCC diagnostic ignored "-Wformat"
	#pragma GCC diagnostic ignored "-Wpragmas"
#endif

#define MSIGHASHLEN 16
static uval_t minMsigLen = 15;
static const char msigNodeName[] = "$ hrt last MSIG filename";

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

		//top level resizing in relaxed mode become mov
		if(!strictMode && (op == m_low || op == m_xdu || op == m_xds))
			op = m_mov;
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
		strictMode = name[0] != 'r';
		reqRelaxed = false;
	}
	qstring print()
	{
		qstring line;
		line.sprnt("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X %s%s",
			hash[0], hash[1], hash[2],  hash[3],  hash[4],  hash[5],  hash[6],  hash[7],
			hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
			strictMode ? "" : "r ", // invalidate name of msig created in relaxed mode to not renaming proc on matching
			name.c_str());
		return line;
	}
	bool chk()
	{
		if (name.empty())
			return false;
		if(tooShort) {
			//msg("[hrt] too short msig: %s!\n", name.c_str());
			return false;
		}
		for (uint32 i = 0; i < MSIGHASHLEN; i++)
			if (hash[i])
				return true;
		return false;
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
public:
	~msigs_t()
	{
		for (auto i : *this)
			delete i;
	}
	bool add(msig_t* s)
	{
		if (!s->chk()) {
			msg("[hrt] Bad or too short msig: %s\n", s->name.c_str());
			delete s;
			return false;
		}
		auto it = find(s);
		if(it != end()) {
			size_t pos = (*it)->name.find(s->name);
			if(pos != qstring::npos
				 && (pos == 0 || (*it)->name[pos-1] == ' ')
				 && (pos + s->name.length() == (*it)->name.length() || (*it)->name[pos + s->name.length()] == ' '))
			{
				msg("[hrt] Duplicate msig `%s` skipped\n", s->name.c_str());
			} else if((*it)->name.length() > 300) {
				if((*it)->name.last() != '.')          // ATTN !!!
					(*it)->name.append(" and more ..."); // ATTN !!! this line must be ended by the same letter as above
				msg("[hrt] Duplicate msig `%s` not merged\n", s->name.c_str());
			} else {
				msg("[hrt] Duplicate msig `%s` merged with '%s'\n", s->name.c_str(), (*it)->name.c_str());
				(*it)->name.append(' ');
				(*it)->name.append(s->name);
			}
			delete s;
			return false;
		}
		insert(s);
		//msg("[hrt] msig '%s' has been added!\n", s->name.c_str());
		return true;
	}
	bool add(mbl_array_t* mba)
	{
		if (!mba)
			return false;
		msig_t* s = new msig_t(mba, true);
		bool res = add(s);
		if(res && s->reqRelaxed)
			add(new msig_t(mba, false));
		return res;
	}
	const char* match(msig_t* m)
	{
		auto i = find(m);
		if (i == end())
			return NULL;
		return (*i)->name.c_str();
	}
	const char* match(mbl_array_t* mba)
	{
		msig_t m(mba, true);
		const char* matched = match(&m);
		if(!matched && m.reqRelaxed) {
			msig_t mr(mba, false);
			matched = match(&mr);
		}
		return matched;
	}
	void save(const char* filename)
	{
		FILE* f = qfopen(filename, "w");
		if (!f) {
			warning("[hrt] Could not open '%s' for writing!\n", filename);
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
		msg("[hrt] %d msigs are saved\n", cnt);
	}
	void load(const char* filename)
	{
		FILE* f = qfopen(filename, "r");
		if (!f) {
			msg("[hrt] Could not open %s for reading!\n", filename);
			return;
		}
		uint32 cnt = 0;
		char buf[4096];
		while (qfgets(buf, 4096, f)) {
			if (add(new msig_t(buf)))
				cnt++;
		}
		qfclose(f);
		msg("[hrt] %d msigs are loaded from %s\n", cnt, filename);
	}
};
msigs_t msigs;

bool msig_add(mbl_array_t* mba)
{
	return msigs.add(mba);
}

const char* msig_match(mbl_array_t* mba)
{
	if (!mba || !msigs.size())
		return NULL;
	const char* name = msigs.match(mba);
	if (name)
		msg("[hrt] %a: msig '%s' found\n", mba->entry_ea, name);
	return name;
}

void msig_save()
{
	qstring filename;
	filename += get_path(PATH_TYPE_IDB);
	filename += ".msig";

	ushort rbtn = 0;
	char buf[QMAXPATH * 2];
	qstrncpy(buf, filename.c_str(), QMAXPATH * 2);

	const char     format[] =
		"[hrt] Create MSIG file\n\n"
		"<All User Named Functions:R>\n"
		"<Manually Selected Functions:R>>\n"
		"<Minimal signature length:u:4:::>\n"
		"<File name:f:1:64::>\n\n";
	if (1 != ask_form(format, &rbtn, &minMsigLen, buf))
		return;
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
				msg("[hrt] msig save is canceled\n");
				return;
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
				msg("[hrt] %a: decompile_func(\"%s\") failed with '%s'\n", funcstru->start_ea, funcName.c_str(), hf.desc().c_str());
			}
		}
		hide_wait_box();
		if(skipCnt)
			msg("[hrt] %d lib func or bad msigs skipped\n", skipCnt);
	}

	if (!msigs.size()) {
		msg("[hrt] No any msigs are defined\n");
		return;
	}
	msigs.save(filename.c_str());
}

void msig_load()
{
	qstring filename = get_path(PATH_TYPE_IDB);
	filename.append(".msig");
	filename = ask_file(0, filename.c_str(), "FILTER MSIG files|*.msig\n[hrt] Load MSIG file:");
	if(filename.empty())
		return;

	msigs.load(filename.c_str());
	netnode nn(msigNodeName, 0, true);
	nn.set(filename.c_str(), filename.size());
}

void msig_auto_load()
{
	netnode nn(msigNodeName);
	if(!exist(nn))
		return;

	qstring filename;
	if(nn.valstr(&filename) < 0 || filename.empty())
		return;

	msigs.load(filename.c_str());
}
