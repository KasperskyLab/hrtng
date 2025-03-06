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
static ushort skipCallArgs = 0;

void SerializeInsn(const minsn_t* insn, bytevec_t& buf);
void SerializeOp(const mop_t& op, bytevec_t& buf, bool indirectCall = false)
{
	//consider any kind of variable (register, global, stack) as a local var
#if IDA_SDK_VERSION < 730
	if (op.t == mop_r || op.t == mop_v || op.t == mop_S)
		append_db(buf, mop_l);
	else
		append_db(buf, op.t);
#else //IDA_SDK_VERSION < 730
	if (op.t == mop_r || op.t == mop_v || op.t == mop_S)
		buf.pack_db(mop_l);
	else
		buf.pack_db(op.t);
#endif //IDA_SDK_VERSION < 730

	buf.append(&op.size, sizeof(op.size));

	switch (op.t) {
	case mop_n:
		buf.append(&op.nnn->value, sizeof(op.nnn->value));
		break;
	case mop_d:
		SerializeInsn(op.d, buf);
		break;
	case mop_b:
		buf.append(&op.b, sizeof(op.b));
		break;
	case mop_f:
		if(indirectCall && skipCallArgs)
			break;
		if (op.f->solid_args) {
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
#if IDA_SDK_VERSION < 730
	append_db(buf, insn->opcode);
#else //IDA_SDK_VERSION >= 730
	buf.pack_db(insn->opcode);
#endif //IDA_SDK_VERSION < 730
	SerializeOp(insn->l, buf);
	SerializeOp(insn->r, buf);
	SerializeOp(insn->d, buf, insn->opcode == m_call && insn->l.t != mop_v);
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

struct ida_local msig_t {
	uint8 hash[MSIGHASHLEN];
	qstring name;
	bool tooShort;

	msig_t(mbl_array_t* mba) 
	{
		name = get_name(mba->entry_ea); //get_visible_name(mba->entry_ea);

		bytevec_t buf;
		SerializeMba(mba, buf);
		tooShort = buf.size() < minMsigLen;

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
	bool add(mbl_array_t* mba)
	{
		if (!mba)
			return false;
		msig_t* s = new msig_t(mba);
		if (!s->chk() || !insert(s).second) {
			msg("[hrt] %a: Bad, too short or duplicate msig: %s\n", mba->entry_ea, s->name.c_str());
			delete s;
			return false;
		}
		//msg("[hrt] %a: msig '%s' has been added!\n", mba->entry_ea, s->name.c_str());
		return true;
	}
	const char* match(mbl_array_t* mba)
	{
		msig_t m(mba);
		auto i = find(&m);
		if (i == end())
			return NULL;
		return (*i)->name.c_str();
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
			warning("[hrt] Could not open %s for reading!\n", filename);
			return;
		}
		uint32 cnt = 0;
		char buf[4096];
		while (qfgets(buf, 4096, f)) {
			msig_t* s = new msig_t(buf);
			if (!s->chk() || !insert(s).second) {
				msg("[hrt] skip bad or duplicate msig: %s\n", s->print().c_str());
				delete s;
			} else {
				cnt++;
			}
		}
		qfclose(f);
		msg("[hrt] %d msigs are loaded\n", cnt);
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
		"<###Turn it on to get more matches if the sample has a lot of indirect calls (but it will be more false positives too)#Skip indirect call arguments:c>>\n"
		"<File name:f:1:64::>\n\n";
	if (1 != ask_form(format, &rbtn, &minMsigLen, &skipCallArgs, buf))
		return;
	filename = buf;

	size_t skipCnt = 0;
	if (rbtn == 0) {
		size_t funcqty = get_func_qty();
		show_wait_box("Decompiling...");
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
			cfunc_t* cf = decompile_func(funcstru, &hf, DECOMP_NO_WAIT);
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
	}

	if(skipCnt)
		msg("[hrt] %d lib func, bad or duplicate msigs skipped\n", skipCnt);

	if (!msigs.size()) {
		msg("[hrt] No any msigs are defined\n");
		return;
	}
	msigs.save(filename.c_str());
}

void msig_load()
{
	char filename[QMAXPATH * 2];
	qstrncpy(filename, "*.msig", QMAXPATH * 2);
	const char     format[] =
		"[hrt] Load MSIG file\n\n"
		"<###This mode have to be the same as used on MSIG creation#Skip indirect call arguments on scanning:c>>\n"
		"<File name:f:1:64::>\n\n";
	if (1 != ask_form(format, &skipCallArgs, filename))
		return;

	msigs.load(filename);
}
