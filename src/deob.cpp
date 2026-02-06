/*
    Copyright © 2017-2026 AO Kaspersky Lab

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
#include <auto.hpp>
#include <bytes.hpp>
#include <intel.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "opt.h"
#include "unflat.h"
#include "deob.h"

#define DEBUG_DO 0

#if DEBUG_DO
#include "MicrocodeExplorer.h"
#define MSG_DO(msg_) msg msg_;
#else
#define MSG_DO(msg_)
#endif

#define DF_PATCH 0x1
#define DF_FAST  0x2
#define DF_FUNC  0x4
static ushort dflags = DF_PATCH | DF_FAST | DF_FUNC;

static bool deob = false;
static bool final_pass = false;
static rangeset_t unreachBlocks; // blocks with trash should be excluded

qstring gen_disasm(ea_t ea, asize_t len)
{
	qstring res;
	ea_t dea = ea;
	while (dea < ea + len) {
		qstring tmp;
		if (!generate_disasm_line(&tmp, dea, GENDSM_REMOVE_TAGS))
			break;
		if (!res.empty())
			res.append('\n');
		res.append(tmp);
		dea = next_not_tail(dea);
		if (dea == BADADDR)
			break;
	}
	return res;
}

asize_t extraSpaceForPatch(ea_t ea)
{
	ea_t end = ea;
	if (is_align(get_flags(ea)))
		end = next_not_tail(ea);

	// put more checks here

	if (end == BADADDR)
		return 0;
	Log(llDebug, "extraSpaceForPatch(%a) => %d\n", end - ea);
	return end - ea;
}

static bool patch_jmp(ea_t from, ea_t to, ea_t endOfBlk)
{
	if (!isX86()) {
		Log(llWarning, "FIXME: patch_jmp is x86 specific\n");
		return false;
	}
	adiff_t dist = to - (from + 2);
	asize_t patchLen = (dist >= -128 && dist <= 127) ? 2 : 5;
	asize_t maxLen = endOfBlk - from;
	if (maxLen < patchLen && maxLen + extraSpaceForPatch(endOfBlk) < patchLen) {
		Log(llWarning, "%a: no space for jmp patch\n", from);
		return false;
	}

	qstring cmt;
	cmt.sprnt("; patched %d bytes:\n", patchLen);//';' in first position prevents comment be copyed to pseudocode
	cmt.append(gen_disasm(from, patchLen));
	del_items(from, DELIT_EXPAND); //Important here!!!

	if (patchLen == 2) {
		patch_byte(from, 0xeb);
		patch_byte(from + 1, uint64(dist));
	} else {
		patch_byte(from, 0xe9);
		patch_dword(from + 1, uint64(dist - 3));
	}
	create_insn(from);
	add_extra_cmt(from, true, cmt.c_str());
	Log(llInfo, "%a: patched %d bytes (jmp %a)\n", from, patchLen, to);
	return true;
}

static bool patch_cond_jmp(ea_t ea, mcode_t op, ea_t trueDest, ea_t falseDest, ea_t endOfBlk)
{
	if (!isX86()) {
		Log(llWarning, "FIXME: patch_cond_jmp is x86 specific\n");
		return false;
	}

	adiff_t tdist = trueDest - (ea + 2);
	asize_t tlen = (tdist >= -128 && tdist <= 127) ? 2 : 6;
	adiff_t fdist = falseDest - (ea + tlen + 2 );
	asize_t flen = (fdist == 0) ? 0 : (fdist >= -128 && fdist <= 127) ? 2 : 5;
	asize_t maxLen = endOfBlk - ea;
	if (maxLen < tlen + flen) {
		Log(llWarning, "%a: no space for cond jmp patch\n", ea);
		return false;
	}

#if 1
	asize_t patchLen = maxLen;
#else
	asize_t patchLen = tlen + flen;
#endif

	qstring cmt;
	cmt.sprnt("; patched %d bytes:\n", patchLen);//';' in first position prevents comment be copyed to pseudocode
	cmt.append(gen_disasm(ea, patchLen));
	del_items(ea, 0 /*DELIT_EXPAND*/, patchLen);

	if (tlen == 2) {
		switch (op) {
		case m_jnz: patch_byte(ea, 0x75); break;
		case m_jz:  patch_byte(ea, 0x74); break;
		case m_jae: patch_byte(ea, 0x73); break;
		case m_jb:  patch_byte(ea, 0x72); break;
		case m_ja:  patch_byte(ea, 0x77); break;
		case m_jbe: patch_byte(ea, 0x76); break;
		case m_jg:  patch_byte(ea, 0x7f); break;
		case m_jge: patch_byte(ea, 0x7d); break;
		case m_jl:  patch_byte(ea, 0x7c); break;
		case m_jle: patch_byte(ea, 0x7e); break;
		default:
			Log(llWarning, "FIXME: patch_cond_jmp unk short op\n");
			return false;
		}
		patch_byte(ea + 1, uint64(tdist));
	} else {
		switch (op) {
		case m_jnz: patch_word(ea, 0x850f); break;
		case m_jz:  patch_word(ea, 0x840f); break;
		case m_jae: patch_word(ea, 0x830f); break;
		case m_jb:  patch_word(ea, 0x820f); break;
		case m_ja:  patch_word(ea, 0x870f); break;
		case m_jbe: patch_word(ea, 0x860f); break;
		case m_jg:  patch_word(ea, 0x8f0f); break;
		case m_jge: patch_word(ea, 0x8d0f); break;
		case m_jl:  patch_word(ea, 0x8c0f); break;
		case m_jle: patch_word(ea, 0x8e0f); break;
		default:
			Log(llWarning, "FIXME: patch_cond_jmp unk near op\n");
			return false;
		}
		patch_dword(ea + 2, uint64(tdist - 4));
	}

	if (!flen) {
		; // do nothing, already here
	} else if(flen == 2) {
		patch_byte(ea + tlen, 0xeb);
		patch_byte(ea + tlen + 1, uint64(fdist));
	}	else {
		patch_byte(ea + tlen, 0xe9);
		patch_dword(ea + tlen + 1, uint64(fdist - 3));
	}

	create_insn(ea);
	if(flen)
		create_insn(ea + tlen);

	//fill tail
	if (tlen + flen < patchLen) {
		for (asize_t i = tlen + flen; i < patchLen; i++)
			patch_byte(ea + i, 0xcc);
		if (!create_align(ea + tlen + flen, patchLen - (tlen + flen), 0))
			create_data(ea + tlen + flen, byte_flag(), patchLen - (tlen + flen), BADNODE);
	}

	add_extra_cmt(ea, true, cmt.c_str());
	Log(llInfo, "%a: patched %d bytes (cond jmp)\n", ea, patchLen);
	return true;
}

//blocks may be reordered at early stages
mblock_t* get_next_mblock(mbl_array_t* mba, int from, ea_t ea)
{
	for (; from < mba->qty && from >= 0; ++from) {
		mblock_t* blk = mba->get_mblock(from);
		//if (blk->flags & MBL_FAKE)
		//	continue;
		if (blk->start == ea)
			return blk;
	}
	return NULL;
}

struct ida_local ijmp_0way_op_visitor_t : mop_visitor_t
{
	mop_t *glbaddr = nullptr;
	mop_t *set = nullptr;
	mop_t *addReg = nullptr;
	int visit_mop(mop_t *op, const tinfo_t *type, bool is_target)
	{
		if(op->is_glbaddr())
			glbaddr = op;
		else if (op->is_insn()) {
			if (is_mcode_set(op->d->opcode))
				set = op;
			else if (op->d->opcode == m_add && isRegOvar(op->d->l.t) && op->d->r.is_glbaddr()) {
				glbaddr = &op->d->r;
				addReg = &op->d->l;
				return 1;
			}
		}
		return 0;
	}
};

#if 0
struct ida_local deob_op_visitor_t : mop_visitor_t
{
	int visit_mop(mop_t *op, const tinfo_t *type, bool is_target)
	{
		return 0;
	}
};
#endif

//icall  cs.2, ($off_1400197B8.8+#0x44927437A5E3AB1C.8)
static int callOrJmp2InitedVar(minsn_t* ins, mblock_t* blk)
{
	mop_t* off;
	if (ins->opcode == m_ijmp)
		off = &ins->d;
	else if (ins->opcode == m_icall)
		off = &ins->r;
	else
		return 0;
	if (!off->is_insn() || !is_mcode_addsub(off->d->opcode))
		return 0;
	ea_t ea = ins->ea; // it possible too small space for near jmp patch // if use `ins->d.d->ea` patch may overwrite significant instuctions
	ea_t addEa = off->d->ea;
	mop_t *num, *gvar;
	if (!ExtractNumAndNonNum(off->d, num, gvar))
		return 0;

	if(!replaceReadOnlyInitedVar2Val(gvar))
		return 0;
	blk->optimize_insn(ins); // original 'ins' is probably not valid after this line

	if (blk->tail) {
		ins = blk->tail;
		MSG_DO((" -> callOrJmp2InitedVar: %a %s\n", ea, ins->dstr()));
		if ((dflags & DF_PATCH) != 0) {
			if (ins->opcode == m_goto) {
				if (ea != BADADDR && blk->end != BADADDR && ins->opcode == m_goto && ins->l.t == mop_v)
					patch_jmp(ea, ins->l.g, blk->end);
			}	else if (ins->opcode == m_call && ins->l.t == mop_v && isX86() && is64bit()) {
/*    --- Temporary hack----
			TODO: not easy to correctly patch icall converted to call:
			- call itself is too short
			- just before call is arguments initialization, that should be saved
			so it better to patch `add rax` or `mov rax`
			case1:
			14000D580 48 B8 63 BA 6D 09 14 BC B7 00        mov     rax, 0B7BC14096DBA63h
			14000D58A 48 03 05 57 F5 00 00                 add     rax, cs:off_14001CAE8
			14000D591 4C 89 F1                             mov     rcx, r14
			14000D594 FF D0                                call    rax
*/
				insn_t addIns;
				int addInsLen = decode_insn(&addIns, addEa);
				if (addInsLen == 7 && addIns.itype == NN_add && addIns.Op1.type == o_reg && addIns.Op2.type == o_mem && get_word(addEa) == 0x0348) {
					qstring cmt;
					cmt.sprnt("; patched %d bytes:\n", addInsLen);//';' in first position prevents comment be copyed to pseudocode
					cmt.append(gen_disasm(addEa, addInsLen));
					del_items(addEa, DELIT_EXPAND);
					patch_byte(addEa + 1, 0x8d); //change opcode to LEA
					patch_dword(addEa + 3, ins->l.g - addEa - 7);
					create_insn(addEa);
					add_extra_cmt(addEa, true, cmt.c_str());
					Log(llInfo, "%a: patched %d bytes (call %a)\n", addEa, addInsLen, ins->l.g);
				}
			}
		}
	}
	return 1;
}

struct ida_local deobfuscation_optimizer_t : public optinsn_t
{
#if IDA_SDK_VERSION < 750
	virtual int idaapi func(mblock_t *blk, minsn_t *ins)
#else
	virtual int idaapi func(mblock_t *blk, minsn_t *ins, int optflags)
#endif //IDA_SDK_VERSION < 750
	{
		int res = 0;
		//check only top level instructions here (ins)
		switch (ins->opcode) {
		case m_icall:
		case m_ijmp:
			res += callOrJmp2InitedVar(ins, blk);
		}

#if 0
		if (!res) {
			//check operands of inst and subinsts
			deob_op_visitor_t vo;
			res = ins->for_all_ops(vo);
		}
#endif
		if (res && blk) {
				blk->mark_lists_dirty();
				blk->mba->dump_mba(true, "after deobfuscation_optimizer");
		}
		return res;
	}
};

static mblock_t *pass_goto_chain(mbl_array_t *mba, int i)
{
	intvec_t visited;
	mblock_t *b = NULL;
	while (true) {
		if (!visited.add_unique(i))
			return NULL; // an endless loop, prefer to keep things as is
		b = mba->get_mblock(i);
		minsn_t *m = getf_reginsn(b->head);// skip assertion instructions and find first regular instruction
		if (m == NULL || m->opcode != m_goto)
			break; // not a goto
		i = m->l.b;
	}
	return b;
}

static bool getGotoTargEa(mblock_t* b, ea_t *ea)
{
	if (!b->tail || b->tail->opcode != m_goto)
		return false;
	if (b->tail->l.t == mop_v) {
		*ea = b->tail->l.g;
		return true;
	}
	if (b->tail->l.t == mop_b) {
		*ea = b->mba->get_mblock(b->tail->l.b)->start;
		return true;
	}
	return false;
}

struct ida_local optblock_optimizer_t : public optblock_t
{
/*
replace1:
	1: jcnd   cond, @4
	2: jcnd   lnot(cond), @4 //has only one predecessor
	3: maybe unreacheble
	4: anything

to:
	1: goto @4
	2: goto @4
	3: maybe unreacheble
	4: anything

replace2:
	1: jcnd   cond, @4
	2: jcnd   lnot(cond), @5 //has only one predecessor
	3: maybe unreacheble
	4: goto @6
	5: goto @6
	6: anything

to:
	1: goto @6
	2: goto @6
	3: maybe unreacheble
	4: goto @6
	5: goto @6
	6: anything
*/
	bool handle_dbl_jc(mblock_t *b1) const
	{
		minsn_t *jc1 = b1->tail;
		if (b1->type != BLT_2WAY || jc1 == NULL || jc1->opcode != m_jcnd || jc1->d.t != mop_b)
			return false;

		mbl_array_t *mba = b1->mba;
		if (b1->serial >= mba->qty - 1)
			return false; // b1 is last one
		mblock_t *b2 = mba->get_mblock(b1->serial + 1);
		//mblock_t *b2 = get_next_mblock(mba, b1->serial + 1, b1->end); //here possible fake blocks with goto
		//mblock_t *b2 = pass_goto_chain(mba, b1->serial + 1);//FIXME: will brake succset/predset

		if (!b2 || b2->type != BLT_2WAY || b2->predset.size() != 1)
			return false; //has only one predecessor

		minsn_t *jc2 = getf_reginsn(b2->head);// skip assertion instructions and find first regular instruction
		if (jc2 == NULL || jc2->opcode != m_jcnd || jc2->d.t != mop_b)
			return false;
		if (b2->serial >= mba->qty - 1)
			return false; // b2 is last one
		mblock_t *b3 =  mba->get_mblock(b2->serial + 1); //get_next_mblock(mba, b2->serial + 1, b2->end);
		if (!b3)
			return false;

		if (!((jc2->l.is_insn(m_lnot) && jc2->l.d->l == jc1->l) || // lnot(cond) and cond
			    (jc1->l.is_insn(m_lnot) && jc1->l.d->l == jc2->l)))  // cond and lnot(cond)
			return false;

		int destB1 = jc1->d.b;
		int i1 = destB1;
		int destB2 = jc2->d.b;
		int i2 = destB2;
		if (i1 != i2) {
			mblock_t *b = pass_goto_chain(mba, i1);
			if(!b || b->serial == destB1)
				return false; // not a chain
			i1 = b->serial;

			b = pass_goto_chain(mba, i2);
			if (!b || b->serial == destB2)
				return false; // not a chain
			i2 = b->serial;

			if (i1 != i2)
				return false; // not a common dest
			// all ok, found two goto chains
		}

		//create jmp to exit microcode
		minsn_t* jmp1 = new minsn_t(jc1->ea);
		jmp1->opcode = m_goto;
		jmp1->l._make_blkref(i1);
		jc1->swap(*jmp1);
		delete jmp1;
		minsn_t* jmp2 = new minsn_t(jc2->ea);
		jmp2->opcode = m_goto;
		jmp2->l._make_blkref(i2);
		jc2->swap(*jmp2);
		delete jmp2;

		// fix the successor/predecessor lists
		b1->type = BLT_1WAY;
		b1->succset.clear();
		b1->succset.push_back(i1);
		b2->type = BLT_1WAY;
		b2->succset.clear();
		b2->succset.push_back(i2);

		b2->predset.del(b1->serial);
		b3->predset.del(b2->serial);
		if (destB1 != destB2) { //chained across goto
			mba->get_mblock(i1)->predset.add(b1->serial);
			mba->get_mblock(destB1)->predset.del(b1->serial);
			mba->get_mblock(i2)->predset.add(b2->serial);
			mba->get_mblock(destB2)->predset.del(b2->serial);
		}

		if (!b3->predset.size()) {
			//b3 is unreacheble
			//b3->start can be FAKE block eith same addr range as b2
			while (b3->start != b2->end && b3->type == BLT_1WAY && (b3->flags & MBL_FAKE) != 0) {
				b3 = mba->get_mblock(b3->succset[0]);
			}
			if (b3->start == b2->end) {
				unreachBlocks.add(b3->start, b3->end);
			} else {
				MSG_DO(("[hrt] handle_dbl_jc: no block at %a\n", b2->end));
			}
		}

		// since we changed the control flow graph, invalidate the use/def chains.
		b1->mark_lists_dirty();
		b2->mark_lists_dirty();
		return true;
	}

	bool ijmp_0way(mblock_t *blk) const
	{
		minsn_t *ijmp = blk->tail;
		if(blk->type != BLT_0WAY || !ijmp || ijmp->opcode != m_ijmp)
			return false;
		blk->mba->dump_mba(false, "[hrt] ijmp at @%d (%a), mat: %d\n", blk->serial, ijmp->ea, blk->mba->maturity);
		MSG_DO(("[hrt] ijmp at %a: %s, mat: %d\n", ijmp->ea, ijmp->d.dstr(), blk->mba->maturity));

		ijmp_0way_op_visitor_t v;
		ijmp->d.for_all_ops(v);
		MSG_DO(("[hrt] glbaddr: %s, set: %s, addReg %s\n", v.glbaddr ? v.glbaddr->dstr() : "-", v.set ? v.set->dstr() : "-", v.addReg ? v.addReg->dstr() : "-"));

		if (!v.glbaddr)
			return false;

/*
   replace:
		2.1  mov    #0x68.8, rcx.8
		2.2  jnz    [ds.2:rax.8{5}].8, #0.8, @4
		3.0  mov    #0x10.8, rcx.8
		4.0  ijmp   cs.2{6}, ([ds.2{6}:(rcx.8+&($qword_14001CB10).8)].8+#0x75A33E683DF49CFB.8)
	to
		2.1  mov    #0x68.8, rcx.8
		2.2  jnz    [ds.2:rax.8{5}].8, #0.8, @5
		3.0  mov    #0x10.8, rcx.8
		4.0  ijmp   cs.2{6}, ([ds.2{6}:(#0x10.8+&($qword_14001CB10).8)].8+#0x75A33E683DF49CFB.8)
		5.0  ijmp   cs.2{6}, ([ds.2{6}:(#0x68.8+&($qword_14001CB10).8)].8+#0x75A33E683DF49CFB.8)
*/
		if (v.addReg) {
			//blk has 2 predecessors and no any other instructions
			if(blk->npred() != 2 || blk->tail != blk->head)
				return false;

			mblock_t *endsWithJcc, *nonJcc;
			int jccDest, jccFallthrough;
			mblock_t* pred0 = blk->mba->get_mblock(blk->predset[0]);
			mblock_t* pred1 = blk->mba->get_mblock(blk->predset[1]);
			if(!SplitMblocksByJccEnding(pred0, pred1, endsWithJcc, nonJcc, jccDest, jccFallthrough) || jccDest != blk->serial)
				return false;

			mlist_t ml;
			blk->append_use_list(&ml, *v.addReg, MUST_ACCESS);
			minsn_t* defT = my_find_def_backwards(endsWithJcc, ml, nullptr);
			if(!defT || defT->opcode != m_mov || defT->l.t != mop_n || !defT->d.equal_mops(*v.addReg, EQ_IGNSIZE))
				return false;
			mop_t numT = defT->l;

			minsn_t* defF = my_find_def_backwards(nonJcc, ml, nullptr);
			if (!defF || defF->opcode != m_mov || defF->l.t != mop_n || !defF->d.equal_mops(*v.addReg, EQ_IGNSIZE))
				return false;
			mop_t numF = defF->l;

			//copy for `true` branch with reg val is substituted into ijmp expression
			mblock_t* copy = blk->mba->insert_block(blk->serial + 1);
			copy->flags |= MBL_FAKE;
			copy->start = ijmp->ea;
			copy->end = ijmp->ea + 1; //make block small for callOrJmp2InitedVar cant patch this jmp
			copy->type = blk->type;
			v.addReg->swap(numT);
			copy->insert_into_block(new minsn_t(*ijmp), nullptr);
			copy->mark_lists_dirty();

			blk->predset.del(endsWithJcc->serial);
			endsWithJcc->succset.del(blk->serial);
			copy->predset.add(endsWithJcc->serial);
			endsWithJcc->succset.add(copy->serial);
			QASSERT(100402, is_mcode_jcond(endsWithJcc->tail->opcode) && endsWithJcc->tail->d.t == mop_b);
			endsWithJcc->tail->d.b = copy->serial;

			//set `false` branch reg val into ijmp expression
			v.addReg->swap(numF);
			blk->mark_lists_dirty();
			ea_t origEnd = blk->end;
			blk->end = blk->start + 1;	//make block small for callOrJmp2InitedVar cant patch this jmp

			copy->optimize_insn(copy->tail, OPTI_ADDREXPRS | OPTI_MINSTKREF | OPTI_COMBINSNS);
			blk->optimize_insn(blk->tail, OPTI_ADDREXPRS | OPTI_MINSTKREF | OPTI_COMBINSNS);
			MSG_DO(("[hrt] ijmp at %a converted to:\n", ijmp->ea));
			MSG_DO(("[hrt]   %d: %s\n", endsWithJcc->serial, endsWithJcc->tail->dstr()));
			MSG_DO(("[hrt]   %d: %s\n", blk->serial, blk->tail->dstr()));
			MSG_DO(("[hrt]   %d: %s\n", copy->serial, copy->tail->dstr()));

			ea_t tDst, fDst;
			if ((dflags & DF_PATCH) != 0 && getGotoTargEa(copy, &tDst) && getGotoTargEa(blk, &fDst))
				patch_cond_jmp(endsWithJcc->tail->ea, endsWithJcc->tail->opcode, tDst, fDst, origEnd);
			return true;
		}

/*
		replace:
			ijmp   cs.2{16}, ([ds.2{16}:((xdu.8((xdu.4((rdx.8 == #1.8)) <<l #7.1))+&($qword_1400184E0).8)+#0xC0.8)].8-#0x1260EC9986F965C0.8)
		to
			1: j_cond (rdx.8 == #1.8), @3
			2: ijmp   cs.2{16}, ([ds.2{16}:((xdu.8((xdu.4(0) <<l #7.1))+&($qword_1400184E0).8)+#0xC0.8)].8-#0x1260EC9986F965C0.8)
			3: ijmp   cs.2{16}, ([ds.2{16}:((xdu.8((xdu.4(1) <<l #7.1))+&($qword_1400184E0).8)+#0xC0.8)].8-#0x1260EC9986F965C0.8)
*/
		if(v.set) {
			QASSERT(100402, v.set->is_insn());
			ea_t setEa = v.set->d->ea;
			minsn_t* jcnd = new minsn_t(*v.set->d);
			jcnd->opcode = set2jcnd(v.set->d->opcode);

			//true block first, it will be shifted down on false block insertion
			mblock_t* copy1 = blk->mba->insert_block(blk->serial + 1);
			copy1->flags |= MBL_FAKE;
			copy1->start = ijmp->ea;
			copy1->end = ijmp->ea + 1; //make block small for callOrJmp2InitedVar cant patch this jmp
			copy1->type = blk->type;
			v.set->make_number(1, v.set->size);
			copy1->insert_into_block(new minsn_t(*ijmp), nullptr);  // copy ijmp with m_setX is replaced to '1'
			copy1->mark_lists_dirty();

			// false is direct successor of blk
			mblock_t* copy0 = blk->mba->insert_block(blk->serial + 1);
			copy0->flags |= MBL_FAKE;
			copy0->start = ijmp->ea;
			copy0->end = ijmp->ea + 1;//make block small for callOrJmp2InitedVar cant patch this jmp
			copy0->type = blk->type;
			v.set->make_number(0, v.set->size);
			copy0->insert_into_block(new minsn_t(*ijmp), nullptr); // copy ijmp with m_setX is replaced to '0'
			copy0->mark_lists_dirty();

			jcnd->d._make_blkref(copy1->serial);
			jcnd->d.size = NOSIZE; //avoid INTERR(50754)
			ijmp->swap(*jcnd);
			delete jcnd;

			blk->type = BLT_2WAY;
			blk->mark_lists_dirty();

			blk->succset.clear();
			blk->succset.add(copy0->serial);
			blk->succset.add(copy1->serial);
			copy0->predset.add(blk->serial);
			copy1->predset.add(blk->serial);

			copy0->optimize_insn(copy0->tail, OPTI_ADDREXPRS | OPTI_MINSTKREF | OPTI_COMBINSNS);
			copy1->optimize_insn(copy1->tail, OPTI_ADDREXPRS | OPTI_MINSTKREF | OPTI_COMBINSNS);
			MSG_DO(("[hrt] ijmp at %a converted to:\n", ijmp->ea));
			MSG_DO(("[hrt]   %d: %s\n", blk->serial, blk->tail->dstr()));
			MSG_DO(("[hrt]   %d: %s\n", copy0->serial, copy0->tail->dstr()));
			MSG_DO(("[hrt]   %d: %s\n", copy1->serial, copy1->tail->dstr()));

			ea_t tDst, fDst;
			if((dflags & DF_PATCH) != 0 && setEa != BADADDR && blk->end != BADADDR
				&& getGotoTargEa(copy1, &tDst) && getGotoTargEa(copy0, &fDst)) {
				patch_cond_jmp(setEa, blk->tail->opcode, tDst, fDst, blk->end);
			}
			return true;
		}
		return false;
	}

	//convert artifacts left by ijmp_0way to extern block jump
	// 0WAY-BLOCK
	// goto   $loc_14000821C
	bool goto_0way(mblock_t *blk) const
	{
		minsn_t *migoto = blk->tail;
		if(blk->type != BLT_0WAY || !migoto || migoto->opcode != m_goto || migoto->l.t != mop_v)
			return false;

		ea_t targ_ea = migoto->l.g;
		if(blk->mba->range_contains(targ_ea)) {
			for (int i = 0; i < blk->mba->qty; i++) {
				const mblock_t* bi = blk->mba->get_mblock(i);
				if (bi->start == targ_ea) {
					MSG_DO(("[hrt] %a: 0way goto to %a has target block. FIXME\n", migoto->ea, targ_ea));
					return false;
				}
			}
			MSG_DO(("[hrt] %a: 0way goto to %a is in scope, but no mblock. Has it marked to keep?\n", migoto->ea, targ_ea));
			blk->mba->dump_mba(false, "[hrt] no target for 0way goto @%d (%a)", blk->serial, migoto->ea);
			return false;
		}

		if(blk->tail == blk->head) {
			MSG_DO(("[hrt] %a: empty 0way goto -> xtern blk %a\n", migoto->ea, targ_ea));
			blk->type = BLT_XTRN;
			blk->start = targ_ea;
			blk->end = blk->start;// + 1;
			blk->remove_from_block(migoto);
			delete migoto;
			return true;
		}
		MSG_DO(("[hrt] %a: non-empty 0way goto -> pass to xtern %a\n", migoto->ea, targ_ea));
		mblock_t* xtrn = blk->mba->insert_block(blk->serial + 1);
		xtrn->type = BLT_XTRN;
		xtrn->start = targ_ea;
		xtrn->end = xtrn->start;// + 1;
		xtrn->predset.add(blk->serial);

		blk->type = BLT_1WAY;
		blk->succset.add(xtrn->serial);
#if 0
		migoto->l.make_blkref(xtrn->serial);
		migoto->l.size = NOSIZE;
#else
		blk->remove_from_block(migoto);
		delete migoto;
#endif
		return true;
	}
	virtual int idaapi func(mblock_t *blk)
	{
		mbl_array_t* mba = blk->mba;
		int changes = 0;
		changes += handle_dbl_jc(blk);
		changes += ijmp_0way(blk);
		changes += goto_0way(blk);
		if (changes) {
			//mba->optimize_local(0);
#if DEBUG_DO
			//ShowMicrocodeExplorer(mba, "after optblock_optimizer");
#endif
			mba->mark_chains_dirty();
			mba->dump_mba(true, "[hrt] after optblock_optimizer");
		}
		return changes;
	}
};

static optblock_optimizer_t optblock_optimizer;
static deobfuscation_optimizer_t deobfuscation_optimizer;

void deob_init()
{
	if (!deob) {
		install_optblock_handler(&optblock_optimizer);
		install_optinsn_handler(&deobfuscation_optimizer);
		deob = true;
	}
}
void deob_done()
{
	if (deob) {
		remove_optinsn_handler(&deobfuscation_optimizer);
		remove_optblock_handler(&optblock_optimizer);
		deob = false;
	}
}

bool catchRetAddr_preprocess(mbl_array_t* mba)
{
	if (!isX86()) {
		Log(llWarning, "FIXME: catchRetAddr_preprocess is x86 specific\n");
		return false;
	}

	bool changed = false;
	for (int i = 0; i < mba->qty; i++) {
		mblock_t* blk = mba->get_mblock(i);
		if (blk->flags & MBL_FAKE)
			continue;
		if (!blk->tail || blk->tail->opcode != m_ijmp)
			continue;
		minsn_t* ijmp = blk->tail;
		minsn_t* mov_cs_seg = ijmp->prev;
		if (!mov_cs_seg)
			continue;
		if (mov_cs_seg->opcode == m_add) //optional: add esp, #const, esp
			mov_cs_seg = mov_cs_seg->prev;
		if (!mov_cs_seg || mov_cs_seg->opcode != m_mov)
			continue;
		minsn_t* pop_eoff = mov_cs_seg->prev;
		if (!pop_eoff || pop_eoff->opcode != m_pop)
			continue;
		if (pop_eoff->prev && pop_eoff->prev->opcode == m_nop) //skip optional nop
			pop_eoff = pop_eoff->prev;

		//check if 'ret' has single cref was added by deob_postprocess on prev pass
		xrefblk_t xb;
		bool bFirstPass = true;
		if (xb.first_from(ijmp->ea, XREF_ALL) && xb.iscode) {
			ea_t dest = xb.to;
			if (!xb.next_from()) { //no more any other references from here allowed
				bFirstPass = false;
				//replace 'ret' ijmp to jmp, don't forget to balance stack
				minsn_t* jmp = new minsn_t(ijmp->ea);
				jmp->opcode = m_goto;
				jmp->l._make_gvar(dest);
				blk->insert_into_block(jmp, ijmp);
				blk->make_nop(ijmp);// calls mark_lists_dirty()
				changed = true;
			}
		}

		if (bFirstPass) {//first pass: add retaddr catcher before 'ret'
			//FIXME: allocate temporal register instead eip
			//FIXME: x86 specific
			mreg_t eip = 0x58;
			mreg_t ss = reg2mreg(R_ss);
			mreg_t esp = reg2mreg(R_sp);
			for (mreg_t i = 0; i < 0x100; i += 4) {
				mop_t op;
				op._make_reg(i);
				//Log(llFlood, "reg_%x  %s\n", i, op.dstr());
				if (!qstrcmp("eip", op.dstr())) {
					eip = i;
					break;
				}
			}
			minsn_t* pc = new minsn_t(ijmp->ea);
			pc->opcode = m_ldx;
			pc->l._make_reg(ss, 2);
			pc->r._make_reg(esp, ea_size);
			pc->d._make_reg(eip, ea_size);
			blk->insert_into_block(pc, pop_eoff->prev);

			minsn_t* call = new minsn_t(pc->ea);
			call->opcode = m_call;
			call->l.make_helper("ret_addr");
			mcallinfo_t* ci = new mcallinfo_t();
			ci->cc = CM_CC_SPECIAL;
			mcallarg_t arg;
			arg._make_reg(eip, ea_size);
			arg.type = get_unk_type(ea_size);
			ci->args.add(arg);
			ci->solid_args = 1;
			call->d.size = 0;
			call->d._make_callinfo(ci);
			blk->insert_into_block(call, pc);
			blk->mark_lists_dirty();
			changed = true;
		}
	}
	return changed;
}

void deob_preprocess(mbl_array_t *mba)
{
	if (!deob)
		return;

#if IDA_SDK_VERSION >= 760
	// mark all blocks non-removable to keep unreachable blocks until connection
	for (int i = 0; i < mba->qty; i++) {
		mblock_t* bi = mba->get_mblock(i);
		if(!(bi->flags & MBL_FAKE))
			bi->flags |= MBL_KEEP;
	}
#endif //IDA_SDK_VERSION >= 760

	if (catchRetAddr_preprocess(mba))
		mba->dump_mba(true, "[hrt] after catchRetAddr_preprocess");
}

/*
replace:
	1: jcnd   cond, loc_xxx
	2: jcnd   lnot(cond), loc_xxx
	3: maybe unreacheble
	loc_xxx:
	4: anything

to:
	1: goto loc_xxx
	2: deleted and undefined
	3: deleted and undefined
	loc_xxx:
	4: anything
and patch first conditional jmp to nonconditional

patch_dbl_jc works better then handle_dbl_jc becouse unreachable blocks are restored by reanalyze..
but ida call optblock_handlers first time at MMAT_LOCOPT level. I'need MMAT_PREOPTIMIZED
*/
typedef std::set<mblock_t *> blocksset_t;
static bool patch_dbl_jc(mbl_array_t *mba, mblock_t *b1, blocksset_t* removeBlk)
{
	minsn_t *jc1 = b1->tail;
	if (b1->type != BLT_NONE || jc1 == NULL || jc1->opcode != m_jcnd || jc1->d.t != mop_v)
		return false;
	if (b1->serial >= mba->qty - 1)
		return false; //if b1 is last one

	mblock_t *b2 = get_next_mblock(mba, b1->serial + 1, b1->end);
	if(!b2 || b2->type != BLT_NONE)
		return false;
	minsn_t *jc2 = getf_reginsn(b2->head);// skip assertion instructions and find first regular instruction
	if (jc2 == NULL || jc2->opcode != m_jcnd || jc2->d.t != mop_v)
		return false;

	if (!((jc2->l.is_insn(m_lnot) && jc2->l.d->l == jc1->l) || // lnot(cond) and cond
		    (jc1->l.is_insn(m_lnot) && jc1->l.d->l == jc2->l)))  // cond and lnot(cond)
		return false;

	ea_t destB1 = jc1->d.g;
	ea_t destB2 = jc2->d.g;
	if (destB1 != destB2)
		return false;

	//create jmp microcode
	minsn_t* jmp1 = new minsn_t(jc1->ea);
	jmp1->opcode = m_goto;
	jmp1->l._make_gvar(destB1);
	jc1->swap(*jmp1);
	delete jmp1;
	minsn_t* jmp2 = new minsn_t(jc2->ea);
	jmp2->opcode = m_goto;
	jmp2->l._make_gvar(destB2);
	jc2->swap(*jmp2);
	delete jmp2;

	if ((dflags & DF_PATCH) != 0) {
		patch_jmp(jc1->ea, destB1, b1->end);
		unreachBlocks.add(b2->start, b2->end); //do not mark b2 as unreach if no patch becouse next pass will not see jc pair
	}
	removeBlk->insert(b2);

	mblock_t *b3 = get_next_mblock(mba, b2->serial + 1, b2->end);//mba->get_mblock(b2->serial + 1);
	if (b3) {
		unreachBlocks.add(b3->start, b3->end);
		removeBlk->insert(b3);
	}
	b1->mark_lists_dirty();
	return true;
}

void deob_preoptimized(mbl_array_t *mba)
{
	if (!deob)
		return;
	bool changed = false;
	blocksset_t removeBlocks;
	for (int i = 0; i < mba->qty; i++) {
		mblock_t *blk = mba->get_mblock(i);
		if (blk->flags & MBL_FAKE)
			continue;
		if (patch_dbl_jc(mba, blk, &removeBlocks))
			changed = true;
	}
	if (changed) {
		for (auto rbi : removeBlocks) //not realy need to maintain 'removeBlocks'
			mba->remove_block(rbi); //causes blocks renumbering, so after this point all my 'bb->idx' are incorrect
		mba->mark_chains_dirty();
		mba->dump_mba(true, "[hrt] after deob_preoptimized");
	}
}

struct ida_local frac_visitor_t : minsn_visitor_t
{
	eavec_t *ret_dests;
	bool changed;
	frac_visitor_t(eavec_t *ret_dests_) : ret_dests(ret_dests_), changed(false) {}
	int visit_minsn()
	{
		if (curins->opcode != m_call || !curins->is_helper("ret_addr"))
			return 0;
		if (ret_dests) { // just remove "ret_addr" on final pass
			mcallinfo_t &fi = *curins->d.f;
			uint64 val;
			if (!fi.args.empty() && fi.args.front().is_constant(&val)) {
				ea_t ret_dest = (ea_t)val;
				if (is_mapped(ret_dest)) {
					if (ret_dests->add_unique(ret_dest)) {
						MSG_DO(("[hrt] new ret_addr %a\n", ret_dest));
						//if(!has_xref(get_flags(ret_dest))) //FIXME: check xref 'from'
						add_cref(curins->ea, ret_dest, (cref_t)(fl_JN | XREF_USER));
					}
				}
			}
		}
		//do not delete helpers on hxe_glbopt event before final pass
		//on prev passes it doesn't care - mba is deleted just after deob_postprocess call
		if (final_pass) {
			blk->make_nop(curins);
			changed = true;
		}
		return 0;
	}
};

//returns 'true' only on final pass changes
bool deob_postprocess(mbl_array_t *mba, eavec_t *new_dests)
{
	frac_visitor_t frac_visitor(new_dests);
	mba->for_all_topinsns(frac_visitor);
	return frac_visitor.changed;
}

#if 0
static bool ensure_code(ea_t ea)
{
	if (!is_loaded(ea))
		return false;
	if (!is_code(get_flags(ea))) {
#if 0
		//does not help
		if(!inf_is_auto_enabled())
			inf_set_auto_enabled(true);
#endif
		if (!is_auto_enabled())
			enable_auto(true);
		//del_items(ea, DELIT_EXPAND);//here maybe user data
		//create_insn(ea); //does not help
		auto_make_code(ea);
		auto_wait();
		del_func(ea);
		return is_code(get_flags(ea));
	}
	return true;
}
#endif

static void fill_nops(ea_t ea, uval_t len) {
	add_extra_cmt(ea, true, "; patched %d bytes", len);
	for (uval_t i = 0; i < len; i++) {
		del_items(ea);
		patch_byte(ea, 0x90);
		create_insn(ea++);
	}
}

bool disasm_dbl_jc(ea_t ea)
{
	if (!isX86())
		return false;
	insn_t insn1;
	insn_t insn2;
	if (decode_insn(&insn1, ea) <= 0)
		return false;

#if 1 //example1 of dirty hack is used to breakthrough some custom obfuscation
	// patch jump into middle of self instr
	// 0401249        loc_401249:
	// 0401249 EB FF  jmp     short near ptr loc_401249+1
	if((dflags & DF_PATCH) != 0 && insn1.itype == NN_jmp && insn1.ops[0].type == o_near && insn1.ops[0].addr == ea + 1) {
		fill_nops(ea, 1);
		return true;
	}
#endif //example1

	if (decode_insn(&insn2, ea + insn1.size) <= 0)
		return false;

#if 1 //example2 of dirty hack is used to breakthrough some custom obfuscation
	// patch xor & jz into middle of prev instr
	// 0401357                 loc_401357:
	// 0401357 66 41 BF EB 05  mov     r15w, 5EBh
	// 040135C 31 C0           xor     eax, eax
	// 040135E 74 FA           jz      short near ptr loc_401357+3
	if((dflags & DF_PATCH) != 0
		 && insn1.itype == NN_xor && insn1.ops[0].type == o_reg && insn1.ops[1].type == o_reg && insn1.ops[0].reg == insn1.ops[1].reg    // insn1 is: xor same reg
		 && insn2.itype == NN_jz && insn2.ops[0].type == o_near && insn2.ops[0].addr == ea - 2 && is_tail(get_flags(insn2.ops[0].addr))) // insn2 is: jz to middle of prev instr
	{
		insn_t insn3;                                                                                                                    // insn3 is: short jmp is hidden inside "mov r15w, 5EBh"
		if(decode_insn(&insn3, insn2.ops[0].addr) > 0 && insn3.itype == NN_jmp && insn3.ops[0].type == o_near && insn3.ops[0].addr == ea + insn1.size + insn2.size + 1)
		{
			//find beginning of prev instr
			ea_t prev = insn2.ops[0].addr;
			while (is_tail(get_flags(--prev))) ;

			fill_nops(prev, insn3.ops[0].addr - prev);
			return true;
		}
	}
#endif //example2

	bool isPair = false;
	switch (insn1.itype)
	{
	case NN_jc:
		isPair = insn2.itype == NN_jnc; break;
	case NN_jnc:
		isPair = insn2.itype == NN_jc; break;
	case NN_jo:
		isPair = insn2.itype == NN_jno; break;
	case NN_jno:
		isPair = insn2.itype == NN_jo; break;
	case NN_js:
		isPair = insn2.itype == NN_jns; break;
	case NN_jns:
		isPair = insn2.itype == NN_js; break;
	case NN_je:
	case NN_jz:
		isPair = insn2.itype == NN_jnz || insn2.itype == NN_jne; break;
	case NN_jne:
	case NN_jnz:
		isPair = insn2.itype == NN_jz || insn2.itype == NN_je; break;
	case NN_ja:
	case NN_jnbe:
		isPair = insn2.itype == NN_jbe || insn2.itype == NN_jna; break;
	case NN_jbe:
	case NN_jna:
		isPair = insn2.itype == NN_ja || insn2.itype == NN_jnbe; break;
	case NN_jae:
	case NN_jnb:
		isPair = insn2.itype == NN_jb || insn2.itype == NN_jnae; break;
	case NN_jb:
	case NN_jnae:
		isPair = insn2.itype == NN_jae || insn2.itype == NN_jnb; break;
	case NN_jg:
	case NN_jnle:
		isPair = insn2.itype == NN_jle || insn2.itype == NN_jng; break;
	case NN_jle:
	case NN_jng:
		isPair = insn2.itype == NN_jg || insn2.itype == NN_jnle; break;
	case NN_jge:
	case NN_jnl:
		isPair = insn2.itype == NN_jl || insn2.itype == NN_jnge; break;
	case NN_jl:
	case NN_jnge:
		isPair = insn2.itype == NN_jge || insn2.itype == NN_jnl; break;
	case NN_jnp:
	case NN_jpo:
		isPair = insn2.itype == NN_jp || insn2.itype == NN_jpe; break;
	case NN_jp:
	case NN_jpe:
		isPair = insn2.itype == NN_jnp || insn2.itype == NN_jpo; break;
	}
	if (isPair) {
		ea_t dest1 = (insn1.ops[0].type == o_near) ? insn1.ops[0].addr : BADADDR;
		ea_t dest2 = (insn2.ops[0].type == o_near) ? insn2.ops[0].addr : BADADDR;
		if (dest1 == dest2 && dest1 != BADADDR) {
			if ((dflags & DF_PATCH) != 0) {
				patch_jmp(insn1.ea, dest1, insn1.ea + insn1.size);
				if (get_first_fcref_to(insn2.ea) == BADADDR) {
					unreachBlocks.add(insn2.ea, insn2.ea + insn2.size); //do not mark b2 as unreach if no patch
					//patch_jmp(insn2.ea, dest2, insn2.ea + insn2.size);
				}
			} else if (get_first_fcref_to(insn2.ea + insn2.size) == BADADDR) {
				unreachBlocks.add(insn2.ea + insn2.size, insn2.ea + insn2.size + 1);
			}
		} else {
			isPair = false;
		}
	}
	return isPair;
}

void remove_funcs_tails(ea_t ea)
{
	int i = 0;
	do {
		func_t *f = get_func(ea); if (!f || !remove_func_tail(f, ea))
			break;
		MSG_DO(("[hrt] func tail at %a deleted\n", ea));
	} while (++i > 100);

	if (i > 100 ) Log(llWarning, "%a FIXME: remove_funcs_tails loops\n", ea);
}

enum Add_BB_Stop_Reason {
	eABBSR_none,
	eABBSR_unreachBlocks,
	eABBSR_decode_insn,
	eABBSR_already_added,
	eABBSR_del_items,
	eABBSR_create_insn,
	eABBSR_bb_end
};

static bool add_bb(ea_t eaBgn, rangeset_t &ranges)
{
#if 0 // it doesnt work, probably need "auto_wait"
	while(del_func(eaBgn)) {
		MSG_DO(("[hrt] func at %a deleted\n", eaBgn));
	}
	remove_funcs_tails(eaBgn);
#endif

	Add_BB_Stop_Reason ABBSR = eABBSR_none;
	ea_t ea = eaBgn;
	while (1) {
		if (unreachBlocks.contains(ea)) {
			ABBSR = eABBSR_unreachBlocks;
			break;
		}

		insn_t insn;
		int sz = decode_insn(&insn, ea);
		if (sz <= 0) {
			ABBSR = eABBSR_decode_insn;
			break;
		}
		flags64_t flg = get_flags(ea);
		if (!is_code(flg)) {
			if (ranges.has_common(range_t(ea, insn.size))) {
				ABBSR = eABBSR_already_added;
				break;
			}
#if 0
			if (!is_unknown(flg) && !del_items(ea, DELIT_SIMPLE, insn.size)) {
				ABBSR = eABBSR_del_items;
				break;
			}
#else
			for (decltype(insn.size) i = 0; i < insn.size; i++) {
				if (!is_unknown(get_flags(ea + i)) && !del_items(ea + i, DELIT_SIMPLE)) {
					ABBSR = eABBSR_del_items;
					break;
				}
			}
#endif
			if (!create_insn(ea, &insn)) {
				ABBSR = eABBSR_create_insn;
				break;
			}
		}
		ea += insn.size;

		//is_basic_block_end has many additional checks (PH.is_basic_block_end(insn, false) doesnt work at all !!!)
		// returnd true if next ins flags is !FF_FLOW || !FF_CODE || FF_REF,  checks: try blocks and crefs

		// May seems to be a good idea to try create next insn forward before is_basic_block_end check
		// but it can continue block after real basic_block_end
		// I have not good alternative for is_basic_block_end except CFG creation so leave here slower variant
		if (is_basic_block_end(insn, false)) {
			disasm_dbl_jc(ea - insn.size);
			ABBSR = eABBSR_bb_end;
			break;
		}
	}
	if (ea != eaBgn && ranges.add(eaBgn, ea)) {
		MSG_DO(("[hrt] new block %a-%a\n", eaBgn, ea));
		return true;
	}

#if DEBUG_DO
	const char* m;
	switch(ABBSR) {
	case eABBSR_unreachBlocks:
		m = "unreachBlocks"; break;
	case eABBSR_decode_insn:
		m = "decode_insn"; break;
	case eABBSR_already_added:
		m = "already_added"; break;
	case eABBSR_del_items:
		m = "del_items"; break;
	case eABBSR_create_insn:
		m = "create_insn"; break;
	case eABBSR_bb_end:
		m = "bb_end"; break;
	default:
		m = "none";
	}
	Log(llDebug, "add_bb fail at %a with %s\n", ea, m);
#endif
	return false;
}

static ea_t get_nullsub_1()
{ // this hack is used only as a way to open new pseudocode view
	ea_t ea = get_name_ea(BADADDR, "nullsub_1");
	if (ea != BADADDR)
		return ea;

	if (!isX86()) {
		Log(llWarning, "FIXME: get_nullsub_1 is x86 specific\n");
		return BADADDR;
	}

	ea = inf_get_max_ea();
	if(is_unknown(get_flags(ea)) &&
		add_segm(0, ea, ea + 1, "[hrt]nullsub", "CODE", ADDSEG_QUIET | ADDSEG_FILLGAP) &&
		put_byte(ea, 0xc3) &&
		create_insn(ea) &&
		add_func(ea) &&
		set_name(ea, "nullsub_1"))
	{
		return ea;
	}
	return BADADDR;
}

void no_code_warning(ea_t ea)
{
	warning("[hrt] Please make code at %a, then press 'Esc' and try decompile again\n", ea);
	jumpto(ea, -1, UIJMP_IDAVIEW | UIJMP_ACTIVATE);
}

void rset2rvec(ea_t eaBgn, const rangeset_t *rs, rangevec_t *rv)
{
	QASSERT(100400, !rs->empty());
	rv->clear();
	const range_t *first = rs->find_range(eaBgn);
	QASSERT(100401, first);
	rv->push_back(range_t(eaBgn, first->end_ea));

	if (first->start_ea != eaBgn)  //startEA somwhere inside first fange
		rv->push_back(range_t(first->start_ea, eaBgn));

	for (auto r : *rs) {
		if (r != *first)
			rv->push_back(range_t(r.start_ea, r.end_ea));
	}
}

//create func chunks
func_t *remake_func(ea_t startEA,  const rangeset_t &ranges)
{
#if 0
	//does not help
	//if (!inf_is_auto_enabled())
	//	inf_set_auto_enabled(true);
	if (!is_auto_enabled())
		enable_auto(true);
#endif
	del_func(startEA);

	const range_t *first = ranges.find_range(startEA);
	if (!first) {
		MSG_DO(("[hrt] !first (%a)\n", startEA));
		return NULL;
	}
	add_func(startEA, first->end_ea);
	func_t *func = get_func(startEA);
	if (!func) {
		MSG_DO(("[hrt] !add_func(%a, %a)\n", startEA, first->end_ea));
		return NULL;
	}
	for (auto range : ranges) {
		if (range != *first) {
			remove_funcs_tails(range.start_ea);
			if (!append_func_tail(func, range.start_ea, range.end_ea)) {
				MSG_DO(("[hrt] !append_func_tail(%a, %a)\n", range.start_ea, range.end_ea));
			}
		}
	}
	if (first->start_ea != startEA) { //startEA somwhere inside first fange
		//remove_funcs_tails(first->start_ea);
		if (!append_func_tail(func, first->start_ea, startEA)) {
			MSG_DO(("[hrt] !append_func_tail(%a, %a)\n", first->start_ea, startEA));
		}
	}
	reanalyze_function(func);
	auto_wait();
	return func;
}

int decompile_obfuscated(ea_t eaBgn)
{
	func_t *func = get_func(eaBgn);
	if (func) {
		if (ASKBTN_YES != ask_yn(ASKBTN_YES, "[hrt] Func '%s' will be destroyed and recreated from scratch.", get_short_name(func->start_ea).c_str()))
			return 0;
		if(del_func(eaBgn)) {
			MSG_DO(("[hrt] func at %a deleted\n", eaBgn));
			if(get_screen_ea() != eaBgn)
				jumpto(eaBgn, -1, UIJMP_IDAVIEW);
		}
		func = NULL;
	}

	const char format[] =
		//"STARTITEM 3\n"
		// title
		"[hrt] Decompile obfuscated code\n\n"
		//"%/\n" // callback
		"<#Patch code on the fly. Work faster and produce a better results###Allow ~P~atching:C>\n"
		"<#Clear checkbox in case of INTERRs. Add new nodes to Control Flow Graph by disasm results.#Fast ~C~FG:C>\n"
		"<#Set checkbox in case of stack related errors. Recreate function on each step.#~F~unc regeneration:C>1>\n"
		"\n\n";
	if (1 != ask_form(format, &dflags))
		return false;

	rangeset_t ranges;
	unreachBlocks.clear();

	if (!add_bb(eaBgn, ranges)) {
		MSG_DO(("[hrt] %a: cant make initial bb\n", eaBgn));
		no_code_warning(eaBgn);
		return 0;
	}

	MSG_DO(("[hrt] deob begins from %a\n", eaBgn));
	show_wait_box("[hrt] Analyzing %a...", eaBgn);
	deob_init();
	bool bChanged;
	ea_t stuck_ea;
	int cnt = 0;
	do {
		stuck_ea = BADADDR;
		bChanged = false;
		final_pass = false;

		if (dflags & DF_FAST) {
			do {
				//using append_to_flowchart is requres to refresh and create_qflow_chart
				qflow_chart_t fc;
				fc.create("tmpfc2", ranges.as_rangevec(), 0); // !!! add line into range.hpp, class rangeset_t: "const rangevec_t &as_rangevec() const { return bag; }"
				bChanged = false;
				for (int n = 0; n < fc.size(); n++) {
					const qbasic_block_t* blk = &fc.blocks[n];
					if (blk->start_ea == blk->end_ea && add_bb(blk->start_ea, ranges)) { //new external block
						bChanged = true;
					}
				}
				//replace_wait_box("[hrt] Adding blocks (%d)\n", fc.size());
			} while (bChanged);
			bChanged = false;
		}

		replace_wait_box("[hrt] Analyzing step %d (%d ranges)...", ++cnt, ranges.nranges());

		const rangevec_t *rv;
		rangevec_t rvTmp;
		//check if first range is entry point
		if (ranges.getrange(0).start_ea == eaBgn) {
			rv = &ranges.as_rangevec(); // !!! add line into range.hpp, class rangeset_t: "const rangevec_t &as_rangevec() const { return bag; }"
		} else {
			//MSG_DO(("[hrt] start_ea != eaBgn\n"));
			rset2rvec(eaBgn, &ranges, &rvTmp);
			rv = &rvTmp;
		}

		if (dflags & DF_FUNC)
			remake_func(eaBgn, ranges);

		MSG_DO(("[hrt] gen_microcode step %d (%d ranges)\n", cnt, rv->size()));
		hexrays_failure_t hf;
		mba_ranges_t mbr(*rv);
		mbl_array_t *mba = gen_microcode(mbr, &hf, NULL, DECOMP_NO_WAIT | DECOMP_NO_CACHE | DECOMP_NO_FRAME | DECOMP_WARNINGS | DECOMP_ALL_BLKS, MMAT_GLBOPT3);
		if (!mba || hf.code != MERR_OK) {
			hide_wait_box();
			deob_done();
			Log(llError, "%a: gen_microcode err %d (%s)\n", hf.errea, hf.code, hf.desc().c_str());
			return 0;
		}

		eavec_t new_dests;
		for (int i = 0; i < mba->qty; i++) {
			mblock_t *blk = mba->get_mblock(i);
			if (blk->type == BLT_XTRN) {
				MSG_DO(("[hrt] xtrn block %a\n", blk->start));
				new_dests.add_unique(blk->start);
			}
		}
		deob_postprocess(mba, &new_dests);
#if DEBUG_DO
		//ShowMicrocodeExplorer(mba, "deob %d", cnt);
#endif
		mba->dump_mba(false, "[hrt] after deob step %d", cnt);
		delete mba;

		for (auto newaddr : new_dests) {
			if (unreachBlocks.contains(newaddr)) {
				MSG_DO(("[hrt] unreachable block as new dest %a\n", newaddr));
				continue;
			}
			if (add_bb(newaddr, ranges)) {
				bChanged = true;
			} else {
				stuck_ea = newaddr;
				MSG_DO(("[hrt] ??? existing or bad block at %a\n", newaddr));
			}
		}
		for (size_t bi = 0; bi < unreachBlocks.nranges(); bi++) {
			const range_t& r = unreachBlocks.getrange((int)bi);
			if (ranges.sub(r)) {
				MSG_DO(("[hrt] removing unreachable block %a-%a\n", r.start_ea, r.end_ea));
				bChanged = true;
			} else {
				MSG_DO(("[hrt] no range found for unreachable block %a-%a\n", r.start_ea, r.end_ea));
			}
			if (is_code(get_flags(r.start_ea)) && get_first_fcref_to(r.start_ea) == BADADDR) {
				del_items(r.start_ea, DELIT_EXPAND, r.end_ea - r.start_ea);
				//create_byte(ea, 1, true);
			}
		}
		if(dflags & DF_PATCH) // can clears unreachBlock
			unreachBlocks.clear();
	} while (bChanged && !user_cancelled());

	replace_wait_box("[hrt] Creating func...");
	MSG_DO(("[hrt] deob final pass at %a, %d ranges\n", eaBgn, ranges.nranges()));
	func = remake_func(eaBgn, ranges);
	final_pass = true;
	hide_wait_box();
#if 0
	if (func) {
		// here is below in `open_pseudocode` very strange (race condition?) bug may be happened:
		// after full decompiling and displaying requested by `eaBgn` function
		// open_pseudocode instead of returning control to the plugin
		// begins decompilation of other proc (I've seen decompiling the first call target inside `func`)
		// this wrong function decompiling skips all early deobfuscation passes and raises a lot of unreasonable INTERRs
		// this bug is unstable and does not reproducible on debuging with breakpoints, but may be catched by debug printing and mba dumping
		COMPAT_open_pseudocode_REUSE_ACTIVE(eaBgn);
		deob_done();
		// the workaround below just removes INTERRs calling deob_done() before open_pseudocode
		// but unneccessary additional decompiling still may be seen in the IDA_DUMPDIR folder

		// UPD a day later:
		// after spending whole day in fighting this bug, it suddenly dissapears after:
		// ___  clearing caches and saving IDB with enabled checkbox "Collect garbage" ___
		// and then appeared again after some short time
	}
#endif
	hexrays_failure_t hf;
	cfuncptr_t cf(nullptr);
	if (func) {
		mark_cfunc_dirty(eaBgn);
		cf = decompile_func(func, nullptr, DECOMP_NO_CACHE | DECOMP_WARNINGS | DECOMP_ALL_BLKS);
	} else {
		cf = decompile_snippet(ranges.as_rangevec(), &hf, DECOMP_NO_CACHE | DECOMP_NO_FRAME | DECOMP_WARNINGS | DECOMP_ALL_BLKS);
	}
	deob_done();
	if (hf.code != MERR_OK) {
		Log(llError, "decompile error %d: %s\n", hf.code, hf.desc().c_str());
		return 0;
	}
	cf->mba->dump_mba(true, "[hrt] decompile_obfuscated final");

	ea_t nullsub = get_nullsub_1();
	if (nullsub == BADADDR)
		nullsub = eaBgn;
	vdui_t *vdui = COMPAT_open_pseudocode_REUSE_ACTIVE(nullsub); //
	vdui->switch_to(cf, true); // broken in ida92 (or early). display requested code just until first click or keypress and then switches to `nullsub`
	jumpto(cf->entry_ea);

	if (stuck_ea != BADADDR) {
		Log(llWarning, "stuck at %a\n", stuck_ea);
		no_code_warning(stuck_ea);
	}
	return 1;
}

