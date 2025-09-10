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
#include <auto.hpp>
#include <bytes.hpp>
#include <intel.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "deob.h"

#define DEBUG_DO 0

#if DEBUG_DO
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
static rangeset_t unreachBlocks;

#if 0 //TODO: not completed
static bool unpackInterlockedExchange(mba_t* mba, mop_t *op)
{
	if (!op->is_insn(m_call))
		return false;
	if (!op->d->is_helper("_InterlockedExchange64"))
		return false;
	mcallinfo_t &fi = *op->d->d.f;
	if (fi.args.size() != 2)
		return false;

	mreg_t tmpReg = mba->alloc_kreg(op->size);
	minsn_t* ins1 = new minsn_t(op->d->ea);
	ins1->opcode = m_mov;
	ins1->d.make_reg(tmpReg, op->size);
	ins1->l = fi.args[0];
	minsn_t* ins2 = new minsn_t(op->d->ea);
	ins2->opcode = m_mov;
	ins2->d = fi.args[0];
	ins2->l = fi.args[1];
	minsn_t* ins3 = new minsn_t(op->d->ea);
	ins3->opcode = m_mov;
	ins3->d = fi.args[1];
	ins3->l.make_reg(tmpReg, op->size);
	mba->free_kreg(tmpReg, op->size);

	//TODO: replace/insert

	return true;
}
#endif

static int bswap_const_to_const(mop_t *op, minsn_t *call)
{
	if (!call->is_bswap())
		return 0;
	if (!call->is_helper("_byteswap_ulong"))
		return 0;
	mcallinfo_t &fi = *call->d.f;
	if (fi.args.empty())
		return 0;
	uint64 val;
	if (!fi.args.front().is_constant(&val))
		return 0;
	val = swap32((uint32)val);
	op->make_number(val, op->size);
	return 1;
}

struct ida_local deob_op_visitor_t : mop_visitor_t
{
	int visit_mop(mop_t *op, const tinfo_t *type, bool is_target)
	{
		if (op->is_insn(m_call))
			return bswap_const_to_const(op, op->d);
		return 0;
	}
};

struct ida_local deob_instr_visitor_t : minsn_visitor_t
{
	int visit_minsn()
	{ 
		switch (curins->opcode) {
		case m_ret:
			//return insert_ret_addr_catcher(curins);
			break;
		}
		return 0;
	}
};

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
		if (ins->opcode == m_ret && blk) {
			//res = insert_ret_addr_catcher(blk, ins);
		}

		if (!res) {
			//check operands of inst and subinsts
			deob_op_visitor_t vo;
			res = ins->for_all_ops(vo);
		}
		if (!res) {
			//check inst and subinsts
			deob_instr_visitor_t vi;
			res = ins->for_all_insns(vi);
		}
		if (res) {
			MSG_DO(("[hrt] %a deobfuscation: %s\n", ins->ea, ins->dstr()));
			//ins->optimize_solo();
			if (blk) {
				blk->mark_lists_dirty();
				blk->mba->verify(true);
			}
		}
		return res;
	}
};

mblock_t *pass_goto_chain(mbl_array_t *mba, int i)
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
		mba->mark_chains_dirty();
		mba->dump_mba(true, "[hrt] after handle_dbl_jc %d/%d", b1->serial, b2->serial);
		//mba->verify(false);
		return true;
	}
	virtual int idaapi func(mblock_t *blk)
	{
		if (handle_dbl_jc(blk))
			return 1;
		return 0;
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

void deob_preprocess(mbl_array_t *mba)
{
	if (!deob)
		return;

	if (!isX86()) {
		Log(llWarning, "FIXME: deob_preprocess is x86 specific\n");
		return ;
	}

	bool changed = false;

	for (int i = 0; i < mba->qty; i++) {
		mblock_t *blk = mba->get_mblock(i);
		if (blk->flags & MBL_FAKE)
			continue;
		if (!blk->tail || blk->tail->opcode != m_ijmp)
			continue;
		minsn_t *ijmp = blk->tail;
		minsn_t *mov_cs_seg = ijmp->prev;
		if (!mov_cs_seg)
			continue;
		if (mov_cs_seg->opcode == m_add) //optional: add esp, #const, esp
			mov_cs_seg = mov_cs_seg->prev;
		if (!mov_cs_seg || mov_cs_seg->opcode != m_mov)
			continue;
		minsn_t *pop_eoff = mov_cs_seg->prev;
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
				minsn_t *jmp = new minsn_t(ijmp->ea);
				jmp->opcode = m_goto;
				jmp->l._make_gvar(dest);
				blk->insert_into_block(jmp, ijmp);
				blk->make_nop(ijmp);// calls mark_lists_dirty()
				changed = true;
			}
		}


		if (bFirstPass) {//first pass: add retaddr catcher before 'ret'
		//FIXME: allocate temporol register instead eip
		//FIXME: x86 specific
			mreg_t eip = 0x58;
			mreg_t ss = reg2mreg(R_ss);
			mreg_t esp = reg2mreg(R_sp);
			for (mreg_t i = 0; i < 0x100; i += 4) {
				mop_t op;
				op._make_reg(i);
				Log(llFlood, "reg_%x  %s\n", i, op.dstr());
				if (!qstrcmp("eip", op.dstr())) {
					eip = i;
#if 1
					break;
				}
#else
			}
				if (!qstrcmp("ss", op.dstr())) {
					ss = i;
				}
				if (!qstrcmp("esp", op.dstr())) {
					esp = i;
				}
#endif
			}
			minsn_t *pc = new minsn_t(ijmp->ea);
			pc->opcode = m_ldx;
			pc->l._make_reg(ss, 2);
			pc->r._make_reg(esp, ea_size);
			pc->d._make_reg(eip, ea_size);
			blk->insert_into_block(pc, pop_eoff->prev);

			minsn_t* call = new minsn_t(pc->ea);
			call->opcode = m_call;
			call->l.make_helper("ret_addr");
			mcallinfo_t *ci = new mcallinfo_t();
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
	if (changed)
		mba->dump_mba(false, "[hrt] after deob_preprocess");
}

static bool patch_jmp(ea_t from, ea_t to, asize_t maxLen)
{
	if (!isX86()) {
		Log(llWarning, "FIXME: patch_jmp is x86 specific\n");
		return false;
	}
	qstring cmt(";patched: ");//';' in first position prevents comment be copyed to pseudocode
	qstring tmp;
	print_insn_mnem(&tmp, from);
	cmt += tmp;
	print_operand(&tmp, from, 0, GETN_NODUMMY);
	cmt += ' ';
	cmt += tmp;
	tag_remove(&cmt);

	del_items(from, DELIT_EXPAND); //Important here!!!

	adiff_t dist = to - from - 2;
	if (dist >= -128 && dist <= 127) {
		if (maxLen < 2) {
			Log(llWarning, "%a: no space for patch\n", from);
			return false;
		}
		patch_byte(from, 0xeb);
		//int64 dist64 = dist;
		patch_byte(from + 1, uint64(dist));
	} else {
		if (maxLen < 6) {
			Log(llWarning, "%a: no space for patch\n", from);
			return false;
		}
		patch_word(from, 0xe990); //prepend with 'nop' to be same size as 'jc'
		patch_dword(from + 2, uint64(dist - 4));
	}
	create_insn(from);
	set_cmt(from, cmt.c_str(), false);//FIXME: doesnt work, why????
	Log(llInfo, "%a: %s\n", from, cmt.c_str());
	return true;
}

//blocks may be reordered at early stages
mblock_t *get_next_mblock(mbl_array_t *mba, int from, ea_t ea)
{
	for (; from < mba->qty && from >= 0; ++from) {
		mblock_t *blk = mba->get_mblock(from);
		//if (blk->flags & MBL_FAKE)
		//	continue;
		if (blk->start == ea)
			return blk;
	}
	return NULL;
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
		patch_jmp(jc1->ea, destB1, b1->end - jc1->ea);
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
		mba->dump_mba(false, "[hrt] after deob_preoptimized");
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
				patch_jmp(insn1.ea, dest1, insn1.size);
				if (get_first_fcref_to(insn2.ea) == BADADDR) {
					unreachBlocks.add(insn2.ea, insn2.ea + insn2.size); //do not mark b2 as unreach if no patch
					//patch_jmp(insn2.ea, dest2, insn2.size);
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

		replace_wait_box("[hrt] Analyzing %d ranges...", ranges.nranges());

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

		if (dflags & DF_FUNC) {
			func = remake_func(eaBgn, ranges);
		}

		MSG_DO(("[hrt] gen_microcode %d ranges\n", rv->size()));
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
	MSG_DO(("[hrt] deob final pass, %d ranges\n", ranges.nranges()));
	func = remake_func(eaBgn, ranges);
	final_pass = true;
	hide_wait_box();
	if (func) {
		COMPAT_open_pseudocode_REUSE_ACTIVE(eaBgn);
	} else {
		hexrays_failure_t hf;
		cfuncptr_t cf = decompile_snippet(ranges.as_rangevec(), &hf, DECOMP_NO_CACHE | DECOMP_NO_FRAME | DECOMP_WARNINGS | DECOMP_ALL_BLKS);
		deob_done();
		if (hf.code != MERR_OK) {
			Log(llError, "decompile_snippet error %d: %s\n", hf.code, hf.desc().c_str());
			return 0;
		}
		cf->mba->dump();

		ea_t nullsub = get_nullsub_1();
		if (nullsub == BADADDR)
			nullsub = eaBgn;
		vdui_t *vdui = COMPAT_open_pseudocode_REUSE_ACTIVE(nullsub);
		vdui->switch_to(cf, true);
	}

	if (stuck_ea != BADADDR) {
		Log(llWarning, "stuck at %a\n", stuck_ea);
		no_code_warning(stuck_ea);
	}
	return 1;
}

