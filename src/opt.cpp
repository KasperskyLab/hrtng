// Here is an evolution of PatternDeobfuscate.cpp && PatternDeobfuscateUtil.cpp
// from https://github.com/carbonblack/HexRaysDeob (https://www.carbonblack.com/blog/defeating-compiler-level-obfuscations-used-in-apt10-malware/)

#include "warn_off.h"
#include <hexrays.hpp>
#include <intel.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "opt.h"

#define DEBUG_DO 0

#if DEBUG_DO
#define MSG_DO(msg_) msg msg_;
#else
#define MSG_DO(msg_)
#endif

// For microinstructions with two or more operands (in l and r), check to see if one of them is numeric and the other one isn't. 
// If this is the case, return pointers to the operands in the appropriately-named argument variables and return true. Otherwise, return false.
bool ExtractNumAndNonNum(minsn_t* insn, mop_t*& numOp, mop_t*& otherOp)
{
	mop_t* num = NULL, * other = NULL;

	//check right hand before
	if (insn->r.t == mop_n) {
		num = &insn->r;
		other = &insn->l;
	}

	//check left hand only for commutative ops
	if (insn->opcode != m_sub) {
		if (insn->l.t == mop_n) {
			if (num != NULL) {
				// Technically we have an option to perform constant folding here... but Hex-Rays should have done / should do that for us
				return false;
			}
			num = &insn->l;
			other = &insn->r;
		}
	}
	if (num == NULL)
		return false;

	numOp = num;
	otherOp = other;
	return true;
}

// For microinstructions with two or more operands (in l and r), check to see
// if one of them is a mop_d (result of another microinstruction), where the
// provider microinstruction is has opcode type mc. If successful, return the
// provider microinstruction and the non-matching micro-operand in the
// appropriately-named arguments. Otherwise, return false.
bool ExtractByOpcodeType(minsn_t* ins, mcode_t mc, minsn_t*& match, mop_t*& noMatch)
{
	mop_t* possNoMatch = NULL;
	minsn_t* possMatch = NULL;

	if (!ins->l.is_insn(mc))
		possNoMatch = &ins->l;
	else
		possMatch = ins->l.d;

	if (!ins->r.is_insn(mc))
		possNoMatch = &ins->r;
	else
		possMatch = ins->r.d;

	if (possNoMatch == NULL || possMatch == NULL)
		return false;

	match = possMatch;
	noMatch = possNoMatch;
	return true;
}

// The obfuscation techniques upon conditional operations have "&1"
// miscellaneously present or not present within them. Writing pattern-matching
// rules for all of the many possibilities would be extremely tedious. This
// helper function reduces the tedium by checking to see whether the provided
// microinstruction is "x & 1" (or "1 & x"), and it extracts x (as both an
// operand, and, if the operand is a mop_d (result of another
// microinstruction), return the provider instruction also.
bool TunnelThroughAnd1(minsn_t* ins, minsn_t*& inner, bool bRequireSize1 = true, mop_t** opInner = NULL)
{
	if (ins->opcode != m_and)
		return false;

	mop_t* andNum, * andNonNum;
	if (!ExtractNumAndNonNum(ins, andNum, andNonNum))
		return false;

	if (andNum->nnn->value != 1)
		return false;

	if (bRequireSize1 && andNum->size != 1)
		return false;

	if (opInner != NULL)
		*opInner = andNonNum;

	// If the non-numeric operand is an instruction, extract the microinstruction and pass that back to the caller.
	if (andNonNum->is_insn()) {
		inner = andNonNum->d;
		return true;
	}

	// Otherwise, if the non-numeric part wasn't a mop_d, check to see whether
	// the caller specifically wanted a mop_d. If they did, fail. If the caller
	// was willing to accept another operand type, return true.
	return opInner != NULL;
}

// It checks to see whether the provided microinstruction is "x | -2" (or "-2 | x"),
// and extracts x as both an operand,
// and, if the operand is a mop_d (result of another microinstruction),
// return the provider instruction also.
bool TunnelThroughOrMinus2(minsn_t* ins, minsn_t*& inner, bool bRequireSize1 = true, mop_t** opInner = NULL)
{
	if (ins->opcode != m_or)
		return false;

	mop_t* orNum, * orNonNum;
	if (!ExtractNumAndNonNum(ins, orNum, orNonNum))
		return false;

	// The number must be the value -2
	if (orNum->nnn->value != 0xFFFFFFFE)
		return false;

	if (bRequireSize1 && orNum->size != 1)
		return false;

	// If requested, pass the operand back to the caller this point
	if (opInner != NULL)
		*opInner = orNonNum;

	// If the non-numeric operand is an instruction, extract the
	// microinstruction and pass that back to the caller.
	if (orNonNum->is_insn()) {
		inner = orNonNum->d;
		return true;
	}

	// Otherwise, if the non-numeric part wasn't a mop_d, check to see whether
	// the caller specifically wanted a mop_d. If they did, fail. If the caller
	// was willing to accept another operand type, return true.
	return opInner != NULL;
}

// The obfuscator implements boolean inversion via "x ^ 1". Hex-Rays, or one of
// our other deobfuscation rules, could also convert these to m_lnot
// instructions. This function checks to see if the microinstruction passed as
// argument matches one of those patterns, and if so, extracts the negated
// term as both a micro-operand and a microinstruction (if the negated operand
// was of mop_d type).
bool ExtractLogicallyNegatedTerm(minsn_t* ins, minsn_t*& insNegated, mop_t** opNegated = NULL)
{
	// Check the m_lnot case.
	if (ins->opcode == m_lnot) {
		// Extract the operand, if requested by the caller.
		if (opNegated != NULL)
			*opNegated = &ins->l;

		// If the operand was mop_d (i.e., result of another microinstruction),
		// retrieve the provider microinstruction. Get rid of the pesky "&1"
		// terms while we're at it.
		if (ins->l.is_insn()) {
			insNegated = ins->l.d;
			while (TunnelThroughAnd1(insNegated, insNegated))
				;
			return true;
		}	else {
			// Otherwise, if the operand was not of type mop_d, "success" depends on whether the caller was willing to accept a non-mop_d operand.
			insNegated = NULL;
			return opNegated != NULL;
		}
	}

	// If the operand wasn't m_lnot, check the m_xor case.
	if (ins->opcode != m_xor)
		return false;

	mop_t* xorNum, * xorNonNum;
	if (!ExtractNumAndNonNum(ins, xorNum, xorNonNum))
		return false;

	if (xorNum->nnn->value != 1 || xorNum->size != 1)
		return false;

	// The non-numeric part must also be 1. This check is probably unnecessary.
	if (xorNonNum->size != 1)
		return false;

	if (opNegated != NULL)
		*opNegated = xorNonNum;

	// If the operand was mop_d (result of another microinstruction), extract it and remove the &1 terms.
	if (xorNonNum->is_insn()) {
		insNegated = xorNonNum->d;
		while (TunnelThroughAnd1(insNegated, insNegated))
			;
		return true;
	}

	// Otherwise, if the operand was not of type mop_d, "success" depends on
	// whether the caller was willing to accept a non-mop_d operand.
	insNegated = NULL;
	return opNegated != NULL;
}

// This function checks whether two conditional terms are logically opposite.
// For example, "eax <s 1" and "eax >=s 1" would be considered logically
// opposite. The check is purely syntactic; semantically-equivalent conditions
// that were not implemented as syntactic logical opposites will not be
// considered the same by this function.
bool AreConditionsOpposite(minsn_t* lhsCond, minsn_t* rhsCond)
{
	// Get rid of pesky &1 terms
	while (TunnelThroughAnd1(lhsCond, lhsCond))
		;
	while (TunnelThroughAnd1(rhsCond, rhsCond))
		;

	// If the conditions were negated via m_lnot or m_xor by 1, get the
	// un-negated part as a microinstruction.
	bool bLhsWasNegated = ExtractLogicallyNegatedTerm(lhsCond, lhsCond);
	bool bRhsWasNegated = ExtractLogicallyNegatedTerm(rhsCond, rhsCond);

	// lhsCond and rhsCond will be set to NULL if their original terms were
	// negated, but the thing that was negated wasn't the result of another
	// microinstruction.
	if (lhsCond == NULL || rhsCond == NULL)
		return false;

	// If one was negated and the other wasn't, compare them for equality.
	// If the non-negated part of the negated comparison was identical to
	// the non-negated comparison, then the conditions are clearly opposite.
	// I guess this could also be extended by incorporating the logic from
	// below, but I didn't need to do that in practice.
	if (bLhsWasNegated != bRhsWasNegated)
		return lhsCond->equal_insns(*rhsCond, EQ_IGNSIZE | EQ_IGNCODE);

	// Otherwise, if both were negated or both were non-negated, compare the
	// conditionals term-wise. First, ensure that both microoperands are
	// setXX instructions.
	else if (is_mcode_set(lhsCond->opcode) && is_mcode_set(rhsCond->opcode))
	{
		// Now we have two possibilities.
		// #1: Condition codes are opposite, LHS and RHS are both equal
		if (negate_mcode_relation(lhsCond->opcode) == rhsCond->opcode)
			return 	lhsCond->l.equal_mops(rhsCond->l, EQ_IGNSIZE) && lhsCond->r.equal_mops(rhsCond->r, EQ_IGNSIZE);

		// #2: Condition codes are the same, LHS and RHS are swapped
		if (lhsCond->opcode == rhsCond->opcode)
			return	rhsCond->r.equal_mops(lhsCond->l, EQ_IGNSIZE) && rhsCond->l.equal_mops(lhsCond->r, EQ_IGNSIZE);
	}
	return false;
}

// This function checks whether the operand is a global variable unchanged since the initialization
bool IsReadOnlyInitedVar(mop_t* op)
{
	if (op->t != mop_v) // global variable?
		return false;

	// The variable is in a writable section? (e.g., .data section)
	segment_t* s = getseg(op->g);
	if (s == NULL)
		return false;
	if (s->perm != (SEGPERM_READ | SEGPERM_WRITE))
		return false;
	// TODO: section with IMAGE_SCN_CNT_INITIALIZED_DATA?

	// The variable doesn't have a byte value?
	if (!is_mapped(op->g))
		return false;
	// The variable doesn't have xrefsTo with write access?
	xrefblk_t xb;
	for (bool ok = xb.first_to(op->g, XREF_DATA); ok; ok = xb.next_to())
		if (xb.type == dr_W)
			return false;

	return true;
}

// Put an mop_t into an mlist_t. The op must be either a register or a stack variable.
bool InsertOp(mblock_t* mb, mlist_t& ml, mop_t* op)
{
	if (!isRegOvar(op->t))
		return false;
	mb->append_use_list(&ml, *op, MUST_ACCESS);
	return true;
}

// Walks backwards through a block, looking at what each instruction defines. 
// It stops when it finds definitions for everything in the mlist_t, or when it hits the beginning of the block.
minsn_t* my_find_def_backwards(mblock_t* mb, mlist_t& ml, minsn_t* start)
{
	for (minsn_t* p = start != NULL ? start : mb->tail; p != NULL; p = p->prev) {
		mlist_t def = mb->build_def_list(*p, /*MAY_ACCESS*/ MUST_ACCESS | FULL_XDSU);//may-list includes all aliasable memory in case of indirect stx
		if (def.includes(ml))
			return p;
	}
	return NULL;
}

// This function traces the operand until getting the instruction with it
bool FindInsWithTheOp(mblock_t* blk, mop_t* op, minsn_t* start, minsn_t*& ins, mcode_t opcode, mopt_t opt = 0)
{
	mlist_t ml;
	if (!InsertOp(blk, ml, op))
		return false;
	minsn_t* mStart = start;
	do {
		minsn_t* mDef = my_find_def_backwards(blk, ml, mStart);
		if (mDef == NULL) {
			// move to previous block
			blk = blk->prevb;
			mStart = NULL;
		} else {
			if (mDef->opcode == opcode && (opt == 0 || opt == mDef->l.t)) {
				ins = mDef;
				return true;
			}

			if (mDef->opcode == m_mov) {
				ml.clear();
				if (!InsertOp(blk, ml, &mDef->l))
					return false;
			} else {
#if DEBUG_DO
				qstring qs;
				mDef->print(&qs);
				tag_remove(&qs);
				MSG_DO(("[E] %a: FindInsWithTheOp found '%s'\n", mDef->ea, qs.c_str()));
#endif
				return false;
			}
			mStart = mDef;
		}
	} while (blk->prevb != NULL);
	return false;
}

// This function traces 2 operands separately for x and y in y * (x - 1)
bool TraceAndExtractOpsMovAndSubBy1(mblock_t* blk, mop_t*& opMov, mop_t*& opSub, minsn_t* start)
{
	minsn_t* insMov, * insSub;

	if (FindInsWithTheOp(blk, &start->l, start, insMov, m_mov) && FindInsWithTheOp(blk, &start->r, start, insSub, m_sub)) {
		opMov = &insMov->l;
		mop_t* num;
		if (ExtractNumAndNonNum(insSub, num, opSub) && num->nnn->value == 1)
			return true;
	}

	// swap the search operands
	if (FindInsWithTheOp(blk, &start->r, start, insMov, m_mov) && FindInsWithTheOp(blk, &start->l, start, insSub, m_sub)) {
		opMov = &insMov->l;
		mop_t* num;
		if (ExtractNumAndNonNum(insSub, num, opSub) && num->nnn->value == 1)
			return true;
	}
	return false;
}

	// This function simplifies microinstruction patterns that look like
	// either: (x & 1) | (y & 1) ==> (x | y) & 1
	// or:     (x & 1) ^ (y & 1) ==> (x ^ y) & 1
	// Though it may not seem like much of an "obfuscation" or "deobfuscation"
	// technique on its own, getting rid of the "&1" terms helps reveal other
	// patterns so they can be deobfuscated.
	int pat_LogicAnd1(minsn_t* ins, mblock_t* /*blk*/)
	{
		if (ins->opcode != m_or && ins->opcode != m_xor)
			return 0;
		if (ins->l.t != mop_d || ins->r.t != mop_d)
			return 0;

		minsn_t* insLeft, * insRight;
		mop_t* opLeft, * opRight;

		// Get rid of & 1. bLeft1 is true if there was an &1.
		bool bLeft1 = TunnelThroughAnd1(ins->l.d, insLeft, true, &opLeft);
		if (!bLeft1)
			return 0;

		// Same for right-hand side
		bool bRight1 = TunnelThroughAnd1(ins->r.d, insRight, true, &opRight);
		if (!bRight1)
			return 0;
		MSG_DO(("[I] pat_LogicAnd1: '%s'", ins->dstr()));

		// If we get here, then the pattern matched.
		// Move the logical operation (OR or XOR) to the left-hand side,
		// with the operands that have the &1 removed.
		ins->l.d->opcode = ins->opcode;
		ins->l.d->l.swap(*opLeft);
		ins->l.d->r.swap(*opRight);

		// Change the top-level instruction from OR or XOR to AND, and set the
		// right-hand side to the 1-bit constant value 1.
		ins->opcode = m_and;
		ins->r.make_number(1, 1);

		return 1;
	}

// move constanst on rigth side and force constant arithmetic be together

// One of the obfuscation patterns involves a subtraction by 1. In the
// assembly code, this is implemented by something like:
//
// add eax, 2
// add eax, ecx ; or whatever
// sub eax, 3
//
// Usually, Hex-Rays will automatically simplify this to (eax+ecx)-1.
// However, I did experience situations where Hex-Rays still represented
// the decompiled output as 2+(eax+ecx)-3. This function, then, determines
// when Hex-Rays has represented the subtraction as just mentioned. If so,
// it extracts the term that is being subtracted by 1.
	int pat_AddSub(minsn_t* ins, mblock_t* blk)
	{
		// We're looking for following expressions where 'a' and 'b' are numeric 
		// (x-a)+b or (x+a)+b --> x+(b-a) or x+(b+a)
		// (x-a)-b or (x+a)-b --> x-(b+a) or x-(b-a) 
		if (ins->opcode != m_add /* && ins->opcode != m_sub*/)
			return 0;

		// Extract b and (x-a)
		mop_t* b = NULL, * xa = NULL;
		if (!ExtractNumAndNonNum(ins, b, xa))
			return 0;

		// Ensure that the purported (x-a) term actually is a subtraction
		if (xa->t != mop_d || (xa->d->opcode != m_sub && xa->d->opcode != m_add))
			return 0;

		// Extract x and a. ExtractNumAndNonNum fixed to check only rhs in case of sub
		mop_t* a = NULL, * x = NULL;
		if (!ExtractNumAndNonNum(xa->d, a, x))
			return 0;

		MSG_DO(("[I] pat_AddSub: '%s'", ins->dstr()));
		//convert (x-a)+b --> x+(b-a)
		xa->d->l.swap(*b); //xa->d is m_sub or m_add
		ins->l.swap(ins->r);// 'x' now in 'b', just swap 'l' and 'r' to place const on right hand
		if(ins->opcode == m_sub) {
			//convert: (x-a)-b or (x+a)-b --> x-(b+a) or x-(b-a)
			//at the moment we have           x-(b-a) or x-(b+a),
			//invert operation in brackers
			if (xa->d->opcode == m_sub)
				xa->d->opcode = m_add;
			else
				xa->d->opcode = m_sub;
		}

		return 1;
	}

	// This function performs the following pattern-substitution:
	// (x * (x-1)) & 1 ==> 0
	int pat_MulSub(minsn_t* andIns, mblock_t* blk)
	{
		// Topmost term has to be &1. The 1 is not required to be 1-byte large.
		minsn_t* ins = andIns;
		if (!TunnelThroughAnd1(ins, ins, false))
			return 0;

		// Looking for multiplication terms
		if (ins->opcode != m_mul)
			return 0;

		// We have two different mechanisms for determining if there is a subtraction by 1.
		bool bWasSubBy1 = false;

		// Ultimately, we need to find thse things:
		minsn_t* insSub;    // Subtraction instruction x-1
		mop_t* opMulNonSub; // Operand of multiply that isn't a subtraction
		mop_t* subNonNum = NULL;   // x from the x-1 instruction

		// Try first method for locating subtraction by 1, i.e., simply subtraction by the constant number 1.
		do {
			// Find the subtraction subterm of the multiplication
			if (!ExtractByOpcodeType(ins, m_sub, insSub, opMulNonSub))
				break;

			mop_t* subNum;
			// Find the numeric part of the subtraction. ExtractNumAndNonNum fixed to check only rhs in case of sub
			if (!ExtractNumAndNonNum(insSub, subNum, subNonNum))
				break;

			// Ensure that the subtraction amount is 1.
			if (subNum->nnn->value != 1)
				break;

			// Indicate that we successfully found the subtraction.
			bWasSubBy1 = true;
		} while (0);


		// If both methods failed, bail.
		if (!bWasSubBy1) {
			// data flow tracking for each y and (x - 1) operands
			if (blk == NULL || !TraceAndExtractOpsMovAndSubBy1(blk, opMulNonSub, subNonNum, ins))
				return 0;
		}

		//for pairs like::
		// -- ldx (smth) size 1
		// and
		// -- low (ldx (smth) size 4) size 1
		// strip "low"
		if (subNonNum->size == 1 && opMulNonSub->size == 1) {
			if (opMulNonSub->is_insn(m_low))
				opMulNonSub = &opMulNonSub->d->l;
			if (subNonNum->is_insn(m_low))
				subNonNum = &subNonNum->d->l;
		}

		// We know we're dealing with (x-1) * y. ensure x==y.
		if (!subNonNum->equal_mops(*opMulNonSub, EQ_IGNSIZE))
			return 0;

		MSG_DO(("[I] pat_MulSub: '%s'", andIns->dstr()));
		// If we get here, the pattern matched.
		// Replace the whole multiplication instruction by 0.
		ins->l.make_number(0, ins->l.size);
		return 1;
	}

	// check y * (x - 1) and extract the operands
	// mop_t *opMulNonSub; // Operand y of multiply that isn't a subtraction
	// mop_t *subNonNum;   // Operand x from the x-1 instruction
	bool CheckAndExtractOpsSubBy1(minsn_t* ins, mop_t*& opMulNonSub, mop_t*& subNonNum)
	{
		minsn_t* insSub;    // Subtraction instruction x-1

		// Find the subtraction subterm of the multiplication
		if (!ExtractByOpcodeType(ins, m_sub, insSub, opMulNonSub))
			return false;

		mop_t* subNum;
		// Find the numeric part of the subtraction. ExtractNumAndNonNum fixed to check only rhs in case of sub
		if (!ExtractNumAndNonNum(insSub, subNum, subNonNum))
			return false;

		// Ensure that the subtraction amount is 1.
		if (subNum->nnn->value != 1)
			return false;

		return true;
	}

	// This function performs the following pattern-substitution:
	// ~(x * (x - 1)) | -2 ==> -1
	int pat_MulSub2(minsn_t* orIns, mblock_t* blk)
	{
		// Topmost term has to be |-2.
		minsn_t* ins = orIns;
		if (!TunnelThroughOrMinus2(ins, ins, false))
			return 0;
		if (ins->opcode != m_xdu)
			return 0;

		// extract the subinstructions
		minsn_t* insBnot, * insMul;
		if (!ins->l.is_insn(m_bnot))
			return 0;
		insBnot = ins->l.d;
		if (!insBnot->l.is_insn(m_mul))
		{
			mop_t* op = &insBnot->l;
			// data flow tracking #1 for y * (x - 1) instruction
			if (blk == NULL || !FindInsWithTheOp(blk, op, insBnot, insMul, m_mul))
				return 0;
		}
		else
			insMul = insBnot->l.d; // m_mul

		// get y *(x-1)
		mop_t* opMulNonSub; // Operand y of multiply that isn't a subtraction
		mop_t* subNonNum;   // Operand x from the x-1 instruction
		if (!CheckAndExtractOpsSubBy1(insMul, opMulNonSub, subNonNum))
		{
			if (blk == NULL)
				return 0;
			// data flow tracking #2: both of the operands are not extracted due to lack of nested sub instruction
			MSG_DO(("[I] pat_MulSub2: tracking #2 OR ins %#a at %#a\n", orIns->ea, blk->mba->entry_ea));
			if (!TraceAndExtractOpsMovAndSubBy1(blk, opMulNonSub, subNonNum, insMul))
				return 0;
		}

		// ensure x==y
		if (!subNonNum->equal_mops(*opMulNonSub, EQ_IGNSIZE))
		{
			if (blk == NULL)
				return 0;
			// data flow tracking #3: both of the operands are extracted but different due to assignment to registers
			MSG_DO(("[I] pat_MulSub2: tracking #3 OR ins %#a at %#a\n", orIns->ea, blk->mba->entry_ea));
			minsn_t* insMov;
			if (opMulNonSub->t != mop_v && FindInsWithTheOp(blk, opMulNonSub, insMul, insMov, m_mov))
				opMulNonSub = &insMov->l;
			if (subNonNum->t != mop_v && FindInsWithTheOp(blk, subNonNum, insMul, insMov, m_mov))
				subNonNum = &insMov->l;
			if (!subNonNum->equal_mops(*opMulNonSub, EQ_IGNSIZE))
				return 0;
		}

		MSG_DO(("[I] pat_MulSub2: '%s'", orIns->dstr()));
		// If we get here, the pattern matched.
		// Replace the whole multiplication instruction by 0.
		//ins->l.make_number(0, ins->l.size);
		insBnot->l.make_number(2, insBnot->l.size); // m_bnot operand to be modified with 2
		return 1;
	}

#if 0
	// This function replaces read-only initialized global variable patterns with 0 in m_setl/m_jl/m_jge, m_seto (MMAT_CALLS or later only)
	// either: dword_73FBB588 >= immediate value (e.g., 10, 9)
	// or:     dword_73FBB588 < immediate value (e.g., 10, 9)
	int pat_InitedVarCondImm(minsn_t*& ins, mblock_t* blk)
	{
		if (ins->opcode == m_seto && (blk == NULL || blk->mba->maturity <= MMAT_LOCOPT))
			return 0;

		mop_t* condNum;
		mop_t* condNonNum;
		if (!ExtractNumAndNonNum(ins, condNum, condNonNum))
			return 0;

		//if (condNum->nnn->value != 10)
		if (condNum->nnn->value != 10 && condNum->nnn->value != 9)
			return 0;

		if (condNonNum->t == mop_v)
		{
			if (!IsReadOnlyInitedVar(condNonNum))
				return 0;
		}
		else
		{
			if (blk == NULL)
				return 0;
			// data flow tracking
			minsn_t* insOut;
			if (!FindInsWithTheOp(blk, condNonNum, ins, insOut, m_mov, mop_v))
				return 0;
			if (!IsReadOnlyInitedVar(&insOut->l))
				return 0;
			//else { MSG_DO(("[I] pat_InitedVarCondImm: tracked ins %a at %a\n", ins->ea, blk->mba->entry_ea));}
		}

		// Replace the global variable with 0
		if (ins->l.equal_mops(*condNonNum, EQ_IGNSIZE))
			ins->l.make_number(0, ins->l.size);
		else
			ins->r.make_number(0, ins->r.size);
		return 1;
	}

	// This function replaces read-only initialized global variable patterns with 0 in m_sets (MMAT_CALLS or later only)
	// either: dword_73FBB588 - 10 >= 0
	// or:     dword_10020CE4 - 10 < 0
	int pat_InitedVarSubImmCond0(minsn_t* ins, mblock_t* blk)
	{
		if (blk == NULL || blk->mba->maturity <= MMAT_LOCOPT)
			return 0;

		minsn_t* insSub;
		if (!ins->l.is_insn(m_sub))
			return 0;
		insSub = ins->l.d;

		int ret = pat_InitedVarCondImm(insSub, blk);
		if (ret && insSub->opcode == m_nop)
		{
			ins->opcode = m_mov;
			ins->l.make_number(1, 1);
			return 1;
		}
		return 0;
	}

	// This function replaces read-only initialized global variable patterns with 0
	// e.g.,
	// v10 = dword_73FBB590;
	// if ( v10 < 10 )
	//     ....
	int pat_InitedVarMov(minsn_t* ins)
	{
		if (!IsReadOnlyInitedVar(&ins->l))
			return 0;

		// Replace the global variable with 0
		ins->l.make_number(0, ins->l.size);
		return 1;
	}
#endif

	// This function looks tries to replace patterns of the form
	// either: (x&y)|(x^y)   ==> x|y
	// or:     (x&y)|(y^x)   ==> x|y
	int pat_OrViaXorAnd(minsn_t* ins, mblock_t* blk)
	{
		if (ins->opcode != m_or)
			return 0;

		// ... where one side is a compound XOR, and the other is not ...
		minsn_t* xorInsn;
		mop_t* nonXorOp;
		if (!ExtractByOpcodeType(ins, m_xor, xorInsn, nonXorOp))
			return 0;

		// .. and the other side is a compound AND ...
		if (!nonXorOp->is_insn(m_and))
			return 0;

		// Extract the operands for the AND and XOR terms
		mop_t* xorOp1 = &xorInsn->l, * xorOp2 = &xorInsn->r;
		mop_t* andOp1 = &nonXorOp->d->l, * andOp2 = &nonXorOp->d->r;

		// The operands must be equal
		if (!(andOp1->equal_mops(*xorOp1, EQ_IGNSIZE) && andOp2->equal_mops(*xorOp2, EQ_IGNSIZE)) ||
			(andOp2->equal_mops(*xorOp1, EQ_IGNSIZE) && andOp1->equal_mops(*xorOp2, EQ_IGNSIZE)))
			return 0;

		MSG_DO(("[I] pat_OrViaXorAnd: '%s'", ins->dstr()));
		// Move the operands up to the top-level OR instruction
		ins->l.swap(*xorOp1);
		ins->r.swap(*xorOp2);
		return 1;
	}

	// This pattern replaces microcode of the form (x|!x), where x is a
	// conditional, and !x is its syntactically-negated version, with 1.
	int pat_OrNegatedSameCondition(minsn_t* ins, mblock_t* blk)
	{
		if (ins->opcode != m_or)
			return 0;

		// Only applies when x and y are compound expressions, i.e., results
		// of other microcode instructions.
		if (ins->l.t != mop_d || ins->r.t != mop_d)
			return 0;

		// Ensure x and y are syntactically-opposite versions of the same
		// conditional.
		if (!AreConditionsOpposite(ins->l.d, ins->r.d))
			return 0;

		MSG_DO(("[I] pat_OrNegatedSameCondition: '%s'", ins->dstr()));
		// If we get here, the pattern matched. Replace both sides of OR with
		// 1, and then call optimize_flat to fold the constants.
		ins->l.make_number(1, 1);
		ins->r.make_number(1, 1);
		return 1;
	}

	// Replace patterns of the form
	// (x & c) | ( ~x & d) (when c and d are numbers such that c == ~d) => x ^ d.
	int pat_OrAndNot(minsn_t* ins, mblock_t* /*blk*/)
	{
		// Looking for OR instructions...
		if (ins->opcode != m_or)
			return 0;

		// ... with compound operands ...
		if (ins->l.t != mop_d || ins->r.t != mop_d)
			return 0;

		minsn_t* lhs1 = ins->l.d;
		minsn_t* rhs1 = ins->r.d;

		// ... where each operand is an AND ...
		if (lhs1->opcode != m_and || rhs1->opcode != m_and)
			return 0;

		// Extract the numeric and non-numeric operands from both AND terms
		mop_t* lhsNum = NULL, * rhsNum = NULL;
		mop_t* lhsNonNum = NULL, * rhsNonNum = NULL;
		bool bLhsSucc = ExtractNumAndNonNum(lhs1, lhsNum, lhsNonNum);
		bool bRhsSucc = ExtractNumAndNonNum(rhs1, rhsNum, rhsNonNum);

		// ... both AND terms must have one constant ...
		if (!bLhsSucc || !bRhsSucc)
			return 0;

		// .. both constants have a size, and are the same size ...
		if (lhsNum->size == NOSIZE || lhsNum->size != rhsNum->size)
			return 0;

		// ... and the constants are bitwise inverses of one another ...
		if ((lhsNum->nnn->value & rhsNum->nnn->value) != 0)
			return 0;

		// One of the non-numeric parts must have a binary not (i.e., ~) on it
		mop_t* nonNottedInsn = NULL, * nottedNum = NULL, * nottedInsn = NULL;

		// Check the left-hand size for binary not
		if (lhsNonNum->is_insn(m_bnot)) {
			// Extract the NOTed term
			nottedInsn = &lhsNonNum->d->l;
			// Make note of the corresponding constant value
			nottedNum = lhsNum;
		} else {
			nonNottedInsn = lhsNonNum;
		}

		// Check the left-hand size for binary not
		if (rhsNonNum->is_insn(m_bnot)) {
			// Both sides NOT? Not what we want, return 0
			if (nottedInsn != NULL)
				return 0;

			// Extract the NOTed term
			nottedInsn = &rhsNonNum->d->l;
			// Make note of the corresponding constant value
			nottedNum = rhsNum;
		} else {
			// Neither side has a NOT? Bail
			if (nonNottedInsn != NULL)
				return 0;
			nonNottedInsn = rhsNonNum;
		}

		// The expression that was NOTed must match the non-NOTed operand
		if (!nonNottedInsn->equal_mops(*nottedInsn, EQ_IGNSIZE))
			return 0;

		MSG_DO(("[I] pat_OrAndNot: '%s'", ins->dstr()));
		// Okay, all of our conditions matched. Make an XOR(x,d) instruction
		ins->opcode = m_xor;
		ins->l.swap(*nonNottedInsn);
		ins->r.swap(*nottedNum);
		return 1;
	}

	// Replaces conditionals of the form
	// !(!c1 || !c2) => (c1 && c2).
	int pat_LnotOrLnotLnot(minsn_t* ins, mblock_t* /*blk*/)
	{
		// The whole expression must be logically negated.
		minsn_t* inner;
		if (!ExtractLogicallyNegatedTerm(ins, inner) || inner == NULL)
			return 0;

		// The thing that was negated must be an OR with compound operands.
		if (inner->opcode != m_or || inner->l.t != mop_d || inner->r.t != mop_d)
			return 0;

		// The two compound operands must also be negated
		minsn_t* insLeft = inner->l.d;
		minsn_t* insRight = inner->r.d;
		mop_t* opLeft, * opRight;
		if (!ExtractLogicallyNegatedTerm(inner->l.d, insLeft, &opLeft) || !ExtractLogicallyNegatedTerm(inner->r.d, insRight, &opRight))
			return 0;

		MSG_DO(("[I] pat_LnotOrLnotLnot: '%s'", ins->dstr()));
		// If we're here, the pattern matched. Make the AND.
		ins->opcode = m_and;
		ins->l.swap(*opLeft);
		ins->r.swap(*opRight);
		return 1;
	}

	// Replaces terms of the form, where n is a number
	// ~(~x | n) ==> x & ~n.
	int pat_BnotOrBnotConst(minsn_t* ins, mblock_t* /*blk*/)
	{
		// We're looking for BNOT instructions (~y)...
		if (ins->opcode != m_bnot || ins->l.t != mop_d)
			return 0;

		// ... where x is an OR instruction ...
		minsn_t* inner = ins->l.d;
		if (inner->opcode != m_or)
			return 0;

		// ... and one side is constant, where the other one isn't ...
		mop_t* orNum, * orNonNum;
		if (!ExtractNumAndNonNum(inner, orNum, orNonNum))
			return 0;

		// ... and the non-constant part is itself a BNOT instruction (~x)
		if (!orNonNum->is_insn(m_bnot))
			return 0;

		MSG_DO(("[I] pat_BnotOrBnotConst: '%s'", ins->dstr()));
		// Once we found it, rewrite the top-level BNOT with an AND
		ins->opcode = m_and;
		ins->l.swap(orNonNum->d->l);

		// Invert the numeric part
		uint64 notNum = ~(orNum->nnn->value) & ((1ULL << (orNum->size * 8)) - 1);
		ins->r.make_number(notNum, orNum->size);
		return 1;
	}

	// Replaces 'call ARITH(cons1, const2)' to result of `cons1 [&|^+-] const2`
	int call_ARITH_2const(mop_t* op, minsn_t* call, mblock_t* /*blk*/)
	{
		if(!op || call->opcode != m_call || call->l.t != mop_v)
			return 0;
		mcallinfo_t *fi = call->d.f;
		if (!fi || fi->return_type.is_void() || fi->args.size() != 2)
			return 0;
		//FIXME: what about spoiled registers and stack balance in case of __stdcall

		uint64 val1, val2, res;
		if (!fi->args.front().is_constant(&val1, false) || !fi->args.back().is_constant(&val2, false))
			return 0;

		qstring funcname = get_name(call->l.g);
		stripName(&funcname, true);
		if(funcname.length() > 3)
			return 0; //optimize away funcs with longer names

		if(!qstrcmp(funcname.c_str(), "AND"))
			res = val1 & val2;
		else if(!qstrcmp(funcname.c_str(), "OR_"))
			res = val1 | val2;
		else if(!qstrcmp(funcname.c_str(), "XOR"))
			res = val1 ^ val2;
		else if(!qstrcmp(funcname.c_str(), "ADD"))
			res = val1 + val2;
		else if(!qstrcmp(funcname.c_str(), "SUB"))
			res = val1 - val2;
		else {
			MSG_DO(("[E] not implemented op"));
			return 0;
		}
		MSG_DO(("[I] call_ARITH_2const: '%s'", call->dstr()));
		op->make_number(res, (int)fi->return_type.get_size(), call->ea);
		return 1;
	}

	// Replaces 'call ARITH_0xNN(x)' ==> `x & NN` or `x ^ NN` or `x + NN` or `x - NN`
	// Replaces 'call LDX_0xNN(x)'   ==> `[x + NN]` (ldx  ds.2, (arg.8+#0xNN.8), result.4)
	// Replaces 'call RET_0xNN()'    ==> `NN`
	int call_ARITH_0xNN(mop_t* op, minsn_t* ins, mblock_t* /*blk*/)
	{
		if(ins->opcode != m_call || ins->l.t != mop_v)
			return 0;

		mcallinfo_t *fi = ins->d.f;
		if (!fi || fi->return_type.is_void())
			return 0;
		//FIXME: what about spoiled registers and stack balance in case of __stdcall

		qstring funcname = get_name(ins->l.g);
		stripName(&funcname, true);
		if(funcname.length() <= 6 || strncmp(funcname.c_str() + 3, "_0x", 3))
			return 0;

		ea_t n;
		if(!atoea(&n, funcname.c_str() + 4))
			return 0;

		mcode_t opcode;
		if(!strncmp(funcname.c_str(), "AND", 3))
			opcode = m_and;
		else if(!strncmp(funcname.c_str(), "OR_", 3))
			opcode = m_or;
		else if(!strncmp(funcname.c_str(), "XOR", 3))
			opcode = m_xor;
		else if(!strncmp(funcname.c_str(), "ADD", 3))
			opcode = m_add;
		else if(!strncmp(funcname.c_str(), "SUB", 3))
			opcode = m_sub;
		else if(!strncmp(funcname.c_str(), "LDX", 3))
			opcode = m_ldx;
		else if(!strncmp(funcname.c_str(), "RET", 3))
			opcode = m_ret;
		else {
			MSG_DO(("[E] not implemented op"));
			return 0;
		}

		MSG_DO(("[I] call_ARITH_0xNN: '%s'", ins->dstr()));
		if(opcode == m_ret) {
			if(!op)
				return 0;
			op->make_number(n, (int)fi->return_type.get_size(), ins->ea);
		} else {
			if(fi->args.size() < 1)
				return 0;
			if(opcode == m_ldx) {
				minsn_t* add = new minsn_t(ins->ea);
				add->opcode = m_add;
				add->l = fi->args.front();
				add->r.make_number(n, add->l.size, ins->ea);
				add->d.size = ea_size;
				ins->r.make_insn(add);
				ins->r.size = ea_size;
				ins->l.make_reg(reg2mreg(R_ds), 2); //FIXME: x86 specific!
			} else {
				ins->l = fi->args.front();
				ins->r.make_number(n, (int)fi->return_type.get_size(), ins->ea);
			}
			ins->opcode = opcode;
		}
		return 1;
	}

	// replace: x ^ c == d
	// to:     x == c ^ d
	int pat_XorCondImm(minsn_t* cjmp, mblock_t* blk)
	{
		if(!is_mcode_convertible_to_set(cjmp->opcode) && !is_mcode_convertible_to_jmp(cjmp->opcode))
			return 0;

		if(!cjmp->l.is_insn(m_xor))
			return 0;

		uint64 num1, num2;
		if (!cjmp->l.d->r.is_constant(&num1, false) || !cjmp->r.is_constant(&num2, false))
			return 0;

		MSG_DO(("[I] pat_XorCondImm: '%s'", cjmp->dstr()));
		cjmp->l.swap(cjmp->l.d->l);
		cjmp->r.nnn->update_value(num1 ^ num2);
		return 1;
	}

	// This function just inspects the instruction and calls the
	// pattern-replacement functions above to perform deobfuscation.
	int OptimizeInsn(mop_t* op, minsn_t* ins, mblock_t* blk)
	{
		int iLocalRetVal = 0;

		switch (ins->opcode) {
		case m_bnot:
			iLocalRetVal = pat_BnotOrBnotConst(ins, blk);
			break;
		case m_or:
			iLocalRetVal = pat_OrAndNot(ins, blk);
			if (!iLocalRetVal)
				iLocalRetVal = pat_OrViaXorAnd(ins, blk);
			if (!iLocalRetVal)
				iLocalRetVal = pat_OrNegatedSameCondition(ins, blk);
			if (!iLocalRetVal)
				iLocalRetVal = pat_LogicAnd1(ins, blk);
			if (!iLocalRetVal)
				iLocalRetVal = pat_MulSub2(ins, blk); // added
			break;
		case m_and:
			iLocalRetVal = pat_MulSub(ins, blk);
			break;
		case m_xor:
			iLocalRetVal = pat_LnotOrLnotLnot(ins, blk);
			if (!iLocalRetVal)
				iLocalRetVal = pat_LogicAnd1(ins, blk);
			break;
		case m_lnot:
			iLocalRetVal = pat_LnotOrLnotLnot(ins, blk);
			break;
		case m_setl:
		case m_jl:
		case m_jge:
		case m_seto: // cause INTERR 50862 -> replace in later maturity level
			//iLocalRetVal = pat_InitedVarCondImm(ins, blk); // added
			break;
		case m_sets:
			//iLocalRetVal = pat_InitedVarSubImmCond0(ins, blk); // added
			break;
		case m_mov:
			//iLocalRetVal = pat_InitedVarMov(ins);// data-flow tracking required
			break;
		case m_add:
		case m_sub:
			iLocalRetVal = pat_AddSub(ins, blk);
			break;
		case m_call:
			iLocalRetVal = call_ARITH_2const(op, ins, blk);
			if (!iLocalRetVal)
				iLocalRetVal = call_ARITH_0xNN(op, ins, blk);
			break;
		case m_jz:
		case m_jnz:
			iLocalRetVal = pat_XorCondImm(ins, blk);
			break;
		}
		return iLocalRetVal;
	}

struct ida_local InstOptimizer : public optinsn_t
{
#if IDA_SDK_VERSION < 750
	virtual int idaapi func(mblock_t* blk, minsn_t* ins)
#else
	virtual int idaapi func(mblock_t* blk, minsn_t* ins, int optflags)
#endif //IDA_SDK_VERSION < 750
	{
		//visits operands first
		struct ida_local opt_op_visitor_t : mop_visitor_t
		{
			int visit_mop(mop_t *op, const tinfo_t *type, bool is_target)
			{
				if (op->is_insn())
					return OptimizeInsn(op, op->d, blk);
				return 0;
			}
		} ov;
		int res = ins->for_all_ops(ov);

		//Optimize top level insn
		if(!res)
			res += OptimizeInsn(nullptr, ins, blk);

		// If any optimizations were performed...
		if (res) {
			MSG_DO((" --> '%s' (%c) ", ins->dstr(), blk != nullptr ? 'b' : 's' ));
			if (blk) {
				blk->optimize_insn(ins);
				blk->mark_lists_dirty();
				blk->mba->verify(false);
			} else {
				ins->optimize_solo();
			}
			MSG_DO((" --> '%s' at %a\n", ins->dstr(), ins->ea));
		}
		return res;
	}
};
InstOptimizer instOptimizer;


void opt_init()
{
	install_optinsn_handler(&instOptimizer);
}

void opt_done()
{
	remove_optinsn_handler(&instOptimizer);
}
