/*
Initially this source file was made from combined parts of
  https://github.com/RolfRolles/HexRaysDeob Unflattener (https://hex-rays.com/blog/hex-rays-microcode-api-vs-obfuscating-compiler/)
Then have been merged ideas and code from:
  https://www.carbonblack.com/blog/defeating-compiler-level-obfuscations-used-in-apt10-malware/ (https://github.com/carbonblack/HexRaysDeob)
  https://www.virusbulletin.com/virusbulletin/2020/03/vb2019-paper-defeating-apt10-compiler-level-obfuscations/
Modified for flattening used in Finspy malware, mostly for solving problem of multiple flattening loops in one proc

Likely against:
 https://github.com/obfuscator-llvm/obfuscator Control Flow Flattening (https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening)
 (obfuscator-llvm-4.0/lib/Transforms/Obfuscation/Flattening.cpp)
or
 https://github.com/HikariObfuscator/Hikari (Hikari/lib/Transforms/Obfuscation/Flattening.cpp)
 there is a small difference between these two Flattening.cpp. Hikari is more fresh and has some odditional obfuscations
or one more project:
 https://tigress.wtf/flatten.html
*/

#include <set>
#include <map>

#include "warn_off.h"
#include <hexrays.hpp>
#include "warn_on.h"

#include "unflat.h"
#include "opt.h"
#include "helpers.h"

#define MIN_NUM_COMPARISONS 2

// 4 - spam level
// 3 - errors, warnings & more info
// 2 - errors & warnings
// 1 - errors only
// 0 - final results
#define DEBUG_UF 0
#if DEBUG_UF > 3 
#define MSG_UF1(msg_) msg msg_
#define MSG_UF2(msg_) msg msg_
#define MSG_UF3(msg_) msg msg_
#define MSG_UF4(msg_) msg msg_
#include "MicrocodeExplorer.h"
#elif DEBUG_UF > 2
#define MSG_UF1(msg_) msg msg_
#define MSG_UF2(msg_) msg msg_
#define MSG_UF3(msg_) msg msg_
#define MSG_UF4(msg_)
#include "MicrocodeExplorer.h"
#elif DEBUG_UF > 1
#define MSG_UF1(msg_) msg msg_
#define MSG_UF2(msg_) msg msg_
#define MSG_UF3(msg_)
#define MSG_UF4(msg_)
#elif DEBUG_UF > 0 
#define MSG_UF1(msg_) msg msg_
#define MSG_UF2(msg_)
#define MSG_UF3(msg_)
#define MSG_UF4(msg_)
#else
#define MSG_UF1(msg_)
#define MSG_UF2(msg_)
#define MSG_UF3(msg_)
#define MSG_UF4(msg_)
#endif

std::set<ea_t> g_BlackList; // not obfuscated
std::set<ea_t> g_WhiteList; // obfuscated and finally unflattened and printed
std::set<ea_t> g_GrayList;  // obfuscated, but user ask to see original code or unflattening fail
ea_t ufCurr = BADADDR;

bool ufIsInWL(ea_t ea) {
	return g_WhiteList.find(ea) != g_WhiteList.end();
}

void ufAddWL(ea_t ea) {
	if(ea != BADADDR)
		g_WhiteList.insert(ea);
}

bool ufIsInGL(ea_t ea) {
	return g_GrayList.find(ea) != g_GrayList.end();
}

void ufAddGL(ea_t ea) {
	if(ea != BADADDR)
		g_GrayList.insert(ea);
}

void ufDelGL(ea_t ea) {
	g_GrayList.erase(ea);
}

inline THREAD_SAFE bool isUfJc(mcode_t opcode)
{
	return opcode == m_jg || opcode == m_jz || opcode == m_jle || opcode == m_jnz;
}

struct ida_local JZInfo
{
	mop_t *op;
	int nSeen;
	qvector<mop_t *> nums;

	JZInfo() : op(NULL) {};

	// This method determines whether a given function is likely obfuscated. It does this by ensuring that:
	// 1) Some minimum number of comparisons are made against the "comparison variable"
	// 2) The constant values used in the comparisons are sufficiently entropic.
	bool ShouldBlacklist()
	{
		// This check is pretty weak. I thought I could set the minimum number to 
		// 6, but the pattern deobfuscators might eliminate some of them before 
		// this function gets called.
		if (nSeen < MIN_NUM_COMPARISONS) {
			MSG_UF3(("[I] Blacklisting due to lack of JZ/JG comparisons %s (%d < minimum of %d)\n", op->dstr(), nSeen, MIN_NUM_COMPARISONS));
			return true;
		}

		// Count the number of 1-bits in the constant values used for comparison
		int iNumBits = 0;
		int iNumOnes = 0;
		int iNumUsed = 0;
		for (auto num : nums) {
			int64 v = num->signed_value();
			if(abs(v) < 0x10000 ) //often balanced positive and negative values cmp's make false positive
				continue;
			iNumUsed++;
			iNumBits += num->size * 8;
			for (int i = 0; i < num->size * 8; ++i) {
				if (v & (1ULL << i))
					++iNumOnes;
			}
		}

		//at least half of numbers shold be used in entropy calculation
		if(iNumUsed * 2 < nSeen) {
			MSG_UF3(("[I] Lack pseudorandom consts for entropy calc (%d used of %d) \n", iNumUsed, nSeen));
			return true;
		}

		// Compute the percentage of 1-bits. Given that these constants seem to be
		// created pseudorandomly, the percentage should be roughly 1/2.
		int fEntropy = iNumBits == 0 ? 0 : (iNumOnes * 100) / iNumBits;
		MSG_UF3(("[I] %d comparisons of %s: %d numbers, %d bits, %d ones, %d entropy\n", nSeen, op->dstr(), nums.size(), iNumBits, iNumOnes, fEntropy));
		if (fEntropy < 32 || fEntropy > 65) {
			MSG_UF3(("[I] Entropy %d indicates this function is not obfuscated\n", fEntropy));
			return true;
		}
		return false;
	}
};

// This class looks for jz/jg comparisons against constant values. For each
// thing being compared, we use a JZInfo structure to collect the number of 
// times it's been used in a comparison, and a list of the values it was
// compared against.
struct ida_local JZCollector : public minsn_visitor_t
{
	qvector<JZInfo> m_SeenComparisons;
	int m_nMaxJz;
	JZCollector() : m_nMaxJz(-1) {};

	int visit_minsn(void)
	{
		// We're looking for jz/jg.. instructions...
		if (!isUfJc(curins->opcode))
			return 0;

		// ... which compare something against a number ...
		if (curins->r.t != mop_n)
			return 0;
		// the operand should be register or var
		if (!isRegOvar(curins->l.t))
			return 0;

		int iFound = 0;
		mop_t *thisMop = &curins->l;

		int idxFound = 0;
		// Search for the comparison operand in the saved information
		for (auto &sc : m_SeenComparisons) {
			if (thisMop->equal_mops(*sc.op, EQ_IGNSIZE)) {
				sc.nSeen += 1;
				sc.nums.push_back(&curins->r);
				iFound = sc.nSeen;
				break;
			}
			++idxFound;
		}

		// If we didn't find it in the vector, create a new JZInfo structure
		if (!iFound) {
			JZInfo &jz = m_SeenComparisons.push_back();
			jz.op = thisMop;
			jz.nSeen = 1;
			jz.nums.push_back(&curins->r);
			iFound = 1;
		}

		// If the variable we just saw has been used more often than the previous candidate, mark this variable as the new candidate
		if (m_nMaxJz < 0 || iFound > m_SeenComparisons[m_nMaxJz].nSeen)
			m_nMaxJz = idxFound;
		return 0;
	}
#if DEBUG_UF >= 4
	void ShouldBlacklist()
	{
		for (auto i : m_SeenComparisons) {
			i.ShouldBlacklist();
		}
	}
#endif
};

// This class is used to find all variables that have 32/64-bit numeric values assigned to them in the first block
typedef qvector<mop_t*> SeenAssignments_t;
struct ida_local BlockInsnAssignNumberExtractor : public minsn_visitor_t
{
	SeenAssignments_t m_SeenAssignments;
	int visit_minsn()
	{
		// We're looking for MOV(const.4,x) or MOV(const.8,x)
		// stx for case of assign var is a pointer
		if ((curins->opcode != m_mov && curins->opcode != m_stx) || curins->l.t != mop_n || curins->l.size < 4)
			return 0;
		m_SeenAssignments.push_back(&curins->d);
		return 0;
	}
};

// Protected functions might use either one or two, variables for the switch dispatch number. If it uses two, one of them is the "update" variable, whose
// contents will be copied into the "comparison" variable in the first dispatch block. This class is used to locate the "update" variable, by simply looking
// for a variable whose contents are copied into the "comparison" variable, which must have had a number assigned to it in the first block.
struct ida_local SingleAssingFinder : public minsn_visitor_t
{
	mop_t *dst;// We're looking for assignments to this variable
	minsn_t* lastSeenAssign;
	int lastSeenBlk;
	size_t seenCnt;

	SingleAssingFinder(mop_t *dest) : dst(dest), lastSeenAssign(NULL), lastSeenBlk(-1), seenCnt(0) {};

	int visit_minsn(void)
	{
		if ((curins->opcode == m_mov || curins->opcode == m_xdu || curins->opcode == m_xds || curins->opcode == m_and ||
			curins->opcode == m_ldx || curins->opcode == m_stx)
			&& curins->d.equal_mops(*dst, EQ_IGNSIZE)) {// We want copies into our comparison variable
			lastSeenAssign = curins;
			lastSeenBlk = blk->serial;
			seenCnt++;
			MSG_UF3(("[I] %a: SingleAssingFinder: blk %d '%s'\n", curins->ea, lastSeenBlk, curins->dstr()));
		}
		return 0;
	}
};
typedef int32 Key_t;
typedef std::map<Key_t, int> KeyToBlock_t;
typedef intvec_t JTargetBlocks_t;

bool getKeyFromValranges(mblock_t* blk, mop_t *var, Key_t* key)
{
	valrng_t vr;
	uvlr_t v;
	vivl_t vivl(*var); // INTERR 52047 if not mop_r nor mop_S
	if (vivl.defined() && blk->get_valranges(&vr, vivl, VR_EXACT) && vr.cvt_to_single_value(&v)) {
		QASSERT(100508, nullptr == qstrchr(vr.dstr(), '|'));
		*key = (Key_t)v;
		return true;
	}
	return false;
}


// Once we know which variable is the one used for comparisons, look for all jz/jnz instructions that compare a number
// against this variable. This then tells us which number corresponds to which basic block.
//remade for walk only blocks uses compare var (du chain based)
struct ida_local JcMapper
{
	KeyToBlock_t KeyToBlockJz;
	KeyToBlock_t KeyToBlockJle;
	KeyToBlock_t KeyToBlockJg;
	JTargetBlocks_t JTargetBlocks;
	mop_t *m_CompareVar;
	mop_t* m_SubCompareVar;
	mop_t *m_AssignVar;
	int m_DispatchBlockNo;
	int m_FirstBlockNo;
	int lastJnzTrg;
	mbl_array_t* mba;
	JcMapper(mbl_array_t* _mba, mop_t *mc, mop_t* mc_sub, mop_t *ma, int iDispatch, int iFirst) :
		mba(_mba), m_CompareVar(mc), m_SubCompareVar(mc_sub), m_AssignVar(ma), m_DispatchBlockNo(iDispatch), m_FirstBlockNo(iFirst), lastJnzTrg(-1)
	{	};

	bool isCompare(mblock_t* blk)
	{
		minsn_t* insn = blk->tail;
		// We're looking for jg/gle/jz/jnz instructions that compare a number ...
		if (!insn || insn->r.t != mop_n || !isUfJc(insn->opcode) || insn->d.t != mop_b)
			return false;

		// ... against our comparison variable ...
		if (!insn->l.equal_mops(*m_CompareVar, EQ_IGNSIZE)) {
			// ... or, if it's the dispatch block, possibly the assignment variable ...
			mop_t* m_AssignVarAnd = NULL;// consider m_AssignVar & 0x3fffffff case
			if (insn->l.is_insn(m_and))
				m_AssignVarAnd = &insn->l.d->l;
			if (blk->serial != m_DispatchBlockNo ||
				(!insn->l.equal_mops(*m_AssignVar, EQ_IGNSIZE) &&
					(m_AssignVarAnd == NULL || !m_AssignVarAnd->equal_mops(*m_AssignVar, EQ_IGNSIZE)))) {
				// or if it's sub-comparison var, include the map
				if (m_SubCompareVar == NULL || !insn->l.equal_mops(*m_SubCompareVar, EQ_IGNSIZE))
					return false;
			}
		}
		return true;
	}

	bool addTarget(mblock_t* curblk, Key_t keyVal, int dstBlk, KeyToBlock_t* map)
	{
		// If the target block number is dispatcher, the actual number actually points to the block itself
		if (dstBlk == m_DispatchBlockNo) {
			if (map == NULL) // ignore empty ret to dispatch for lastJnz
				return true;
			MSG_UF3(("[I] JZMapper: changed blockNo (dispatcher to the current %d)\n", curblk->serial));
			dstBlk = curblk->serial;
		}

		mblock_t* targBlk = mba->get_mblock(dstBlk);
		if (!map) {
			// jz compare block, was predecessor of this block, can be removed becouse of "always true" for calculated single valrange,
			// so try to restore compare key from valrange
			if (getKeyFromValranges(targBlk, m_CompareVar, &keyVal))
				map = &KeyToBlockJz;
		}
		
		// ignore lastJnz if it pure goto dispatch
		if (!map) {
			minsn_t* tail = targBlk->tail;
			if (tail && tail->opcode == m_goto && tail->l.t == mop_b && tail->l.b == m_DispatchBlockNo && tail == getf_reginsn(targBlk->head))
				return true;
		}
		if (map && (map->count(keyVal) || KeyToBlockJz.count(keyVal))) {
			MSG_UF2(("[W] %a: Ignoring %d (0x%X) at %d -> block ID %d (dupez?)\n", targBlk->start, (int32)keyVal, (int32)keyVal, curblk->serial, dstBlk));
			return false;
		}
		if (map) {
			(*map)[keyVal] = dstBlk;
		} else {
			if (lastJnzTrg != -1) {
				MSG_UF1(("[E] %a -> %a: redefine lastJnzTrg %d with %d->%d\n", curblk->start, targBlk->start, lastJnzTrg, curblk->serial, dstBlk));
			}
			lastJnzTrg = dstBlk;
		}
		JTargetBlocks.add_unique(dstBlk);
		MSG_UF3(("[I] %a: Inserting %d (0x%X) at %d -> %d into %s map (%d/%d)\n",
			curblk->start, (int32)keyVal, (int32)keyVal, curblk->serial, dstBlk,
			map == NULL ? "Ljnz" : map == &KeyToBlockJz ? "jz" : (map == &KeyToBlockJg ? "jg" : "jle"),
			(int)(KeyToBlockJz.size() + KeyToBlockJle.size() + KeyToBlockJg.size()), (int)JTargetBlocks.size()));
		return true;
	}

	bool addCmp(mblock_t* blk) //was visit_minsn
	{
		if (!isCompare(blk))
			return false;
		minsn_t* curins = blk->tail;
		Key_t keyVal = (Key_t)curins->r.nnn->value;

		//check if next compare in chain is exist, but ignore dispatch itself
		bool nextComp = blk->serial + 1 != m_DispatchBlockNo && isCompare(mba->get_mblock(blk->serial + 1));
		bool brComp = curins->d.b != m_DispatchBlockNo && isCompare(mba->get_mblock(curins->d.b));
		if (nextComp && !brComp) {
			if (curins->opcode != m_jnz) {
				QASSERT(100504, curins->opcode == m_jz || curins->opcode == m_jg || curins->opcode == m_jle);
				return addTarget(blk, keyVal, curins->d.b, curins->opcode == m_jz ? &KeyToBlockJz : curins->opcode == m_jg ? &KeyToBlockJg : &KeyToBlockJle);
			}
		} else if (!nextComp && brComp) {
			if (curins->opcode != m_jz) {
				QASSERT(100506, curins->opcode == m_jnz || curins->opcode == m_jg || curins->opcode == m_jle);
				return addTarget(blk, keyVal, blk->serial + 1, curins->opcode == m_jnz ? &KeyToBlockJz : curins->opcode == m_jg ? &KeyToBlockJle : &KeyToBlockJg);
			}
		} else if (!nextComp && !brComp) {
			//we've got last jc in chain, add targets to both lists
			if (curins->opcode == m_jz) {
				bool res = addTarget(blk, keyVal, curins->d.b, &KeyToBlockJz);
				res &= addTarget(blk, keyVal, blk->serial + 1, NULL);
				return res;
			} else if (curins->opcode == m_jnz) {
				bool res = addTarget(blk, keyVal, blk->serial + 1, &KeyToBlockJz);
				res &= addTarget(blk, keyVal, curins->d.b, NULL);
				return res;
			}
			//check if keyVal is beetween maxJle and minJg
			QASSERT(100507, curins->opcode == m_jg || curins->opcode == m_jle);
#if 1
			// resolve both with valranges
			bool res = addTarget(blk, 0, blk->serial + 1, NULL);
			res &= addTarget(blk, 0, curins->d.b, NULL);
			return res;
#else
			if (!KeyToBlockJg.empty() && !KeyToBlockJle.empty()) {
				Key_t maxJle = KeyToBlockJle.rbegin()->first;
				Key_t minJg = KeyToBlockJg.begin()->first;
				if (maxJle < keyVal && keyVal < minJg) {
					bool res = addTarget(blk, keyVal, curins->d.b, curins->opcode == m_jg ? &KeyToBlockJg : &KeyToBlockJle);
					res &= addTarget(blk, keyVal, blk->serial + 1, curins->opcode == m_jg ? &KeyToBlockJle : &KeyToBlockJg);
					return res;
				}
			}
#endif
		} else {
			QASSERT(100505, nextComp && brComp); 
			// shortening checks path, may be skipped
			if (curins->opcode == m_jg || curins->opcode == m_jle) {
				MSG_UF3(("[I] %a: Skip short path, key %d (0x%X) at %d\n", blk->start, (int32)keyVal, (int32)keyVal, blk->serial));
				return true; // not error
			}
		}
		MSG_UF1(("[E] %a: Strange compare in blk %d '%s'\n", blk->start, blk->serial, curins->dstr()));
		return false;
	}

	bool FindComparesInUseChain(int defBlk, mop_t* cmpVar)
	{
		mbl_graph_t* graph = mba->get_graph();
		if (graph->is_du_chain_dirty(GC_REGS_AND_STKVARS)) {
			MSG_UF2(("[W] du chain is dirty\n"));
			return false;
		}
		chain_keeper_t du = graph->get_du(GC_REGS_AND_STKVARS);

		const block_chains_t& bc = du[defBlk];
		const chain_t* ch = bc.get_chain(*cmpVar, cmpVar->size);
		if (ch == NULL) {
			MSG_UF2(("[W] no def/use chain for %s def %d\n", cmpVar->dstr(), defBlk));
			//mba->get_mblock(defBlk)->build_lists(false); // doesnt help
			return false;
		}
		mlist_t list;
		mba->get_mblock(defBlk)->append_use_list(&list, *cmpVar, MUST_ACCESS);

		for (int i = 0; i < ch->size(); i++) {
			int bn = ch->at(i);
			mblock_t* blk = mba->get_mblock(bn);      // block that uses the instruction
			minsn_t* ins = blk->head;

			//walk all instructions in block to be sure our Use of cmpVar has not been redefined before compare 
			for (minsn_t* p = ins; p != NULL && !list.empty(); p = p->next) {
				mlist_t use = blk->build_use_list(*p, MUST_ACCESS); // things used by the insn
				mlist_t def = blk->build_def_list(*p, MUST_ACCESS); // things defined by the insn
				if (list.has_common(use)) {
					if (p != blk->tail || !addCmp(blk)) {
						MSG_UF2(("[W] %a: found strange use cmpVar '%s' at %d\n", p->ea, p->dstr(), bn));
					}
				}
				list.sub(def);
			}
		}
		return true;
	}

	int FindBlockByKey(Key_t key)
	{
		auto itJz = KeyToBlockJz.find(key);
		if (itJz != KeyToBlockJz.end())
			return itJz->second;

		auto itJle = KeyToBlockJle.lower_bound(key);
		if (itJle != KeyToBlockJle.end())
			return itJle->second;

		auto itJg = KeyToBlockJg.upper_bound(key);
		if (itJg != KeyToBlockJg.begin()) {
			itJg--;
			if (itJg->first <= key) // if (itJg->first == key - 1)
				return itJg->second;
		}

		if (lastJnzTrg != -1)
			return lastJnzTrg;
		return -1;
	}
};

#if DEBUG_UF >= 4
struct ida_local KeyMapper : public minsn_visitor_t
{
	std::multimap<int, minsn_t*> keys;
	mop_t* m_CompareVar;
	mop_t* m_SubCompareVar;
	mop_t* m_AssignVar;
	KeyMapper(mop_t* mc, mop_t* mc_sub, mop_t* ma) : 	m_CompareVar(mc), m_SubCompareVar(mc_sub), m_AssignVar(ma) {};

	int visit_minsn(void)
	{
		if (curins->opcode >= m_jnz && curins->opcode <= m_jle) {
			if (curins->r.t == mop_n &&
				(curins->l.equal_mops(*m_CompareVar, EQ_IGNSIZE) || curins->l.equal_mops(*m_AssignVar, EQ_IGNSIZE))) {
				keys.insert(std::pair<int, minsn_t*>((int)curins->r.nnn->value, curins));
			}
			return 0;
		}
		if ((curins->opcode == m_mov || curins->opcode == m_stx) && curins->l.t == mop_n &&
			(curins->d.equal_mops(*m_CompareVar, EQ_IGNSIZE) || curins->d.equal_mops(*m_AssignVar, EQ_IGNSIZE))) {
			keys.insert(std::pair<int, minsn_t*>((int)curins->l.nnn->value, curins));
		}
		return 0;
	}
	void doMap(mbl_array_t* mba)
	{
		MSG_UF4(("[I] %d key compare/assign\n", (int)keys.size()));
		int prev = 0;
		int idx = 0;
		for (auto& k : keys) {
			if (k.first >= 0)
				break;
			if (prev != k.first)
				--idx;
			prev = k.first;
		}

		prev = 0;
		for (auto& k : keys) {
			int cur = k.first;
			if (prev && cur != prev)
				++idx;
			prev = cur;

			qstring s; k.second->print(&s); tag_remove(&s);
			MSG_UF4(("[I] %a: key %d (%d) : %s\n", k.second->ea, k.first, idx, s.c_str()));
#if 0
			mop_t* num = &k.second->r;
			if (k.second->opcode == m_mov)
				num = &k.second->l;
			QASSERT(100503, num->t == mop_n);
			num->nnn->update_value((unsigned int)idx);
#endif
		}

		//doesnt work
		//for (int i = 0; i < mba->qty; ++i)
		//	mba->get_mblock(i)->flags &= ~MBL_VALRANGES;
	}
};
#endif

static array_of_bitsets *ComputeDominators(mbl_array_t *mba)
{
	int iNumBlocks = mba->qty;
	array_of_bitsets domInfo;
	domInfo.resize(iNumBlocks);

	// Per the algorithm, initialize each block to be dominated by every block
	for (auto &bs : domInfo)
		bs.fill_with_ones(iNumBlocks - 1);

	// ... except the first block, which only dominates itself
	domInfo.front().clear();
	domInfo.front().add(0);

	// Now we've got a standard, not-especially-optimized dataflow analysis fixedpoint computation...
	bool bChanged;
	do {
		bChanged = false;
		for (int i = 1; i < iNumBlocks; ++i) {
			bitset_t &bsCurr = domInfo.at(i);
			bitset_t bsBefore(bsCurr);// Grab its current dataflow value and copy it
			mblock_t *blockI = mba->get_mblock(i);// Get that block from the graph

			// Iterate over its predecessors, intersecting their dataflow values against this one's values
			for (int j = 0; j < blockI->npred(); ++j)
				bsCurr.intersect(domInfo.at(blockI->pred(j)));

			bsCurr.add(i);// Then, re-indicate that the block dominates itself
			bChanged |= bsBefore != bsCurr; // If this process changed the dataflow information, we're going to need another iteration
		}
	} while (bChanged);
	

	// The dominator information has been computed. Now we're going to derive some information from it. Namely, the current representation tells us,
	// for each block, which blocks dominate it. We want to know, instead, for each block, which blocks are dominated by it. This is a simple 
	// transformation; for each block b and dominator d, update the information for d to indicate that it dominates b.
	array_of_bitsets *domInfoOutput = new array_of_bitsets;
	domInfoOutput->resize(iNumBlocks);

	for (int i = 0; i < iNumBlocks; ++i) {
		bitset_t &bsCurr = domInfo.at(i);// Get the dominator information for this block (b)
		for (auto it = bsCurr.begin(); it != bsCurr.end(); bsCurr.inc(it))// For each block d that dominates this one, mark that d dominates b
			domInfoOutput->at(*it).add(i);
	}
	return domInfoOutput;
}

struct ida_local CFFlattenInfo
{
	mop_t opAssigned;
	mop_t opCompared;
	mop_t opSubCompared;
	int iFirst, iDispatch;
	JcMapper* jcm;
	intvec_t m_DominatedClusters;
	bool bTrackingFirstBlocks;
	bool bOpAndAssign;
	int64 OpAndImm;
	bool bPtrAssign;

	CFFlattenInfo() : iFirst(-1), iDispatch(-1), bTrackingFirstBlocks(false), bOpAndAssign(false), OpAndImm(0), jcm(NULL), bPtrAssign(false) {}
	~CFFlattenInfo() { if(jcm) delete jcm; }

	// This function finds the "first" block immediately before the control flow flattening dispatcher begins. The logic is simple; start at the beginning
	// of the function, keep moving forward until the next block has more than one predecessor. As it happens, this is where the assignment to the switch 
	// dispatch variable takes place, and that's mostly why we want it.
	mblock_t* GetFirstBlock(mbl_array_t* mba)
	{
		// Initialise iFirst and iDispatch to erroneous values
		iFirst = -1, iDispatch = -1;
		int npred_max = MIN_NUM_COMPARISONS - 1;

		// search for the block with maximum preds
		for (mblock_t* mb = mba->get_mblock(0); mb->nextb != NULL; mb = mb->nextb) {
			//dispatch is a block where jcc chain begins
			if (npred_max < mb->npred() && mb->tail != NULL && is_mcode_jcond(mb->tail->opcode) && mb->tail->r.t == mop_n) {
				if (isRegOvar(mb->tail->l.t) || (mb->tail->l.is_insn(m_and))) {
					npred_max = mb->npred();
					iDispatch = mb->serial;
				}
			}
		}
		// extract the minimum block id (probably it's the "first" block)
		if (iDispatch != -1) {
			iFirst = mba->get_mblock(iDispatch)->pred(0); // it's rough but works mostly
			mblock_t* mbFirst = mba->get_mblock(iFirst);
			if (iFirst >= iDispatch || (mbFirst->tail != NULL && is_mcode_jcond(mbFirst->tail->opcode))) {// or check the minimum number gently
				int iMinNum = iDispatch;
				for (int i = 0; i < mba->get_mblock(iDispatch)->npred(); i++) {
					int iCurr = mba->get_mblock(iDispatch)->pred(i);
					mblock_t* mbCurr = mba->get_mblock(iCurr);
					if (iCurr < iMinNum && !(mbCurr->tail != NULL && is_mcode_jcond(mbCurr->tail->opcode)))
						iMinNum = iCurr;
				}
				if(iMinNum != iDispatch)
					iFirst = iMinNum;
			}
		}

		if (iFirst != -1)
			return mba->get_mblock(iFirst);
		MSG_UF1(("[E] First block could not be found\n"));
		return NULL;
	}

	// This function computes all of the preliminary information needed for unflattening.
	bool GetAssignedAndComparisonVariables(mbl_array_t *mba)
	{
		// Look for the variable that was used in the largest number of jcc comparisons against a constant. This is our "comparison" variable.
		JZCollector jzc;
		mba->for_all_topinsns(jzc);
		if (jzc.m_nMaxJz < 0) {
			MSG_UF3(("[I] No comparisons seen; failed\n"));
			return false;
		}
#if DEBUG_UF >= 4
		jzc.ShouldBlacklist();
#endif

		//it maybe second pass for the same proc already cleared, recalc entropy again
		if (jzc.m_SeenComparisons[jzc.m_nMaxJz].ShouldBlacklist()) {
			int i = 0; //m_nMaxJz may be with low entropy but still exist flattened blocks, looks for more cmps
			for (; i < jzc.m_SeenComparisons.size(); ++i) {
				if (i != jzc.m_nMaxJz && !jzc.m_SeenComparisons[i].ShouldBlacklist()) {
					jzc.m_nMaxJz = i;
					break;
				}
			}
			if(i == jzc.m_SeenComparisons.size())
				return false;
		}

		MSG_UF1(("[I] ----------------------- Unflattening ---------------------------------\n"));
		mblock_t *first = GetFirstBlock(mba); // Find the "first" block in the function, the one immediately before the control flow switch.
		if (!first)
			return false;
		MSG_UF1(("[I] found first block %d (ea=%a), dispatcher %d (ea=%a) \n", this->iFirst, mba->get_mblock(this->iFirst)->start, this->iDispatch, mba->get_mblock(this->iDispatch)->start));

		mop_t *opMax = jzc.m_SeenComparisons[jzc.m_nMaxJz].op;// opMax is our "comparison" variable used in the control flow switch.
		MSG_UF3(("[I] Comparison variable: %s\n", opMax->dstr()));
		// if there are nested control flow switches, we have to identify the opMax of the dispatcher
		mblock_t* mb_dispatch = mba->get_mblock(this->iDispatch);
		mop_t* opMaxMoreLikely = NULL;
		mop_t* opMaxSub = NULL;
		for (auto const& sc : jzc.m_SeenComparisons) {
			if (sc.nSeen >= MIN_NUM_COMPARISONS) {
				mop_t* op = sc.op;
				//mlist_t ml;
				//mb_dispatch->append_use_list(&ml, *op, MUST_ACCESS);
				opMaxMoreLikely = opMaxSub = NULL;
				for (minsn_t* p = mb_dispatch->tail; p != NULL; p = p->prev) {
					//mlist_t def = mb_dispatch->build_def_list(*p, MAY_ACCESS | FULL_XDSU);
					//if ((def.includes(ml) || 
					if (isRegOvar(p->l.t) && p->l.equal_mops(*op, EQ_IGNSIZE)) {
						if (isUfJc(p->opcode))
							opMaxMoreLikely = op;
						else if (opMaxMoreLikely != NULL && p->opcode == m_mov && isRegOvar(p->d.t))
							opMaxSub = &p->d;
					} else if (p->opcode == m_and && isRegOvar(p->d.t) && p->d.equal_mops(*op, EQ_IGNSIZE))
						opMaxMoreLikely = op;
				}
				if (opMaxMoreLikely != NULL)
					break;
			}
		}
		if (opMaxMoreLikely != NULL && !opMax->equal_mops(*opMaxMoreLikely, EQ_IGNSIZE)) {
			qstring tmpo; opMax->print(&tmpo); tag_remove(&tmpo);
			qstring tmpn; opMaxMoreLikely->print(&tmpn); tag_remove(&tmpn);
			MSG_UF3(("[I] Comparison variable renewed from %s to %s (probably nested control flow dispatchers)\n", tmpo.c_str(), tmpn.c_str()));
			opMax = opMaxMoreLikely;
		}

		// Get all variables assigned to numbers in the first block. If we find the comparison variable in there, then the assignment and comparison 
		// variables are the same. If we don't, then there are two separate variables. The "first" block sometimes doesn't contain the assignment to
		// the comparison variable. So I modified to trace back from the block to the beginning (called first blocks)
		BlockInsnAssignNumberExtractor fbe;
		bool bFound = false;
		int assingBlk = iFirst;
		for (mblock_t* mb = first; mb->prevb != NULL; mb = mb->prevb) {
			mb->for_all_insns(fbe);
			for (auto as : fbe.m_SeenAssignments) {
				if (opMax->equal_mops(*as, EQ_IGNSIZE)) {
					assingBlk = mb->serial;
					bFound = true;// Was the comparison variable assigned a number in the first block?
					break;
				}
			}
			if (bFound)
				break;
		}

		mop_t *localOpAssigned = NULL; // This is the "assignment" variable, whose value is updated by the switch case code
		
		if (bFound && mb_dispatch->head != NULL && mb_dispatch->head->opcode != m_and) {
			// If the "comparison" variable was assigned a number in the first block, then the function is only using one variable, not two, for dispatch.
			localOpAssigned = opMax;
		}  else {
			// Otherwise, look for assignments of one of the variables assigned a number in the first block to the comparison variable
			// For all variables assigned a number in the first block, find all assignments throughout the function to the comparison variable
			SingleAssingFinder saf(opMax);
			mba->for_all_topinsns(saf);
			if (saf.seenCnt != 1 || saf.lastSeenBlk == -1) {// There should have only been one of them; is that true?
				MSG_UF1(("[E] Comparison var %s was assigned %d times, not 1 as expected\n", opMax->dstr(), saf.seenCnt));
				return false;
			}

			// If only one variable (X) assigned a number in the first block was ever copied into the comparison variable, then X is our "assignment" variable.
			localOpAssigned = &saf.lastSeenAssign->l;
			if (saf.lastSeenAssign->opcode == m_ldx) {
				localOpAssigned = &saf.lastSeenAssign->r; //off is in 'r' part of m_ldx
				this->bPtrAssign = true;
			}
			assingBlk = saf.lastSeenBlk;
			if (saf.lastSeenAssign->opcode == m_and && saf.lastSeenAssign->r.t == mop_n && saf.lastSeenAssign->r.nnn->value != 0) {
				this->bOpAndAssign = true;
				this->OpAndImm = saf.lastSeenAssign->r.nnn->value;
				MSG_UF3(("[I] Update variable '%s' is assigned by AND instruction with %x\n", localOpAssigned->dstr(), this->OpAndImm));
			}

#if DEBUG_UF >= 2
			// Verify the number that was assigned to the assignment variable in the first block.
			bool found = false;
			for (auto as : fbe.m_SeenAssignments) {
				if (localOpAssigned->equal_mops(*as, EQ_IGNSIZE)) {
					found = true;
					break;
				}
			}
			if (!bFound) {
				MSG_UF2(("[W] ??? couldn't find any direct const assignment to assignment variable %s. Hope FindNumericDefBackwards will do it.\n", localOpAssigned->dstr()));
			}
#endif
		}
		// Make copies of the comparison and assignment variables so we don't run into liveness issues
		opCompared = *opMax;
		opAssigned = *localOpAssigned;
		if (opMaxSub != NULL)
			opSubCompared = *opMaxSub;

#if DEBUG_UF >= 1
		qstring tmpc; opCompared.print(&tmpc); tag_remove(&tmpc);
		qstring tmpa; opAssigned.print(&tmpa); tag_remove(&tmpa);
		if (opMaxSub == NULL) {
			MSG_UF1(("[I] comparison variable: %s, update variable: %s %s\n", tmpc.c_str(), tmpa.c_str(), bPtrAssign ? "(ptr)" : ""));
		} else {
			qstring tmp; opSubCompared.print(&tmp); tag_remove(&tmp);
			MSG_UF1(("[I] comparison variable: %s, update variable: %s, sub comparison variable: %s\n", tmpc.c_str(), tmpa.c_str(), tmp.c_str()));
		}
#endif

#if DEBUG_UF >= 4
		KeyMapper km(&opCompared, &opSubCompared, localOpAssigned);
		mba->for_all_topinsns(km);
		km.doMap(mba);
#endif

		// Extract the key-to-block mapping for each Jcc against the comparison variable
		jcm = new JcMapper(mba, &opCompared, &opSubCompared, localOpAssigned, iDispatch, iFirst);
		if (assingBlk == iDispatch) {// dispatch block may compare assignVar instead of cmpVar
			jcm->addCmp(mba->get_mblock(iDispatch)); // may produce duplicates
		}
		if (jcm->FindComparesInUseChain(assingBlk, &opCompared)) {
			if(opSubCompared.t != mop_z)
				jcm->FindComparesInUseChain(iDispatch, &opSubCompared);
		} else {
			// ida can lost def-use chain for stack vars. Why??? (example: 782192b540ce0746cc058b3871e19284)
			// try old way, enum all blocks
			MSG_UF3(("[I] old way of Jc targets resolving, results may be incorrect in case of multiple flattening\n"));
			for (int i = 1 ; i < mba->qty - 1; ++i) {
				jcm->addCmp(mba->get_mblock(i));
			}
		}
		if (jcm->JTargetBlocks.size() < MIN_NUM_COMPARISONS) {
			MSG_UF1(("[E] too few jc targets was found\n"));
			return false;
		}

		array_of_bitsets *ab = ComputeDominators(mba);
		// Compute some more information from the dominators. Basically, once the control flow dispatch switch has transferred
		// control to the function's code, there might be multiple basic blocks that can execute before control goes back to the
		// switch statement. For all of those blocks, we want to know the "first" block as part of that region of the graph, 
		// i.e., the one targeted by a jump out of the control flow dispatch switch.

		// array mapping each basic block to the block that dominates it and was targeted by the control flow switch.
		m_DominatedClusters.resize(mba->qty, -1);
		for (auto i : jcm->JTargetBlocks) {
			// For each block dominated by this control flow switch target, mark that this block its the beginning of its cluster.
			for (auto it = ab->at(i).begin(); it != ab->at(i).end(); ab->at(i).inc(it))
				m_DominatedClusters[*it] = i;
		}
		delete ab;

		// Check if the first blocks may contain block update variables for flattened if-else statement blocks
		if (this->iFirst > 2 && mba->get_mblock(iFirst - 2)->tail != NULL && is_mcode_jcond(mba->get_mblock(iFirst - 2)->tail->opcode))
			this->bTrackingFirstBlocks = true;

		return true;
	}
};

struct ida_local MovInfo
{
	mop_t *opCopy;
	minsn_t *insMov;
	int iBlock;
};
typedef qvector<MovInfo> MovChain;

// For a block that ends in a conditional jump, extract the integer block numbers for the "taken" and "not taken" cases.
bool getJccDests(mblock_t *blk, mblock_t *&endsWithJcc, int &jccDest, int &jccFallthrough)
{
	if (!blk->tail || !is_mcode_jcond(blk->tail->opcode))
		return false;
	endsWithJcc = blk;
	QASSERT(100510, blk->tail->d.t == mop_b);
	jccDest = blk->tail->d.b;
	jccFallthrough = blk->serial + 1;
	return true;
}

// For a block with two predecessors, figure out if one of them ends in a jcc instruction. 
// Return the block that ends in a jcc and the one that doesn't. Also return the integer numbers of those blocks.
bool SplitMblocksByJccEnding(mblock_t *pred1, mblock_t *pred2, mblock_t *&endsWithJcc, mblock_t *&nonJcc, int &jccDest, int &jccFallthrough)
{
	endsWithJcc = NULL;
	nonJcc = NULL;
	// Check if the first block ends with jcc. Make sure the second one doesn't also.
	if (getJccDests(pred1, endsWithJcc, jccDest, jccFallthrough)) {
		if (pred2->tail && is_mcode_jcond(pred2->tail->opcode))
			return false;
		nonJcc = pred2;
	} else {
		// Otherwise, check if the second block ends with jcc. Make sure the first one doesn't also.
		if (!getJccDests(pred2, endsWithJcc, jccDest, jccFallthrough))
			return false;
		nonJcc = pred1;
	}
	return true;
}

void AppendGoto(mblock_t *blk, int iBlockDest)
{
	minsn_t* newGoto;
	if (blk->tail)
		newGoto = new minsn_t(blk->tail->ea);
	else
		newGoto = new minsn_t(blk->start);
	newGoto->opcode = m_goto;
	newGoto->l.make_blkref(iBlockDest);
	blk->insert_into_block(newGoto, blk->tail);
	MSG_UF3(("[I] %a: AppendGoto %d -> %d\n", blk->start, blk->serial, iBlockDest));
}

#if IDA_SDK_VERSION < 760
void DeleteBlock(mblock_t *mb)
{
	mbl_array_t *mba = mb->mba;
	for (int j = 0; j < mb->nsucc(); ++j)
		mba->get_mblock(mb->succ(j))->predset.del(mb->serial);

	mb->succset.clear();
	mb->type = BLT_NONE;

	uint32 cnt = 0;
	minsn_t *pCurr = mb->head, *pNext = NULL;
	while (pCurr != NULL) {
		pNext = pCurr->next;
		if(!pCurr->is_assert())
			++cnt;
		delete pCurr;
		pCurr = pNext;
	}
	mb->head = NULL;
	mb->tail = NULL;
	MSG_UF3(("[I] %a: DeleteBlock %d (%d insns)\n", mb->start, mb->serial, cnt));
}

// The goto-to-goto elimination and unflattening remove edges in the control flow graph.
// As a result, certain blocks might no longer be reachable anymore in the graph.
// Thus, they can be deleted with no ill-effects.
// In theory, we could wait for Hex-Rays to remove these blocks, which it eventually will, sometime after MMAT_GLBOPT2. 
// Originally, I just let Hex-Rays remove the blocks. However, it turned out that the blocks were removed too late,
// which hampered other optimizations that Hex-Rays otherwise would have been able to perform had the blocks been
// eliminated earlier. Thus, I wrote this function to remove the unreachable blocks immediately after unflattening,
// which allowed the aforementioned simplifications to happen.
//
// At the time of writing, I'm still coordinating with Hex-Rays to see if I can
// make use of internal decompiler machinery to perform elimination. If I can,
// we'll use that instead of this function. For now, we prune manually.
int PruneUnreachable(mbl_array_t *mba)
{
	bitset_t visited;

	// This is a standard worklist-based algorithm. This list keeps track of reachable predecessors yet-to-be-visited.
	// Initialize the worklist to block #0, which always denotes the entry block in an mbl_array_t.
	intvec_t worklist;
	worklist.push_back(0);
	while (!worklist.empty()) {
		int iCurr = worklist.back();
		worklist.pop_back();
		if (visited.has(iCurr))
			continue;
		visited.add(iCurr);
		for (auto iSucc : mba->get_mblock(iCurr)->succset)
			worklist.push_back(iSucc);
	}
	
	qvector<mblock_t*> brem;
	for (int i = 0; i < mba->qty - 1; ++i) {
		if (!visited.has(i)) {
			// If so, delete the instructions on the block and remove any outgoing edges.
			mblock_t* blk = mba->get_mblock(i);
			brem.push_back(blk);
			DeleteBlock(blk);
		}
	}
	for (auto b : brem)
		mba->remove_block(b); //causes blocks renumbering, so after this point all my 'bb->idx' are incorrect

	return (int)brem.size();
}
#endif

#define NO_GOTO -1
// This function eliminates transfers to blocks with a single goto on them.
// Either if a given block has a goto at the end of it, where the destination is a block with a single goto on it, 
// or if the block doesn't end in a goto, but simply falls through to a block with a single goto on it.
// Also, this process happens recursively; i.e., if A goes to B, and B goes to C, and C goes to D, 
// then after we've done our tranformations, A will go to D.
//bes: also dial with jc blocks
bool RemoveSingleGotos(mbl_array_t* mba)
{
	intvec_t goto_targets;
	goto_targets.resize(mba->qty);
	for (int i = 0; i < mba->qty; ++i) {
		goto_targets[i] = NO_GOTO;
		mblock_t* b = mba->get_mblock(i);
		minsn_t* m2 = getf_reginsn(b->head);
		if (m2 == NULL || m2->opcode != m_goto)// Is the first non-assert instruction a goto?
			continue;
		QASSERT(100501, m2->l.t == mop_b);
		goto_targets[i] = m2->l.b;
	}

	int iRetVal = 0;
	for (int i = 0; i < mba->qty; ++i) {
		mblock_t* blk = mba->get_mblock(i);

		const int nsucc = blk->nsucc();
		if (nsucc < 1 || nsucc > 2 || blk->is_call_block())
			continue;

		minsn_t* mgoto = blk->tail;
		if (mgoto == NULL)
			continue;

		int iOriginalGotoTarget;
		if (mgoto->opcode == m_goto) {// If the last instruction was a goto, get the information from there.
			iOriginalGotoTarget = mgoto->l.b;
		} else if (is_mcode_jcond(mgoto->opcode)) {
			iOriginalGotoTarget = mgoto->d.b;
		} else {
			iOriginalGotoTarget = blk->succ(0);// Otherwise, take the number of the only successor block.
		}

		// Now, we determine if the target was a single-goto block.
		int iGotoTarget = iOriginalGotoTarget;
		bool bShouldReplace = false;
		intvec_t visited;
		while (true) {
			if (!visited.add_unique(iGotoTarget)) {
				bShouldReplace = false;
				break;
			}
			if (goto_targets[iGotoTarget] == NO_GOTO) // Once we find the first non-single-goto block, stop.
				break;
			bShouldReplace = true;
			iGotoTarget = goto_targets[iGotoTarget];// Now check: did the single-goto block also target a single-goto block?
		}
		if (!bShouldReplace)
			continue;

		// If the block had a goto, overwrite its block destination.
		if (mgoto->opcode == m_goto) {
			MSG_UF4(("[I] %a: RemoveSingleGotos replace %d -> %d in '%s'\n", blk->start, blk->serial, iGotoTarget, mgoto->dstr()));
			mgoto->l.b = iGotoTarget;
		} else if (is_mcode_jcond(mgoto->opcode)) {
			MSG_UF4(("[I] %a: RemoveSingleGotos replace %d -> %d in '%s'\n", blk->start, blk->serial, iGotoTarget, mgoto->dstr()));
			mgoto->d.b = iGotoTarget;
		} else {
			// Otherwise, add a goto onto the block. You might think you could skip
			// this step and just change the successor information, but you'll get an INTERR if you do.
			AppendGoto(blk, iGotoTarget);
		}
		blk->succset.del(iOriginalGotoTarget);
		blk->succset.add(iGotoTarget);
		mba->get_mblock(iGotoTarget)->predset.add(blk->serial);
		mba->get_mblock(iOriginalGotoTarget)->predset.del(blk->serial);
		++iRetVal;
	}
	if (iRetVal) {
		MSG_UF3(("[I] Removed %d vacuous GOTOs\n", iRetVal));
#if IDA_SDK_VERSION < 760
		PruneUnreachable(mba);
		mba->dump_mba(true, "[hrt] after RemoveSingleGotos");
#else
		mba->dump_mba(true, "[hrt] after RemoveSingleGotos");
		// merge_blocks (combine_blocks) or remove_empty_and_unreachable_blocks produce itsown dumps
		mba->merge_blocks(); //mba->remove_empty_and_unreachable_blocks();
#endif //IDA_SDK_VERSION < 760
	}
	return iRetVal != 0;
}

// The "deferred graph modifier" records changes that the client wishes to make to a given graph, but does not apply them immediately. Weird things could
// happen if we were to modify a graph while we were iterating over it, so save the modifications until we're done iterating over the graph.
// Last (exit) block of mba may be shifted by CopyMblock, so if 'dest' is current 'exit' block replace it with '-1' value
// Later on applying replace '-1' to actual 'exit' block number
struct ida_local DeferredGraphModifier
{
	mbl_array_t* mba;
	qvector<std::pair<int, int> > m_RemoveEdges;
	qvector<std::pair<int, int> > m_AddEdges;

	DeferredGraphModifier(mbl_array_t* _mba) : mba(_mba) {}

	void Remove(int src, int dest) {
		if (dest == mba->qty - 1)
			dest = -1; 
		MSG_UF3(("[I] DGM Del %d->%d\n", src, dest));
		auto it = m_AddEdges.find(std::pair<int, int>(src, dest));
		if (it != m_AddEdges.end()) {
			m_AddEdges.erase(it);
		} else {
			m_RemoveEdges.push_back(std::pair<int, int>(src, dest));
		}
	}

	void Add(int src, int dest) {
		if (dest == mba->qty - 1)
			dest = -1;
		MSG_UF3(("[I] DGM Add %d->%d\n", src, dest));
		m_AddEdges.push_back(std::pair<int, int>(src, dest));
	}

	void Replace(int src, int oldDest, int newDest) {
		Remove(src, oldDest);
		Add(src, newDest);
	}

	bool getDest(int src, int* dst) { //FIXME: there may be more then one dest
		for (auto p = m_AddEdges.begin(); p != m_AddEdges.end(); ++p) {
			if (p->first == src) {
				*dst = p->second;
				if(*dst == -1)
					*dst = mba->qty - 1;
				return true;
			}
		}
		return false;
	}

	mblock_t* GetBlk(int serial) {
		if (serial == -1)
			serial = mba->qty - 1;
		return mba->get_mblock(serial);
	}

	// Apply the planned changes to the graph
	int Apply()
	{
		int iChanged = 0;
		for (auto re : m_RemoveEdges) {
			mblock_t *mSrc = mba->get_mblock(re.first);
			mblock_t *mDst = GetBlk(re.second);
			// Remove the source as a predecessor for dest, and vice versa
			mSrc->succset.del(mDst->serial);
			mDst->predset.del(mSrc->serial);
			MSG_UF3(("[I] DGM Removed edge %d->%d (%a->%a)\n", mSrc->serial, mDst->serial, mSrc->start, mDst->start));
			++iChanged;
		}

		// Iterate through the edges slated for addition
		for (auto ae : m_AddEdges) {
			mblock_t *mSrc = mba->get_mblock(ae.first);
			mblock_t *mDst = GetBlk(ae.second);
			// Add the source as a predecessor for dest, and vice versa
			MSG_UF3(("[I] DGM Added edge %d->%d (%a->%a)\n", mSrc->serial, mDst->serial, mSrc->start, mDst->start));
			mDst->predset.add_unique(mSrc->serial);
			if (!mSrc->succset.has(mDst->serial)) {
				mSrc->succset.add(mDst->serial);
			} else {
				// The case when jc target is next block (hexrays raize INTERR(50860) becise outs.add_unique(tail->d.b); 
				// or INTERR(50856) when I trying also use add_unique (one out edge instead two equal)
				if (mSrc->tail && is_mcode_jcond(mSrc->tail->opcode)) {
					MSG_UF3(("[I] %a: DGM Blk %d Erasing '%s'\n", mSrc->tail->ea, mSrc->serial, mSrc->tail->dstr()));
					mSrc->make_nop(mSrc->tail);
					mSrc->type = BLT_1WAY;
				} else {
					MSG_UF1(("[E] DGM Unhandled duplicate successor  %d->%d (%a->%a)\n", mSrc->serial, mDst->serial, mSrc->start, mDst->start));
				}
			}
			++iChanged;
		}
		return iChanged;
	}

	// Either change the destination of an existing goto, or add a new goto onto the end of the block to the destination. 
	// Also, plan to modify the graph structure later to reflect these changes.
	bool ChangeGoto(mblock_t *blk, int iOld, int iNew)
	{
		MSG_UF3(("[I] %a: ChangeGoto %d -> %d (was %d)\n", blk->start, blk->serial, iNew, iOld));
		if (blk->tail != NULL && is_mcode_jcond(blk->tail->opcode))
			blk->tail->d.b = iNew;
		else if (blk->tail && blk->tail->opcode == m_goto)
			blk->tail->l.b = iNew;
		else
			AppendGoto(blk, iNew);

		if (iOld != -1)
			Replace(blk->serial, iOld, iNew);
		else
			Add(blk->serial, iNew);
		blk->mark_lists_dirty();
		return true;
	}
};

// dirty hack to append reg or stkvar into mlist
bool mop2list(mop_t* mop, mlist_t* ml, mbl_array_t* mba)
{
	if (!isRegOvar(mop->t))
		return false;
	gco_info_t gko;
	gko.size = ea_size;
	if (mop->t == mop_r) {
		gko.flags = GCO_REG | GCO_USE;
		gko.regnum = mop->r;
	} else {
		gko.flags = GCO_STK | GCO_USE;
		gko.stkoff = mop->s->off;
	}
	gko.append_to_list(ml, mba);
	return true;
}
struct ida_local CFUnflattener
{
	CFFlattenInfo cfi;
	MovChain m_DeferredErasuresLocal;
	//MovChain m_PerformedErasuresGlobal

	// Find the block that dominates iDispPred, and which is one of the targets of the control flow flattening switch.
	mblock_t *GetDominatedClusterHead(mbl_array_t *mba, int iDispPred, int &iClusterHead)
	{
		mblock_t *mbClusterHead = NULL;
		// Find the block that is targeted by the dispatcher, and that dominates the block we're currently looking at. 
		// This logic won't work for the first block (since it wasn't targeted by the control 
		// flow dispatch switch, so it doesn't have an entry in the dominated cluster information), so we special-case it.
		if (iDispPred == cfi.iFirst) {
			//iClusterHead = cfi.iFirst;
			iClusterHead = 1; // to trace back until the start
			mbClusterHead = mba->get_mblock(iClusterHead);

		} else {
			// If it wasn't the first block, look up its cluster head block 
			iClusterHead = cfi.m_DominatedClusters[iDispPred];
			if (iClusterHead < 0) {
				return NULL;
			}
			mbClusterHead = mba->get_mblock(iClusterHead);
		}
		return mbClusterHead;
	}

	minsn_t* my_find_def_backwards_hacked(mblock_t* mb, mlist_t& ml, minsn_t* start)
	{
		for (minsn_t* p = start != NULL ? start : mb->tail; p != NULL; p = p->prev) {
			if (p->opcode == m_stx) {
				// special case for "*var = smth" assingnment, consider as definition of var when bPtrAssign
				// build_def_list returns in that case nothing for MUST_ACCESS and everything for MAY_ACCESS
				mlist_t def;
				if (mop2list(&p->d, &def, mb->mba)) {
					if (def.includes(ml))
						return p;
				}
			} else {
				mlist_t def = mb->build_def_list(*p, MUST_ACCESS | FULL_XDSU);//may-list includes all aliasable memory in case of indirect stx
				if (def.includes(ml))
					return p;
			}
		}
		return NULL;
	}

	// A wrapper around my_find_def_backwards. It is extended in the following ways:
	// * If my_find_def_backwards identifies a definition of the variable "op" which is an assignment from another variable,
	//   this function then continues looking for numeric assignments to that var (and recursively so, if that var is assigned from another var).
	// * It keeps a list of all the assignment instructions it finds along the way, storing them in the vector passed as the "chain" argument.
	// * It has support for traversing more than one basic block in a graph, if the bRecursive argument is true. 
	// * It won't traverse into blocks with more than one successor if bAllowMultiSuccs is false. 
	// * In any case, it will never traverse past the block numbered iBlockStop, if that parameter is non-negative.
	bool FindNumericDefBackwards(mblock_t* blk, mop_t* op, mop_t*& opNum, MovChain& chain, bool bRecursive, bool bAllowMultiSuccs, int iBlockStop)
	{
		mbl_array_t* mba = blk->mba;
		mlist_t ml;

		if (!InsertOp(blk, ml, op))
			return false;

		// Start from the end of the block. This variable gets updated when a copy is encountered, so that subsequent searches start from the right place.
		minsn_t* mStart = NULL;
		bool bFirst = true;
		do {
			minsn_t* mDef;
			if(bFirst && cfi.bPtrAssign) // use hacked version only at the first assignment in a chain
				mDef = my_find_def_backwards_hacked(blk, ml, mStart);
			else
				mDef = my_find_def_backwards(blk, ml, mStart);
			if (mDef != NULL) {
				// Ensure that it's kind of a mov instruction we want
				if (mDef->opcode != m_mov && mDef->opcode != m_xdu && mDef->opcode != m_xds && 
					!(bFirst && cfi.bPtrAssign && mDef->opcode == m_stx)) {
					MSG_UF1(("[E] %a: FindNumericDef found '%s' in blk %d\n", mDef->ea, mDef->dstr(), blk->serial));
					return false;
				}
				bFirst = false;
				// Now that we found a mov, add it to the chain.
				MovInfo& mi = chain.push_back();
				mi.opCopy = &mDef->l;
				mi.iBlock = blk->serial;
				mi.insMov = mDef;
				if (mDef->l.t == mop_n) {// Was it a numeric assignment?
					opNum = &mDef->l;
					return true;
				}

				// Otherwise, if it was not a numeric assignment, then try to track whatever was assigned to it. 
				ml.clear();
				if (cfi.bPtrAssign && mDef->l.t == mop_a) { //is it addr of?
					// InsertOp() doesnt work in that case becouse &var use all memory
					// try dirty hack
					if(!mop2list(mDef->l.a, &ml, mba))
						return false;
				} else {
					// This can only succeed if the thing that was assigned was a register or stack variable.
					if (!InsertOp(blk, ml, &mDef->l))
						return false;
				}

				// Try to start tracking the other thing...
				mStart = mDef;// Resume the search from the assignment instruction we just processed.
				MSG_UF3(("[I] %a: Blk %d FindNumericDef now tracking '%s'\n", mDef->ea, blk->serial, mDef->l.dstr()));
			} else {
				// Otherwise, we did not find a definition of the currently-tracked variable on this block. Try to continue if the parameters allow.
				// If recursion was disallowed, or we reached the topmost legal block, then quit.
				if (!bRecursive || blk->serial == iBlockStop)
					return false;

				// If there is more than one predecessor for this block, we don't know which one to follow, so stop.
				if (blk->npred() != 1)
					return false;

				// Recurse into sole predecessor block
				int iPred = blk->pred(0);
				blk = mba->get_mblock(iPred);

				// If the predecessor has more than one successor, check to see whether the arguments allow that.
				if (!bAllowMultiSuccs && blk->nsucc() != 1)
					return false;

				// Resume the search at the end of the new block.
				mStart = NULL;
			}
		} while (true);
		return false;
	}

	// This function attempts to locate the numeric assignment to a given variable "what" starting from the end of the block "mb".
	// It follows definitions backwards, even across blocks, until it either reaches the block "mbClusterHead", or, 
	// if the boolean "bAllowMultiSuccs" is false, it will stop the first time it reaches a block with more than one successor.
	// If it finds an assignment whose source is a stack variable, then it will not be able to continue in the backwards direction,
	// because intervening memory writes will make the definition information useless. 
	int FindBlockTargetOrLastCopy(mblock_t *mb, mblock_t *mbClusterHead, mop_t *what, bool bAllowMultiSuccs, bool bRecursive)
	{
		int iClusterHead = mbClusterHead->serial;
		MovChain local;
		mop_t *opNum = NULL;
		// Search backwards looking for a numeric assignment to "what". We may or may not find a numeric assignment, 
		// but we might find intervening assignments where "what" is copied from other variables.
		bool bFound = FindNumericDefBackwards(mb, what, opNum, local, bRecursive, bAllowMultiSuccs, iClusterHead);
		if (local.empty())
			return -1;

		// Copy the assignment chain into the erasures vector, so we can later  remove them if our analysis succeeds.
		m_DeferredErasuresLocal.insert(m_DeferredErasuresLocal.end(), local.begin(), local.end());

		if (bFound) {
			// Look up the integer number of the block corresponding to that value.
			int64 theImm = opNum->nnn->value;
			if (cfi.bOpAndAssign) // m_and assignment with immediate value
				theImm &= cfi.OpAndImm;
			int iDestNo = cfi.jcm->FindBlockByKey((Key_t)theImm);
			if (iDestNo > 0) {
				if (cfi.bOpAndAssign) {
					MSG_UF3(("[I] Target resolved: %d (cluster head %d) -> %d (%x & %x = %x)\n", mb->serial, iClusterHead, iDestNo, opNum->nnn->value, cfi.OpAndImm, theImm));
				} else {
					MSG_UF3(("[I] Target resolved: %d (cluster head %d) -> %d (%d (0x%X))\n", mb->serial, iClusterHead, iDestNo, (int)theImm, (int)theImm));
				}
				return iDestNo;
			}
			MSG_UF1(("[E] %a: Block %d assign unknown key %d (0x%X)\n", mb->start, mb->serial, (int)theImm, (int)theImm));
		}
		return -1;
	}

	// This function is used for unflattening constructs that have two successors, such as if statements. Given a block that assigns to the assignment variable
	// that has two predecessors, analyze each of the predecessors looking for numeric assignments by calling the previous function.
	bool FindTargets4TwoPreds(mblock_t *mb, mblock_t *mbClusterHead, mop_t *opCopy, mblock_t*& endsWithJcc, mblock_t *&nonJcc, int &actualDfltTarget, int &actualJccTarget)
	{
		if (mb->npred() != 2)
			return false;
		mbl_array_t* mba = mb->mba;
		mblock_t *pred1 = mba->get_mblock(mb->pred(0));
		mblock_t *pred2 = mba->get_mblock(mb->pred(1));
		int jccDest = -1;
		int jccFallthrough = -1;

		// Given the two predecessors, find the block with the conditional jump at the end of it (store the block in "endsWithJcc") and the one without
		// (store it in nonJcc). Also find the block number of the jcc target, and the block number of the jcc fallthrough (i.e., the block number of nonJcc).
		if (!SplitMblocksByJccEnding(pred1, pred2, endsWithJcc, nonJcc, jccDest, jccFallthrough)) {
			MSG_UF3(("[I] Block %d w/preds %d, %d did not have one predecessor ending in jcc, one without\n", mb->serial, pred1->serial, pred2->serial));
			return false;
		}

		// Sanity checking the structure of the graph. The nonJcc block should only have one incoming edge...
		if (nonJcc->npred() != 1) {
			MSG_UF3(("[I] Block %d w/preds %d, %d, non-jcc pred %d had %d predecessors (not 1)\n", mb->serial, pred1->serial, pred2->serial, nonJcc->serial, nonJcc->npred()));
			return false;
		}

		// ... namely, from the block ending with the jcc.
		if (nonJcc->pred(0) != endsWithJcc->serial) {
			MSG_UF3(("[I] Block %d w/preds %d, %d, non-jcc pred %d did not have the other as its predecessor\n", mb->serial, pred1->serial, pred2->serial, nonJcc->serial));
			return false;
		}

		// Call the previous function to locate the numeric definition of the 
		// variable that is used to update the assignment variable if the jcc is not taken.
		actualDfltTarget = FindBlockTargetOrLastCopy(endsWithJcc, mbClusterHead, opCopy, false, true);
		if (actualDfltTarget > 0) {
			// ... then do the same thing when the jcc is not taken.
			actualJccTarget = FindBlockTargetOrLastCopy(nonJcc, mbClusterHead, opCopy, true, true);
			// If that succeeded, great! We can unflatten this two-way block.
			if (actualJccTarget > 0)
				return true;
		}
		return false;
	}

	void CopyMinsns(mblock_t* src, mblock_t* dst)
	{
		// allow copying to an empty block or appending to a block without a conditional jump
		QASSERT(100502, dst->tail == NULL || !is_mcode_jcond(dst->tail->opcode));
		if (dst->tail && dst->tail->opcode == m_goto) {
			MSG_UF3(("[I] CopyMinsns %d -> %d: remove '%s' at dst\n", src->serial, dst->serial, dst->tail->dstr()));
			minsn_t* delme = dst->tail;
			dst->remove_from_block(delme);
			delete delme;
		}
		minsn_t* insn = src->head;
		do {
			bool skip = false;
			//skip erasable instructions
			for (auto erase : m_DeferredErasuresLocal) {
				if (erase.iBlock == src->serial && erase.insMov == insn) {
					skip = true;
					break;
				}
			}
			if (!skip) {
				minsn_t* mCopy = new minsn_t(*insn);
				dst->insert_into_block(mCopy, dst->tail);
				MSG_UF3(("[I] CopyMinsns %d -> %d: '%s'\n", src->serial, dst->serial, dst->tail->dstr()));
			}	else {
				MSG_UF3(("[I] skip CopyMinsns %d -> %d: '%s'\n", src->serial, dst->serial, insn->dstr()));
			}
			insn = insn->next;
		} while (insn != NULL);
	}

	mblock_t* CopyMblock(mblock_t* src)
	{
		mbl_array_t* mba = src->mba;
		mblock_t* dst = mba->insert_block(mba->qty - 1);
		MSG_UF3(("[I] CopyMblock %d -> %d\n", src->serial, dst->serial));
		CopyMinsns(src, dst);

		// copy struct members
		dst->flags = src->flags;
		dst->start = src->start;
		dst->end = src->end;
		dst->type = src->type;

		// copy mlist_t
		dst->dead_at_start = src->dead_at_start;
		dst->mustbuse = src->mustbuse;
		dst->maybuse = src->maybuse;
		dst->mustbdef = src->mustbdef;
		dst->maybdef = src->maybdef;
		dst->dnu = src->dnu;

		// copy sval_t
		dst->maxbsp = src->maxbsp;
		dst->minbstkref = src->minbstkref;
		dst->minbargref = src->minbargref;
		return dst;
	}

	mblock_t* MakeGotoBlock(DeferredGraphModifier& dgm, mbl_array_t* mba, int iBlockDest)
	{
		mblock_t* blk = mba->insert_block(mba->qty - 1);
		MSG_UF3(("[I] MakeGotoBlock %d\n", blk->serial));
		blk->type = BLT_1WAY;
		blk->flags |= MBL_FAKE;
		ea_t ea = mba->first_epilog_ea;
		if (ea == BADADDR)
			ea = mba->mbr.start();
		blk->start = ea;
		AppendGoto(blk, iBlockDest);
		dgm.Add(blk->serial, iBlockDest);
		return blk;
	}

	void AppendInsnCopyAndConnect(DeferredGraphModifier& dgm, mblock_t* src, mblock_t* dst, int newDest)
	{
		CopyMinsns(src, dst);
		dgm.ChangeGoto(dst, src->serial, newDest);
		dst->mark_lists_dirty();
	}

	int CopyBlocksAndConnectPredNDest(DeferredGraphModifier& dgm, mblock_t* mb, mblock_t* pred, int iDest)
	{
		MSG_UF3(("[I] %a: CopyBlocksAndConnectPredNDest mb:%d pred:%d dest:%d\n", mb->start, mb->serial, pred->serial, iDest));
		mblock_t* mbCopy = CopyMblock(mb);
		dgm.ChangeGoto(pred, mb->serial, mbCopy->serial);
		if (mb->tail != NULL && is_mcode_jcond(mb->tail->opcode)) {
			mblock_t* mbSuccFalseCopy = MakeGotoBlock(dgm, mb->mba, mb->serial + 1);
			QASSERT(100509, mbCopy->serial + 1 == mbSuccFalseCopy->serial);
			dgm.Add(mbCopy->serial, mbCopy->serial + 1); // the order is important (add false case then true case, or INTERR 50860)
		}
		dgm.ChangeGoto(mbCopy, -1, iDest);
		return mbCopy->serial;
	}

	void PostHandleTwoPreds(DeferredGraphModifier& dgm, mblock_t* mb, int oldTarget, int actualDfltTarget, mblock_t* nonJcc, int actualNonJccTarget)
	{
		MSG_UF3(("[I] %a: PostHandleTwoPreds mb:%d->%d (old %d), nJcc:%d->%d\n", mb->start, mb->serial, actualDfltTarget, oldTarget, nonJcc->serial, actualNonJccTarget));
		const bool bJcond = mb->tail != NULL && is_mcode_jcond(mb->tail->opcode);
		// handle endWithJcc's destination (actualDfltTarget)
		if (bJcond && actualDfltTarget == mb->serial + 1) {	// we can not change the jump target to be the next block
			MSG_UF1(("[E] %a: PostHandleTwoPreds: actualDfltTarget is matched with the false case of the dispatcher predecessor %d. Abort.\n", mb->start, mb->serial));
			return;
		}
		dgm.ChangeGoto(mb, oldTarget, actualDfltTarget);

		// this is not flattened if-statement blocks. Abort. 
		if (actualDfltTarget == actualNonJccTarget) {
			MSG_UF2(("[W] %a: PostHandleTwoPreds: actualDfltTarget is matched with actualNonJccTarget in the dispatcher predecessor %d.\n", mb->start, mb->serial));
			return;
		}

		// handle nonJcc
		if (bJcond) {
			// copy the conditional blocks for nonJcc
			CopyBlocksAndConnectPredNDest(dgm, mb, nonJcc, actualNonJccTarget);
		} else {
			// change the destination from mb->serial to actualNonJccTarget
			AppendInsnCopyAndConnect(dgm, mb, nonJcc, actualNonJccTarget);
		}
	}

	// ida changes number of stopBlk on inserting new block (CopyMblock), renumbers sucessors/predecessors of moved block 
	// but not changes microcode to correlate changed sucessors
	void CorrectStopBlockPreds(DeferredGraphModifier& dgm, mbl_array_t* mba)
	{
		int stopBlkNum = mba->qty - 1;
		mblock_t* mbCurrentStop = mba->get_mblock(stopBlkNum);
		for (auto bNum : mbCurrentStop->predset) {
			mblock_t* stopPred = mba->get_mblock(bNum);
			if (stopPred->tail != NULL) {
				if (is_mcode_jcond(stopPred->tail->opcode)) {
					MSG_UF3(("[I] CorrectStopBlockPreds: The pred of BLT_STOP block (%d) with Jcc will be updated\n", stopPred->serial));
					if (stopPred->serial + 1 != stopBlkNum && stopPred->tail->d.b != stopBlkNum)
						dgm.ChangeGoto(stopPred, stopPred->tail->d.b, stopBlkNum);
					else if (stopPred->serial + 1 == stopBlkNum && stopPred->succ(0) != stopBlkNum)
						dgm.ChangeGoto(stopPred, stopPred->succ(0), stopBlkNum);
					else if (stopPred->tail->d.b == stopBlkNum && stopPred->succ(1) != stopBlkNum)
						dgm.ChangeGoto(stopPred, stopPred->succ(1), stopBlkNum);
				} else {
					MSG_UF3(("[I] CorrectStopBlockPreds: The pred of BLT_STOP block (%d) will be updated\n", stopPred->serial));
					if ((stopPred->tail->opcode != m_goto && stopPred->serial + 1 != stopBlkNum) || stopPred->succ(0) != stopBlkNum)
						dgm.ChangeGoto(stopPred, stopPred->succ(0), stopBlkNum);
					else if (stopPred->tail->opcode == m_goto && stopPred->tail->l.b != stopBlkNum)
						dgm.ChangeGoto(stopPred, stopPred->tail->l.b, stopBlkNum);
				}
			}
		}
	}

	bool FindJccInFirstBlocks(mbl_array_t* mba, mop_t*& opCopy, mblock_t*& endsWithJcc, mblock_t*& nonJcc, int& actualGotoTarget, int& actualJccTarget)
	{
		actualGotoTarget = actualJccTarget = -1;

		// search assignment for endsWithJcc (the assignment can be done in every endsWithJcc blocks)
		for (int iCurrent = cfi.iFirst; iCurrent > 0; iCurrent -= 2) {
			endsWithJcc = mba->get_mblock(iCurrent);
			if (iCurrent == cfi.iFirst || is_mcode_jcond(endsWithJcc->tail->opcode)) {
				actualGotoTarget = FindBlockTargetOrLastCopy(endsWithJcc, endsWithJcc, opCopy, false, false);
				if (actualGotoTarget > 0)
					break;
				else {
					mop_t* opCopy2nd = m_DeferredErasuresLocal.back().opCopy;
					if (!opCopy2nd->equal_mops(*opCopy, EQ_IGNSIZE)) {
#if DEBUG_UF >= 3
						qstring qs1;	opCopy2nd->print(&qs1); tag_remove(&qs1);
						qstring qs2;	opCopy->print(&qs2); tag_remove(&qs2);
						MSG_UF3(("[I] %a: FindJccInFirstBlocks %s assigned to %s\n", m_DeferredErasuresLocal.back().insMov->ea, qs1.c_str(), qs2.c_str()));
#endif
						opCopy = opCopy2nd;
					}
				}
			}
		}

		// search assignment for nonJcc
		for (int iCurrent = cfi.iFirst - 1; iCurrent > 0; iCurrent -= 2) {
			nonJcc = mba->get_mblock(iCurrent);
			if (!is_mcode_jcond(nonJcc->tail->opcode)) {
				actualJccTarget = FindBlockTargetOrLastCopy(nonJcc, nonJcc, opCopy, false, false);
				if (actualJccTarget > 0 && actualGotoTarget > 0) {
					// actual endsWithJcc is the pred of nonJcc
					endsWithJcc = mba->get_mblock(nonJcc->pred(0));
					return true;
				}
			}
		}

		// handle case then first block assing additional variable
		return actualGotoTarget > 0 && endsWithJcc->serial == cfi.iFirst;
	}

	// Erase the now-superfluous chain of instructions that were used to copy a numeric value into the assignment variable.
	void ProcessErasures(mbl_array_t *mba)
	{
		//m_PerformedErasuresGlobal.insert(m_PerformedErasuresGlobal.end(), m_DeferredErasuresLocal.begin(), m_DeferredErasuresLocal.end());
		for (auto erase : m_DeferredErasuresLocal) {
			if (erase.insMov->opcode == m_mov && erase.insMov->l.t == mop_n && !erase.insMov->d.equal_mops(cfi.opAssigned, EQ_IGNSIZE)) {
				//such assignment may be used more then once (proc 0040C090 in 80B5FD4217C76DBBA3F05A97A27ED762)
				MSG_UF2(("[W] %a: Blk %d Skip erasing '%s'\n", erase.insMov->ea, erase.iBlock, erase.insMov->dstr()));
				continue;
			}
			MSG_UF3(("[I] %a: Blk %d Erasing '%s'\n", erase.insMov->ea, erase.iBlock, erase.insMov->dstr()));
			mblock_t* mb = mba->get_mblock(erase.iBlock);
			mb->make_nop(erase.insMov);
			mb->mark_lists_dirty();
		}
		m_DeferredErasuresLocal.clear();
	}

	bool run(mbl_array_t *mba)
	{
		if (!cfi.GetAssignedAndComparisonVariables(mba)) {
			MSG_UF1(("[E] Couldn't get control-flow flattening information\n"));
			return false;
		}
#if DEBUG_UF >= 2
	//ShowMicrocodeExplorer(mba, "beforeUnflattening1");
#endif

		ufCurr = mba->entry_ea;
		ufAddGL(ufCurr);// temporary add to graylist until proc will be printed

		// enable mblock_t copy for later maturity levels
		mba->clr_mba_flags2(MBA2_NO_DUP_CALLS);

		DeferredGraphModifier dgm(mba);
		int iFixed = 0;
		int skippedPreds = 0;
		int iFail = 0;

		// Iterate through the predecessors of the top-level control flow switch
		for (auto iDispPred : mba->get_mblock(cfi.iDispatch)->predset) {
			mblock_t* mb = mba->get_mblock(iDispPred);
			int nsucc = mb->nsucc();
			if (nsucc > 2) {
				MSG_UF1(("[E] nsucc check: The dispatcher predecessor %d had %d successors, > 2 (continue)\n", iDispPred, mb->nsucc()));
				++iFail;
				continue;
			}
			bool bJcond = false;
			if (nsucc == 2) {
				bJcond = mb->tail != NULL && is_mcode_jcond(mb->tail->opcode) && mb->tail->d.b == cfi.iDispatch;
				if (!bJcond) {
					MSG_UF1(("[E] nsucc 2 but !bJcond: The dispatcher predecessor %d (continue)\n", iDispPred));
					++iFail;
					continue;
				}
			}

			// Find the block that dominates this cluster, or skip this block if we can't. This ensures that we only try to unflatten parts of the
			// control flow graph that were actually flattened. Also, we need the cluster head so we know where to bound our searches for numeric  definitions.
			int iClusterHead;
			mblock_t* mbClusterHead = GetDominatedClusterHead(mba, iDispPred, iClusterHead);
			if (mbClusterHead == NULL) {
				MSG_UF3(("[I] Dominator tree algorithm didn't work for predecessor %d\n", iDispPred));
				mbClusterHead = mb;
			}

			// Try to find a numeric assignment to the assignment variable, but pass false for the last parameter so that the search stops if it 
			// reaches a block with more than one successor. This ought to succeed if the flattened control flow region only has one destination,
			// rather than two destinations for flattening of if-statements.
			m_DeferredErasuresLocal.clear();
			int iDestNo = FindBlockTargetOrLastCopy(mb, mbClusterHead, &cfi.opAssigned, true, true);
			// Stash off a copy of the last variable in the chain of assignments to the assignment variable, as well as the assignment instruction
			// (the latter only for debug-printing purposes).
			mop_t* opCopy;
			if (m_DeferredErasuresLocal.empty())
				opCopy = &cfi.opAssigned;
			else
				opCopy = m_DeferredErasuresLocal.back().opCopy;
			// set the block number of the pred true case if the last assignment is block sub-comparison variable (TODO: the validation with more sample cases needed)
			if (iDestNo < 0 && cfi.opSubCompared.t != mop_z && opCopy->equal_mops(cfi.opSubCompared, EQ_IGNSIZE)) {
				MSG_UF3(("[I] The dispatcher predecessor %d: the last assignment is block sub-comparison variable (useless loop condition?)\n", iDispPred));
				mblock_t* pred = mba->get_mblock(mb->pred(0));
				if (is_mcode_jcond(pred->tail->opcode) && pred->npred() == 1) {
					iDestNo = pred->tail->d.b;
					MSG_UF3(("[I] The dispatcher predecessor %d: the destination is set to the block number of the pred true case %d\n", iDispPred, iDestNo));
				}
			}

			if (iDestNo > 0) {
				MSG_UF3(("[I] The dispatcher predecessor %d, cluster head = %d, destination = %d\n", iDispPred, iClusterHead, iDestNo));
				dgm.ChangeGoto(mb, cfi.iDispatch, iDestNo); // Make a note to ourselves to modify the graph structure later
				ProcessErasures(mba); // Erase the intermediary assignments to the assignment variable
				++iFixed;
				continue;
			}

			if (opCopy->t == mop_n) {
				MSG_UF1(("[E] The dispatcher predecessor %d at %a assign unknown numeric value %d\n", iDispPred, mb->start, (int)opCopy->nnn->value));
				++iFail;
				continue;
			}

			if (mb->npred() == 1 && iClusterHead == -1 && m_DeferredErasuresLocal.empty() && mb->get_reginsn_qty() == 1 &&
				(mb->tail->opcode == m_goto || mb->tail->opcode == m_jnz)) { //is_simple_goto_block || is_simple_jcnd_block
				MSG_UF2(("[W] %a: The dispatcher predecessor %d seems is a blind goto/jnz disp\n", mb->start, iDispPred));
				++skippedPreds; // count as correct block
				continue;
			}

			// Call the function that handles the case of a conditional assignment to the assignment variable (i.e., the flattened version of an if-statement).
			mblock_t* endsWithJcc = NULL;
			mblock_t* nonJcc = NULL;
			int actualDfltTarget, actualNonJccTarget;
			if (FindTargets4TwoPreds(mb, mbClusterHead, opCopy, endsWithJcc, nonJcc, actualDfltTarget, actualNonJccTarget)) {
				if (bJcond) {
					MSG_UF3(("[I] FindTargets4TwoPreds: The dispatcher predecessor %d (conditional jump true case), actualDfltTarget from endsWithJcc = %d, actualNonJccTarget from nonJcc = %d\n", mb->serial, actualDfltTarget, actualNonJccTarget));
				} else {
					MSG_UF3(("[I] FindTargets4TwoPreds: The dispatcher predecessor %d (goto), actualDfltTarget from endsWithJcc = %d, actualNonJccTarget from nonJcc = %d\n", mb->serial, actualDfltTarget, actualNonJccTarget));
				}
				PostHandleTwoPreds(dgm, mb, cfi.iDispatch, actualDfltTarget, nonJcc, actualNonJccTarget);
				ProcessErasures(mba);
				++iFixed;
				continue;
			}

			// goto n preds
			if (mb->npred() >= 2) {
				bool nPredsOk = true;
				bool mbOrigUsed = false;
				for (int i = 0; i < mb->npred(); i++) {
					mblock_t* pred = mba->get_mblock(mb->pred(i));
					bool bJcondPred = pred->tail != NULL && is_mcode_jcond(pred->tail->opcode);
					int iClusterHeadForPred;
					mblock_t* mbClusterHeadForPred = GetDominatedClusterHead(mba, pred->serial, iClusterHeadForPred);
					if (mbClusterHeadForPred == NULL)
						mbClusterHeadForPred = pred;

					int iDestPred = FindBlockTargetOrLastCopy(pred, mbClusterHeadForPred, opCopy, true, true);
					if (iDestPred > 0) {
						if (bJcond || bJcondPred) {
							MSG_UF2(("[W] goto n preds: The dispatcher predecessor %d (conditional jump true case bJcond=%d, bJcondPred=%d), pred index %d (%d -> %d)\n", mb->serial, bJcond, bJcondPred, i, pred->serial, iDestPred));
							if (!mbOrigUsed) {
								mbOrigUsed = true;
								dgm.ChangeGoto(mb, cfi.iDispatch, iDestPred);
							} else {
								CopyBlocksAndConnectPredNDest(dgm, mb, pred, iDestPred);
							}
						} else {
							MSG_UF3(("[I] goto n preds: The dispatcher predecessor %d (goto), pred index %d (%d -> %d)\n", mb->serial, i, pred->serial, iDestPred));
							// change the destination from mb->serial to iDestPred
							AppendInsnCopyAndConnect(dgm, mb, pred, iDestPred);
						}
					}
					// for flattened conditional predecessors
					else if (pred->npred() == 2 && FindTargets4TwoPreds(pred, mbClusterHeadForPred, opCopy, endsWithJcc, nonJcc, actualDfltTarget, actualNonJccTarget)) {
						if (bJcondPred) {
							MSG_UF2(("[W] FindTargets4TwoPreds + goto n preds combo1: The dispatcher predecessor %d (conditional jump true case), "
								"pred index % d block number % d, actualDfltTarget from endsWithJcc = % d, actualNonJccTarget from nonJcc = %d\n",
								mb->serial, i, pred->serial, actualDfltTarget, actualNonJccTarget));
							//#1: Jcc-true branch
							if (!mbOrigUsed) {
								mbOrigUsed = true;
								dgm.ChangeGoto(mb, cfi.iDispatch, actualDfltTarget);
							} else {
								CopyBlocksAndConnectPredNDest(dgm, mb, pred, actualDfltTarget);
							}
							//#2: Jcc-false branch (nonJcc), copy pred
							mblock_t* predCopy = CopyMblock(pred);
							mblock_t* predSuccFalseGoto = MakeGotoBlock(dgm, mba, pred->serial + 1);
							QASSERT(100511, predCopy->serial + 1 == predSuccFalseGoto->serial);
							dgm.ChangeGoto(nonJcc, pred->serial, predCopy->serial);
							dgm.Add(predCopy->serial, predCopy->serial + 1); // the order is important (add false case then true case, or INTERR 50860)
							//#2: Jcc-false branch (nonJcc), copy mb
							CopyBlocksAndConnectPredNDest(dgm, mb, predCopy, actualNonJccTarget);
						} else if (bJcond) { //&& !bJcondPred
							MSG_UF2(("[W] FindTargets4TwoPreds + goto n preds combo2: The dispatcher predecessor %d (conditional jump true case), "
								"pred index %d block number %d, actualDfltTarget from endsWithJcc = %d, actualNonJccTarget from nonJcc = %d\n",
								mb->serial, i, pred->serial, actualDfltTarget, actualNonJccTarget));
							// copy and connect #1: copied mb to each pred
							//FIXME: 	if (!mbOrigUsed) ... 
							int iCopied = CopyBlocksAndConnectPredNDest(dgm, mb, pred, cfi.iDispatch);
							if (iCopied != -1) {
								mblock_t* mbCopy = mba->get_mblock(iCopied);
								// copy and connect #2: copied pred to nonJcc
								iCopied = CopyBlocksAndConnectPredNDest(dgm, pred, nonJcc, mbCopy->serial);
								if (iCopied != -1) {
									mblock_t* predCopy = mba->get_mblock(iCopied);
									// the same operations as ones in FindTargets4TwoPreds case
									PostHandleTwoPreds(dgm, mbCopy, cfi.iDispatch, actualDfltTarget, predCopy, actualNonJccTarget);
								}
							}
						} else { // !bJcond && !bJcondPred
							MSG_UF2(("[W] FindTargets4TwoPreds + goto n preds combo3: The dispatcher predecessor %d (goto), "
								"pred index %d block number %d, actualDfltTarget from endsWithJcc = %d, actualNonJccTarget from nonJcc = %d\n",
								mb->serial, i, pred->serial, actualDfltTarget, actualNonJccTarget));
							// 1st copy: mb code to the pred tail
							CopyMinsns(mb, pred);
							// the same operations as ones in FindTargets4TwoPreds case
							PostHandleTwoPreds(dgm, pred, mb->serial, actualDfltTarget, nonJcc, actualNonJccTarget);
						}
					} else {
						MSG_UF1(("[E] goto n preds: The dispatcher predecessor %d (%a), pred index %d block number %d (%a), destination not found\n", mb->serial, mb->start, i, pred->serial, pred->start));
						nPredsOk = false;
						break;
					}
				}

				// ProcessErasures should be called after taking care of all preds
				if (nPredsOk) {
					ProcessErasures(mba);
					++iFixed;
					MSG_UF3(("[I] goto n preds %d ok\n", mb->serial));
				} else {
					m_DeferredErasuresLocal.clear();
					++iFail;
				}
				continue;
			}

			// For the case when the update variables for if-statement are assigned in the first blocks, or somewhere else
			if (mb->npred() == 1 && !cfi.opAssigned.equal_mops(*opCopy, EQ_IGNSIZE)) {
				if (!cfi.bTrackingFirstBlocks || !FindJccInFirstBlocks(mba, opCopy, endsWithJcc, nonJcc, actualDfltTarget, actualNonJccTarget)) {
					MSG_UF2(("[W] %a: first blocks: The dispatcher predecessor %d, FindJccInFirstBlocks failed for %s\n", mb->start, mb->serial, opCopy->dstr()));
				} else {
					if (actualNonJccTarget == -1) { // the only one assignment found
						MSG_UF3(("[I] first blocks: The dispatcher predecessor %d, destination = %d\n", iDispPred, actualDfltTarget));
						dgm.ChangeGoto(mb, cfi.iDispatch, actualDfltTarget);
						ProcessErasures(mba);
						++iFixed;
						continue;
					}

					// dispatcher predecessor -> endsWithJcc
					MSG_UF3(("[I] first blocks: The dispatcher predecessor %d, endsWithJcc = %d & actualDfltTarget = %d, nonJcc = %d & actualNonJccTarget = %d\n", mb->serial, endsWithJcc->serial, actualDfltTarget, nonJcc->serial, actualNonJccTarget));
					dgm.ChangeGoto(mb, cfi.iDispatch, endsWithJcc->serial);

					// endsWithJcc true case -> actualDfltTarget
					int JccTrueSerial = endsWithJcc->succ(0) == nonJcc->serial ? endsWithJcc->succ(1) : endsWithJcc->succ(0);
					dgm.ChangeGoto(endsWithJcc, JccTrueSerial, actualDfltTarget);
					// nonJcc -> actualNonJccTarget
					dgm.ChangeGoto(nonJcc, nonJcc->succ(0), actualNonJccTarget);
					ProcessErasures(mba);
					++iFixed;
					continue;
				}

				// look for key somwhere in Valranges
				Key_t keyVal;
				if (getKeyFromValranges(mb, opCopy, &keyVal)) {
					int iDestNo = cfi.jcm->FindBlockByKey(keyVal);
					if (iDestNo > 0) {
						MSG_UF3(("[I] Valranges for %s: The dispatcher predecessor %d, destination = %d\n", opCopy->dstr(), iDispPred, iDestNo));
						dgm.ChangeGoto(mb, cfi.iDispatch, iDestNo);
						//FIXME: erasures can contain garbage from above call FindJccInFirstBlocks, can find real assinment for opCopy with help of use-def chain
						m_DeferredErasuresLocal.clear(); //ProcessErasures(mba); 
						++iFixed;
						continue;
					}
				}
			}

			MSG_UF1(("[E] %a: no more handlers: The dispatcher predecessor %d\n", mb->start, mb->serial));
			++iFail;
		}
		// end for loop that unflattens all blocks

		{// print statistics
			qstring tmpc; cfi.opCompared.print(&tmpc); tag_remove(&tmpc);
			qstring tmpa; cfi.opAssigned.print(&tmpa); tag_remove(&tmpa);
			mblock_t *dispBlk = mba->get_mblock(cfi.iDispatch);
			Log(llNotice, "%a: unflat '%s': '%s' cmp, '%s' asgn; disp at %a ; %d jc, %d targets; %d dispatch predecessors: %d resolved + %d skipped + %d failed\n",
			    mba->entry_ea, get_short_name(mba->entry_ea).c_str(),
			    tmpc.c_str(), tmpa.c_str(),
			    dispBlk->start,
			    (int)(cfi.jcm->KeyToBlockJz.size() + cfi.jcm->KeyToBlockJle.size() + cfi.jcm->KeyToBlockJg.size() + (cfi.jcm->lastJnzTrg != -1)),
			    (int)(cfi.jcm->JTargetBlocks.size()),
			    (int)dispBlk->predset.size(), iFixed, skippedPreds, iFail);
			if (iFail) {
				Log(llNotice, "unflat: not all predecessors were resolved, pseudocode may be incorrect\n");
			}
		}

		// fix/append jump in the pred of the last block to pass control correctly
		CorrectStopBlockPreds(dgm, mba);
		int defChanged = dgm.Apply();// apply the deferred modifications to the graph structure.

#if 1
		if (defChanged != 0) {
			mba->dump_mba(true, "[hrt] before PruneUnreachable");
#if IDA_SDK_VERSION < 760
			const int nRemoved = PruneUnreachable(mba);
			defChanged += nRemoved;
			MSG_UF3(("[I] Removed unreachable %d blocks\n", nRemoved));
#else
			mba->remove_empty_and_unreachable_blocks();
#endif //IDA_SDK_VERSION < 760
		}
#endif

		if ((defChanged + iFixed) != 0) {
			mba->mark_chains_dirty();
			mba->optimize_local(0);
			return true;
		}
		return false;
	}
};

bool unflattening(mbl_array_t *mba)
{
	if (g_BlackList.find(mba->entry_ea) != g_BlackList.end())
		return false;

	//unflattening may be called few times during decompilation
	//do not check graylist on secondary calls
	Log(llDebug, "%a: unflattening ufCurr: %a\n", mba->entry_ea, ufCurr);
static uint32 reentryCnt;
	if(ufCurr == mba->entry_ea) {
		if(++reentryCnt % 100 == 0) {
			int answer = ask_yn(ASKBTN_YES, "[hrt] %a: unflattening looping %d!\nWait 100 more?", mba->entry_ea, reentryCnt);
			if(answer == ASKBTN_NO) {
				//ufCurr = BADADDR; // left this proc in gray list
				return false;
			}
		}
	} else {
		if(ufIsInGL(mba->entry_ea))
			return false;
		reentryCnt = 0;
	}

	bool changed = RemoveSingleGotos(mba);

	if (mba->get_graph()->is_du_chain_dirty(GC_REGS_AND_STKVARS)) {
		mba->analyze_calls(ACFL_GLBPROP);
		if (mba->get_graph()->is_du_chain_dirty(GC_REGS_AND_STKVARS)) {
			MSG_UF2(("[W] du chain still dirty\n"));
		}
	}

#if DEBUG_UF >= 3
	//ShowMicrocodeExplorer(mba, "beforeUnflattening0");
#endif
	CFUnflattener unfl;
	if (unfl.run(mba)) {
		mba->dump_mba(true, "[hrt] after unflattening");
		return true;
	} else {
		if (!ufIsInWL(mba->entry_ea) && !ufIsInGL(mba->entry_ea))
			g_BlackList.insert(mba->entry_ea);
	}
	return changed;
}
