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

/*
	This feature is inspired by ideas of GraphSlick plugin(https://github.com/lallousx86/GraphSlick)
*/

#include "warn_off.h"
#include <hexrays.hpp>
#include <pro.h>
#include <prodir.h>
#include <diskio.hpp>
#include "warn_on.h"

#include <map>
#include <set>
#include <stack>
#include "helpers.h"
#include "ordered_set.h"
#include "deinline.h"

#ifdef __GNUC__
	#pragma GCC diagnostic ignored "-Wmultichar"
	#pragma GCC diagnostic ignored "-Wformat"
	#pragma GCC diagnostic ignored "-Wpragmas"
	#pragma GCC diagnostic ignored "-Wfour-char-constants"
#endif


#define DEBUG_DI 0

#if DEBUG_DI > 2
	#include "MicrocodeExplorer.h"
#endif
#if DEBUG_DI > 1
	#define MSG_DI1(msg_) msg msg_
	#define MSG_DI2(msg_) msg msg_
#elif DEBUG_DI > 0
	#define MSG_DI1(msg_) msg msg_
	#define MSG_DI2(msg_)
#else
	#define MSG_DI1(msg_)
	#define MSG_DI2(msg_)
#endif

struct sBB;
class ida_local lessBBidx {
public:
	bool operator()(const sBB* x, const sBB* y) const;
};
// set of basic blocks sorted by idx
class ida_local bbs_t : public std::set<sBB*, lessBBidx>
{
public:
	void destroy();
	void add(sBB* bb) { insert(bb);}
	bool has(sBB* bb) const { return find(bb) != end(); }
	sBB* get(int idx) const;
	void makeCFG(mbl_array_t *mba);
	void serialize(bytevec_t &b) const;
	bool deserialize(const bbs_t &src, const uchar **ptr, const uchar *end);
	iterator getNextMatched(const sBB* bb, const_iterator startFrom, minsn_t** first) const;
};

typedef uint32 cmdtype_t;                             // microcode opcode and args types packed in one dword
typedef std::map<cmdtype_t, uint32>      freq_t;      // cmdtype_t frequency dictionary
typedef std::pair<bbs_t::iterator, bool> bbsIns_t;    // bbs_t insertion result
typedef qvector<bbs_t>                   mtch_t;      // groups of matched blocks
typedef std::pair<sBB*, sBB*>            twoBB_t;     // head/exit pair or parts of two paths in pathsStk_t
typedef std::stack<twoBB_t>              pathsStk_t;  // temporary stack for building paths
typedef std::basic_string<char32_t>      pathstr_t;   // group numbers in path
typedef std::set<mblock_t*>              mblockset_t;

class ida_local lessPSLen {
public:
	bool operator()(const pathstr_t& x, const pathstr_t& y) const;
};
class path_t;
struct sInline;
class lessInline;
typedef std::map<ea_t, path_t> paths_t;     // storage of found normalized paths, key is head block or micro-instruction inside head block address
typedef std::map<sInline*, paths_t, lessInline>  inlines_t;   // map lib inline to found paths
typedef uint32 ssze_t; // serialize_size_type;


bool lessPSLen::operator()(const pathstr_t& x, const pathstr_t& y) const
{
	if (x.length() == y.length())
		return x < y;
	return x.length() < y.length();
}

cmdtype_t optype(mopt_t op)
{
	//consider all types of variables (register, global, stack) as local var
	if(op == mop_r || op == mop_v || op == mop_S)
		return static_cast<cmdtype_t>(mop_l);
	return static_cast<cmdtype_t>(op);
}

// fill cmdtype_t frequency dictionary
struct ida_local freq_visitor_t : public minsn_visitor_t {
	freq_t& freq;
	uint32 instCnt;
	freq_visitor_t(freq_t& _freq, mbl_array_t *_mba, mblock_t *_blk,	minsn_t *_topins)
		: minsn_visitor_t(_mba, _blk, _topins), freq(_freq), instCnt(0) {}
	virtual ~freq_visitor_t() {}
	virtual int idaapi visit_minsn(void)
	{
		if (!curins->is_assert()) { // skip asserts
			cmdtype_t ct;
			if (curins->opcode == m_icall) //consider m_icall is same as m_call. Maybe something else (cond-jumps?)
				ct = static_cast<cmdtype_t>(m_call) << 16;
			else
				ct = static_cast<cmdtype_t>(curins->opcode) << 16;
			ct |= optype(curins->l.t) << (2 * 4);
			ct |= optype(curins->r.t) << (1 * 4);
			ct |= optype(curins->d.t) << (0 * 4);
			freq[ct]++;
			instCnt++;
			if (curins->d.t == mop_f) { //list of arguments
				mcallinfo_t *f = curins->d.f;
				if (f->solid_args) {
					cmdtype_t args = ((static_cast<cmdtype_t>(m_nop) << 16)) | (static_cast<cmdtype_t>(mop_f) << (0 * 4));
					freq[args] += static_cast<uint32>(f->solid_args);
					instCnt    += static_cast<uint32>(f->solid_args);
				}
			} //else if (curins->r.t == mop_c) {} //TODO: mcases
		}
		return 0;
	}
};

enum eBBKind {
	eBBK_whole, // common block type, using frequency dictionary of all instructions of the block, all blocks in the chain may have this type. inner blocks must have this type
	eBBK_head,  // head of chain, tail instructions of the block are pattern matching
	eBBK_tail,  // tail of chain, head instructions of the block are pattern matching
	eBBK_single // single block is not part of chain, pattern is a subset of all instructions of the block
};

//basic-block class
struct ida_local sBB {
	ea_t bgn;
	ea_t end;
	int32 idx; //idx of block inside mba or path
	eBBKind kind;
	bbs_t  preds;
	bbs_t  succs;
	freq_t freq;
	uint32 instCnt = 0;
	minsn_t* minsnlst = nullptr; //here is IDA's blk->head in case of eBBK_whole, and pattern in other cases

	sBB(ea_t bgn_, ea_t end_, int idx_, eBBKind kind_ = eBBK_whole) : bgn(bgn_), end(end_),  idx(idx_), kind(kind_) {}
	sBB(int idx_, eBBKind kind_ = eBBK_whole) : bgn(BADADDR), end(BADADDR),  idx(idx_), kind(kind_) {}
	~sBB() {
		if(kind != eBBK_whole) { //do not delete minsnlst of eBBK_whole block, it belong to ida
			minsn_t *mi = minsnlst;
			while(mi != nullptr) {
				minsn_t *next = mi->next;
				delete mi;
				mi = next;
			}
		}
	}
	void addPred(sBB* bb) {
		bbsIns_t r = preds.insert(bb);
		if (r.second) bb->addSucc(this);
	}
	void addSucc(sBB* bb) {
		bbsIns_t r = succs.insert(bb);
		if (r.second) bb->addPred(this);
	}
	void calcFreq(mblock_t* blk)
	{
		freq_visitor_t fv(freq, blk->mba, blk, blk->head);
		blk->for_all_insns(fv);
		instCnt = fv.instCnt;
		minsnlst = blk->head;
	}
	bool match_freq(const sBB* bb) const
	{
		if (succs.size() != bb->succs.size()) {
#if DEBUG_DI > 3
			Log(llFlood, "!match %a vs %a = !nsuccs\n", bgn, bb->bgn);
#endif
			return false;
		}
		uint32 minCnt = std::min(instCnt, bb->instCnt);
		if (!minCnt)
			return instCnt == bb->instCnt;
		if (minCnt > 2) {
			uint32 lenDiff = static_cast<uint32>(std::abs(static_cast<int32>(instCnt - bb->instCnt))) * 100 / minCnt;
				if (lenDiff > 100) {
#if DEBUG_DI > 3
					Log(llFlood, "!match %a vs %a = lenDiff %d%%\n", bgn, bb->bgn, lenDiff);
#endif
					return false;
			}
		}
		uint32 coverPerc;
		if (minCnt < 2)
			coverPerc = 49;
		else if (minCnt < 5)
			coverPerc = 50;
		else if (minCnt < 7)
			coverPerc = 60;
		else if (minCnt < 9)
			coverPerc = 69;
		else
			coverPerc = 85;
		const freq_t* fs;
		const freq_t* fb;
		uint32 ics, icb;
		if (freq.size() < bb->freq.size()) {
			fs = &freq;
			fb = &bb->freq;
			ics = instCnt;
			icb = bb->instCnt;
		}
		else {
			fs = &bb->freq;
			fb = &freq;
			ics = bb->instCnt;
			icb = instCnt;
		}
		uint32 common = 0;
		uint32 cs = 0, cb = 0;
		uint32 tp = 0;
		for (auto fsi = fs->begin(); fsi != fs->end(); fsi++) {
			auto fbi = fb->find(fsi->first);
			if (fbi == fb->end())
				continue;
			common++;
			cs += fsi->second;
			cb += fbi->second;
			tp += std::min(fsi->second, fbi->second) * 100 / std::max(fsi->second, fbi->second);
		}
		if (!common) {
#if DEBUG_DI > 3
			Log(llFlood, "!match %a vs %a = no common\n", bgn, bb->bgn );
#endif
			return false;
		}

		uint32 cps = 100 * cs / ics;
		uint32 cpb = 100 * cb / icb;
		bool res = cps > coverPerc && cpb > coverPerc && tp / common >= 90;
		//bool res = cps > coverPerc && (relaxed || (cpb > coverPerc && tp / common >= 90));
#if DEBUG_DI > 3
		Log(llFlood, "%smatch %a vs %a = %d(%d) %d(%d) (%d) %d\n", res ? "" : "!", bgn, bb->bgn, cps, ics, cpb, icb, coverPerc, tp / common);
#elif DEBUG_DI > 2
		if (!res && cps > coverPerc - 10 && cpb > coverPerc - 10 && tp / common >= 80) {
			Log(llFlood, "!match %a vs %a = %d %d (%d) %d\n", bgn, bb->bgn, cps, cpb, coverPerc, tp / common);
		}
#endif
		return res;
	}
	sBB* convert(eBBKind newKind, minsn_t *from, minsn_t *to, qstring* errorStr)
	{
		if(kind == eBBK_whole && newKind != eBBK_whole) {
#if IDA_SDK_VERSION >= 830
			minsn_t *copylst = nullptr;
			if(!from)
				from = minsnlst;
			MSG_DI2(("[hrt] convert blk at %a to %s (%a-%a)\n", bgn, newKind == eBBK_tail ? "tail" : newKind == eBBK_head ? "head" : "single", from->ea, to ? to->ea : 0));

			minsn_t *prev = nullptr;
			for(minsn_t *mi = getf_reginsn(from); mi != getf_reginsn(to); mi = getf_reginsn(mi->next)) {
				if((newKind == eBBK_tail || newKind == eBBK_single) && (is_mcode_jcond(mi->opcode) || mi->opcode == m_jtbl)) {
					errorStr->sprnt("Not allowed branch in block %d at %a", idx, mi->ea);
					//del copylst
					minsn_t *i = copylst;
					while(i != nullptr) {
						minsn_t *next = i->next;
						delete i;
						i = next;
					}
					return nullptr;
				}

				minsn_t *copy = new minsn_t(*mi);
				if(!prev) {
					copylst = copy;
				} else {
					prev->next = copy;
					copy->prev = prev;
				}
				prev = copy;
			}
			sBB* newBB = new sBB(*this);
			newBB->kind = newKind;
			newBB->minsnlst = copylst;
			return newBB;
#else
			errorStr->sprnt("Not allowed partially block selection for IDA version less 8.3");
			return nullptr;
#endif //IDA_SDK_VERSION >= 830
		}
		errorStr->sprnt("Not suitable BBKind convert of block %d", idx);
		return nullptr;
	}
	bool match_mop(mop_t &mo, mop_t &other) const
	{
		//ignore variable placement
		if(mo.t == mop_r || mo.t == mop_S || mo.t == mop_l || mo.t == mop_v) {
			if(other.t == mop_r || other.t == mop_S || other.t == mop_l || other.t == mop_v)
				return true;
			return false;
		}

		//ignore block number
		if(mo.t == mop_b) {
			if(other.t == mop_b)
				return true;
			return false;
		}
		//ignore string
		if (mo.t == mop_str) {
			if (other.t == mop_str)
				return true;
			return false;
		}

		//dive into sub-instruction
		if(mo.t == mop_d) {
			if(other.t == mop_d)
				return match_minsn(mo.d, other.d);
			return false;
		}

		//dive into address of
		if (mo.t == mop_a) {
			if (other.t == mop_a)
				return match_mop(*mo.a, *other.a);
			return false;
		}

		if (mo.t == mop_f) {
			if (other.t == mop_f && mo.f->args.size() == other.f->args.size()) { // more checks?
				for (size_t i = 0; i < mo.f->args.size(); i++)
					if (!match_mop(mo.f->args[i], other.f->args[i]))
						return false;
				return true;
			}
			return false;
		}

		if (mo.t == mop_p) {
			if (other.t == mop_p)
				return match_mop(mo.pair->lop, other.pair->lop) && match_mop(mo.pair->hop, other.pair->hop);
			return false;
		}

		return mo == other;
	}
	bool match_minsn(minsn_t *mi, minsn_t *other) const
	{
#if 0
		//ignore call target expression
		if((mi->opcode == m_call || mi->opcode == m_icall) &&
			 (other->opcode == m_call || other->opcode == m_icall)) {
			return match_mop(mi->d, other->d);
		}
#endif
		if(mi->opcode == other->opcode &&
			 match_mop(mi->l, other->l) &&
			 match_mop(mi->r, other->r) &&
			 match_mop(mi->d, other->d))
			return true;
		return false;
	}
	// `this` sBB is pattern, `bb` is compared alive block
	bool match_head(const sBB* bb, minsn_t** first = nullptr) const
	{
		if (succs.size() != bb->succs.size() || !minsnlst || !bb->minsnlst)
			return false;

		minsn_t *mi = minsnlst;
		minsn_t* other = bb->minsnlst;

		//comparing in backward order starting from last
		while(mi->next != nullptr) mi = mi->next;
		while(other->next != nullptr) other = other->next;
		mi = getb_reginsn(mi);
		other = getb_reginsn(other);

		minsn_t *matched = nullptr;
		while(mi != nullptr && other != nullptr) {
			if (!match_minsn(mi, other))
				return false;
			matched = other;
			mi = getb_reginsn(mi->prev);
			other = getb_reginsn(other->prev);
		}
		bool res = (mi == nullptr && matched != nullptr);
		if (res && first)
			*first = matched;
		return res;
	}
	// `this` sBB is pattern, `bb` is compared alive block
	bool match_tail(const sBB* bb, minsn_t** last = nullptr) const
	{
		minsn_t *mi = getf_reginsn(minsnlst);
		minsn_t *other = getf_reginsn(bb->minsnlst);
		minsn_t *matched = nullptr;
		while(mi != nullptr && other != nullptr) {
			if (!match_minsn(mi, other))
				return false;
			matched = other;
			mi = getf_reginsn(mi->next);
			other = getf_reginsn(other->next);
		}
		bool res = (mi == nullptr && matched != nullptr);
		if (res && last)
			*last = matched;
		return res;
	}
	// `this` sBB is pattern, `bb` is compared alive block
	bool match_single(const sBB* bb, minsn_t** first = nullptr, minsn_t** last = nullptr) const
	{
		minsn_t *mi = getf_reginsn(minsnlst);
		minsn_t *other = getf_reginsn(bb->minsnlst);
		minsn_t *firstmatch = nullptr;
		minsn_t *lastmatch = nullptr;
		while(mi != nullptr && other != nullptr) {
			if(match_minsn(mi, other)) {
				if(!firstmatch)
					firstmatch = other;
				lastmatch = other;
				mi = getf_reginsn(mi->next);
			} else if(firstmatch)
				break;
			other = getf_reginsn(other->next);
		}
		bool res = (mi == nullptr && firstmatch != nullptr && lastmatch != nullptr);
		if(res) {
			if(first)
				*first = firstmatch;
			if(last)
				*last = lastmatch;
		}
		return res;
	}
	bool match(const sBB* bb, minsn_t** first = nullptr, minsn_t** last = nullptr) const
	{
		switch(kind) {
		case eBBK_whole:  return match_freq(bb);
		case eBBK_head:   return match_head(bb, first);
		case eBBK_tail:   return match_tail(bb, last);
		case eBBK_single: return match_single(bb, first, last);
		}
		return false;
	}
	char getKind() const
	{
		switch (kind) {
		case eBBK_head:   return 'h';
		case eBBK_tail:   return 't';
		case eBBK_single: return 's';
		default:          return ' ';
		}
	}
	void serialize(bytevec_t &b, bool bNoFreq = false) const
	{
		b.append("sBB", 3);
		b.pack_db(getKind());
		b.append(&idx, sizeof(idx));
		if(kind == eBBK_whole) {
			ssze_t fsz = static_cast<ssze_t>(freq.size());
			if (bNoFreq)
				fsz = 0;
			b.append(&fsz, sizeof(fsz));
			if (!bNoFreq) {
				for (auto fi : freq) {
					b.append(&fi.first, sizeof(fi.first));
					b.append(&fi.second, sizeof(fi.second));
				}
			}
		} else {
			int cnt = 0;
			for(minsn_t *mi = getf_reginsn(minsnlst); mi != nullptr; mi = getf_reginsn(mi->next))
				cnt++;
			b.append(&cnt, sizeof(cnt));
#if IDA_SDK_VERSION >= 830
			if(minsnlst) {
				for(minsn_t *mi = getf_reginsn(minsnlst); mi != nullptr; mi = getf_reginsn(mi->next)) {
					bytevec_t tmp;
					int fmt = mi->serialize(&tmp);
					b.append(&fmt, sizeof(fmt));
					b.pack_bytevec(tmp);
				}
			}
#else
			//TODO: implement replacement for minsn_t::serialize(), see msig.cpp SerializeInsn()
#endif //IDA_SDK_VERSION >= 830
		}
		// preds and succs are saved and restored inside path_t
	}
	static sBB* deserialize(const uchar **ptr, const uchar *end)
	{
		#define ADV_PTR(sz) { *ptr += sz; if(*ptr > end) return NULL; }
		while(memcmp("sBB", *ptr, 3))
			ADV_PTR(1);
		ADV_PTR(3);
		eBBKind kind;
		switch(**ptr) {
		case 'h': kind = eBBK_head; break;
		case 't': kind = eBBK_tail; break;
		case 's': kind = eBBK_single; break;
		default:  kind = eBBK_whole; break;
		}
		ADV_PTR(1);
		sBB bb(*reinterpret_cast<const decltype(idx)*>(*ptr), kind);
		ADV_PTR(sizeof(decltype(idx)));
		if(kind == eBBK_whole) {
			ssze_t fsz = *reinterpret_cast<const decltype(fsz)*>(*ptr);
			ADV_PTR(sizeof(decltype(fsz)));
			for(ssze_t i = 0; i < fsz; i++) {
				freq_t::key_type k = *reinterpret_cast<const decltype(k)*>(*ptr);
				ADV_PTR(sizeof(decltype(k)));
				freq_t::mapped_type m = *reinterpret_cast<const decltype(m)*>(*ptr);
				ADV_PTR(sizeof(decltype(m)));
				bb.freq[k] = m;
				bb.instCnt += m;
			}
		} else {
			int cnt = *reinterpret_cast<const decltype(cnt)*>(*ptr);
			ADV_PTR(sizeof(decltype(cnt)));
			minsn_t *prev = nullptr;
			while(cnt--) {
				int fmt = *reinterpret_cast<const decltype(fmt)*>(*ptr);
				ADV_PTR(sizeof(decltype(fmt)));
#if IDA_SDK_VERSION >= 830
				bytevec_t tmp;
				if(!unpack_bytevec(&tmp, ptr, end))
					return NULL;
				minsn_t *mi = new minsn_t(BADADDR);
				if(!mi->deserialize(&tmp[0], tmp.size(), fmt))
					return NULL;
				if(prev) {
					prev->next = mi;
					mi->prev = prev;
				 } else {
					bb.minsnlst = mi;
				}
				prev = mi;
#else
			//TODO: implement replacement for minsn_t::deserialize()
#endif //IDA_SDK_VERSION >= 830
			}
		}
		sBB *newBB = new sBB(bb);
		bb.minsnlst = nullptr; //avoid del on dtor
		return newBB;
		#undef ADV_PTR
	}
};

bool lessBBidx::operator()(const sBB* x, const sBB* y) const
{
	return x->idx < y->idx;
}

void bbs_t::destroy()
{
	for(auto bb : *this)
		delete bb;
	clear();
}

sBB* bbs_t::get(int idx) const
{
	sBB bb(idx);
	auto it = lower_bound(&bb);
	if(it != end() && (*it)->idx == idx)
		return *it;
	return nullptr;
}

// build Control Flow Graph, calc frequency dictionary for each basic block
void bbs_t::makeCFG(mbl_array_t *mba)
{
	for (int i = 0; i < mba->qty; i++) {
		mblock_t *blk = mba->get_mblock(i);
		sBB* bb = get(i);
		if (nullptr == bb) {
			bb = new sBB(blk->start, blk->end, i);
			bb->calcFreq(blk);
			add(bb);
		}
		for (int sit = 0; sit < blk->nsucc(); sit++) {
			int blksi = blk->succ(sit);
			mblock_t *blks = mba->get_mblock(blksi);
			sBB* bbs = get(blksi);
			if (bbs == nullptr) {
				bbs = new sBB(blks->start, blks->end, blksi);
				bbs->calcFreq(blks);
				add(bbs);
			}
			bb->addSucc(bbs);
		}
		for (int pit = 0; pit < blk->npred(); pit++) {
			int blkpi = blk->pred(pit);
			mblock_t *blkp = mba->get_mblock(blkpi);
			sBB* bbp = get(blkpi);
			if (bbp == nullptr) {
				bbp = new sBB(blkp->start, blkp->end, blkpi);
				bbp->calcFreq(blkp);
				add(bbp);
			}
			bb->addPred(bbp);
		}
	}
}

void bbs_t::serialize(bytevec_t &b) const
{
	b.append("bbst", 4);
	ssze_t sz = static_cast<ssze_t>(size());
	b.append(&sz, sizeof(sz));
	for(auto it : *this) {
		b.append(&it->idx, sizeof(it->idx));
	}
}

bool bbs_t::deserialize(const bbs_t &src, const uchar **ptr, const uchar *end)
{
	#define ADV_PTR(sz) { *ptr += sz; if(*ptr > end) return false; }
	while(memcmp("bbst", *ptr, 4))
		ADV_PTR(1);
	ADV_PTR(4);
	ssze_t sz = *reinterpret_cast<const ssze_t*>(*ptr);
	ADV_PTR(sizeof(sz));
	for(ssze_t i = 0; i < sz; i++) {
		decltype(sBB::idx) index = *reinterpret_cast<const decltype(sBB::idx)*>(*ptr);
		ADV_PTR(sizeof(index));
		sBB* bb = src.get(index);
		if(!bb)
			return false;
		if(!insert(bb).second)
			return false;
	}
	return true;
	#undef ADV_PTR
}

bbs_t::iterator bbs_t::getNextMatched(const sBB* bb, bbs_t::const_iterator startFrom, minsn_t** first) const
{
	auto it = startFrom;
	for(; it != end(); it++) {
		if(bb->match(*it, first))
			break;
	}
	return it;
}

// list of unique path nodes ordered from head to tail (exit)
class ida_local path_t : public OrderedSet<sBB*, lessBBidx>
{
public:
	sBB* exit;
	path_t() : exit(nullptr) {}
	bool validate(qstring* errorStr)
	{
		// check single node paths is large enought
		if (size() < 2 && front()->instCnt < MIN_LEN_OF_1_BLOCK_INLINE) {
			errorStr->sprnt("Single block inline applicant at %a has %d microcode instructions, should be at least %d",
				front()->bgn, front()->instCnt, MIN_LEN_OF_1_BLOCK_INLINE);
			return false;
		}

		// do not check single block path for entries/exits
		if(front()->kind == eBBK_single)
			return true;

		// check path has no other entries from outside except head
		if (size() > 1) {
			auto pi = begin(); pi++;
			for (; pi != end(); pi++) {
				for (auto p : (*pi)->preds) {
					if (!has_item(p)) {
						errorStr->sprnt("entrance into the middle (from block %a to block %a). Head block %a must be a single entry", p->bgn, (*pi)->bgn, front()->bgn);
						return false;
					}
				}
			}
		}
		// check path has no any other exit outside
		for (auto pi : *this) {
			if(pi->kind == eBBK_tail) // tail block should be cut off before branch
				continue;
			for (auto s : pi->succs) {
				if (!has_item(s) && s != exit) {
					errorStr->sprnt("more then one exit (from block %a to block %a). Exit block %a must be alone", pi->bgn, s->bgn, exit->bgn);
					return false;
				}
			}
		}
		return true;
	}
	bool create_from_head_exit(sBB* head, sBB* exit_, qstring* errorStr)
	{
		clear();
		exit = exit_;

		push_back(head);
		if(head->kind != eBBK_single) {
			std::stack<sBB*> queue;
			queue.push(head);
			while (!queue.empty()) {
				sBB* bb = queue.top();
				queue.pop();
				for (auto s : bb->succs) {
					if (!has_item(s)) {
						if(s != exit)
							queue.push(s);
						if(s != exit || exit->kind == eBBK_tail)
							push_back(s);
					}
				}
			}
		}
		this->print("path created:");
		return validate(errorStr);
	}
	bool create_from_whole_mba(mbl_array_t *mba, qstring* errorStr)
	{
		mba->dump_mba(false, "create_from_whole_mba");
		bbs_t allBBs;
		allBBs.makeCFG(mba);
		sBB* head = nullptr; //first non-fake block
		sBB* exit = nullptr; //first fake block after head
		for (int n = 0; n < mba->qty; n++) {
			sBB* bb = allBBs.get(n);
			assert(bb);
			if (!head && (mba->natural[n]->flags & MBL_FAKE) == 0)
				head = bb;
			if (head && !exit && (mba->natural[n]->flags & MBL_FAKE) != 0)
				exit = bb;
		}
		if (!head) {
			errorStr->sprnt("No head block found for inline applicant %a", mba->entry_ea);
			allBBs.destroy();
			return false;
		}
		if(!exit) {
			errorStr->sprnt("No exit block found for inline applicant %a", mba->entry_ea);
			allBBs.destroy();
			return false;
		}
		if(head == exit && !has_xref(get_flags(head->bgn)) && head->minsnlst) {
			head = head->convert(eBBK_single, nullptr, nullptr, errorStr);
		} else {
			if(!has_xref(get_flags(head->bgn)) && head->minsnlst)
				head = head->convert(eBBK_head, nullptr, nullptr, errorStr);
			if(!has_xref(get_flags(exit->bgn)) && exit->minsnlst)
				exit = exit->convert(eBBK_tail, nullptr, nullptr, errorStr);
		}
		if(head && exit && create_from_head_exit(head, exit, errorStr)) {
			//free blocks not in path
			for(auto b : allBBs)
				if (!has_item(b) && b != exit)
					delete b;
			return true;
		}
		allBBs.destroy();
		return false;
	}
	bool create_from_entry_exit(mbl_array_t *mba, bbs_t *allBBs, ea_t head_ea, ea_t exit_ea)
	{
		mba->dump_mba(false, "create_from_entry_exit(%a, %a)",head_ea, exit_ea);
		MSG_DI2(("[hrt] create_from_entry_exit(%a-%a)\n", head_ea, exit_ea));
		sBB* head = nullptr;
		sBB* exit = nullptr;
		minsn_t* mhead = nullptr;
		minsn_t* mexit = nullptr;
		for (int n = 0; n < mba->qty; n++) {
			sBB* bb = allBBs->get(n);
			assert(bb);
			if (bb->bgn == head_ea) {
				head = bb;
				MSG_DI2(("[hrt] create_from_entry_exit found head %a\n", head_ea));
			} else if(bb->bgn == exit_ea) {
				exit = bb;
				MSG_DI2(("[hrt] create_from_entry_exit found exit %a\n", exit_ea));
			}
			if(!head && bb->bgn < head_ea /* && head_ea < bb->end*/) {
				//look if head inside of the block
				for(minsn_t* mi = getf_reginsn(bb->minsnlst); mi != nullptr; mi = getf_reginsn(mi->next))
					if(mi->ea == head_ea) {
						if (mi != getf_reginsn(bb->minsnlst)) {
							mhead = mi;
							MSG_DI2(("[hrt] create_from_entry_exit found mi-head %a in blk %d\n", mhead->ea, bb->idx));
						}	else {
							MSG_DI2(("[hrt] create_from_entry_exit found unaligned mi-head %a in blk %d\n", mhead->ea, bb->idx));
						}
						head = bb;
						break;
					}
			}
			if(!exit && bb->bgn < exit_ea && exit_ea < bb->end) {
				//look if exit inside of the block
				for(minsn_t* mi = getf_reginsn(bb->minsnlst); mi != nullptr; mi = getf_reginsn(mi->next))
					if(mi->ea == exit_ea) {
						if(mi != getf_reginsn(bb->minsnlst)) {
							mexit = mi;
							MSG_DI2(("[hrt] create_from_entry_exit found mi-exit %a in blk %d\n", mexit->ea, bb->idx));
						} else {
							MSG_DI2(("[hrt] create_from_entry_exit found unaligned mi-exit %a in blk %d\n", mi->ea, bb->idx));
						}
						exit = bb;
						break;
					}
			}
		}
		if (!head) {
			Log(llError, "No head block found for inline applicant %a-%a\n", head_ea, exit_ea);
			return false;
		}
		if (!exit) {
			Log(llError, "No exit block found for inline applicant %a-%a\n", head_ea, exit_ea);
			return false;
		}
		qstring errorStr;
		sBB* newhead = nullptr;
		sBB* newexit = nullptr;
		if(head == exit && mhead && mexit) {
			head = head->convert(eBBK_single, mhead, mexit, &errorStr);
			newhead = head;
		} else {
			if (mhead) {
				head = head->convert(eBBK_head, mhead, nullptr, &errorStr);
				newhead = head;
			}
			if (mexit) {
				exit = exit->convert(eBBK_tail, nullptr, mexit, &errorStr);
				newexit = exit;
			}
		}
		if (head && exit && create_from_head_exit(head, exit, &errorStr)) {
			//path contains block pointers from allBBs being invalid when allBBs be destroyed, make copy ot them
			bytevec_t buf;
			serialize(buf);
			clear();
			const uchar* ptr = &buf[0];
			if(!deserialize(&ptr, &buf[buf.size()]))
				errorStr = "deserialize";
		}
		if (newhead)
			delete newhead;
		if (newexit)
			delete newexit;
		if(errorStr.empty())
			return true;
		Log(llError, "Inline applicant %a-%a error:%s\n", head_ea, exit_ea, errorStr.c_str());
		return false;
	}
	void make_matched(const char* name, paths_t &grp, const bbs_t &src) const
	{
		MSG_DI2(("[hrt] make_matched %s\n", name));
		sBB* head1 = front();
		minsn_t* firstInsn = nullptr;
		for(auto hi = src.getNextMatched(head1, src.begin(), &firstInsn); hi != src.end(); hi = src.getNextMatched(head1, ++hi, &firstInsn)) {
			sBB* head2 = *hi;
			ea_t pathEa = head2->bgn;
			if (head1->kind == eBBK_single || head1->kind == eBBK_head) {
				QASSERT(100201, firstInsn);
				pathEa = firstInsn->ea;
			}
			sBB* exit2 = nullptr;
			path_t path2;
			path2.push_back(head2);
			if (head1->kind == eBBK_single) {
				MSG_DI2(("[hrt] single node path '%s': %a\n", name, head2->bgn));
				path2.exit = head2;
				grp[pathEa] = path2;
				continue;
			}
			MSG_DI2(("[hrt] start make path '%s' from: %a\n", name, head2->bgn));
			bbs_t matched1;
			bbs_t visited2;
			pathsStk_t queue;
			queue.push(twoBB_t(head1, head2));
			while (!queue.empty()) {
				sBB* bb1 = queue.top().first;
				sBB* bb2 = queue.top().second;
				if (bb1->succs.size() != bb2->succs.size()) {
					MSG_DI2(("[hrt]   dif nsuccs\n"));
					break;
				}
				queue.pop();
				if (bb2->succs.empty() && bb1->succs.empty()) {
					//case of no-return call block
					exit2 = bb2;
					continue;
				}
				bool bNoMatches = false;
				for (auto s2 : bb2->succs) {
					if (!path2.has_item(s2) && visited2.insert(s2).second) {
						auto s1 = bb1->succs.begin();
						for (; s1 != bb1->succs.end(); s1++) {
							if (*s1 != exit && !matched1.has(*s1) && (*s1)->match(s2)) {
								MSG_DI2(("[hrt]   add matched bb: %a\n", s2->bgn));
								path2.push_back(s2);
								matched1.insert(*s1);
								queue.push(twoBB_t(*s1, s2));
								break;
							}
						}
						if (s1 == bb1->succs.end()) {
							if (!exit2 || s2 == exit2) { //Sic! *s2 == exit2 for break! avoids setting bNoMatches = true
								exit2 = s2;
								MSG_DI2(("[hrt]   exit: %a\n", exit2->bgn));
								break;
							} else {
								bNoMatches = true;
								MSG_DI2(("[hrt]   no matches for %a\n", s2->bgn));
								break;
							}
						}
					}
				}
				if (bNoMatches)
					break;
			}
			if(path2.size() == size() && exit2) {
				path2.exit = exit2;
				qstring errstr;
				if (path2.validate(&errstr)) {
					path2.print("matched path");
					grp[pathEa] = path2;
				} else {
					MSG_DI1(("[hrt] %s\n", errstr.c_str()));
				}
			} else {
				MSG_DI2(("[hrt]   no exit or incomplete\n"));
			}
		}
	}
	void serialize(bytevec_t &b) const
	{
		ssze_t sz = static_cast<ssze_t>(size());
		b.append(&sz, sizeof(sz));
		for (auto bb : *this)
			bb->serialize(b);
		exit->serialize(b, true);
		for (auto bb : *this)
			if(bb->idx != exit->idx)  // skip successors for exit and single blocks
				bb->succs.serialize(b);
	}
	bool deserialize(const uchar **ptr, const uchar *end_)
	{
		#define ADV_PTR(sz) { *ptr += sz; if(*ptr > end_) return false; }
		bbs_t allBlocks;
		ssze_t sz = *reinterpret_cast< const decltype(sz)*>(*ptr);
		ADV_PTR(sizeof(decltype(sz)));
		while ( sz-- ) {
			sBB* bb = sBB::deserialize(ptr, end_);
			if (!bb)
				return false;
			push_back(bb);
			allBlocks.add(bb);
		}
		QASSERT(100203, allBlocks.size() == size());
		sBB* exi = sBB::deserialize(ptr, end_);
		if (!exi)
			return false;
		allBlocks.add(exi);
		exit = exi;

		for (auto bb : *this) {
			if (bb->idx == exit->idx)  // no successors for exit and single blocks
				continue;
			if(!bb->succs.deserialize(allBlocks, ptr, end_))
				return false;
		}
		return true;
		#undef ADV_PTR
	}
#if DEBUG_DI
	void print(const char* fmt, ...) const
	{
		qstring m;
		va_list va;
		va_start(va, fmt);
		m.cat_vsprnt(fmt, va);
		va_end(va);

		uint32 instCnt = 0;
		if (size()) {
			qstring path;
			for (auto n = begin(); n != end(); n++) {
				instCnt += (*n)->instCnt;
				if (n != begin())
					path.append(", ");
				path.cat_sprnt("%d/%a/%c", (*n)->idx, (*n)->bgn, (*n)->getKind());
			}
			msg("[hrt] %s %a-%a (%u insn/%d blocks): %s\n", m.c_str(), front()->bgn, exit ? exit->bgn : BADADDR, instCnt, (int)size(), path.c_str());
		} else {
			msg("[hrt] %s None-%a empty-path\n", m.c_str(), exit ? exit->bgn : BADADDR);
		}
	}
#else
	void print(const char* fmt, ...) const {}
#endif
};


// path_t storage
struct ida_local sInline
{
	qstring comment; // source file MD5 and head-exit addreses this inline has been generated from
	qstring name;    // name the inline will be displayed in decompile view. This is temporary (in-memory) storage, on disk is used filename. Must be unique
	path_t path;
	bool bLib; //this inline has been loaded from or saved to inlines library
	bool bTmp; //this inline has been just created, but not checked yet does it work
	sInline() : bLib(false), bTmp(true) {}
	sInline(const char* name_) : name(name_), bLib(false), bTmp(true) {}
	bool create_from_entry_exit(mbl_array_t *mba, bbs_t *allBBs, ea_t head_ea, ea_t exit_ea);
	bool create_from_whole_mba(mbl_array_t *mba, const char* name_, qstring* errorStr);
	void upd_comment(ea_t head_ea, ea_t exit_ea)
	{
		bytevec_t hash;
		hash.resize(16);
		if (retrieve_input_file_md5(&hash[0])) {
			char hashstr[33];
			get_hex_string(hashstr, 33, &hash[0], hash.size());
			hashstr[32] = 0;
			comment.sprnt("%s (%a-%a)", hashstr, head_ea, exit_ea);
		}
	}
	void serialize(bytevec_t &b) const
	{
		b.append(comment.c_str(), comment.length());
		b.append("\r\n\x0Inln\x0", 8);
		path.serialize(b);
	}
	bool deserialize(const uchar **ptr, const uchar *end_)
	{
		bLib = true; bTmp = false;
		#define ADV_PTR(sz) { *ptr += sz; if(*ptr >= end_) return false; }
		while(memcmp("\r\n\x0Inln\x0", *ptr, 8)) {
			//comment.append(*reinterpret_cast<const char*>(*ptr));
			ADV_PTR(1);
		}
		ADV_PTR(8);
		return path.deserialize(ptr, end_);
		#undef ADV_PTR
	}
};

class ida_local lessInline {
public:
	bool operator()(const sInline* x, const sInline* y) const { return  x->name < y->name; }
};

struct ida_local sInlinesLib : std::set<sInline*, lessInline>
{
	bool has(const char *name)
	{
		sInline i(name);
		return find(&i) != end();
	}
	static qstring getBasePath(bool bCreate = false)
	{
		qstring	basePath = get_user_idadir();
		basePath.append("/inlines");
		if (bCreate) {
			if(!qisdir(basePath.c_str())) {
#ifdef _WIN32
				if(qmkdir(basePath.c_str(), 0) < 0)
#else
				if(qmkdir(basePath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0)
#endif
					Log(llError, "Error %d on mkdir(\"%s\")\n", get_qerrno(), basePath.c_str());
			}
		}
		return basePath;
	}
	void save()
	{
		qstring	basePath = getBasePath(true);
		basePath.append('/');
		uint32 cnt = 0;
		for (auto inl : *this) {
			if (inl->bLib || inl->bTmp)
				continue; //do not overwrite inline files was loaded from lib
			qstring path = inl->name;
			size_t pdir = 0;
			for (size_t p = 0; p < path.size(); p++) {
				//sanitize_file_name(&path[pprev],  p - pprev);
				switch (path[p]) {
				case ':':
				case '?':
				case '*':
				case '<':
				case '>':
				case '|':
				case '\'':
				case '\"':
				case ' ':
					path[p] = '_';
					break;
				case '.':
				{
					if (pdir == p) {
						path.remove(pdir, 1); //avoid duplicates "..."
						p--;
						break;
					}
					// make dir in form 'Name'
					//path[pdir] = qtoupper(path[pdir]);
					//for (auto i = pdir + 1; i < p; i++)
					//	path[i] = qtolower(path[i]);
					qstring dir = basePath + path.substr(0, p);
#ifdef _WIN32
					if(qmkdir(dir.c_str(), 0) < 0)
#else
					if(qmkdir(dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0)
#endif
						Log(llError, "Error %d on mkdir(\"%s\")\n", get_qerrno(), basePath.c_str());
					path[p] = '/';
					pdir = p + 1;
					break;
				}
				}
			}
			qstring fullpath(basePath); fullpath.append(path);
			fullpath = unique_nameD(fullpath.c_str(), "-", [](const qstring& n) {qstring p(n); p.append(".inl"); return !qfileexist(p.c_str()); });
			fullpath.append(".inl");
			FILE *fd = qfopen(fullpath.c_str(), "wb");
			if(!fd) {
				Log(llError, "Could not open '%s' for writing!\n", fullpath.c_str());
			} else {
				bytevec_t buf;
				inl->serialize(buf);
				qfwrite(fd, &buf[0], buf.size());
				qfclose(fd);
				inl->bLib = true;
				Log(llFlood, "inline '%s' saved in file:'%s'\n", inl->name.c_str(), fullpath.c_str());
				++cnt;
			}
		}
		if(cnt)
			Log(llNotice, "%d inlines saved\n", cnt);
	}
	static void loadInlines(const char *dir, sInlinesLib* il)
	{
		qstring fname = dir;
		fname.append("/*");

		qffblk64_t blk;
		for (int res = qfindfirst(fname.c_str(), &blk, FA_DIREC); res == 0; res = qfindnext(&blk)) {
			fname = dir;
			fname.append('/');
			fname.append(blk.ff_name);
			if (0 != (blk.ff_attrib & FA_DIREC)) {
				if(blk.ff_name[0] != '.')
					loadInlines(fname.c_str(), il);
			} else {
				const char *ext = get_file_ext(fname.c_str());
				if(!ext || qstrcmp(ext, "inl"))
					continue;
				FILE* fd = qfopen(fname.c_str(), "rb");
				if (fd) {
					bytevec_t buf;
					qfseek(fd, 0, SEEK_END);
					buf.resize(qftell(fd));
					qfseek(fd, 0, SEEK_SET);
					qfread(fd, &buf[0], buf.size());
					qfclose(fd);

					qstring inlName = fname.c_str();
					inlName.remove(0, getBasePath().length() + 1);
					inlName.remove_last(4);
					inlName.replace("/", ".");

					sInline* inlin = new sInline(inlName.c_str());
					const uchar* ptr = &buf[0];
					if (buf.size() > 10 && inlin->deserialize(&ptr, &buf[buf.size()])) {
						il->insert(inlin);
						Log(llFlood, "inline '%s' loaded\n", inlin->name.c_str());
					} else {
						Log(llError, "broken inline '%s' in file:'%s'\n", inlin->name.c_str(), fname.c_str());
						delete inlin;
					}
				}
			}
		}
		qfindclose(&blk);
	}
	void load()
	{
		qstring	basePath = getBasePath();
		loadInlines(basePath.c_str(), this);
		if(size())
			Log(llNotice, "%d inlines are loaded\n", (int)size());
	}
};

static sInlinesLib inlinesLib;
static ea_t selection_bgn = BADADDR;
static ea_t selection_end = BADADDR;

bool sInline::create_from_entry_exit(mbl_array_t *mba, bbs_t *allBBs, ea_t head_ea, ea_t exit_ea)
{
	if (!path.create_from_entry_exit(mba, allBBs, head_ea, exit_ea))
		return false;

	name.cat_sprnt("inline_%a_%a", head_ea, exit_ea);
	upd_comment(head_ea, exit_ea);
	return true;
}

bool sInline::create_from_whole_mba(mbl_array_t *mba, const char* name_, qstring* errorStr)
{
	if (!path.create_from_whole_mba(mba, errorStr))
		return false;

	textctrl_info_t t;
	t.flags = TXTF_READONLY /*| TXTF_FIXEDFONT*/;
	qstr_printer_t vp(t.text, true);

	for (auto pi : path) {
		t.text.cat_sprnt("Block %d: %a-%a\n", pi->idx, pi->bgn, pi->end);
		mba->natural[pi->idx]->print(vp);
		t.text.append('\n');
	}
	t.text.cat_sprnt("Exit %d: %a\n", path.exit->idx, path.exit->bgn);
	mba->natural[path.exit->idx]->print(vp);

	qstring nam(name_);
	const char format[] =
		"[hrt] Please confirm microcode for inline\n\n"
		"<Name:i:256:100::>\n"
		"<:t::::>\n"
		"\n\n";
	while (1) {
		if (!ask_form(format, &nam, &t))
			return false;
		if (!nam.length())
			continue;
		if (!inlinesLib.has(nam.c_str()))
			break;
		Log(llError, "inline '%s' already exist\n", nam.c_str());
	}

	upd_comment(path.front()->bgn, path.exit->bgn);
	name = nam;
	validate_name(&name, VNT_IDENT);
	return true;
}

int mreg2regWchk(mreg_t mreg, int width)
{
	int reg = mreg2reg(mreg, width);
	if (reg == -1 || (width == PH.segreg_size && (PH.reg_first_sreg <= reg && reg <= PH.reg_last_sreg))) {// || (reg == ph.reg_code_sreg || reg == ph.reg_data_sreg)))
		MSG_DI2(("[hrt] ignore bad and segment register %d\n", reg));
		return -1;
	}
	return reg;
}

struct ida_local mlist2mop_t : public mlist_mop_visitor_t
{
	mop_t* mop = nullptr;
	int idaapi visit_mop(mop_t* op) {
		if (op->is_reg() || op->t == mop_S) {
			mop = op;
			return 1;
		}
		return 0;
	}
};

bool inlReplace(mbl_array_t* mba, const sInline* inl, ea_t headEa, const path_t& path, mblockset_t& removeBlocks)
{
	//---------------------------------------------------------------------------
	// head block uses and defs
	mblock_t* headb = mba->get_mblock(path.front()->idx);
	minsn_t* hfirst = headb->head;
	minsn_t* hlast = nullptr;
	sBB* ihead = inl->path.front();
	mlist_t huses;
	mlist_t hdefs;
	int hud = -1; // index of head block is only set in case eBBK_head || eBBK_single
	if((ihead->kind == eBBK_head || ihead->kind == eBBK_single)) {
		if(!ihead->match(path.front(), &hfirst, &hlast) || hfirst->ea != headEa) {
			Log(llError, " %a: inlReplace mismatch head\n", headEa);
			return false;
		}
		const minsn_t *insn = hlast;
		if(!insn)
			insn = headb->tail;
		for(; insn && insn != hfirst->prev; insn = insn->prev) {
			mlist_t use = headb->build_use_list(*insn, MUST_ACCESS);
			mlist_t def = headb->build_def_list(*insn, MUST_ACCESS);
			hdefs.add(def);
			huses.add(use);
			huses.sub(def); // remove local uses below def
		}
		hud = headb->serial;
		MSG_DI2(("[hrt] huses %s\n", huses.dstr()));
		MSG_DI2(("[hrt] hdefs %s\n", hdefs.dstr()));
	}

	//---------------------------------------------------------------------------
	// exit block uses and defs
	sBB* exit = path.exit;
	mblock_t* exitb = mba->get_mblock(exit->idx);
	sBB* iexit = inl->path.exit;
	minsn_t* exitlast = nullptr;
	mlist_t euses;
	mlist_t edefs;
	int eud = -1; // index of exit block is only set in case eBBK_tail
	if(iexit->kind == eBBK_tail) {
		if(!iexit->match(exit, nullptr, &exitlast) || !exitlast) {
			Log(llError, " %a: inlReplace mismatch tail\n", headEa);
			return false;
		}
		for(const minsn_t *insn = exitb->head; insn && insn != exitlast->next; insn = insn->next) {
			mlist_t use = headb->build_use_list(*insn, MUST_ACCESS);
			mlist_t def = headb->build_def_list(*insn, MUST_ACCESS);
			edefs.add(def);
			euses.add(use);
		}
		eud = exitb->serial;
		MSG_DI2(("[hrt] euses %s\n", euses.dstr()));
		MSG_DI2(("[hrt] edefs %s\n", edefs.dstr()));
	}


	//---------------------------------------------------------------------------
	mlist_t uses;   //collect uses are defined somewhere outside before "inline"
	mlist_t defs;   //collect defines are used somewhere after "inline"
	mlist_t retregs;
	//mlist_t spoiled;//collect defines inside "inline" spoils registers
	mcallinfo_t ci;
	bool bHave1Ret = false;
	{
		mbl_graph_t* graph = mba->get_graph();
		chain_keeper_t ud = graph->get_ud(GC_REGS_AND_STKVARS);
		chain_keeper_t du = graph->get_du(GC_REGS_AND_STKVARS);

		for (auto n : path) {
			mblock_t* b = mba->get_mblock(n->idx);
			const block_chains_t& udc = ud[b->serial];
			MSG_DI2(("[hrt] %a: %3d ud chain: %s\n", b->start, b->serial, udc.dstr()));
			for (block_chains_iterator_t udi = block_chains_begin(&udc); udi != block_chains_end(&udc); udi = block_chains_next(udi)) {
				const chain_t& ch = block_chains_get(udi);
				mlist_t chLst; chain_append_list(ch, mba, &chLst);

				//is already listed
				if(uses.includes(chLst))
					continue;
				//skip chains used in head block but above hfirst
				if(hud == b->serial && !chLst.has_common(huses))
					continue;
				//skip chains used in exit block but below exitlast
				if(eud == b->serial && !chLst.has_common(euses))
					continue;

				for (size_t i = 0; i < ch.size(); i++) {
					sBB tmp(ch.at(i)); // block that defines the instruction
					if(hud == tmp.idx) {
						//check if it defined in head block below hfirst
						if(chLst.is_subset_of(hdefs))
							continue;
					} else if(eud == tmp.idx) {
						//check if it defined in exit block above exitlast
						if(chLst.is_subset_of(edefs))
							continue;
					} else if(path.has_item(&tmp)) // continue search if defined inside path
						continue;

					chain_append_list(ch, mba, &uses);
					MSG_DI2(("[hrt] %a: %3d uses ext-%d def %s\n", b->start, b->serial, tmp.idx, ch.dstr()));
					mcallarg_t a;
					if (!a.create_from_mlist(mba, chLst, mba->fullsize)) {
						MSG_DI2(("[hrt] !a.create_from_mlist: %s  %x\n", ch.dstr(), ch.width));
						break;
					}
					a.type = get_unk_type(ch.width);
					if (a.type.empty()) {
						MSG_DI2(("[hrt] !get_unk_type: %s  %x\n", ch.dstr(), ch.width));
						break;
					}
					if (ch.is_reg()) {
						int reg = mreg2regWchk(ch.get_reg(), ch.width);
						if (reg == -1)
							break;
						a.argloc.set_reg1(reg);
					} else if (ch.is_stkoff()) {
						a.argloc.set_stkoff(ch.get_stkoff()); //is here IDA or decompiler stkoff?
					} else {
						MSG_DI2(("[hrt]  unk chain!!!\n"));
						break;
					}
					if (ci.args.add_unique(a)) {
						MSG_DI2(("[hrt]   add arg: %s\n", a.dstr()));
					}
					break;
				} //chain's blocks loop may be stopped on the first found using has been defined outside
			}// block_chains_begin -- block_chains_next

			const block_chains_t& duc = du[b->serial];
			MSG_DI2(("[hrt] %a: %3d du chain: %s\n", b->start, b->serial, duc.dstr()));
			for (block_chains_iterator_t dui = block_chains_begin(&duc); dui != block_chains_end(&duc); dui = block_chains_next(dui)) {
				const chain_t& ch = block_chains_get(dui);
				mlist_t chLst; chain_append_list(ch, mba, &chLst);

				//is already listed
				if(defs.includes(chLst))
					continue;
				//skip chains defined in head block but above hfirst
				if(hud == b->serial && !chLst.has_common(hdefs))
					continue;
				//skip chains defined in exit block but below exitlast
				if(eud == b->serial && !chLst.has_common(edefs))
					continue;

				for (size_t i = 0; i < ch.size(); i++) {
					sBB tmp(ch.at(i)); // block that uses the instruction
					if(hud == tmp.idx) {
						//check if it used in head block below hfirst
						if(chLst.is_subset_of(huses))
							continue;
					} else if(eud == tmp.idx) {
						//check if it used in exit block above exitlast
						if(chLst.is_subset_of(euses))
							continue;
					} else if (path.has_item(&tmp)) // continue search if in-path definition is used inside path
						continue;

					chain_append_list(ch, mba, &defs);
					MSG_DI2(("[hrt]  %a: %3d defs ext-%d use %s\n", b->start, b->serial, tmp.idx, ch.dstr()));;
					if (!bHave1Ret && ch.is_reg()) {
						int reg = mreg2regWchk(ch.get_reg(), ch.width);
						if (reg == -1)
							break; // ignore bad and segment registers
						ci.return_type = get_unk_type(ch.width);
						if (ci.return_type.empty()) {
							MSG_DI2(("[hrt] !get_unk_type: %s  %x\n", ch.dstr(), ch.width));
							break;
						}
						chain_append_list(ch, mba, &retregs);
						mop_t& rr = ci.retregs.push_back();
						rr.create_from_mlist(mba, chLst, mba->fullsize);
						ci.return_argloc.set_reg1(reg);
						bHave1Ret = true;
						MSG_DI2(("[hrt]   add return: %s\n", ch.dstr()));
					}
					break;
				} //chain's blocks loop may be stopped on the first found definition has been used outside
			} //block_chains_begin -- block_chains_next
			//spoiled.add(b->mustbdef);
		} // path nodes loop
	}

	//---------------------------------------------------------------------------
	// huses may get smth is defined inside head block above hfirst, not in ud chain
	// add it to arguments too
	huses.sub(uses); // remove already found
	uses.add(huses); // add not found
	minsn_t* hlastNext = hlast;
	if (hlastNext)
		hlastNext = hlastNext->next;
	while(!huses.empty()) {
		MSG_DI2(("[hrt] huses left: %s\n", huses.dstr()));
		mlist2mop_t mlist2mop;
		if (!headb->for_all_uses(&huses, hfirst, hlastNext, mlist2mop) || !mlist2mop.mop) {
			MSG_DI2(("[hrt] !for_all_uses: %s \n", huses.dstr()));
			break;
		}
		mlist_t mopl;
		headb->append_use_list(&mopl, *mlist2mop.mop, MUST_ACCESS);

		mcallarg_t a;
		if (!a.create_from_mlist(mba, mopl, mba->fullsize)) {
			MSG_DI2(("[hrt] !a.create_from_mlist: %s  %x\n", mopl.dstr()));
			break;
		}
		a.type = get_unk_type(mlist2mop.mop->size);
		if (a.type.empty()) {
			MSG_DI2(("[hrt] !get_unk_type: %x\n", mlist2mop.mop->size));
			break;
		}
		if (mlist2mop.mop->is_reg()) {
			int reg = mreg2regWchk(mlist2mop.mop->r, mlist2mop.mop->size);
			if (reg == -1)
				break;
			a.argloc.set_reg1(reg);
		} else if (mlist2mop.mop->t == mop_S) {
			sval_t vdoff;
			if(!mlist2mop.mop->get_stkoff(&vdoff)) {
				MSG_DI2(("[hrt] !get_stkoff: %s\n", mlist2mop.mop->dstr()));
				break;
			}
			a.argloc.set_stkoff(vdoff);//is here IDA or decompiler stkoff?
		} else {
			MSG_DI2(("[hrt]  unk mop!!!\n"));
			break;
		}
		if (ci.args.add_unique(a)) {
			MSG_DI2(("[hrt]   add arg: %s\n", a.dstr()));
		}
		huses.sub(mopl);
	}

	//---------------------------------------------------------------------------
	// hdefs of single block may be used inside of the block below hlast, but not exist in du chain
	// also
	// edefs of tail block may be used inside of the block below exitlast, but not exist in du chain
	// add it to returns too
	if(!bHave1Ret && (iexit->kind == eBBK_tail || ihead->kind == eBBK_single)) {
		edefs.add(hdefs); // mix all together
		edefs.sub(defs);  // remove already found
		defs.add(edefs);
		mblock_t* blk = headb;
		minsn_t* first = hlast;
		if(iexit->kind == eBBK_tail) {
			blk = exitb;
			first = exitlast;
		}
		if(first && first->next) {
			first = first->next;
			//check if tail micro inctructions of the block use any of edefs
			while(!edefs.empty()) {
				MSG_DI2(("[hrt] edefs left: %s\n", edefs.dstr()));
				mlist2mop_t mlist2mop;
				if (!blk->for_all_uses(&edefs, first, nullptr, mlist2mop) || !mlist2mop.mop) {
					MSG_DI2(("[hrt] !for_all_uses: %s \n", edefs.dstr()));
					break;
				}
				mlist_t mopl;
				blk->append_def_list(&mopl, *mlist2mop.mop, MUST_ACCESS);
				if (mlist2mop.mop->is_reg()) {
					int reg = mreg2regWchk(mlist2mop.mop->r, mlist2mop.mop->size);
					if (reg == -1)
						break; // ignore bad and segment registers
					ci.return_type = get_unk_type(mlist2mop.mop->size);
					if (ci.return_type.empty()) {
						MSG_DI2(("[hrt] !get_unk_type: %x\n", mlist2mop.mop->size));
						break;
					}
					retregs.add(mopl);
					mop_t& rr = ci.retregs.push_back();
					rr.create_from_mlist(mba, mopl, mba->fullsize);
					ci.return_argloc.set_reg1(reg);
					bHave1Ret = true;
					MSG_DI2(("[hrt]   add return: %s\n", rr.dstr()));
					break;
				}
				edefs.sub(mopl);
			}
		}
	}

	//---------------------------------------------------------------------------

	ci.cc = CM_CC_SPECIAL;
	ci.solid_args = (int)ci.args.size();
	ci.spoiled.add(defs.reg); //spoiled);
	ci.dead_regs.add(defs.reg);
	ci.return_regs.add(defs.reg);
	if(!bHave1Ret)
		ci.return_type.create_simple_type(BTF_VOID);
	else
		ci.dead_regs.sub(retregs);
	//ci->flags |= FCI_HASCALL;

#if DEBUG_DI > 1
	msg("[hrt] uses: %s\n", uses.dstr());
	msg("[hrt] defs: %s\n", defs.dstr());
	//msg("spoiled: %s\n", spoiled.dstr());
	msg("[hrt] callinfo: %s\n", ci.dstr());
#endif

	//---------------------------------------------------------------------------
	headb->mustbuse.clear();// = uses;
	headb->maybuse.clear();// = uses;
	headb->mustbdef.clear();// = defs;
	headb->maybdef.clear();// = defs;
	headb->dnu.clear();// = defs;
	headb->flags &= ~MBL_CALL; // necessary if remove a call from the block
	headb->mark_lists_dirty();

	//make helper call
	minsn_t* call = new minsn_t(headEa);
	call->opcode = m_call;
	call->l.make_helper(inl->name.c_str());
	if(bHave1Ret)
		call->d.size = (int)ci.return_type.get_size();
	else
		call->d.size = 0;
	call->d._make_callinfo(new mcallinfo_t(ci));

	//destroy old headb microcode
	minsn_t* prev = hfirst->prev;
	minsn_t* ins = hfirst;
	while (ins && ins != hlastNext) {
		MSG_DI2(("[hrt] %a: delete %s in blk %d\n", ins->ea, ins->dstr(), headb->serial));
		minsn_t* next = headb->remove_from_block(ins);
		delete ins;
		ins = next;
	}

	//insert helper call to head block
	headb->insert_into_block(call, prev);

	// nothing to do with predecessors and successors for single node path
	if (ihead->kind == eBBK_single)
		return true;

	//destroy old exitb microcode
	if (exitlast) {
		minsn_t* ins = exitb->head;
		while (ins != exitlast->next) {
			minsn_t* next = ins->next;
			MSG_DI2(("[hrt] %a: delete %s in blk %d\n", ins->ea, ins->dstr(), exitb->serial));
			exitb->remove_from_block(ins);
			delete ins;
			ins = next;
		}
	}

	//remove predecessors of head are accessed from inside path
	for (auto pi = headb->predset.begin(); pi != headb->predset.end(); ) {
		sBB tmp(*pi);
		if (path.has_item(&tmp))
			pi = headb->predset.erase(pi);
		else
			pi++;
	}

	//single succ of head to exit node
	headb->succset.resize(1);
	headb->succset[0] = exitb->serial;
	headb->type = BLT_1WAY;

	//remove preds of exit to path
	for (auto pit = exitb->predset.begin(); pit != exitb->predset.end(); ) {
		sBB bb(*pit);
		if (path.has_item(&bb))
			pit = exitb->predset.erase(pit); //no break, remove all links into path
		else
			pit++;
	}
	//add pred of exit to head
	exitb->predset.push_back(headb->serial);

	//create jmp to exit microcode
	minsn_t* jmp = new minsn_t(headEa + 1);
	jmp->opcode = m_goto;
	jmp->l._make_blkref(exitb->serial);
	headb->insert_into_block(jmp, headb->tail);

	//detach nodes of path (except head and exit)
	for (auto node : path) {
		mblock_t* blk = mba->natural[node->idx];
		if(blk == headb || blk == exitb)
			continue;
		blk->succset.clear();
		blk->predset.clear();
		blk->type = BLT_NONE;
		MSG_DI2(("[hrt] %a: detach blk %d\n", blk->start, blk->serial));
		removeBlocks.insert(blk);
	}
	return true;
}


struct ida_local sBBGrpMatcher {
	bbs_t     allBBs;   // all blocks of considered MBA
	inlines_t inlFound;

	~sBBGrpMatcher()
	{
		allBBs.destroy();
	}

	void selection2inline(mbl_array_t *mba)
	{
		if (selection_bgn == BADADDR || selection_end == BADADDR)
			return;

		sInline *inl = new sInline();
		bool res = inl->create_from_entry_exit(mba, &allBBs, selection_bgn, selection_end);
		if (res)
			inlinesLib.insert(inl);
		else
			delete inl;

		selection_bgn = BADADDR;
		selection_end = BADADDR;
	}

	void findMatchedInlines()
	{
		for(auto il : inlinesLib) {
			paths_t grp;
			il->path.make_matched(il->name.c_str(), grp, allBBs);
			if(grp.size()) {
				if(il->bTmp) {
					il->bTmp = false; //unmark temporary inlines
					Log(llDebug, "inline '%s' validated\n", il->name.c_str());
				}
				inlFound[il] = grp;
			}
		}
	}

	bool replaceInlines(mbl_array_t *mba)
	{
#if DEBUG_DI > 2
		ShowMicrocodeExplorer(mba, "before replaceInlines");
#endif
		bool cm_changed = false;
		mba->dump_mba(false, "[hrt] before replaceInlines");
		mblockset_t removeBlocks;
		bbs_t usedBBs;
		for (auto i : inlFound) {
			const paths_t& grp = i.second;
			for (auto j : grp) {
				ea_t inlEa = j.first;
				const path_t& path = j.second;

				//check for overlapped inlines
				bool dup = false;
				for (auto pi : path) {
					if (usedBBs.has(pi)) {
						dup = true;
						break;
					}
				}
				if (dup) {
					Log(llDebug, "%a: skip overlapped inline '%s'\n", inlEa, i.first->name.c_str());
					path.print("  ");
					continue;
				}
				Log(llInfo, "%a: substitute inline: %s\n", inlEa, i.first->name.c_str());
				path.print("   ");
				for (auto pi : path)
					usedBBs.add(pi);

				cm_changed |= inlReplace(mba, i.first, inlEa, path, removeBlocks);
			}
		}
		if(cm_changed) {
#if DEBUG_DI > 2
			ShowMicrocodeExplorer(mba, "after replaceInlines1");
#endif
			for (auto rb : removeBlocks)
				mba->remove_block(rb); //causes blocks renumbering, so after this point all my 'bb->idx' are incorrect
			mba->mark_chains_dirty();
			mba->dump_mba(true, "[hrt] after replaceInlines");
			cm_changed |= mba->merge_blocks();
#if DEBUG_DI > 2
			ShowMicrocodeExplorer(mba, "after replaceInlines2");
#endif
		}
		return cm_changed;
	}

	qstring getPathStr(const pathstr_t &p)
	{
		qstring path;
		for (auto n : p) {
			path.cat_sprnt("%d_", n);
		}
		return path;
	}

#if DEBUG_DI
	void printPathStr(const pathstr_t &p, const char* fmt, ...)
	{
		qstring m;
		va_list va;
		va_start(va, fmt);
		m.cat_vsprnt(fmt, va);
		va_end(va);

		qstring path = getPathStr(p);
		msg("[hrt] %s pathstr: %s\n", m.c_str(), path.c_str());
	}

	void printInlines()
	{
		if (inlFound.size())
			msg("[hrt] found inlines:\n");
		int idx = 0;
		for(auto i : inlFound) {
			const paths_t& grp = i.second;
			msg("[hrt] inline%d %s (%d)\n", idx++, i.first->name.c_str(), (int)grp.size());
			for(auto g : grp)
				g.second.print("  ");
		}
	}

#else //DEBUG_DI
	void printPathStr(const pathstr_t &p, const char* fmt, ...) {}
	void printInlines() {}
#endif //DEBUG_DI

	bool deinline(mbl_array_t *mba)
	{
		allBBs.makeCFG(mba);
		selection2inline(mba);
		findMatchedInlines();
		printInlines();
		if (inlFound.size())
			return replaceInlines(mba);
		return false;
	}
};

static std::map<ea_t, sBBGrpMatcher> matchers;
static std::set<ea_t> disabled_matchers;
static std::set<ea_t> has_inlines_cache;

bool deinline(mbl_array_t *mba)
{
	if(!inlinesLib.size() && (selection_bgn == BADADDR || selection_end == BADADDR))
		return false;
	if (disabled_matchers.find(mba->entry_ea) != disabled_matchers.end())
		return false;
	MSG_DI1(("[hrt] deinline at %d maturity\n", mba->maturity));
	if(mba->maturity < DEINLINE_MATURITY)
		return false;
	auto it = matchers.find(mba->entry_ea);
	if (it != matchers.end()) {
		// deinline may be called few times while decompiling one function -  process only once
		MSG_DI1(("[hrt] deinline already called\n"));
		return false;
	}
	if(!matchers[mba->entry_ea].deinline(mba))
		return false;
	has_inlines_cache.insert(mba->entry_ea);
	return true;
}

void deinline_reset(ea_t entry_ea)
{
	//avoid dropping when showing hint for snipped started from function entry
	if(disabled_matchers.find(entry_ea) == disabled_matchers.end())
		matchers.erase(entry_ea);
}

//cleaning not more used matchers
static std::map<vdui_t *, ea_t> vdui2ea;
void deinline_reset(vdui_t *vu, bool closeWnd)
{
	auto it = vdui2ea.find(vu);
	if (closeWnd) {
		if (it != vdui2ea.end()) {
			matchers.erase(it->second);
			vdui2ea.erase(it);
		}
		return;
	}
	if (vdui2ea[vu] != vu->cfunc->entry_ea)
		matchers.erase(vdui2ea[vu]);
	vdui2ea[vu] = vu->cfunc->entry_ea;
}

//----------------------------------------------

static sBBGrpMatcher *getMatcher(ea_t ea)
{
	auto it = matchers.find(ea);
	if (it == matchers.end())
		return nullptr;
	return &it->second;
}

bool hasInlines(vdui_t *vu, bool* bEnabled)
{
	bool disabled = false;
	if (disabled_matchers.find(vu->cfunc->entry_ea) != disabled_matchers.end())
		disabled = true;

	if (bEnabled)
		*bEnabled = !disabled;

	return disabled || has_inlines_cache.find(vu->cfunc->entry_ea) != has_inlines_cache.end();
}

void XXable_inlines(ea_t entry_ea, bool bDisable)
{
	if (bDisable)
		disabled_matchers.insert(entry_ea);
	else
		disabled_matchers.erase(entry_ea);
}

static const path_t* getInlPath(vdui_t *vu, qstring &name)
{
	if (!vu->item.is_citem() || vu->item.e->op != cot_helper)
		return nullptr;
	const sBBGrpMatcher *matcher = getMatcher(vu->cfunc->entry_ea);
	if (!matcher)
		return nullptr;

	cexpr_t *e = vu->item.e;
	name = e->helper;
	sInline i(name.c_str());
	inlines_t::const_iterator ii = matcher->inlFound.find(&i);
	if (ii == matcher->inlFound.end())
		return nullptr;

	citem_t *call = vu->cfunc->body.find_parent_of(e);
	QASSERT(100210, call->op == cot_call);

	paths_t::const_iterator pi = ii->second.find(call->ea);
	if (pi == ii->second.end())
		return nullptr;

	return &pi->second;
}

bool is_inline(vdui_t *vu)
{
	qstring name;
	if (getInlPath(vu, name))
		return true;
	return false;
}

void ren_inline(vdui_t *vu)
{
	if (!vu || !vu->item.is_citem() || vu->item.e->op != cot_helper)
		return;
	sBBGrpMatcher *matcher = getMatcher(vu->cfunc->entry_ea);
	if (!matcher)
		return;

	cexpr_t *e = vu->item.e;
	qstring name(e->helper);
	sInline i(name.c_str());
	auto li = inlinesLib.find(&i);
	if (li == inlinesLib.end() || (*li)->bLib) {
		warning("[hrt] could not rename a library inline\n"
			"%s\n"
			"rename the corresponding file in\n"
			"%s\n"
			"and restart IDA"
			, name.c_str(), sInlinesLib::getBasePath().c_str());
		return;
	}

	auto ii = matcher->inlFound.find(&i);
	if (ii == matcher->inlFound.end() || ii->first->bLib)
		return;

	qstring newname = name;
	while (1) {
		if (!ask_ident(&newname, "[hrt] Please enter new inline name (empty name to delete"))
			return;
		if (!newname.length()) {
			if (ASKBTN_YES != ask_yn(ASKBTN_YES, "[hrt] delete %s", name.c_str()))
				continue;
			matcher->inlFound.erase(ii);
			inlinesLib.erase(li);
			vu->refresh_view(true);
			return;
		}
		sInline i(newname.c_str());
		if (matcher->inlFound.find(&i) == matcher->inlFound.end() && !inlinesLib.has(newname.c_str()))
			break;
		Log(llError, "inline '%s' already exist\n", newname.c_str());
	}

	bool allFound = true;
	for (auto pi : ii->second) {
		const path_t& p = pi.second;
		citem_t *item = vu->cfunc->body.find_closest_addr(p.front()->bgn);
		if (item && item->op == cot_call && static_cast<cexpr_t*>(item)->x->op == cot_helper &&!qstrcmp(name.c_str(), static_cast<cexpr_t*>(item)->x->helper)) {
			cexpr_t* call = static_cast<cexpr_t*>(item);
			cexpr_t* newHlp = create_helper(false, call->x->type, "%s", newname.c_str());
			if (newHlp) {
				call->x->replace_by(newHlp);
				continue;
			}
		}
		allFound = false;
	}

	(*li)->name = newname;
#if __cplusplus > 201402L // C++17
	inlinesLib.insert(inlinesLib.extract(li));
#else
	{
		sInline* i = *li;
		inlinesLib.erase(li);
		inlinesLib.insert(i);
	}
#endif
	if(allFound)
		vu->cfunc->refresh_func_ctext();
	else
		vu->refresh_view(true);
}

int deinline_hint(vdui_t *vu, qstring *result_hint, int *implines)
{
	//this may be a bad idea, decompile_snippet can optimize away code is not used inside snippet (but used outside)
	qstring name;
	const path_t* path = getInlPath(vu, name);
	if (!path)
		return 0;

	rangevec_t ranges;
	for (auto b : *path)
		ranges.push_back(range_t(b->bgn, b->end));

	hexrays_failure_t hf;
	ea_t entry_ea = path->front()->bgn;
	XXable_inlines(entry_ea, true); // temporary disable inlines
	cfuncptr_t cf = decompile_snippet(ranges, &hf, DECOMP_NO_WAIT | DECOMP_NO_FRAME);
	XXable_inlines(entry_ea, false); // enable inlines
	result_hint->cat_sprnt("inline %s\n", name.c_str());
	if (hf.code == MERR_OK) {
		cf->statebits |= CFS_LVARS_HIDDEN; // hide local variables to get cf->hdrlines depending only on number of arguments
		const strvec_t &sv = cf->get_pseudocode();
		for (int i = 0; i < sv.size(); i++) {
			if(cf->hdrlines > 5 && i > 2 && i < cf->hdrlines - 3) {
				if(i == 3)
					result_hint->cat_sprnt("  " COLSTR("//    ... skipped args",SCOLOR_COLLAPSED) "\n");
				continue; //skip a lot of arguments
			}
			result_hint->cat_sprnt("%s\n", sv[i].line.c_str());
		}
		if (sv.size() > 24)
			*implines = 25;
		else
			*implines = (int)sv.size() + 1;
	} else {
		result_hint->cat_sprnt("decompile_snippet error %d: %s\n", hf.code, hf.desc().c_str());
		*implines = 2;
	}
#if IDA_SDK_VERSION < 760
	  ///< Possible return values:
	  ///<  0: the event has not been handled
	  ///<  1: hint has been created (should set *implines to nonzero as well)
	  ///<  2: hint has been created but the standard hints must be
	  ///<     appended by the decompiler
	return 2;
#else //IDA_SDK_VERSION >= 760
    ///< Possible return values:
    ///< \retval 0 continue collecting hints with other subscribers
    ///< \retval 1 stop collecting hints
  return 0;
#endif //IDA_SDK_VERSION < 760
}

bool inl_create_from_whole_mba(mbl_array_t *mba, const char* name, qstring* errorStr)
{
	sInline *inl = new sInline();
	bool res = inl->create_from_whole_mba(mba, name, errorStr);
	if(res)
		inlinesLib.insert(inl);
	else
		delete inl;
	return res;
}

void selection2inline(ea_t bgn, ea_t end)
{
	selection_bgn = bgn;
	selection_end = end;
}

//----------------------------------------------
void save_inlines()
{
	if(inlinesLib.size())
		inlinesLib.save();
}

void deinline_init()
{
	inlinesLib.load();
}

void deinline_done()
{
	//inlinesLib.save();
}

