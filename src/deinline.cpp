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
	This feature is inspired by ideas of GraphSlick plugin(https://github.com/lallousx86/GraphSlick)
*/

//set 1 to enable automatic inlines detection like in GraphSlick (https://github.com/lallousx86/GraphSlick)
#define ENABLE_FIND_MATCHED_PATHS 0

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
class ida_local lessBBaddr {
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
	iterator getNextMatched(const sBB* bb, const_iterator startFrom) const;
};

typedef uint32 cmdtype_t;                             // microcode opcode and args types packed in one dword
typedef std::map<cmdtype_t, uint32>      freq_t;      // cmdtype_t frequency dictionary
typedef std::pair<bbs_t::iterator, bool> bbsIns_t;    // bbs_t insertion result
typedef qvector<bbs_t>                   fmtch_t;     // groups of freq matched blocks
typedef std::pair<sBB*, sBB*>            twoBB_t;     // head/exit pair or parts of two paths in pathsStk_t
typedef std::stack<twoBB_t>              pathsStk_t;  // temporary stack for building paths
typedef std::basic_string<char32_t>      pathstr_t;   // group numbers in path

class ida_local lessPSLen {
public:
	bool operator()(const pathstr_t& x, const pathstr_t& y) const;
};
class path_t;
typedef std::map<const sBB*, path_t, lessBBaddr> paths_t;     // storage of found normalized paths, key is head block addr
typedef std::map<pathstr_t, paths_t, lessPSLen>  samePaths_t; // same paths groups
typedef std::map<qstring, paths_t>               inlines_t;   // resulting named paths groups
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

//basic-block class
struct ida_local sBB {
	ea_t bgn;
	ea_t end;
	bbs_t  preds;
	bbs_t  succs;
	freq_t freq;
	uint32 instCnt;
	int32 matchGrpIdx;
	int32 idx; //idx of block inside mba or path

	sBB(ea_t bgn_, ea_t end_, int idx_) : bgn(bgn_), end(end_), instCnt(0), matchGrpIdx(-1), idx(idx_) {}
	sBB(int idx_) : bgn(BADADDR), end(BADADDR), instCnt(0), matchGrpIdx(-1), idx(idx_) {}
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
	}
	bool match(const sBB* bb) const
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
	void serialize(bytevec_t &b, bool bNoFreq = false) const
	{
		b.append("sBB ", 4);
		b.append(&idx, sizeof(idx));
		ssze_t fsz = static_cast<ssze_t>(freq.size());
		if (bNoFreq)
			fsz = 0;
		b.append(&fsz, sizeof(fsz));
		if (!bNoFreq) {
			for (auto fi = freq.begin(); fi != freq.end(); fi++) {
				b.append(&fi->first, sizeof(fi->first));
				b.append(&fi->second, sizeof(fi->first));
			}
		}
		// preds and succs are saved and restored inside path_t
	}
	static sBB* deserialize(const uchar **ptr, const uchar *end)
	{
		#define ADV_PTR(sz) { *ptr += sz; if(*ptr > end) return NULL; }
		while(memcmp("sBB ", *ptr, 4))
			ADV_PTR(1);
		ADV_PTR(4);
		sBB bb(*reinterpret_cast<const decltype(idx)*>(*ptr));
		ADV_PTR(sizeof(decltype(idx)));
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
		return new sBB(bb);
		#undef ADV_PTR
	}
};

bool lessBBidx::operator()(const sBB* x, const sBB* y) const
{
	return x->idx < y->idx;
}

bool lessBBaddr::operator()(const sBB* x, const sBB* y) const
{
	return x->bgn < y->bgn;
}

void bbs_t::destroy()
{
	for(auto it = begin(); it != end(); it++)
		delete *it;
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
	for(auto it = begin(); it != end(); it++) {
		b.append(&(*it)->idx, sizeof((*it)->idx));
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

bbs_t::iterator bbs_t::getNextMatched(const sBB* bb, bbs_t::const_iterator startFrom) const
{
	auto it = startFrom;
	for(; it != end(); it++) {
		if(bb->match(*it))
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
		// check paths has no enties from outside except head
		if (size() > 1) {
			auto pi = begin(); pi++;
			for (; pi != end(); pi++) {
				for (auto p = (*pi)->preds.begin(); p != (*pi)->preds.end(); p++) {
					if (!has_item(*p)) {
						if (errorStr)
							errorStr->sprnt("Inline applicant has entrance into the middle (from block %a to block %a). Head block %a must be a single entry",
							(*p)->bgn, (*pi)->bgn, front()->bgn);
						return false;
					}
				}
			}
		}
		// check paths has no any other exit outside
		for (auto pi = begin(); pi != end(); pi++) {
			for (auto s = (*pi)->succs.begin(); s != (*pi)->succs.end(); s++) {
				if (!has_item(*s) && *s != exit) {
					if (errorStr)
						errorStr->sprnt("Inline applicant has more then one exit (from block %a to block %a). Exit block %a must be alone",
						(*pi)->bgn, (*s)->bgn, exit->bgn);
					return false;
				}
			}
		}

		// check single node paths is large enought
		if (size() < 2 && front()->instCnt < MIN_LEN_OF_1_BLOCK_INLINE) {
			if (errorStr)
				errorStr->sprnt("Single block inline applicant at %a has %d microcode instructions, should be at least %d",
					front()->bgn, front()->instCnt, MIN_LEN_OF_1_BLOCK_INLINE);
			return false;
		}
		return true;
	}
	bool create_from_head_exit(sBB* head, sBB* exit_, qstring* errorStr)
	{
		clear();
		exit = exit_;

		push_back(head);
		std::stack<sBB*> queue;
		queue.push(head);
		while (!queue.empty()) {
			sBB* bb = queue.top();
			queue.pop();
			for (auto s = bb->succs.begin(); s != bb->succs.end(); s++) {
				if (!has_item(*s) && *s != exit) {
					push_back(*s);
					queue.push(*s);
				}
			}
		}
		bool res = validate(errorStr);
		if (res) {
			this->print("path created:");
		}
		return res;
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
			if (errorStr)
				errorStr->sprnt("No head block found for inline applicant %a", mba->entry_ea);
			allBBs.destroy();
			return false;
		}
		if(!exit) {
			if (errorStr)
				errorStr->sprnt("No exit block found for inline applicant %a", mba->entry_ea);
			allBBs.destroy();
			return false;
		}
		bool res = create_from_head_exit(head, exit, errorStr);
		if(res) {
			//free blocks not in path
			for(auto b = allBBs.begin(); b != allBBs.end(); b++)
				if (!has_item(*b) && *b != exit)
					delete *b;
		} else {
			allBBs.destroy();
		}
		return res;
	}
	bool create_from_entry_exit(mbl_array_t *mba, bbs_t *allBBs, ea_t head_ea, ea_t exit_ea)
	{
		sBB* head = nullptr;
		sBB* exit = nullptr;
		for (int n = 0; n < mba->qty; n++) {
			sBB* bb = allBBs->get(n);
			assert(bb);
			if (bb->bgn == head_ea)
				head = bb;
			else if(bb->bgn == exit_ea)
				exit = bb;
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
		bool res = create_from_head_exit(head, exit, &errorStr);
		if (res) {
			//path contains block pointers from allBBs being invalid when allBBs be destroyed, make copy ot them
			bytevec_t buf;
			serialize(buf);
			clear();
			const uchar* ptr = &buf[0];
			deserialize(&ptr, &buf[buf.size()]);
		} else {
			Log(llError, "Inline applicant %a-%a error:%s\n", head_ea, exit_ea, errorStr.c_str());
		}
		return res;
	}
	void make_matched(paths_t &grp, const bbs_t &src) const
	{
		sBB* head1 = front();
		for(auto hi = src.getNextMatched(head1, src.begin()); hi != src.end(); hi = src.getNextMatched(head1, ++hi)) {
			sBB* head2 = *hi;
			sBB* exit2 = nullptr;
			path_t path2;
			path2.push_back(head2);
			MSG_DI2(("[hrt] start make path from: %a\n", head2->bgn));
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
				bool bNoMatches = false;
				for (auto s2 = bb2->succs.begin(); s2 != bb2->succs.end(); s2++) {
					if (!path2.has_item(*s2) && visited2.insert(*s2).second) {
						auto s1 = bb1->succs.begin();
						for (; s1 != bb1->succs.end(); s1++) {
							if (*s1 != exit && !matched1.has(*s1) && (*s1)->match(*s2)) {
								MSG_DI2(("[hrt]   add matched bb: %a\n", (*s2)->bgn));
								path2.push_back(*s2);
								matched1.insert(*s1);
								queue.push(twoBB_t(*s1, *s2));
								break;
							}
						}
						if (s1 == bb1->succs.end()) {
							if (!exit2 || *s2 == exit2) { //Sic! *s2 == exit2 for break! avoids setting bNoMatches = true
								exit2 = *s2;
								MSG_DI2(("[hrt]   exit: %a\n", exit2->bgn));
								break;
							} else {
								bNoMatches = true;
								MSG_DI2(("[hrt]   no matches for %a\n", (*s2)->bgn));
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
					grp[path2.front()] = path2;
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
//		b.append("Path", 4);
		ssze_t sz = static_cast<ssze_t>(size());
		b.append(&sz, sizeof(sz));
		decltype(sBB::idx) idx = 0;
		for (auto it = begin(); it != end(); it++, idx++) {
			const sBB* bb = *it;
			bb->serialize(b);
		}
		exit->serialize(b, true);
		//preds and succs
		for (auto it = begin(); it != end(); it++, idx++) {
			const sBB* bb = *it;
			//bb->preds.serialize(b); //preds are not really need to store
			bb->succs.serialize(b);
		}
	}
	bool deserialize(const uchar **ptr, const uchar *end_)
	{
		#define ADV_PTR(sz) { *ptr += sz; if(*ptr > end_) return false; }
/*
		while(memcmp("Path", *ptr,  4))
			ADV_PTR(1);
		ADV_PTR(4);
*/
		bbs_t allBlocks;
		ssze_t sz = *reinterpret_cast< const decltype(sz)*>(*ptr);
		ADV_PTR(sizeof(decltype(sz)));
		while ( sz-- ) {
			sBB* bb = sBB::deserialize(ptr, end_);
			push_back(bb);
			allBlocks.add(bb);
		}
		QASSERT(100203, allBlocks.size() == size());
		sBB* exi = sBB::deserialize(ptr, end_);
		allBlocks.add(exi);
		exit = exi;

		//preds and succs
		for (auto it = begin(); it != end(); it++) {
			sBB* bb = *it;
			//preds are not really need to store
			//if(!bb->preds.deserialize(allBlocks, ptr, end_))
			//	return false;
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
				path.cat_sprnt("%a", (*n)->bgn);
			}
			Log(llDebug, "%s %a-%a (%ui/%db): %s\n", m.c_str(), front()->bgn, exit ? exit->bgn : BADADDR, instCnt, (int)size(), path.c_str());
		} else {
			Log(llDebug, "%s None-%a empty-path\n", m.c_str(), exit ? exit->bgn : BADADDR);
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
		for (auto it = begin(); it != end(); it++) {
			sInline *inl = *it;
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
			fullpath = unique_name(fullpath.c_str(), "-", [](const qstring& n) {qstring p(n); p.append(".inl"); return !qfileexist(p.c_str()); });
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

	for (auto pi = path.begin(); pi != path.end(); pi++) {
		t.text.cat_sprnt("Block %d: %a-%a\n", (*pi)->idx, (*pi)->bgn, (*pi)->end);
		mba->natural[(*pi)->idx]->print(vp);
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

struct ida_local sBBGrpMatcher {
	bbs_t     allBBs;
	bbs_t     usedBBs;
	fmtch_t   fmatches;
	inlines_t inlines;

	~sBBGrpMatcher()
	{
		allBBs.destroy();
	}

	void matchBBs()
	{
		bbs_t src = allBBs; // clears src during matching
		for(auto i = src.begin(); i != src.end(); i = src.erase(i)) {
			if(usedBBs.has(*i))
				continue;  //do not consider blocks included into found inlines
			bbs_t g;
			g.add(*i);
			auto j = i;
			for(j++; j != src.end(); ) {
				if ((*i)->match(*j)) {
					g.add(*j);
					j = src.erase(j); 
				}	else {
					j++;
				}
			}
			if(g.size() > 1) {
				for(auto b = g.begin(); b != g.end(); b++)
					(*b)->matchGrpIdx = static_cast<decltype(sBB::matchGrpIdx)>(fmatches.size());
				fmatches.push_back(g);
			}
		}
		QASSERT(100208, src.empty());
		printFMatches();
	}

	void findMatchedPaths()
	{
		matchBBs();

		samePaths_t samePaths;
		for (size_t i = 0; i < fmatches.size(); i++) {
			bbs_t& mi = fmatches[i];
			// Find equivalent paths from two equivalent nodes
			for (auto b1 = mi.begin(); b1 != mi.end(); b1++) {
				auto b2 = b1;
				for (b2++; b2 != mi.end(); b2++) {
					path_t path1;
					path_t path2;
					path1.push_back(*b1);
					path2.push_back(*b2);
					MSG_DI2(("[hrt] start build path from: %a and %a\n", (*b1)->bgn, (*b2)->bgn));
					bbs_t visited1, visited2;
					pathsStk_t queue;
					queue.push(twoBB_t(*b1, *b2));
					while (!queue.empty()) {
						sBB* bb1 = queue.top().first;
						sBB* bb2 = queue.top().second;
						queue.pop();
						if (bb1->succs.size() != bb2->succs.size())
							break;
						for (auto s1 = bb1->succs.begin(); s1 != bb1->succs.end(); s1++) {
							if ((*s1)->matchGrpIdx != -1 && !path1.has_item(*s1) && !path2.has_item(*s1) && visited1.insert(*s1).second) {
								bool matched = false;
								auto s2 = bb2->succs.begin();
								for (; s2 != bb2->succs.end(); s2++) {
									if (*s1 != *s2 && (*s1)->matchGrpIdx == (*s2)->matchGrpIdx &&
										!path2.has_item(*s2) && !path1.has_item(*s2) && visited2.insert(*s2).second)
									{
										matched = true;
										break;
									}
								}
								if (matched) {
									MSG_DI2(("[hrt]   add matched pair: %a and %a\n", (*s1)->bgn, (*s2)->bgn));
									path1.push_back(*s1);
									path2.push_back(*s2);
									queue.push(twoBB_t(*s1, *s2));
								}
							}
						}
					}
					assert(path1.size() == path2.size());
					sBB* head1 = path1.front();
					sBB* head2 = path2.front();
#if DEBUG_DI > 1
					path1.print("initial 1:");
					path2.print("        2:");
#endif

					if (path1.size() > 1) {
						// trim both paths to be single entry
						bool changedH = false;
						for (;;) {
							bool bRemove = false;
							auto pi1 = path1.begin(); pi1++;
							auto pi2 = path2.begin(); pi2++;
							for (; pi1 != path1.end() /* && pi2 != path2.end()*/; pi1++, pi2++) {
								for (auto p1 = (*pi1)->preds.begin(); p1 != (*pi1)->preds.end(); p1++) {
									if (!path1.has_item(*p1)) {
										bRemove = true;
										MSG_DI2(("[hrt] pred out of path1, remove %a and %a\n", (*pi1)->bgn, (*pi2)->bgn));
										path1.remove(pi1);
										path2.remove(pi2);
										break;
									}
								}
								if (!bRemove) {
									for (auto p2 = (*pi2)->preds.begin(); p2 != (*pi2)->preds.end(); p2++) {
										if (!path2.has_item(*p2)) {
											bRemove = true;
											MSG_DI2(("[hrt] pred out of path2, remove %a and %a\n", (*pi1)->bgn, (*pi2)->bgn));
											path1.remove(pi1);
											path2.remove(pi2);
											break;
										}
									}
								}
								if (bRemove) {
									changedH = true;
									break;
								}
							}
							if (!bRemove) {
								break;
							}
							//continue;
						}
						if (changedH) {
							head1 = path1.front();
							head2 = path2.front();
#if DEBUG_DI > 1
							path1.print("trimmedHead 1:");
							path2.print("            2:");
#endif
							assert(path1.size() == path2.size());
						}
					}

					// trim both paths to be single exit (exit node is out of path)
					sBB* exit1 = nullptr;
					sBB* exit2 = nullptr;
					bool changedE = false;
					for (;;) {
						bool bRemove = false;
						auto pi1 = path1.begin();
						auto pi2 = path2.begin();
						for (; pi1 != path1.end() /* && pi2 != path2.end()*/; pi1++, pi2++) {
							//for (ssize_t j = path1.size() - 1; j >= 0 && !bRemove ; j--) {
							for (auto s1 = (*pi1)->succs.begin(); s1 != (*pi1)->succs.end(); s1++) {
								if (!path1.has_item(*s1)) {
									if (!exit1)
										exit1 = *s1;
									else if (exit1 != *s1) {
										bRemove = true;
										MSG_DI2(("[hrt] succ out of path1, remove %a and %a\n", (*pi1)->bgn, (*pi2)->bgn));
										path1.remove(pi1);
										path2.remove(pi2);
										exit1 = nullptr; exit2 = nullptr;
										break;
									}
								}
							}
							if (!bRemove) {
								for (auto s2 = (*pi2)->succs.begin(); s2 != (*pi2)->succs.end(); s2++) {
									if (!path2.has_item(*s2)) {
										if (!exit2)
											exit2 = *s2;
										else if (exit2 != *s2) {
											bRemove = true;
											MSG_DI2(("[hrt] succ out of path2, remove %a and %a\n", (*pi1)->bgn, (*pi2)->bgn));
											path1.remove(pi1);
											path2.remove(pi2);
											exit1 = nullptr; exit2 = nullptr;
											break;
										}
									}
								}
							}
							if (bRemove) {
								changedE = true;
								break;
							}
						}
						if (!bRemove)
							break;
					}
					assert(path1.size() == path2.size());
					if (changedE) {
#if DEBUG_DI > 1
						path1.print("trimmedTail 1:");
						path2.print("            2:");
#endif
						if (!path1.size()) {
							MSG_DI2(("[hrt] no single exit found\n"));
							continue;
						}
						if (head1 != path1.front() || head2 != path2.front()) {
							MSG_DI2(("[hrt] head is cut off\n"));
							continue;
						}
					}
					if (!exit1 || !exit2) {
						MSG_DI2(("[hrt] should not get here, no single exit found\n"));
						continue;
					}

					// include paths in set only if they are large enought
					uint32 instCnt1 = 0;
					uint32 instCnt2 = 0;
					for (auto it = path1.begin(); it != path1.end(); it++) instCnt1 += (*it)->instCnt;
					for (auto it = path2.begin(); it != path2.end(); it++) instCnt2 += (*it)->instCnt;
					if (path1.size() < 3 || instCnt1 < 30 || instCnt2 < 30) {
						MSG_DI2(("[hrt] skip too short path (%d block(s), %d m-inst)\n", (int)path1.size(), instCnt1));
						continue;
					}

					//set exit nodes of paths
					path1.exit = exit1;
					path2.exit = exit2;

					pathstr_t pathStr;
					for (auto it = path1.begin(); it != path1.end(); it++)
						pathStr.append(1, uint32((*it)->matchGrpIdx));
					paths_t &paths = samePaths[pathStr];
					paths[head1] = path1;
					paths[head2] = path2;
#if DEBUG_DI > 1
					printPathStr(pathStr, "found pair");
					path1.print(" 1:");
					path2.print(" 2:");
#endif
				}
			}
		}
		fmatches.clear(); //no need any more
		if (!samePaths.size())
			return;
#if DEBUG_DI
		Log(llDebug, "found %d similar paths\n", (int)samePaths.size());
		int idx = 0;
		for (auto p = samePaths.begin(); p != samePaths.end(); p++) {
			printPathStr(p->first, "%d (%d)", idx++, (int)p->second.size());
			for (auto pp = p->second.begin(); pp != p->second.end(); pp++)
				pp->second.print(" ");
		}
#endif
		//remove shorter paths are included into longer
		//samePaths are stored size ascending (lessPSLen sorting care)
		for (auto shrt = samePaths.begin(); shrt != samePaths.end(); ) {
			auto lng = shrt;
			bool remove = false;
			for (lng++; lng != samePaths.end(); lng++) {
				if (shrt->first.length() <= lng->first.length()) { //get rid of equal len paths too
					//first check short path string is substring of longer path, and shorter path have not more numbers of found paths
					if (lng->first.find(shrt->first) != pathstr_t::npos &&  shrt->second.size() <= lng->second.size()) {
						remove = true;
#if DEBUG_DI > 1
						printPathStr(shrt->first, "remove (%d)", (int)shrt->second.size());
						printPathStr(lng->first, " included in (%d)", (int)lng->second.size());
#endif
						break;
					} else {
						//check every node of shorter path is not part of longer
						for (auto sp = shrt->second.begin(); sp != shrt->second.end(); ) { //paths in shorter group
							bool bFound = false;
							for (auto sn = sp->second.begin(); sn != sp->second.end() && !bFound; sn++) { //nodes in shorter path
								for (auto lp = lng->second.begin(); lp != lng->second.end(); lp++) { //paths in longer group
									if (lp->second.has_item(*sn)) {
										bFound = true;
										break;
									}
								}
							}
							if (bFound) {
#if DEBUG_DI > 1
								sp->second.print("remove");
								printPathStr(shrt->first, " from group (%d)", (int)shrt->second.size());
								printPathStr(lng->first, " has node included in (%d)", (int)lng->second.size());
#endif
								sp = shrt->second.erase(sp);
							}	else {
								sp++;
							}
						}
						if (shrt->second.size() < 2) { //remove empty and single-path groups
							remove = true;
#if DEBUG_DI > 1
							printPathStr(shrt->first, "remove empty or single group");
#endif
							break;
						}
					}
				}
			}
			if (remove)
				shrt = samePaths.erase(shrt);
			else
				shrt++;
		}
		if (!samePaths.size())
			return;
#if DEBUG_DI > 1
		Log(llDebug, "after removing includes: %d similars\n", (int)samePaths.size());
		idx = 0;
		for (auto p = samePaths.begin(); p != samePaths.end(); p++)
			printPathStr(p->first, "%d (%d)", idx++, (int)p->second.size());
#endif
		//make results 
		for (auto p = samePaths.begin(); p != samePaths.end(); p++) {
			assert(p->second.size());
			paths_t &grp = p->second;
			qstring name;
			name.sprnt("inline_%s", getPathStr(p->first).c_str());
			inlines[name] = p->second;
		}
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
		for(auto ili = inlinesLib.begin(); ili != inlinesLib.end(); ili++) {
			paths_t grp;
			(*ili)->path.make_matched(grp, allBBs);
			if(grp.size()) {
				if((*ili)->bTmp) {
					(*ili)->bTmp = false; //unmark temporary inlines
					Log(llDebug, "inline '%s' validated\n", (*ili)->name.c_str());
				}
				for(auto gi = grp.begin(); gi != grp.end(); gi++)
					for(auto i = gi->second.begin(); i != gi->second.end(); i++)
						usedBBs.add(*i);
				inlines[(*ili)->name] = grp;
			}
		}
	}

	bool replaceInlines(mbl_array_t *mba)
	{
		bool cm_changed = false;
		cm_changed = mba->merge_blocks();// does not work
		mba->dump_mba(false, "[hrt] before replaceInlines");
		std::set<mblock_t *> removeBlocks;
		bbs_t processedBBs;
		//const ivl_t &lvars_region = mba->get_lvars_region();
		//const ivl_t &args_region = mba->get_args_region();
		//for (int n = 0; n < mba->qty; n++) msg("%a %d/%d  ", mba->natural[n]->start, mba->natural[n]->serial, n); msg("\n");
		for (auto i = inlines.begin(); i != inlines.end(); i++) {
				const paths_t& grp = i->second;
				for (auto j = grp.begin(); j != grp.end(); j++)  {
					const sBB    *head = j->first;
					const path_t &path = j->second;

					//check for overlapped inlines
					bool dup = false;
					for(auto pi = path.begin(); pi != path.end(); pi++) {
						if(processedBBs.has(*pi)) {
							dup	= true;
							break;
						}
					}
					if(dup) {
						Log(llDebug, "%a: skip overlapped inline '%s'\n", head->bgn, i->first.c_str());
						path.print("  ");
						continue;
					}
					Log(llInfo, "%a: substitute inline: %s\n", head->bgn, i->first.c_str());
					for(auto pi = path.begin(); pi != path.end(); pi++)
						processedBBs.add(*pi);

					mlist_t uses;   //collect uses are defined somewhere outside before "inline"
					mlist_t defs;   //collect defines are used somewhere after "inline"
					mlist_t retregs;
					mcallinfo_t *ci = new mcallinfo_t();
					bool bHave1Ret = false;
					//mlist_t spoiled;//collect defines inside "inline" spoils registers
					{
						// get use-def chains. do it inside a block in order to release
						// the chains immediately after using them
						mbl_graph_t *graph = mba->get_graph();
						chain_keeper_t ud = graph->get_ud(GC_REGS_AND_STKVARS);
						chain_keeper_t du = graph->get_du(GC_REGS_AND_STKVARS);

						for (auto n = path.begin(); n != path.end(); n++) {
							mblock_t *b = mba->get_mblock((*n)->idx);
							//b->make_lists_ready(); it doesnt helps
							const block_chains_t &udc = ud[b->serial];
							MSG_DI2(("[hrt] %a: %3d ud chain: %s\n", b->start, b->serial, udc.dstr()));
							for(block_chains_iterator_t udi = block_chains_begin(&udc); udi != block_chains_end(&udc); udi = block_chains_next(udi)) {
								const chain_t & ch = block_chains_get(udi);
								for (size_t i = 0; i < ch.size(); i++ ) {
									sBB tmp(ch.at(i)); // block that defines the instruction
									if(!path.has_item(&tmp)) {
										mlist_t al;
#if IDA_SDK_VERSION < 760
										ch.append_list(&uses);
										ch.append_list(&al);
#else
										ch.append_list(mba, &uses);
										ch.append_list(mba, &al);
#endif
										MSG_DI2(("[hrt] %a: %3d uses ext def %s\n", b->start, b->serial, ch.dstr()));
										mcallarg_t a;
										if (!a.create_from_mlist(mba, al, mba->fullsize)) {
											MSG_DI2(("[hrt] !a.create_from_mlist: %s  %x\n", ch.dstr(), ch.width));
											continue; //break;
										}
										a.type = get_unk_type(ch.width);
										if (a.type.empty()) {
											MSG_DI2(("[hrt] !get_unk_type: %s  %x\n", ch.dstr(), ch.width));
											continue; //break;
										}
										if (ch.is_reg()) {
											int reg = mreg2reg(ch.get_reg(), ch.width);
											if (reg == -1 || (ch.width == PH.segreg_size && (PH.reg_first_sreg <= reg && reg <= PH.reg_last_sreg))) {// || (reg == ph.reg_code_sreg || reg == ph.reg_data_sreg)))
												MSG_DI2(("[hrt] ignore bad and segment registers\n"));
												continue; //break;
											}
											a.argloc.set_reg1(reg);
										} else if (ch.is_stkoff()) {
											a.argloc.set_stkoff(ch.get_stkoff());
										} else {
											MSG_DI2(("[hrt]  unk chain!!!\n"));
											continue; //break;
										}
										if (ci->args.add_unique(a)) {
											MSG_DI2(("[hrt]   add arg: %s\n", a.dstr()));
										}
										//break;
									}
								}
							}
							const block_chains_t &duc = du[b->serial];
							MSG_DI2(("[hrt] %a: %3d du chain: %s\n", b->start, b->serial, duc.dstr()));
							for(block_chains_iterator_t dui = block_chains_begin(&duc); dui != block_chains_end(&duc); dui = block_chains_next(dui)) {
								const chain_t & ch = block_chains_get(dui);
								for (size_t i = 0; i < ch.size(); i++ ) {
									sBB tmp(ch.at(i)); // block that uses the instruction
									if(!path.has_item(&tmp)) {
#if IDA_SDK_VERSION < 760
										ch.append_list(&defs);
#else
										ch.append_list(mba, &defs);
#endif
										MSG_DI2(("[hrt]  %a: %3d defs ext use %3d %s\n", b->start, b->serial, ch.at(i), ch.dstr()));;
										if (!bHave1Ret && ch.is_reg()) {
											int reg = mreg2reg(ch.get_reg(), ch.width);
											if (reg == -1 || (ch.width == PH.segreg_size && (PH.reg_first_sreg <= reg && reg <= PH.reg_last_sreg)))// || (reg == PH.reg_code_sreg || reg == PH.reg_data_sreg)))
												break; // ignore bad and segment registers
											ci->return_type = get_unk_type(ch.width);
											if (ci->return_type.empty()) {
												MSG_DI2(("[hrt] !get_unk_type: %s  %x\n", ch.dstr(), ch.width));
												break;
											}
											mlist_t al;
#if IDA_SDK_VERSION < 760
											ch.append_list(&al);
											ch.append_list(&retregs);
#else
											ch.append_list(mba, &al);
											ch.append_list(mba, &retregs);
#endif
											mop_t &rr = ci->retregs.push_back();
											rr.create_from_mlist(mba, al, mba->fullsize);
											ci->return_argloc.set_reg1(reg);
											bHave1Ret = true;
											MSG_DI2(("[hrt]   add return: %s\n", ch.dstr()));
										}
										break;
									}
								}
							}
							//spoiled.add(b->mustbdef);
						}
					}
#if 0
					headb->mustbuse.clear();
					headb->mustbuse.add(headb->maybuse);
					//set defs same as dnu
					headb->mustbdef.clear();
					headb->maybdef.clear();
					headb->mustbdef.add(headb->dnu);
					headb->maybdef.add(headb->dnu);
#else
					mblock_t *headb = mba->get_mblock(head->idx);
					headb->mustbuse = uses;
					headb->maybuse = uses;
					headb->mustbdef = defs;
					headb->maybdef = defs;
					headb->dnu = defs;
					//spoiled = defs;	spoiled.mem.clear();
#endif

#if 0
					msg("+headb->maybuse: %s\n", headb->maybuse.dstr());
					msg("+headb->maybdef: %s\n", headb->maybdef.dstr());
					msg("+headb->dnu: %s\n", headb->dnu.dstr());
					//msg("+spoiled: %s\n", spoiled.dstr());
#endif
					//replace head microcode to helper call
					minsn_t* call = new minsn_t(headb->start);
					call->opcode = m_call;
					call->l.make_helper(i->first.c_str());
					ci->cc = CM_CC_SPECIAL;
#if 0
					int sz = 1;
					for (auto ur = headb->maybuse.reg.begin(); ur != headb->maybuse.reg.end(); headb->maybuse.reg.inc(ur, sz)) {
						sz = headb->maybuse.reg.count(*ur);
						QASSERT(100209, sz != 0);
						if (sz > ea_size) {
							MSG_DI2(("[hrt] consecutive regs? sz %d ()\n", sz));
							sz = ea_size;
						}
						int reg = mreg2reg(*ur, sz);
						if (reg == -1 || 
							(sz == PH.segreg_size && (PH.reg_first_sreg <= reg && reg <= PH.reg_last_sreg)))// || (reg == PH.reg_code_sreg || reg == PH.reg_data_sreg)))
							continue; // ignore bad and segment registers

						mcallarg_t ma;
						ma.set_regarg(*ur, sz, get_unk_type(sz));
						ma.argloc.set_reg1(reg);
						ci->args.add(ma);
					}

					if (!headb->maybuse.mem.empty()) {
						MSG_DI2(("maybuse.mem: %s\n", headb->maybuse.mem.dstr()));
						for (size_t umi = 0; umi < headb->maybuse.mem.nivls(); umi++) {
							const ivl_t & um = headb->maybuse.mem.getivl(umi);
							if (lvars_region.includes(um)) {
								MSG_DI2(("[hrt]  stack var: %s -- %x.%x\n", um.dstr(), (int)(um.off - lvars_region.off), um.size));
							} else if (args_region.includes(um)) {
								MSG_DI2(("[hrt]  stack arg: %s -- %x.%x\n", um.dstr(), (int)(um.off - args_region.off), um.size));
							} else
								continue;
							ivlset_t ivs;
							ivs.add(um);
							mcallarg_t a;
							if (a.create_from_ivlset(mba, ivs, mba->fullsize)) {
								if (um.size <= ea_size) {
									a.type = get_unk_type(um.size);
								} else {
									MSG_DI2(("[hrt] strange size: %s  %x\n", um.dstr(), um.size));
									a.type = dummy_ptrtype(um.size, false);
									continue;//!!!
								}
								a.argloc.set_stkoff(um.off - lvars_region.off);
								ci->args.add(a);
							}
						}
					}
#endif
					ci->solid_args = (int)ci->args.size();
					ci->spoiled.add(headb->mustbdef); //spoiled);
					ci->dead_regs.add(headb->dnu);
					ci->return_regs.add(headb->mustbdef);
					if (!bHave1Ret) {
						ci->return_type.create_simple_type(BTF_VOID); //FIXME: return struct with defines
						call->d.size = 0;
					} else {
						call->d.size = (int)ci->return_type.get_size(); //call returns size
						ci->dead_regs.sub(retregs);
					}
					//ci->flags |= FCI_HASCALL;

					MSG_DI2(("[hrt] callinfo: %s\n", ci->dstr()));
					call->d._make_callinfo(ci);
					

					headb->flags &= ~MBL_CALL; // necessary if remove a call from the block
					//headb->flags |= MBL_CALL;

					//destroy old headb microcode
					while(headb->head) {
						minsn_t *ins = headb->head;
						headb->remove_from_block(ins);
						delete ins;
					}

					//set new microcode
					headb->insert_into_block(call, nullptr);
					headb->mark_lists_dirty();

					//if (path.size() > 1)
					{
						sBB *exit = j->second.exit;
						mblock_t *exitb = mba->get_mblock(exit->idx);

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
						minsn_t* jmp = new minsn_t(headb->start + 1);
						jmp->opcode = m_goto;
						jmp->l._make_blkref(exitb->serial);
						headb->insert_into_block(jmp, headb->tail);

						//remove nodes of path (except head)
						auto node = path.begin();
						for (node++; node != path.end(); node++) {
							mblock_t *blk = mba->natural[(*node)->idx];
							blk->succset.clear();
							blk->predset.clear();
							blk->type = BLT_NONE;
							removeBlocks.insert(blk);
						}
					}
					cm_changed = true;
				}
			}
			for(auto rbi = removeBlocks.begin(); rbi != removeBlocks.end(); rbi++)
				mba->remove_block(*rbi); //causes blocks renumbering, so after this point all my 'bb->idx' are incorrect
			
		mba->mark_chains_dirty();
		mba->dump_mba(true, "[hrt] after replaceInlines");
		return cm_changed;
	}

	qstring getPathStr(const pathstr_t &p)
	{
		qstring path;
		for (auto n = p.begin(); n != p.end(); n++) {
			path.cat_sprnt("%d_", *n);
		}
		return path;
	}

#if DEBUG_DI
	void printFMatches()
	{
		if (fmatches.size())
			Log(llDebug, "similar blocks:\n");
		bbs_t dupes;
		for (size_t i = 0; i < fmatches.size(); i++) {
			const bbs_t& grp = fmatches[i];
			qstring str;
			str.sprnt("grp%d (%d): ", (int)i, (int)grp.size());
			for (auto j = grp.begin(); j != grp.end(); j++) {
				str.cat_sprnt("%a ", (*j)->bgn);
				bbsIns_t result = dupes.insert(*j);
				if(!result.second)
					str.cat_sprnt("DUPEZZ! ");
			}
			Log(llDebug, "%s\n", str.c_str());
		}
	}

	void printPathStr(const pathstr_t &p, const char* fmt, ...)
	{
		qstring m;
		va_list va;
		va_start(va, fmt);
		m.cat_vsprnt(fmt, va);
		va_end(va);

		qstring path = getPathStr(p);
		Log(llDebug, "%s pathstr: %s\n", m.c_str(), path.c_str());
	}

	void printInlines()
	{
		if (inlines.size())
			Log(llDebug, "found inlines:\n");
		int idx = 0;
		for(auto i = inlines.begin(); i != inlines.end(); i++) {
			const paths_t& grp = i->second;
			Log(llDebug, "inline%d %s (%d)\n", idx++, i->first.c_str(), (int)grp.size());
			for(auto j = grp.begin(); j != grp.end(); j++) 
				j->second.print("  ");
		}
	}

#else //DEBUG_DI
	void printFMatches() {}
	void printPathStr(const pathstr_t &p, const char* fmt, ...) {}
	void printInlines() {}
#endif //DEBUG_DI

	bool deinline(mbl_array_t *mba) 
	{
		allBBs.makeCFG(mba);
		selection2inline(mba);
		findMatchedInlines();
#if ENABLE_FIND_MATCHED_PATHS
		//enable automatic inlines detection like in GraphSlick (https://github.com/lallousx86/GraphSlick)
		findMatchedPaths();
#endif
		printInlines();
		if (inlines.size())
			return replaceInlines(mba);
		return false;
	}
};

static std::map<ea_t, sBBGrpMatcher> matchers;
static std::set<ea_t> disabled_matchers;
static std::set<ea_t> has_inlines_cache;

bool deinline(mbl_array_t *mba)
{
#if ENABLE_FIND_MATCHED_PATHS
	//do not check were inlines loaded
#else
	if(!inlinesLib.size() && (selection_bgn == BADADDR || selection_end == BADADDR))
		return false;
#endif
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
	auto ii = matcher->inlines.find(name);
	if (ii == matcher->inlines.end())
		return nullptr;

	citem_t *call = vu->cfunc->body.find_parent_of(e);
	QASSERT(100210, call->op == cot_call);

	sBB tmp(call->ea, BADADDR, -1);
	auto pi = ii->second.find(&tmp);
	if (pi == ii->second.end())
		return nullptr;

	return &pi->second;
}

bool is_nlib_inline(vdui_t *vu)
{
	qstring name;
	if (!getInlPath(vu, name))
		return false;

	sInline i(name.c_str());
	auto li = inlinesLib.find(&i);
	if (li == inlinesLib.end() || !(*li)->bLib)
		return true;
	return false;
}

bool ren_inline(vdui_t *vu)
{
	if (!vu->item.is_citem() || vu->item.e->op != cot_helper)
		return false;
	sBBGrpMatcher *matcher = getMatcher(vu->cfunc->entry_ea);
	if (!matcher)
		return false;

	cexpr_t *e = vu->item.e;
	qstring name(e->helper);
	auto ii = matcher->inlines.find(name);
	if (ii == matcher->inlines.end())
		return false;

	qstring newname = name;
	while (1) {
		if (!ask_ident(&newname, "[hrt] Please enter inline name"))
			return false;
		if (!newname.length())
			continue;
		if (matcher->inlines.find(newname) == matcher->inlines.end() && !inlinesLib.has(newname.c_str()))
			break;
		Log(llError, "inline '%s' already exist\n", newname.c_str());
	} 

	for (auto pi = ii->second.begin(); pi != ii->second.end(); pi++) {
		const path_t& p = pi->second;
		citem_t *item = vu->cfunc->body.find_closest_addr(p.front()->bgn);
		if (item && item->op == cot_call && static_cast<cexpr_t*>(item)->x->op == cot_helper) {
			cexpr_t* call = static_cast<cexpr_t*>(item);
			cexpr_t* newHlp = create_helper(false, call->x->type, newname.c_str());
			if (newHlp)
				call->x->replace_by(newHlp);
		}
	}

	std::swap(matcher->inlines[newname], ii->second);
	matcher->inlines.erase(ii);

	sInline i(name.c_str());
	auto li = inlinesLib.find(&i);
	if (li != inlinesLib.end() && !(*li)->bLib) {
		(*li)->name = newname;
#if __cplusplus > 201402L // C++17
		inlinesLib.insert(inlinesLib.extract(li));
#else
		sInline *i = *li;
		inlinesLib.erase(li);
		inlinesLib.insert(i);
#endif
	}
	return true;
}

int deinline_hint(vdui_t *vu, qstring *result_hint, int *implines)
{
	//this may be a bad idea, decompile_snippet can optimize away code is not used inside snippet (but used outside)
	qstring name;
	const path_t* path = getInlPath(vu, name);
	if (!path)
		return 0;
	
	rangevec_t ranges;
//	if (path->front()->bgn < path->exit->bgn) {
//		ranges.push_back(range_t(path->front()->bgn, path->exit->bgn));
//	} else {
		for (auto b = path->begin(); b != path->end(); b++)
			ranges.push_back(range_t((*b)->bgn, (*b)->end));
		//ranges.push_back(range_t(path->exit->bgn, path->exit->end)); //EXPEREMENTAL: add exit node
//	}

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

//TODO:
// - relaxed block matching for head blocks
// - compare imm constants (call dests)

