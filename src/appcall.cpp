/*
    Copyright © 2017-2025 AO Kaspersky Lab.

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
  This feature is inspired by ideas of Krypton plugin by Karthik Selvaraj(https://www.hex-rays.com/contests/2012/Krypton_2012_Hex-Rays_Contest.zip)
  that uses IDA's powerful Appcall feature(https://hex-rays.com/wp-content/uploads/2019/12/debugging_appcall.pdf) - call functions inside the debugged program
  The main problem of Krypton - it can't deal with mixed registers/stack arguments because tries to analyze low level assembler code.
  This implementation takes everything from Hex-Rays generated pseudocode.
 */

#ifdef _MSC_VER
#define _CRT_NO_VA_START_VALIDATION
#endif
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wvarargs"
#endif


#include "warn_off.h"
#include <hexrays.hpp>
#include <dbg.hpp>
#include "warn_on.h"

#include "helpers.h"
#include "appcall.h"
#include "appcall_view.h"
#include "decr.h"


#define FIRST_PATCH_EA
#define DEBUG_AC 0

static bool getStringFromBuf(const char* buf, int buflen, qstring *str, int32 strtype, bool bAuto)
{
	if(!buf)
		return false;

	if(strtype == STRTYPE_C) {
		for(int i = 0; i < buflen; i++) {
			unsigned char ch = buf[i];
			if(ch == 0) {
				str->append(buf, i);
				return true;
			}
			if(bAuto && (ch >= 128 || (ch < ' ' && !qstrchr("\a\b\f\n\r\t\v",ch))))
				return false;
		}
	} 
	else if(strtype == STRTYPE_C_16) {
		for(int i = 0; i < buflen; i++) {
			wchar16_t ch = *((wchar16_t*)buf +i);
			if(ch == 0) {
				return utf16_utf8(str, (wchar16_t*)buf, i);
			}
			if(bAuto && (ch >= 128 || (ch < ' ' && !qstrchr("\a\b\f\n\r\t\v",(char)ch))))
				return false;
		}
	}
	return false;
}

static bool getStringFromMem(ea_t ea, qstring *str, int32 strtype, bool bAuto)
{
	if(!ea)
		return false;
	qstring name;
	size_t len = get_max_strlit_length(ea, strtype, ALOPT_IGNHEADS);
	if(len && get_strlit_contents(&name, ea, len, strtype) > 0) {
		str->append(name);
		return true;
	}
	char buf[MAXSTR * 2];
	ssize_t rdsz = read_dbg_memory(ea, buf, MAXSTR*2);
	if(!rdsz)
		return false;
	return getStringFromBuf(buf, MAXSTR, str, strtype, bAuto);
}

bool idaapi is_appcallable(vdui_t *vu, cexpr_t **pcall, ea_t *dstea)
{
	if (!vu->item.is_citem())
		return false;
	cexpr_t * callDst = vu->item.e;
	if (callDst->op == cot_obj) {
		citem_t *call = vu->cfunc->body.find_parent_of(callDst);
		if (call && call->op == cot_cast)
			call = vu->cfunc->body.find_parent_of(call);
		if (call && call->op == cot_call) {
			ea_t ea = callDst->obj_ea;
      if (is_mapped(ea)) {
				if(dstea)
					*dstea = ea;
				if(pcall)
					*pcall = (cexpr_t *)call;
				return true;
			}
		}
	}
	return false;
}

struct ida_local appcallable_locator_t : public ctree_visitor_t
{
	ea_t dstea;
	cexpr_t *call;
	appcallable_locator_t(ea_t _dstea): ctree_visitor_t(CV_FAST), dstea(_dstea), call(NULL) {}
	int idaapi visit_expr(cexpr_t * e)
	{
		if(e->op == cot_call) {
			cexpr_t *callDst = e->x;
			if(callDst->op == cot_obj) {
				ea_t ea = callDst->obj_ea;
        if (is_mapped(ea) && dstea == ea) {
					call = e;
					return 1; //stop
				}
			}
		}
		return 0; //continue
	}
};

static cexpr_t * findCall(cfunc_t* func, const ea_t callea, const ea_t calldstea)
{
	eamap_t &eamap = func->get_eamap();
	eamap_iterator_t eait = eamap_find(&eamap, callea);
	if(eait == eamap_end(&eamap))
		return NULL;
	cinsnptrvec_t& insvec = eamap_second(eait);
	for(cinsnptrvec_t::iterator iit = insvec.begin(); iit != insvec.end(); iit++) {
		cinsn_t *stmt = *iit;
		appcallable_locator_t loc(calldstea);
		loc.apply_to(stmt, NULL);
		if(loc.call)
			return loc.call;
	}
	return NULL;
}

bool Appcaller::init(bool dbg, uint32 keyArg, uint32 keyLenArg, ea_t callea, uint32 resArgNum_, int32 strtype_, eACStrDisp disp, ea_t ib, ea_t ie)
{
	//force close opened form to avoid crash
	close_appcall_view();

	bDbgEngine = dbg;
	keyArgNum = keyArg;
	keyLenArgNum = keyLenArg;
	oldDebuggerOptions = 0;
	funcea = callea;
	strtype = strtype_;
	resDisp = disp;
	initStart = ib;
	initStop = ie;
	calls.clear();
	multilineCmt = false;
	resArgNum = resArgNum_;
	if(!get_tinfo(&tif, funcea)) {
		Log(llError, "no typeinfo for %a\n", funcea);
		return false;
	}
	qstring typeStr;
	tif.print(&typeStr);
	if(!tif.is_decl_func()) {
		Log(llError, "%a not function type %s\n", funcea, typeStr.c_str());
		return false;
	}

	if(!tif.get_func_details(&fi)) {
		Log(llError, "get_func_details failed for %a\n", funcea);
		return false;
	}

	size_t nargs = fi.size();
	if(resArgNum > nargs || keyArgNum > nargs || keyLenArgNum > nargs) {
		Log(llError, "Wrong arg selected (%u, %u, %u), this function has only %u (pls check func type 'Y')\n", (uint32_t)resArgNum, (uint32_t)keyArgNum, (uint32_t)keyLenArgNum, (uint32_t)fi.size());
		return false;
	}

	return true;
}

bool Appcaller::initDbg()
{
	if(!bDbgEngine) {
		int64 itCnt = -1;
		ushort itSz = strtype == STRTYPE_C_16 ? 1 : 0;
		return decr_init(&itCnt, &itSz);
	}

	isDbgRunning = get_process_state();
	if (DSTATE_RUN == isDbgRunning) {
		return false;
	}

	oldDebuggerOptions = set_debugger_options(DOPT_ENTRY_BPT | DOPT_LIB_MSGS | DOPT_THREAD_MSGS | DOPT_THREAD_BPT | DOPT_START_BPT);
	inf_set_appcall_options(APPCALL_DEBEV);

	if(DSTATE_NOTASK != isDbgRunning) {
		if(initStart)
			Log(llWarning, "Warning: debugger is already running so initializer call has been skipped\n");
		return true;
	}

	qstring idbPath = get_path(PATH_TYPE_IDB);
	idbPath.append(".bak");
	save_database(idbPath.c_str(), 0/*DBFL_BAK*/);

	if(start_process(NULL, NULL, NULL) == 1) {
		if(wait_for_next_event(WFNE_SUSP/*WFNE_ANY*/, -1) >= 0) {//after this call ida think that debugger is in suspended state
			if(initStart) {
				do {
					//wait_for_next_event(WFNE_SUSP /*WFNE_ANY*/, -1);
					const debug_event_t* ev = get_debug_event();
					if(!ev || ev->eid() == PROCESS_EXITED || ev->eid() == PROCESS_DETACHED) {
						Log(llError, "Debugger exit while within Init\n");
						set_debugger_options(oldDebuggerOptions);
						return false;
					}
					if(ev->eid() == PROCESS_STARTED || ev->eid() == PROCESS_ATTACHED) {
						//TODO: check processor
						const char* ipName = "EIP";
						if(is64bit())
							ipName = "RIP";
						set_reg_val(ipName, initStart);
						run_to(initStop);
					}
					if(ev->eid() == EXCEPTION /*&& !ev->exc.can_cont*/) {
						Log(llError, "Debugger catch exception %x at %a while Init, if the exception should be handled by app try \"Debugger->Debugger Options->Edit Exceptions->Edit->Pass to application\"\n", ev->exc().code, ev->exc().ea);
						doneDbg();
						return false;
					}
					if(ev->eid() == BREAKPOINT)
						return true;
				} while (wait_for_next_event(WFNE_CONT | WFNE_SUSP /*WFNE_ANY*/, -1) >= 0); // WFNE_CONT need for remote debugger
				Log(llWarning, "Debugger exit1 while within Init\n");
			}
			return true;
		}
	}
	Log(llError, "Failed to launch debugger\n");
	set_debugger_options(oldDebuggerOptions);
	return false;
}

void Appcaller::doneDbg()
{
	if(!bDbgEngine)
		return;

	//stop debugger if it was started by Appcaller only
	if(DSTATE_NOTASK == isDbgRunning) {
		exit_process();
		for(int i = 0; i < 10; i++) {
			dbg_event_code_t code = wait_for_next_event(WFNE_ANY, 1);
			if(/*code == PROCESS_EXIT || code == PROCESS_DETACH ||*/ code == DEC_NOTASK || code == DEC_ERROR)
				break;
		}
#if IDA_SDK_VERSION < 750 //IDA 7.5 and later instead open_pseudocode(OPF_REUSE) opens new window
		vdui_t * ui = COMPAT_open_pseudocode_REUSE(saveViewProcEa);
		if(ui && savePlace)
			jumpto(ui->ct, savePlace, saveX, saveY);
#endif //IDA_SDK_VERSION < 750
	}
	set_debugger_options(oldDebuggerOptions);
}

void makeBufVal(idc_value_t &val, char idx)
{
	qstring gvarName("ht_appcall_buf");
	gvarName.append('0'+idx);
	idc_value_t *v = add_idc_gvar(gvarName.c_str());
	v->set_string("");
	v->qstr().resize(1024, 0);
	create_idcv_ref(&val, v);
}

bool Appcaller::getArgv(cexpr_t *call, qvector<idc_value_t> &argv, ea_t* patchea, qstring &error)
{
	if(call->op != cot_call)
		return false;
	carglist_t &args = *call->a;
	size_t argnum = args.size();

	if(fi.size() != args.size()) {
		//TODO check vararg(,...)
		error = "wrong arguments number in call";
		return false;
	}

	qstring argsStr;
	argv.resize(argnum);
	for(size_t i = 0; i < argnum; i++) {
		bool bufArg = false;
		cexpr_t *arg = skipCast(&args[i]); //ignore typecast
		switch (arg->op)
		{
		case cot_num:
			argv[i].set_int64(arg->numval());
			break;
		case cot_str:
			argv[i].set_string(arg->string);
			break;
		case cot_obj:
			argv[i].set_int64(arg->obj_ea);
#ifdef FIRST_PATCH_EA
			if(*patchea == BADADDR && i != keyArgNum - 1)
#endif //FIRST_PATCH_EA
			{
				*patchea = arg->obj_ea;
			}
			break;
		case cot_ref:
			if(arg->x->op == cot_obj) {
				argv[i].set_int64(arg->x->obj_ea);
#ifdef FIRST_PATCH_EA
				if(*patchea == BADADDR && i != keyArgNum - 1)
#endif //FIRST_PATCH_EA
				{
					*patchea = arg->x->obj_ea;
				}
				break;
			} else if(arg->x->op == cot_var) {
				bufArg = true;
				break;
			}
			//!!! fall down to return
		case cot_var:
			bufArg = true;
			break;
		case cot_memptr:
		case cot_memref:
		default:
			error.sprnt("don't know what to do with argument %u", (uint32_t)(i + 1));
			bufArg = true;
			//dont return here, arg will be used for single call
		}
		if(bufArg)
			makeBufVal(argv[i], (char)i);

#if DEBUG_AC
		if(bufArg) {
			//buffer
			argsStr.append("buffer[1024]");
		} else {
			qstring oneArg;
			print_idcv(&oneArg, argv[i]);
			argsStr.append(oneArg);
		}
		if(argnum > 1 && i != argnum - 1)
			argsStr.append(", ");
	}
	qstring funcname = get_short_name(funcea);
	Log(llFlood, "%a: prep dbg_appcall %s(%s)\n", call->ea, funcname.c_str(), argsStr.c_str());
#else //DEBUG_AC
	}
#endif //DEBUG_AC
	return true;
}

bool Appcaller::getString(idc_value_t &r, qstring *decodedStr, qstring &error)
{
	switch(r.vtype) {
	case VT_LONG:
	case VT_INT64:
		{
		ea_t ea = r.vtype == VT_LONG ? r.num : (ea_t)r.i64;
#if DEBUG_AC
		Log(llFlood, "getString VT_LONG/VT_INT64 %a\n", ea);
#endif //DEBUG_AC
		if(is_mapped(ea)) {
			if(resDisp != acsdArray) { //acsdAuto || acsdPointer
				ea_t ea2 = get_ea(ea);
				if(is_mapped(ea2)) {
					if(getStringFromMem(ea2, decodedStr, strtype, resDisp == acsdAuto))
						return true;
				}
			}
			if(resDisp != acsdPointer) { //acsdAuto || acsdArray
				if(getStringFromMem(ea, decodedStr, strtype, resDisp == acsdAuto))
					return true;
			}
		}
		error.cat_sprnt(" can't get string from %a, try to change type of expected string to void*", ea);
		return false;
		}
	case VT_STR:
		{
#if DEBUG_AC
			Log(llFlood, "getString VT_STR %d '%s'\n", r.qstr().length(),  r.c_str());
#endif //DEBUG_AC
			if(resDisp != acsdArray && r.qstr().size() >= ea_size) { //acsdAuto || acsdPointer
				ea_t ea2 = *(ea_t*)r.qstr().begin();
				if(is_mapped(ea2)) {
					if(getStringFromMem(ea2, decodedStr, strtype, resDisp == acsdAuto))
						return true;
				}
			}
			if(resDisp != acsdPointer) { //acsdAuto || acsdArray
				if(getStringFromBuf(r.qstr().begin(), (int)r.qstr().size(), decodedStr, strtype, resDisp == acsdAuto))
					return true;
			}
			if(strtype == STRTYPE_C_16)
				return utf16_utf8(decodedStr, (const wchar16_t *)r.qstr().begin());
			else
				*decodedStr = r.qstr();
			return true;
		}
	case VT_REF: 
		{
#if DEBUG_AC
		Log(llFlood, "getString VT_REF \n");
#endif //DEBUG_AC
			idc_value_t *v  = deref_idcv(&r, VREF_ONCE);
			bool ret = getString(*v, decodedStr, error);

			//make advice
			if(ret && !strlen(decodedStr->c_str()) && resArgNum > 0 /*&& resArgNum < fi.size()*/) {
					tinfo_t argt = fi[resArgNum - 1].type;
					if(!argt.is_pvoid())
						Log(llWarning, "advice: Ida's dbg_appcall so capricious, pls try void* type for argument %d '%s'\n", resArgNum, fi[resArgNum - 1].name.c_str());
			}

			//clear global buf for future use
			QASSERT(100301, v->vtype == VT_STR);
			v->qstr().fill(0, 0, 1024);
			return ret;
		}
	}
	error.cat_sprnt(" unknown appcall result type %d, try to change type of expected value to void*", r.vtype);
	return false;
}

bool get_int_idc_value(const idc_value_t &idcval, int64 *val)
{
	if(idcval.vtype == VT_LONG) {
		*val = idcval.num;
	} else if(idcval.vtype == VT_INT64) {
		*val = idcval.i64;
	} else
		return false;
	return true;
}


bool Appcaller::execAppcall(ea_t callea, ea_t patchea, idc_value_t *argv, qstring *decodedStr, qstring &error)
{
	if(!bDbgEngine) {
		int64 len = -1;
		if(patchea == BADADDR) {
			error.cat_sprnt(" no patchea");
			return false;
		}
		ea_t keyEa = 0;
		if(keyArgNum && keyArgNum <= fi.size()) {
			int64 l = 0;
			if(!get_int_idc_value(argv[keyArgNum - 1], &l)) {
				error.cat_sprnt(" no key in arg%u", keyArgNum);
				return false;
			}
			keyEa = (ea_t)l;
		}

		size_t keyLen = 0;
		if(keyLenArgNum && keyLenArgNum <= fi.size()) {
			int64 l = 0;
			if(!get_int_idc_value(argv[keyLenArgNum - 1], &l)) {
				error.cat_sprnt(" no key length in arg%u", keyLenArgNum);
				return false;
			}
			keyLen = (size_t)l;
		}

		for(uint32 i = 0; i < (uint32)fi.size(); i++) {
			uint32 argNum = i + 1;
			if(argNum == resArgNum || argNum == keyArgNum || argNum == keyLenArgNum)
				continue;
			int64 l = 0;
			if(!get_int_idc_value(argv[i], &l))
				continue;
			if(!l || l > 0x1000 || l == patchea)
				continue;
			len = l;
			//break; //use last good arg as len, uncomment to use first
		}
		return decr_string_4appcall(patchea, NULL, len, keyEa, keyLen, decodedStr, &error);
	}
	//----------------------------------
	idc_value_t r;
	error_t err = dbg_appcall(&r, funcea, NO_THREAD, &tif, argv, fi.size());
	if(err != eOk) {
		error.cat_sprnt(" dbg_appcall return %d, nobody knows what does this mean", err);
		return false;
	}
	if(!resArgNum)
		return getString(r, decodedStr, error);
	if(resArgNum > fi.size()) {
		error.cat_sprnt(" Wrong result arg num %d", resArgNum);
		return false;
	}
	return getString(argv[resArgNum - 1], decodedStr, error);
}

bool Appcaller::execAppcalls(bool bMultiLineComment)
{
	if(!calls.size()) {
		Log(llError, "No any 'good' calls to %a was found\n", funcea);
		return false;
	}
	if(!initDbg())
		return false;
	bool bRes = false;
	for(size_t i = 0; i < calls.size(); i++) {
		if(calls[i].args.size() == fi.size() && calls[i].error.empty())
			bRes |= execAppcall(calls[i].ea, calls[i].patchea, &calls[i].args[0], &calls[i].decrResult, calls[i].error);
	}
	doneDbg();
	multilineCmt = bMultiLineComment;
	open_appcall_view();
	return bRes;
}


static bool idcVal2str(const idc_value_t &val, qstring &str)
{
	switch(val.vtype) {
	case VT_LONG:
		str.cat_sprnt("0x%a", val.num);
		break;
//	case VT_STR2:
	case VT_REF:
		str.append("buffer");
		break;
	case VT_INT64:
		str.cat_sprnt("0x%a", (ea_t)val.i64);
		break;
	default:
		Log(llError, "idcVal2str wrong vtype - %d\n", val.vtype);
		return false;
	}
	return true;
}

static bool str2idcVal(qstring str, idc_value_t &val, bool &derefPtr, char idx)
{
	ea_t x;
	str.trim2();
	derefPtr = false;
	if(!qstrcmp(str.c_str(), "buffer")) {
		makeBufVal(val, idx);
		return true;
	} 
	if(str[0] == '*') {
		derefPtr = true;
		str = str.substr(1);
	}
	if(!atoea(&x, str.c_str())) {
		Log(llError, "validateArgs wrong arguments '%s'\n", str.c_str());
		return false;
	}
	val.set_int64(x);
	return true;
}


static bool validateArgs(qvector<idc_value_t> &argv, ea_t* patchea, uint32 keyArgNum)
{
	size_t argnum = argv.size();
	if(!argnum)
		return true;
	qstring argsStr;
	for(size_t i = 0; i < argnum; i++) {
		if(!idcVal2str(argv[i], argsStr))
			return false;
		if(argnum > 1 && i != argnum - 1)
			argsStr.append(", ");
	}

	qstring argsStrNew = argsStr;
	if(!ask_str(&argsStrNew, HIST_SRCH,
		"Please check call arguments.\n"
		"Keyword 'buffer' and numbers are accepted"))
		return false;
	if(argsStrNew == argsStr)
		return true;

	*patchea = BADADDR; //FIXME

	size_t i = 0;
	for(size_t findPos = 0;;) {
		qstring oneArg;
		size_t commaPos = argsStrNew.find(',', findPos);
		oneArg = argsStrNew.substr(findPos, commaPos);
		findPos = commaPos + 1;
		bool derefPtr;
		if(!str2idcVal(oneArg, argv[i], derefPtr, (char)i))
			return false;
		if(argv[i].vtype == VT_INT64) {
			if(derefPtr) {
				argv[i].i64 = get_ea((ea_t)argv[i].i64);
			}
			if(i != keyArgNum - 1 && is_loaded((ea_t)argv[i].i64))
				*patchea = (ea_t)argv[i].i64;
		}
		i++;
		if(commaPos == qstring::npos)
			break;
	}
	if(i != argnum) {
		Log(llError, "validateArgs wrong arguments number\n");
		return false;
	}
	return true;
}

bool Appcaller::runOne(cexpr_t *call)
{
	qstring error;
	qvector<idc_value_t> argv;
	ea_t patchea = BADADDR;
	if(!getArgv(call, argv, &patchea, error)) {
		Log(llError, "%a: appcall error - %s\n", call->ea, error.c_str());
		return false;
	}
	
	if(!validateArgs(argv, &patchea, keyArgNum))
		return false;
	//qstring oneArg;
	//print_idcv(&oneArg, argv[i]);

	if(!initDbg())
		return false;
	qstring resStr;
	ea_t callEa = call->ea; //will be invalid after doneDbg
	bool e = execAppcall(call->ea, patchea, &argv[0], &resStr, error);
	doneDbg();
	if(e) {
		qstring patchBtn;
		patchBtn.cat_sprnt("Patch at %a ", patchea);
		patchBtn += get_short_name(patchea);
		int answ =  ask_buttons(patchBtn.c_str(), "Comment", NULL, ASKBTN_CANCEL, 
			"[hrt] Decryption result is\n\n %s \n\nwrite into idb?", resStr.c_str());
		if(ASKBTN_YES == answ) {
			if(patchea != BADADDR && !resStr.empty()) {
				if(strtype == STRTYPE_C_16)
					patch_wstr(patchea, resStr.c_str(), -1);
				else
					patch_str(patchea, resStr.c_str(), -1);
				Log(llInfo, "%a was patched to %s\n", patchea, resStr.c_str());
			}
		} else if(ASKBTN_NO == answ) {
			append_cmt(callEa, resStr.c_str(), true);
		} else {
			//we don't modify anything, so will not refresh view
			e = false;
		}
	} else {
		Log(llError, "%a: appcall error - %s\n", call->ea, error.c_str());
	}
	return e;
}

bool Appcaller::runAll()
{
	//TODO loop first_to next_to get_first_dref_to  
	std::multimap<func_t*, ea_t> xreffuncs;
	for(ea_t xrefea = get_first_cref_to(funcea); xrefea != BADADDR; xrefea = get_next_cref_to(funcea, xrefea)) {
		func_t *xreffunc = get_func(xrefea);
		xreffuncs.insert(std::pair<func_t*, ea_t>(xreffunc, xrefea));
	}
	func_t *prevxf = NULL;
	cfuncptr_t cf(nullptr);
	size_t i = 0;
	size_t n = xreffuncs.size();
	show_wait_box("[hrt] Decompiling...");
	for(std::multimap<func_t*, ea_t>::iterator it = xreffuncs.begin(); it != xreffuncs.end(); it++) {
		if(user_cancelled()) {
			hide_wait_box();
			Log(llNotice, "appcall is canceled\n");
			return false;
		}
		appcall_t ac;
		ac.ea = it->second;
		if(it->first == NULL) {
			ac.error.sprnt("no func for xref %a", ac.ea);
			cf.reset();
		} else if(it->first != prevxf) {
			prevxf = it->first;
			replace_wait_box("[hrt] Decompiling %a (%" FMT_Z "/%" FMT_Z ")", it->first->start_ea, i++, n);
			hexrays_failure_t hf;
			cf = decompile(it->first, &hf, DECOMP_NO_WAIT);
			if(!cf) {
				ac.error.sprnt("decompile func %a failed at %a with err %d %s (%s)", it->first->start_ea, hf.errea, hf.code, hf.str.c_str(), hf.desc().c_str());
				Log(llWarning, "%s\n", ac.error.c_str());
			}
		}
		if(cf) {
			cexpr_t *call = findCall(cf, it->second, funcea);
			if(!call) {
				ac.error.sprnt("smth wrong in finding call at %a", it->second);
				Log(llWarning, "%s\n", ac.error.c_str());
			} else {
				qstring callstr;
				call->print1(&callstr, cf);
				tag_remove(&ac.callStr, callstr);
				getArgv(call, ac.args, &ac.patchea, ac.error);
			}
		}
		calls.push_back(ac);
	}
	hide_wait_box();
	execAppcalls(false);
	return true;//bRes;
}

bool Appcaller::runLoop(cexpr_t *call)
{
	qvector<idc_value_t> argv;
	qstring error;
	ea_t patchea = BADADDR;
	getArgv(call, argv, &patchea, error);

	size_t argnum = argv.size();
	if(!argnum)
		return false;

	uint64 loops = 1;
	qvector<qstring> argstrs; argstrs.resize(argnum);
	qvector<int64> increments; increments.resize(argnum);
	qvector<bool> derefPtr; derefPtr.resize(argnum);

	qstring format = 
		//"STARTITEM 2\n"
		//title 
		"[hrt] Appcall function in loop\n\n"
		"<loops:L::6::>\n";

	for(size_t i = 0; i < argv.size(); i++) {
		idcVal2str(argv[i], argstrs[i]);
		format.cat_sprnt("<#* at the beginning for deref pointer#arg%u:q::18::> <increment:l::6::>\n", (uint32_t)(i + 1));
	}
	format.append("\n\n");
	int vask_form_res = 0;
	switch (argnum) {
	case 1:	
		vask_form_res = ask_form(format.c_str(), &loops, &argstrs[0], &increments[0]);
		break;
	case 2:
		vask_form_res = ask_form(format.c_str(), &loops, &argstrs[0], &increments[0], &argstrs[1], &increments[1]);
		break;
	case 3:
		vask_form_res = ask_form(format.c_str(), &loops, &argstrs[0], &increments[0], &argstrs[1], &increments[1], &argstrs[2], &increments[2]);
		break;
	case 4:
		vask_form_res = ask_form(format.c_str(), &loops, &argstrs[0], &increments[0], &argstrs[1], &increments[1], &argstrs[2], &increments[2], &argstrs[3], &increments[3]);
		break;
	case 5:
		vask_form_res = ask_form(format.c_str(), &loops, &argstrs[0], &increments[0], &argstrs[1], &increments[1], &argstrs[2], &increments[2], &argstrs[3], &increments[3], &argstrs[4], &increments[4]);
		break;
	default:
		warning("[hrt] FIXME: Too many agruments...");
	}
	if(!vask_form_res)
		return false;

	for(size_t i = 0; i < argv.size(); i++) {
		if(!str2idcVal(argstrs[i], argv[i], derefPtr[i], (char)i))
			return false;
	}

	for(uint64 j = 0; j < loops; j++) {
		appcall_t ac;
		ac.ea = call->ea;
		ac.args = argv;
		ac.patchea = BADADDR;
		//ac.callStr = buf;
		for(size_t i = 0; i < argv.size(); i++) {
			if(argv[i].vtype == VT_INT64) {
				if(derefPtr[i])
					ac.args[i].i64 = get_ea((ea_t)(argv[i].i64 + increments[i] * j));
				else
					ac.args[i].i64 = argv[i].i64 + increments[i] * j;
				if(is_loaded((ea_t)ac.args[i].i64)) {
#ifdef FIRST_PATCH_EA
					if(ac.patchea == BADADDR)
#endif //FIRST_PATCH_EA
					{
						ac.patchea = (ea_t)ac.args[i].i64;
					}
				}
			}
		}
		calls.push_back(ac);
	}
	return execAppcalls(true);
}

static int idaapi appcall_dlg_cb(int field_id, form_actions_t &fa)
{
	if(field_id == 1 || field_id == -1) { //Decryptor is changed and at start
		ushort val;
		fa.get_rbgroup_value(1, &val);
		if(val == 0) {
			fa.enable_field(2, false);//disable Find result
			fa.enable_field(3, true); //enable  Find key
			fa.enable_field(4, true); //enable  Find key len
			fa.enable_field(5, false); //disable Init start
			fa.enable_field(6, false); //disable Init stop
		} else {
			fa.enable_field(2, true); //enable Find result
			fa.enable_field(3, false); //disable  Find key
			fa.enable_field(4, false); //disable  Find key len
			if(!dbg) {
				warning("[hrt] 'Select debugger' at first");
			} else if(!qstrcmp(dbg->name, "imul")) {
				fa.enable_field(5, true);  //enable Init start
				fa.enable_field(6, true);  //enable Init stop
			}
		}
	}
	return 1;
}

bool Appcaller::run(ea_t dstea, cexpr_t *call)
{
	qstring funcname = get_short_name(dstea);
	static ushort decryptor = 0;
	static ushort kind = 0;
	static ushort strType_ = 0;
	static ushort strDisp = 0;
	static sval_t resArgNum_ = 0;
	static sval_t keyArgNum_ = 0;
	static sval_t keyLenArgNum_ = 0;

	static ea_t initEnd = BADADDR;
	static ea_t initBgn = BADADDR;
	if(initBgn == BADADDR && initEnd == BADADDR) {
		if(dbg && !qstrcmp(dbg->name, "imul")) {
			initBgn = inf_get_start_ea();
			func_t *initFunc = get_func(initBgn);
			if(initFunc && initFunc->does_return())
				initEnd = get_item_head(initFunc->end_ea - 1);
			else
				initEnd = get_item_end(initBgn);
		} else {
			initBgn = 0;
			initEnd = 0;
		}
	}

	const char format[] = 
		//"STARTITEM 2\n"
		//title 
		"[hrt] Mass strings decryption\n\n"
		"%/"                // callback
		"by %q at %$\n"
		"<#Use one of embedded into the plugin decryptor you will be asked on the next step#Decryptor engine#What will we use?#[hrt] decryptor:R>\n"
		"<#Use currently selected IDA debugger in Appcall mode#Appcall debugger:r>1>\n"                     // 1
		"<#All calls of the selected proc#Amount#How many strings we will decrypt#All ~x~refs:R>\n"
		"<#Only call under the cursor#~S~ingle call:r>\n"
		"<#Few calls with custom arguments#Custom calls ~l~oop:r>>\n"
		"<##Expected wide of string chars#what kind of string should be returned by call#~8~bit chars:R>\n"
		"<1~6~bit chars:r>>\n"
		"<##Disposition#How call returns decrypted string#Auto detect:R>\n"
		"<#Fill buffer with decrypted string characters#Chars array:r>\n"
		"<#Put pointer to string into the buffer#Pointer to string:r>>\n"
		"<#0 - return value; 1,2,... arguments#Find result in argument:D2:2:2::>\n"     // 2
		"<#0 - same key for all calls; 1,2,... arguments#Find key in argument:D3:2:2::>\n"    // 3
		"<#0 - if not applicable; 1,2,... arguments#Find key length in arg:D4:2:2::>\n" // 4
		"\nRun initializer on debugger start (exec CRT startup)\n"
		"<#0 - to work without Init#Init start:$5:32:20::>\n"                          // 5
		"<#-1 - to run until breakpoint#Init  stop:$6:32:20::>\n";                      // 6

	if(!ask_form(format, appcall_dlg_cb, &funcname, &dstea, &decryptor, &kind, &strType_, &strDisp,  &resArgNum_, &keyArgNum_, &keyLenArgNum_, &initBgn, &initEnd))
		return false;

	if(!init(decryptor == 1, (uint32)keyArgNum_, (uint32)keyLenArgNum_, dstea, (uint32)resArgNum_, strType_ == 1 ? STRTYPE_C_16 : STRTYPE_C, (eACStrDisp)strDisp, initBgn, initEnd))
		return false;
	//if initializer
	// TODO
	switch (kind) {
	case 0:
		return runAll();
		break;
	case 1:
		return runOne(call);
		break;
	case 2:
		return runLoop(call);
		break;
	}
	return false;
}

bool Appcaller::re_run(const qvector<reappcall_t> &patchlist)
{
	ea_t dstea = appcaller.funcea;
	static sval_t resArgNum_ = 0;
	ushort strType_ = 0;
	ushort strDisp = 0;
	qstring argsStr;

	if(appcaller.calls.size()) {
		size_t argnum = appcaller.calls[0].args.size();
		for(size_t i = 0; i < argnum; i++) {
			idcVal2str(appcaller.calls[0].args[i], argsStr); //ignore errors
			if(argnum > 1 && i != argnum - 1)
				argsStr.append(", ");
		}
	}

	const char format[] = 
		//"STARTITEM 2\n"
		//title 
		"[hrt] reExec Appcall function\n\n"
		"<Address or name of function will be called:$:32:20::>\n"
		"<#Comma separated 'buffer', 'patchaddr' and numbers are accepted#List of call arguments:q:1024:40::>\n"
		"<##Expected wide of string chars#what kind of string should be returned by call#~8~bit chars:R>\n"
		"<1~6~bit chars:r>>\n"
		"<##Disposition#How call returns decrypted string#Auto detect:R>\n"
		"<#Fill buffer with decrypted string characters#Chars array:r>\n"
		"<#Put pointer to string into the buffer#Pointer to string:r>>\n"
		"<#0 return value; 1,2,... arguments#Find string in argument:D:2:2::>\n"
		"\n\n";
	while(1) {
		if(!ask_form(format, &dstea, &argsStr, &strType_, &strDisp,  &resArgNum_))
			return false;
		if(patchlist.size() == 1 || argsStr.find("patchaddr") != qstring::npos)
			break;
		Log(llError, "no 'patchaddr' argument was specified\n");
	}


	if(!init(appcaller.bDbgEngine, appcaller.keyArgNum, appcaller.keyLenArgNum, dstea,
					 (uint32)resArgNum_, strType_ == 1 ? STRTYPE_C_16 : STRTYPE_C,
					 (eACStrDisp)strDisp, appcaller.initStart, appcaller.initStop))
		return false;

	qvector<idc_value_t> argv;
	argv.resize(fi.size());

	size_t patchArgNum = -1;
	size_t i = 0;
	for(size_t findPos = 0;;) {
		qstring oneArg;
		size_t commaPos = argsStr.find(',', findPos);
		oneArg = argsStr.substr(findPos, commaPos);
		findPos = commaPos + 1;
		bool derefPtr;
		if(!qstrcmp(oneArg.c_str(), "patchaddr")) {
			if(patchArgNum != -1) {
				Log(llError, "too many 'patchaddr' arguments was specified\n");
				return false;
			}
			patchArgNum = i;
		}  else {
			if(!str2idcVal(oneArg, argv[i], derefPtr, (char)i))
				return false;
			if(argv[i].vtype == VT_INT64) {
				if(derefPtr) {
					argv[i].i64 = get_ea((ea_t)argv[i].i64);
				}
				//if(is_loaded((ea_t)argv[i].i64))
				//	*patchea = (ea_t)argv[i].i64;
			}
		}
		i++;
		if(commaPos == qstring::npos)
			break;
	}
	if(i != fi.size()) {
		Log(llError, "wrong arguments number\n");
		return false;
	}
	if(patchlist.size() > 1 && patchArgNum == -1) {
		Log(llError, "no 'patchaddr' argument was specified\n");
		return false;
	}

	for(size_t j = 0; j < patchlist.size(); j++) {
		appcall_t ac;
		ac.args = argv;
		ac.ea = patchlist[j].ea;
		ac.callStr = patchlist[j].callStr;
		ac.patchea = patchlist[j].patchea;
		if(patchArgNum != -1)
			ac.args[patchArgNum].set_int64(ac.patchea);
		calls.push_back(ac);
	}
	execAppcalls(false);
	return true;
}

Appcaller appcaller;

bool do_appcall2(vdui_t *vu)
{
	cexpr_t* call;
	ea_t dstea;
	if (!is_appcallable(vu, &call, &dstea))
		return false;

#if IDA_SDK_VERSION < 750 //IDA 7.5 and later instead open_pseudocode(OPF_REUSE) opens new one
	appcaller.saveViewProcEa = vu->cfunc->entry_ea;
	place_t *place =  get_custom_viewer_place(vu->ct, false, &appcaller.saveX, &appcaller.saveY);
	appcaller.savePlace = (simpleline_place_t*)place->clone();
#endif //IDA_SDK_VERSION < 750

	bool res = appcaller.run(dstea, call);
	//delete appcaller.savePlace; //LEAK can't correctly delete memory allocated by simpleline_place_t::clone()
	return res;
}

bool re_do_appcall(const qvector<reappcall_t> &patchlist)
{
	return appcaller.re_run(patchlist);
}
