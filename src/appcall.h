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
  This feature is inspired by ideas of Krypton plugin by Karthik Selvaraj(https://www.hex-rays.com/contests/2012/Krypton_2012_Hex-Rays_Contest.zip)
  that uses IDA's powerful Appcall feature(https://hex-rays.com/wp-content/uploads/2019/12/debugging_appcall.pdf) - call functions inside the debugged program
  The main problem of Krypton - it can't deal with mixed registers/stack arguments because tries to analyze low level assembler code.
  This implementation takes everything from Hex-Rays generated pseudocode.
 */

#pragma once
#include "warn_off.h"
#include <hexrays.hpp>
#include <typeinf.hpp>
#include <expr.hpp>
#include "warn_on.h"

struct ida_local appcall_t
{
	ea_t ea;
	qstring callStr;
	qvector<idc_value_t> args;
	ea_t patchea;
	qstring decrResult;
	qstring error;

	appcall_t() : patchea(BADADDR) {}
};

struct ida_local reappcall_t
{
	ea_t ea;
	qstring callStr;
	ea_t patchea;
	reappcall_t(const appcall_t &ac) : ea(ac.ea), patchea (ac.patchea) , callStr(ac.callStr) {}
};

enum eACStrDisp {
	acsdAuto = 0,
	acsdArray,
	acsdPointer
};

struct ida_local Appcaller
{
#if IDA_SDK_VERSION < 750 //IDA 7.5 and later instead open_pseudocode(OPF_REUSE) opens new one
	ea_t saveViewProcEa;
	simpleline_place_t * savePlace;
	int saveX, saveY;
#endif //IDA_SDK_VERSION < 750
	int isDbgRunning;
	uint oldDebuggerOptions;
	ea_t funcea;
	tinfo_t tif;
	func_type_data_t fi;
	qvector<appcall_t> calls;
	int32 strtype;
	eACStrDisp resDisp;
	uint32 resArgNum;
	bool multilineCmt;

	ea_t initStart;
	ea_t initStop;

	bool   bDbgEngine;
	uint32 keyArgNum;
	uint32 keyLenArgNum;

	Appcaller()	: funcea(BADADDR) {}
	bool run(ea_t dstea, cexpr_t *call);
	bool re_run(const qvector<reappcall_t> &patchlist);

private:
	bool init(bool dbg, uint32 keyArg, uint32 keyLenArg, ea_t dstea, uint32 resArgNum_, int32 strtype_, eACStrDisp disp,  ea_t ib, ea_t ie);
	bool initDbg();
	void doneDbg();
	bool getArgv(cexpr_t *call, qvector<idc_value_t> &argv, ea_t* patchea, qstring &error);
	bool execAppcall(ea_t callea, ea_t patchea, idc_value_t *argv, qstring *decodedStr, qstring &error);
	bool execAppcalls(bool bMultiLineComment);
	bool getString(idc_value_t &r, qstring *decodedStr, qstring &error);
	bool runOne(cexpr_t *call);
	bool runAll();
	bool runLoop(cexpr_t *call);
};

extern Appcaller appcaller;

bool is_appcallable(vdui_t *ud, cexpr_t **pcall, ea_t *dstea);
bool do_appcall2(vdui_t *vu);
bool re_do_appcall(const qvector<reappcall_t> &patchlist);
