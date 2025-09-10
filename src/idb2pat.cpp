// IDB2PAT: fixed a few things + Ida7/8/9 API
//
//  Original Plugin: https://github.com/alexander-pick/idb2pat
//
// IDA2PAT for IDA 6.2 OSX
// fixed a few things and ingtgrated crc16.cpp into it to work proper
// 8/10/2011 - Alexander Pick
//
//  Original Plugin:
//
//  IDB to PAT v1.0
//  Plugin module for IDA Pro v4.30/IDASDK430
//  J.C. Roberts <mercury@abac.com>
//
//
//  *   LICENSE/: Freeware / Public domain :-)
//
//  *   The CCITT CRC 16 code written by Ilfak Guilfanov (ig@datarescue.be> and
//      provided in the FLAIR Utilities v4.21 package. You will need the
//      "CRC16.CPP" file from this package in order to complile. Also portions
//      of the plugin originated from the MS VC++ skeleton provided with the 
//      IDA Pro SDK v4.30.
//
//  *   Portions were originally written by Quine (quine@blacksun.res.cmu.edu)
//      in his  IDV_2_SIG plugin. Quine's IDA Page at http://surf.to/quine_ida
//      I've tried to reach him at above address regarding the license of his
//      code but emails to that address bounce. As far as I know it was 
//      licensed as freeware but if I'm wrong I would like Quine to contact me.
//
//  *   See the "readme.txt" for further information.
//

#include <map>
#include "helpers.h"

// Minumum number of bytes a function needs in order to be patterned
#define MIN_SIG_LENGTH 10

// These things need to be shorts rather than #def or enum since
// AskUsingForm_c() requires shorts.

const short CHKBX_DO_NADA = 0x0000;     // Null for no boxes checked
const short CHKBX_DO_LIBS = 0x0001;     // Include library functions
const short CHKBX_DO_SUBS = 0x0002;     // Include Auto-Generated Names "sub_*"
const short CHKBX_NO_LIBS = 0x0004;     // Exclude library functions
const short CHKBX_DO_TEMP = 0x0008;     // Not used

const short RADIO_NON_FUNC = 0x0000;    // non auto-generated
const short RADIO_LIB_FUNC = 0x0001;    // library functions
const short RADIO_PUB_FUNC = 0x0002;    // exported functions
const short RADIO_ALL_FUNC = 0x0003;    // all functions
const short RADIO_USR_FUNC = 0x0004;    // user selected function

const short RADIO_IS_ERROR = -1;

// Structure for passing user options
typedef struct tagPATOPTION {
    short radio;
    short chkbx;
} PATOPTION;

// crc16 from flair
#define POLY 0x8408

static unsigned short local_crc16(unsigned char *data_p, size_t length)
{
	unsigned char i;
	unsigned int data;

	if (length == 0) return 0;
	unsigned int crc = 0xFFFF;
	do
	{
		data = *data_p++;
		for (i = 0; i < 8; i++)
		{
			if ((crc ^ data) & 1)
				crc = (crc >> 1) ^ POLY;
			else
				crc >>= 1;
			data >>= 1;
		}
	} while (--length != 0);

	crc = ~crc;
	data = crc;
	crc = (crc << 8) | ((data >> 8) & 0xff);
	return (unsigned short)(crc);
}

// _____________________________________________________________________________
// *****************************************************************************
// -----------------------------------------------------------------------------
// Globals ;-)

PATOPTION opt_stru;                     // User defined options structure
PATOPTION* opt_ptr = &opt_stru;         // umm... pointer to said structure

// Vars for Stats
int g_skip_ctr = 0;          // Number of Skiped Function Counter
int g_shrt_ctr = 0;          // Number of Functions too short for sig
int g_libs_ctr = 0;          // Number of Library Function Counter
int g_pubs_ctr = 0;          // Number of Public Function Counter
int g_badf_ctr = 0;          // Number of Bad Functin Number Counter
int g_badn_ctr = 0;          // Number of Bad Function Name Counter
int g_badp_ctr = 0;          // Number of Bad Public Name Counter
int g_badr_ctr = 0;          // Number of Bad Reference Name Counter
int g_pats_ctr = 0;          // Number of Pattern Created

// _____________________________________________________________________________
// *****************************************************************************
// -----------------------------------------------------------------------------
// FUNCTION: find_ref_loc
//
// this function finds the location of a reference within an instruction
// or a data item e.g.
//      .text:00401000  E8 FB 0F 00 00   call sub_402000
//
// find_ref_loc(0x401000, 0x402000) would return 0x401001
// it works for both segment relative and self-relative offsets
static ea_t find_ref_loc(ea_t item, ea_t _ref)
{
	ea_t i;
	if (is_code(get_flags(item))) {
		insn_t cmd;
		decode_insn(&cmd, item);
		if (cmd.ops[0].type == o_near) {
			// we've got a self-relative reference
			_ref = _ref - (get_item_end(item));
		} else if(is64bit() && (cmd.ops[0].type == o_mem || cmd.ops[1].type == o_mem)) {
			// we've got a self-relative reference
			_ref = _ref - (get_item_end(item));
		}
	}
	for (i = item; i <= get_item_end(item) - 4; i++) {
		if (get_dword(i) == (uint32_t)_ref) {
			return i;
		}
	}
	return BADADDR;
}

// _____________________________________________________________________________
// *****************************************************************************
// marks off bytes as variable
static void set_v_bytes(qvector<bool>& bv, ea_t pos) {
	for (size_t i = 0; i < 4; i++) {
		bv[pos + i] = true;
	}
}

// _____________________________________________________________________________
// *****************************************************************************
// -----------------------------------------------------------------------------
// FUNCTION: make_pattern
// this is what does the real work
static void make_pattern(func_t* funcstru, FILE* fptr_pat, PATOPTION* opt_ptr)
{
	typedef std::map<ea_t, ea_t, std::less<ea_t> > ref_map;
	typedef qvector<bool> bool_vec;

	ea_t start_ea = funcstru->start_ea;           // Get Function Start EA
	uval_t len = funcstru->end_ea - start_ea;     // Get Function Length
	bool_vec v_bytes; v_bytes.resize(len);
	ref_map refs;

	// PART #1  Get the pubs and refernces
	qvector<ea_t> qpublics;
	ea_t ea = start_ea;
	while (ea - start_ea < len) {
		flags64_t mflags = get_flags(ea);

		// load up the publics vector
		if (opt_ptr->chkbx & CHKBX_DO_SUBS) {
			// Does the current byte have dummy name (includes "sub_" "loc_" etc.)
			if (has_dummy_name(mflags)) {
				qstring name;
				get_name(&name, ea);
				if (!name.empty() && !strncmp(name.c_str(), "sub_", 4)) {
					// Only include the "sub_"names (exclude "loc_" etc.)
					qpublics.push_back(ea);
				}
			}
		}
		// Does the current byte have non-trivial (non-dummy) name?
		if (has_name(mflags)) {
			qpublics.push_back(ea);
		}

		// load up refernces map
		ea_t ref_ea = get_first_dref_from(ea);
		if (ref_ea != BADADDR) {
			// a data location is referenced
			ea_t ref_loc_ea = find_ref_loc(ea, ref_ea);
			if (ref_loc_ea != BADADDR) {                        // Error Check
				set_v_bytes(v_bytes, ref_loc_ea - start_ea);
				refs[ref_loc_ea] = ref_ea;
			}
			// check if there is a second data location ref'd
			if ((ref_ea = get_next_dref_from(ea, ref_ea)) != BADADDR) {
				ref_loc_ea = find_ref_loc(ea, ref_ea);
				if (ref_loc_ea != BADADDR) {                    // Error Check
					set_v_bytes(v_bytes, ref_loc_ea - start_ea);
					refs[ref_loc_ea] = ref_ea;
				}
			}
		} else {
			// do we have a code ref?
			if ((ref_ea = get_first_fcref_from(ea)) != BADADDR) {
				// if so, make sure it is outside of function
				if ((ref_ea < start_ea) || (ref_ea >= start_ea + len)) {
					ea_t ref_loc_ea = find_ref_loc(ea, ref_ea);
					if (ref_loc_ea != BADADDR) {                // Error Check
						set_v_bytes(v_bytes, ref_loc_ea - start_ea);
						refs[ref_loc_ea] = ref_ea;
					}
				}
			}
		}
		ea = next_not_tail(ea);
	}

// PART #2
	// write out the first string of bytes,
	// making sure not to go past the end of the function
	uval_t first_string = (len < 32 ? len : 32);
	for (uval_t i = 0; i < first_string; i++) {
		if (v_bytes[i]) {
			qfprintf(fptr_pat, "..");
		} else {
			qfprintf(fptr_pat, "%02X", get_byte(start_ea + i));
		}
	}

// PART #3
	// fill in anything less than 32
	if (first_string < 32) {
		for (uval_t i = 0; i < (32 - first_string); i++) {
			qfprintf(fptr_pat, "..");
		}
	}

// PART #4
	// put together the crc data
	unsigned char crc_data[256];
	uval_t pos = 32;
	while ((pos < len) && (!v_bytes[pos]) && (pos < 255 + 32)) {
		crc_data[pos - 32] = get_byte(start_ea + pos);
		pos++;
	}

// PART #5
	// alen is length of the crc data
	uval_t alen = pos - 32;
	ushort crc = local_crc16(crc_data, alen);
	qfprintf(fptr_pat, " %02X %04X %04X", alen, crc, (unsigned int)len);


// PART #6:    Write Public Names
	// write the publics
	for (qvector<ea_t>::iterator p = qpublics.begin(); p != qpublics.end(); p++) {
		// Get name of public
		qstring name;
		get_name(&name, *p);
		sval_t xoff = (*p - start_ea);

		//IDA does not accept whole sig file if any of names longer then 1023
		if(name.length() > 1023) {
			ushort crc = local_crc16((unsigned char*)name.c_str(), name.length());
			name = name.substr(0, 1023 - 4);
			name.cat_sprnt("%04x", crc);
			Log(llWarning, "idb2pat %a: too long name trimmed '%s'\n", *p, name.c_str());
		}

		// make sure we have a name
		if (name.empty()) {
			g_badp_ctr++;                   // Inc Bad Publics
		}	else if (is_uname(name.c_str())) {// Is it a user-specified name? (valid name & !dummy prefix)
			// check for negative offset and adjust output
			if (xoff >= 0) {
				qfprintf(fptr_pat, " :%08X %s", xoff, name.c_str());
			} else {
				qfprintf(fptr_pat, " :-%08X %s", -xoff, name.c_str());
			}
		}	else if ((opt_ptr->chkbx & CHKBX_DO_SUBS) && (!strncmp(name.c_str(), "sub_", 4))) { // grab autogen "sub_" names
			// Use our own prefix so there isn't a reserved prefix problem
			qstring xname = "FAKE_";
			xname += name;
			if (xoff >= 0) {
				qfprintf(fptr_pat, " :%08X %s", xoff, xname.c_str());
			} else {
				qfprintf(fptr_pat, " :-%08X %s", -xoff, xname.c_str());
			}
		}	else {
			g_badp_ctr++;                   // Inc Bad Publics
		}
	}

// PART #7     Write named referneces
	// (*r).first   holds the ea in the function where the reference is used
	// (*r).second  holds the ea of the reference itself
	// write the references
	for (ref_map::iterator r = refs.begin(); r != refs.end(); r++) {
		// Get name of reference
		qstring name;
		get_name(&name, (*r).second);
		sval_t xoff = ((*r).first - start_ea);
		flags64_t mflags = get_flags((*r).second);

		if (name.empty()) {
			g_badr_ctr++;                       // Inc bad refs counter
		} else  if (has_user_name(mflags)) {// Is it a user-specified name?
			// check for negative offset and adjust output
			if (xoff >= 0) {
				qfprintf(fptr_pat, " ^%08X %s", xoff, name.c_str());
			} else {
				qfprintf(fptr_pat, " ^-%08X %s", -xoff, name.c_str());
			}
		} else if ((opt_ptr->chkbx & CHKBX_DO_SUBS) && (!strncmp(name.c_str(), "sub_", 4))) { // grab autogen "sub_" names
			// Use our own prefix so there isn't a reserved prefix problem
			qstring xname = "FAKE_";
			xname += name;
			if (xoff >= 0) {
				qfprintf(fptr_pat, " ^%08X %s", xoff, xname.c_str());
			}	else {
				qfprintf(fptr_pat, " ^-%08X %s", -xoff, xname.c_str());
			}
		} else {
			g_badr_ctr++;                       // Inc bad refs counter
		}
	}

// PART #8
	// and finally write out the last string with the rest of the function
	qfprintf(fptr_pat, " ");
	for (uval_t i = pos; i < len; i++) {
		if (v_bytes[i]) {
			qfprintf(fptr_pat, "..");
		} else {
			qfprintf(fptr_pat, "%02X", get_byte(start_ea + i));
		}
	}
	g_pats_ctr++;
	qfprintf(fptr_pat, "\n");
}


// _____________________________________________________________________________
// *****************************************************************************
// -----------------------------------------------------------------------------
// FUNCTION: opt_diaolg
//
// Dialog for gettig user desired options
//
static PATOPTION* opt_diaolg(PATOPTION* opt_ptr)
{

    // Build the format string constant used to create the dialog
    const char format[] =
    "STARTITEM 0\n"                                                 // TabStop
    "HELP\n"                                                        // Help
    "**********************************************************************\n"
    "                                                                      \n"
    "                              IDB_2_PAT                               \n"
    "                                                                      \n"
    "For the most part, this plugin is an exercise in futility. There are  \n"
    "very few valid reasons why anyone should ever want to build signatures\n"
    "of the functions in an existing disassemblly. There are better        \n"
    "reasons, methods and tools for creating signatures for use with IDA.  \n"
    "Most importantly, the right way to create signatures is from object   \n"
    "files, oject libraries or dynamically linked libraries, so please     \n"
    "realize this plugin is nothing more than a kludge since we are asking \n"
    "FLAIR to do something it was not designed to do.                      \n"
    "                                                                      \n"
    "**********************************************************************\n"
    "Option: Create patterns for Non-Auto Named Functions                  \n"
    "                                                                      \n"
    "    If you find the rare situation where you want to make patterns    \n"
    "from functions in an existing database, this option is probably your  \n"
    "best bet. It will only create patterns for functions without          \n"
    "autogenerated names and it will exclude functions marked as libraries \n"
    "(e.g. they were already found and named through other FLAIR           \n"
    "signatures). You may want to remove named functions like _main and    \n"
    "WinMain from the resulting pattern file, since these will already     \n"
    "exist in the disassembly where it's applied.                          \n"
    "                                                                      \n"
    "**********************************************************************\n"
    "Option: Create Patterns for Library Functions Only                    \n"
    "                                                                      \n"
    "    I did include the ability to build patterns for functions IDA has \n"
    "already marked as libraries. This is forpeople doing source code      \n"
    "recovery/recreation since the pattern file can be further parsed to   \n"
    "figure out which header files are needed. There are probably better   \n"
    "ways togo about this as well but until I have time to write specific a\n"
    "plugin for figureing out which headers are included, this can give you\n"
    "a step in the right direction.Out side of gathering information on    \n"
    "applied library signatures, this feature is pointless since you're    \n"
    "building patternss for function that were previously found with other \n"
    "signatures you already have.                                          \n"
    "                                                                      \n"
    "**********************************************************************\n"
    "Option: Create Patterns for Public Functions Only                     \n"
    "                                                                      \n"
    "    This could be useful when dealing with a situation where functions\n" 
    "were once stored in a DLL and are now statically linked in an         \n"
    "executable. It's still may a better bet to build a signature from the \n"
    "DLL and then apply it to the statically linked executable.            \n"
    "                                                                      \n"
    "**********************************************************************\n"
    "Option: Create Patterns For Everything                                \n"
    "                                                                      \n"
    "    You generally do NOT want to build patterns for every function in \n"
    "the disassembly. The only place where I can see a legitimate use for  \n"
    "creating signatures of every functionin the database is if your goal  \n"
    "is to see how similar two executables are. Instead of using a hex     \n"
    "editor and doing aresyncronizing binary compare between the two       \n"
    "executables,you could use IDA signatures to get a different/better    \n"
    "wayto visualize the similarities.                                     \n"
    "                                                                      \n"
    "    There are a lot of problems with trying to do this. The first and \n"
    "most obvious problem is reserved name prefixes (e.g. sub_) on         \n"
    "autogenerated function names. Another cascading problem is of course  \n"
    "references to these names withing other functions and whether or not  \n"
    "to keep these references in the patterns in order to cut down the     \n"
    "numberof collisions. There are plenty of other problems with this     \n"
    "approach that I won't mention but there are quite a few ofthem.       \n"
    "                                                                      \n"
    "    I've hacked together a simple work-around. When the user has      \n"
    "selected everything mode, the pulgin will prepend the autogenerated   \n"
    "function names with FAKE_ and references to these sub routines are    \n"
    "kept to reduce collisions. This should (in theory) work, since every  \n"
    "reference will also have it's own public pattern in the resulting     \n"
    "file. In other words, the named references will resolve to another    \n"
    "(public) function pattern in the file. The problem with this approach \n"
    "is of course having erroneous address numbers in names of functions   \n"
    "where the signature is applied (e.g. the nameFAKE_sub_DEADBEEF could  \n"
    "be applied to any anddress where a matching function is found). My    \n"
    "guess why this will work is because a module in a library may have a  \n"
    "by name reference to another object in the library. The pattern file  \n"
    "of a library would keep the references, since the names are defined   \n"
    "in other pattern lines of the file. Of course I could be wrong but    \n"
    "it's worth a shot. If need be comment out the 'sub_' tests in         \n"
    "part #7 (references) of make_pattern() to get rid of the refs. So far \n"
    "it has worked well for avoiding collisions, On my test file with      \n"
    "1090 functions there were no collisions between 'FAKE_sub_' functions.\n"
    "                                                                      \n"
    "**********************************************************************\n"
    "Option: Create Pattern For User Selected Function                     \n"
    "                                                                      \n"
    "    This allows the user to select a function from the list  and      \n"
    "create a pattern for it. It does not work on functions with auto      \n"
    "generated names but probably could with a bit more work.              \n"
    "                                                                      \n"
    "**********************************************************************\n"
    "ENDHELP\n"
    "Choose Option\n"                                               // Title
    "Please choose the method for selecting functions.\n\n"         // MsgText


     //  Radio Button 0x0000
    "<#Create patterns for all functions with user created names.\n"// hint0
    "This excludes all library functions and auto-generated names.#"// hint0
    "Non-Auto Named Functions:R>\n"                                 // text0

     //  Radio Button 0x0001
    "<#Create patterns for functions maked as libraries.\n"         // hint1
    "This excludes all auto-generated names.#"                      // hint1
    "Library Functions Only:R>\n"                                   // text1

     //  Radio Button 0x0002
    "<#Create patterns for functions marked as public.\n"           // hint2
    "This excludes all auto-generated names.#"                      // hint2
    "Public Functions Only:R>\n"                                    // text2

     //  Radio Button 0x0003
    "<#CAUTION -This will make a real mess of names in any\n"       // hint3
    "disassembly where the resulting signature is applied.#"        // hint3
    "Create Patterns For Everything:R>\n"                           // text3

     //  Radio Button 0x0004
    "<#You get prompted to choose a function from the list.#"       // hint4
    "User Selected Function:R>>\n\n"                                // text4
    ; // End Dialog Format String

    // Starting value is masked to set which radio button is checked by default.
    opt_ptr->radio = RADIO_NON_FUNC;                    // Set Default Radio

    // Starting value is masked to set which boxes are checked by default.
    opt_ptr->chkbx = CHKBX_DO_NADA;                     // Set Default ChkBox

    // Create the option dialog.
    int ok = ask_form(format, &(opt_ptr->radio));
    if (!ok){
        opt_ptr->radio = RADIO_IS_ERROR;                        // Error Occured
    }

    if (opt_ptr->radio == RADIO_ALL_FUNC) {                     // Set up hoser
        opt_ptr->chkbx = (opt_ptr->chkbx) + CHKBX_DO_LIBS;
        opt_ptr->chkbx = (opt_ptr->chkbx) + CHKBX_DO_SUBS;
    }
    return opt_ptr;
}

// _____________________________________________________________________________
// *****************************************************************************
// -----------------------------------------------------------------------------
// FUNCTION: get_pat_file
// Set pattern file name and open file for writing
static FILE* get_pat_file()
{
	qstring filename = get_path(PATH_TYPE_IDB);
	filename += ".pat";
	filename = ask_file(1, filename.c_str(), "Enter the name of the pattern file:");
	if (filename.empty())
		return NULL;
	FILE* fptr_pat = qfopen(filename.c_str(), "a");
	if (!fptr_pat) {
		warning("[hrt] idb2pat: Could not open %s for writing!\n", filename.c_str());
	} else {
		Log(llInfo, "idb2pat using: %s\n", filename.c_str());
	}
	return fptr_pat;
}

static void make_pattern_wcheck(func_t* funcstru, FILE* fptr_pat, PATOPTION* opt_ptr)
{
	if (!funcstru) {
		g_skip_ctr++;                     // Inc skiped function counter
		g_badf_ctr++;                     // Inc the bad function # counter
		return;
	}
	qstring name = get_name(funcstru->start_ea);
	if (name.empty()) {
		Log(llWarning, "idb2pat %a: get_name() FAILED\n", funcstru->start_ea);
		g_skip_ctr++;                     // Inc skiped function counter
		g_badn_ctr++;                     // inc the bad name counter
		return;
	}
	if ((funcstru->end_ea - funcstru->start_ea) < MIN_SIG_LENGTH) {
		Log(llInfo, "idb2pat %a: too short function %s\n", funcstru->start_ea, name.c_str());
		g_skip_ctr++;                     // Inc skiped function counter
		g_shrt_ctr++;                     // Inc function too Short counter
		return;
	}
	make_pattern(funcstru, fptr_pat, opt_ptr);
}


// _____________________________________________________________________________
// *****************************************************************************
// -----------------------------------------------------------------------------
// FUNCTION: run
//
// The main plugin
//
void run_idb2pat()
{
// reset global counters. -necessary because of how plugins are handled
	g_skip_ctr = 0;                       // skiped function counter
	g_shrt_ctr = 0;                       // too short function counter
	g_libs_ctr = 0;                       // lib function counter
	g_pubs_ctr = 0;                       // pub function counter
	g_badf_ctr = 0;                       // bad function number counter
	g_badn_ctr = 0;                       // bad function name counter
	g_badp_ctr = 0;                       // Bad Public Name Counter in patern
	g_badr_ctr = 0;                       // Bad Reference Name Counter in pat
	g_pats_ctr = 0;                       // Number of Patterns Created

	// Get number of function and test result.
	size_t funcqty = get_func_qty();
	if (funcqty == 0)
		return;

	// get user desired options and test result
	opt_ptr = opt_diaolg(opt_ptr);
	if (opt_ptr->radio == -1)
		return;

	// get file for pattern (*.PAT) and test result
	FILE* fptr_pat = get_pat_file();
	if (!fptr_pat)
		return;

	// Handle the choice of user selected function
	// CASE 5 == RADIO_USR_FUNC  (build pattern for user selected function)
	if (opt_ptr->radio == RADIO_USR_FUNC) {
		// Do the "Choose Function" dialog
		func_t* funcstru = choose_func("Choose Function", -1);
		make_pattern_wcheck(funcstru, fptr_pat, opt_ptr);
	} else {
		for (size_t i = 0; i < funcqty; i++) {
			func_t* funcstru = getn_func(i);              // get current function
			if(!funcstru)
				continue;
			if ((funcstru->flags & FUNC_LIB))
				g_libs_ctr++;                 // Inc the libs counter
			if (is_public_name(funcstru->start_ea))
				g_pubs_ctr++;                 // Inc the pubs counter

			switch (opt_ptr->radio) {
			// CASE 0 == RADIO_NON_FUNC  (pats non auto-named functions)
			case RADIO_NON_FUNC:
				if (!(funcstru->flags & FUNC_LIB) && is_uname(get_name(funcstru->start_ea).c_str())) {
					make_pattern_wcheck(funcstru, fptr_pat, opt_ptr);
				} else {
					g_skip_ctr++;         // Inc skiped function counter
				}
				break;
				// CASE 1 == RADIO_LIB_FUNC  (pattern for library functions)
			case RADIO_LIB_FUNC:
				if ((funcstru->flags & FUNC_LIB)) {
					make_pattern_wcheck(funcstru, fptr_pat, opt_ptr);
				} else {
					g_skip_ctr++;         // Inc skiped function counter
				}
				break;
				// CASE 2 == RADIO_PUB_FUNC  (patterns for public functions)
			case RADIO_PUB_FUNC:
				if (is_public_name(funcstru->start_ea)) {
					make_pattern_wcheck(funcstru, fptr_pat, opt_ptr);
				} else {
					g_skip_ctr++;         // Inc skiped function counter
				}
				break;

				// CASE 3 == RADIO_ALL_FUNC  (patterns for everything)
			case RADIO_ALL_FUNC:
				opt_ptr->chkbx = CHKBX_DO_SUBS;
				make_pattern_wcheck(funcstru, fptr_pat, opt_ptr);
				break;

				// default error
			default:
				g_skip_ctr++;         // Inc skiped function counter
			}
		}
	}

	// Check for file ptr, write pattern EOF marker and close file
	if (fptr_pat) {
		qfprintf(fptr_pat, "---\n");         // add end of *.PAT file marker
		qfclose(fptr_pat);                   // close file handle
	}

// print out the stats
	Log(llNotice, "idb2pat stat\n"
			"Total # of Funtions    %i\n", (int)funcqty);
	LogTail(llNotice,"# of Pub Function      %i\n", g_pubs_ctr);
	LogTail(llNotice,"# of Lib Function      %i\n", g_libs_ctr);
	LogTail(llNotice,"# of Skipped           %i\n", g_skip_ctr);
	LogTail(llNotice,"# of Short Functions   %i\n", g_shrt_ctr);
	LogTail(llNotice,"# of Bad Func Names    %i\n", g_badn_ctr);
	LogTail(llNotice,"# of Bad Func #'s      %i\n", g_badf_ctr);
	LogTail(llNotice,"# of Bad Pub Names     %i\n", g_badp_ctr);
	LogTail(llNotice,"# of Bad Ref Names     %i\n", g_badr_ctr);
	LogTail(llNotice,"Total Funcion Patterns %i\n", g_pats_ctr);
}

