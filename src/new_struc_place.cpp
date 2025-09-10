//Evolution of new_struc_place.cpp from https://github.com/nihilus/hexrays_tools

#include "warn_off.h"
#include <pro.h>
#include <hexrays.hpp>
#include <ida.hpp>
#include <kernwin.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include "warn_off.h"

#include "new_struct.h"
#include "new_struc_place.h"
#include "helpers.h"

// shortcut to make the text more readable
typedef new_struc_place_t cp_t;

//--------------------------------------------------------------------------
// Short information about the current location.
// It will be displayed in the status line
void ida_export new_struc_place_t__print(const cp_t *ths, qstring *buf, void *)
{
	buf->sprnt("%d %d", ths->idx, ths->subtype);
}

//--------------------------------------------------------------------------
// Convert current location to 'uval_t'
uval_t ida_export new_struc_place_t__touval(const cp_t *ths, void *)
{
	return (ths->idx << 5) + ths->subtype;
}

//--------------------------------------------------------------------------
// Make a copy
place_t *ida_export new_struc_place_t__clone(const cp_t *ths)
{
	return new cp_t(*ths);
}

//--------------------------------------------------------------------------
// Copy from another new_struc_place_t object
void ida_export new_struc_place_t__copyfrom(cp_t *ths, const place_t *from)
{
	new_struc_place_t *s = (new_struc_place_t *)from;
	ths->idx     = s->idx;
	ths->lnnum = s->lnnum;
	ths->subtype = s->subtype;
}

//--------------------------------------------------------------------------
// Create a new_struc_place_t object at the specified address
// with the specified data
static new_struc_place_t new_struc_place;
place_t *ida_export new_struc_place_t__makeplace(const cp_t *, void *, uval_t x, int lnnum)
{
	new_struc_place.idx = (x >> 5);
	new_struc_place.subtype = x & 0x1F;
	new_struc_place.lnnum = lnnum;
	return &new_struc_place;
}

//--------------------------------------------------------------------------
// Compare two locations except line numbers (lnnum)
  // This function is used to organize loops.
  // For example, if the user has selected an area, its boundaries are remembered
  // as location objects. Any operation within the selection will have the following
  // look: for ( loc=starting_location; loc < ending_location; loc.next() )
  // In this loop, the comparison function is used.
  // Returns: -1: if the current location is less than 't2'
  //           0: if the current location is equal to than 't2'
  //           1: if the current location is greater than 't2'
int ida_export new_struc_place_t__compare(const cp_t *ths, const place_t *t2)
{
	new_struc_place_t *s = (new_struc_place_t *)t2;
	uval_t i1 = new_struc_place_t__touval(ths, NULL);
	uval_t i2 = new_struc_place_t__touval(s, NULL);

	if (i1 == i2)
		return 0;
	if (i1 > i2)
		return 1;
	else
		return -1;
}

int ida_export new_struc_place_t__compare2(const cp_t *ths, const place_t *t2, void*)
{
	return new_struc_place_t__compare(ths, t2);
}

#if IDA_SDK_VERSION >= 920
bool ida_export new_struc_place_t__equals(const cp_t *ths, const place_t *t2, void*)
{
	return new_struc_place_t__compare(ths, t2) == 0;
}
#endif // IDA_SDK_VERSION >= 920

//--------------------------------------------------------------------------
// Check if the location data is correct and if not, adjust it
void ida_export new_struc_place_t__adjust(cp_t *ths, void *ud)
{
	field_info_t &sv = *(field_info_t *)ud;
	if (ud == NULL)
		ths->idx = BADADDR;
	else {
		if (ths->idx >= sv.size())
			ths->idx = (uval_t)sv.size() - 1;
		if (ths->subtype >= sv.types_at_idx_qty(ths->idx))
			ths->subtype = sv.types_at_idx_qty(ths->idx) - 1;
	}
}

//--------------------------------------------------------------------------
// Move to the previous location
bool ida_export new_struc_place_t__prev(cp_t *ths, void * ud)
{
	field_info_t &sv = *(field_info_t *)ud;
	if (ths->idx == BADADDR)
		return false;

	if ( ths->idx == 0 && ths->subtype == 0 )
		return false;
	if(ths->subtype>0)
	{
		--ths->subtype;
		return true;
	}
	--ths->idx;
	ths->subtype = sv.types_at_idx_qty(ths->idx)-1;
	return true;
}

//--------------------------------------------------------------------------
// Move to the next location
bool ida_export new_struc_place_t__next(cp_t *ths, void *ud)
{
	field_info_t &sv = *(field_info_t *)ud;
	if(ths->idx + 1 >  sv.size())
		return false;
	
	ths->subtype++;
	if(ths->subtype == sv.types_at_idx_qty(ths->idx)) {
		++ths->idx;
		ths->subtype = 0;
		if (ths->idx ==  sv.size())
			return false;
	} else {
		//++ths->subtype;	
	}
	return true;
}

//--------------------------------------------------------------------------
// Are we at the beginning of the data?
bool ida_export new_struc_place_t__beginning(const cp_t *ths, void *)
{
	if (ths->idx == BADADDR)
		return true;
	return ths->idx == 0 && ths->subtype == 0;
}

//--------------------------------------------------------------------------
// Are we at the end of the data?
bool ida_export new_struc_place_t__ending(const cp_t *ths, void *ud)
{
	field_info_t &sv = *(field_info_t *)ud;
	if (ths->idx == BADADDR)
		return true;
	if (ths->idx+1 >= sv.size())
		return true;	
	return ((ths->idx+1  == sv.size()) && (ths->subtype + 1 == sv.types_at_idx_qty(ths->idx)));
}

//--------------------------------------------------------------------------
/// Generate text lines for the current location.
/// \param ud             pointer to user-defined context data. Is supplied by linearray_t
/// \param lines          array of pointers to output lines. the pointers will be overwritten
///                       by lines that are allocated using qstrdup. the caller must qfree them.
/// \param maxsize        maximal number of lines to generate
/// \param default_lnnum  pointer to the cell that will contain the number of
///                       the most 'interesting' generated line
/// \param pfx_color      pointer to the cell that will contain the line prefix color
/// \param bgcolor        pointer to the cell that will contain the background color
/// \return number of generated lines

int ida_export new_struc_place_t__generate(
	const cp_t *ths,
	qstrvec_t *out,
	int *default_lnnum,
	color_t *prefix_color,
	bgcolor_t *bg_color,
	void *ud,
	int maxsize)
{
	field_info_t &sv = *(field_info_t *)ud;
	uval_t idx = ths->idx;

	if (sv.size()==0) {
		out->push_back("Please do \"scan variable\" at first");
		return (int)out->size();
	}

	if (idx >= sv.size() || maxsize <= 0)
		return 0;
	
	auto iter =  sv.begin();
	if (iter == sv.end())
		return 0;
	if (!safe_advance(iter, sv.end(), idx))
		return 0;
	if (iter == sv.end())
		return 0;

	const scan_info_t& si = iter->second;
	uval_t offset = iter->first;
	qstring name;
	name.sprnt("field_%02x", offset);
	qstring prefix;
	unsigned int len = si.nesting_counter*2;
	if (len >= MAXSTR)
		len = MAXSTR - 1;
	prefix.fill(' ', len);

	auto i = si.types.begin();
	if(i == si.types.end())
		return 0;

	if (!safe_advance(i, si.types.end(), ths->subtype))
		return 0;

	if (i != si.types.end()) {
		qstring line;
		qstring result;
		i->type.print(&result, name.c_str(), PRTYPE_1LINE, 5, 40);

		if ( sv.current_offset == offset  && out->size() == 0)
			line.sprnt("%s" COLSTR( "%08a", SCOLOR_ERROR) ": %s", prefix.c_str(), offset, result.c_str());
		else
			line.sprnt("%s" "%08a" ": %s", prefix.c_str(), offset, result.c_str());
		if (si.is_array)
			line.cat_sprnt( COLSTR( "[]", SCOLOR_ERROR));
		out->push_back(line);

		if (i->enabled) {
			if (si.types.in_conflict())
				*bg_color = 0x4500A0;//0xA0FFFF;
			else
				*bg_color = DEFCOLOR;//0xFFFFFF;
		} else {
			*bg_color = 0x0000ff;//0xDCDCDC;
		}		
	}

	if (si.types.size() == ths->subtype + 1) {
		for (max_adjustments_t::iterator j = sv.max_adjustments.begin(); j != sv.max_adjustments.end(); j++) {
			if (j->second == offset) {
				qstring s;
				s.sprnt("%s%08a: -------------- last accessed offset from scan 0x%08a  ----------", prefix.c_str(), offset, j->first);
				out->push_back(s);
			}
		}
		
		if(idx == sv.size()-1) {
			//TODO: use color SCOLOR_AUTOCMT
			out->push_back("/*-----------------------------------------------------------------------") ;
			out->push_back("'del' to remove collisions");
			out->push_back("'ins' to insert BYTE field, useful if you know struct allocation size");
			out->push_back("'*' to change master offset (for nested structs)");
			out->push_back("'+' and '-' to shift parts of structure (substruct select)");
			out->push_back("'p' to build substructures");
			out->push_back("'y' to change item type");
			out->push_back("'r' to make array");
			out->push_back("'x' to show functions list");
			out->push_back("'g' to show pseudocode of next function");
			out->push_back("Click on some variable in pseudocode and choose \"finalize structure\"");
			out->push_back("-----------------------------------------------------------------------*/") ;
		}
	}
	*default_lnnum = 0;
	return (int)out->size();
}

/// Serialize this instance.
/// It is fundamental that all instances of a particular subclass
/// of of place_t occupy the same number of bytes when serialized.
/// \param out   buffer to serialize into
void  ida_export new_struc_place_t__serialize(const cp_t *, bytevec_t *)
{
}

/// De-serialize into this instance.
/// 'pptr' should be incremented by as many bytes as
/// de-serialization consumed.
/// \param pptr pointer to a serialized representation of a place_t of this type.
/// \param end pointer to end of buffer.
/// \return whether de-serialization was successful
bool        ida_export new_struc_place_t__deserialize(cp_t *, const uchar **, const uchar *)
{
	return false;
}

static int new_struc_place_id = -1;
static new_struc_place_t _template;
void register_new_struc_place()
{
	new_struc_place_id = register_place_class(&_template, 0, &PLUGIN);
}

/// Get the place's ID (i.e., the value returned by register_place_class())
/// \return the id
int         ida_export new_struc_place_t__id(const cp_t *)
{
	return new_struc_place_id;
}

/// Get this place type name.
/// All instances of a given class must return the same string.
/// \return the place type name. Please try and pick something that is
///         not too generic, as it might clash w/ other plugins. A good
///         practice is to prefix the class name with the name
///         of your plugin. E.g., "myplugin:srcplace_t".
const char *ida_export new_struc_place_t__name(const cp_t *)
{
	return "hrt:new_struc_place_t";
}

/// Map the location to an ea_t.
/// \return the corresponding ea_t, or BADADDR;
ea_t        ida_export new_struc_place_t__toea(const cp_t *)
{
	return BADADDR;
}

/// Visit this place, possibly 'unhiding' a section of text.
/// If entering that place required some expanding, a place_t
/// should be returned that represents that section, plus some
/// flags for later use by 'leave()'.
/// \param out_flags flags to be used together with the place_t that is
///                  returned, in order to restore the section to its
///                  original state when leave() is called.
/// \return a place_t corresponding to the beginning of the section
///         of text that had to be expanded. That place_t's leave() will
///         be called with the flags contained in 'out_flags' when the user
///         navigates away from it.
place_t *   ida_export new_struc_place_t__enter(const cp_t *, uint32 *)
{
	return NULL;
}

/// Leave this place, possibly 'hiding' a section of text that was
/// previously expanded (at enter()-time.)
void        ida_export new_struc_place_t__leave(const cp_t *, uint32)
{
}

/// Rebase the place instance
/// \param infos the segments that were moved
/// \return true if place was rebased, false otherwise
bool ida_export new_struc_place_t__rebase(cp_t *, const segm_move_infos_t &)
{
	return true;
}

