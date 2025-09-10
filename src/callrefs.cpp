/*
  ida-sdk\src\plugins\vds14\hexrays_sample14.cpp
  modified for:
  * join into one line and correctly display calls that occupy few lines of pseudocode
  * shows global variables xrefs too
  * shows helpers calls (for easy inlines finding)
*/

/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2025 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It shows xrefs to the called function as the decompiler output.
 *      All calls are displayed with the call arguments.
 *      Usage: Shift-X or Jump, Jump to call xrefs...
 */

#include "warn_off.h"
#include <hexrays.hpp>
#include "warn_on.h"
#include "helpers.h"

struct ida_local xref_info_t
{
  qstring text;
  ea_t ea;
  char xref_type;
};
DECLARE_TYPE_AS_MOVABLE(xref_info_t);
typedef qvector<xref_info_t> xrefvec_t;

//-------------------------------------------------------------------------
// go backwards until the beginning of the basic block
static ea_t find_bb_start(ea_t call_ea)
{
  ea_t ea = call_ea;
  while ( true )
  {
    flags64_t F = get_flags(ea);
    if ( !is_flow(F) || has_xref(F) )
      break;
    insn_t tmp;
    ea_t prev = decode_prev_insn(&tmp, ea);
    if ( prev == BADADDR )
      break;
    ea = prev;
  }
  return ea;
}

//-------------------------------------------------------------------------
static bool determine_decompilation_range(mba_ranges_t *mbr, ea_t call_ea, const tinfo_t &tif)
{
  func_t *pfn = get_func(call_ea);
  if ( pfn != nullptr && calc_func_size(pfn) <= 4096 )
  { // a small function, decompile it entirely
    mbr->pfn = pfn;
    return true;
  }

  ea_t minea = call_ea;
  ea_t maxea = call_ea;
  eavec_t addrs;
  if ( !get_arg_addrs(&addrs, call_ea) )
  {
    apply_callee_tinfo(call_ea, tif);
    if ( !get_arg_addrs(&addrs, call_ea) )
      minea = find_bb_start(call_ea);
  }
  for ( size_t i=0; i < addrs.size(); i++ )
  {
    if ( minea > addrs[i] )
      minea = addrs[i];
    if ( maxea < addrs[i] )
      maxea = addrs[i];
  }
  range_t &r = mbr->ranges.push_back();
  r.start_ea = minea;
  r.end_ea = get_item_end(maxea);
  return true;
}

//-------------------------------------------------------------------------
// decompile the snippet
static bool generate_call_line(qstring *out, bool *canceled, ea_t call_ea, const tinfo_t &tif)
{
  mba_ranges_t mbr;
  if ( !determine_decompilation_range(&mbr, call_ea, tif) )
    return false;
  hexrays_failure_t hf;
  cfuncptr_t func = decompile(mbr, &hf, DECOMP_NO_WAIT);
  if ( func == nullptr )
  {
    if ( hf.code == MERR_CANCELED )
      *canceled = true;
    return false;
  }
  citem_t *call = func->body.find_closest_addr(call_ea);
  if ( call == nullptr || call->ea != call_ea )
    return false;
  const strvec_t &sv = func->get_pseudocode();
  int y;
  if ( !func->find_item_coords(call, nullptr, &y) )
    return false;
  *out = sv[y].line;
  tag_remove(out);
  // indentation does not convey much info, so remove the leading spaces
  out->trim2();
  if(out->last() == '(') { // it may be call with args each in own line
    for(y++; y < sv.size() ; y++) {
      qstring line = sv[y].line;
      tag_remove(&line);
      line.trim2();
      char last = line.last();
      out->append(line);
      if(last == ';' || last == ')' || out->length() > 200)
          break;
    }
  }
  return true;
}

//-------------------------------------------------------------------------
struct ida_local cxref_chooser_t : public chooser_t
{
protected:
  ea_t func_ea;
  const xrefvec_t &list;

  static const int widths_[];
  static const char *const header_[];
  enum { ICON = 55 };

public:
  cxref_chooser_t(uint32 flags, ea_t func_ea, const xrefvec_t &list, const char *title);
  ea_t choose_modal(ea_t xrefpos_ea);
  ea_t choose_modal2(ea_t xrefpos_ea);

  virtual size_t idaapi get_count() const override { return list.size(); }
  virtual void idaapi get_row(
          qstrvec_t *cols,
          int *icon_,
          chooser_item_attrs_t *attrs,
          size_t n) const override;

  // calculate the location of the item,
  // item_data is a pointer to a xref position
  virtual ssize_t idaapi get_item_index(const void *item_data) const override;

protected:
  static const char *direction_str(ea_t ea, ea_t refea)
  {
    return ea > refea ? "Up" : ea < refea ? "Down" : "";
  }
  static void get_xrefed_name(qstring *buf, ea_t ref);

  xrefvec_t::const_iterator find(const xrefpos_t &pos) const
  {
    xrefvec_t::const_iterator it = list.begin();
    xrefvec_t::const_iterator end = list.end();
    for ( ; it != end; ++it )
    {
      const xref_info_t &cur = *it;
      if ( cur.ea == pos.ea && cur.xref_type == pos.type )
        break;
    }
    return it;
  }
};

//-------------------------------------------------------------------------
const int cxref_chooser_t::widths_[] =
{
  6,  // Direction
  1,  // Type
  15, // Address
  50, // Text
};
const char *const cxref_chooser_t::header_[] =
{
  "Direction",  // 0
  "Type",       // 1
  "Address",    // 2
  "Text",       // 3
};

//-------------------------------------------------------------------------
inline cxref_chooser_t::cxref_chooser_t(uint32 flags_, ea_t func_ea_, const xrefvec_t &list_, const char *title_)
  : chooser_t(flags_, qnumber(widths_), widths_, header_, title_), func_ea(func_ea_), list(list_)
{
  CASSERT(qnumber(widths_) == qnumber(header_));
  icon = ICON;
  deflt_col = 2;
}

//-------------------------------------------------------------------------
inline ea_t cxref_chooser_t::choose_modal(ea_t xrefpos_ea)
{
  if ( list.empty() )
  {
    warning("[hrt] There are no %s", title);
    return BADADDR;
  }

  xrefpos_t defpos;
  get_xrefpos(&defpos, xrefpos_ea);
  ssize_t n = ::choose(this, &defpos);
  if ( n < 0 || n >= (ssize_t)list.size() )
    return BADADDR;
  const xref_info_t &entry = list[n];
  if ( n == 0 )
  {
    del_xrefpos(xrefpos_ea);
  }
  else
  {
    xrefpos_t xp(entry.ea, entry.xref_type);
    set_xrefpos(xrefpos_ea, &xp);
  }
  return entry.ea;
}

//-------------------------------------------------------------------------
inline ea_t cxref_chooser_t::choose_modal2(ea_t xrefpos_ea)
{
	xrefpos_t defpos;
	defpos.ea = xrefpos_ea;
	defpos.type = fl_USobsolete;

	ssize_t n = ::choose(this, &defpos);
	if ( n < 0 || n >= (ssize_t)list.size() )
    return BADADDR;
  const xref_info_t &entry = list[n];
  return entry.ea;
}

//-------------------------------------------------------------------------
void idaapi cxref_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const
{
  const xref_info_t &entry = list[n];
  qstrvec_t &cols = *cols_;
  cols[0] = direction_str(func_ea, entry.ea);
  cols[1].sprnt("%c", xrefchar(entry.xref_type));
  get_xrefed_name(&cols[2], entry.ea);
  cols[3] = entry.text;
}

//------------------------------------------------------------------------
ssize_t idaapi cxref_chooser_t::get_item_index(const void *item_data) const
{
  if ( list.empty() )
    return NO_SELECTION;

  // `item_data` is a pointer to a xref position
  xrefpos_t item_pos = *(const xrefpos_t *)item_data;

  if ( !item_pos.is_valid() )
    return 0; // first item by default

  xrefvec_t::const_iterator it = find(item_pos);
  if ( it == list.end() )
    return 0; // first item by default
  return it - list.begin();
}

//-------------------------------------------------------------------------
void cxref_chooser_t::get_xrefed_name(qstring *buf, ea_t ref)
{
  int f2 = GNCN_NOCOLOR; //-V688
  if ( !inf_show_xref_fncoff() )
    f2 |= GNCN_NOFUNC;
  if ( !inf_show_xref_seg() )
    f2 |= GNCN_NOSEG;
  get_nice_colored_name(buf, ref, f2);
}

//-------------------------------------------------------------------------
bool jump_to_call_or_glbl(ea_t ea)
{
  // Retrieve all xrefs to the ea
  xrefblk_t xb;
  xrefvec_t list;
  for ( bool ok = xb.first_to(ea, 0); ok; ok=xb.next_to() )
  {
    xref_info_t &entry = list.push_back();
    entry.ea = xb.from;
    entry.xref_type = xb.type;
  }

  // Generate decompiler output or disassembly output for each xref
  tinfo_t tif;
  if (!get_tinfo(&tif, ea))
    guess_tinfo(&tif, ea);
  show_wait_box("[hrt] Decompiling...");
  bool canceled = false;
  size_t n = list.size();
  for ( size_t i=0; i < n; i++ )
  {
    xref_info_t &entry = list[i];
    bool success = false;
    if (!canceled && !user_cancelled())
    {
      replace_wait_box("[hrt] Decompiling %a (%" FMT_Z "/%" FMT_Z ")...", entry.ea, i, n);
      success = generate_call_line(&entry.text, &canceled, entry.ea, tif);
    }
    if ( !success )
      generate_disasm_line(&entry.text, entry.ea, GENDSM_REMOVE_TAGS);
  }
  hide_wait_box();

  // Display the xref chooser
  qstring title;
  get_short_name(&title, ea);
  title.insert("[hrt] xrefs to ");

  cxref_chooser_t xrefch(CH_MODAL | CH_KEEP, ea, list, title.c_str());
  ea_t target = xrefch.choose_modal(ea);
  if ( target == BADADDR )
    return false;

  // Jump to the seleected target
  return jumpto(target);
}

struct ida_local helpers_locator_t : public ctree_visitor_t
{
	cfunc_t *func;
	const char* helper;
	xrefvec_t *list;
	helpers_locator_t(cfunc_t *func_, const char* helper_, xrefvec_t *list_): ctree_visitor_t(CV_FAST), func(func_), helper(helper_), list(list_) {}
	int idaapi visit_expr(cexpr_t * e)
	{
		if(e->op == cot_call && e->x->op == cot_helper && !qstrcmp(helper, e->x->helper)) {
			xref_info_t &entry = list->push_back();
			entry.ea = e->ea;
			entry.xref_type = fl_USobsolete;

			const strvec_t &sv = func->get_pseudocode();
			int y;
			if (func->find_item_coords(e, nullptr, &y)) {
				entry.text = sv[y].line;
				tag_remove(&entry.text);
				entry.text.ltrim();
			}
		}
		return 0; //continue
	}
};

bool jump_to_helper(vdui_t *vu, cexpr_t *helper)
{
  if(helper->op != cot_helper)
    return false;

  xrefvec_t list;
  helpers_locator_t loc(vu->cfunc, helper->helper, &list);
  loc.apply_to(&vu->cfunc->body, nullptr);

  // Display the xref chooser
  qstring title = helper->helper;
  title.insert("[hrt] xrefs to ");
  citem_t *call = vu->cfunc->body.find_parent_of(helper);


  cxref_chooser_t xrefch(CH_MODAL | CH_KEEP, call->ea, list, title.c_str());
  ea_t target = xrefch.choose_modal2(call->ea);
  if ( target == BADADDR )
    return false;

  // Jump to the seleected target
  citem_t *item = vu->cfunc->body.find_closest_addr(target);
  if (!item)
    return false;

  int x, y;
  if (!vu->cfunc->find_item_coords(item, &x, &y))
    return false;
  return jump_custom_viewer(vu->ct, y, x, 0);
}
