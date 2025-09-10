//  ida-sdk\src\plugins\vds12\hexrays_sample12.cpp
//	with minor integration related changes

/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2025 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It shows a list of direct references to a register from the current
 *      instruction.
 */

#include "warn_off.h"
#include <hexrays.hpp>
#include <frame.hpp>
#include "warn_on.h"

#include "helpers.h"

//--------------------------------------------------------------------------
static void collect_block_xrefs(eavec_t *out, mlist_t *list, const mblock_t *blk, const minsn_t *ins, bool find_uses)
{
  for (const minsn_t *p=ins; p != NULL && !list->empty(); p = find_uses ? p->next : p->prev ) {
    mlist_t use = blk->build_use_list(*p, MUST_ACCESS); // things used by the insn
    mlist_t def = blk->build_def_list(*p, MUST_ACCESS); // things defined by the insn
    mlist_t &plst = find_uses ? use : def;
    if (list->has_common(plst))
      out->add_unique(p->ea); // this microinstruction seems to use our operand
    list->sub(def);
  }
}

//--------------------------------------------------------------------------
static void collect_xrefs(eavec_t *out, const op_parent_info_t &ctx, const mop_t *mop, mlist_t list, const graph_chains_t &du, bool find_uses)
{
  // first collect the references in the current block
  minsn_t *start = find_uses ? ctx.topins->next : ctx.topins->prev;
  collect_block_xrefs(out, &list, ctx.blk, start, find_uses);

  // then find references in other blocks
  int serial = ctx.blk->serial;                 // block number of the operand
  const block_chains_t &bc = du[serial];        // chains of that block
  const chain_t *ch = bc.get_chain(*mop);       // chain of the operand
  if ( ch == nullptr )
    return; // odd
  for ( size_t i = 0; i < ch->size(); i++ )
  {
    int bn = ch->at(i);
    mblock_t *b = ctx.mba->get_mblock(bn);      // block that uses the instruction
    minsn_t *ins = find_uses ? b->head : b->tail;
    mlist_t tmp = list;
    collect_block_xrefs(out, &tmp, b, ins, find_uses);
  }
}

//--------------------------------------------------------------------------
static const int xwidths[] = { 7, sizeof(ea_t)*2, 60 };
static const char *const xheader[] = { "Type", "Address", "Instruction" };

struct ida_local rxref_chooser_t : public chooser_t
{
  const eavec_t &xrefs;
  const gco_info_t &gco;
  ea_t curr_ea;
	size_t ndefs;

  rxref_chooser_t(const eavec_t &v, const char *t, size_t n, ea_t ea, const gco_info_t &_gco)
    : chooser_t(CH_MODAL|CH_KEEP, qnumber(xwidths), xwidths, xheader, t), xrefs(v), gco(_gco), curr_ea(ea), ndefs(n)
  { }
  virtual size_t idaapi get_count() const { return xrefs.size(); }
  virtual void idaapi get_row(qstrvec_t *cols, int *, chooser_item_attrs_t *,size_t n) const
  {
    ea_t ea = get_ea(n);
    bool both = (gco.flags & (GCO_USE|GCO_DEF)) == (GCO_USE|GCO_DEF);
    cols->at(0) = ea == curr_ea && both ? "use/def"
                : n < ndefs             ? "def"
                :                         "use";
    cols->at(1).sprnt("%a", ea);
    generate_disasm_line(&cols->at(2), ea, GENDSM_REMOVE_TAGS);
  }
  virtual ea_t idaapi get_ea(size_t n) const { return xrefs[n]; }
};

//--------------------------------------------------------------------------
static void show_xrefs(ea_t ea, const gco_info_t &gco, const eavec_t &_xrefs, size_t ndefs)
{
  qstring title;
  title.sprnt("[hrt] xrefs to %s at %a", gco.name.begin(), ea);
  rxref_chooser_t xc(_xrefs, title.begin(), ndefs, ea, gco);
  ssize_t i = xc.choose();
  if ( i >= 0 )
    jumpto(_xrefs[i]);
}

//--------------------------------------------------------------------------
bool regrefs(ea_t ea, func_t *pfn, gco_info_t &gco)
{
  // generate microcode
  hexrays_failure_t hf;
  mba_ranges_t mbr(pfn);
  mbl_array_t *mba = gen_microcode(mbr, &hf, NULL, DECOMP_WARNINGS, MMAT_PREOPTIMIZED);
  if ( mba == nullptr ) {
    warning("[hrt] %a: %s", hf.errea, hf.desc().c_str());
    return true;
  }

  merror_t merr = mba->build_graph();
  if ( merr != MERR_OK ) {
    qstring tmp;
    ea_t errea = get_merror_desc(&tmp, merr, mba);
    warning("[hrt] %a: %s", errea, tmp.c_str());
    return true;
  }

  // determine calling conventions without performing any optimizations
  // or deleting dead code (doing so would delete an instruction that
  // refers to our register and confuse the user)
  int ncalls = mba->analyze_calls(ACFL_GUESS);

  // we ignore eventual errors and try to show something even if we failed
  // to detect some calling conventions
  if ( ncalls < 0 )
    Log(llWarning, "%a: failed to determine some calling conventions\n", pfn->start_ea);

  // prepare mlist for the current operand. we will use to to find references
  // to the current operand in the microcode. usually we do not use operands
  // (processor instruction operands nor microcode instruction operands)
  // for searches. instead, we build a 'mlist_t' instance and use it.
  mlist_t list;
  if ( !gco.append_to_list(&list, mba) ) {
    warning("[hrt] Failed to represent %s as microcode list", gco.name.c_str());
    delete mba;
    return false;
  }

  op_parent_info_t ctx;
  mop_t *mop = mba->find_mop(&ctx, ea, gco.is_def(), list);
  if ( mop == nullptr ) {
    warning("[hrt] Could not find the operand in the microcode, sorry");
    delete mba;
    return false;
  }

  eavec_t xrefs;
  size_t ndefs = 0;
  {
    // get use-def chains. do it inside a block in order to release
    // the chains immediately after using them
    mbl_graph_t *graph = mba->get_graph();
    chain_keeper_t ud = graph->get_ud(GC_REGS_AND_STKVARS);
    chain_keeper_t du = graph->get_du(GC_REGS_AND_STKVARS);

    if (gco.is_use()) {
      // collect definitions
      collect_xrefs(&xrefs, ctx, mop, list, ud, false);
      ndefs = xrefs.size();
      // register is used by the current instruction - add 'ea' as use-addr
      xrefs.add_unique(ea);
    }

    if (gco.is_def()) {
      // register is defined by the current instruction - add 'ea' as def-addr
      if (xrefs.add_unique(ea))
        ndefs = xrefs.size();
      // collect using
      collect_xrefs(&xrefs, ctx, mop, list, du, true);
    }
    // the chains will be released after quitting the block
  }

  show_xrefs(ea, gco, xrefs, ndefs);

  // We must explicitly delete the microcode array
  delete mba;
  return true;
}

