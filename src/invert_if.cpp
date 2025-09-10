/*
  ida-sdk\src\plugins\vds3\hexrays_sample3.cpp
	with INTERR 50683 fix and minimal integration related changes
*/

/*
 *      Hex-Rays Decompiler project
 *      Copyright (c) 2007-2025 by Hex-Rays, support@hex-rays.com
 *      ALL RIGHTS RESERVED.
 *
 *      Sample plugin for Hex-Rays Decompiler.
 *      It introduces a new command for the user: invert if-statement
 *      For example, a statement like
 *
 *      if ( cond )
 *      {
 *        statements1;
 *      }
 *      else
 *      {
 *        statements2;
 *      }
 *
 *      will be displayed as
 *
 *      if ( !cond )
 *      {
 *        statements2;
 *      }
 *      else
 *      {
 *        statements1;
 *      }
 *
 *      Please note that the plugin cannot directly modify the current ctree.
 *      If the ctree is recreated, the changes will be lost.
 *      To make them persistent, we need to save information about the inverted
 *      if statements in the database and automatically reapply them
 *      for each new build. This approach makes all modifications
 *      persistent. The user can quit IDA and restart the session:
 *      his changes will be intact.
 *
 */
#include "warn_off.h"
#include <hexrays.hpp>
#include "warn_on.h"

#include "invert_if.h"
#include "helpers.h"

// The node to keep inverted-if information.
static const char nodename[] = "$ hexrays inverted-if";
static netnode node;

// Cached copy of inverted if-statement addresses
static eavec_t inverted_ifs;

// INTERR 50683 workaround
void fix_jmp_cnd_ea(cexpr_t *e, ea_t ea)
{
  switch ( e->op )
  {
  case cot_comma:
  case cot_lor:
  case cot_land:
    fix_jmp_cnd_ea(e->y, ea);
    return;
  }
  if(e->ea != BADADDR)
    e->ea = ea;
}

//--------------------------------------------------------------------------
// The user has selected to invert the if statement. Update ctree
// and refresh the view.
static void do_invert_if(cinsn_t *i)
{
  QASSERT(100106, i->op == cit_if);
  cif_t &cif = *i->cif;
  // create an inverted condition and swap it with the if-condition
  cexpr_t *notcond = lnot(new cexpr_t(cif.expr));
  notcond->swap(cif.expr);
  delete notcond;
  // swap if branches
  qswap(cif.ielse, cif.ithen);

  // INTERR 50683 workaround
  fix_jmp_cnd_ea(&i->cif->expr, i->ea);
}

//--------------------------------------------------------------------------
static void add_inverted_if(ea_t ea)
{
  eavec_t::iterator p = inverted_ifs.find(ea);
  if ( p != inverted_ifs.end() ) // already present?
    inverted_ifs.erase(p);       // delete the mark
  else
    inverted_ifs.push_back(ea);  // remember if-statement address
  // immediately save data into the database
	eavec_t copy = inverted_ifs;
	for (size_t i = 0; i < copy.size(); i++)
		copy[i] = ea2node(copy[i]);
	node.setblob(copy.begin(), copy.size() * sizeof(ea_t), 0, 'I');
}

//--------------------------------------------------------------------------
// Check if the item under the cursor is 'if' or 'else' keyword
// If yes, return pointer to the corresponding ctree item
cinsn_t *find_if_statement(vdui_t *vu)
{
  // 'if' keyword: straightforward check
  if ( vu->item.is_citem() )
  {
    cinsn_t *i = vu->item.i;
    // we can handle only if-then-else statements, so check that the 'else'
    // clause exists
    if ( i->op == cit_if && i->cif->ielse != nullptr )
      return i;
  }
  // check for 'else' line. The else lines do not correspond
  // to any ctree item. That's why we have to check for them separately.
  // we could extract the corresponding text line but this would be a bad approach
  // a line with single 'else' would not give us enough information to locate
  // the corresponding 'if'. That's why we use the line tail marks.
  // All 'else' line will have the ITP_ELSE mark
  if ( vu->tail.citype == VDI_TAIL && vu->tail.loc.itp == ITP_ELSE )
  {
    // for tail marks, we know only the corresponding ea,
    // not the pointer to if-statement
    // find it by walking the whole ctree
    struct ida_local if_finder_t : public ctree_visitor_t
    {
      ea_t ea;
      cinsn_t *found;
      if_finder_t(ea_t e) : ctree_visitor_t(CV_FAST|CV_INSNS), ea(e), found(nullptr) {}
      int idaapi visit_insn(cinsn_t *i) override
      {
        if ( i->op == cit_if && i->ea == ea )
        {
          found = i;
          return 1; // stop enumeration
        }
        return 0;
      }
    };
    if_finder_t iff(vu->tail.loc.ea);
    if ( iff.apply_to(&vu->cfunc->body, nullptr) )
      return iff.found;
  }
  return nullptr;
}

//--------------------------------------------------------------------------
void convert_marked_ifs(cfunc_t *cfunc)
{
  // we walk the ctree and for each if-statement check if has to be inverted
  struct ida_local if_inverter_t : public ctree_visitor_t
  {
    if_inverter_t(void) : ctree_visitor_t(CV_FAST|CV_INSNS) {}
    int idaapi visit_insn(cinsn_t *i)
    {
      if ( i->op == cit_if && inverted_ifs.has(i->ea) )
        do_invert_if(i);
      return 0; // continue enumeration
    }
  };
  if_inverter_t ifi;
  ifi.apply_to(&cfunc->body, NULL); // go!
}

//-------------------------------------------------------------------------
struct ida_local invert_if_ah_t : public action_handler_t
{
  virtual int idaapi activate(action_activation_ctx_t *ctx)
  {
    vdui_t *vu = get_widget_vdui(ctx->widget);
    cinsn_t *i = find_if_statement(vu);
    add_inverted_if(i->ea);
    // we manually invert this if and recreate text.
    // this is faster than rebuilding ctree from scratch.
    do_invert_if(i);
    vu->cfunc->refresh_func_ctext();
    return 1;
  }

  virtual action_state_t idaapi update(action_update_ctx_t *ctx)
  {
    vdui_t *vu = get_widget_vdui(ctx->widget);
    if ( vu == NULL )
      return AST_DISABLE_FOR_WIDGET;
    return find_if_statement(vu) == NULL ? AST_DISABLE : AST_ENABLE;
  }
  virtual idaapi ~invert_if_ah_t() {}
};
static invert_if_ah_t invert_if_ah;
static const action_desc_t invert_if_action = ACTION_DESC_LITERAL(
        INV_IF_ACTION_NAME, "[hrt] Invert if-statement", &invert_if_ah,
        NULL, NULL, -1);

//--------------------------------------------------------------------------
// Initialize the plugin.
void init_invert_if()
{
  if ( !node.create(nodename) ) // create failed -> node existed
  {
    size_t n;
    void *blob = node.getblob(NULL, &n, 0, 'I');
    if ( blob != NULL )
    {
      inverted_ifs.clear();
      inverted_ifs.inject((ea_t *)blob, n / sizeof(ea_t));
      for ( size_t i=0; i < inverted_ifs.size(); i++ )
        inverted_ifs[i] = node2ea(inverted_ifs[i]);
    }
  }
  register_action(invert_if_action);
}
