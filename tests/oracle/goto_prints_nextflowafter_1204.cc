/*
 * GOTO-PRINTS-NEXTFLOWAFTER-ARMS-0001: locked Ghidra 12.0.4 oracle for the
 * `getParent()->nextFlowAfter(this)` virtual dispatch that
 * `BlockGoto::gotoPrints` (block.cc:2881-2890 cc:2885) reaches through.
 *
 * Covers every reachable override with hand-built copy-level trees (leaves
 * are BlockCopy, so `getFrontLeaf` is non-null and the dispatch is
 * discriminative — unlike Vertex-leaf fixtures whose front leaves
 * null-degenerate):
 *
 *   case while_tail_break_goto  — BlockWhileDo (block.cc:3341-3351): a
 *       goto at the body List tail gets front_leaf(cond) = the loop head
 *       (NOT the loop-after block); target==after → prints=1.
 *   case infloop_backedge_goto  — BlockInfLoop (block.cc:3476-3483): a
 *       goto targeting the loop head gets the head itself as next →
 *       prints=0 (natural backedge, no goto statement/label).
 *   case switch_fallthru_goto   — BlockSwitch (block.cc:3639-3661): the
 *       dispatch-root slot (cs[0] head copy) → null (arm cc:3642); a
 *       t_goto case falling through to the next case → that case's front
 *       leaf → prints=0; non-t_goto cases → null ("Otherwise there is a
 *       break statement in the flow"). Labels stay at their all-zero
 *       defaults so the finalizePrinting stable_sort (block.cc:3591,
 *       equal keys) preserves grabCaseBasic order — matching the Rust
 *       component-order model; the real label sort lands with
 *       JUMPTABLE-TABLEAPI-0001 on both sides.
 *   case switch_multigoto_gotoedge — BlockSwitch whose dispatch root
 *       cs[0] is a BlockMultiGoto (ruleBlockGoto's isSwitchOut peel,
 *       block.cc:1707-1751): grabCaseBasic's t_multigoto arm (block.cc
 *       3548-3553) APPENDS the peeled gotoedge target as a case with
 *       gototype f_goto_goto after the regular cases. The last regular
 *       case is a t_goto whose nextFlowAfter falls through into the
 *       APPENDED case (arm cc:3653-3657 — caseblocks extend past the
 *       absorbed component list); BlockMultiGoto::nextFlowAfter
 *       (block.cc:2931-2936) gives null for its wrapped head; and
 *       scopeBreak promotes the appended case to f_break_goto because
 *       its target IS the switch exit (cc:3620-3623, "empty break").
 *   case goto_wrapping_goto     — BlockGoto (block.cc:2899-2903): the
 *       inner goto under the outer goto's wrapped List gets the OUTER
 *       goto target's front leaf; prints=0 when the inner target IS the
 *       outer target (the outer goto subsumes it).
 *   case if_else_tail_goto      — BlockIf (block.cc:3127-3134): slot-0
 *       null; tc/fc → the parent arm (the if's successor), never the
 *       sibling fc.
 *   case dowhile_tail_goto      — BlockDoWhile (block.cc:3448-3451):
 *       always null → prints=1.
 *
 * Trees are built through the production factories (newBlockGoto /
 * newBlockList / newBlockWhileDo / newBlockDoWhile / newBlockInfLoop /
 * grabCaseBasic + identifyInternal + addBlock — the same calls
 * BlockGraph::newBlockSwitch performs), on BlockCopy leaves mirrored from
 * originals with real edges exactly as BlockGraph::buildCopy
 * (block.cc:1925-1938) does. The ActionFinalStructure tail
 * scopeBreak(-1,-1) (blockaction.cc:2193) then runs over the root list.
 *
 * Registered normalizations (mirrored on the Rust side):
 *  - top-level list order is arranged explicitly after construction
 *    (production orderBlocks sorts by index; the factories append, so the
 *    fixture re-orders to the canonical [loop, exit] order);
 *  - for a BlockSwitch parent the dispatch walk enumerates slot 0 =
 *    getBlock(0) (the cs[0] dispatch root, arm-① null) and then one slot
 *    per CaseOrder entry (slot i+1) instead of the absorbed component
 *    list: grabCaseBasic APPENDS the multigoto gotoedge targets to
 *    caseblocks beyond the components (block.cc:3548-3553) and Rugra's
 *    BlockSwitch keeps the appended cases in its `cases` list, so both
 *    sides emit one line per PRINTED case. For pure-component switches
 *    caseblocks == components[1..] and the walk is identical;
 *  - observation lines are sorted before printing (per-block facts are
 *    order-free).
 *
 * Mirrors tests/oracle/goto_prints_nextflowafter_1204.rs case for case.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as blockstruct_blockgoto_wrapped_1204.cc).
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "blockaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "jumptable.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef class
#undef private

using namespace ghidra;

static std::string typeName(FlowBlock::block_type bt)
{
  switch (bt) {
  case FlowBlock::t_plain: return "plain";
  case FlowBlock::t_basic: return "basic";
  case FlowBlock::t_graph: return "graph";
  case FlowBlock::t_copy: return "copy";
  case FlowBlock::t_goto: return "goto";
  case FlowBlock::t_multigoto: return "multigoto";
  case FlowBlock::t_ls: return "list";
  case FlowBlock::t_condition: return "condition";
  case FlowBlock::t_if: return "properif";
  case FlowBlock::t_whiledo: return "whiledo";
  case FlowBlock::t_dowhile: return "dowhile";
  case FlowBlock::t_switch: return "switch";
  case FlowBlock::t_infloop: return "infloop";
  default: return "?";
  }
}

// Fixture graph: originals (with real edges + explicit indexes) are owned
// here; the structure graph owns the BlockCopy leaves and composites as
// in production.
struct FixtureGraph {
  BlockGraph structure;
  std::vector<BlockBasic *> originals;

  BlockBasic *original(int4 index)
  {
    BlockBasic *orig = new BlockBasic(nullptr);
    orig->index = index;	// distinct indexes drive scopeBreak threading
    originals.push_back(orig);
    return orig;
  }

  void edge(FlowBlock *from, FlowBlock *to) { structure.addEdge(from, to); }

  // Mirror BlockGraph::buildCopy (block.cc:1925-1938): one BlockCopy per
  // original, copymap back-references, then replaceUsingMap on each copy.
  std::vector<FlowBlock *> copyOf(int n)
  {
    std::vector<FlowBlock *> copies;
    for (int4 i = 0; i < n; ++i) {
      FlowBlock *c = structure.newBlockCopy(originals[i]);
      originals[i]->copymap = c;
      copies.push_back(c);
    }
    for (int4 i = 0; i < (int4)copies.size(); ++i)
      ((BlockCopy *)copies[i])->replaceUsingMap();
    return copies;
  }
};

struct Observation {
  std::map<FlowBlock *, std::string> names;
  std::vector<std::string> lines;

  void name(FlowBlock *bl, const std::string &nm) { names[bl] = nm; }
  std::string nameOf(FlowBlock *bl) const
  {
    if (bl == (FlowBlock *)0) return "null";
    std::map<FlowBlock *, std::string>::const_iterator it = names.find(bl);
    if (it != names.end()) return it->second;
    return "anon";
  }
  std::string desc(FlowBlock *bl) const
  {
    return nameOf(bl) + ":" + (bl == (FlowBlock *)0 ? "null" : typeName(bl->getType()));
  }

  // Per-(composite, component) dispatch observation: the production
  // virtual call gotoPrints reaches through (block.cc:2885).
  void observeDispatch(FlowBlock *parent)
  {
    BlockGraph *g = dynamic_cast<BlockGraph *>(parent);
    if (g == (BlockGraph *)0) return;
    BlockSwitch *sw = dynamic_cast<BlockSwitch *>(parent);
    if (sw != (BlockSwitch *)0) {
      // Normalization (see file header): slot 0 is the cs[0] dispatch
      // root (arm-① null); slots 1.. are the CaseOrder entries — the
      // printed cases, which for the multigoto gotoedge variant extend
      // past the absorbed component list (block.cc:3548-3553).
      for (int4 slot = 0; slot < 1 + sw->getNumCaseBlocks(); ++slot) {
        FlowBlock *comp = (slot == 0) ? g->getBlock(0) : sw->getCaseBlock(slot - 1);
        FlowBlock *next = parent->nextFlowAfter(comp);
        std::ostringstream s;
        s << "dispatch parent=" << typeName(parent->getType())
          << "[" << slot << "] comp=" << desc(comp)
          << " next=" << desc(next);
        lines.push_back(s.str());
      }
      return;
    }
    for (int4 i = 0; i < g->getSize(); ++i) {
      FlowBlock *comp = g->getBlock(i);
      FlowBlock *next = parent->nextFlowAfter(comp);
      std::ostringstream s;
      s << "dispatch parent=" << typeName(parent->getType())
        << "[" << i << "] comp=" << desc(comp)
        << " next=" << desc(next);
      lines.push_back(s.str());
    }
  }

  static void collectGotos(FlowBlock *bl, std::vector<FlowBlock *> &out)
  {
    if (bl->getType() == FlowBlock::t_goto) out.push_back(bl);
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0)
      for (int4 i = 0; i < g->getSize(); ++i) collectGotos(g->getBlock(i), out);
  }

  static void collectAll(FlowBlock *bl, std::vector<FlowBlock *> &out)
  {
    out.push_back(bl);
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0)
      for (int4 i = 0; i < g->getSize(); ++i) collectAll(g->getBlock(i), out);
  }

  // Per-BlockGoto observation: gototype + gotoPrints after the
  // ActionFinalStructure tail scopeBreak (blockaction.cc:2193).
  void observeGotos(const std::vector<FlowBlock *> &toplist)
  {
    std::vector<FlowBlock *> gotos;
    for (int4 i = 0; i < (int4)toplist.size(); ++i) collectGotos(toplist[i], gotos);
    for (int4 i = 0; i < (int4)gotos.size(); ++i) {
      BlockGoto *bg = (BlockGoto *)gotos[i];
      std::ostringstream s;
      s << "goto " << desc(bg)
        << " target=" << desc(bg->getGotoTarget())
        << " gototype=" << bg->getGotoType()
        << " prints=" << (bg->gotoPrints() ? 1 : 0);
      lines.push_back(s.str());
    }
  }

  void emit(const std::string &caseName, const std::vector<FlowBlock *> &toplist)
  {
    std::cout << "case " << caseName << '\n';
    std::vector<FlowBlock *> all;
    for (int4 i = 0; i < (int4)toplist.size(); ++i) collectAll(toplist[i], all);
    for (int4 i = 0; i < (int4)all.size(); ++i) observeDispatch(all[i]);
    observeGotos(toplist);
    std::sort(lines.begin(), lines.end());
    for (int4 i = 0; i < (int4)lines.size(); ++i) std::cout << lines[i] << '\n';
    std::cout << "end\n";
  }
};

int main()
{
  {
    // while_tail_break_goto: WhileDo[cond=b0, body=List[b1, goto(b2→b3)]],
    // b3 = block after the loop (the goto target). gotoPrints must
    // compare the target b3 against the LOOP HEAD b0 → prints=1.
    FixtureGraph f;
    for (int4 i = 0; i < 4; ++i) f.original(i);
    f.edge(f.originals[0], f.originals[1]); // flow b0 → b1
    f.edge(f.originals[2], f.originals[3]); // b2's out-edge: the target b3
    std::vector<FlowBlock *> c = f.copyOf(4);
    Observation obs;
    obs.name(c[0], "b0"); obs.name(c[1], "b1"); obs.name(c[2], "b2"); obs.name(c[3], "b3");
    BlockGoto *gt = f.structure.newBlockGoto(c[2]);
    obs.name(gt, "g0");
    std::vector<FlowBlock *> nodes;
    nodes.push_back(c[1]); nodes.push_back(gt);
    BlockList *body = f.structure.newBlockList(nodes);
    obs.name(body, "body");
    BlockWhileDo *wd = f.structure.newBlockWhileDo(c[0], body);
    obs.name(wd, "wd");
    // Canonical root order [wd, b3] (production orderBlocks intent): the
    // factories append, so arrange explicitly.
    std::vector<FlowBlock *> order;
    order.push_back(wd); order.push_back(c[3]);
    f.structure.list = order;
    f.structure.scopeBreak(-1, -1); // ActionFinalStructure tail (cc:2193)
    obs.emit("while_tail_break_goto", f.structure.getList());
  }
  {
    // infloop_backedge_goto: InfLoop[body=List[b0, goto(b1→b0)]] — an
    // explicit backedge goto to the loop head. nextFlowAfter gives the
    // head → gotobl==nextbl → prints=0 (natural backedge).
    FixtureGraph f;
    for (int4 i = 0; i < 2; ++i) f.original(i);
    f.edge(f.originals[1], f.originals[0]); // b1's out-edge: back to head
    std::vector<FlowBlock *> c = f.copyOf(2);
    Observation obs;
    obs.name(c[0], "b0"); obs.name(c[1], "b1");
    BlockGoto *gt = f.structure.newBlockGoto(c[1]);
    obs.name(gt, "g0");
    std::vector<FlowBlock *> nodes;
    nodes.push_back(c[0]); nodes.push_back(gt);
    BlockList *body = f.structure.newBlockList(nodes);
    obs.name(body, "body");
    BlockInfLoop *il = f.structure.newBlockInfLoop(body);
    obs.name(il, "il");
    std::vector<FlowBlock *> order;
    order.push_back(il);
    f.structure.list = order;
    f.structure.scopeBreak(-1, -1);
    obs.emit("infloop_backedge_goto", f.structure.getList());
  }
  {
    // switch_fallthru_goto: Switch components [head, goto(c0→c1), c1,
    // c2] — the second case is a fallthru goto. Dispatch: head (cs[0]
    // dispatch root) → null; the goto case → front_leaf(c1) → prints=0;
    // c1/c2 (non-t_goto) → null. Structure built through the same calls
    // as newBlockSwitch (block.cc:1904-1919) on a hollow switch
    // (jumptable null — labels stay 0, the sort is stable-identity).
    FixtureGraph f;
    for (int4 i = 0; i < 4; ++i) f.original(i);
    f.edge(f.originals[0], f.originals[1]); // dispatch edge head→c0
    f.edge(f.originals[0], f.originals[2]); // dispatch edge head→c1
    f.edge(f.originals[0], f.originals[3]); // dispatch edge head→c2
    f.edge(f.originals[1], f.originals[2]); // c0's out-edge: fallthru c1
    std::vector<FlowBlock *> c = f.copyOf(4);
    Observation obs;
    obs.name(c[0], "head"); obs.name(c[1], "c0"); obs.name(c[2], "c1"); obs.name(c[3], "c2");
    BlockGoto *gt = f.structure.newBlockGoto(c[1]);
    obs.name(gt, "g0");
    std::vector<FlowBlock *> cs;
    cs.push_back(c[0]); cs.push_back(gt); cs.push_back(c[2]); cs.push_back(c[3]);
    static BlockBasic hollow(nullptr);
    BlockSwitch *bs = new BlockSwitch(&hollow);
    bs->grabCaseBasic(f.originals[0], cs);
    f.structure.identifyInternal(bs, cs);
    f.structure.addBlock(bs);
    obs.name(bs, "sw");
    std::vector<FlowBlock *> order;
    order.push_back(bs);
    f.structure.list = order;
    f.structure.scopeBreak(-1, -1);
    obs.emit("switch_fallthru_goto", f.structure.getList());
  }
  {
    // goto_wrapping_goto: g_outer wraps List[g_inner]; both target b2.
    // The inner goto's dispatch crosses the Goto arm → next =
    // front_leaf(b2); inner target == b2 → prints=0 (subsumed).
    FixtureGraph f;
    for (int4 i = 0; i < 3; ++i) f.original(i);
    f.edge(f.originals[0], f.originals[2]); // b0's out-edge: target b2
    std::vector<FlowBlock *> c = f.copyOf(3);
    Observation obs;
    obs.name(c[0], "b0"); obs.name(c[1], "b1"); obs.name(c[2], "b2");
    BlockGoto *gin = f.structure.newBlockGoto(c[0]);
    obs.name(gin, "g_in");
    std::vector<FlowBlock *> inner_nodes;
    inner_nodes.push_back(gin);
    BlockList *inner = f.structure.newBlockList(inner_nodes);
    obs.name(inner, "inner");
    f.edge(inner, c[2]);		// outer goto target b2
    BlockGoto *gout = f.structure.newBlockGoto(inner);
    obs.name(gout, "g_out");
    std::vector<FlowBlock *> order;
    order.push_back(gout);
    f.structure.list = order;
    f.structure.scopeBreak(-1, -1);
    obs.emit("goto_wrapping_goto", f.structure.getList());
  }
  {
    // if_else_tail_goto: If[cond=b0, tc=List[b1, goto(b2→b4)], fc=b3],
    // b4 = block after the if. The tc-tail goto's dispatch: If slot!=0 →
    // parent arm → b4 (NEVER the fc head b3); target b4 → prints=0.
    FixtureGraph f;
    for (int4 i = 0; i < 5; ++i) f.original(i);
    f.edge(f.originals[0], f.originals[1]);
    f.edge(f.originals[0], f.originals[3]);
    f.edge(f.originals[2], f.originals[4]); // b2's out-edge: past the if
    std::vector<FlowBlock *> c = f.copyOf(5);
    Observation obs;
    obs.name(c[0], "b0"); obs.name(c[1], "b1"); obs.name(c[2], "b2");
    obs.name(c[3], "b3"); obs.name(c[4], "b4");
    BlockGoto *gt = f.structure.newBlockGoto(c[2]);
    obs.name(gt, "g0");
    std::vector<FlowBlock *> nodes;
    nodes.push_back(c[1]); nodes.push_back(gt);
    BlockList *tc = f.structure.newBlockList(nodes);
    obs.name(tc, "tc");
    BlockIf *bif = f.structure.newBlockIfElse(c[0], tc, c[3]);
    obs.name(bif, "if");
    std::vector<FlowBlock *> order;
    order.push_back(bif); order.push_back(c[4]);
    f.structure.list = order;
    f.structure.scopeBreak(-1, -1);
    obs.emit("if_else_tail_goto", f.structure.getList());
  }
  {
    // dowhile_tail_goto: DoWhile[List[b0, goto(b1→b2)]], b2 = block
    // after the loop. DoWhile arm → null → prints=1.
    FixtureGraph f;
    for (int4 i = 0; i < 3; ++i) f.original(i);
    f.edge(f.originals[1], f.originals[2]); // b1's out-edge: past the loop
    std::vector<FlowBlock *> c = f.copyOf(3);
    Observation obs;
    obs.name(c[0], "b0"); obs.name(c[1], "b1"); obs.name(c[2], "b2");
    BlockGoto *gt = f.structure.newBlockGoto(c[1]);
    obs.name(gt, "g0");
    std::vector<FlowBlock *> nodes;
    nodes.push_back(c[0]); nodes.push_back(gt);
    BlockList *body = f.structure.newBlockList(nodes);
    obs.name(body, "body");
    BlockDoWhile *dw = f.structure.newBlockDoWhile(body);
    obs.name(dw, "dw");
    std::vector<FlowBlock *> order;
    order.push_back(dw); order.push_back(c[2]);
    f.structure.list = order;
    f.structure.scopeBreak(-1, -1);
    obs.emit("dowhile_tail_goto", f.structure.getList());
  }
  {
    // switch_multigoto_gotoedge: the switch's dispatch root cs[0] is a
    // BlockMultiGoto — ruleBlockGoto's isSwitchOut peel (newBlockMultiGoto
    // over the head copy, gotoedge = head's slot-2 target c[3]). The
    // regular cases are cA (plain copy) and g0 (t_goto wrapping cB, its
    // own out-edge to `out` outside the switch); grabCaseBasic's
    // t_multigoto arm (block.cc:3548-3553) appends the gotoedge target
    // c[3] as a case with gototype f_goto_goto AFTER g0, so g0's
    // nextFlowAfter falls through into the APPENDED case (front leaf c3,
    // arm cc:3653-3657) — NOT to g0's own goto target `out`. The
    // multigoto arm itself is null for the wrapped head (block.cc
    // 2931-2936). scopeBreak promotes the appended case to f_break_goto
    // (cc:3620-3623: its target c3 IS the block after the switch root,
    // i.e. the switch exit) while g0 stays f_goto_goto (target `out` is
    // not any enclosing loop exit).
    FixtureGraph f;
    for (int4 i = 0; i < 5; ++i) f.original(i);
    f.edge(f.originals[0], f.originals[1]); // dispatch edge head→cA
    f.edge(f.originals[0], f.originals[2]); // dispatch edge head→cB
    f.edge(f.originals[0], f.originals[3]); // dispatch edge head→c3 (peeled)
    f.edge(f.originals[2], f.originals[4]); // cB's own out-edge → out
    std::vector<FlowBlock *> c = f.copyOf(5);
    Observation obs;
    obs.name(c[0], "head"); obs.name(c[1], "cA"); obs.name(c[2], "cB");
    obs.name(c[3], "c3"); obs.name(c[4], "out");
    BlockMultiGoto *mg = f.structure.newBlockMultiGoto(c[0], 2);
    obs.name(mg, "mg");
    BlockGoto *gt = f.structure.newBlockGoto(c[2]);
    obs.name(gt, "g0");
    std::vector<FlowBlock *> cs;
    cs.push_back(mg); cs.push_back(c[1]); cs.push_back(gt);
    static BlockBasic hollow(nullptr);
    BlockSwitch *bs = new BlockSwitch(&hollow);
    bs->grabCaseBasic(f.originals[0], cs);
    f.structure.identifyInternal(bs, cs);
    f.structure.addBlock(bs);
    obs.name(bs, "sw");
    std::vector<FlowBlock *> order;
    order.push_back(bs); order.push_back(c[3]); order.push_back(c[4]);
    f.structure.list = order;
    f.structure.scopeBreak(-1, -1); // ActionFinalStructure tail (cc:2193)
    obs.emit("switch_multigoto_gotoedge", f.structure.getList());
  }
  return 0;
}
