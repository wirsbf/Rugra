/*
 * BLOCKACTION-SCOPEBREAK-GOTOTYPE-0001: locked Ghidra 12.0.4 scopeBreak
 * goto_type oracle (block.hh:88-91 goto types; block.cc:1270-1288
 * BlockGraph::scopeBreak, 2866-2874 BlockGoto::scopeBreak, 2856-2864
 * BlockGoto::markUnstructured, 3075-3084 BlockIf::scopeBreak, 3067-3073
 * BlockIf::markUnstructured, 3324-3330 BlockWhileDo::scopeBreak,
 * 3434-3439 BlockDoWhile::scopeBreak; blockaction.cc:2186-2197
 * ActionFinalStructure tail).
 *
 * Motivation (disproof record): the curl next_url `goto LAB_001050e7;`
 * residual was hypothesised to be a missing Rugra scopeBreak goto_type
 * conversion. The oracle keeps that goto UNCONVERTED (golden
 * ghidra_curl_1204.c next_url: `if (glob->size <= (int)uVar8) goto
 * LAB_001050e7;` with the label 31 lines later, after both loops) because
 * the goto exits TWO loop scopes and block.cc:2872 only reclassifies a
 * goto whose target is the INNERMOST enclosing loop's exit. This fixture
 * locks both arms on synthetic graphs driven through the production
 * CollapseStructure::collapseAll + the ActionFinalStructure tail
 * (scopeBreak(-1,-1) then markUnstructured):
 *
 *   case loop_exit_goto       — WhileDo body jumps to the loop's own exit
 *                               block; scopeBreak must set f_break_goto
 *                               (block.cc:3082-3083 via WhileDo passing its
 *                               curexit as the body's curloopexit,
 *                               cc:3329) and markUnstructured must NOT mark
 *                               the target (cc:3071 gototype gate).
 *   case nested_two_level_goto — the next_url shape: WhileDo nested in a
 *                               DoWhile, body jumps to the DoWhile's exit
 *                               (two loop scopes out); the goto must stay
 *                               f_goto_goto (inner WhileDo passes its OWN
 *                               exit as curloopexit, cc:3329, which is not
 *                               the target) and markUnstructured MUST mark
 *                               the target f_unstructured_targ (cc:3071-3072).
 *   case dowhile_body_goto    — unconditional-branch BlockGoto out of a
 *                               DoWhile body to the DoWhile's exit;
 *                               BlockGoto::scopeBreak cc:2872-2873 sets
 *                               f_break_goto; markUnstructured must NOT
 *                               mark (cc:2860 gototype gate).
 *   case forward_exit_goto    — a non-loop goto into the middle of the
 *                               following flow; stays f_goto_goto and the
 *                               target is marked (baseline goto arm).
 *
 * Mirrors tests/oracle/blockstruct_scopebreak_gototype_1204.rs case for
 * case. Observation lines (one per tree-resident BlockGoto or
 * gototarget-carrying BlockIf) are sorted before printing: Rugra installs
 * composites at the consumed slot while the oracle appends to the parent
 * list, so top-level order is a registered normalization on both sides —
 * the per-goto facts (gototype, target identity + f_unstructured_targ,
 * wrapped/condition identity) are order-free.
 *
 * Synthetic leaves are Vertex : FlowBlock (t_basic) on this side and
 * BlockBasic on the Rust side; both sides drive the identical production
 * rule path (structureLoops -> CollapseStructure::collapseAll ->
 * scopeBreak(-1,-1) -> markUnstructured).
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

struct Vertex : public FlowBlock {
  int id;
  explicit Vertex(int id_) : FlowBlock(), id(id_) {}
  virtual block_type getType(void) const { return t_basic; }
  virtual bool isComplex(void) const { return false; }
  virtual void printHeader(ostream &s) const { s << 'b' << id; }
  // Synthetic leaf has no PcodeOp condition to flip: the default
  // FlowBlock::negateCondition (block.cc:294) swaps out-edges and then
  // asks lastOp()->isBooleanFlip() — null on this leaf. The flip only
  // affects in-block condition text and edge ORDER, which this fixture
  // observes order-free (sorted lines), so a no-op override is a faithful
  // stand-in (same scheme as goto_cascade's Vertex overrides).
  virtual bool negateCondition(bool toporbottom) { return false; }
};

class Graph {
public:
  BlockGraph graph;
  std::vector<FlowBlock *> created;	// the BlockCopy tree nodes
  std::vector<FlowBlock *> leafs;	// the wrapped Vertex leafs

  // Production shape: ActionBlockStructure's buildCopy (blockaction.cc:2177)
  // wraps every basic block in a BlockCopy before structuring, so every
  // tree path bottoms out at t_copy and markCopyBlock's
  // getFrontLeaf()->flags write (block.cc:1236) has a non-null front leaf.
  FlowBlock *makeBlock(void)
  {
    FlowBlock *bl = new Vertex((int4)leafs.size());
    leafs.push_back(bl);
    FlowBlock *cp = graph.newBlockCopy(bl);
    created.push_back(cp);
    return cp;
  }

  void edge(FlowBlock *from, FlowBlock *to) { graph.addEdge(from, to); }

  std::string nameOf(FlowBlock *bl, const std::vector<FlowBlock *> &toplist) const
  {
    for (int4 i = 0; i < (int4)leafs.size(); ++i)
      if (leafs[i] == bl) {
        std::stringstream s;
        s << 'b' << i;
        return s.str();
      }
    for (int4 i = 0; i < (int4)toplist.size(); ++i)
      if (toplist[i] == bl) {
        std::stringstream s;
        s << 'c' << i;
        return s.str();
      }
    std::stringstream s;
    s << 't' << bl->getIndex();
    return s.str();
  }

  // Collect every tree-resident unstructured-branch carrier: BlockGoto
  // (t_goto) and BlockIf with a gototarget (newBlockIfGoto form).
  struct GotoObs {
    FlowBlock *bl;		// the BlockGoto or BlockIf node
    FlowBlock *target;		// gototarget
    bool isIf;			// true = BlockIf-goto form
    FlowBlock *body;		// wrapped block (BlockGoto) / condition (BlockIf)
  };

  static void collectGotos(FlowBlock *bl, std::vector<GotoObs> &out, int4 depth)
  {
    if (depth > 8) return;
    if (bl->getType() == FlowBlock::t_goto) {
      BlockGoto *bg = (BlockGoto *)bl;
      GotoObs o; o.bl = bl; o.target = bg->getGotoTarget(); o.isIf = false;
      o.body = bg->getBlock(0);
      out.push_back(o);
    }
    else if (bl->getType() == FlowBlock::t_if) {
      BlockIf *bi = (BlockIf *)bl;
      if (bi->getGotoTarget() != (FlowBlock *)0) {
	GotoObs o; o.bl = bl; o.target = bi->getGotoTarget(); o.isIf = true;
	o.body = bi->getBlock(0);	// the condition component
	out.push_back(o);
      }
    }
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0) {
      for (int4 i = 0; i < g->getSize(); ++i)
	collectGotos(g->getBlock(i), out, depth + 1);
    }
  }

  void observe(const GotoObs &o, const std::vector<FlowBlock *> &toplist, std::vector<std::string> &lines) const
  {
    std::stringstream s;
    uint4 gototype = o.isIf ? ((BlockIf *)o.bl)->getGotoType()
                            : ((BlockGoto *)o.bl)->getGotoType();
    // markCopyBlock (block.cc:1233-1237) sets the flag on the target's
    // FRONT LEAF, not the target node itself — observe it there. Identity
    // fields are deliberately reduced to node TYPES: the collapse creates
    // fresh BlockCopy nodes (getCopy) whose getIndex() differs between the
    // two tree builders, and this fixture's discriminative facts are the
    // gototype conversion + the marking gate, not node identity.
    int4 targmark = 0;
    const FlowBlock *fl = o.target->getFrontLeaf();
    if (fl != (const FlowBlock *)0 && (fl->flags & FlowBlock::f_unstructured_targ) != 0)
      targmark = 1;
    s << (o.isIf ? "ifgoto" : "blockgoto")
      << " body=" << typeName(o.body->getType())
      << " target=" << typeName(o.target->getType())
      << " gototype=" << gototype
      << " targ_unstructured=" << targmark;
    lines.push_back(s.str());
  }

  void run(const std::string &caseName)
  {
    std::vector<FlowBlock *> rootlist;
    graph.structureLoops(rootlist);
    graph.clearVisitCount();

    CollapseStructure collapse(graph);
    collapse.collapseAll();

    // ActionFinalStructure tail (blockaction.cc:2193-2194).
    graph.scopeBreak(-1, -1);
    graph.markUnstructured();

    std::vector<FlowBlock *> toplist = graph.getList();
    std::vector<std::string> lines;
    int4 total = 0;
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      std::vector<GotoObs> gotos;
      collectGotos(toplist[i], gotos, 0);
      for (int4 j = 0; j < (int4)gotos.size(); ++j) {
	total += 1;
	observe(gotos[j], toplist, lines);
      }
    }
    std::sort(lines.begin(), lines.end());
    std::cout << "case " << caseName << '\n';
    std::cout << "gotos=" << total << '\n';
    for (int4 i = 0; i < (int4)lines.size(); ++i) std::cout << lines[i] << '\n';
    std::cout << "end\n";
  }
};

int main()
{
  // Case 1 "loop_exit_goto": WhileDo whose body block jumps to the loop's
  // own exit block (the WhileDo is followed by that exit in the top list).
  //   b0 -> b1 (cond) ; b1 -> b2 (body, true) ; b1 -> b4 (exit, false)
  //   b2 -> b1 (back) ; b2 -> b4 (extra exit -> goto edge)
  // Expect: IfGoto(b2 -> b4) gototype=f_break_goto (2), b4 unmarked.
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b4 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b1, b4);
    g.edge(b2, b1);
    g.edge(b2, b4);
    g.run("loop_exit_goto");
  }
  // Case 2 "nested_two_level_goto" (the next_url shape): WhileDo nested in
  // a DoWhile; the WhileDo body jumps past BOTH loops to the DoWhile exit.
  //   b0 -> b1 (while cond) ; b1 -> b3 (while exit, false) ; b1 -> b2 (body)
  //   b2 -> b1 (back) ; b2 -> b5 (goto: two levels out)
  //   b3 -> b4 (do-while bottom) ; b4 -> b1 (do-while back) ; b4 -> b5 (exit)
  // Expect: IfGoto(b2 -> b5) gototype=f_goto_goto (1), b5 MARKED
  // f_unstructured_targ (this is the golden next_url goto).
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b3 = g.makeBlock();
    FlowBlock *b4 = g.makeBlock();
    FlowBlock *b5 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b1, b3);
    g.edge(b2, b1);
    g.edge(b2, b5);
    g.edge(b3, b4);
    g.edge(b4, b1);
    g.edge(b4, b5);
    g.run("nested_two_level_goto");
  }
  // Case 3 "dowhile_body_goto": unconditional-branch BlockGoto out of a
  // DoWhile body to the DoWhile's exit.
  //   b0 -> b1 (body) ; b1 -> b3 (goto edge, single out) ; b2 -> b1 ; 
  //   b2 -> b3 (exit) ; b1 -> b2 (fall into bottom)
  // Expect: BlockGoto(b1 -> b3) gototype=f_break_goto (2), b3 unmarked.
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b1, b3);
    g.edge(b2, b1);
    g.edge(b2, b3);
    g.run("dowhile_body_goto");
  }
  // Case 4 "forward_exit_goto": a plain goto skipping over one block in a
  // straight-line region (no loop exit involved).
  //   b0 -> b1 ; b1 -> b4 (goto) ; b1 -> b2 (fall) ; b2 -> b4 ; b4 -> b5
  // Expect: IfGoto(b1 -> b4) stays f_goto_goto (1) unless b4 is the
  // fall-thru successor (gotoPrints family, not loop scope) — target marked.
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b4 = g.makeBlock();
    FlowBlock *b5 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b1, b4);
    g.edge(b2, b4);
    g.edge(b4, b5);
    g.run("forward_exit_goto");
  }
  return 0;
}
