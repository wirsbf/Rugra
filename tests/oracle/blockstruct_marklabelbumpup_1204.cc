/*
 * BLOCKSTRUCT-MARKLABELBUMPUP-0001: locked Ghidra 12.0.4
 * BlockGraph::markLabelBumpUp (block.cc:1258-1268) / loop overrides
 * (BlockWhileDo block.cc:3316-3322, BlockDoWhile block.cc:3426-3432,
 * BlockInfLoop block.cc:3454-3460) f_label_bumpup projection oracle,
 * driven from the ActionFinalStructure fifth call site
 * (blockaction.cc:2195 `graph.markLabelBumpUp(false)`).
 *
 * The fixture drives the production call sequence on synthetic graphs
 * built through the production path (buildCopy snapshot +
 * CollapseStructure::collapseAll, blockaction.cc:2177-2183), then runs the
 * complete ActionFinalStructure tail (cc:2191-2195: orderBlocks /
 * finalizePrinting / scopeBreak / markUnstructured / markLabelBumpUp) and
 * observes the f_label_bumpup flag on EVERY tree-resident node.
 *
 * Semantics under test (the four decisive classes):
 *   - references/state: the flag lives on each FlowBlock; loops force
 *     `true` down their front chain regardless of the incoming bump
 *     (cc:3319/3429/3457 hard-coded `true`), then clear their OWN flag
 *     only when the incoming bump was false (cc:3320-3321/3430-3431/
 *     3458-3459);
 *   - traversal order: BlockGraph list order — list[0] receives `bump`,
 *     list[1..] receive `false` (cc:1263-1267); loop component order is
 *     [condition, body] for whiledo (newBlockWhileDo block.cc:1858-1870),
 *     [body] for dowhile/infloop;
 *   - counters: none (pure flag lattice, no counting);
 *   - comparison keys: none (no sorting inside the algorithm).
 *
 * Cases (see the .metadata.json input_manifest):
 *   1. whiledo_simple   — condition chain flagged, body not, loop itself
 *      cleared (root passes false).
 *   2. dowhile_simple   — single body component flagged, loop cleared.
 *   3. infloop_simple   — body component flagged, loop cleared.
 *   4. nested_loops_front — WhileDo sitting at the FRONT of a DoWhile
 *      body: the inner loop receives `true` through the forced front
 *      chain and KEEPS its own flag (cc:3320 `!bump` is false) — the
 *      differentiator against a port that clears unconditionally or
 *      marks every child flat.
 *   5. straight_line    — no loops: nothing flagged anywhere (control).
 *
 * Observation: per case, every tree node as one sorted multiset line
 * `type=<t> bump=<0|1> kids=<n>` (kids = component-list size; the
 * BlockCopy/BlockBasic leaves have 0). Lines are sorted because the two
 * collapse implementations install composites at different list slots
 * (registered normalization, same scheme as the scopebreak fixture); the
 * per-node (type, bump, kids) facts are order-free.
 */

// Test-only access: FlowBlock::flags (f_label_bumpup reads) and the
// composite constructors run through the production BlockGraph factories;
// the same `private -> public` / `class -> struct` include trick as the
// sibling blockstruct fixtures (STL pre-included before the defines).
#include <bits/stdc++.h>
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
  virtual bool negateCondition(bool toporbottom) { return false; }
};

class Graph {
public:
  BlockGraph graph;
  std::vector<FlowBlock *> leafs;

  // Production shape: ActionBlockStructure's buildCopy (blockaction.cc:2177)
  // wraps every basic block in a BlockCopy before structuring.
  FlowBlock *makeBlock(void)
  {
    FlowBlock *bl = new Vertex((int4)leafs.size());
    leafs.push_back(bl);
    return graph.newBlockCopy(bl);
  }

  void edge(FlowBlock *from, FlowBlock *to) { graph.addEdge(from, to); }

  static void collect(FlowBlock *bl, std::vector<std::string> &lines, int4 depth)
  {
    if (depth > 8) return;
    const BlockGraph *g = dynamic_cast<const BlockGraph *>(bl);
    int4 kids = (g != (const BlockGraph *)0) ? g->getSize() : 0;
    std::stringstream s;
    s << "type=" << typeName(bl->getType())
      << " bump=" << (((bl->flags & FlowBlock::f_label_bumpup) != 0) ? 1 : 0)
      << " kids=" << kids;
    lines.push_back(s.str());
    if (g != (const BlockGraph *)0) {
      for (int4 i = 0; i < g->getSize(); ++i)
	collect(g->getBlock(i), lines, depth + 1);
    }
  }

  void run(const std::string &caseName)
  {
    std::vector<FlowBlock *> rootlist;
    graph.structureLoops(rootlist);
    graph.clearVisitCount();
    graph.clearVisitCount();

    CollapseStructure collapse(graph);
    collapse.collapseAll();

    // ActionFinalStructure tail, reduced to the three calls that need no
    // Funcdata (blockaction.cc:2193-2195). orderBlocks (cc:2191) only
    // permutes the root list — the root passes `false` to every slot, so
    // the permutation cannot change the flag lattice; finalizePrinting
    // (cc:2192) is switch-only and these graphs hold no switches. The
    // scopebreak fixture uses the same reduced tail.
    graph.scopeBreak(-1, -1);
    graph.markUnstructured();
    graph.markLabelBumpUp(false); // cc:2195 — the call under test

    std::vector<std::string> lines;
    int4 total = 0;
    const std::vector<FlowBlock *> &toplist = graph.getList();
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      collect(toplist[i], lines, 0);
      total += 1;
    }
    std::sort(lines.begin(), lines.end());
    std::cout << "case " << caseName << '\n';
    std::cout << "roots=" << total << '\n';
    for (int4 i = 0; i < (int4)lines.size(); ++i) std::cout << lines[i] << '\n';
    std::cout << "end\n";
  }
};

int main()
{
  // Case 1: plain while-do. b1 is the condition, b2 the body, b3 the exit.
  //   b0 -> b1 ; b1 -> b2 (true) ; b1 -> b3 (false) ; b2 -> b1 (back)
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
    g.run("whiledo_simple");
  }
  // Case 2: plain do-while. b1 the body, b2 the bottom, b3 the exit.
  //   b0 -> b1 ; b1 -> b2 ; b2 -> b1 (back) ; b2 -> b3 (exit)
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b2, b1);
    g.edge(b2, b3);
    g.run("dowhile_simple");
  }
  // Case 3: infinite loop. b1's only out edge returns to itself.
  //   b0 -> b1 ; b1 -> b1 (back, no exit)
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b1);
    g.run("infloop_simple");
  }
  // Case 4: WhileDo at the FRONT of a DoWhile body (the next_url shape
  // without the unstructured edge). The dowhile forces `true` down its
  // single body component; the body's first child (the whiledo) receives
  // `true` through the list and KEEPS its own flag.
  //   b0 -> b1 (while cond) ; b1 -> b2 (body) ; b1 -> b3 (while exit)
  //   b2 -> b1 (back) ; b3 -> b4 (do bottom) ; b4 -> b1 (do back)
  //   b4 -> b5 (exit)
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
    g.edge(b3, b4);
    g.edge(b4, b1);
    g.edge(b4, b5);
    g.run("nested_loops_front");
  }
  // Case 5: straight line, no loops — control: nothing flagged.
  //   b0 -> b1 -> b2
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.run("straight_line");
  }
  return 0;
}
