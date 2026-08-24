/*
 * BLOCKSTRUCT-GOTOCASCADE-CONDSTMT-0001: locked Ghidra 12.0.4
 * CollapseStructure::collapseAll (blockaction.cc:1877-1893) oracle,
 * covering the goto-cascade chain: TraceDAG likely-goto selection
 * (updateLoopBody cc:1193-1253, TraceDAG cc:499-1014), one-edge-at-a-time
 * selectGoto (cc:1260-1277), ruleBlockGoto (cc:1450-1475), and the loop
 * guard negations (ruleBlockWhileDo cc:1538-1542, ruleBlockDoWhile
 * cc:1564-1572).
 *
 * The fixture builds synthetic control-flow graphs through the production
 * BlockGraph APIs (newBlock/addEdge), mirrors the ActionBlockStructure
 * entry state (blockaction.cc:2177-2180: the structure copy inherits
 * spanning-tree labels; reproduced by running structureLoops on the graph
 * first), then drives CollapseStructure::collapseAll directly.
 *
 * The post-run observation covers: the final top-level component list
 * (order + type + interior-goto flag + out-edge labels), and every original
 * block's surviving out-edge labels, visitcount-0 state and flip-path flag
 * (the observable of negateCondition's swapEdges, block.cc:232).
 *
 * Cases:
 *   1. loop_break_marked_goto   — while + break: which edge TraceDAG picks
 *                                 first, ruleBlockGoto's if-goto wrap, and
 *                                 loop convergence (the parseconfig chain).
 *   2. diamond_if_recovery      — plain if/else diamond must structure with
 *                                 ZERO goto marks (condition body recovery).
 *   3. while_guard_direction    — loop body on the fall-through (false) edge
 *                                 must negate the condition (cc:1540) — the
 *                                 head's flip flag must be set.
 *   4. dowhile_guard_direction  — self-loop back edge on slot 0 must negate
 *                                 (cc:1566-1569).
 *   5. consumed_edge_cleared    — after collapse, consumed blocks lose their
 *                                 external boundary edges (identifyInternal
 *                                 block.cc:935-960): the DEAD/isolated
 *                                 determination.
 *   6. irreducible_goto_cascade — classic two-entry irreducible pair: the
 *                                 cascade must CONVERGE (clipExtraRoots or
 *                                 TraceDAG marks, structure the remainder)
 *                                 instead of marking every edge.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as block_calcloop_1204.cc): BlockGraph's
// helper members (structureLoops, getList, addBlock) are implicitly private;
// `class -> struct` + `private -> public` opens them in this TU only.
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

static std::string flagsText(uint4 label)
{
  std::string out;
  if (label & FlowBlock::f_goto_edge) out += 'g';
  if (label & FlowBlock::f_loop_edge) out += 'l';
  if (label & FlowBlock::f_defaultswitch_edge) out += 'd';
  if (label & FlowBlock::f_irreducible) out += 'i';
  if (label & FlowBlock::f_tree_edge) out += 't';
  if (label & FlowBlock::f_forward_edge) out += 'f';
  if (label & FlowBlock::f_cross_edge) out += 'c';
  if (label & FlowBlock::f_back_edge) out += 'b';
  if (label & FlowBlock::f_loop_exit_edge) out += 'x';
  if (out.empty()) out.push_back('-');
  return out;
}

// Synthetic vertex: plain FlowBlock topology, but with BlockBasic's
// isComplex()==false for a block holding only a branch (the statement count
// of a pure condition is 1, block.cc:2399-2400) so ruleBlockOr can fold
// simple short-circuit patterns exactly like the real pipeline.
struct Vertex : public FlowBlock {
  int id;
  explicit Vertex(int id_) : FlowBlock(), id(id_) {}
  virtual block_type getType(void) const { return t_basic; }
  virtual bool isComplex(void) const { return false; }
  virtual void printHeader(ostream &s) const { s << 'b' << id; }
};

class Graph {
public:
  BlockGraph graph;
  std::vector<FlowBlock *> created;

  FlowBlock *makeBlock(void)
  {
    FlowBlock *bl = new Vertex((int4)created.size());
    graph.addBlock(bl);
    created.push_back(bl);
    return bl;
  }

  void edge(FlowBlock *from, FlowBlock *to)
  {
    graph.addEdge(from, to);
  }

  // Name a block by creation id (bN) or, for post-run components, by
  // top-level list position (cN).
  std::string nameOf(FlowBlock *bl, const std::vector<FlowBlock *> &toplist) const
  {
    for (int4 i = 0; i < created.size(); ++i)
      if (created[i] == bl) return string("b") + char('0' + i);
    for (int4 i = 0; i < toplist.size(); ++i)
      if (toplist[i] == bl) return string("c") + char('0' + i);
    return "b?";
  }

  void run(const std::string &caseName)
  {
    // ActionBlockStructure entry state (cc:2177-2180): the structure copy
    // inherits spanning-tree/back-edge labels (block.cc:1685-1691 via
    // buildCopy); reproduce by running the driver on the same graph.
    std::vector<FlowBlock *> rootlist;
    graph.structureLoops(rootlist);
    graph.clearVisitCount();

    CollapseStructure collapse(graph);
    collapse.collapseAll();

    // ---- observation ----
    std::vector<FlowBlock *> toplist = graph.getList();
    std::cout << "case " << caseName << '\n';
    std::cout << "list=";
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      if (i != 0) std::cout << ',';
      std::cout << 'c' << i << '(' << FlowBlock::typeToName(toplist[i]->getType()) << ')';
    }
    std::cout << '\n';
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      FlowBlock *bl = toplist[i];
      std::cout << 'c' << i << " type=" << FlowBlock::typeToName(bl->getType())
                << " gotoout=" << (bl->hasInteriorGoto() ? 1 : 0)
                << " out=[";
      for (int4 j = 0; j < bl->sizeOut(); ++j) {
        if (j != 0) std::cout << ' ';
        std::cout << j << ':' << flagsText(bl->outofthis[j].label)
                  << "->" << nameOf(bl->getOut(j), toplist);
      }
      std::cout << "]\n";
      std::cout << "tree c" << i << ":\n";
      dumpTree(bl, toplist, 1);
    }
    for (int4 i = 0; i < (int4)created.size(); ++i) {
      FlowBlock *bl = created[i];
      // NOTE: the consumed-vertex in-degree is normalized OUT: Ghidra's
      // selfIdentify re-points/dedups external in-edges while keeping
      // sibling-internal ones, whereas Rugra's install-in-place model
      // clears consumed in-edges — a documented model divergence tracked as
      // BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001, not goto-cascade semantics.
      std::cout << 'b' << i << " out=[";
      for (int4 j = 0; j < bl->sizeOut(); ++j) {
        if (j != 0) std::cout << ' ';
        std::cout << j << ':' << flagsText(bl->outofthis[j].label);
      }
      std::cout << "] flip=" << (bl->getFlipPath() ? 1 : 0)
                << " listed=" << (std::find(toplist.begin(), toplist.end(), bl) != toplist.end() ? 1 : 0)
                << '\n';
    }
    std::cout << "end\n";
  }

  // Recursive structure-tree projection. Every structured block in Ghidra is
  // a BlockGraph whose children were installed by identifyInternal in the
  // factory's node order ({cond,clause} for if/whiledo, {b1,b2} for
  // conditions, list order for lists). t_goto children are NOT dumped:
  // newBlockGoto wraps its block in place and the Rugra model has no child
  // back-reference (documented normalization).
  void dumpTree(FlowBlock *bl, const std::vector<FlowBlock *> &toplist, int4 depth) const
  {
    for (int4 i = 0; i < depth; ++i) std::cout << "  ";
    std::cout << FlowBlock::typeToName(bl->getType());
    if (bl->getType() == FlowBlock::t_if) {
      BlockIf *bif = (BlockIf *)bl;
      if (bif->getGotoTarget() != (FlowBlock *)0)
        std::cout << " gototarget=" << nameOf(bif->getGotoTarget(), toplist);
    }
    if (bl->hasInteriorGoto()) std::cout << " gotoout=1";
    if (bl->getFlipPath()) std::cout << " flip=1";
    std::cout << '\n';
    if (bl->getType() == FlowBlock::t_goto) return;
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g == (BlockGraph *)0) return;
    for (int4 i = 0; i < g->getSize(); ++i)
      dumpTree(g->getBlock(i), toplist, depth + 1);
  }
};

int main(void)
{
  {
    // 1. loop_break_marked_goto: while(rdi!=rsi){ if(rax==0x10) break; rax++; }
    //    b0: 2-out {b1 fall, b3 exit}   b1: 2-out {b2 fall, b3 break}
    //    b2: 1-out  {b0 back}           b3: ret (0 out)
    Graph g;
    FlowBlock *b0 = g.makeBlock(), *b1 = g.makeBlock(), *b2 = g.makeBlock(), *b3 = g.makeBlock();
    g.edge(b0, b1); // slot 0: fall-through into body
    g.edge(b0, b3); // slot 1: exit
    g.edge(b1, b2); // slot 0: fall-through
    g.edge(b1, b3); // slot 1: break
    g.edge(b2, b0); // back edge
    g.run("loop_break_marked_goto");
  }
  {
    // 2. diamond_if_recovery: if/else diamond + continuation.
    //    b0: {b1 fall, b2 taken}, b1->{b3}, b2->{b3}, b3->{b4}, b4: ret.
    //    Expected: properif/if + list, ZERO goto edges.
    Graph g;
    FlowBlock *b0 = g.makeBlock(), *b1 = g.makeBlock(), *b2 = g.makeBlock(),
              *b3 = g.makeBlock(), *b4 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b0, b2);
    g.edge(b1, b3);
    g.edge(b2, b3);
    g.edge(b3, b4);
    g.run("diamond_if_recovery");
  }
  {
    // 3. while_guard_direction: body on the FALL-THROUGH (false) edge.
    //    b0: {b1 fall=body, b2 exit}, b1->{b0 back}.
    //    ruleBlockWhileDo i==0 -> negateCondition (cc:1540): flip=1 on b0.
    Graph g;
    FlowBlock *b0 = g.makeBlock(), *b1 = g.makeBlock(), *b2 = g.makeBlock();
    g.edge(b0, b1); // slot 0: body (false path)
    g.edge(b0, b2); // slot 1: exit (true path)
    g.edge(b1, b0); // back edge
    g.run("while_guard_direction");
  }
  {
    // 4. dowhile_guard_direction: self loop on slot 0.
    //    b0: {b0 fall(self), b1 exit}. ruleBlockDoWhile i==0 -> negate
    //    (cc:1566-1569): flip=1 on b0.
    Graph g;
    FlowBlock *b0 = g.makeBlock(), *b1 = g.makeBlock();
    g.edge(b0, b0); // slot 0: self back edge
    g.edge(b0, b1); // slot 1: exit
    g.run("dowhile_guard_direction");
  }
  {
    // 5. consumed_edge_cleared: straight chain b0->b1->b2->b3 collapses to
    //    ONE component; consumed blocks lose their external edges and leave
    //    the top-level list (identifyInternal block.cc:935-960).
    Graph g;
    FlowBlock *b0 = g.makeBlock(), *b1 = g.makeBlock(), *b2 = g.makeBlock(),
              *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b2, b3);
    g.run("consumed_edge_cleared");
  }
  {
    // 6. irreducible_goto_cascade: classic two-entry pair.
    //    b0: {b1, b2}, b1: {b2, b3}, b2: {b1, b3}, b3: ret.
    //    The cascade must converge with a bounded number of goto marks.
    Graph g;
    FlowBlock *b0 = g.makeBlock(), *b1 = g.makeBlock(), *b2 = g.makeBlock(),
              *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b0, b2);
    g.edge(b1, b2);
    g.edge(b1, b3);
    g.edge(b2, b1);
    g.edge(b2, b3);
    g.run("irreducible_goto_cascade");
  }
  return 0;
}
