/*
 * BLOCKACTION-DOWHILE-ABSORB-0001: locked Ghidra 12.0.4
 * CollapseStructure::collapseAll (blockaction.cc:1877-1893) oracle,
 * covering the do-while absorption chain at the newBlockList force step:
 *
 *   BlockGraph::newBlockList (block.cc:1758-1774) captures
 *   outforce = nodes.back()->sizeOut() (and out0 when binary) BEFORE
 *   identifyInternal, then forceOutputNum(outforce) (block.cc:880-889)
 *   resurrects a chain-internal back-edge as a composite SELF edge labeled
 *   f_loop_edge|f_back_edge, and forceFalseEdge (block.cc:1204-1217)
 *   preserves which branch was the false path (out0 internal → self).
 *   That self edge is what ruleBlockDoWhile (cc:1555) absorbs — the
 *   main @321a/@3225/@28ec/@28f7 latch-pair shape: ruleBlockGoto
 *   (newBlockIfGoto) → ruleBlockCat (force self edge) → ruleBlockDoWhile.
 *
 * Cases:
 *   1. latch_pair_goto_dowhile — the main @321a topology (head exits to
 *      body+latch-exit target, latch exits back to head and to the shared
 *      target): TraceDAG/selectGoto marks the head's exit, ruleBlockGoto
 *      wraps an if-goto, cat merges it with the latch, forceOutputNum
 *      restores the back-edge as the composite self edge, ruleBlockDoWhile
 *      absorbs the latch. Final tree must contain dowhile(list{if(goto),latch}).
 *   2. chain_tail_backedge_dowhile — no goto at all: a straight chain whose
 *      tail branches back into the chain. cat merges the chain,
 *      forceOutputNum adds the self edge, dowhile absorbs. This isolates
 *      the pure newBlockList force semantic.
 *   3. tail_out0_internal_flip — the tail's out(0) points back INTO the
 *      chain (out0 is internalized): forceFalseEdge's parent==this arm
 *      must swap the self edge to slot 0, and ruleBlockDoWhile must
 *      negate (cc:1566-1569) — observable as the flip flag.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as blockstruct_goto_cascade_1204.cc):
// BlockGraph's helper members (structureLoops, getList, addBlock) are
// implicitly private; `class -> struct` + `private -> public` opens them
// in this TU only.
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

// Synthetic vertex: plain FlowBlock topology, isComplex()==false so the
// condition-bearing blocks fold exactly like real basic blocks.
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
    // inherits spanning-tree/back-edge labels; reproduce by running
    // structureLoops on the same graph.
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

  // Recursive structure-tree projection (same scheme as
  // blockstruct_goto_cascade_1204.cc): child order is the factory node
  // order. t_goto children are NOT dumped (documented normalization).
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

int main(int argc, char **argv)
{
  std::string filter = (argc > 1) ? argv[1] : "";

  if (filter.empty() || filter == "latch_pair_goto_dowhile") {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b1, b3);
    g.edge(b2, b3);
    g.edge(b2, b1);
    g.run("latch_pair_goto_dowhile");
  }
  if (filter.empty() || filter == "chain_tail_backedge_dowhile") {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b2, b3);
    g.edge(b2, b1);
    g.run("chain_tail_backedge_dowhile");
  }
  if (filter.empty() || filter == "tail_out0_internal_flip") {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b3 = g.makeBlock();
    FlowBlock *b9 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b0, b9);
    g.edge(b1, b2);
    g.edge(b2, b1);
    g.edge(b2, b3);
    g.run("tail_out0_internal_flip");
  }
  return 0;
}
