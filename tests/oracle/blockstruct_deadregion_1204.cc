/*
 * BLOCKSTRUCT-NORETURN-DEADREGION-0001: locked Ghidra 12.0.4
 * CollapseStructure::collapseAll (blockaction.cc:1877-1893) oracle for
 * control-flow graphs whose loop bodies contain no-return artificial-halt
 * blocks (FlowInfo::checkForFlowModification dead-inserts the halt after
 * the CALL, flow.cc:641-646; the halt block never has out-edges and the
 * fall-through region behind it is never walked, flow.cc:479-480, so the
 * structurer must terminate on these shapes and structure the reachable
 * remainder).
 *
 * Cases (synthetic FlowBlock graphs through the production BlockGraph
 * APIs — newBlock/addEdge — driven exactly like the E2E structurer sees
 * them, with spanning-tree labels established by structureLoops first):
 *   1. noret_halt_loop_body — the E2E glob_word topology (19 vertices,
 *      three halt sinks at 8/13/15/17/18's shapes: blocks with no
 *      out-edges inside and after the loop). The projection covers
 *      termination (the previous Rugra port never converged here) and
 *      the final structure shape.
 *   2. canary_if_halt — the __stack_chk_fail shape: a two-way condition
 *      whose failure arm is a pure halt sink and whose ok arm returns.
 *   3. partial_reachable_after_halt — the halt block sits mid-function
 *      and the region behind it is still reachable through a second
 *      entry: only the halt block itself is a sink.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as blockstruct_goto_cascade_1204.cc):
// BlockGraph's helper members are implicitly private; `class -> struct` +
// `private -> public` opens them in this TU only.
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
  if (label & FlowBlock::f_irreducible) out += 'i';
  if (label & FlowBlock::f_tree_edge) out += 't';
  if (label & FlowBlock::f_back_edge) out += 'b';
  if (out.empty()) out.push_back('-');
  return out;
}

// Synthetic vertex: plain FlowBlock topology, with BlockBasic's
// isComplex()==false for a pure condition (block.cc:2399-2400).
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
    for (int4 i = 0; i < (int4)created.size(); ++i)
      if (created[i] == bl) return string("b") + char('0' + i);
    for (int4 i = 0; i < (int4)toplist.size(); ++i)
      if (toplist[i] == bl) return string("c") + char('0' + i);
    return "b?";
  }

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
    std::cout << " in=" << bl->sizeIn() << " out=" << bl->sizeOut() << '\n';
    if (bl->getType() == FlowBlock::t_goto) return;
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g == (BlockGraph *)0) return;
    for (int4 i = 0; i < g->getSize(); ++i)
      dumpTree(g->getBlock(i), toplist, depth + 1);
  }

  void run(const std::string &caseName)
  {
    // ActionBlockStructure entry state (cc:2177-2180): the structure copy
    // inherits spanning-tree/back-edge labels; reproduce by running
    // structureLoops on the graph first.
    std::vector<FlowBlock *> rootlist;
    graph.structureLoops(rootlist);
    graph.clearVisitCount();

    CollapseStructure collapse(graph);
    collapse.collapseAll();

    std::vector<FlowBlock *> toplist = graph.getList();
    std::cout << "case " << caseName << '\n';
    std::cout << "list=";
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      if (i != 0) std::cout << ',';
      std::cout << 'c' << i << '(' << FlowBlock::typeToName(toplist[i]->getType()) << ')';
    }
    std::cout << '\n';
    for (int4 i = 0; i < (int4)toplist.size(); ++i)
      dumpTree(toplist[i], toplist, 0);
    for (int4 i = 0; i < (int4)created.size(); ++i) {
      FlowBlock *bl = created[i];
      bool listed = std::find(toplist.begin(), toplist.end(), bl) != toplist.end();
      std::cout << 'b' << i << " listed=" << (listed ? 1 : 0) << " out=[";
      for (int4 j = 0; j < bl->sizeOut(); ++j) {
        if (j != 0) std::cout << ' ';
        std::cout << j << ':' << flagsText(bl->outofthis[j].label);
      }
      std::cout << "] flip=" << (bl->getFlipPath() ? 1 : 0) << '\n';
    }
    std::cout << "end\n";
  }
};

int main(void)
{
  {
    // 1. noret_halt_loop_body: the E2E glob_word 19-block topology.
    //    Halts (no out-edges): 8, 13, 15, 17, 18.
    Graph g;
    std::vector<FlowBlock *> b(19);
    for (int i = 0; i < 19; ++i) b[i] = g.makeBlock();
    int edges[][2] = {
      {0, 11}, {0, 1},
      {1, 2}, {1, 12},
      {2, 4}, {2, 3},
      {3, 8},
      {4, 6}, {4, 5},
      {5, 10},
      {6, 9}, {6, 7},
      {7, 8},
      {9, 10},
      {10, 1}, {10, 12},
      {11, 12},
      {12, 14}, {12, 13},
      {14, 16}, {14, 15},
      {16, 18}, {16, 17},
    };
    for (auto &e : edges) g.edge(b[e[0]], b[e[1]]);
    g.run("noret_halt_loop_body");
  }
  {
    // 2. canary_if_halt: b0 {b1 fail-halt, b2 ok}; b1 halt; b2 ret.
    Graph g;
    FlowBlock *b0 = g.makeBlock(), *b1 = g.makeBlock(), *b2 = g.makeBlock();
    g.edge(b0, b1); // slot 0: canary mismatch -> __stack_chk_fail halt
    g.edge(b0, b2); // slot 1: ok path
    g.run("canary_if_halt");
  }
  {
    // 3. partial_reachable_after_halt: b0 {b1, b4}; b1 halt (mid-function);
    //    b4 -> b2 (second entry into the region behind the halt);
    //    b2 -> b3; b3 ret.
    Graph g;
    FlowBlock *b0 = g.makeBlock(), *b1 = g.makeBlock(), *b2 = g.makeBlock(),
              *b3 = g.makeBlock(), *b4 = g.makeBlock();
    g.edge(b0, b1); // slot 0: noreturn call arm -> halt sink
    g.edge(b0, b4); // slot 1: guard arm
    g.edge(b4, b2); // region behind the halt stays reachable
    g.edge(b2, b3);
    g.run("partial_reachable_after_halt");
  }
  return 0;
}
