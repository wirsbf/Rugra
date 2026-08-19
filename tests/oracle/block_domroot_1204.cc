/*
 * HTTPD-ADDDESCEND-THROW-0001: locked Ghidra 12.0.4 dominator-root oracle.
 *
 * Exercises BlockGraph::structureLoops (block.cc:2194-2215 ->
 * findSpanningTree block.cc:1009-1136) followed by
 * BlockGraph::calcForwardDominator (block.cc:1954-2032) on four synthetic
 * graphs chosen to pin the root-selection semantics:
 *
 *   A. multi-root graph with trailing orphan blocks (in0/out0) appended at
 *      the END of the component vector — the httpd lifter shape. Pins the
 *      rootlist head/tail swap (block.cc:1031-1035): the original head
 *      (first sizeIn()==0 block in list order) must finish the DFS last and
 *      take reverse-post-order slot 0, and the final swap (block.cc:1129)
 *      must restore it to rootlist front. Orphans may never steal RPO[0].
 *   B. single root whose entry has a back-edge into it — pins the
 *      createVirtualRoot branch at block.cc:1978-1984 (root with in-edges
 *      gets an artificial root; entry ends with immed_dom == null).
 *   C. cross-root merge — pins the finger-arithmetic alias: a freshly
 *      constructed FlowBlock has index == 0 (block.cc:61-69), so a finger
 *      walking into the virtual root lands on numnodes-0 = the postorder
 *      slot of list[0]. A merge of two different roots' subtrees therefore
 *      converges to immed_dom == list[0], NOT null.
 *   D. pure cycle with no sizeIn()==0 candidate — pins the rootlist
 *      fallback rootlist = { list[0] } (block.cc:1036-1038).
 *
 * After structureLoops + calcForwardDominator the fixture prints, for each
 * case: the reverse post order (component list order after
 * `list = rpostorder`, block.cc:1135), every block's index field, the final
 * rootlist, and every block's immediate dominator (or NULL). All four cases
 * are reducible, so findIrreducible (block.cc:1147) never forces a rebuild
 * and calcLoop (block.cc:2104) never runs — that machinery is outside this
 * fixture's coverage and registered as such in the metadata.
 *
 * Test-only access: BlockGraph::addBlock / newBlock (block.hh:366-413) are
 * implicitly private (the class body never emits an explicit access label
 * before them), so the common `#define private public` fixture lever cannot
 * reach them; production graphs are assembled by Funcdata's flow-following
 * constructor. This fixture additionally defines `class` as `struct` around
 * the decompile headers — flipping the default member access to public —
 * solely to append plain FlowBlock components. structureLoops,
 * calcForwardDominator, getBlock, getIndex and getImmedDom are public API
 * used unmodified. The header set and define order follow the proven
 * block_index_assign_1204.cc pattern: <bits/stdc++.h> prelude, both defines,
 * architecture.hh first (the canonical umbrella include that establishes
 * the declaration order every decompile .cc relies on), then block.hh and
 * the rest of the umbrella headers.
 */
#include <bits/stdc++.h>

#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
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

namespace {

using namespace ghidra;

struct CaseGraph {
  BlockGraph graph;
  std::vector<FlowBlock *> blocks;
  std::vector<std::string> names;
  std::map<FlowBlock *, std::string> label_of;

  FlowBlock *add(const std::string &name)
  {
    // newBlock() (block.cc:1659-1665) already registers the new plain
    // FlowBlock via addBlock internally — calling addBlock again would
    // double-register the component.
    FlowBlock *bl = graph.newBlock();
    blocks.push_back(bl);
    names.push_back(name);
    label_of[bl] = name;
    return bl;
  }

  void edge(FlowBlock *from, FlowBlock *to) { graph.addEdge(from, to); }
};

void run_case(const std::string &title, CaseGraph &cg)
{
  std::cout << title << std::endl;

  std::vector<FlowBlock *> rootlist;
  cg.graph.structureLoops(rootlist);
  cg.graph.calcForwardDominator(rootlist);

  // Reverse post order == component list order after `list = rpostorder`.
  std::cout << "rpo:";
  for(int4 i = 0; i < cg.graph.getSize(); ++i) {
    FlowBlock *bl = cg.graph.getBlock(i);
    std::cout << ' ' << cg.label_of[bl] << '(' << bl->getIndex() << ')';
  }
  std::cout << std::endl;

  std::cout << "rootlist:";
  for(int4 i = 0; i < (int4)rootlist.size(); ++i)
    std::cout << ' ' << cg.label_of[rootlist[i]];
  std::cout << std::endl;

  // Walk in the (reordered) component list order so both sides print in the
  // same sequence; labels keep the observation block-name keyed.
  for(int4 i = 0; i < cg.graph.getSize(); ++i) {
    FlowBlock *bl = cg.graph.getBlock(i);
    FlowBlock *dom = bl->getImmedDom();
    std::cout << "idom " << cg.label_of[bl] << ": "
              << (dom == (FlowBlock *)0 ? std::string("NULL") : cg.label_of[dom])
              << std::endl;
  }
}

} // namespace

int main(void)
{
  {
    CaseGraph cg;
    FlowBlock *e = cg.add("E");
    FlowBlock *a = cg.add("A");
    FlowBlock *b = cg.add("B");
    cg.add("O1");
    cg.add("O2");
    cg.edge(e, a);
    cg.edge(a, b);
    run_case("case A: multi-root trailing orphans", cg);
  }
  {
    CaseGraph cg;
    FlowBlock *e = cg.add("E");
    FlowBlock *a = cg.add("A");
    cg.edge(e, a);
    cg.edge(a, e);
    run_case("case B: single root with back-edge into entry", cg);
  }
  {
    // Edge insertion order fixes the in-edge order of M as [R0, R1], which
    // the "first processed predecessor" scan (block.cc:1995-1999) reads.
    CaseGraph cg;
    FlowBlock *r0 = cg.add("R0");
    FlowBlock *m = cg.add("M");
    FlowBlock *x = cg.add("X");
    FlowBlock *r1 = cg.add("R1");
    cg.edge(r0, m);
    cg.edge(r1, m);
    cg.edge(m, x);
    run_case("case C: cross-root merge (virtual-root index alias)", cg);
  }
  {
    CaseGraph cg;
    FlowBlock *x = cg.add("X");
    FlowBlock *y = cg.add("Y");
    cg.edge(x, y);
    cg.edge(y, x);
    run_case("case D: pure cycle, no root candidate", cg);
  }
  return 0;
}
