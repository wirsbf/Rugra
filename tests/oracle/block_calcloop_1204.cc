/*
 * BLOCK-CALCLOOP-0001: locked Ghidra 12.0.4 BlockGraph::calcLoop
 * (block.cc:2104-2147) oracle, including the structureLoops failsafe
 * wiring (block.cc:2211-2214) and the structureReset graph chain
 * (structureLoops + calcForwardDominator, funcdata_block.cc:711-712).
 *
 * The fixture builds synthetic control-flow graphs through the production
 * BlockGraph APIs (newBlock/addEdge), then either calls calcLoop directly
 * (fresh unlabeled edges: calcLoop's own f_loop_edge writes are isolated
 * from the spanning-tree labels) or drives the full structureLoops /
 * structureLoops+calcForwardDominator chain. The post-call observation
 * covers every input the oracle consumers read: the component list order,
 * per-block index / visitcount / numdesc / mark / mark2 / copymap /
 * immed_dom, the final rootlist, and every out-edge plus mirrored in-edge
 * label.
 *
 * Cases cover: a reducible single back edge labeled f_loop_edge by the
 * direct DFS, nested inner/outer loops labeled latch-first, a self loop on
 * slot 0 followed by a fresh child on slot 1, a double calcLoop run whose
 * second pass must skip already-labeled edges (block.cc:2131 isLoopOut)
 * and leave the state identical, a diamond whose cross edge into a
 * visited-but-popped block truncates the search without a label
 * (block.cc:2138 else), the classic two-entry irreducible pair driven
 * end-to-end through structureLoops (findIrreducible labels the second
 * entry f_irreducible, irreduciblecount > 0, calcLoop then labels the
 * cycle's back edge f_loop_edge), and the structureReset chain
 * structureLoops+calcForwardDominator on a nested irreducible-inside-loop
 * graph (copymap FIND reuse) projecting the immediate dominators.
 */

#include <bits/stdc++.h>

// Test-only access: FlowBlock's private fields sit behind an explicit
// `private:` label, but BlockGraph's helper members (calcLoop,
// structureLoops, calcForwardDominator, ...) are implicitly private (no
// access label after `class BlockGraph : public FlowBlock {`), so
// `private -> public` alone cannot reach them.  `class -> struct` opens
// the implicit-private section; no decompile header uses
// `template<class ...>` or `enum class`, and <bits/stdc++.h> has already
// pulled every standard header, so the rewrite only touches Ghidra
// declarations in this translation unit.
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

class Graph {
public:
  BlockGraph graph;
  std::vector<FlowBlock *> created;

  FlowBlock *makeBlock(void)
  {
    FlowBlock *bl = graph.newBlock();
    created.push_back(bl);
    return bl;
  }

  void edge(FlowBlock *from, FlowBlock *to)
  {
    graph.addEdge(from, to);
  }

  std::string name(FlowBlock *bl) const
  {
    std::ostringstream out;
    out << 'b' << (std::find(created.begin(), created.end(), bl) - created.begin());
    return out.str();
  }

  // Uniform post-call projection shared by every call path. `extra` carries
  // the per-case driver annotation (calcLoop pass count or "-" for the
  // structureLoops chains, whose internals never escape the driver).
  // `full_state` gates the copymap/numdesc projection: FlowBlock's
  // user-provided constructor (block.cc:61-69) initializes flags, index,
  // visitcount, parent and immed_dom but leaves copymap and numdesc
  // indeterminate until findSpanningTree initializes them (block.cc:1025-
  // 1027), so the direct calcLoop cases (no spanning tree) print "-" —
  // those values are heap noise, not algorithm output.
  void observe(const std::string &caseName, const std::string &extra, bool fullState)
  {
    std::ostringstream roots, list, blocks, outedges, inedges;
    const std::vector<FlowBlock *> &gl = graph.getList();
    for (int4 i = 0; i < gl.size(); ++i) {
      if (i != 0) list << ',';
      list << name(gl[i]);
    }
    blocks << '[';
    for (int4 i = 0; i < created.size(); ++i) {
      FlowBlock *bl = created[i];
      if (i != 0) blocks << ';';
      blocks << name(bl) << ":index=" << bl->index
             << ",visit=" << bl->visitcount
             << ",desc=";
      if (fullState)
        blocks << bl->numdesc;
      else
        blocks << '-';
      blocks << ",mark=" << ((bl->flags & FlowBlock::f_mark) ? 1 : 0)
             << ",mark2=" << ((bl->flags & FlowBlock::f_mark2) ? 1 : 0)
             << ",copy=";
      if (!fullState)
        blocks << '-';
      else if (bl->copymap == bl)
        blocks << "self";
      else if (bl->copymap == (FlowBlock *)0)
        blocks << "null";
      else
        blocks << "other:" << name(bl->copymap);
      blocks << ",dom=";
      if (bl->immed_dom == (FlowBlock *)0)
        blocks << "null";
      else
        blocks << name(bl->immed_dom);
    }
    blocks << ']';
    bool first = true;
    for (int4 i = 0; i < created.size(); ++i) {
      FlowBlock *bl = created[i];
      for (int4 s = 0; s < bl->outofthis.size(); ++s) {
        if (!first) outedges << ';';
        first = false;
        outedges << name(bl) << '!' << s << '>' << name(bl->outofthis[s].point)
                 << ':' << flagsText(bl->outofthis[s].label);
      }
    }
    first = true;
    for (int4 i = 0; i < created.size(); ++i) {
      FlowBlock *bl = created[i];
      for (int4 s = 0; s < bl->intothis.size(); ++s) {
        if (!first) inedges << ';';
        first = false;
        inedges << name(bl) << '@' << s << '<' << name(bl->intothis[s].point)
                << ':' << flagsText(bl->intothis[s].label);
      }
    }
    std::cout << "case=" << caseName
              << "|extra=" << extra
              << "|list=[" << list.str() << ']'
              << "|blocks=" << blocks.str()
              << "|out=[" << outedges.str() << ']'
              << "|in=[" << inedges.str() << ']' << '\n';
  }

  // Rootlist projection for the structureLoops chains (funcdata_block.cc:
  // 711-713 consume it: calcForwardDominator input and the
  // rootlist.size() > 1 -> blocks_unreachable decision).
  void observeRoots(const std::string &caseName, const std::string &extra,
                    const std::vector<FlowBlock *> &rootlist)
  {
    std::ostringstream roots;
    for (int4 i = 0; i < rootlist.size(); ++i) {
      if (i != 0) roots << ',';
      roots << name(rootlist[i]);
    }
    std::cout << "case=" << caseName << "_roots|extra=" << extra
              << "|roots=[" << roots.str() << ']'
              << "|unreachable=" << (rootlist.size() > 1 ? 1 : 0) << '\n';
  }
};

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=BLOCK-CALCLOOP-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    {
      // Reducible single loop b0->b1->b2->b1: direct calcLoop on the fresh
      // (unlabeled) graph. DFS path b0,b1,b2; b2!0->b1 closes the cycle
      // (b1 carries f_mark2), so addLoopEdge(b2,0) labels it f_loop_edge;
      // no other edge is touched (block.cc:2133-2137).
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b1, b2);
      g.edge(b2, b1);
      g.graph.calcLoop();
      g.observe("reducible_backedge_labeled", "direct:1", false);
    }
    {
      // Nested loops: inner latch b3->b2 and outer latch b4->b1. The DFS
      // labels the inner back edge first, then continues to b4 and labels
      // the outer back edge; both latches keep f_loop_edge (block.cc:2121-
      // 2144 stack discipline).
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      FlowBlock *b4 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b1, b2);
      g.edge(b2, b3);
      g.edge(b3, b2);
      g.edge(b3, b4);
      g.edge(b4, b1);
      g.graph.calcLoop();
      g.observe("nested_loops_inner_outer", "direct:1", false);
    }
    {
      // Self loop on slot 0 with a fresh child on slot 1: b1 is on its own
      // DFS path when its out-edge 0 is scanned, so the self edge is the
      // cycle (addLoopEdge(b1,0)); slot 1 still descends into b2.
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b1, b1);
      g.edge(b1, b2);
      g.graph.calcLoop();
      g.observe("self_loop_then_child", "direct:1", false);
    }
    {
      // Double calcLoop run on the reducible loop: the second pass must
      // skip the edge labeled by the first (block.cc:2131 isLoopOut
      // continue), leave the labels untouched, and clear both marks again
      // (block.cc:2145-2146) — the projection is identical to one pass.
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b1, b2);
      g.edge(b2, b1);
      g.graph.calcLoop();
      g.graph.calcLoop();
      g.observe("calc_loop_twice_loopout_skip", "direct:2", false);
    }
    {
      // Diamond b0->{b1,b2}, both into b3, with back edge b3->b1. The DFS
      // descends b0!0 first: b3!0->b1 closes a cycle (labeled). After b1
      // and b3 pop, b0!1 descends into b2 and b2!0->b3 hits a
      // visited-but-popped block (f_mark set, f_mark2 clear): the search
      // truncates with NO label and NO descent (block.cc:2138 else).
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b0, b2);
      g.edge(b1, b3);
      g.edge(b2, b3);
      g.edge(b3, b1);
      g.graph.calcLoop();
      g.observe("visited_truncate_no_label", "direct:1", false);
    }
    {
      // Classic two-entry irreducible pair driven end-to-end through
      // structureLoops (block.cc:2194-2215): findSpanningTree builds the
      // tree (b0!0->b1, b1!0->b2 tree; b2!0->b1 back), findIrreducible
      // promotes the second entry b0!1->b2 to f_irreducible
      // (irreduciblecount = 1), so calcLoop runs (block.cc:2211-2214) and
      // its DFS labels the cycle's back edge b2!0->b1 f_loop_edge on top
      // of the spanning-tree labels.
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b0, b2);
      g.edge(b1, b2);
      g.edge(b2, b1);
      std::vector<FlowBlock *> rootlist;
      g.graph.structureLoops(rootlist);
      g.observe("irreducible_endtoend_calcloop", "loops", true);
      g.observeRoots("irreducible_endtoend_calcloop", "loops", rootlist);
    }
    {
      // structureReset graph chain (funcdata_block.cc:711-712):
      // structureLoops followed by calcForwardDominator on a nested
      // irreducible-inside-outer-loop graph (the findIrreducible FIND-reuse
      // shape). irreduciblecount > 0 so calcLoop labels both latches; the
      // dominator projection pins the chain's combined observable state
      // (immed_dom per block, entry null).
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      FlowBlock *b4 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b1, b2);
      g.edge(b1, b3);
      g.edge(b2, b3);
      g.edge(b3, b2);
      g.edge(b2, b4);
      g.edge(b4, b1);
      std::vector<FlowBlock *> rootlist;
      g.graph.structureLoops(rootlist);
      g.graph.calcForwardDominator(rootlist);
      g.observe("structure_reset_chain_dominator", "reset", true);
      g.observeRoots("structure_reset_chain_dominator", "reset", rootlist);
    }
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
