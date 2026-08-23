/*
 * BLOCK-FINDIRREDUCIBLE-0001: locked Ghidra 12.0.4
 * BlockGraph::findIrreducible (block.cc:1147-1199) irreducible-edge
 * labeling oracle, including the structureLoops driver wiring
 * (block.cc:2194-2215).
 *
 * The fixture builds synthetic control-flow graphs through the production
 * BlockGraph APIs (newBlock/addEdge), runs findSpanningTree followed by
 * findIrreducible (or the full structureLoops driver), and observes the
 * complete post-call state: needrebuild and irreduciblecount results, the
 * preorder vector fed to findIrreducible, the final rootlist, the reordered
 * component list, every block's index / visitcount / numdesc / mark /
 * copymap (the FIND-structure collapse state), and every out-edge and
 * mirrored in-edge label.
 *
 * Cases cover: a reducible diamond with zero marks, a self-loop back edge
 * whose head is excluded from the reachunder set (block.cc:1160), the
 * classic two-entry irreducible pair with a forward edge promoted to
 * irreducible (block.cc:1182 cross/forward clear), parallel edges seeding
 * the reachunder set twice (double irreduciblecount), a nested
 * irreducible-inside-outer-loop graph whose outer reachunder walk observes
 * copymaps collapsed by the inner pass (FIND reuse, block.cc:1161/1173/
 * 1194), a multi-root graph where a cross edge is promoted to irreducible,
 * and the full structureLoops end-to-end driver on a reducible graph.
 */

#include <bits/stdc++.h>

// Test-only access: FlowBlock's private fields sit behind an explicit
// `private:` label, but BlockGraph's helper members (findSpanningTree,
// findIrreducible, ...) are implicitly private (no access label after
// `class BlockGraph : public FlowBlock {`), so `private -> public` alone
// cannot reach them.  `class -> struct` opens the implicit-private section;
// no decompile header uses `template<class ...>` or `enum class`, and
// <bits/stdc++.h> has already pulled every standard header, so the rewrite
// only touches Ghidra declarations in this translation unit.
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

  // Uniform post-call projection shared by both call paths. `rebuildText`
  // and `cntText` are "-" for the structureLoops case (not observable from
  // outside the driver; the local irreduciblecount never escapes).
  void observe(const std::string &caseName,
               const std::string &rebuildText,
               const std::string &cntText,
               const std::vector<FlowBlock *> &preorder,
               const std::vector<FlowBlock *> &rootlist)
  {
    std::ostringstream pre, roots, list, blocks, outedges, inedges;
    for (int4 i = 0; i < preorder.size(); ++i) {
      if (i != 0) pre << ',';
      pre << name(preorder[i]);
    }
    for (int4 i = 0; i < rootlist.size(); ++i) {
      if (i != 0) roots << ',';
      roots << name(rootlist[i]);
    }
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
             << ",desc=" << bl->numdesc
             << ",mark=" << ((bl->flags & FlowBlock::f_mark) ? 1 : 0)
             << ",copy=";
      if (bl->copymap == bl)
        blocks << "self";
      else if (bl->copymap == (FlowBlock *)0)
        blocks << "null";
      else
        blocks << "other:" << name(bl->copymap);
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
              << "|rebuild=" << rebuildText
              << "|cnt=" << cntText
              << "|pre=[" << pre.str() << ']'
              << "|roots=[" << roots.str() << ']'
              << "|list=[" << list.str() << ']'
              << "|blocks=" << blocks.str()
              << "|out=[" << outedges.str() << ']'
              << "|in=[" << inedges.str() << ']' << '\n';
  }

  // findSpanningTree + findIrreducible path (block.cc:2203-2204 shape).
  void runPair(const std::string &caseName)
  {
    std::vector<FlowBlock *> preorder;
    std::vector<FlowBlock *> rootlist;
    graph.findSpanningTree(preorder, rootlist);
    int4 irreduciblecount = 0;
    bool needrebuild = graph.findIrreducible(preorder, irreduciblecount);
    std::ostringstream rb, cn;
    rb << (needrebuild ? 1 : 0);
    cn << irreduciblecount;
    observe(caseName, rb.str(), cn.str(), preorder, rootlist);
  }
};

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=BLOCK-FINDIRREDUCIBLE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    {
      // Reducible single-entry diamond plus bypass: no back edges, the
      // reachunder set stays empty for every vertex, zero marks.
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b0, b2);
      g.edge(b1, b3);
      g.edge(b2, b3);
      g.edge(b0, b3);
      g.runPair("reducible_diamond_zero_marks");
    }
    {
      // Self-loop: the back edge b1->b1 has y == x, so the loop head never
      // enters its own reachunder set (block.cc:1160); zero marks.
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b1, b1);
      g.edge(b1, b2);
      g.runPair("self_loop_head_skipped");
    }
    {
      // Classic two-entry irreducible pair: b1 <-> b2 with entries from b0
      // on both sides. The forward edge b0!1->b2 is promoted to irreducible
      // (its forward classification is cleared, block.cc:1182) and b2
      // collapses into the loop head b1.
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b0, b2);
      g.edge(b1, b2);
      g.edge(b2, b1);
      g.runPair("classic_two_entry");
    }
    {
      // Parallel edges b0->b0->b2: the reachunder seeding loop pushes
      // FIND(y) once per back edge without a dedup check (block.cc:1161),
      // so the BFS re-scans the duplicate member and irreduciblecount
      // accumulates per parallel edge (2).
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b0, b2);
      g.edge(b0, b2);
      g.edge(b1, b2);
      g.edge(b2, b1);
      g.runPair("parallel_edges_double_count");
    }
    {
      // Irreducible pair {b2,b3} nested inside the outer b1 loop: x=b2's
      // pass collapses b3 into b2, and the later x=b1 pass observes
      // FIND(b3) = b2 (copymap reuse, block.cc:1161/1173/1194); the whole
      // inner component collapses into b1. b1!1->b3 is promoted.
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
      g.runPair("nested_irreducible_find_reuse");
    }
    {
      // Two roots (b0, b1): the rootlist head/tail swap makes b1's tree the
      // first visited; b0's later cross edge b0!0->b2 is promoted to
      // irreducible (cross classification cleared).
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      g.edge(b0, b2);
      g.edge(b1, b3);
      g.edge(b2, b3);
      g.edge(b3, b2);
      g.runPair("multi_root_cross_to_irreducible");
    }
    {
      // Full structureLoops driver (block.cc:2194-2215) on a reducible
      // graph: single pass, no rebuild, irreduciblecount == 0 so calcLoop
      // is never reached. needrebuild/irreduciblecount are driver-internal
      // (projected as "-").
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      FlowBlock *b4 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b1, b2);
      g.edge(b2, b1);
      g.edge(b2, b3);
      g.edge(b3, b2);
      g.edge(b3, b4);
      std::vector<FlowBlock *> rootlist;
      g.graph.structureLoops(rootlist);
      std::vector<FlowBlock *> preorder;
      g.observe("structure_loops_reducible_endtoend", "-", "-", preorder, rootlist);
    }
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
