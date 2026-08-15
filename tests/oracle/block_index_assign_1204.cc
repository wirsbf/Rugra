/*
 * BLOCK-INDEX-ASSIGN-0001: locked Ghidra 12.0.4
 * BlockGraph::findSpanningTree (block.cc:1009-1136) reverse-post-order
 * FlowBlock::index assignment oracle.
 *
 * The fixture builds synthetic control-flow graphs through the production
 * BlockGraph APIs (newBlock/addEdge) and observes the complete post-call
 * state: preorder and rootlist output vectors, the reordered component
 * list, every block's index / visitcount / numdesc / copymap, every
 * out-edge and mirrored in-edge label, and the distinct-in-range index
 * invariant.
 *
 * Cases cover: empty graph early return, single block, single-entry DAG
 * with pre-corrupted index/visitcount/copymap/numdesc, multi-entry
 * rootlist head/tail swap, no-root assume-first with a loop, an
 * unreachable component forcing the two-pass extraroots regeneration, the
 * stale-root list machinery with self-loops, and irreducible/goto
 * pre-labels that the pass-start clearEdgeFlags(~0) wipes.
 */

#include <bits/stdc++.h>

// Test-only access: FlowBlock's private fields sit behind an explicit
// `private:` label, but BlockGraph's helper members (findSpanningTree,
// clearEdgeFlags, ...) are implicitly private (no access label after
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

  void observe(const std::string &caseName,
               std::vector<FlowBlock *> &preorder,
               std::vector<FlowBlock *> &rootlist)
  {
    std::ostringstream pre, roots, list, blocks, outedges, inedges;
    pre << '[';
    for (int4 i = 0; i < preorder.size(); ++i) {
      if (i != 0) pre << ',';
      pre << name(preorder[i]);
    }
    pre << ']';
    roots << '[';
    for (int4 i = 0; i < rootlist.size(); ++i) {
      if (i != 0) roots << ',';
      roots << name(rootlist[i]);
    }
    roots << ']';
    const std::vector<FlowBlock *> &gl = graph.getList();
    list << '[';
    for (int4 i = 0; i < gl.size(); ++i) {
      if (i != 0) list << ',';
      list << name(gl[i]);
    }
    list << ']';
    bool indices_ok = true;
    std::vector<bool> seen(created.size(), false);
    blocks << '[';
    for (int4 i = 0; i < created.size(); ++i) {
      FlowBlock *bl = created[i];
      if (i != 0) blocks << ';';
      blocks << name(bl) << ":index=" << bl->index
             << ",visit=" << bl->visitcount
             << ",desc=" << bl->numdesc
             << ",copy=";
      if (bl->copymap == bl)
        blocks << "self";
      else if (bl->copymap == (FlowBlock *)0)
        blocks << "null";
      else
        blocks << "other:" << name(bl->copymap);
      if (bl->index < 0 || bl->index >= (int4)created.size() || seen[bl->index])
        indices_ok = false;
      else
        seen[bl->index] = true;
    }
    blocks << ']';
    for (int4 i = 0; i < seen.size(); ++i)
      if (!seen[i]) indices_ok = false;
    outedges << '[';
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
    outedges << ']';
    inedges << '[';
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
    inedges << ']';
    std::cout << "case=" << caseName
              << "|preorder=" << pre.str()
              << "|roots=" << roots.str()
              << "|list=" << list.str()
              << "|blocks=" << blocks.str()
              << "|out=" << outedges.str()
              << "|in=" << inedges.str()
              << "|indices_ok=" << (indices_ok ? 1 : 0) << '\n';
  }
};

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=BLOCK-INDEX-ASSIGN-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    {
      Graph g;
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      g.graph.findSpanningTree(preorder, rootlist);
      g.observe("empty_graph_early_return", preorder, rootlist);
    }
    {
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      (void)b0;
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      g.graph.findSpanningTree(preorder, rootlist);
      g.observe("single_block", preorder, rootlist);
    }
    {
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
      b1->index = 99;
      b1->visitcount = 5;
      b1->copymap = b0;
      b2->numdesc = 77;
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      g.graph.findSpanningTree(preorder, rootlist);
      g.observe("single_entry_dag_corrupt_reset", preorder, rootlist);
    }
    {
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      g.edge(b0, b2);
      g.edge(b1, b2);
      g.edge(b2, b3);
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      g.graph.findSpanningTree(preorder, rootlist);
      g.observe("multi_entry_rootlist_swap", preorder, rootlist);
    }
    {
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b1, b0);
      g.edge(b1, b2);
      g.edge(b2, b1);
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      g.graph.findSpanningTree(preorder, rootlist);
      g.observe("no_root_assume_first_loop", preorder, rootlist);
    }
    {
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b2, b3);
      g.edge(b3, b2);
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      g.graph.findSpanningTree(preorder, rootlist);
      g.observe("unreachable_extraroots_twopass", preorder, rootlist);
    }
    {
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      FlowBlock *b4 = g.makeBlock();
      g.edge(b0, b3);
      g.edge(b1, b0);
      g.edge(b2, b1);
      g.edge(b2, b2);
      g.edge(b4, b4);
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      g.graph.findSpanningTree(preorder, rootlist);
      g.observe("stale_root_machinery", preorder, rootlist);
    }
    {
      Graph g;
      FlowBlock *b0 = g.makeBlock();
      FlowBlock *b1 = g.makeBlock();
      FlowBlock *b2 = g.makeBlock();
      FlowBlock *b3 = g.makeBlock();
      g.edge(b0, b1);
      g.edge(b0, b2);
      g.edge(b1, b3);
      g.edge(b2, b3);
      b0->setOutEdgeFlag(0, FlowBlock::f_irreducible | FlowBlock::f_back_edge);
      b1->setOutEdgeFlag(0, FlowBlock::f_goto_edge | FlowBlock::f_loop_exit_edge);
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      g.graph.findSpanningTree(preorder, rootlist);
      g.observe("irreducible_prelabel_wiped", preorder, rootlist);
    }
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
