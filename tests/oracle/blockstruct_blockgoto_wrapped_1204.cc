/*
 * MAIN-RC2-BLOCKGOTO-WRAPPED-0001: locked Ghidra 12.0.4 BlockGoto
 * lifecycle oracle (block.hh:547-565; block.cc:1702-1713 newBlockGoto,
 * 2856-2864 markUnstructured, 2866-2874 scopeBreak, 2881-2890 gotoPrints).
 *
 * Mirrors tests/oracle/blockstruct_blockgoto_wrapped_1204.rs case for case:
 * the same synthetic graphs run through the production CollapseStructure::
 * collapseAll (ruleBlockGoto fires inside), then the ActionFinalStructure
 * tail scopeBreak(-1,-1) (blockaction.cc:2193). Every tree-resident BlockGoto
 * prints an observation line (index / in+out degree / wrapped component
 * identity+type / gototarget identity+type / gototype / gotoPrints); lines
 * are sorted before printing (the oracle appends composites to the parent
 * list while Rugra installs at the consumed slot — order is a registered
 * normalization on both sides, the per-goto facts are order-free).
 *
 * Synthetic leaves are Vertex : FlowBlock (t_basic): getFrontLeaf returns
 * null for them on BOTH sides (block.cc:344-348 stops at t_copy), so the
 * gotoPrints observation is null-degenerate here by construction — it locks
 * the comparison plumbing, not a prints=1 discriminative case (documented
 * normalization; production trees bottom out at BlockCopy).
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as blockstruct_goto_cascade_1204.cc).
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

  void edge(FlowBlock *from, FlowBlock *to) { graph.addEdge(from, to); }

  std::string nameOf(FlowBlock *bl, const std::vector<FlowBlock *> &toplist) const
  {
    for (int4 i = 0; i < (int4)created.size(); ++i)
      if (created[i] == bl) return string("b") + char('0' + i);
    for (int4 i = 0; i < (int4)toplist.size(); ++i)
      if (toplist[i] == bl) return string("c") + char('0' + i);
    std::stringstream s;
    s << 't' << bl->getIndex();
    return s.str();
  }

  static void collectGotos(FlowBlock *bl, std::vector<FlowBlock *> &out, int4 depth)
  {
    if (depth > 8) return;
    if (bl->getType() == FlowBlock::t_goto) out.push_back(bl);
    // Uniform component walk: every Ghidra composite is a BlockGraph whose
    // list the factories filled in identifyInternal node order.
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0) {
      for (int4 i = 0; i < g->getSize(); ++i)
        collectGotos(g->getBlock(i), out, depth + 1);
    }
  }

  void observe(BlockGoto *bg, const std::vector<FlowBlock *> &toplist, std::vector<std::string> &lines) const
  {
    // block.cc:1705-1708: gototarget captured pre-removeEdge; wrapped block
    // is the single list component (getBlock(0)).
    FlowBlock *wrapped = bg->getBlock(0);
    FlowBlock *target = bg->getGotoTarget();
    std::stringstream s;
    s << "goto idx=" << bg->getIndex()
      << " sizein=" << bg->sizeIn()
      << " sizeout=" << bg->sizeOut()
      << " wrapped=" << nameOf(wrapped, toplist) << ':' << typeName(wrapped->getType())
      << " target=" << nameOf(target, toplist) << ':' << typeName(target->getType())
      << " gototype=" << bg->getGotoType()
      << " prints=" << (bg->gotoPrints() ? 1 : 0);
    lines.push_back(s.str());
  }

  void run(const std::string &caseName)
  {
    std::vector<FlowBlock *> rootlist;
    graph.structureLoops(rootlist);
    graph.clearVisitCount();

    CollapseStructure collapse(graph);
    collapse.collapseAll();

    // ActionFinalStructure tail (blockaction.cc:2193).
    graph.scopeBreak(-1, -1);

    std::vector<FlowBlock *> toplist = graph.getList();
    std::vector<std::string> lines;
    int4 total = 0;
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      std::vector<FlowBlock *> gotos;
      collectGotos(toplist[i], gotos, 0);
      for (int4 j = 0; j < (int4)gotos.size(); ++j) {
        total += 1;
        observe((BlockGoto *)gotos[j], toplist, lines);
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
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b2, b0);
    g.edge(b2, b3);
    g.edge(b3, b1);
    g.run("double_back_goto");
  }
  {
    Graph g;
    FlowBlock *b0 = g.makeBlock();
    FlowBlock *b1 = g.makeBlock();
    FlowBlock *b2 = g.makeBlock();
    FlowBlock *b3 = g.makeBlock();
    FlowBlock *b4 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    g.edge(b1, b3);
    g.edge(b2, b1);
    g.edge(b2, b4);
    g.edge(b3, b4);
    g.edge(b4, b1);
    g.run("loop_exit_conflict_gotos");
  }
  return 0;
}
