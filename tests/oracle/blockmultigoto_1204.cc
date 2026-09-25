/*
 * BLOCKSTRUCT-MULTIGOTO-0001: locked Ghidra 12.0.4 BlockMultiGoto oracle
 * (block.hh:573-593; block.cc:1720-1753 newBlockMultiGoto, 2918-2951
 * scopeBreak/printHeader/nextFlowAfter; blockaction.cc:1456-1458
 * ruleBlockGoto isSwitchOut arm).
 *
 * Mirrors blockmultigoto_1204.rs case for case. Four case families:
 *
 *  A. Rule-driven (production path): the same topologies as the
 *     blockstruct_blockgoto_wrapped_1204 fixture, with f_switch_out set on
 *     the multi-exit block whose edge TraceDAG/selectGoto marks — ruleBlockGoto
 *     must route to newBlockMultiGoto (cc:1456-1458), NOT newBlockGoto. Every
 *     tree-resident BlockMultiGoto prints an observation line (index, degrees,
 *     wrapped component, gotoedge list, hasDefaultGoto); lines are sorted
 *     before printing (append-vs-slot-install order is a registered
 *     normalization on both sides).
 *
 *  A2. loop_exit_conflict (B2-MG-RESID-2 same-shape closure): a WhileDo
 *      whose body holds BOTH a multigoto (switch-out block, gotoedge exiting
 *      the loop) and a contrast BlockGoto targeting the SAME loop exit.
 *      BlockGoto::scopeBreak promotes the contrast to f_break_goto
 *      (cc:2872-2873) while BlockMultiGoto::scopeBreak discards curexit and
 *      never reclassifies gotoedges (cc:2918-2922) — the promotion contrast
 *      is the observation. Built through the production factories
 *      (newBlockMultiGoto / newBlockGoto / newBlockList / newBlockWhileDo);
 *      the withdrawn collapse-driven variant diverged in the legacy cascade
 *      domain, not in newBlockMultiGoto (see B2-MG-RESID-2 registration).
 *
 *  B. Direct-call (pure function semantics, the newBlockMultiGoto contract):
 *     a switch block with 3 external targets + a self edge; peeling a
 *     non-default edge exercises identifyInternal's self-edge absorption +
 *     forceOutputNum(sizeOut()+1) restore (cc:1741-1747); peeling the default
 *     edge on the SAME block exercises the already-t_multigoto branch
 *     (cc:1726-1732: addEdge + removeEdge + setDefaultGoto) and the
 *     pre-mutation isDefaultBranch capture (cc:1725).
 *
 *  C. copy_switch_consumption (B2-MG-RESID-1 same-shape closure): the
 *     multigoto formed over a switch-out head is CONSUMED by newBlockSwitch's
 *     recording path (block.cc:1904-1919) — built here through the same
 *     production calls (newBlockMultiGoto peel, grabCaseBasic,
 *     identifyInternal, addBlock) on a buildCopy graph. The observation is
 *     the BlockSwitch's per-case facts: regular cases (gototype 0) first,
 *     then grabCaseBasic's t_multigoto append arm (cc:3548-3553) re-adds the
 *     peeled gotoedge target as a case with gototype f_goto_goto; no
 *     residual multigoto survives (it is absorbed as cs[0]). The roots are
 *     ordered [switch, after, gotoedge-target] so scopeBreak does NOT
 *     promote the appended case (cc:3620-3623 fires only when the target is
 *     the immediate switch exit) and the raw f_goto_goto stays observable.
 *     The withdrawn rule-pipeline variant lost the pre-collapse goto mark on
 *     the oracle side (see B2-MG-RESID-1 registration); the real-input
 *     consumption path is covered by the curl gp E2E evidence.
 */

#include <bits/stdc++.h>
#include <iostream>

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
  explicit Vertex(int id_) : FlowBlock(), id(id_) { }
  virtual block_type getType(void) const { return t_basic; }
  virtual bool isComplex(void) const { return false; }
  virtual void printHeader(ostream &s) const { s << 'b' << id; }
  // Test-only protected-member access (setFlag is protected, block.hh:155).
  void markSwitchOut() { flags |= f_switch_out; }
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
    if (bl != (FlowBlock *)0 && bl->getType() == FlowBlock::t_copy)
      return nameOf(((BlockCopy *)bl)->copy, toplist);
    for (int4 i = 0; i < (int4)created.size(); ++i)
      if (created[i] == bl) return string("b") + char('0' + i);
    for (int4 i = 0; i < (int4)toplist.size(); ++i)
      if (toplist[i] == bl) return string("c") + char('0' + i);
    std::stringstream s;
    s << 't' << bl->getIndex();
    return s.str();
  }

  static void collectSwitches(FlowBlock *bl, std::vector<FlowBlock *> &out, int4 depth)
  {
    if (depth > 8) return;
    if (bl->getType() == FlowBlock::t_switch) out.push_back(bl);
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0) {
      for (int4 i = 0; i < g->getSize(); ++i)
        collectSwitches(g->getBlock(i), out, depth + 1);
    }
  }

  static void collectMultigotos(FlowBlock *bl, std::vector<FlowBlock *> &out, int4 depth)
  {
    if (depth > 8) return;
    if (bl->getType() == FlowBlock::t_multigoto) out.push_back(bl);
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0) {
      for (int4 i = 0; i < g->getSize(); ++i)
        collectMultigotos(g->getBlock(i), out, depth + 1);
    }
  }

  static void collectGotos(FlowBlock *bl, std::vector<FlowBlock *> &out)
  {
    if (bl->getType() == FlowBlock::t_goto) out.push_back(bl);
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0)
      for (int4 i = 0; i < g->getSize(); ++i) collectGotos(g->getBlock(i), out);
  }

  void observe(BlockMultiGoto *mg, const std::vector<FlowBlock *> &toplist, std::vector<std::string> &lines) const
  {
    // block.cc:1734/1738: wrapped block is the single list component.
    FlowBlock *wrapped = mg->getBlock(0);
    std::stringstream s;
    s << "multigoto idx=" << mg->getIndex()
      << " sizein=" << mg->sizeIn()
      << " sizeout=" << mg->sizeOut()
      << " wrapped=" << nameOf(wrapped, toplist) << ':' << typeName(wrapped->getType())
      << " numgotos=" << mg->numGotos()
      << " gotos=";
    for (int4 i = 0; i < mg->numGotos(); ++i) {
      FlowBlock *t = mg->getGoto(i);
      s << (i == 0 ? "" : ",") << nameOf(t, toplist) << ':' << typeName(t->getType());
    }
    s << " hasdefault=" << (mg->hasDefaultGoto() ? 1 : 0);
    // Out-edge projection after the peel: target names + loop-edge count
    // (forceOutputNum restores a self edge labeled f_loop_edge|f_back_edge,
    // block.cc:887-888).
    s << " outs=";
    int4 loops = 0;
    for (int4 i = 0; i < mg->sizeOut(); ++i) {
      FlowBlock *t = mg->getOut(i);
      s << (i == 0 ? "" : ",") << nameOf(t, toplist);
      if (mg->isLoopOut(i)) loops += 1;
    }
    s << " loopouts=" << loops;
    lines.push_back(s.str());
  }

  void run(const std::string &caseName)
  {
    std::cerr << "RUN " << caseName << std::endl;
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
      std::vector<FlowBlock *> mgs;
      collectMultigotos(toplist[i], mgs, 0);
      for (int4 j = 0; j < (int4)mgs.size(); ++j) {
        total += 1;
        observe((BlockMultiGoto *)mgs[j], toplist, lines);
      }
    }
    std::sort(lines.begin(), lines.end());
    std::cout << "case " << caseName << '\n';
    std::cout << "multigotos=" << total << '\n';
    for (int4 i = 0; i < (int4)lines.size(); ++i) std::cout << lines[i] << '\n';
    std::cout << "end\n";
  }

  // Family C: rule pipeline over a BlockCopy graph — the multigoto is
  // consumed by newBlockSwitch; observe the BlockSwitch's per-case gototypes
  // (grabCaseBasic's t_multigoto arm, block.cc:3548-3553).
  void runSwitch(const std::string &caseName)
  {
    std::cerr << "RUN " << caseName << std::endl;
    std::vector<FlowBlock *> rootlist;
    graph.structureLoops(rootlist);
    graph.clearVisitCount();

    CollapseStructure collapse(graph);
    collapse.collapseAll();
    graph.scopeBreak(-1, -1);

    std::vector<FlowBlock *> toplist = graph.getList();
    std::vector<std::string> lines;
    std::vector<FlowBlock *> sws;
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      std::vector<FlowBlock *> mgs;
      collectMultigotos(toplist[i], mgs, 0);
      for (int4 j = 0; j < (int4)mgs.size(); ++j) {
        lines.push_back(std::string("residual_multigoto ") + nameOf(mgs[j], toplist));
      }
      collectSwitches(toplist[i], sws, 0);
    }
    for (int4 i = 0; i < (int4)sws.size(); ++i) {
      BlockSwitch *bs = (BlockSwitch *)sws[i];
      std::stringstream s;
      s << "switch numcases=" << bs->getNumCaseBlocks();
      for (int4 c = 0; c < bs->getNumCaseBlocks(); ++c) {
        FlowBlock *cb = bs->getCaseBlock(c);
        // CaseOrder::block holds the structured case component; naming goes
        // through copies to the synthetic vertices.
        s << " case" << c << '=' << nameOf(cb, toplist) << ':' << typeName(cb->getType())
          << "/gt" << bs->getGotoType(c) << "/def" << (bs->isDefaultCase(c) ? 1 : 0);
      }
      lines.push_back(s.str());
    }
    int4 switches = (int4)sws.size();
    std::sort(lines.begin(), lines.end());
    std::cout << "case " << caseName << '\n';
    std::cout << "switches=" << switches << '\n';
    if (getenv("FIXTURE_TREE")) {
      for (int4 i = 0; i < (int4)toplist.size(); ++i) {
        std::cout << "[top" << i << "] ";
        toplist[i]->printTree(std::cout, 1);
        std::cout << '\n';
      }
    }
    for (int4 i = 0; i < (int4)lines.size(); ++i) std::cout << lines[i] << '\n';
    std::cout << "end\n";
  }

  // Family B: direct newBlockMultiGoto calls on a hand-labeled switch block.
  void runDirect(const std::string &caseName)
  {
    std::cerr << "RUN " << caseName << std::endl;
    std::vector<FlowBlock *> rootlist;
    graph.structureLoops(rootlist);
    graph.clearVisitCount();

    // s = the switch block: outs = {t0, t1, dflt, self}, dflt is the formal
    // default edge (cc:1725 isDefaultBranch capture target).
    FlowBlock *t0 = makeBlock();
    FlowBlock *t1 = makeBlock();
    FlowBlock *dflt = makeBlock();
    FlowBlock *s = makeBlock();
    edge(s, t0);
    edge(s, t1);
    edge(s, dflt);
    edge(s, s); // self edge — identifyInternal absorbs it in the wrap
    ((Vertex *)s)->markSwitchOut();
    s->setDefaultSwitch(2); // the s->dflt edge
    std::vector<FlowBlock *> toplist = graph.getList();

    // Peel 1 (fresh wrap, cc:1733-1751): non-default edge s->t1 (slot 1).
    BlockMultiGoto *mg = graph.newBlockMultiGoto(s, 1);
    {
      std::stringstream o;
      o << "peel1 type=" << typeName(mg->getType())
        << " sizeout=" << mg->sizeOut()
        << " numgotos=" << mg->numGotos()
        << " gotos=" << nameOf(mg->getGoto(0), toplist)
        << " hasdefault=" << (mg->hasDefaultGoto() ? 1 : 0)
        << " t1_sizein=" << t1->sizeIn()
        << " loopouts=";
      int4 loops = 0;
      for (int4 i = 0; i < mg->sizeOut(); ++i)
        if (mg->isLoopOut(i)) loops += 1;
      o << loops;
      std::cout << o.str() << '\n';
    }

    // Peel 2 (already-t_multigoto branch, cc:1726-1732): the default edge.
    // After peel 1 the self edge is the restored f_loop edge at slot 2 and
    // dflt sits at slot 1 (t0=0, dflt=1, self=2).
    int4 dslot = -1;
    for (int4 i = 0; i < mg->sizeOut(); ++i)
      if (mg->getOut(i) == dflt) dslot = i;
    BlockMultiGoto *mg2 = graph.newBlockMultiGoto(mg, dslot);
    {
      std::stringstream o;
      o << "peel2 type=" << typeName(mg2->getType())
        << " sizeout=" << mg2->sizeOut()
        << " numgotos=" << mg2->numGotos()
        << " gotos=" << nameOf(mg2->getGoto(0), toplist) << ',' << nameOf(mg2->getGoto(1), toplist)
        << " hasdefault=" << (mg2->hasDefaultGoto() ? 1 : 0)
        << " dflt_sizein=" << dflt->sizeIn();
      std::cout << o.str() << '\n';
    }

    // scopeBreak on the multigoto (block.cc:2918-2922): curesxit discarded,
    // -1 passed down, gotoedges untouched.
    mg2->scopeBreak(7, 9);
    std::cout << "after_scopebreak numgotos=" << mg2->numGotos()
              << " hasdefault=" << (mg2->hasDefaultGoto() ? 1 : 0) << '\n';
    std::cout << "case " << caseName << '\n';
    std::cout << "end\n";
  }

  // Family A2 (loop_exit_conflict): WhileDo[cond=h, body=List[mg(s), gt(t→e)]],
  // roots [wd, e]. The multigoto's gotoedge (s→e) and the contrast goto's
  // target (t→e) BOTH exit the loop; scopeBreak must promote ONLY the
  // BlockGoto (cc:2872-2873) — BlockMultiGoto::scopeBreak discards curexit
  // and never reclassifies gotoedges (cc:2918-2922). The promotion contrast
  // plus the surviving multigoto facts are the observation.
  void runLoopExit(const std::string &caseName)
  {
    std::cerr << "RUN " << caseName << std::endl;
    std::vector<FlowBlock *> rootlist;
    graph.structureLoops(rootlist);
    graph.clearVisitCount();

    FlowBlock *h = makeBlock();
    FlowBlock *s = makeBlock();
    FlowBlock *t = makeBlock();
    FlowBlock *e = makeBlock();
    edge(h, s); // loop head flows into the multi-exit body block
    edge(s, h); // backedge
    edge(s, e); // the switch-out edge peeled as the multigoto gotoedge
    edge(t, e); // the contrast goto's own edge to the same loop exit
    ((Vertex *)s)->markSwitchOut();

    // s outs = [h(0), e(1)] — peel slot 1 (the loop-exiting edge).
    BlockMultiGoto *mg = graph.newBlockMultiGoto(s, 1);
    BlockGoto *gt = graph.newBlockGoto(t);
    std::vector<FlowBlock *> nodes;
    nodes.push_back(mg); nodes.push_back(gt);
    BlockList *body = graph.newBlockList(nodes);
    BlockWhileDo *wd = graph.newBlockWhileDo(h, body);
    std::vector<FlowBlock *> order;
    order.push_back(wd); order.push_back(e);
    graph.list = order; // canonical [loop, exit] root order
    graph.scopeBreak(-1, -1); // ActionFinalStructure tail (cc:2193)

    std::vector<FlowBlock *> toplist = graph.getList();
    std::vector<std::string> lines;
    int4 total = 0;
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      std::vector<FlowBlock *> mgs;
      collectMultigotos(toplist[i], mgs, 0);
      for (int4 j = 0; j < (int4)mgs.size(); ++j) {
        total += 1;
        BlockMultiGoto *m = (BlockMultiGoto *)mgs[j];
        FlowBlock *wrapped = m->getBlock(0);
        std::stringstream o;
        // Degrees/outs are deliberately NOT observed here: identifyInternal
        // bubbles the multigoto's edges up to the List/WhileDo level on the
        // oracle side, while the Rust mirror builds those composites as
        // literals — the degree bookkeeping is family B's direct-peel
        // observation territory. This case's discriminative facts: the
        // gotoedge list survives scopeBreak un-reclassified while the
        // contrast BlockGoto is promoted (see loopgoto below).
        o << "loopmg wrapped=" << nameOf(wrapped, toplist) << ':' << typeName(wrapped->getType())
          << " numgotos=" << m->numGotos() << " gotoedges=";
        for (int4 k = 0; k < m->numGotos(); ++k) {
          FlowBlock *tg = m->getGoto(k);
          o << (k == 0 ? "" : ",") << nameOf(tg, toplist) << ':' << typeName(tg->getType());
        }
        o << " hasdefault=" << (m->hasDefaultGoto() ? 1 : 0);
        lines.push_back(o.str());
      }
    }
    // The contrast goto: promoted to f_break_goto because its target IS the
    // loop exit; gotoPrints is evaluated through the production lazy call
    // (parent chain: gt → body list → WhileDo → front_leaf(cond)).
    std::vector<FlowBlock *> gotos;
    for (int4 i = 0; i < (int4)toplist.size(); ++i) collectGotos(toplist[i], gotos);
    for (int4 i = 0; i < (int4)gotos.size(); ++i) {
      BlockGoto *g = (BlockGoto *)gotos[i];
      std::stringstream o;
      o << "loopgoto target=" << nameOf(g->getGotoTarget(), toplist) << ':' << typeName(g->getGotoTarget()->getType())
        << " gototype=" << g->getGotoType()
        << " prints=" << (g->gotoPrints() ? 1 : 0);
      lines.push_back(o.str());
    }
    std::sort(lines.begin(), lines.end());
    std::cout << "case " << caseName << '\n';
    std::cout << "multigotos=" << total << '\n';
    for (int4 i = 0; i < (int4)lines.size(); ++i) std::cout << lines[i] << '\n';
    std::cout << "end\n";
  }
};

// Family C helper: originals (explicit indexes + real edges) mirrored into
// the structure graph as BlockCopy leaves exactly as
// BlockGraph::buildCopy (block.cc:1925-1938) does.
class CopyGraph {
public:
  BlockGraph structure;
  std::vector<FlowBlock *> originals;

  FlowBlock *original(int4 index)
  {
    BlockBasic *orig = new BlockBasic(nullptr);
    orig->index = index; // distinct indexes (mirror the Rust fixture's)
    originals.push_back(orig);
    return orig;
  }

  void edge(FlowBlock *from, FlowBlock *to) { structure.addEdge(from, to); }

  std::vector<FlowBlock *> copyOf(int n)
  {
    std::vector<FlowBlock *> copies;
    for (int4 i = 0; i < n; ++i) {
      FlowBlock *c = structure.newBlockCopy(originals[i]);
      originals[i]->copymap = c;
      copies.push_back(c);
    }
    for (int4 i = 0; i < (int4)copies.size(); ++i)
      ((BlockCopy *)copies[i])->replaceUsingMap();
    return copies;
  }

  std::string nameOf(FlowBlock *bl) const
  {
    if (bl == (FlowBlock *)0) return "null";
    if (bl->getType() == FlowBlock::t_copy)
      return nameOf(((BlockCopy *)bl)->copy);
    for (int4 i = 0; i < (int4)originals.size(); ++i)
      if (originals[i] == bl) return string("b") + char('0' + i);
    std::stringstream s;
    s << 't' << bl->getIndex();
    return s.str();
  }

  // Residual-multigoto walk with the switch-root skip normalization: Rugra
  // keeps the BlockSwitch's cs[0] dispatch root in `control` outside the
  // walked component list, so a multigoto consumed as cs[0] (the
  // grabCaseBasic append arm's source, block.cc:3548-3553) is NOT residual
  // there — skip it here so both sides observe the same residual set.
  static void collectMultigotosSkipSwitchRoot(FlowBlock *bl, std::vector<FlowBlock *> &out, int4 depth)
  {
    if (depth > 8) return;
    if (bl->getType() == FlowBlock::t_multigoto) out.push_back(bl);
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0) {
      for (int4 i = 0; i < g->getSize(); ++i) {
        if (dynamic_cast<BlockSwitch *>(bl) != (BlockSwitch *)0 && i == 0)
          continue; // cs[0] dispatch root: consumed, not residual (Rugra `control`)
        collectMultigotosSkipSwitchRoot(g->getBlock(i), out, depth + 1);
      }
    }
  }

  static void collectSwitches(FlowBlock *bl, std::vector<FlowBlock *> &out, int4 depth)
  {
    if (depth > 8) return;
    if (bl->getType() == FlowBlock::t_switch) out.push_back(bl);
    BlockGraph *g = dynamic_cast<BlockGraph *>(bl);
    if (g != (BlockGraph *)0)
      for (int4 i = 0; i < g->getSize(); ++i)
        collectSwitches(g->getBlock(i), out, depth + 1);
  }

  void run(const std::string &caseName)
  {
    std::cerr << "RUN " << caseName << std::endl;
    std::vector<FlowBlock *> toplist = structure.getList();
    std::vector<std::string> lines;
    std::vector<FlowBlock *> sws;
    for (int4 i = 0; i < (int4)toplist.size(); ++i) {
      std::vector<FlowBlock *> mgs;
      collectMultigotosSkipSwitchRoot(toplist[i], mgs, 0);
      for (int4 j = 0; j < (int4)mgs.size(); ++j)
        lines.push_back(std::string("residual_multigoto ") + nameOf(mgs[j]));
      collectSwitches(toplist[i], sws, 0);
    }
    for (int4 i = 0; i < (int4)sws.size(); ++i) {
      BlockSwitch *bs = (BlockSwitch *)sws[i];
      std::stringstream s;
      s << "switch numcases=" << bs->getNumCaseBlocks();
      for (int4 c = 0; c < bs->getNumCaseBlocks(); ++c) {
        FlowBlock *cb = bs->getCaseBlock(c);
        s << " case" << c << '=' << nameOf(cb) << ':' << typeName(cb->getType())
          << "/gt" << bs->getGotoType(c) << "/def" << (bs->isDefaultCase(c) ? 1 : 0);
      }
      lines.push_back(s.str());
    }
    int4 switches = (int4)sws.size();
    std::sort(lines.begin(), lines.end());
    std::cout << "case " << caseName << '\n';
    std::cout << "switches=" << switches << '\n';
    for (int4 i = 0; i < (int4)lines.size(); ++i) std::cout << lines[i] << '\n';
    std::cout << "end\n";
  }
};

int main()
{
  {
    // Family A case 1: double_back with the multi-exit block b2 marked as a
    // switch — ruleBlockGoto's isSwitchOut arm must multigoto-wrap (the
    // unflagged twin in blockstruct_blockgoto_wrapped_1204 forms a BlockGoto).
    Graph inner;
    FlowBlock *b0 = inner.makeBlock();
    FlowBlock *b1 = inner.makeBlock();
    FlowBlock *b2 = inner.makeBlock();
    FlowBlock *b3 = inner.makeBlock();
    inner.edge(b0, b1);
    inner.edge(b1, b2);
    inner.edge(b2, b0);
    inner.edge(b2, b3);
    inner.edge(b3, b1);
    ((Vertex *)b2)->markSwitchOut();
    Graph g;
    g.graph.buildCopy(inner.graph);
    g.created = inner.created;
    g.runSwitch("switch_double_back_multigoto");
  }
  {
    // Family A2: loop_exit_conflict same-shape closure (B2-MG-RESID-2).
    Graph g;
    g.runLoopExit("loop_exit_conflict");
  }
  {
    // Family B: direct newBlockMultiGoto semantics.
    Graph g;
    g.runDirect("direct_newblockmultigoto");
  }
  {
    // Family C: copy_switch_consumption same-shape closure
    // (B2-MG-RESID-1) — the multigoto is consumed into the BlockSwitch
    // through newBlockSwitch's production recording calls; the gotoedge
    // target re-appears as the appended f_goto_goto case.
    CopyGraph f;
    for (int4 i = 0; i < 5; ++i) f.original(i);
    f.edge(f.originals[0], f.originals[1]); // dispatch edge head→cA
    f.edge(f.originals[0], f.originals[2]); // dispatch edge head→cB
    f.edge(f.originals[0], f.originals[3]); // dispatch edge head→gtgt (peeled)
    std::vector<FlowBlock *> c = f.copyOf(5);
    // Peel the head copy's slot-2 edge (→c[3]) as the multigoto gotoedge
    // (ruleBlockGoto's isSwitchOut arm did this in the pipeline; here the
    // production factory is called directly — newBlockMultiGoto, cc:1707).
    BlockMultiGoto *mg = f.structure.newBlockMultiGoto(c[0], 2);
    // newBlockSwitch's recording (block.cc:1904-1919) over cs=[mg, cA, cB]:
    // grabCaseBasic BEFORE identifyInternal; hollow jumptable keeps labels 0
    // (the real label sort is JUMPTABLE-TABLEAPI-0001 on both sides).
    std::vector<FlowBlock *> cs;
    cs.push_back(mg); cs.push_back(c[1]); cs.push_back(c[2]);
    static BlockBasic hollow(nullptr);
    BlockSwitch *bs = new BlockSwitch(&hollow);
    bs->grabCaseBasic(f.originals[0], cs);
    f.structure.identifyInternal(bs, cs);
    f.structure.addBlock(bs);
    // Roots [switch, after, gotoedge-target]: the gotoedge target is NOT the
    // immediate switch exit, so scopeBreak keeps the appended case's raw
    // f_goto_goto (cc:3620-3623 does not fire) — observable as gt1.
    std::vector<FlowBlock *> order;
    order.push_back(bs); order.push_back(c[4]); order.push_back(c[3]);
    f.structure.list = order;
    f.structure.scopeBreak(-1, -1); // ActionFinalStructure tail (cc:2193)
    f.run("copy_switch_consumption");
  }
  return 0;
}
