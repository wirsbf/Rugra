/*
 * BLOCKSTRUCT-ORDERBLOCKS-0001: locked Ghidra 12.0.4
 * BlockGraph::orderBlocks (block.hh:430-431) /
 * FlowBlock::compareFinalOrder (block.cc:709-730) final-print-order
 * sort-key oracle.
 *
 * The fixture drives the production orderBlocks() on synthetic top-level
 * lists whose members carry hand-assigned indices (the values the collapse
 * phase leaves on real composites: entry-block mirror index 0 and
 * min-of-components otherwise) and hand-assigned lastOp() arms covering
 * the comparator's full decision surface:
 *   - null lastOp (loops / switch / FlowBlock base, block.hh:239),
 *   - a CPUI_RETURN last op (return-ending block, block.cc:717-728),
 *   - a non-RETURN last op (falls to the index key, block.cc:729),
 * through real BlockGoto (block.hh:562) and BlockMultiGoto (block.hh:590)
 * wrappers so the virtual lastOp() delegation over getBlock(0) is exercised
 * on the same objects the production comparator reads.
 *
 * Cases (see the .metadata.json input_manifest):
 *   1. entry_first_return_last  — index-0 entry pulled out of the middle,
 *      two RETURN-ending blocks pushed to the tail (stable tie: the earlier
 *      pre-sort RETURN block stays first; libstdc++ insertion sort keeps
 *      comparator ties in pre-sort order for ranges <= 16).
 *   2. null_vs_return_arms      — the (null, RETURN), (RETURN, null) and
 *      (null, non-RETURN) arms of block.cc:724-728 with no return blocks
 *      reaching the index key vs one that does.
 *   3. goto_wrapped_lastop      — a real BlockGoto wrapping a
 *      RETURN-ending block sorts to the tail via BlockGoto::lastOp
 *      (block.hh:562 -> getBlock(0)->lastOp()).
 *   4. multigoto_wrapped_lastop — a real BlockMultiGoto wrapping a
 *      non-RETURN block (block.hh:590 delegation) stays ahead of a
 *      RETURN-ending sibling.
 *   5. single_block_skip        — the list.size()!=1 guard (block.hh:431):
 *      a one-element list is left untouched.
 *
 * Observation: per case, the post-orderBlocks list as
 * `<pos> name=bN idx=<i> type=<typename> lastop=<R|n|->` lines.
 */

#include <bits/stdc++.h>

// Test-only access: FlowBlock::index (assigned by findSpanningTree /
// min-of-components addBlock propagation in production) and PcodeOp::opcode
// (set through TypeOp registration in production) are hand-assigned here;
// the same `private -> public` / `class -> struct` include trick as the
// sibling blockstruct/block fixtures.
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

// Minimal TypeOp so a standalone PcodeOp carries a real opcode through
// PcodeOp::code() (op.hh:233 `opcode->getOpcode()`) — exactly what
// compareFinalOrder reads at block.cc:714-724. The two pure virtuals are
// print-only paths never reached by the comparator.
struct FixtureTypeOp : public TypeOp {
  FixtureTypeOp(OpCode c) : TypeOp((TypeFactory *)0, c, "fixture") {}
  virtual void push(PrintLanguage *, const PcodeOp *, const PcodeOp *) const {}
  virtual void printRaw(ostream &, const PcodeOp *) {}
};

struct Vertex : public FlowBlock {
  int id;
  PcodeOp *last; // null | RETURN op | non-RETURN op
  Vertex(int id_) : FlowBlock(), id(id_), last((PcodeOp *)0) {}
  virtual block_type getType(void) const { return t_basic; }
  virtual PcodeOp *lastOp(void) const { return last; }
  virtual void printHeader(ostream &s) const { s << 'b' << id; }
};

static PcodeOp *makeOp(OpCode opc)
{
  PcodeOp *op = new PcodeOp(0, SeqNum());
  op->opcode = new FixtureTypeOp(opc);
  return op;
}

class Fixture {
public:
  BlockGraph graph;
  std::vector<FlowBlock *> created;
  std::vector<PcodeOp *> ops;

  FlowBlock *make(int idx, PcodeOp *last)
  {
    Vertex *bl = new Vertex((int)created.size());
    graph.addBlock(bl);
    created.push_back(bl);
    if (last != (PcodeOp *)0) ops.push_back(last);
    bl->index = idx;
    bl->last = last;
    return bl;
  }

  std::string kindOf(FlowBlock *bl) const
  {
    PcodeOp *op = bl->lastOp();
    if (op == (PcodeOp *)0) return "-";
    return (op->code() == CPUI_RETURN) ? "R" : "n";
  }

  std::string nameOf(FlowBlock *bl) const
  {
    for (int4 i = 0; i < (int4)created.size(); ++i)
      if (created[i] == bl) return string("b") + char('0' + i);
    return "b?";
  }

  void run(const std::string &caseName)
  {
    graph.orderBlocks(); // block.hh:430 production entry
    std::cout << "case " << caseName << '\n';
    const std::vector<FlowBlock *> &lst = graph.getList();
    for (int4 i = 0; i < (int4)lst.size(); ++i) {
      FlowBlock *bl = lst[i];
      std::cout << i << ' ' << nameOf(bl) << " idx=" << bl->getIndex()
                << " type=" << FlowBlock::typeToName(bl->getType())
                << " lastop=" << kindOf(bl) << '\n';
    }
    std::cout << "end\n";
  }
};

int main(void)
{
  // Case 1: entry (index 0) in the middle, two RETURN-ending blocks ahead
  // of it; non-RETURN members (plain op idx7, null idx4) sort by index.
  {
    Fixture f;
    PcodeOp *opRetA = makeOp(CPUI_RETURN);
    PcodeOp *opPlainEntry = makeOp(CPUI_COPY);
    PcodeOp *opRetB = makeOp(CPUI_RETURN);
    PcodeOp *opPlain = makeOp(CPUI_COPY);
    f.make(5, opRetA);        // b0 RETURN
    f.make(0, opPlainEntry);  // b1 entry, non-RETURN
    f.make(2, opRetB);        // b2 RETURN
    f.make(7, opPlain);       // b3 plain
    f.make(4, (PcodeOp *)0);  // b4 null (loop-like)
    f.run("entry_first_return_last");
  }

  // Case 2: (null, RETURN) / (RETURN, null) arms with an entry that has a
  // NULL lastOp (block.cc:712 fires before the RETURN arms), plus a
  // non-RETURN op vs null pair that falls to the index key.
  {
    Fixture f;
    PcodeOp *opRetA = makeOp(CPUI_RETURN);
    PcodeOp *opRetB = makeOp(CPUI_RETURN);
    PcodeOp *opPlain = makeOp(CPUI_INT_ADD);
    f.make(3, (PcodeOp *)0); // b0 null
    f.make(1, opRetA);       // b1 RETURN
    f.make(6, opRetB);       // b2 RETURN
    f.make(8, opPlain);      // b3 plain
    f.make(0, (PcodeOp *)0); // b4 entry, null lastOp
    f.run("null_vs_return_arms");
  }

  // Case 3: real BlockGoto (newBlockGoto, block.cc:1704-1716) wrapping a
  // RETURN-ending block — BlockGoto::lastOp (block.hh:562) delegates to
  // getBlock(0), so the goto composite sorts to the tail.
  {
    Fixture f;
    PcodeOp *opRet = makeOp(CPUI_RETURN);
    PcodeOp *opPlain = makeOp(CPUI_COPY);
    PcodeOp *opTarget = makeOp(CPUI_COPY);
    FlowBlock *b0 = f.make(2, opRet);   // becomes the goto component
    FlowBlock *b1 = f.make(1, opPlain); // plain sibling
    FlowBlock *t = f.make(0, opTarget); // entry + goto target
    f.graph.addEdge(b0, t);
    BlockGoto *g = f.graph.newBlockGoto(b0); // removes b0, appends g at END
    g->index = 2;                             // hand-assigned composite index
    f.created.push_back(g);                   // stable name: b3
    f.run("goto_wrapped_lastop");
  }

  // Case 4: real BlockMultiGoto (newBlockMultiGoto, block.cc:1719-1754)
  // wrapping a non-RETURN block — BlockMultiGoto::lastOp (block.hh:590)
  // delegates to getBlock(0), so the multigoto composite sorts by index
  // ahead of a RETURN-ending sibling.
  {
    Fixture f;
    PcodeOp *opPlain = makeOp(CPUI_COPY);
    PcodeOp *opRet = makeOp(CPUI_RETURN);
    PcodeOp *opNullSibling = (PcodeOp *)0;
    FlowBlock *b0 = f.make(1, opPlain); // becomes the multigoto component
    FlowBlock *t1 = f.make(5, opRet);   // RETURN sibling (kept edge)
    FlowBlock *t2 = f.make(7, opNullSibling); // null sibling (goto edge target)
    f.graph.addEdge(b0, t1);
    f.graph.addEdge(b0, t2);
    BlockMultiGoto *mg = f.graph.newBlockMultiGoto(b0, 1);
    mg->index = 1;
    f.created.push_back(mg); // stable name: b3
    f.run("multigoto_wrapped_lastop");
  }

  // Case 5: single-element list skips the sort (block.hh:431).
  {
    Fixture f;
    PcodeOp *opRet = makeOp(CPUI_RETURN);
    f.make(0, opRet); // lone entry/RETURN block
    f.run("single_block_skip");
  }
  return 0;
}
