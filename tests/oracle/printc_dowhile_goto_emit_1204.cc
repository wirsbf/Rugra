/*
 * PRINTC-NESTED-DOWHILE-EMIT-0001: locked Ghidra 12.0.4 PrintC
 * do-while body emission + goto-wrapped structured emission oracle:
 *
 *   PrintC::emitBlockDoWhile (printc.cc:3068-3095):
 *     pushMod(); unsetMod(no_branch|only_branch);
 *     emitAnyLabelStatement(bl); tagLine(); print(KEYWORD_DO);
 *     openBraceIndent(...);
 *     pushMod();
 *     int4 id2 = emit->beginBlock(bl->getBlock(0));
 *     setMod(no_branch);
 *     bl->getBlock(0)->emit(this);        <-- STRUCTURED dispatch of the body
 *     emit->endBlock(id2); popMod();
 *     closeBraceIndent(...);
 *     op = bl->getBlock(0)->lastOp();
 *     tagOp(KEYWORD_WHILE,...); setMod(only_branch);
 *     bl->getBlock(0)->emit(this);        <-- condition re-emission
 *     print(SEMICOLON); popMod();
 *
 *   PrintC::emitBlockGoto (printc.cc:2766-2778):
 *     pushMod(); setMod(no_branch);
 *     bl->getBlock(0)->emit(this);        <-- STRUCTURED dispatch of the
 *                                           wrapped block — a DoWhile nested
 *                                           inside a Goto-wrapped composite
 *                                           renders `do { ... } while(...);`,
 *                                           never a flat single-iteration
 *                                           op walk
 *     popMod();
 *     if (bl->gotoPrints()) { tagLine(); emitGotoStatement(...); }
 *
 * Mirrors tests/oracle/printc_dowhile_goto_emit_1204.rs case for case. The
 * fixture builds the production structure-copy shape by hand (originals are
 * BlockBasic blocks, BlockCopy mirrors through BlockGraph::newBlockCopy +
 * copymap/replaceUsingMap exactly as BlockGraph::buildCopy block.cc:1925-1938),
 * then installs the composites through the same calls the structurer uses
 * (newBlockList, BlockIf + identifyInternal + addBlock like ruleBlockProperIf,
 * newBlockDoWhile block.cc:1874-1884, BlockGoto via identifyInternal like
 * ruleBlockGoto block.cc:1702-1713).
 *
 * Cases:
 *   1. dowhile_structured_body — body = list[ RET 10,
 *      properif(cond CBRANCH(const 7), RET 20, RET 30), latch CBRANCH(const 5) ].
 *      Locks: `do` keyword, structured body (statement + nested if/else with
 *      the latch branch suppressed), the printc.cc:3081-3083 getBlock(0)
 *      dispatch, and the `while (5);` tail from the latch CBRANCH re-emission
 *      (cc:3088-3093). This is main's strlen-loop shape: a break-guard-style
 *      properif nested inside the do body.
 *   2. goto_wrapped_dowhile — the case-1 BlockDoWhile wrapped by a BlockGoto
 *      (gototarget = a RET tail basic, f_goto_goto). Locks printc.cc:2771:
 *      the wrapped structured block emits through the virtual dispatch —
 *      `do { ... } while (5);` appears; a flat op-list walk would collapse
 *      the loop to single-iteration statements. The goto's parent is nulled
 *      before emission so gotoPrints() takes the cc:2889 null-parent arm
 *      (no formal goto statement) — isolating the body-dispatch observation
 *      from goto-statement placement.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as printc_whiledo_body_emit_1204.cc): the
// fixture drives production structures whose helpers are protected/private
// (identifyInternal, BlockBasic::insert, FlowBlock::parent).
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
#include "printc.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef class
#undef private

using namespace ghidra;

class FixturePrintC final : public PrintC {
public:
  FixturePrintC(void) : PrintC(nullptr, "printc-dowhile-goto-emit-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  void render_dowhile(const BlockDoWhile *bl) {
    emitBlockDoWhile(bl);
    emit->flush();
  }

  void render_goto(const BlockGoto *bl) {
    emitBlockGoto(bl);
    emit->flush();
  }
};

static void append(BlockBasic &block, PcodeOp *op)
{
  block.insert(block.endOp(), op);
}

// One do-while under construction. originals are owned by this struct; the
// structure graph owns the BlockCopy/BlockIf/BlockList/BlockDoWhile nodes as
// in production.
struct DoWhileBuild {
  PcodeOpBank bank;
  ConstantSpace constant_space;
  TypeBase int_type;
  TypeOpCbranch cbranch_type;
  TypeOpReturn return_type;

  BlockBasic stmt{nullptr};		// first body statement
  BlockBasic ifcond{nullptr};		// properif condition basic
  BlockBasic ifb{nullptr};		// properif then-branch
  BlockBasic elseb{nullptr};		// properif else-branch
  BlockBasic latch{nullptr};		// do-while latch (terminal CBRANCH)
  BlockBasic tail{nullptr};		// goto target (never copied)

  JumpTable jt;			// unused; parity with whiledo fixture layout
  BlockGraph structure;
  BlockDoWhile *dw;

  explicit DoWhileBuild(void)
    : constant_space(nullptr, nullptr), int_type(4, TYPE_INT),
      cbranch_type(nullptr), return_type(nullptr),
      jt(nullptr, Address()), dw((BlockDoWhile *)0)
  {
  }

  // 1-bit bool constant varnode for the CBRANCH in(1). The HighVariable is
  // required: pushVnExplicit → getHighTypeReadFacing → HighVariable::
  // updateType dereferences it (same as the whiledo fixture's bool_const).
  Varnode *bool_const(uintb value)
  {
    Varnode *vn = new Varnode(1, Address(&constant_space, value), &int_type);
    new HighVariable(vn);
    return vn;
  }

  // CBRANCH with in(0) = code placeholder, in(1) = const(value).
  PcodeOp *make_cbranch(uintb value)
  {
    PcodeOp *op = bank.create(2, Address());
    bank.changeOpcode(op, &cbranch_type);
    op->setInput(bool_const(0x1000), 0);	// code pointer placeholder
    op->setInput(bool_const(value), 1);
    return op;
  }

  // 2-input RETURN with value const(value) — same shape as the whiledo
  // fixture (post-ActionReturnRecovery: in(0) indirect slot, in(1) value).
  PcodeOp *make_return(uintb value)
  {
    Varnode *val = new Varnode(4, Address(&constant_space, value), &int_type);
    new HighVariable(val);
    PcodeOp *op = bank.create(2, Address());
    bank.changeOpcode(op, &return_type);
    op->setInput(bool_const(0x1000), 0);
    op->setInput(val, 1);
    return op;
  }

  // Mirror BlockGraph::buildCopy over the originals, then install the
  // composites the way the structurer does: properif via identifyInternal
  // (ruleBlockProperIf blockaction.cc), body list via newBlockList, the
  // loop via newBlockDoWhile (block.cc:1874-1884).
  void finish(void)
  {
    append(stmt, make_return(10));
    append(ifcond, make_cbranch(7));
    append(ifb, make_return(20));
    append(elseb, make_return(30));
    append(latch, make_cbranch(5));
    append(tail, make_return(50));

    std::vector<FlowBlock *> originals;
    originals.push_back(&stmt);
    originals.push_back(&ifcond);
    originals.push_back(&ifb);
    originals.push_back(&elseb);
    originals.push_back(&latch);

    std::vector<BlockCopy *> copies;
    for (int4 i = 0; i < (int4)originals.size(); ++i) {
      BlockCopy *c = structure.newBlockCopy(originals[i]);
      originals[i]->copymap = c;
      copies.push_back(c);
    }
    for (int4 i = 0; i < (int4)copies.size(); ++i)
      copies[i]->replaceUsingMap();

    BlockIf *ifblk = new BlockIf();
    std::vector<FlowBlock *> ifnodes;
    ifnodes.push_back(copies[1]);		// condition
    ifnodes.push_back(copies[2]);		// then
    ifnodes.push_back(copies[3]);		// else
    structure.identifyInternal(ifblk, ifnodes);
    structure.addBlock(ifblk);

    std::vector<FlowBlock *> lsnodes;
    lsnodes.push_back(copies[0]);
    lsnodes.push_back(ifblk);
    lsnodes.push_back(copies[4]);		// latch last: while-cond source
    BlockList *body = structure.newBlockList(lsnodes);

    dw = structure.newBlockDoWhile(body);
  }

  std::string render(void)
  {
    std::ostringstream output;
    FixturePrintC printer;
    printer.setOutputStream(&output);
    printer.render_dowhile(dw);
    return output.str();
  }

  // Wrap the finished BlockDoWhile in a BlockGoto the way ruleBlockGoto
  // wraps an existing composite (block.cc:1702-1713 shape: gototarget from
  // the out edge, identifyInternal over the single node), then null the
  // parent so gotoPrints() takes the null-parent arm (cc:2889) and no
  // formal goto statement is emitted — the observation isolates the
  // printc.cc:2771 wrapped-block dispatch.
  std::string render_wrapped(void)
  {
    BlockGoto *g = new BlockGoto(&tail);	// f_goto_goto, target = tail
    std::vector<FlowBlock *> nodes;
    nodes.push_back(dw);
    structure.identifyInternal(g, nodes);
    structure.addBlock(g);
    g->parent = (FlowBlock *)0;

    std::ostringstream output;
    FixturePrintC printer;
    printer.setOutputStream(&output);
    printer.render_goto(g);
    return output.str();
  }
};

static std::string to_hex(const std::string &value)
{
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (const unsigned char byte : value)
    stream << std::setw(2) << static_cast<unsigned int>(byte);
  return stream.str();
}

int main(int argc, char **argv)
{
  const bool raw = argc == 2 && std::string(argv[1]) == "--raw";
  {
    // 1. dowhile_structured_body
    DoWhileBuild s;
    s.finish();
    std::cout << "dowhile_structured_body=" << (raw ? to_hex(s.render()) : s.render()) << '\n';
  }
  {
    // 2. goto_wrapped_dowhile
    DoWhileBuild s;
    s.finish();
    std::cout << "goto_wrapped_dowhile=" << (raw ? to_hex(s.render_wrapped()) : s.render_wrapped()) << '\n';
  }
  return 0;
}
