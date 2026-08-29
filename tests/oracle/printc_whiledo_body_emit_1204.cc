/*
 * MAIN-RC3-STRUCTURED-EMIT-0001: locked Ghidra 12.0.4 PrintC::
 * emitBlockWhileDo body-emission oracle (printc.cc:3061-3062, and the
 * emitForLoop body printc.cc:2994-2995, and the overflow arm cc:3017-3044):
 *   setMod(no_branch);
 *   int4 id2 = emit->beginBlock(bl->getBlock(1));
 *   bl->getBlock(1)->emit(this);        <-- UNCONDITIONAL structured dispatch
 *   emit->endBlock(id2);
 * The body is emitted via the FlowBlock virtual dispatch — a BlockList body
 * renders its children in order, a BlockIf child renders if/else — there is
 * no flat op-list side-arm in the oracle.
 *
 * Mirrors tests/oracle/printc_whiledo_body_emit_1204.rs case for case. The
 * fixture builds the production structure-copy shape by hand (originals are
 * BlockBasic blocks, BlockCopy mirrors through BlockGraph::newBlockCopy +
 * copymap/replaceUsingMap exactly as BlockGraph::buildCopy block.cc:1925-1938),
 * then installs the composites through the same calls the structurer uses
 * (newBlockList, BlockIf + identifyInternal + addBlock like ruleBlockProperIf,
 * newBlockWhileDo block.cc:1858-1870).
 *
 * Cases:
 *   1. whiledo_structured_body — cond CBRANCH(const 3), body =
 *      list[ RET 10, properif(cond CBRANCH(const 7), RET 20, RET 30) ].
 *      Locks: while (3) header, structured body (statement + nested
 *      if/else), the printc.cc:3061-3062 unconditional dispatch.
 *   2. forloop_structured_body — same graph with iterateOp set (CBRANCH
 *      const 5): emitBlockWhileDo cc:3007-3009 dispatches to emitForLoop;
 *      locks the for-header slots (printc.cc:2970-2991) AND the body
 *      printc.cc:2994-2995.
 *   3. overflow_structured_body — f_whiledo_overflow flag (block.hh:102)
 *      set via setOverflowSyntax(): locks the compact `while( true )`
 *      header bytes (cc:3023-3028) and the if(cond) break; arm
 *      (cc:3035-3043) over a structured list body.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as printc_switch_emit_1204.cc): the fixture
// drives production structures whose helpers are protected/private
// (identifyInternal, BlockBasic::insert, BlockWhileDo::iterateOp).
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
  FixturePrintC(void) : PrintC(nullptr, "printc-whiledo-body-emit-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  void render(const BlockWhileDo *bl) {
    emitBlockWhileDo(bl);
    emit->flush();
  }
};

static void append(BlockBasic &block, PcodeOp *op)
{
  block.insert(block.endOp(), op);
}

// One whiledo under construction. originals are owned by this struct; the
// structure graph owns the BlockCopy/BlockIf/BlockList/BlockWhileDo nodes as
// in production.
struct WhileDoBuild {
  PcodeOpBank bank;
  ConstantSpace constant_space;
  TypeBase int_type;
  TypeOpCbranch cbranch_type;
  TypeOpReturn return_type;

  BlockBasic cond{nullptr};		// the loop condition basic
  BlockBasic stmt{nullptr};		// first body statement
  BlockBasic ifcond{nullptr};		// the properif condition basic
  BlockBasic ifb{nullptr};		// properif then-branch
  BlockBasic elseb{nullptr};		// properif else-branch

  JumpTable jt;			// unused; parity with switch fixture layout
  BlockGraph structure;
  BlockWhileDo *wd;

  Varnode condvar;			// the CBRANCH condition input

  explicit WhileDoBuild(uintb cond_value)
    : constant_space(nullptr, nullptr), int_type(4, TYPE_INT),
      cbranch_type(nullptr), return_type(nullptr),
      jt(nullptr, Address()), wd((BlockWhileDo *)0),
      condvar(1, Address(&constant_space, 0), &int_type)
  {
    condvar.updateType(&int_type, true, true);
  }

  // 1-bit bool constant varnode for the CBRANCH in(1). The HighVariable is
  // required: pushVnExplicit → getHighTypeReadFacing → HighVariable::
  // updateType dereferences it (same as the switch fixture's swvar).
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

  // 2-input RETURN with value const(value) — same shape as the switch
  // fixture (post-ActionReturnRecovery: in(0) indirect slot, in(1) value).
  // HighVariable on the value: same pushVnExplicit requirement as bool_const.
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
  // (ruleBlockProperIf blockaction.cc), body list via newBlockList, and the
  // loop via newBlockWhileDo (block.cc:1858-1870).
  void finish(void)
  {
    append(cond, make_cbranch(3));
    append(stmt, make_return(10));
    append(ifcond, make_cbranch(7));
    append(ifb, make_return(20));
    append(elseb, make_return(30));

    std::vector<FlowBlock *> originals;
    originals.push_back(&cond);
    originals.push_back(&stmt);
    originals.push_back(&ifcond);
    originals.push_back(&ifb);
    originals.push_back(&elseb);

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
    ifnodes.push_back(copies[2]);		// condition
    ifnodes.push_back(copies[3]);		// then
    ifnodes.push_back(copies[4]);		// else
    structure.identifyInternal(ifblk, ifnodes);
    structure.addBlock(ifblk);

    std::vector<FlowBlock *> lsnodes;
    lsnodes.push_back(copies[1]);
    lsnodes.push_back(ifblk);
    BlockList *body = structure.newBlockList(lsnodes);

    wd = structure.newBlockWhileDo(copies[0], body);
  }

  std::string render(void)
  {
    std::ostringstream output;
    FixturePrintC printer;
    printer.setOutputStream(&output);
    printer.render(wd);
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
    // 1. whiledo_structured_body
    WhileDoBuild s(3);
    s.finish();
    std::cout << "whiledo_structured_body=" << (raw ? to_hex(s.render()) : s.render()) << '\n';
  }
  {
    // 2. forloop_structured_body: iterateOp set (CBRANCH const 5) —
    // emitBlockWhileDo cc:3007-3009 dispatches to emitForLoop. The
    // initializer slot stays null (optional, cc:2976-2980).
    WhileDoBuild s(3);
    s.finish();
    PcodeOp *iter = s.bank.create(2, Address());
    s.bank.changeOpcode(iter, &s.cbranch_type);
    iter->setInput(s.bool_const(0x1000), 0);
    Varnode *five = s.bool_const(5);
    iter->setInput(five, 1);
    s.wd->iterateOp = iter;
    std::cout << "forloop_structured_body=" << (raw ? to_hex(s.render()) : s.render()) << '\n';
  }
  {
    // 3. overflow_structured_body: f_whiledo_overflow set — the compact
    // while( true ) header (cc:3023-3028) + if(cond) break; arm.
    WhileDoBuild s(3);
    s.finish();
    s.wd->setOverflowSyntax();
    std::cout << "overflow_structured_body=" << (raw ? to_hex(s.render()) : s.render()) << '\n';
  }
  return 0;
}
