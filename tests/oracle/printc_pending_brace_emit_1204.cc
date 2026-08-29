/*
 * PRINTC-STRUCTEMIT-MAIN-IVAR4-DUP-0001: locked Ghidra 12.0.4 PrintC::
 * emitBlockIf PendingBrace oracle (printc.cc:2878-2948 + prettyprint.hh:
 * 102/443-457/1129-1137):
 *   if (isSet(pending_brace)) emit->setPendingPrint(&pendingBrace);   2884
 *   ...condBlock->emit(this)...                                       2897
 *   if (emit->hasPendingPrint(&pendingBrace)) {                       2900
 *     emit->cancelPendingPrint(); emit->spaces(1);                    2901-2902
 *   } else emit->tagLine();                                           2905
 *   ...                                                               2946
 *   if (pendingBrace.getIndentId() >= 0)
 *     emit->closeBraceIndent(CLOSE_CURLY, pendingBrace.getIndentId());2947-2948
 * The PendPrint slot is BASE-CLASS Emit state; only EmitPrettyPrint::
 * tagLine fires it (prettyprint.cc:920/930) — EmitNoMarkup::tagLine
 * (prettyprint.hh:557) never does.
 *
 * Mirrors tests/oracle/printc_pending_brace_emit_1204.rs case for case.
 * Structure built like the whiledo fixture (BlockCopy mirrors via
 * newBlockCopy/copymap/replaceUsingMap as buildCopy block.cc:1925-1938,
 * composites via identifyInternal like ruleBlockProperIf): a 3-component
 * parent properif(condA CBRANCH 3, thenA RET 20, else = child properif)
 * where the child's condition block varies per case.
 *
 * Cases:
 *   1. elseif_stmtcond_pretty — child condition = [RET 21, CBRANCH 9],
 *      EmitPrettyPrint: the condition statement's tagLine FIRES the
 *      pending brace -> `else {` + `return 21;` + newline `if (9) {` +
 *      deferred close (cc:2946-2948). The main-region golden shape.
 *   2. elseif_emptycond_pretty — child condition = [CBRANCH 9] only,
 *      EmitPrettyPrint: nothing fires the brace -> cc:2900-2902 cancel +
 *      spaces(1) -> merged `else if (9) {`, no deferred close.
 *   3. elseif_stmtcond_nomarkup — same graph as case 1, EmitNoMarkup:
 *      tagLine never fires the brace (hh:557) -> condition statements
 *      print inline after `else`, then cc:2902 spaces(1) merges the
 *      `if` onto the statement's line; indentId stays -1 so cc:2946
 *      closes nothing.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as printc_whiledo_body_emit_1204.cc).
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
#include "prettyprint.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef class
#undef private

using namespace ghidra;

class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(bool pretty)
    : PrintC(nullptr, "printc-pending-brace-emit-1204") {
    delete emit;
    emit = pretty ? static_cast<Emit *>(new EmitPrettyPrint())
                  : static_cast<Emit *>(new EmitNoMarkup());
  }

  void render(const BlockIf *bl) {
    // docFunction (printc.cc:2651/2664) opens the emitter's function group
    // before any block emission — EmitPrettyPrint's indent stack needs that
    // root group (TokenBreak/BeginIndent read indentstack.back()). The group
    // itself prints no bytes (PrintClass::Begin), so the observation stays
    // the bare if-emission stream.
    int4 id = emit->beginFunction((const Funcdata *)0);
    emitBlockIf(bl);
    emit->endFunction(id);
    emit->flush();
  }
};

static void append(BlockBasic &block, PcodeOp *op)
{
  block.insert(block.endOp(), op);
}

struct PendingBraceBuild {
  PcodeOpBank bank;
  ConstantSpace constant_space;
  TypeBase int_type;
  TypeOpCbranch cbranch_type;
  TypeOpReturn return_type;

  BlockBasic conda{nullptr};		// parent condition basic
  BlockBasic thena{nullptr};		// parent then-branch
  BlockBasic condb{nullptr};		// child condition basic
  BlockBasic thenb{nullptr};		// child then-branch

  BlockGraph structure;
  BlockIf *parent;

  explicit PendingBraceBuild(bool stmt_in_cond)
    : constant_space(nullptr, nullptr), int_type(4, TYPE_INT),
      cbranch_type(nullptr), return_type(nullptr),
      parent((BlockIf *)0)
  {
    append(conda, make_cbranch(3));
    append(thena, make_return(20));
    if (stmt_in_cond)
      append(condb, make_return(21));
    append(condb, make_cbranch(9));
    append(thenb, make_return(40));
  }

  Varnode *bool_const(uintb value)
  {
    Varnode *vn = new Varnode(1, Address(&constant_space, value), &int_type);
    new HighVariable(vn);
    return vn;
  }

  PcodeOp *make_cbranch(uintb value)
  {
    PcodeOp *op = bank.create(2, Address());
    bank.changeOpcode(op, &cbranch_type);
    op->setInput(bool_const(0x1000), 0);
    op->setInput(bool_const(value), 1);
    return op;
  }

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

  void finish(void)
  {
    std::vector<FlowBlock *> originals;
    originals.push_back(&conda);
    originals.push_back(&thena);
    originals.push_back(&condb);
    originals.push_back(&thenb);

    std::vector<BlockCopy *> copies;
    for (int4 i = 0; i < (int4)originals.size(); ++i) {
      BlockCopy *c = structure.newBlockCopy(originals[i]);
      originals[i]->copymap = c;
      copies.push_back(c);
    }
    for (int4 i = 0; i < (int4)copies.size(); ++i)
      copies[i]->replaceUsingMap();

    BlockIf *child = new BlockIf();
    std::vector<FlowBlock *> childnodes;
    childnodes.push_back(copies[2]);		// child condition
    childnodes.push_back(copies[3]);		// child then
    structure.identifyInternal(child, childnodes);
    structure.addBlock(child);

    parent = new BlockIf();
    std::vector<FlowBlock *> parentnodes;
    parentnodes.push_back(copies[0]);		// parent condition
    parentnodes.push_back(copies[1]);		// parent then
    parentnodes.push_back(child);		// parent else = child properif
    structure.identifyInternal(parent, parentnodes);
    structure.addBlock(parent);
  }

  std::string render(bool pretty)
  {
    std::ostringstream output;
    FixturePrintC printer(pretty);
    printer.setOutputStream(&output);
    printer.render(parent);
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
    // 1. elseif_stmtcond_pretty
    PendingBraceBuild s(true);
    s.finish();
    std::cout << "elseif_stmtcond_pretty=" << (raw ? to_hex(s.render(true)) : s.render(true)) << '\n';
  }
  {
    // 2. elseif_emptycond_pretty
    PendingBraceBuild s(false);
    s.finish();
    std::cout << "elseif_emptycond_pretty=" << (raw ? to_hex(s.render(true)) : s.render(true)) << '\n';
  }
  {
    // 3. elseif_stmtcond_nomarkup
    PendingBraceBuild s(true);
    s.finish();
    std::cout << "elseif_stmtcond_nomarkup=" << (raw ? to_hex(s.render(false)) : s.render(false)) << '\n';
  }
  return 0;
}
