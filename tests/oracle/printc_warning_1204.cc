// PRINTC-WARNING-COMMENT-0001 fixture — PrintC's comment emission protocol
// (the print side of Funcdata::warning / Funcdata::warningHeader) against
// locked Ghidra 12.0.4.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Covers the emission path that renders
//   /* WARNING: Subroutine does not return */
// (flow.cc:646 checkForFlowModification -> funcdata.cc:119 Funcdata::warning
// -> CommentDatabaseInternal -> CommentSorter -> PrintC) plus the header
// form of funcdata.cc:135 Funcdata::warningHeader:
//
//   docFunction:2650        commsorter.setupFunctionList(instr_comment_type|
//                           head_comment_type, fd, *fd->getArch()->commentdb,
//                           option_unplaced)
//   emitCommentFuncHeader   (printc.cc:3272-3311) header_basic drain of
//                           header/warningheader comments before the
//                           signature; trailing tagLine when any emitted
//   emitBlockBasic:2684     commsorter.setupBlockList(bb) per-block window
//   emitBlockBasic:2712/2717 emitCommentGroup(inst) before each printed
//                           statement (instr_comment_type = user2|warning)
//   emitBlockBasic:2742     emitCommentGroup(NULL) tail drain
//   emitLineComment         (printlanguage.cc:589-648) C-style delimiters
//                           ("/* " / " */") and the absolute indent override
//                           (indent<0 -> line_commentindent=20; EmitNoMarkup::
//                           tagLine(indent) writes endl + exactly `indent`
//                           spaces, prettyprint.hh:557)
//
// Cases (mirrored step-for-step by printc_warning_1204.rs):
//   clean    — function with an empty comment database: zero bytes emitted
//   noreturn — Funcdata::warning("Subroutine does not return", call addr)
//              positioned at the call op's block; emitted at that block's
//              first statement landmark at column 20
//   multi    — warningHeader at the entry (header_basic drain at indent 0)
//              + an intra-block warning positioned between two ops + a
//              warning positioned at a later block's first op
//
// Block indexes come from the production BlockGraph::findSpanningTree
// reverse-post-order assignment (same as the Rust port); block ranges use
// Funcdata::setBasicBlockRange with end == the address of the block's last
// op, matching Rugra's [start_addr, last-op addr] projection.
#include <bits/stdc++.h>

// Test-only access, same pattern as tests/oracle/comment_sorter_iterators_
// 1204.cc: FixtureArchitecture must assign the protected Architecture::
// commentdb member so Funcdata::warning/warningHeader run through the real
// glb->commentdb channel; `class -> struct` opens the implicit-private
// section for the Translate overrides.
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "comment.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "printc.hh"
#include "printlanguage.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef class
#undef private

using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "register", false, 8, 1, 4,
                              AddrSpace::hasphysical, 0, 0));
    SpacebaseSpace *stack = new SpacebaseSpace(this, this, "stack", 5, 8,
                              getSpace(3), 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = getSpace(4);
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    setDefaultCodeSpace(3);
    dummy_register.space = getSpace(4);
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override {
    return (PcodeInjectLibrary *)0;
  }
  void buildTypegrp(DocumentStorage &) override {}
  void buildCoreTypes(DocumentStorage &) override {}
  void buildCommentDB(DocumentStorage &) override {}
  void buildStringManager(DocumentStorage &) override {}
  void buildConstantPool(DocumentStorage &) override {}
  void buildContext(DocumentStorage &) override {}
  void buildSymbols(DocumentStorage &) override {}
  void buildSpecFile(DocumentStorage &) override {}
  void modifySpaces(Translate *) override {}
  void resolveArchitecture(void) override {}

public:
  FixtureArchitecture() {
    FixtureTranslate *fixture_translate = new FixtureTranslate();
    translate = fixture_translate;
    copySpaces(fixture_translate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  // Route Funcdata::warning/warningHeader through the real
  // glb->commentdb channel (funcdata.cc:128/144). NOTE: Architecture's
  // destructor deletes commentdb, so the database must be heap-allocated
  // (a fresh one per case; earlier ones intentionally leak in this test
  // binary — only the final one is reclaimed by the Architecture).
  void installCommentDB(CommentDatabase *db) { commentdb = db; }

  void printMessage(const std::string &) const override {}
};

// PrintC subclass exposing the protected comment protocol steps the oracle
// performs inside docFunction/emitBlockBasic. PrintC(nullptr, nm) matches
// the printc_display_1204 precedent; resetDefaultsPrintC installs the
// C-style delimiters ("/* " / " */") and line_commentindent = 20. The ctor
// swaps the default EmitPrettyPrint (printlanguage.cc:69) for a bare
// EmitNoMarkup so the fixture observes the comment protocol bytes
// (EmitNoMarkup::tagLine(indent) writes endl + exactly `indent` spaces,
// prettyprint.hh:557) without the pretty printer's line-fill state — the
// same emitter class the Rust comparand drives.
class FixturePrintC final : public PrintC {
public:
  FixturePrintC() : PrintC(nullptr, "printc-warning-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  // printc.cc:2650 docFunction comment setup.
  void loadComments(const Funcdata *fd) {
    commsorter.setupFunctionList(instr_comment_type | head_comment_type, fd,
                                 *fd->getArch()->commentdb, option_unplaced);
  }
  // printc.cc:2652 emitCommentFuncHeader.
  void headerEmit(const Funcdata *fd) { emitCommentFuncHeader(fd); }
  // printc.cc:2684 setupBlockList(bb).
  void blockList(const FlowBlock *bl) { commsorter.setupBlockList(bl); }
  // printc.cc:2712/2717 emitCommentGroup(inst).
  void groupEmit(const PcodeOp *inst) { emitCommentGroup(inst); }
};

// Drive the docFunction/emitBlockBasic comment protocol over one function
// and return the raw EmitNoMarkup bytes: header drain, then per block the
// setupBlockList window, one emitCommentGroup landmark per op (insertion
// order), and the emitCommentGroup(NULL) tail.
std::string run_protocol(Funcdata &fd, const std::vector<BlockBasic *> &blocks) {
  FixturePrintC printer;
  std::ostringstream out;
  printer.setOutputStream(&out);
  printer.loadComments(&fd);
  printer.headerEmit(&fd);
  for (BlockBasic *bb : blocks) {
    printer.blockList(bb);
    std::list<PcodeOp *>::const_iterator iter;
    for (iter = bb->beginOp(); iter != bb->endOp(); ++iter)
      printer.groupEmit(*iter);
    printer.groupEmit((const PcodeOp *)0);
  }
  return out.str();
}

void report(const char *case_id, const std::string &emission) {
  std::cout << "case=" << case_id << "|len=" << emission.size() << "|emit=<<<"
            << emission << ">>>\n";
}

PcodeOp *new_op(Funcdata &fd, AddrSpace *ram, uintb off, BlockBasic *bb) {
  PcodeOp *op = fd.newOp(0, Address(ram, off));
  fd.opSetOpcode(op, CPUI_COPY);
  fd.opInsertEnd(op, bb);
  return op;
}

}  // namespace

int main() {
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  AttributeId::initialize();
  ElementId::initialize();
  std::cout << "schema=1|fixture=PRINTC-WARNING-COMMENT-0001|oracle="
            << "e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureTranslate trans;
    FixtureArchitecture architecture;
    AddrSpace *ram = trans.getSpace(3);

    // ---- case clean: no comments anywhere ----
    {
      architecture.installCommentDB(new CommentDatabaseInternal);
      Address fad(ram, 0x8000);
      Funcdata fd("clean", "clean", architecture.symboltab->getGlobalScope(),
                  fad, (FunctionSymbol *)0, 0x10);
      BlockGraph graph;
      BlockBasic *bb = graph.newBlockBasic(&fd);
      fd.setBasicBlockRange(bb, Address(ram, 0x8000), Address(ram, 0x8004));
      (void)new_op(fd, ram, 0x8000, bb);
      (void)new_op(fd, ram, 0x8004, bb);
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      graph.findSpanningTree(preorder, rootlist);
      report("clean", run_protocol(fd, {bb}));
    }

    // ---- case noreturn: one inline warning at the call op ----
    {
      architecture.installCommentDB(new CommentDatabaseInternal);
      Address fad(ram, 0x9000);
      Funcdata fd("noreturn", "noreturn",
                  architecture.symboltab->getGlobalScope(), fad,
                  (FunctionSymbol *)0, 0x20);
      BlockGraph graph;
      BlockBasic *bb0 = graph.newBlockBasic(&fd);
      BlockBasic *bb1 = graph.newBlockBasic(&fd);
      fd.setBasicBlockRange(bb0, Address(ram, 0x9000), Address(ram, 0x9006));
      fd.setBasicBlockRange(bb1, Address(ram, 0x9008), Address(ram, 0x900a));
      graph.addEdge(bb0, bb1);
      (void)new_op(fd, ram, 0x9000, bb0);
      (void)new_op(fd, ram, 0x9006, bb0);
      PcodeOp *call = new_op(fd, ram, 0x9008, bb1);
      (void)new_op(fd, ram, 0x900a, bb1);
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      graph.findSpanningTree(preorder, rootlist);
      // flow.cc:646 channel: data.warning("Subroutine does not return",
      // op->getAddr()) -> funcdata.cc:119 prefix "WARNING: " ->
      // commentdb addCommentNoDuplicate(warning, fad, call addr).
      fd.warning("Subroutine does not return", call->getAddr());
      report("noreturn", run_protocol(fd, {bb0, bb1}));
    }

    // ---- case multi: header warning + two inline warnings ----
    {
      architecture.installCommentDB(new CommentDatabaseInternal);
      Address fad(ram, 0xa000);
      Funcdata fd("multi", "multi", architecture.symboltab->getGlobalScope(),
                  fad, (FunctionSymbol *)0, 0x20);
      BlockGraph graph;
      BlockBasic *bb0 = graph.newBlockBasic(&fd);
      BlockBasic *bb1 = graph.newBlockBasic(&fd);
      BlockBasic *bb2 = graph.newBlockBasic(&fd);
      fd.setBasicBlockRange(bb0, Address(ram, 0xa000), Address(ram, 0xa006));
      fd.setBasicBlockRange(bb1, Address(ram, 0xa008), Address(ram, 0xa00a));
      fd.setBasicBlockRange(bb2, Address(ram, 0xa00c), Address(ram, 0xa00e));
      graph.addEdge(bb0, bb1);
      graph.addEdge(bb1, bb2);
      (void)new_op(fd, ram, 0xa000, bb0);
      (void)new_op(fd, ram, 0xa006, bb0);
      PcodeOp *call1 = new_op(fd, ram, 0xa008, bb1);
      (void)new_op(fd, ram, 0xa00a, bb1);
      PcodeOp *call2 = new_op(fd, ram, 0xa00c, bb2);
      (void)new_op(fd, ram, 0xa00e, bb2);
      std::vector<FlowBlock *> preorder;
      std::vector<FlowBlock *> rootlist;
      graph.findSpanningTree(preorder, rootlist);
      // funcdata.cc:135 warningHeader -> warningheader@fad (header_basic).
      fd.warningHeader(
          "Unknown calling convention -- yet parameter storage is locked");
      // Two noreturn warnings at two distinct call blocks, each at its
      // block's first-op address (the curl golden form; addCommentNoDuplicate
      // keeps both because the addresses differ).
      fd.warning("Subroutine does not return", call1->getAddr());
      fd.warning("Subroutine does not return", call2->getAddr());
      report("multi", run_protocol(fd, {bb0, bb1, bb2}));
    }
  } catch (const LowlevelError &err) {
    std::cerr << err.explain << '\n';
    return 1;
  }
  return 0;
}
