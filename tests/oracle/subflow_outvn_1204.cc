/*
 * SUBFLOW-OUTVN-UNWRAP-0001: locked Ghidra 12.0.4
 * SubvariableFlow::traceForwardSext / traceForward createLink outvn oracle.
 *
 * The fixture builds small sub-variable data-flows through the production
 * Funcdata APIs and runs the production SubvariableFlow analysis that
 * RuleSubvarSext::applyOp (subflow.cc:1729-1740) and the subvar rules drive.
 *
 * Some-precondition cases (the traced reader op has an output) run the full
 * doTrace/doReplacement pair and dump the surviving op layout; both sides
 * must agree byte-for-byte.
 *
 * None-precondition cases (the traced reader op lost its output through the
 * production Funcdata::opUnsetOutput path while remaining alive and wired as
 * a reader) observe the pre-trace state only.  The locked oracle cannot run
 * doTrace on that state: traceForwardSext's COPY/MULTIEQUAL/INT_* case
 * (subflow.cc:894-895) passes the null outvn pointer straight into
 * createLink, which dereferences it in setReplacement (subflow.cc:70
 * vn->isMark()).  The Rugra comparand converts that impossible input into
 * the case's failure path (abort the trace) and enforces it with internal
 * assertions instead of printed lines, so the shared stdout stays
 * byte-comparable.
 */

#include <bits/stdc++.h>

// Test-only access is required to read SubvariableFlow::pullcount and
// PcodeOp internals, matching what production Ghidra reaches through
// friend-only APIs.
#define private public
#include "subflow.hh"
#include "architecture.hh"
#include "cover.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef private

using namespace ghidra;

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
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1, 6,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
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

  void printMessage(const std::string &) const override {}
};

class Graph {
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  std::map<PcodeOp *, std::string> opNames;
  std::vector<BlockBasic *> blockIndices;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const std::string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), nextOffset(0) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    block->index = static_cast<int4>(blockIndices.size());
    blockIndices.push_back(block);
    return block;
  }

  PcodeOp *makeOp(const std::string &name, OpCode opcode, int4 inputs)
  {
    Address pc(ram, fd.getAddress().getOffset() + (uintb)nextOffset);
    nextOffset += 1;
    PcodeOp *op = fd.newOp(inputs, pc);
    fd.opSetOpcode(op, opcode);
    opNames.insert(std::make_pair(op, name));
    return op;
  }

  Varnode *uniqueOut(int4 size, PcodeOp *op)
  {
    return fd.newUniqueOut(size, op);
  }

  Varnode *constant(int4 size, uintb value)
  {
    return fd.newConstant(size, value);
  }

  Varnode *input(const std::string &, uintb offset, int4 size)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    return fd.setInputVarnode(vn);
  }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot)
  {
    fd.opSetInput(op, vn, slot);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block)
  {
    fd.opInsertEnd(op, block);
  }

  static std::string opcodeName(OpCode code)
  {
    switch (code) {
    case CPUI_COPY: return "COPY";
    case CPUI_MULTIEQUAL: return "MULTIEQUAL";
    case CPUI_INT_NEGATE: return "INT_NEGATE";
    case CPUI_INT_XOR: return "INT_XOR";
    case CPUI_INT_OR: return "INT_OR";
    case CPUI_INT_AND: return "INT_AND";
    case CPUI_INT_SEXT: return "INT_SEXT";
    case CPUI_INT_ZEXT: return "INT_ZEXT";
    case CPUI_SUBPIECE: return "SUBPIECE";
    default: return "OTHER";
    }
  }

  static std::string vnText(Varnode *vn)
  {
    if (vn == (Varnode *)0)
      return "null";
    std::ostringstream out;
    if (vn->isConstant())
      out << "c" << vn->getOffset();
    else if (vn->getSpace()->getName() == "unique")
      out << "u";
    else
      out << vn->getSpace()->getName() << vn->getOffset();
    out << ":" << vn->getSize();
    return out.str();
  }

  std::string opsText(void)
  {
    std::ostringstream out;
    out << '[';
    bool first = true;
    for (uint4 b = 0; b < blockIndices.size(); ++b) {
      BlockBasic *block = blockIndices[b];
      for (list<PcodeOp *>::const_iterator iter = block->beginOp();
           iter != block->endOp(); ++iter) {
        PcodeOp *op = *iter;
        if (!first) out << ',';
        first = false;
        std::map<PcodeOp *, std::string>::const_iterator name = opNames.find(op);
        if (name != opNames.end())
          out << name->second << '=';
        else
          out << "new_" << opcodeName(op->code()) << '=';
        out << opcodeName(op->code()) << '(';
        for (int4 i = 0; i < op->numInput(); ++i) {
          if (i != 0) out << ' ';
          out << vnText(op->getIn(i));
        }
        out << ")->" << vnText(op->getOut());
      }
    }
    out << ']';
    return out.str();
  }

  std::string descText(Varnode *root)
  {
    std::ostringstream desc;
    desc << '[';
    bool first = true;
    for (list<PcodeOp *>::const_iterator iter = root->beginDescend();
         iter != root->endDescend(); ++iter) {
      if (!first) desc << ',';
      first = false;
      std::map<PcodeOp *, std::string>::const_iterator name = opNames.find(*iter);
      desc << (name != opNames.end() ? name->second : std::string("new"));
    }
    desc << ']';
    return desc.str();
  }
};

// One sext-mode Some-precondition case: the RuleSubvarSext entry shape.
//   in1 (1-byte input) --SEXT--> out4 --[target]--> tout4
//   tout4 --SUBPIECE(0)--> pul1 --COPY--> use1
// The target op exercises the merged COPY/MULTIEQUAL/INT_{NEGATE,XOR,OR,AND}
// case of SubvariableFlow::traceForwardSext (subflow.cc:888-897).
static void runSextSome(FixtureArchitecture &arch, const std::string &caseName,
                        OpCode targetCode)
{
  Graph g(arch, caseName, 0x6000);
  BlockBasic *b0 = g.makeBlock();
  Varnode *in1 = g.input("in1", 0x28, 1);
  PcodeOp *sextop = g.makeOp("sext", CPUI_INT_SEXT, 1);
  g.setInput(sextop, in1, 0);
  Varnode *out4 = g.uniqueOut(4, sextop);
  g.insertEnd(sextop, b0);

  int4 targetInputs = (targetCode == CPUI_COPY || targetCode == CPUI_INT_NEGATE) ? 1
    : (targetCode == CPUI_MULTIEQUAL ? 2 : 2);
  PcodeOp *top = g.makeOp("t", targetCode, targetInputs);
  g.setInput(top, out4, 0);
  if (targetCode == CPUI_MULTIEQUAL)
    g.setInput(top, out4, 1);
  else if (targetInputs == 2)
    // 0xffffff80 passes setReplacement's sign-extension check (subflow.cc:82-88)
    // while exercising the binary input createLink path in sext mode.
    g.setInput(top, g.constant(4, 0xffffff80), 1);
  Varnode *tout4 = g.uniqueOut(4, top);
  g.insertEnd(top, b0);

  PcodeOp *sub = g.makeOp("sub", CPUI_SUBPIECE, 2);
  g.setInput(sub, tout4, 0);
  g.setInput(sub, g.constant(8, 0), 1);
  Varnode *pul1 = g.uniqueOut(1, sub);
  g.insertEnd(sub, b0);

  PcodeOp *use = g.makeOp("use", CPUI_COPY, 1);
  g.setInput(use, pul1, 0);
  g.uniqueOut(1, use);
  g.insertEnd(use, b0);

  // RuleSubvarSext::applyOp (subflow.cc:1729-1740) entry:
  //   SubvariableFlow(&data, op->getOut(), calc_mask(invn size),
  //                   isaggressive=false, sext=true, big=false)
  SubvariableFlow subflow(&g.fd, out4, calc_mask(in1->getSize()), false, true, false);
  bool traced = subflow.doTrace();
  if (traced)
    subflow.doReplacement();
  std::cout << "case=" << caseName
            << "|traced=" << (traced ? 1 : 0)
            << "|ops=" << g.opsText() << '\n';
}

// One sext-mode None-precondition case: identical graph, but the target op
// lost its output through the production Funcdata::opUnsetOutput path
// (funcdata_op.cc:52-66) and remains alive and wired as a reader of out4.
// The locked oracle cannot run doTrace on this state: the merged case passes
// the null outvn into createLink (subflow.cc:895) whose setReplacement
// dereferences it (subflow.cc:70).  Only the pre-trace state is observed.
static void runSextNone(FixtureArchitecture &arch, const std::string &caseName,
                        OpCode targetCode)
{
  Graph g(arch, caseName, 0x6100);
  BlockBasic *b0 = g.makeBlock();
  Varnode *in1 = g.input("in1", 0x28, 1);
  PcodeOp *sextop = g.makeOp("sext", CPUI_INT_SEXT, 1);
  g.setInput(sextop, in1, 0);
  Varnode *out4 = g.uniqueOut(4, sextop);
  g.insertEnd(sextop, b0);

  int4 targetInputs = (targetCode == CPUI_COPY || targetCode == CPUI_INT_NEGATE) ? 1
    : (targetCode == CPUI_MULTIEQUAL ? 2 : 2);
  PcodeOp *top = g.makeOp("t", targetCode, targetInputs);
  g.setInput(top, out4, 0);
  if (targetCode == CPUI_MULTIEQUAL)
    g.setInput(top, out4, 1);
  else if (targetInputs == 2)
    // 0xffffff80 passes setReplacement's sign-extension check (subflow.cc:82-88)
    // while exercising the binary input createLink path in sext mode.
    g.setInput(top, g.constant(4, 0xffffff80), 1);
  Varnode *tout4 = g.uniqueOut(4, top);
  g.insertEnd(top, b0);

  PcodeOp *sub = g.makeOp("sub", CPUI_SUBPIECE, 2);
  g.setInput(sub, tout4, 0);
  g.setInput(sub, g.constant(8, 0), 1);
  Varnode *pul1 = g.uniqueOut(1, sub);
  g.insertEnd(sub, b0);

  PcodeOp *use = g.makeOp("use", CPUI_COPY, 1);
  g.setInput(use, pul1, 0);
  g.uniqueOut(1, use);
  g.insertEnd(use, b0);

  g.fd.opUnsetOutput(top);

  std::cout << "case=" << caseName
            << "|t_out_null=" << (top->getOut() == (Varnode *)0 ? 1 : 0)
            << "|t_alive=" << (top->getParent() != (BlockBasic *)0 ? 1 : 0)
            << "|tout4_written=" << (tout4->isWritten() ? 1 : 0)
            << "|root_desc=" << g.descText(out4)
            << "|oracle_run=0|oracle_reason=traceForwardSext_null_outvn_deref_subflow_cc_895_to_70"
            << '\n';
}

// One plain-mode Some-precondition case: the non-sext tracer
// (SubvariableFlow::traceForward, subflow.cc:373-658) reached from the
// subvar rules with aggressive=true (RuleSubvarAnd shape after its guards).
static void runPlainSome(FixtureArchitecture &arch, const std::string &caseName,
                         OpCode targetCode)
{
  Graph g(arch, caseName, 0x6200);
  BlockBasic *b0 = g.makeBlock();
  Varnode *root = g.input("root", 0x30, 4);

  int4 targetInputs = (targetCode == CPUI_COPY) ? 1 : 2;
  PcodeOp *top = g.makeOp("t", targetCode, targetInputs);
  g.setInput(top, root, 0);
  if (targetInputs == 2) {
    // INT_OR: 0x100 keeps doesOrSet at -1 (mask&~orval != 0).
    // INT_AND: 0xff keeps doesAndClear at -1 (mask&andval != 0).
    uintb value = (targetCode == CPUI_INT_OR) ? 0x100 : 0xff;
    g.setInput(top, g.constant(4, value), 1);
  }
  Varnode *tout4 = g.uniqueOut(4, top);
  g.insertEnd(top, b0);

  PcodeOp *sub = g.makeOp("sub", CPUI_SUBPIECE, 2);
  g.setInput(sub, tout4, 0);
  g.setInput(sub, g.constant(8, 0), 1);
  Varnode *pul1 = g.uniqueOut(1, sub);
  g.insertEnd(sub, b0);

  PcodeOp *use = g.makeOp("use", CPUI_COPY, 1);
  g.setInput(use, pul1, 0);
  g.uniqueOut(1, use);
  g.insertEnd(use, b0);

  SubvariableFlow subflow(&g.fd, root, 0xff, true, false, false);
  bool traced = subflow.doTrace();
  if (traced)
    subflow.doReplacement();
  std::cout << "case=" << caseName
            << "|traced=" << (traced ? 1 : 0)
            << "|ops=" << g.opsText() << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=SUBFLOW-OUTVN-UNWRAP-0001|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b" << '\n';
  try {
    FixtureArchitecture arch;
    runSextSome(arch, "sext_some_copy", CPUI_COPY);
    runSextSome(arch, "sext_some_multiequal", CPUI_MULTIEQUAL);
    runSextSome(arch, "sext_some_int_negate", CPUI_INT_NEGATE);
    runSextSome(arch, "sext_some_int_xor", CPUI_INT_XOR);
    runSextSome(arch, "sext_some_int_or", CPUI_INT_OR);
    runSextSome(arch, "sext_some_int_and", CPUI_INT_AND);
    runSextNone(arch, "sext_none_copy", CPUI_COPY);
    runSextNone(arch, "sext_none_multiequal", CPUI_MULTIEQUAL);
    runSextNone(arch, "sext_none_int_negate", CPUI_INT_NEGATE);
    runSextNone(arch, "sext_none_int_xor", CPUI_INT_XOR);
    runSextNone(arch, "sext_none_int_or", CPUI_INT_OR);
    runSextNone(arch, "sext_none_int_and", CPUI_INT_AND);
    runPlainSome(arch, "plain_some_copy", CPUI_COPY);
    runPlainSome(arch, "plain_some_int_or", CPUI_INT_OR);
    runPlainSome(arch, "plain_some_int_and", CPUI_INT_AND);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
