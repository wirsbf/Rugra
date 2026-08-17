// VARNODE-ADDDESCEND-THROW-0001 fixture — Varnode::addDescend (varnode.cc:330-340).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable behaviors pinned by this fixture (one stdout line per case):
//   free_first          free non-spacebase varnode accepts its FIRST
//                       descendant; coverdirty flag state observable.
//   free_second_throw   the SECOND descendant on a free non-spacebase
//                       varnode throws LowlevelError("Free varnode has
//                       multiple descendants") verbatim (varnode.cc:336);
//                       the throw fires BEFORE push_back/setFlags, so the
//                       descend list length and flags are unchanged.
//   spacebase_exempt    a free varnode flagged spacebase accepts multiple
//                       descendants (varnode.cc:334 `!isSpacebase()` guard).
//   written_accumulate  a WRITTEN varnode (createDef) accumulates multiple
//                       descendants without throwing.
//   input_accumulate    an INPUT varnode (setInput) accumulates multiple
//                       descendants without throwing.
//   const_second_throw  a CONSTANT varnode is free by the isFree() test
//                       (varnode.hh:238 checks written|input only) and gets
//                       NO exemption in addDescend — only Funcdata::opSetInput
//                       (funcdata_op.cc:108-115) dedups constants upstream, so
//                       a second addDescend throws here too.
//   order               descendants accumulate in push order (std::list
//                       push_back; varnode.cc:338), observed via beginDescend
//                       iteration order of the ops' sequence order values.
#include <bits/stdc++.h>

// Test-only access is required to construct the same valid def-use graph that
// production Ghidra builds through the friend-only Funcdata/VarnodeBank APIs.
#define private public
#include "architecture.hh"
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

static size_t countDescendants(const Varnode *vn) {
  return static_cast<size_t>(std::distance(vn->beginDescend(), vn->endDescend()));
}

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureTranslate trans;
  FixtureArchitecture architecture;
  Datatype *unknown8 = architecture.types->getBase(8, TYPE_UNKNOWN);
  Datatype *unknown4 = architecture.types->getBase(4, TYPE_UNKNOWN);
  VarnodeBank bank(&trans);

  PcodeOp op1(0, SeqNum(Address(trans.getSpace(3), 0x1000), 1));
  PcodeOp op2(0, SeqNum(Address(trans.getSpace(3), 0x1010), 2));

  // free_first + free_second_throw: free register-space varnode, one legal
  // first descendant, then the illegal second (varnode.cc:333-339).
  Varnode *free_vn = bank.create(
      8, Address(trans.getSpace(4), 0x80), unknown8);
  free_vn->addDescend(&op1);
  std::cout << "free_first:count=" << countDescendants(free_vn)
            << ",flags=" << free_vn->getFlags() << '\n';
  std::string free_error;
  try { free_vn->addDescend(&op2); }
  catch (const LowlevelError &err) { free_error = err.explain; }
  std::cout << "free_second_throw:error=" << free_error
            << ",count=" << countDescendants(free_vn)
            << ",flags=" << free_vn->getFlags() << '\n';

  // spacebase_exempt: free varnode flagged spacebase bypasses the guard
  // (varnode.cc:334 `isFree()&&(!isSpacebase())`).
  Varnode *spacebase_vn = bank.create(
      8, Address(trans.getSpace(4), 0x88), unknown8);
  spacebase_vn->setFlags(Varnode::spacebase);
  spacebase_vn->addDescend(&op1);
  spacebase_vn->addDescend(&op2);
  std::cout << "spacebase_exempt:count=" << countDescendants(spacebase_vn)
            << ",flags=" << spacebase_vn->getFlags() << '\n';

  // written_accumulate: createDef marks written|insert|coverdirty; multiple
  // descendants legal.
  PcodeOp defop(0, SeqNum(Address(trans.getSpace(3), 0x1020), 3));
  Varnode *written_vn = bank.createDef(
      8, Address(trans.getSpace(4), 0x90), unknown8, &defop);
  written_vn->addDescend(&op1);
  written_vn->addDescend(&op2);
  std::cout << "written_accumulate:count=" << countDescendants(written_vn)
            << ",flags=" << written_vn->getFlags() << '\n';

  // input_accumulate: setInput marks input|insert; multiple descendants legal.
  Varnode *input_vn = bank.create(
      8, Address(trans.getSpace(4), 0x98), unknown8);
  input_vn = bank.setInput(input_vn);
  input_vn->addDescend(&op1);
  input_vn->addDescend(&op2);
  std::cout << "input_accumulate:count=" << countDescendants(input_vn)
            << ",flags=" << input_vn->getFlags() << '\n';

  // const_second_throw: constants are free by the isFree() test and get no
  // addDescend exemption; opSetInput-level dedup is what protects them in
  // production.
  Varnode *const_vn = bank.create(
      4, Address(trans.getConstantSpace(), 0x1234), unknown4);
  const_vn->addDescend(&op1);
  std::string const_error;
  try { const_vn->addDescend(&op2); }
  catch (const LowlevelError &err) { const_error = err.explain; }
  std::cout << "const_second_throw:error=" << const_error
            << ",count=" << countDescendants(const_vn)
            << ",flags=" << const_vn->getFlags() << '\n';

  // order: descend iteration preserves push order (std::list push_back).
  // getTime() is the immutable SeqNum identity (address.hh:139); the 2-arg
  // SeqNum ctor leaves `order` uninitialized, so it is not observable here.
  std::cout << "order:written=";
  for (auto iter = written_vn->beginDescend();
       iter != written_vn->endDescend(); ++iter)
    std::cout << (*iter)->getSeqNum().getTime() << ',';
  std::cout << '\n';
  return 0;
}
