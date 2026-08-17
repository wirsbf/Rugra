// VARNODE-ADDDESCEND-THROW-0001 (op_insert_input 收编子项) fixture —
// Funcdata::opInsertInput (funcdata_op.cc:308-317).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// opInsertInput = PcodeOp::insertInput(slot) (op.cc:311-318: push NULL slot,
// shift inputs at/after slot up) followed by the FULL Funcdata::opSetInput
// (funcdata_op.cc:104-125) — never a raw descend push. Observable behaviors
// pinned by this fixture (one stdout line per case):
//   shift             inserting at slot 0 pushes the existing input to slot 1
//                     (final slot order + per-varnode descend count preserved
//                     by the shift + coverdirty set on the inserted constant
//                     via opSetInput->addDescend varnode.cc:339).
//   middle            append-at-len then middle insert produce [a,c,b]; the
//                     shifted Varnode b keeps exactly one descend entry (the
//                     descend list stores the op pointer, not the slot).
//   same_vn           inserting the same INPUT Varnode into two slots of one
//                     op adds TWO descend entries (cc:107 compares against the
//                     fresh NULL slot only, so the early-return never fires on
//                     the second insert).
//   const_dedup       a CONSTANT Varnode that already has a live descendant is
//                     CLONED by opSetInput cc:108-115 (constants have one
//                     descendant); the clone lands in the bank (numVarnodes
//                     +1) and the original keeps descend==1.
//   free_first        a free (not written|input) register Varnode accepts its
//                     FIRST opInsertInput (addDescend free guard passes on an
//                     empty descend list).
//   free_second_throw the SECOND opInsertInput of the same free Varnode
//                     throws LowlevelError("Free varnode has multiple
//                     descendants") from addDescend (varnode.cc:336) INSIDE
//                     opSetInput; the throw fires before push_back/setFlags,
//                     so descend count and flags are unchanged.
//
// All ops are built with newOp(0) and populated purely through
// opInsertInput so C++ and Rust agree slot-for-slot (Rugra's Vec cannot
// represent Ghidra's newOp(N) nullable preallocated slots — declared
// representation gap, see op_insert_1204 metadata).
//
// Declared divergence (production-unobservable): after the caught throw the
// abandoned op's slot count differs (C++ keeps the insertInput-expanded NULL
// slot; Rust's split-tail representation never materialized it). Production
// aborts the whole function on LowlevelError, so that state is never read;
// the fixture observes only the throwing Varnode's state, which matches.
#include <bits/stdc++.h>

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
    dummy_register.space = reg;
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

size_t countDescendants(const Varnode *vn) {
  return static_cast<size_t>(std::distance(vn->beginDescend(), vn->endDescend()));
}

}  // namespace

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  try {
    FixtureTranslate trans;
    FixtureArchitecture architecture;
    AddrSpace *ram = trans.getSpace(3);
    AddrSpace *reg = trans.getSpace(4);
    Funcdata fd("insert_input", "insert_input",
                architecture.symboltab->getGlobalScope(),
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x20);

    // shift: [reg] -> insert zero-const at 0 -> [zero, reg].
    PcodeOp *sub = fd.newOp(0, Address(ram, 0x5010));
    fd.opSetOpcode(sub, CPUI_INT_SUB);
    Varnode *reg_vn = fd.newVarnode(8, reg, 0x4444);
    fd.opInsertInput(sub, reg_vn, 0);
    Varnode *zero_vn = fd.newConstant(8, 0);
    fd.opInsertInput(sub, zero_vn, 0);
    std::cout << "shift:numInput=" << sub->numInput()
              << ",in0=" << std::hex << sub->getIn(0)->getOffset()
              << ",in1=" << sub->getIn(1)->getOffset() << std::dec
              << ",regdesc=" << countDescendants(reg_vn)
              << ",zeroflags=" << zero_vn->getFlags() << '\n';

    // middle: [a] -> append b at len -> [a,b] -> insert c at 1 -> [a,c,b].
    PcodeOp *add = fd.newOp(0, Address(ram, 0x5020));
    fd.opSetOpcode(add, CPUI_INT_ADD);
    Varnode *a_vn = fd.newVarnode(8, reg, 0x1110);
    Varnode *b_vn = fd.newVarnode(8, reg, 0x1118);
    fd.opInsertInput(add, a_vn, 0);
    fd.opInsertInput(add, b_vn, 1);
    Varnode *c_vn = fd.newConstant(8, 0x2222);
    fd.opInsertInput(add, c_vn, 1);
    std::cout << "middle:numInput=" << add->numInput()
              << ",in0=" << std::hex << add->getIn(0)->getOffset()
              << ",in1=" << add->getIn(1)->getOffset()
              << ",in2=" << add->getIn(2)->getOffset() << std::dec
              << ",bdesc=" << countDescendants(b_vn) << '\n';

    // same_vn: input Varnode in two slots of one op -> two descend entries.
    PcodeOp *twice = fd.newOp(0, Address(ram, 0x5030));
    fd.opSetOpcode(twice, CPUI_INT_ADD);
    Varnode *iv = fd.newVarnode(8, reg, 0x2300);
    iv = fd.setInputVarnode(iv);
    fd.opInsertInput(twice, iv, 0);
    fd.opInsertInput(twice, iv, 1);
    std::cout << "same_vn:numInput=" << twice->numInput()
              << ",slot0_same=" << (twice->getIn(0) == iv)
              << ",slot1_same=" << (twice->getIn(1) == iv)
              << ",desc=" << countDescendants(iv) << '\n';

    // const_dedup: shared constant cloned on the second insert (cc:108-115).
    PcodeOp *k1 = fd.newOp(0, Address(ram, 0x5040));
    fd.opSetOpcode(k1, CPUI_COPY);
    PcodeOp *k2 = fd.newOp(0, Address(ram, 0x5041));
    fd.opSetOpcode(k2, CPUI_COPY);
    Varnode *k_vn = fd.newConstant(4, 0x33);
    fd.opInsertInput(k1, k_vn, 0);
    int4 before = fd.numVarnodes();
    fd.opInsertInput(k2, k_vn, 0);
    int4 after = fd.numVarnodes();
    std::cout << "const_dedup:distinct=" << (k2->getIn(0) != k_vn)
              << ",offset=" << std::hex << k2->getIn(0)->getOffset() << std::dec
              << ",origdesc=" << countDescendants(k_vn)
              << ",clonedesc=" << countDescendants(k2->getIn(0))
              << ",vndelta=" << (after - before) << '\n';

    // free_first + free_second_throw: free Varnode's second insert throws
    // from opSetInput->addDescend (varnode.cc:333-339) before push/flags.
    PcodeOp *f1 = fd.newOp(0, Address(ram, 0x5050));
    fd.opSetOpcode(f1, CPUI_COPY);
    PcodeOp *f2 = fd.newOp(0, Address(ram, 0x5051));
    fd.opSetOpcode(f2, CPUI_COPY);
    Varnode *free_vn = fd.newVarnode(8, reg, 0x2200);
    fd.opInsertInput(f1, free_vn, 0);
    std::cout << "free_first:desc=" << countDescendants(free_vn)
              << ",flags=" << free_vn->getFlags() << '\n';
    std::string free_error;
    try { fd.opInsertInput(f2, free_vn, 0); }
    catch (const LowlevelError &err) { free_error = err.explain; }
    std::cout << "free_second_throw:error=" << free_error
              << ",desc=" << countDescendants(free_vn)
              << ",flags=" << free_vn->getFlags() << '\n';
  }
  catch (const LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
