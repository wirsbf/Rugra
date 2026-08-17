// VARNODE-COPYSYMBOL-FIELDS-0001 fixture — Funcdata::opSetInput constant
// single-reader dedup branch calling Varnode::copySymbol
// (funcdata_op.cc:104-125, varnode.cc:493-505).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable behaviors pinned by this fixture (one stdout line per case):
//   locks_type        a typelock+namelock+typed constant with one consumer
//                     gets deduplicated on the second opSetInput; the fresh
//                     copy inherits the Datatype POINTER (cc:496), the
//                     typelock|namelock bits (cc:498-499) and the constant
//                     address/size (cc:111), while the source keeps its own
//                     state and its single descendant.
//   no_locks          an unlocked constant's copy carries the ctor's unknown
//                     base type (same pointer) and no lock bits.
//   mapentry_symbol   a constant carrying a SymbolEntry (equate-shaped:
//                     name-locked symbol mapped in the constant space) has
//                     that mapentry pointer copied (cc:497) — and ONLY the
//                     typelock|namelock flag bits: the copy is NOT marked
//                     mapped even though the source is.
//   identity_return   opSetInput with the varnode already in the slot returns
//                     before the dedup branch (cc:107): the input pointer
//                     stays identical and the descend list is not doubled.
//   spacebase_exempt  a spacebase-flagged constant skips the dedup branch
//                     (cc:110): both ops share the ORIGINAL varnode, which
//                     legally accumulates two descendants.
//   The high bookkeeping half of copySymbol (cc:500-504) is not driven here:
//   assignHigh only attaches a HighVariable when Funcdata::highlevel_on is
//   set (funcdata_varnode.cc:51), which this fixture never enables (see the
//   metadata coverage note).
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

static const char *metaToken(type_metatype meta) {
  switch (meta) {
  case TYPE_UNKNOWN: return "unknown";
  case TYPE_INT: return "int";
  default: return "other";
  }
}

// Print the full post-dedup state of one deduplicated consumer pair.
// op1 is the first consumer (kept the source), op2 the second (received the
// fresh copy). src is the original constant varnode.
static void printCase(const char *label, Funcdata &fd, PcodeOp *op1,
                      PcodeOp *op2, Varnode *src) {
  Varnode *cvn = op2->getIn(0);
  const Datatype *ct = cvn->getType();
  std::cout << label
            << ":op1_is_src=" << (op1->getIn(0) == src ? 1 : 0)
            << ",op2_is_src=" << (op2->getIn(0) == src ? 1 : 0)
            << ",cvn_flags=" << cvn->getFlags()
            << ",cvn_tl=" << (cvn->isTypeLock() ? 1 : 0)
            << ",cvn_nl=" << (cvn->isNameLock() ? 1 : 0)
            << ",type_same=" << (cvn->getType() == src->getType() ? 1 : 0)
            << ",type_size=" << (ct != (Datatype *)0 ? ct->getSize() : -1)
            << ",type_meta=" << (ct != (Datatype *)0 ? metaToken(ct->getMetatype()) : "null")
            << ",cvn_mapped=" << (cvn->isMapped() ? 1 : 0)
            << ",cvn_mapentry=" << (cvn->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
            << ",off=" << std::hex << cvn->getOffset() << std::dec
            << ",sz=" << cvn->getSize()
            << ",src_flags=" << src->getFlags()
            << ",src_descend=" << countDescendants(src)
            << ",cvn_descend=" << countDescendants(cvn)
            << ",src_tl=" << (src->isTypeLock() ? 1 : 0)
            << ",src_nl=" << (src->isNameLock() ? 1 : 0)
            << '\n';
}

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureTranslate trans;
  FixtureArchitecture architecture;
  AddrSpace *ram = trans.getSpace(3);
  AddrSpace *constant_space = trans.getConstantSpace();
  Datatype *int4_type = architecture.types->getBase(4, TYPE_INT);
  Scope *scope = architecture.symboltab->getGlobalScope();
  Funcdata fd("fx", "fx", scope, Address(ram, 0x1000), (FunctionSymbol *)0,
              0x20);
  int4 pc = 0x2000;

  // Two fresh single-input COPY ops per case, attached to the same source
  // constant in slot 0: the first opSetInput keeps the source (no descendant
  // yet), the second enters the dedup branch (funcdata_op.cc:108-115).
  auto makeOp = [&fd, &ram, &pc]() {
    PcodeOp *op = fd.newOp(1, Address(ram, pc));
    pc += 0x10;
    fd.opSetOpcode(op, CPUI_COPY);
    return op;
  };

  // locks_type: typelock via updateType(int4,true,false) + namelock flag.
  {
    Varnode *src = fd.newConstant(4, 0x1234);
    src->updateType(int4_type, true, false);
    src->setFlags(Varnode::namelock);
    PcodeOp *op1 = makeOp();
    PcodeOp *op2 = makeOp();
    fd.opSetInput(op1, src, 0);
    fd.opSetInput(op2, src, 0);
    printCase("locks_type", fd, op1, op2, src);
  }

  // no_locks: the constant exactly as newConstant produced it — the ctor's
  // unknown base type and no lock bits.
  {
    Varnode *src = fd.newConstant(4, 0x5a5a);
    PcodeOp *op1 = makeOp();
    PcodeOp *op2 = makeOp();
    fd.opSetInput(op1, src, 0);
    fd.opSetInput(op2, src, 0);
    printCase("no_locks", fd, op1, op2, src);
  }

  // mapentry_symbol: a name-locked Symbol mapped at the constant's own
  // address in the constant space (the shape production equates produce for
  // equate-locked constants), attached with the production
  // Varnode::setSymbolEntry plus a typelock updateType.
  {
    Varnode *src = fd.newConstant(4, 0x1234);
    SymbolEntry *entry = scope->addSymbol(
        "eq0", int4_type, Address(constant_space, 0x1234), Address());
    scope->setAttribute(entry->getSymbol(), Varnode::namelock);
    src->setSymbolEntry(entry);
    src->updateType(int4_type, true, false);
    PcodeOp *op1 = makeOp();
    PcodeOp *op2 = makeOp();
    fd.opSetInput(op1, src, 0);
    fd.opSetInput(op2, src, 0);
    printCase("mapentry_symbol", fd, op1, op2, src);
    Varnode *cvn = op2->getIn(0);
    std::cout << "mapentry_copy:sym_name="
              << cvn->getSymbolEntry()->getSymbol()->getName()
              << ",entry_offset=" << cvn->getSymbolEntry()->getOffset()
              << ",entry_same=" << (cvn->getSymbolEntry() == src->getSymbolEntry() ? 1 : 0)
              << '\n';
  }

  // identity_return: the second opSetInput with the SAME varnode and slot
  // returns at cc:107 before any dedup or descend mutation.
  {
    Varnode *src = fd.newConstant(4, 0x0d0d);
    PcodeOp *op1 = makeOp();
    fd.opSetInput(op1, src, 0);
    fd.opSetInput(op1, src, 0); // identity early-return
    std::cout << "identity_return:op1_is_src="
              << (op1->getIn(0) == src ? 1 : 0)
              << ",src_descend=" << countDescendants(src)
              << ",src_flags=" << src->getFlags() << '\n';
  }

  // spacebase_exempt: cc:110 `!vn->isSpacebase()` skips the dedup; both ops
  // share the original varnode, which accumulates two descendants.
  {
    Varnode *src = fd.newConstant(4, 0x7777);
    src->setFlags(Varnode::spacebase);
    PcodeOp *op1 = makeOp();
    PcodeOp *op2 = makeOp();
    fd.opSetInput(op1, src, 0);
    fd.opSetInput(op2, src, 0);
    std::cout << "spacebase_exempt:op1_is_src=" << (op1->getIn(0) == src ? 1 : 0)
              << ",op2_is_src=" << (op2->getIn(0) == src ? 1 : 0)
              << ",src_descend=" << countDescendants(src)
              << ",src_flags=" << src->getFlags() << '\n';
  }
  return 0;
}
