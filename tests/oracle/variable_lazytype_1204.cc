// VARIABLE-GETTYPE-LAZY-UPDATETYPE-0001 fixture — the lazy updateType()
// trigger inside HighVariable::getType (variable.hh:174) and the const
// isTypeLock re-derivation (variable.hh:222), driven on the locked oracle.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable behaviors pinned by this fixture (one stdout line per case):
//   lt_ctor_dirty_lazy_rederive
//                 A freshly constructed HighVariable is typedirty
//                 (variable.cc:224 ctor seeds flagsdirty|namerepdirty|
//                 typedirty|coverdirty with type=(Datatype*)0). The FIRST
//                 const getType() call must run updateType (variable.cc:
//                 400-416): re-derive from the typelocked int4
//                 representative, strip (no-op for a base type), refresh
//                 flags.typelock from the representative (cc:413-415). A
//                 second getType() is stable, and the const isTypeLock()
//                 reads the refreshed typelock.
//   lt_precleaned_external_settype_rederives
//                 After an explicit updateType() pre-clean (typedirty bit
//                 observable as 0), an EXTERNAL type-set on the member —
//                 Varnode::copySymbol (varnode.cc:493-504): type copy at
//                 cc:496, typelock bit copy at cc:498-499, high->typeDirty()
//                 at cc:501 — flips the raw typedirty bit to 1. The next
//                 const getType() re-derives to the copied typelocked uint4
//                 WITHOUT any explicit update call; the second is stable and
//                 const isTypeLock() reflects the copied typelock.
//   lt_instance_isolation
//                 Two HighVariables pre-cleaned side by side: dirtying one
//                 member through copySymbol leaves the other's typedirty bit
//                 clear and its const getType() type unchanged — the lazy
//                 cache and the dirty bit are per-HighVariable state.
//   lt_finalized_guard
//                 A dynamic whole-map Symbol entry (SymbolEntry dynamic ctor,
//                 database.hh:140) attached via Varnode::setSymbolEntry
//                 (varnode.cc:429-439, high->setSymbol sets symboloffset=-1
//                 for a dynamic entry, variable.cc:261-262), then
//                 finalizeDatatype (variable.cc:551-566) locks the symbol's
//                 int4 (whole-match getExactPiece) and sets type_finalized
//                 (cc:565). A subsequent manual typeDirty() sets the raw bit,
//                 but the next const getType() keeps the finalized int4 —
//                 updateType clears the bit FIRST and then returns early on
//                 type_finalized (variable.cc:405-407), so the representative
//                 (typelocked uint4) must NOT leak through.
//
// Observations per case (single line, pipe-separated; cases print the field
// set they exercise):
//   lt_ctor_dirty_lazy_rederive:
//     case|dirty_ctor|meta1|meta2|tl|hsym|hoff
//   lt_precleaned_external_settype_rederives:
//     case|dirty_pre|dirty_post|meta_pre|meta1|meta2|tl|hsym|hoff
//   lt_instance_isolation:
//     case|dirtyA_pre|dirtyB_pre|dirtyA_post|dirtyB_post|metaA|metaB
//   lt_finalized_guard:
//     case|dirty_pre|hsym|hoff|dirty_manual|meta1|meta2|tl
#include <bits/stdc++.h>

// Test-only access is required to drive HighVariable::updateType/typeDirty
// and read the typedirty highflags bit directly (variable.hh:132+ private
// section), matching the varnode_highbranch_1204 fixture harness.
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
#include "variable.hh"
#include "varnode.hh"
#undef private

#include "ruleaction.hh"

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

static const char *metaToken(type_metatype meta) {
  switch (meta) {
  case TYPE_UNKNOWN: return "unknown";
  case TYPE_INT: return "int";
  case TYPE_UINT: return "uint";
  default: return "other";
  }
}

static int4 dirtyBit(HighVariable *high) {
  return (high->highflags & HighVariable::typedirty) ? 1 : 0;
}

// A fresh constant destination with an auto-attached HighVariable
// (setHighLevel, funcdata_varnode.cc:48-59 via 66-73) whose single member is
// typelocked to `ct` through Varnode::updateType (varnode.cc:474-489).
static Varnode *makeLockedDst(Funcdata &fd, Datatype *ct, uintb val) {
  Varnode *dst = fd.newConstant(4, val);
  dst->updateType(ct, true, false);
  return dst;
}

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureTranslate trans;
  FixtureArchitecture architecture;
  AddrSpace *ram = trans.getSpace(3);
  Datatype *int4_type = architecture.types->getBase(4, TYPE_INT);
  Datatype *uint4_type = architecture.types->getBase(4, TYPE_UINT);
  Scope *scope = architecture.symboltab->getGlobalScope();
  Funcdata fd("fx", "fx", scope, Address(ram, 0x1000), (FunctionSymbol *)0,
              0x20);
  fd.setHighLevel();

  // lt_ctor_dirty_lazy_rederive: the ctor-seeded typedirty bit is visible,
  // and the first const getType() re-derives int from the typelocked
  // representative through variable.cc:400-416.
  {
    Varnode *dst = makeLockedDst(fd, int4_type, 0x11111111);
    HighVariable *high = dst->high;
    int4 dirty_ctor = dirtyBit(high);
    const char *meta1 = metaToken(high->getType()->getMetatype());
    const char *meta2 = metaToken(high->getType()->getMetatype());
    int4 tl = high->isTypeLock() ? 1 : 0;
    std::cout << "case=lt_ctor_dirty_lazy_rederive"
              << "|dirty_ctor=" << dirty_ctor
              << "|meta1=" << meta1
              << "|meta2=" << meta2
              << "|tl=" << tl
              << "|hsym=none|hoff=-99" << '\n';
  }

  // lt_precleaned_external_settype_rederives: pre-clean via explicit
  // updateType, then an external type-set through Varnode::copySymbol
  // (cc:496 type copy + cc:501 typeDirty) flips the bit; the next const
  // getType() lazily re-derives uint.
  {
    Varnode *src = fd.newConstant(4, 0x22222222);
    src->updateType(uint4_type, true, false);
    Varnode *dst = makeLockedDst(fd, int4_type, 0x22222222);
    HighVariable *high = dst->high;
    high->updateType(); // pre-clean the typedirty cache bit
    int4 dirty_pre = dirtyBit(high);
    const char *meta_pre = metaToken(high->getType()->getMetatype());
    dst->copySymbol(src);
    int4 dirty_post = dirtyBit(high);
    const char *meta1 = metaToken(high->getType()->getMetatype());
    const char *meta2 = metaToken(high->getType()->getMetatype());
    int4 tl = high->isTypeLock() ? 1 : 0;
    std::cout << "case=lt_precleaned_external_settype_rederives"
              << "|dirty_pre=" << dirty_pre
              << "|dirty_post=" << dirty_post
              << "|meta_pre=" << meta_pre
              << "|meta1=" << meta1
              << "|meta2=" << meta2
              << "|tl=" << tl
              << "|hsym=none|hoff=-99" << '\n';
  }

  // lt_instance_isolation: dirtying member A leaves high B's bit clear and
  // its const getType() type unchanged.
  {
    Varnode *src = fd.newConstant(4, 0x33333333);
    src->updateType(uint4_type, true, false);
    Varnode *dstA = makeLockedDst(fd, int4_type, 0x33333333);
    Varnode *dstB = makeLockedDst(fd, int4_type, 0x44444444);
    HighVariable *highA = dstA->high;
    HighVariable *highB = dstB->high;
    highA->updateType(); // pre-clean both
    highB->updateType();
    int4 dirtyA_pre = dirtyBit(highA);
    int4 dirtyB_pre = dirtyBit(highB);
    dstA->copySymbol(src);
    int4 dirtyA_post = dirtyBit(highA);
    int4 dirtyB_post = dirtyBit(highB);
    const char *metaA = metaToken(highA->getType()->getMetatype());
    const char *metaB = metaToken(highB->getType()->getMetatype());
    std::cout << "case=lt_instance_isolation"
              << "|dirtyA_pre=" << dirtyA_pre
              << "|dirtyB_pre=" << dirtyB_pre
              << "|dirtyA_post=" << dirtyA_post
              << "|dirtyB_post=" << dirtyB_post
              << "|metaA=" << metaA
              << "|metaB=" << metaB << '\n';
  }

  // lt_finalized_guard: finalizeDatatype locks the symbol's int4; a manual
  // typeDirty then must NOT leak the uint4 representative through the const
  // getType() (variable.cc:405-407 finalized short-circuit).
  {
    Varnode *dst = makeLockedDst(fd, uint4_type, 0x55555555);
    HighVariable *high = dst->high;
    high->updateType(); // pre-clean
    int4 dirty_pre = dirtyBit(high);
    Symbol *sym = new Symbol(scope, "FIXTURE_TY", int4_type);
    RangeList rnglist;
    SymbolEntry *entry =
        new SymbolEntry(sym, Varnode::mapped, 0x1234, 0, 4, rnglist);
    dst->setSymbolEntry(entry); // high->setSymbol -> symboloffset -1 (dynamic)
    high->finalizeDatatype(architecture.types);
    const char *hsym = high->getSymbol()->getName().c_str();
    int4 hoff = high->getSymbolOffset();
    high->typeDirty();
    int4 dirty_manual = dirtyBit(high);
    const char *meta1 = metaToken(high->getType()->getMetatype());
    const char *meta2 = metaToken(high->getType()->getMetatype());
    int4 tl = high->isTypeLock() ? 1 : 0;
    std::cout << "case=lt_finalized_guard"
              << "|dirty_pre=" << dirty_pre
              << "|hsym=" << hsym
              << "|hoff=" << hoff
              << "|dirty_manual=" << dirty_manual
              << "|meta1=" << meta1
              << "|meta2=" << meta2
              << "|tl=" << tl << '\n';
  }
  return 0;
}
