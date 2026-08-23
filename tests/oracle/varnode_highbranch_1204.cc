// VARNODE-COPYSYMBOL-HIGHBRANCH-0001 fixture — the high!=0 bookkeeping half
// of Varnode::copySymbol (varnode.cc:500-504) and its wiring through
// Varnode::copySymbolIfValid (varnode.cc:510-522) +
// PcodeOp::collapseConstantSymbol (op.cc:503-540).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable behaviors pinned by this fixture (one stdout line per case):
//   hb_close_propagates_high      copySymbolIfValid accepting a close equate
//                                 propagates the markup AND, because the
//                                 destination carries a HighVariable
//                                 (setHighLevel is on, funcdata_varnode.cc:
//                                 48-59/66-73), runs the full cc:500-504
//                                 bookkeeping: high->typeDirty() flips the
//                                 typedirty bit on a pre-cleaned cache,
//                                 high->setSymbol(this) attaches the copied
//                                 mapentry's Symbol (dynamic equate entry ->
//                                 symboloffset -1, variable.cc:261-262), and
//                                 the lazy updateType re-derivation both
//                                 flips isTypeLock and re-reads the copied
//                                 int type (variable.cc:400-416).
//   hb_not_close_no_high_effects  the cc:519 isValueClose rejection leaves
//                                 the pre-cleaned high untouched: typedirty
//                                 stays clear, no Symbol attaches, no lock
//                                 bits or mapentry move onto the
//                                 destination.
//   hb_copy_null_mapentry_dirty   a direct copySymbol from a typelocked
//                                 source WITHOUT a SymbolEntry: cc:501
//                                 typeDirty still fires but the cc:502
//                                 mapentry guard blocks setSymbol.
//   hb_dst_no_high                a destination created with highlevel
//                                 disabled (fresh Funcdata, no setHighLevel)
//                                 takes the field copy (cc:496-499) with the
//                                 cc:500 outer guard skipping all high
//                                 bookkeeping — no crash, high stays null.
//   hb_op_level_marked_input      the RuleCollapseConstants integration
//                                 (ruleaction.cc:3854-3882) ->
//                                 collapseConstantSymbol (op.cc:503-540) ->
//                                 copySymbolIfValid chain on an INT_ADD whose
//                                 input 0 is equate-marked: the collapsed
//                                 constant (now op input 0) carries the
//                                 markup AND an attached high Symbol.
//
// Observations per case (single line, pipe-separated):
//   hb_*: case|has_high|dirty_before|tl_before|hmeta_before|dirty_after|
//         tl_after|hmeta_after|hsym|hoff|dst_tl|dst_nl|dst_mapentry
//   (hsym prints the Symbol name or "none"; cases that do not apply print
//   the same field set with the values they observe.)
#include <bits/stdc++.h>

// Test-only access is required to drive HighVariable::updateType and read
// the typedirty highflags bit directly (variable.hh:132+ private section),
// matching the varnode_copy_symbol_1204 fixture harness.
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
  default: return "other";
  }
}

// A typelocked equate-marked source constant: the equate is created through
// the public Scope::addEquateSymbol (database.cc:1712-1724, a dynamic
// size-1 whole map) and attached with Varnode::setSymbolEntry
// (varnode.cc:429), then the type is typelocked to int4 through
// Varnode::updateType (varnode.cc:474-489).
static Varnode *makeEquateSrc(Funcdata &fd, Scope *scope, Datatype *int4_type,
                              uintb val) {
  Varnode *src = fd.newConstant(4, val);
  Symbol *sym = scope->addEquateSymbol("FIXTURE_EQ", 0, val, Address(), 0);
  src->setSymbolEntry(sym->getFirstWholeMap());
  src->updateType(int4_type, true, false);
  return src;
}

// Print the full post-copy state of one destination varnode + its high.
// pre_clean runs updateType() on the destination's high so the typedirty
// bit starts clear (the discriminating precondition for cc:501).
static void printCase(const char *label, Varnode *dst, Varnode *src,
                      void (*op)(Varnode *, Varnode *)) {
  // Varnode::getHigh throws when high==0 (varnode.cc); read the field so
  // the no-high control case observes the null instead of crashing.
  HighVariable *high = dst->high;
  int4 has_high = (high != (HighVariable *)0) ? 1 : 0;
  int4 dirty_before = 0, tl_before = 0;
  const char *hmeta_before = "none";
  const char *hsym = "none";
  int4 hoff = -99;
  if (has_high) {
    high->updateType(); // pre-clean the typedirty cache bit
    dirty_before = (high->highflags & HighVariable::typedirty) ? 1 : 0;
    tl_before = high->isTypeLock() ? 1 : 0;
    hmeta_before = metaToken(high->getType()->getMetatype());
  }
  op(dst, src);
  int4 dirty_after = 0, tl_after = 0;
  const char *hmeta_after = "none";
  if (has_high) {
    high = dst->high;
    dirty_after = (high->highflags & HighVariable::typedirty) ? 1 : 0;
    tl_after = high->isTypeLock() ? 1 : 0;
    hmeta_after = metaToken(high->getType()->getMetatype());
    Symbol *hs = high->getSymbol();
    if (hs != (Symbol *)0) {
      hsym = hs->getName().c_str();
      hoff = high->getSymbolOffset();
    }
  }
  std::cout << "case=" << label
            << "|has_high=" << has_high
            << "|dirty_before=" << dirty_before
            << "|tl_before=" << tl_before
            << "|hmeta_before=" << hmeta_before
            << "|dirty_after=" << dirty_after
            << "|tl_after=" << tl_after
            << "|hmeta_after=" << hmeta_after
            << "|hsym=" << hsym
            << "|hoff=" << hoff
            << "|dst_tl=" << (dst->isTypeLock() ? 1 : 0)
            << "|dst_nl=" << (dst->isNameLock() ? 1 : 0)
            << "|dst_mapentry=" << (dst->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
            << '\n';
}

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureTranslate trans;
  FixtureArchitecture architecture;
  AddrSpace *ram = trans.getSpace(3);
  Datatype *int4_type = architecture.types->getBase(4, TYPE_INT);
  Scope *scope = architecture.symboltab->getGlobalScope();
  Funcdata fd("fx", "fx", scope, Address(ram, 0x1000), (FunctionSymbol *)0,
              0x20);
  // highlevel_on: every newConstant destination gets a fresh HighVariable
  // (funcdata_varnode.cc:48-59 via 66-73), exactly like the real
  // ActionAssignHigh-on pipeline the markedInput collapse runs in.
  fd.setHighLevel();

  // hb_close_propagates_high: equate value equal to the destination constant
  // (cc:642 exact close) -> the full copySymbol incl. cc:500-504.
  {
    Varnode *src = makeEquateSrc(fd, scope, int4_type, 0x33333333);
    Varnode *dst = fd.newConstant(4, 0x33333333);
    printCase("hb_close_propagates_high", dst, src,
              [](Varnode *d, Varnode *s) { d->copySymbolIfValid(s); });
  }

  // hb_not_close_no_high_effects: equate 0x12345678 vs constant 0x33333333
  // -> cc:519 rejects before any copy; the pre-cleaned high must stay clean.
  {
    Varnode *src = makeEquateSrc(fd, scope, int4_type, 0x12345678);
    Varnode *dst = fd.newConstant(4, 0x33333333);
    printCase("hb_not_close_no_high_effects", dst, src,
              [](Varnode *d, Varnode *s) { d->copySymbolIfValid(s); });
  }

  // hb_copy_null_mapentry_dirty: direct copySymbol from a typelocked source
  // with NO SymbolEntry: cc:501 typeDirty fires, cc:502 guard blocks
  // setSymbol.
  {
    Varnode *src = fd.newConstant(4, 0x44444444);
    src->updateType(int4_type, true, false);
    Varnode *dst = fd.newConstant(4, 0x44444444);
    printCase("hb_copy_null_mapentry_dirty", dst, src,
              [](Varnode *d, Varnode *s) { d->copySymbol(s); });
  }

  // hb_dst_no_high: destination from a Funcdata with highlevel disabled —
  // the field copy runs, the cc:500 outer guard skips the bookkeeping.
  {
    Funcdata fd2("fx2", "fx2", scope, Address(ram, 0x2000), (FunctionSymbol *)0,
                 0x20);
    Varnode *src = makeEquateSrc(fd, scope, int4_type, 0x33333333);
    Varnode *dst = fd2.newConstant(4, 0x33333333);
    printCase("hb_dst_no_high", dst, src,
              [](Varnode *d, Varnode *s) { d->copySymbolIfValid(s); });
  }

  // hb_op_level_marked_input: RuleCollapseConstants (ruleaction.cc:
  // 3854-3882) -> collapseConstantSymbol (op.cc:503-540) ->
  // copySymbolIfValid on an INT_ADD with the equate marked on input 0.
  // The collapsed constant (0x11111111+0x22222222 = 0x33333333, close to
  // the equate) becomes op input 0 with the markup AND the high Symbol
  // attached by cc:502-503.
  {
    RuleCollapseConstants collapseRule("analysis");
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);
    PcodeOp *op = fd.newOp(2, Address(ram, 0x5000));
    fd.opSetOpcode(op, CPUI_INT_ADD);
    Varnode *in0 = fd.newConstant(4, 0x11111111);
    Varnode *in1 = fd.newConstant(4, 0x22222222);
    fd.opSetInput(op, in0, 0);
    fd.opSetInput(op, in1, 1);
    fd.newUniqueOut(4, op);
    fd.opInsertEnd(op, block);
    Symbol *sym = scope->addEquateSymbol("FIXTURE_EQ", 0, 0x33333333, Address(), 0);
    in0->setSymbolEntry(sym->getFirstWholeMap());

    const int4 apply = collapseRule.applyOp(op, fd);
    // After the collapse the op is COPY(newConst) and the new constant is
    // input 0 (ruleaction.cc:3874 opSetInput(op,vn,0)).
    Varnode *newIn0 = op->numInput() > 0 ? op->getIn(0) : (Varnode *)0;
    HighVariable *high = newIn0->high;
    Symbol *hs = (high != (HighVariable *)0) ? high->getSymbol() : (Symbol *)0;
    std::cout << "case=hb_op_level_marked_input"
              << "|apply=" << apply
              << "|opcode=" << static_cast<int4>(op->code())
              << "|in0_symbol=" << (newIn0->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
              << "|in0_has_high=" << (high != (HighVariable *)0 ? 1 : 0)
              << "|in0_high_symbol=" << (hs != (Symbol *)0 ? hs->getName() : std::string("none"))
              << "|in0_high_off=" << (high != (HighVariable *)0 ? high->getSymbolOffset() : -99)
              << '\n';
  }
  return 0;
}
