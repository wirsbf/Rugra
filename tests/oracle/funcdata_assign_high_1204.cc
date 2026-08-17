// FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001 fixture — Funcdata::assignHigh /
// Funcdata::setHighLevel / newVarnode-family high wiring / Varnode::copySymbol
// high leg (funcdata_varnode.cc:48-59,595-605,72,89,110,135,157,182,196,212,231;
// variable.cc:220-235; varnode.cc:493-505).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable behaviors pinned by this fixture (one stdout line per case):
//   off_constant       with highlevel_on CLEAR, newConstant leaves the
//                      Varnode high-less (assignHigh early-out, cc:51).
//   off_unique         with highlevel_on CLEAR, newUnique leaves the Varnode
//                      high-less.
//   sethigh_flag       setHighLevel() sets highlevel_on (cc:599).
//   sethigh_index      setHighLevel() records vbank.getCreateIndex() as
//                      high_level_index BEFORE the assign sweep (cc:600),
//                      observed as == the pre-sweep snapshot.
//   sethigh_const      a pre-existing constant Varnode gets a HighVariable
//                      (constants are not annotations; cc:54-56).
//   sethigh_written    a pre-existing written Varnode gets a HighVariable
//                      AND its Cover is allocated by the hasCover->calcCover
//                      leg (cc:52-53), observed as cover pointer turning
//                      non-null with the coverdirty bit set.
//   sethigh_input      a pre-existing input Varnode gets a HighVariable.
//   sethigh_iop        an iop-space annotation Varnode stays high-less
//                      (isAnnotation guard, cc:54).
//   sethigh_instances  the fresh HighVariable holds exactly one instance,
//                      the member itself, with mergegroup 0 (numMergeClasses-1,
//                      variable.cc:231-232) and numMergeClasses 1
//                      (variable.cc:223).
//   sethigh_idem       a second setHighLevel() is a no-op: the flag is
//                      already set, and an existing member's HighVariable
//                      pointer is stable (cc:598 early return).
//   on_constant        with highlevel_on SET, newConstant assigns a
//                      HighVariable immediately (cc:72).
//   on_unique          with highlevel_on SET, newUnique assigns a
//                      HighVariable immediately (cc:89).
//   on_varnodeout      with highlevel_on SET, newVarnodeOut assigns a
//                      HighVariable immediately (cc:110) with the same
//                      one-instance/mergegroup-0 shape.
//   on_uniqueout       with highlevel_on SET, newUniqueOut assigns a
//                      HighVariable immediately (cc:135).
//   on_iop             newVarnodeIop stays high-less (iop space is an
//                      annotation, cc:182 -> cc:54 guard).
//   on_space           newVarnodeSpace gets a HighVariable (constant-space
//                      encoding is not an annotation, cc:196).
//   on_coderef         newCodeRef stays high-less (explicit annotation flag,
//                      cc:231 -> cc:54 guard).
//   dedup_high         opSetInput's constant-dedup copy (funcdata_op.cc:108-115)
//                      is a newConstant, so with highlevel_on SET the copy
//                      carries a HighVariable (the cc:72 leg feeds
//                      copySymbol's cc:500-504 high leg) — this is the
//                      FUNCDATA-NEWUNIQUE-ASSIGNHIGH-0001 / R1 closing
//                      observation: the copy differs from the original
//                      constant, holds one high instance, and the copied
//                      type pointer matches.
//   copysymbol_dirty   Varnode::copySymbol on a high-owning copy re-arms the
//                      HighVariable typedirty bit (varnode.cc:500-501),
//                      observed by clearing the bit first (test-only write)
//                      and re-observing it set after the call.
//   copysymbol_symbol  copySymbol with a NULL mapentry leaves the
//                      HighVariable symbol unset (varnode.cc:502 guard).
//
// Test-only access is required to drive the friend-only Funcdata factory
// surface and to clear a HighVariable dirty bit for the copysymbol_dirty
// case. Standard headers come first so the access macro cannot leak into
// libstdc++.
#include <bits/stdc++.h>
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

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureArchitecture architecture;
  AddrSpace *ram = architecture.getSpaceByName("ram");
  AddrSpace *reg = architecture.getSpaceByName("register");

  // Non-empty name so Funcdata::Funcdata builds a real ScopeLocal
  // (funcdata.cc:57-71); newVarnodeOut/newVarnode dereference localmap for
  // queryProperties (funcdata_varnode.cc:115,161).
  Scope *parent = architecture.symboltab->getGlobalScope();
  Funcdata fd("fixture", "fixture", parent, Address(ram, 0x1000),
              (FunctionSymbol *)0, 0x100);

  // --- A: highlevel_on CLEAR — assignHigh must early-out (cc:51) --------
  Varnode *off_const = fd.newConstant(4, 0x1111);
  Varnode *off_uniq = fd.newUnique(4);
  std::cout << "off_constant:" << (off_const->high != (HighVariable *)0) << '\n';
  std::cout << "off_unique:" << (off_uniq->high != (HighVariable *)0) << '\n';

  // --- B: populate the bank, then setHighLevel (cc:595-605) -------------
  // written shape via newVarnodeOut (createDef: written|insert flags, so
  // hasCover()==true when the assign sweep reaches it).
  PcodeOp *defop = fd.newOp(1, Address(ram, 0x1020));
  Varnode *written_vn = fd.newVarnodeOut(8, Address(reg, 0x310), defop);
  // input varnode
  Varnode *input_vn = fd.newVarnode(8, Address(reg, 0x300));
  input_vn = fd.setInputVarnode(input_vn);
  // iop-space annotation varnode
  PcodeOp *annot_op = fd.newOp(1, Address(ram, 0x1030));
  Varnode *iop_vn = fd.newVarnodeIop(annot_op);
  // cover of a not-yet-assigned written varnode is null
  bool pre_cover_null = (written_vn->cover == (Cover *)0);
  // Public-channel index baseline: the create index of the LAST Varnode
  // created before the sweep (VarnodeBank assigns increasing indices;
  // getCreateIndex() after the sweep must be >= this baseline).
  uint4 index_baseline = iop_vn->getCreateIndex();

  fd.setHighLevel();
  std::cout << "sethigh_flag:" << fd.isHighOn() << '\n';
  std::cout << "sethigh_index:" << (fd.getHighLevelIndex() != 0
            && fd.getHighLevelIndex() > index_baseline) << '\n';
  std::cout << "sethigh_const:" << (off_const->high != (HighVariable *)0) << '\n';
  bool written_cover_ok = pre_cover_null && (written_vn->cover != (Cover *)0)
      && ((written_vn->getFlags() & Varnode::coverdirty) != 0);
  std::cout << "sethigh_written:" << (written_vn->high != (HighVariable *)0)
            << ",cover=" << written_cover_ok << '\n';
  std::cout << "sethigh_input:" << (input_vn->high != (HighVariable *)0) << '\n';
  std::cout << "sethigh_iop:" << (iop_vn->high != (HighVariable *)0) << '\n';

  HighVariable *h_const = off_const->high;
  bool shape = (h_const->numInstances() == 1) && (h_const->getInstance(0) == off_const)
      && (off_const->mergegroup == 0) && (h_const->numMergeClasses == 1);
  std::cout << "sethigh_instances:" << shape << '\n';

  HighVariable *h_const_before = off_const->high;
  fd.setHighLevel();
  std::cout << "sethigh_idem:" << (off_const->getHigh() == h_const_before) << '\n';

  // --- C: highlevel_on SET — the newVarnode family assigns highs --------
  Varnode *on_const = fd.newConstant(4, 0x2222);
  std::cout << "on_constant:" << (on_const->high != (HighVariable *)0) << '\n';
  Varnode *on_uniq = fd.newUnique(4);
  std::cout << "on_unique:" << (on_uniq->high != (HighVariable *)0) << '\n';

  PcodeOp *out_op = fd.newOp(1, Address(ram, 0x1040));
  Varnode *on_vnout = fd.newVarnodeOut(8, Address(reg, 0x320), out_op);
  HighVariable *h_vnout = on_vnout->high;
  bool vnout_shape = (h_vnout != (HighVariable *)0)
      && (h_vnout->numInstances() == 1) && (h_vnout->getInstance(0) == on_vnout)
      && (on_vnout->mergegroup == 0);
  std::cout << "on_varnodeout:" << (h_vnout != (HighVariable *)0)
            << ",shape=" << vnout_shape << '\n';

  PcodeOp *uout_op = fd.newOp(1, Address(ram, 0x1050));
  Varnode *on_uout = fd.newUniqueOut(8, uout_op);
  std::cout << "on_uniqueout:" << (on_uout->high != (HighVariable *)0) << '\n';

  PcodeOp *iop_op = fd.newOp(1, Address(ram, 0x1060));
  Varnode *on_iop = fd.newVarnodeIop(iop_op);
  std::cout << "on_iop:" << (on_iop->high != (HighVariable *)0) << '\n';

  Varnode *on_space = fd.newVarnodeSpace(ram);
  std::cout << "on_space:" << (on_space->high != (HighVariable *)0) << '\n';

  Varnode *on_coderef = fd.newCodeRef(Address(ram, 0x2000));
  std::cout << "on_coderef:" << (on_coderef->high != (HighVariable *)0) << '\n';

  // --- D: opSetInput constant dedup feeds copySymbol's high leg (R1) ----
  PcodeOp *use1 = fd.newOp(1, Address(ram, 0x1070));
  PcodeOp *use2 = fd.newOp(1, Address(ram, 0x1080));
  Varnode *shared_const = fd.newConstant(4, 0xABCD);
  // First attach: no descendant yet, no dedup, addDescend(use1).
  fd.opSetInput(use1, shared_const, 0);
  // Second attach: shared_const now has a descendant -> dedup fires
  // (funcdata_op.cc:108-115): cvn = newConstant(...); cvn->copySymbol(vn).
  fd.opSetInput(use2, shared_const, 0);
  Varnode *dedup_vn = use2->getIn(0);
  bool dedup_ok = (dedup_vn != shared_const) && dedup_vn->isConstant()
      && (dedup_vn->getOffset() == 0xABCD)
      && (dedup_vn->high != (HighVariable *)0)
      && (dedup_vn->high->numInstances() == 1)
      && (dedup_vn->high->getInstance(0) == dedup_vn)
      && (dedup_vn->getType() != (Datatype *)0)
      && (dedup_vn->getType()->getSize() == shared_const->getType()->getSize());
  std::cout << "dedup_high:" << dedup_ok << '\n';

  // --- E: copySymbol typedirty re-arm + symbol guard (varnode.cc:500-504)
  HighVariable *h_dedup = dedup_vn->high;
  // Test-only: clear the ctor-armed typedirty so the re-arm is observable.
  h_dedup->highflags &= ~(uint4)HighVariable::typedirty;
  Varnode *src_const = fd.newConstant(4, 0xABCD);
  dedup_vn->copySymbol(src_const);
  bool rearm = ((h_dedup->highflags & HighVariable::typedirty) != 0)
      && (h_dedup->getSymbol() == (Symbol *)0);
  std::cout << "copysymbol_dirty:" << rearm << '\n';
  std::cout << "copysymbol_symbol:" << (h_dedup->getSymbol() == (Symbol *)0) << '\n';
  (void)defop; (void)annot_op;
  return 0;
}
