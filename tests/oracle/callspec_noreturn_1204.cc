/*
 * CALLSPEC-NORETURN-1204: locked Ghidra 12.0.4 oracle for the FuncProto /
 * FuncCallSpecs no-return flag lifecycle (CALLSPEC-NORETURN-WIRE-0001
 * slice a).
 *
 * Covered projection (all observations go through public Ghidra API):
 *  - FuncProto::FuncProto (fspec.cc:3778): flags == 0, so isNoReturn() and
 *    isInline() default to false; FuncCallSpecs(PcodeOp*) (fspec.cc:4924)
 *    inherits the same false defaults through FuncProto().
 *  - setNoReturn (fspec.hh:1439) / isNoReturn (fspec.hh:1434): explicit set,
 *    repeated-set idempotence, clear via false — driven both on a plain
 *    FuncProto and through the FuncCallSpecs inherited surface (the surface
 *    flow.cc:747 truncateIndirectJump uses).
 *  - copyFlowEffects (fspec.cc:3806-3812): only the is_inline|no_return
 *    subset is copied, as a one-way overwrite (clear-then-OR: a source bit
 *    of 0 clears the destination bit); modellock and everything else stays
 *    untouched. This is the flow.cc:664 queryCall channel that propagates a
 *    callee's noreturn state onto the call site.
 *  - FuncProto::copy (fspec.cc:3789) copies the flags wholesale;
 *    FuncCallSpecs::clone (fspec.cc:4964-4977) preserves the copied
 *    FuncProto bits, rebinds to the new op, and resets the active-input
 *    recovery state.
 *  - No void->noreturn inference exists anywhere in the fspec layer: a
 *    void-returning prototype (setInternal + a decoded <prototype> with a
 *    void <returnsym> and no noreturn attribute) stays isNoReturn()==false.
 *    The only producers of the bit are the explicit XML attribute
 *    (fspec.cc:4720-4722), OptionNoReturn (options.cc:358), a direct
 *    setNoReturn, and copyFlowEffects/copy propagation.
 *  - decode/encode channel (fspec.cc:4675-4840 / 4625-4667): the
 *    noreturn="true" attribute sets the bit, an absent attribute leaves it
 *    clear, noreturn="false" leaves it clear, and encode emits the
 *    attribute only when the bit is set.
 *
 * The fixture architecture (spaces + TypeFactory + a decoded "fixture"
 * ProtoModel) mirrors the action_merge_order_1204 fixture; the two bare
 * PcodeOps carry the CALLIND opcode so the FuncCallSpecs constructor leaves
 * the entry address invalid exactly like a CALLIND call site.
 */

#include <bits/stdc++.h>

// Test-only access observer for PcodeOp::setOpcode (op.cc:276), the same
// #define pattern the fspec_phase0 / address_space fixtures use; layout is
// unchanged (access specifiers only), and the mangled setOpcode symbol
// resolves against the locked archive. <bits/stdc++.h> is included first so
// the defines never leak into libstdc++ headers.
#define class struct
#define private public
#define protected public
#include "op.hh"
#undef protected
#undef private
#undef class

#include "architecture.hh"
#include "database.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "translate.hh"
#include "type.hh"

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

  ProtoModel *fixture_model(void) { return protoModels["fixture"]; }
  TypeOp *callind_behavior(void) { return inst[CPUI_CALLIND]; }

  void printMessage(const std::string &) const override {}
};

// A bare CALLIND-opcoded PcodeOp: the FuncCallSpecs constructor takes the
// non-CALL branch and leaves the entry address invalid (fspec.cc:4942).
static PcodeOp *make_callind_op(FixtureArchitecture &arch, uintm ord) {
  PcodeOp *op = new PcodeOp(1, SeqNum(Address(), ord));
  op->setOpcode(arch.callind_behavior());
  return op;
}

// Decode a <prototype> element into a FuncProto backed by the fixture
// model + void type. Mirrors the Funcdata prototype-restore staging
// (setInternal before decode, fspec.cc:4679-4680).
static void decode_proto(FixtureArchitecture &arch, FuncProto &proto,
                         const std::string &xml) {
  proto.setInternal(arch.fixture_model(), arch.types->getTypeVoid());
  std::istringstream stream(xml);
  XmlDecode decoder(&arch);
  decoder.ingestStream(stream);
  proto.decode(decoder, &arch);
}

int main(void) {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=CALLSPEC-NORETURN-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    TypeVoid void_type;

    // ---- case=default_ctor ------------------------------------------
    {
      FuncProto proto;
      proto.setInternal((ProtoModel *)0, &void_type);
      PcodeOp *op = make_callind_op(arch, 1);
      FuncCallSpecs fc(op);
      std::cout << "case=default_ctor"
                << "|proto_noret=" << (int4)proto.isNoReturn()
                << "|proto_inline=" << (int4)proto.isInline()
                << "|callspec_noret=" << (int4)fc.isNoReturn()
                << "|callspec_inline=" << (int4)fc.isInline()
                << "|callspec_entry_invalid="
                << (int4)fc.getEntryAddress().isInvalid()
                << '\n';
    }

    // ---- case=explicit_set_idempotent ------------------------------
    {
      FuncProto proto;
      proto.setInternal((ProtoModel *)0, &void_type);
      proto.setNoReturn(true);
      int4 a = proto.isNoReturn();
      proto.setNoReturn(true);
      int4 b = proto.isNoReturn();
      proto.setNoReturn(false);
      int4 c = proto.isNoReturn();
      proto.setNoReturn(false);
      int4 d = proto.isNoReturn();
      // Through the FuncCallSpecs inherited surface (flow.cc:747 uses
      // fc->setNoReturn(true) on a callspec).
      PcodeOp *op = make_callind_op(arch, 2);
      FuncCallSpecs fc(op);
      fc.setNoReturn(true);
      int4 e = fc.isNoReturn();
      fc.setNoReturn(false);
      int4 f = fc.isNoReturn();
      std::cout << "case=explicit_set_idempotent"
                << "|set_true=" << a
                << "|set_true_again=" << b
                << "|set_false=" << c
                << "|set_false_again=" << d
                << "|callspec_set_true=" << e
                << "|callspec_clear=" << f
                << '\n';
    }

    // ---- case=copy_flow_effects -------------------------------------
    {
      // callee{inline=T,noret=T} -> fc{F,F} becomes {T,T}
      FuncProto callee1;
      callee1.setInternal((ProtoModel *)0, &void_type);
      callee1.setInline(true);
      callee1.setNoReturn(true);
      PcodeOp *op = make_callind_op(arch, 3);
      FuncCallSpecs fc(op);
      fc.copyFlowEffects(callee1);
      int4 s1_noret = fc.isNoReturn();
      int4 s1_inline = fc.isInline();

      // callee{F,F} -> fc{previous T,T} clears to {F,F} (one-way overwrite)
      FuncProto callee2;
      callee2.setInternal((ProtoModel *)0, &void_type);
      fc.copyFlowEffects(callee2);
      int4 s2_noret = fc.isNoReturn();
      int4 s2_inline = fc.isInline();

      // callee{inline=F,noret=T} -> fc {F,T}; modellock (a non-subset flag
      // on the source) must not leak into the callspec.
      FuncProto callee3;
      callee3.setInternal((ProtoModel *)0, &void_type);
      callee3.setNoReturn(true);
      callee3.setModelLock(true);
      fc.copyFlowEffects(callee3);
      int4 s3_noret = fc.isNoReturn();
      int4 s3_inline = fc.isInline();
      int4 ml_leak = fc.isModelLocked();
      int4 ml_src = callee3.isModelLocked();
      std::cout << "case=copy_flow_effects"
                << "|step1_noret=" << s1_noret
                << "|step1_inline=" << s1_inline
                << "|step2_noret=" << s2_noret
                << "|step2_inline=" << s2_inline
                << "|step3_noret=" << s3_noret
                << "|step3_inline=" << s3_inline
                << "|modellock_not_copied=" << (int4)(ml_leak == 0)
                << "|src_modellock_stays=" << ml_src
                << '\n';
    }

    // ---- case=full_copy_and_clone -----------------------------------
    {
      FuncProto a;
      a.setInternal((ProtoModel *)0, &void_type);
      a.setNoReturn(true);
      a.setInline(true);
      FuncProto b;
      b.setInternal((ProtoModel *)0, &void_type);
      b.copy(a);
      int4 copy_noret = b.isNoReturn();
      int4 copy_inline = b.isInline();

      PcodeOp *op1 = make_callind_op(arch, 4);
      PcodeOp *op2 = make_callind_op(arch, 5);
      FuncCallSpecs *fc1 = new FuncCallSpecs(op1);
      // initActiveInput dereferences the prototype model (fspec.cc:5335
      // getMaxInputDelay), so stage the fixture model first.
      fc1->setInternal(arch.fixture_model(), arch.types->getTypeVoid());
      fc1->setNoReturn(true);
      fc1->setInline(true);
      fc1->initActiveInput();
      FuncCallSpecs *clone = fc1->clone(op2);
      int4 clone_noret = clone->isNoReturn();
      int4 clone_inline = clone->isInline();
      int4 clone_rebound = (clone->getOp() == op2) && (op1 != op2);
      int4 clone_active_reset =
          (clone->isInputActive() == false && fc1->isInputActive() == true);
      std::cout << "case=full_copy_and_clone"
                << "|copy_noret=" << copy_noret
                << "|copy_inline=" << copy_inline
                << "|clone_noret=" << clone_noret
                << "|clone_inline=" << clone_inline
                << "|clone_rebound=" << clone_rebound
                << "|clone_active_reset=" << (int4)clone_active_reset
                << '\n';
      delete clone;
      delete fc1;
      delete op2;
      delete op1;
    }

    // ---- case=void_no_inference -------------------------------------
    {
      // A void-returning prototype never gains noreturn implicitly.
      FuncProto proto;
      proto.setInternal(arch.fixture_model(), arch.types->getTypeVoid());
      int4 ctor_void = proto.isNoReturn();
      FuncProto decoded;
      decode_proto(
          arch, decoded,
          "<prototype model=\"fixture\" extrapop=\"0\">"
          "<returnsym typelock=\"true\">"
          "<addr space=\"ram\" offset=\"0x0\" size=\"1\"/>"
          "<void/>"
          "</returnsym></prototype>");
      int4 decode_void = decoded.isNoReturn();
      int4 decode_void_output = decoded.getOutputType()->getMetatype() == TYPE_VOID;
      std::cout << "case=void_no_inference"
                << "|setinternal_void_noret=" << ctor_void
                << "|decode_void_noret=" << decode_void
                << "|decode_output_is_void=" << (int4)decode_void_output
                << '\n';
    }

    // ---- case=decode_encode_channel ----------------------------------
    {
      FuncProto with_true;
      decode_proto(
          arch, with_true,
          "<prototype model=\"fixture\" extrapop=\"0\" noreturn=\"true\">"
          "<returnsym typelock=\"true\">"
          "<addr space=\"ram\" offset=\"0x0\" size=\"1\"/>"
          "<void/>"
          "</returnsym></prototype>");
      int4 d_true = with_true.isNoReturn();

      FuncProto with_absent;
      decode_proto(
          arch, with_absent,
          "<prototype model=\"fixture\" extrapop=\"0\">"
          "<returnsym typelock=\"true\">"
          "<addr space=\"ram\" offset=\"0x0\" size=\"1\"/>"
          "<void/>"
          "</returnsym></prototype>");
      int4 d_absent = with_absent.isNoReturn();

      FuncProto with_false;
      decode_proto(
          arch, with_false,
          "<prototype model=\"fixture\" extrapop=\"0\" noreturn=\"false\">"
          "<returnsym typelock=\"true\">"
          "<addr space=\"ram\" offset=\"0x0\" size=\"1\"/>"
          "<void/>"
          "</returnsym></prototype>");
      int4 d_false = with_false.isNoReturn();

      // encode emits the noreturn attribute only when the bit is set.
      std::ostringstream out_set;
      XmlEncode enc_set(out_set);
      with_true.encode(enc_set);
      int4 e_present = out_set.str().find("noreturn=") != std::string::npos;
      std::ostringstream out_clear;
      XmlEncode enc_clear(out_clear);
      with_absent.encode(enc_clear);
      int4 e_absent = out_clear.str().find("noreturn=") != std::string::npos;
      std::cout << "case=decode_encode_channel"
                << "|decode_true=" << d_true
                << "|decode_absent=" << d_absent
                << "|decode_false_attr=" << d_false
                << "|encode_present=" << e_present
                << "|encode_absent=" << e_absent
                << '\n';
    }
  } catch (const LowlevelError &err) {
    std::cerr << "fixture LowlevelError: " << err.explain << '\n';
    return 1;
  }
  return 0;
}
