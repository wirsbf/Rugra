// FUNCDATA-DBGFAMILY-0001 bilateral fixture — the OPACTION_DEBUG
// observation family on Funcdata.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
// The oracle side of this fixture is compiled against a libdecomp build with
// -DOPACTION_DEBUG (the whole debug family lives under that ifdef,
// funcdata.hh:580-612 + funcdata.cc:1007-1118); the hooks stay dormant
// (opactdbg_on false from the ctor, funcdata.cc:74-81) until enabled.
//
// Covered definitions:
//   debugEnable/debugDisable (hh:602/603)     debugClear (hh:604-605)
//   debugSize (hh:601)                        debugSetBreak (hh:610)
//   debugHandleBreak (hh:609)                 debugActivate (hh:595)
//   debugDeactivate (hh:596)                  enableJTCallback (hh:593)
//   disableJTCallback (hh:594)                debugSetRange (cc:1063)
//   debugCheckRange (cc:1076)                 debugModClear (cc:1024)
//   debugPrintRange (cc:1100, routed through setDebugStream(&cout))
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

void jtcb(Funcdata &orig, Funcdata &fd) { (void)orig; (void)fd; }

}  // namespace

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  try {
    FixtureTranslate trans;
    FixtureArchitecture architecture;
    architecture.setDebugStream(&std::cout);
    AddrSpace *ram = trans.getSpace(3);
    Funcdata fd("dbg_family", "dbg_family",
                architecture.symboltab->getGlobalScope(),
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x20);
    BlockBasic *b0 = const_cast<BlockGraph &>(fd.getBasicBlocks()).newBlockBasic(&fd);
    PcodeOp *op1 = fd.newOp(1, Address(ram, 0x5010));
    fd.opSetOpcode(op1, CPUI_COPY);
    fd.opInsertEnd(op1, b0);
    PcodeOp *op2 = fd.newOp(1, Address(ram, 0x5030));
    fd.opSetOpcode(op2, CPUI_INT_ADD);
    fd.opInsertEnd(op2, b0);

    // case=debug_lifecycle: enable/size/clear/disable and the break knobs.
    {
      fd.debugEnable();
      int size_on = fd.debugSize();
      fd.debugSetRange(Address(ram, 0x5010), Address(ram, 0x5020));
      int size_r1 = fd.debugSize();
      fd.debugClear();
      int size_cleared = fd.debugSize();
      fd.debugDisable();
      bool on_after_disable = fd.opactdbg_on;
      fd.debugSetBreak(5);
      int breakcount = fd.opactdbg_breakcount;
      fd.debugHandleBreak();
      bool breakon_after = fd.opactdbg_breakon;
      std::cout << "case=debug_lifecycle|size_on=" << size_on
                << "|size_r1=" << size_r1 << "|size_cleared=" << size_cleared
                << "|on_after_disable=" << on_after_disable
                << "|breakcount=" << breakcount
                << "|breakon_after=" << breakon_after << '\n';
    }

    // case=debug_range_matrix: two ranges (bounded PC; entire-function with
    // unique window) against ops inside/outside.
    {
      fd.debugEnable();
      fd.debugSetRange(Address(ram, 0x5010), Address(ram, 0x5020));
      fd.debugSetRange(Address(), Address(), 0, 3);
      bool r1_hit = fd.debugCheckRange(op1);
      bool r1_miss = fd.debugCheckRange(op2);
      std::cout << "case=debug_range_matrix|r1_hit=" << r1_hit
                << "|r1_miss=" << r1_miss << '|';
      fd.debugPrintRange(0);
      std::cout << '|';
      fd.debugPrintRange(1);
      std::cout << std::flush;
      std::cout << '\n';
    }

    // case=debug_mod_clear: a traced op takes the modified addl-flag via
    // debugModCheck; debugModClear drops it and the lists.
    {
      fd.debugClear();
      fd.debugSetRange(Address(ram, 0x5000), Address(ram, 0x6000));
      fd.debugModCheck(op1);
      bool marked = op1->isModified();
      size_t list_len = fd.modify_list.size();
      fd.debugModClear();
      bool marked_after = op1->isModified();
      size_t list_len_after = fd.modify_list.size();
      bool active_after = fd.opactdbg_active;
      std::cout << "case=debug_mod_clear|marked=" << marked
                << "|list_len=" << list_len << "|marked_after=" << marked_after
                << "|list_len_after=" << list_len_after
                << "|active_after=" << active_after << '\n';
    }

    // case=debug_activate: activation is gated on debugging being on.
    {
      fd.debugDisable();
      fd.debugActivate();
      bool active_off = fd.opactdbg_active;
      fd.debugEnable();
      fd.debugActivate();
      bool active_on = fd.opactdbg_active;
      fd.debugDeactivate();
      bool active_deactivated = fd.opactdbg_active;
      std::cout << "case=debug_activate|active_off=" << active_off
                << "|active_on=" << active_on
                << "|active_deactivated=" << active_deactivated << '\n';
    }

    // case=jt_callback: enable/disable stores and clears the fn pointer.
    {
      fd.enableJTCallback(jtcb);
      bool enabled = (fd.jtcallback != (void (*)(Funcdata &, Funcdata &))0);
      fd.disableJTCallback();
      bool disabled = (fd.jtcallback != (void (*)(Funcdata &, Funcdata &))0);
      std::cout << "case=jt_callback|enabled=" << enabled
                << "|disabled=" << disabled << '\n';
    }
  } catch (const LowlevelError &err) {
    std::cout << "case=lowlevel_error|" << err.explain << '\n';
    return 1;
  }
  return 0;
}
