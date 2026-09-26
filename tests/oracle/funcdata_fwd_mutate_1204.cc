// FUNCDATA-FWD-MUTATE-0001 bilateral fixture — the Funcdata mutation
// forwarder family (funcdata.hh maintenance inlines).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Covered definitions:
//   markReturnCopy (hh:452)          — return_copy flag bit
//   opMarkStartBasic (hh:480)        — startbasic flag bit
//   opMarkStartInstruction (hh:481)  — startmark flag bit
//   opDeadInsertAfter (hh:460)       — dead-list reorder
//   opDeadAndGone (hh:476)           — destroy + deadandgone retention
//   initActiveOutput/clearActiveOutput (hh:418/420) — ParamActive slot
//   clearDeadOps (hh:428)            — destroyDead
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

std::string deadOrder(const Funcdata &fd) {
  std::ostringstream out;
  bool first = true;
  for (auto iter = fd.beginOpDead(); iter != fd.endOpDead(); ++iter) {
    if (!first) out << ',';
    first = false;
    out << get_opname((*iter)->code());
  }
  return out.str();
}

size_t optreeSize(const Funcdata &fd) {
  size_t n = 0;
  for (auto iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) ++n;
  return n;
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
    Funcdata fd("fwd_mutate", "fwd_mutate",
                architecture.symboltab->getGlobalScope(),
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x20);
    BlockBasic *b0 = const_cast<BlockGraph &>(fd.getBasicBlocks()).newBlockBasic(&fd);

    // case=mark_flags: the three flag-bit setters, projected as raw hex
    // flag words before/after each mutation.
    {
      PcodeOp *copy = fd.newOp(1, Address(ram, 0x5010));
      fd.opSetOpcode(copy, CPUI_COPY);
      fd.opInsertEnd(copy, b0);
      bool b0 = copy->isReturnCopy();
      fd.markReturnCopy(copy);
      bool b1 = copy->isReturnCopy();
      fd.opMarkStartBasic(copy);
      bool b2 = copy->isBlockStart();
      fd.opMarkStartInstruction(copy);
      bool b3 = copy->isInstructionStart();
      std::cout << "case=mark_flags|ret_copy0=" << b0 << "|ret_copy1=" << b1
                << "|block_start=" << b2 << "|instr_start=" << b3 << '\n';
    }

    // case=dead_insert: opDeadInsertAfter reorders the dead list.
    {
      PcodeOp *d1 = fd.newOp(1, Address(ram, 0x6010));
      fd.opSetOpcode(d1, CPUI_INT_ADD);
      PcodeOp *d2 = fd.newOp(1, Address(ram, 0x6020));
      fd.opSetOpcode(d2, CPUI_INT_SUB);
      // Creation order puts d1 before d2; move d1 after d2.
      fd.opDeadInsertAfter(d1, d2);
      std::string order = deadOrder(fd);
      // And back.
      fd.opDeadInsertAfter(d2, d1);
      std::string order2 = deadOrder(fd);
      std::cout << "case=dead_insert|swapped=" << order
                << "|restored=" << order2 << '\n';
    }

    // case=dead_and_gone: destroy moves the op to retention and drops
    // every index (optree shrinks).
    {
      PcodeOp *d3 = fd.newOp(1, Address(ram, 0x6030));
      fd.opSetOpcode(d3, CPUI_INT_MULT);
      size_t optree_before = optreeSize(fd);
      size_t dead_before = 0;
      for (auto iter = fd.beginOpDead(); iter != fd.endOpDead(); ++iter)
        ++dead_before;
      fd.opDeadAndGone(d3);
      size_t optree_after = optreeSize(fd);
      size_t dead_after = 0;
      for (auto iter = fd.beginOpDead(); iter != fd.endOpDead(); ++iter)
        ++dead_after;
      std::cout << "case=dead_and_gone|optree_before=" << optree_before
                << "|optree_after=" << optree_after
                << "|dead_before=" << dead_before
                << "|dead_after=" << dead_after << '\n';
    }

    // case=active_output: initActiveOutput installs the ParamActive
    // recovery object; clearActiveOutput deletes it.
    {
      fd.initActiveOutput();
      bool present = (fd.getActiveOutput() != (ParamActive *)0);
      fd.clearActiveOutput();
      bool cleared = (fd.getActiveOutput() != (ParamActive *)0);
      std::cout << "case=active_output|present=" << present
                << "|cleared=" << cleared << '\n';
    }

    // case=clear_dead_ops: destroyDead empties the dead list.
    {
      PcodeOp *d4 = fd.newOp(2, Address(ram, 0x6040));
      fd.opSetOpcode(d4, CPUI_INT_OR);
      size_t dead_before = 0;
      for (auto iter = fd.beginOpDead(); iter != fd.endOpDead(); ++iter)
        ++dead_before;
      fd.clearDeadOps();
      size_t dead_after = 0;
      for (auto iter = fd.beginOpDead(); iter != fd.endOpDead(); ++iter)
        ++dead_after;
      std::cout << "case=clear_dead_ops|dead_before=" << dead_before
                << "|dead_after=" << dead_after << '\n';
    }
  } catch (const LowlevelError &err) {
    std::cout << "case=lowlevel_error|" << err.explain << '\n';
    return 1;
  }
  return 0;
}
