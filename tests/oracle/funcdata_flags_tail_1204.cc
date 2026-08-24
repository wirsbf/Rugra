// FUNCDATA-NEWVARNODE-FLAGS-TAIL-0001 (R9-F2 funcdata 租约外两处) fixture —
// Funcdata::newIndirectOp (funcdata_op.cc:683-698) and
// Funcdata::newIndirectCreation (funcdata_op.cc:710-728).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// The constructors build their varnodes through newVarnode (cc:689) /
// newVarnodeOut (cc:692/719), whose property-flag TAIL
// (funcdata_varnode.cc:148-165 / 104-127) runs
// `localmap->queryProperties(addr,size,usepoint,vflags)` and installs the
// range flags with `vn->setFlags(vflags & ~Varnode::typelock)` (or
// setSymbolProperties on a symbol hit — the flag bits are the same
// getAllFlags fold).  This fixture pins that the tail is observable on the
// INDIRECT in/out varnodes at construction time:
//
//   stack_window_indirect        newIndirectOp at stack 0x20 (inside the
//                                installed ScopeLocal param window
//                                [0,511]): in/out carry mapped|addrtied
//                                (database.cc:1272-1275 in-scope branch).
//   persist_band_indirect        after Database::setPropertyRange installs a
//                                whole-ram persist band [0x1000,0x2000],
//                                a newIndirectOp at ram 0x1000 gives in/out
//                                persist (database.cc:1278-1279 flagbase
//                                branch); the stack-window varnode from case
//                                1 is NOT retroactively re-flagged.
//   persist_band_creation_false  newIndirectCreation(possibleout=false) at
//                                ram 0x1008: out = persist|written|insert|
//                                coverdirty|indirect_creation; the constant
//                                in0 takes indirect_creation.
//   persist_band_creation_true   possibleout=true: in0 keeps no
//                                indirect_creation; out unchanged.
//   unique_creation_false        control: unique 0x700 is in no scope and no
//                                band -> out has NO property bits.
//   free_second_throw            异常前状态 (pre-exception state): the
//                                stack-window INDIRECT input[0] is a FREE
//                                varnode with one descendant; a second
//                                opSetInput fires addDescend's
//                                LowlevelError("Free varnode has multiple
//                                descendants") (varnode.cc:333-339) AFTER
//                                opUnsetInput cleared the old slot — in0's
//                                tail-applied flags and descend count are
//                                unchanged at the throw.
//
// Declared divergence (production-unobservable, not printed): after the
// caught throw the abandoned op's slot 0 is NULL in C++ (clearInput ran)
// while Rugra's Vec still holds the old dummy varnode — the op_insert_1204
// null-slot representation gap; production aborts the function on
// LowlevelError so that state is never read.
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

std::string hexf(uint4 flags) {
  std::ostringstream out;
  out << "0x" << std::hex << flags;
  return out.str();
}

std::string blockOrder(const BlockBasic *bl) {
  std::ostringstream out;
  bool first = true;
  for (auto iter = bl->beginOp(); iter != bl->endOp(); ++iter) {
    if (!first)
      out << ',';
    first = false;
    out << get_opname((*iter)->code());
  }
  return out.str();
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
    AddrSpace *stack = trans.getSpace(5);
    AddrSpace *unique = trans.getSpace(2);
    Funcdata fd("flags_tail", "flags_tail",
                architecture.symboltab->getGlobalScope(),
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x20);
    // The ctor leaves FuncProto::localrange/paramrange EMPTY (setModel
    // populates neither), so resetLocalWindow installs an empty window.
    // Install the default-model stack window through the production
    // resetLocalWindow tail (Database::setRange) — params [0,511] plus
    // locals [highest-999999,highest] (fspec.cc:2263-2320) — the way a
    // decoded prototype would, so the in-scope queryProperties branch is
    // reachable.
    RangeList window;
    window.insertRange(stack, 0, 511);
    window.insertRange(stack, 0xffffffffffffffff - 999999,
                       0xffffffffffffffff);
    architecture.symboltab->setRange(fd.getScopeLocal(), window);
    BlockBasic *b0 = const_cast<BlockGraph &>(fd.getBasicBlocks()).newBlockBasic(&fd);

    // case 1: stack-window INDIRECT — in/out both inside [0,511].
    PcodeOp *effect1 = fd.newOp(0, Address(ram, 0x5010));
    fd.opSetOpcode(effect1, CPUI_INT_SUB);
    fd.opInsertEnd(effect1, b0);
    int4 vn_before = fd.numVarnodes();
    PcodeOp *ind1 = fd.newIndirectOp(effect1, Address(stack, 0x20), 8, 0);
    int4 vn_after = fd.numVarnodes();
    const Varnode *in0 = ind1->getIn(0);
    const Varnode *out = ind1->getOut();
    std::cout << "case=stack_window_indirect|op=" << get_opname(ind1->code())
              << "|opic=" << (ind1->isIndirectCreation() ? 1 : 0)
              << "|iss=" << (ind1->isIndirectStore() ? 1 : 0)
              << "|in0=" << hexf(in0->getFlags())
              << "|in0free=" << (in0->isFree() ? 1 : 0)
              << "|in0desc=" << countDescendants(in0)
              << "|out=" << hexf(out->getFlags())
              << "|outwritten=" << (out->isWritten() ? 1 : 0)
              << "|outoff=0x" << std::hex << out->getOffset() << std::dec
              << "|outsz=" << out->getSize()
              << "|vndelta=" << (vn_after - vn_before)
              << "|order=" << blockOrder(b0) << '\n';

    // Whole-ram persist property band [0x1000,0x2000] (construction-time
    // consultation only — case 1's varnodes must stay un-flagged).
    architecture.symboltab->setPropertyRange(Varnode::persist,
                                             Range(ram, 0x1000, 0x2000));

    // case 2: persist-band INDIRECT at ram 0x1000.
    PcodeOp *effect2 = fd.newOp(0, Address(ram, 0x5011));
    fd.opSetOpcode(effect2, CPUI_INT_SUB);
    fd.opInsertEnd(effect2, b0);
    vn_before = fd.numVarnodes();
    PcodeOp *ind2 = fd.newIndirectOp(effect2, Address(ram, 0x1000), 4, 0);
    vn_after = fd.numVarnodes();
    const Varnode *in0b = ind2->getIn(0);
    const Varnode *outb = ind2->getOut();
    std::cout << "case=persist_band_indirect|in0=" << hexf(in0b->getFlags())
              << "|in0desc=" << countDescendants(in0b)
              << "|out=" << hexf(outb->getFlags())
              << "|outoff=0x" << std::hex << outb->getOffset() << std::dec
              << "|outsz=" << outb->getSize()
              << "|vndelta=" << (vn_after - vn_before)
              << "|in0_stable=" << hexf(in0->getFlags())
              << "|order=" << blockOrder(b0) << '\n';

    // case 3: persist-band INDIRECT-creation, possibleout=false.
    vn_before = fd.numVarnodes();
    PcodeOp *c1 = fd.newIndirectCreation(effect2, Address(ram, 0x1008), 4, false);
    vn_after = fd.numVarnodes();
    const Varnode *c1in = c1->getIn(0);
    const Varnode *c1out = c1->getOut();
    std::cout << "case=persist_band_creation_false|opic="
              << (c1->isIndirectCreation() ? 1 : 0)
              << "|in0=" << hexf(c1in->getFlags())
              << "|in0desc=" << countDescendants(c1in)
              << "|out=" << hexf(c1out->getFlags())
              << "|outwritten=" << (c1out->isWritten() ? 1 : 0)
              << "|vndelta=" << (vn_after - vn_before)
              << "|order=" << blockOrder(b0) << '\n';

    // case 4: possibleout=true — in0 keeps no indirect_creation.
    PcodeOp *c2 = fd.newIndirectCreation(effect2, Address(ram, 0x1010), 4, true);
    const Varnode *c2in = c2->getIn(0);
    const Varnode *c2out = c2->getOut();
    std::cout << "case=persist_band_creation_true|in0=" << hexf(c2in->getFlags())
              << "|out=" << hexf(c2out->getFlags())
              << "|outsz=" << c2out->getSize() << '\n';

    // case 5: control — unique 0x700 is in no scope and no band.
    PcodeOp *c3 = fd.newIndirectCreation(effect2, Address(unique, 0x700), 4, false);
    const Varnode *c3out = c3->getOut();
    std::cout << "case=unique_creation_false|out=" << hexf(c3out->getFlags())
              << "|outoff=0x" << std::hex << c3out->getOffset() << std::dec
              << '\n';

    // case 6: 异常前状态 — second opSetInput of the free stack-window
    // INDIRECT input throws from addDescend after opUnsetInput.
    PcodeOp *other = fd.newOp(0, Address(ram, 0x5020));
    fd.opSetOpcode(other, CPUI_COPY);
    Varnode *dummy = fd.newConstant(8, 0x77);
    fd.opInsertInput(other, dummy, 0);
    vn_before = fd.numVarnodes();
    std::string throw_error;
    try { fd.opSetInput(other, const_cast<Varnode *>(in0), 0); }
    catch (const LowlevelError &err) { throw_error = err.explain; }
    vn_after = fd.numVarnodes();
    std::cout << "case=free_second_throw|err=" << throw_error
              << "|in0=" << hexf(in0->getFlags())
              << "|in0desc=" << countDescendants(in0)
              << "|dummy_desc=" << countDescendants(dummy)
              << "|vndelta=" << (vn_after - vn_before) << '\n';
  }
  catch (const LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
