/*
 * VARNODE-BANK-KEY-LIVE-0001: locked Ghidra 12.0.4 VarnodeBank::makeFree /
 * setInput / setDef / xref key-lifecycle oracle, exercised through the
 * ActionSetCasts::castOutput closure Funcdata::opSetOutput /
 * Funcdata::opUnsetOutput.
 *
 * The fixture builds def-use graphs through the production Funcdata APIs and
 * observes the complete VarnodeBank state: both tree iteration orders
 * (location-first and definition-first), per-Varnode membership counts in
 * each tree, the input/written/free classification, the insert flag, and the
 * defining SeqNum order.  Case makefree_inplace_key_drift reproduces the
 * hand-built-fixture discipline: a bank-managed free Varnode whose def/flags
 * are mutated IN PLACE (Varnode::setDef directly, bypassing the
 * erase-reinsert of VarnodeBank::setDef), then handed to VarnodeBank::
 * makeFree.  Ghidra erases through the lociter/defiter stored inside the
 * Varnode (varnode.cc:1319-1320), so the drifted live comparison key never
 * participates in the removal.
 */

#include <bits/stdc++.h>

// Test-only access is required to call Varnode::setDef directly and to read
// the Funcdata::vbank trees, matching what production Ghidra reaches through
// friend-only VarnodeBank/Funcdata APIs.
#define private public
#include "architecture.hh"
#include "cover.hh"
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

class Graph {
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  std::map<Varnode *, std::string> vnNames;
  std::map<PcodeOp *, std::string> opNames;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const std::string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), nextOffset(0) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    return blocks.newBlockBasic(&fd);
  }

  PcodeOp *makeOp(const std::string &name, OpCode opcode, int4 inputs)
  {
    Address pc(ram, fd.getAddress().getOffset() + (uintb)nextOffset);
    nextOffset += 1;
    PcodeOp *op = fd.newOp(inputs, pc);
    fd.opSetOpcode(op, opcode);
    opNames.insert(std::make_pair(op, name));
    return op;
  }

  Varnode *constant(const std::string &name, int4 size, uintb value)
  {
    Varnode *vn = fd.newConstant(size, value);
    vnNames.insert(std::make_pair(vn, name));
    return vn;
  }

  Varnode *input(const std::string &name, uintb offset, int4 size)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    vnNames.insert(std::make_pair(vn, name));
    return fd.setInputVarnode(vn);
  }

  // Bank-managed free Varnode in the register space; mirrors
  // Funcdata::newVarnode(s, Address(reg, off)).
  Varnode *regFree(const std::string &name, uintb offset, int4 size)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    vnNames.insert(std::make_pair(vn, name));
    return vn;
  }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot)
  {
    fd.opSetInput(op, vn, slot);
  }

  void setOutput(PcodeOp *op, Varnode *vn)
  {
    fd.opSetOutput(op, vn);
  }

  void unsetOutput(PcodeOp *op)
  {
    fd.opUnsetOutput(op);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block)
  {
    fd.opInsertEnd(op, block);
  }

  static char classOf(const Varnode *vn)
  {
    uint4 f = vn->getFlags() & (Varnode::input | Varnode::written);
    if (f == Varnode::input)
      return 'i';
    if (f == Varnode::written)
      return 'w';
    return 'f';
  }

  static std::string spaceToken(const Varnode *vn)
  {
    return vn->getSpace()->getName();
  }

  std::string nameOf(const Varnode *vn) const
  {
    std::map<Varnode *, std::string>::const_iterator iter =
        vnNames.find(const_cast<Varnode *>(vn));
    return iter == vnNames.end() ? "?" : (*iter).second;
  }

  // Complete location-tree iteration order.  Each entry prints
  // name.space.hexoffset.size.class.createIndex so the projection observes
  // both the comparator layering and the physical node positions.
  std::string locText(void) const
  {
    std::ostringstream out;
    out << '[';
    bool first = true;
    for (VarnodeLocSet::const_iterator iter = fd.beginLoc();
         iter != fd.endLoc(); ++iter) {
      if (!first) out << ',';
      first = false;
      const Varnode *vn = *iter;
      out << nameOf(vn) << '.' << spaceToken(vn) << '.' << std::hex
          << vn->getOffset() << std::dec << '.' << vn->getSize() << '.'
          << classOf(vn) << '.' << vn->getCreateIndex();
    }
    out << ']';
    return out.str();
  }

  // Complete definition-tree iteration order.  Written entries print the
  // defining SeqNum order; free/input entries print '-'.
  std::string defText(void) const
  {
    std::ostringstream out;
    out << '[';
    bool first = true;
    for (VarnodeDefSet::const_iterator iter = fd.beginDef();
         iter != fd.endDef(); ++iter) {
      if (!first) out << ',';
      first = false;
      const Varnode *vn = *iter;
      out << nameOf(vn) << '.' << classOf(vn) << '.';
      if (classOf(vn) == 'w')
        out << vn->getDef()->getSeqNum().getOrder();
      else
        out << '-';
      out << '.' << spaceToken(vn) << '.' << std::hex << vn->getOffset()
          << std::dec << '.' << vn->getSize() << '.' << vn->getCreateIndex();
    }
    out << ']';
    return out.str();
  }

  int4 locMembers(const Varnode *vn) const
  {
    int4 count = 0;
    for (VarnodeLocSet::const_iterator iter = fd.beginLoc();
         iter != fd.endLoc(); ++iter) {
      if (*iter == vn)
        count += 1;
    }
    return count;
  }

  int4 defMembers(const Varnode *vn) const
  {
    int4 count = 0;
    for (VarnodeDefSet::const_iterator iter = fd.beginDef();
         iter != fd.endDef(); ++iter) {
      if (*iter == vn)
        count += 1;
    }
    return count;
  }
};

// castOutput-semantics output swap: opSetOutput(B, out1) with out1 currently
// written by A follows Funcdata::opSetOutput (funcdata_op.cc:115-131):
// opUnsetOutput(A) -> VarnodeBank::makeFree(out1) -> setDef(out1, B).  Two
// full swaps prove the loc/def trees remove and reinsert across the
// free/written key-class boundary twice with stable iteration orders.
static void runOpSetOutputSwap(FixtureArchitecture &arch)
{
  Graph g(arch, "opsetoutput_swap", 0x5800);
  BlockBasic *b0 = g.makeBlock();
  Varnode *c8 = g.constant("c8", 8, 5);
  Varnode *c4 = g.constant("c4", 4, 7);
  Varnode *i0 = g.input("i0", 0x80, 4);
  PcodeOp *a = g.makeOp("A", CPUI_COPY, 1);
  g.setInput(a, c8, 0);
  Varnode *out1 = g.regFree("out1", 0x100, 4);
  g.setOutput(a, out1);
  g.insertEnd(a, b0);
  PcodeOp *b = g.makeOp("B", CPUI_INT_ADD, 2);
  g.setInput(b, i0, 0);
  g.setInput(b, c4, 1);
  g.insertEnd(b, b0);
  std::string loc0 = g.locText();
  std::string def0 = g.defText();
  g.setOutput(b, out1);
  std::string loc1 = g.locText();
  std::string def1 = g.defText();
  g.setOutput(a, out1);
  std::string loc2 = g.locText();
  std::string def2 = g.defText();
  std::cout << "case=opsetoutput_swap"
            << "|loc0=" << loc0 << "|def0=" << def0
            << "|loc1=" << loc1 << "|def1=" << def1
            << "|loc2=" << loc2 << "|def2=" << def2
            << "|out1_members=" << g.locMembers(out1) << ',' << g.defMembers(out1)
            << ',' << g.locMembers(out1) << ',' << g.defMembers(out1)
            << ',' << g.locMembers(out1) << ',' << g.defMembers(out1)
            << "|out1_written=" << (out1->isWritten() ? 1 : 0)
            << "|out1_insert=" << ((out1->getFlags() & Varnode::insert) != 0 ? 1 : 0)
            << "|out1_def2=" << out1->getDef()->getSeqNum().getOrder() << '\n';
}

// Hand-built key drift: the free Varnode's def is wired IN PLACE via
// PcodeOp::setOutput + Varnode::setDef (varnode.cc:394) — exactly what
// Rugra's hand-built test fixtures do — so the live comparison key
// classifies it as written while its stored tree positions remain in the
// free section.  The pad Varnode (created before out2 at a higher offset)
// makes the stale position observable: a re-sorted tree would move the
// written out2 BEFORE the free pad, the physical iteration keeps it after.
// makeFree must still erase it through the stored lociter/defiter and
// reinsert it as a free Varnode, restoring the pre-drift iteration order.
static void runMakeFreeInPlaceKeyDrift(FixtureArchitecture &arch)
{
  Graph g(arch, "makefree_inplace_key_drift", 0x5900);
  BlockBasic *b0 = g.makeBlock();
  Varnode *c8 = g.constant("c8", 8, 5);
  PcodeOp *d2 = g.makeOp("d2", CPUI_COPY, 1);
  g.setInput(d2, c8, 0);
  g.insertEnd(d2, b0);
  Varnode *pad = g.regFree("pad", 0x180, 4);
  Varnode *out2 = g.regFree("out2", 0x120, 4);
  std::string loc0 = g.locText();
  std::string def0 = g.defText();
  // Hand-built wiring exactly like Rugra's unit-test fixtures: the op's
  // output slot and the Varnode's def/written classification are assigned
  // IN PLACE, bypassing VarnodeBank::setDef's erase-reinsert.
  d2->setOutput(out2);
  out2->setDef(d2); // in-place: written + coverdirty, no erase/reinsert
  std::string loc1 = g.locText();
  std::string def1 = g.defText();
  // Funcdata::opUnsetOutput -> VarnodeBank::makeFree(out2): the legal path
  // under key drift (erase via the stored lociter/defiter).
  g.unsetOutput(d2);
  std::string loc2 = g.locText();
  std::string def2 = g.defText();
  std::cout << "case=makefree_inplace_key_drift"
            << "|loc0=" << loc0 << "|def0=" << def0
            << "|loc1=" << loc1 << "|def1=" << def1
            << "|loc2=" << loc2 << "|def2=" << def2
            << "|out2_free=" << (out2->isFree() ? 1 : 0)
            << "|out2_insert=" << ((out2->getFlags() & Varnode::insert) != 0 ? 1 : 0)
            << "|out2_input=" << (out2->isInput() ? 1 : 0)
            << "|out2_members=" << g.locMembers(out2) << ',' << g.defMembers(out2)
            << ',' << g.locMembers(out2) << ',' << g.defMembers(out2)
            << ',' << g.locMembers(out2) << ',' << g.defMembers(out2) << '\n';
}

// After a full write/free transition cycle the Varnode must be removable
// from both trees: opUnsetOutput -> makeFree (insert flag cleared), then
// Funcdata::destroyVarnode -> VarnodeBank::destroy drops it entirely.
static void runDestroyAfterTransitions(FixtureArchitecture &arch)
{
  Graph g(arch, "destroy_after_transitions", 0x5a00);
  BlockBasic *b0 = g.makeBlock();
  Varnode *c8 = g.constant("c8", 8, 5);
  PcodeOp *e = g.makeOp("E", CPUI_COPY, 1);
  g.setInput(e, c8, 0);
  Varnode *out3 = g.regFree("out3", 0x140, 4);
  g.setOutput(e, out3);
  g.insertEnd(e, b0);
  std::string loc0 = g.locText();
  std::string def0 = g.defText();
  g.unsetOutput(e);
  std::string loc1 = g.locText();
  std::string def1 = g.defText();
  int4 free1 = out3->isFree() ? 1 : 0;
  int4 insert1 = (out3->getFlags() & Varnode::insert) != 0 ? 1 : 0;
  int4 members1a = g.locMembers(out3);
  int4 members1b = g.defMembers(out3);
  g.setOutput(e, out3); // rebind after the free window
  int4 written2 = out3->isWritten() ? 1 : 0;
  g.fd.opDestroy(e);   // destroyVarnode(out3) -> VarnodeBank::destroy
  std::string loc2 = g.locText();
  std::string def2 = g.defText();
  std::cout << "case=destroy_after_transitions"
            << "|loc0=" << loc0 << "|def0=" << def0
            << "|loc1=" << loc1 << "|def1=" << def1
            << "|out3_free1=" << free1 << "|out3_insert1=" << insert1
            << "|out3_members1=" << members1a << ',' << members1b
            << "|out3_written2=" << written2
            << "|loc2=" << loc2 << "|def2=" << def2
            << "|out3_members2=" << g.locMembers(out3) << ',' << g.defMembers(out3)
            << '\n';
}

// Boundary: opSetOutput with the Varnode that is already the op's output is
// the cc:117 early return; no makeFree, no setDef, unchanged trees.
static void runRebindSameOutputNoop(FixtureArchitecture &arch)
{
  Graph g(arch, "rebind_same_output_noop", 0x5b00);
  BlockBasic *b0 = g.makeBlock();
  Varnode *c8 = g.constant("c8", 8, 5);
  PcodeOp *f = g.makeOp("F", CPUI_COPY, 1);
  g.setInput(f, c8, 0);
  Varnode *out4 = g.regFree("out4", 0x160, 4);
  g.setOutput(f, out4);
  g.insertEnd(f, b0);
  std::string loc0 = g.locText();
  std::string def0 = g.defText();
  int4 def0order = out4->getDef()->getSeqNum().getOrder();
  g.setOutput(f, out4); // same-output early return
  std::string loc1 = g.locText();
  std::string def1 = g.defText();
  std::cout << "case=rebind_same_output_noop"
            << "|loc0=" << loc0 << "|def0=" << def0
            << "|loc1=" << loc1 << "|def1=" << def1
            << "|out4_def0=" << def0order
            << "|out4_def1=" << out4->getDef()->getSeqNum().getOrder()
            << "|out4_members=" << g.locMembers(out4) << ',' << g.defMembers(out4)
            << ',' << g.locMembers(out4) << ',' << g.defMembers(out4) << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=VARNODE-BANK-KEY-LIVE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    runOpSetOutputSwap(arch);
    runMakeFreeInPlaceKeyDrift(arch);
    runDestroyAfterTransitions(arch);
    runRebindSameOutputNoop(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
