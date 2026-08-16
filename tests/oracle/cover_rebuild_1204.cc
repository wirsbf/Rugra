/*
 * COVER-REBUILD-SELFLOCK-0001: locked Ghidra 12.0.4 Varnode::updateCover /
 * Cover::rebuild / addDefPoint / addRefPoint / addRefRecurse oracle.
 *
 * The fixture builds synthetic def-use/CFG graphs through the production
 * Funcdata APIs and observes the complete rebuilt Cover, the coverdirty flag
 * lifecycle, and the descendant list after updateCover.  Case
 * slot2_selfref_double reproduces the production self-lock topology: the
 * Varnode whose Cover is rebuilt is itself MULTIEQUAL input slot 2 (and slot
 * 1) of a reader in a join block.  Case implied_multiequal_reader drives a
 * MULTIEQUAL reader of an implied intermediate output whose slots never hold
 * the rebuild root, pinning the root-vs-current identity of the addRefPoint
 * MULTIEQUAL slot match.
 */

#include <bits/stdc++.h>

// Test-only access is required to read Varnode::cover / Cover::cover and to
// set Varnode flags directly, matching what production Ghidra reaches through
// friend-only Funcdata/VarnodeBank APIs.
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

// Render a CoverBlock endpoint the way CoverBlock::print classifies it: the
// begin sentinel and the input marker collapse to "b", the end sentinel to
// "e", anything else is the SeqNum order.  Printing the classification plus
// the numeric order keeps the observation byte-comparable without relying on
// the host's pointer-valued sentinels.
static std::string endpoint(uintm uindex)
{
  if (uindex == (uintm)0)
    return "b";
  if (uindex == ~((uintm)0))
    return "e";
  std::ostringstream out;
  out << uindex;
  return out.str();
}

class Graph {
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  std::map<PcodeOp *, std::string> opNames;
  std::vector<PcodeOp *> opOrder;
  std::vector<BlockBasic *> blockIndices;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const std::string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), nextOffset(0) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    // Production assigns FlowBlock::index via BlockGraph::findSpanningTree
    // reverse post-order (block.cc:1081), which this fixture does not run.
    // Assign creation-order indices as a deterministic, distinct precondition
    // matching the Rust comparand's explicit BlockBasic index argument.
    block->index = static_cast<int4>(blockIndices.size());
    blockIndices.push_back(block);
    return block;
  }

  void edge(BlockBasic *from, BlockBasic *to)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.addEdge(from, to);
  }

  PcodeOp *makeOp(const std::string &name, OpCode opcode, int4 inputs)
  {
    Address pc(ram, fd.getAddress().getOffset() + (uintb)nextOffset);
    nextOffset += 1;
    PcodeOp *op = fd.newOp(inputs, pc);
    fd.opSetOpcode(op, opcode);
    opNames.insert(std::make_pair(op, name));
    opOrder.push_back(op);
    return op;
  }

  Varnode *uniqueOut(int4 size, PcodeOp *op)
  {
    return fd.newUniqueOut(size, op);
  }

  Varnode *constant(int4 size, uintb value)
  {
    return fd.newConstant(size, value);
  }

  Varnode *input(const std::string &, uintb offset, int4 size)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    return fd.setInputVarnode(vn);
  }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot)
  {
    fd.opSetInput(op, vn, slot);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block)
  {
    fd.opInsertEnd(op, block);
  }

  void observe(const std::string &caseName, Varnode *root)
  {
    uint4 dirtyBefore = root->getFlags() & Varnode::coverdirty;
    root->updateCover();
    uint4 dirtyAfter = root->getFlags() & Varnode::coverdirty;
    root->updateCover();
    std::string defOrder = std::string("-");
    if (root->getDef() != (PcodeOp *)0)
      defOrder = std::to_string(root->getDef()->getSeqNum().getOrder());
    std::ostringstream desc;
    desc << '[';
    bool first = true;
    for (std::list<PcodeOp *>::const_iterator iter = root->beginDescend();
         iter != root->endDescend(); ++iter) {
      if (!first) desc << ',';
      first = false;
      desc << opNames[*iter];
    }
    desc << ']';
    std::ostringstream slots;
    slots << '[';
    first = true;
    for (std::list<PcodeOp *>::const_iterator iter = root->beginDescend();
         iter != root->endDescend(); ++iter) {
      PcodeOp *op = *iter;
      for (int4 slot = 0; slot < op->numInput(); ++slot) {
        if (op->getIn(slot) == root) {
          if (!first) slots << ',';
          first = false;
          slots << opNames[op] << '.' << slot;
        }
      }
    }
    slots << ']';
    std::ostringstream orders;
    orders << '[';
    first = true;
    for (std::vector<PcodeOp *>::const_iterator iter = opOrder.begin();
         iter != opOrder.end(); ++iter) {
      if (!first) orders << ',';
      first = false;
      orders << opNames[*iter] << '=' << (*iter)->getSeqNum().getOrder();
    }
    orders << ']';
    std::cout << "case=" << caseName
              << "|dirty_before=" << (dirtyBefore != 0 ? 1 : 0)
              << "|dirty_after=" << (dirtyAfter != 0 ? 1 : 0)
              << "|has_cover=" << (root->hasCover() ? 1 : 0)
              << "|cover_object=" << (root->cover != (Cover *)0 ? 1 : 0)
              << "|input=" << (root->isInput() ? 1 : 0)
              << "|written=" << (root->isWritten() ? 1 : 0)
              << "|implied=" << (root->isImplied() ? 1 : 0)
              << "|def_order=" << defOrder
              << "|desc=" << desc.str()
              << "|slots=" << slots.str()
              << "|orders=" << orders.str()
              << "|cover=" << coverText(root) << '\n';
  }

  static std::string coverText(Varnode *root)
  {
    if (root->cover == (Cover *)0)
      return "[null]";
    std::ostringstream out;
    out << '[';
    bool first = true;
    for (std::map<int4, CoverBlock>::const_iterator iter = root->cover->begin();
         iter != root->cover->end(); ++iter) {
      if (!first) out << ',';
      first = false;
      out << (*iter).first << ':'
          << endpoint(CoverBlock::getUIndex((*iter).second.getStart())) << '-'
          << endpoint(CoverBlock::getUIndex((*iter).second.getStop()));
    }
    out << ']';
    return out.str();
  }
};

static void runInputRoot(FixtureArchitecture &arch)
{
  Graph g(arch, "input_root", 0x5000);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0, b1);
  Varnode *i0 = g.input("i0", 0x28, 4);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *r1 = g.makeOp("r1", CPUI_INT_ADD, 2);
  g.setInput(r1, i0, 0);
  g.setInput(r1, c4, 1);
  g.uniqueOut(4, r1);
  g.insertEnd(r1, b1);
  i0->calcCover();
  g.observe("input_root", i0);
}

static void runPhiPredecessorFill(FixtureArchitecture &arch)
{
  Graph g(arch, "phi_predecessor_fill", 0x5100);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b0, b2);
  g.edge(b2, b1);
  Varnode *i0 = g.input("i0", 0x30, 4);
  Varnode *i1 = g.input("i1", 0x34, 4);
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 2);
  g.setInput(m, i1, 0);
  g.setInput(m, i0, 1);
  g.uniqueOut(4, m);
  g.insertEnd(m, b1);
  i0->calcCover();
  g.observe("phi_predecessor_fill", i0);
}

static void runDefinedLinear(FixtureArchitecture &arch)
{
  Graph g(arch, "defined_linear", 0x5200);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0, b1);
  Varnode *c8 = g.constant(8, 0x1122334455667788LL);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *d = g.makeOp("d", CPUI_COPY, 1);
  g.setInput(d, c8, 0);
  Varnode *root = g.uniqueOut(8, d);
  g.insertEnd(d, b0);
  PcodeOp *r1 = g.makeOp("r1", CPUI_INT_OR, 2);
  g.setInput(r1, root, 0);
  g.setInput(r1, c4, 1);
  g.uniqueOut(8, r1);
  g.insertEnd(r1, b0);
  PcodeOp *r2 = g.makeOp("r2", CPUI_INT_MULT, 2);
  g.setInput(r2, root, 0);
  g.setInput(r2, c4, 1);
  g.uniqueOut(8, r2);
  g.insertEnd(r2, b1);
  root->calcCover();
  g.observe("defined_linear", root);
}

static void runSlot2SelfRefDouble(FixtureArchitecture &arch)
{
  Graph g(arch, "slot2_selfref_double", 0x5300);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  BlockBasic *b3 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b0, b2);
  g.edge(b1, b3);
  g.edge(b2, b3);
  g.edge(b0, b3);
  Varnode *c8 = g.constant(8, 5);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *d = g.makeOp("d", CPUI_COPY, 1);
  g.setInput(d, c8, 0);
  Varnode *root = g.uniqueOut(8, d);
  g.insertEnd(d, b0);
  PcodeOp *r1 = g.makeOp("r1", CPUI_INT_ADD, 2);
  g.setInput(r1, root, 0);
  g.setInput(r1, c4, 1);
  g.uniqueOut(8, r1);
  g.insertEnd(r1, b1);
  PcodeOp *r2 = g.makeOp("r2", CPUI_INT_XOR, 2);
  g.setInput(r2, root, 0);
  g.setInput(r2, root, 1);
  g.uniqueOut(8, r2);
  g.insertEnd(r2, b2);
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 3);
  g.setInput(m, r1->getOut(), 0);
  g.setInput(m, root, 1);
  g.setInput(m, root, 2);
  g.uniqueOut(8, m);
  g.insertEnd(m, b3);
  root->calcCover();
  g.observe("slot2_selfref_double", root);
}

static void runSlot2Single(FixtureArchitecture &arch)
{
  Graph g(arch, "slot2_single", 0x5400);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  BlockBasic *b3 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b0, b2);
  g.edge(b1, b3);
  g.edge(b2, b3);
  g.edge(b0, b3);
  Varnode *c8 = g.constant(8, 5);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *d = g.makeOp("d", CPUI_COPY, 1);
  g.setInput(d, c8, 0);
  Varnode *root = g.uniqueOut(8, d);
  g.insertEnd(d, b0);
  PcodeOp *r1 = g.makeOp("r1", CPUI_INT_ADD, 2);
  g.setInput(r1, root, 0);
  g.setInput(r1, c4, 1);
  g.uniqueOut(8, r1);
  g.insertEnd(r1, b1);
  PcodeOp *r2 = g.makeOp("r2", CPUI_INT_XOR, 2);
  g.setInput(r2, root, 0);
  g.setInput(r2, c4, 1);
  g.uniqueOut(8, r2);
  g.insertEnd(r2, b2);
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 3);
  g.setInput(m, r1->getOut(), 0);
  g.setInput(m, c4, 1);
  g.setInput(m, root, 2);
  g.uniqueOut(8, m);
  g.insertEnd(m, b3);
  root->calcCover();
  g.observe("slot2_single", root);
}

static void runImpliedChain(FixtureArchitecture &arch)
{
  Graph g(arch, "implied_chain", 0x5500);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0, b1);
  Varnode *c8 = g.constant(8, 5);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *d = g.makeOp("d", CPUI_COPY, 1);
  g.setInput(d, c8, 0);
  Varnode *root = g.uniqueOut(8, d);
  g.insertEnd(d, b0);
  PcodeOp *r1 = g.makeOp("r1", CPUI_INT_AND, 2);
  g.setInput(r1, root, 0);
  g.setInput(r1, c4, 1);
  Varnode *t1 = g.uniqueOut(8, r1);
  g.insertEnd(r1, b0);
  t1->setImplied();
  PcodeOp *r2 = g.makeOp("r2", CPUI_INT_OR, 2);
  g.setInput(r2, t1, 0);
  g.setInput(r2, c4, 1);
  g.uniqueOut(8, r2);
  g.insertEnd(r2, b1);
  root->calcCover();
  g.observe("implied_chain", root);
}

static void runImpliedMultiequalReader(FixtureArchitecture &arch)
{
  Graph g(arch, "implied_multiequal_reader", 0x5800);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  BlockBasic *b3 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b0, b2);
  g.edge(b1, b3);
  g.edge(b2, b3);
  g.edge(b0, b3);
  Varnode *c8 = g.constant(8, 5);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *d = g.makeOp("d", CPUI_COPY, 1);
  g.setInput(d, c8, 0);
  Varnode *root = g.uniqueOut(8, d);
  g.insertEnd(d, b0);
  PcodeOp *r1 = g.makeOp("r1", CPUI_INT_AND, 2);
  g.setInput(r1, root, 0);
  g.setInput(r1, c4, 1);
  Varnode *t1 = g.uniqueOut(8, r1);
  g.insertEnd(r1, b1);
  t1->setImplied();
  PcodeOp *r2 = g.makeOp("r2", CPUI_INT_XOR, 2);
  g.setInput(r2, root, 0);
  g.setInput(r2, c4, 1);
  g.uniqueOut(8, r2);
  g.insertEnd(r2, b2);
  // No slot of m holds root: only the implied intermediate t1 and constants.
  // Cover::rebuild passes the ROOT to addRefPoint even when descending from
  // the implied t1 (cover.cc:490), so the MULTIEQUAL slot match at
  // cover.cc:606 must find no slot and recurse through no predecessor.
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 3);
  g.setInput(m, t1, 0);
  g.setInput(m, c4, 1);
  g.setInput(m, c4, 2);
  g.uniqueOut(8, m);
  g.insertEnd(m, b3);
  root->calcCover();
  g.observe("implied_multiequal_reader", root);
}

static void runDirtyFlagCycle(FixtureArchitecture &arch)
{
  Graph g(arch, "dirty_flag_cycle", 0x5600);
  BlockBasic *b0 = g.makeBlock();
  Varnode *c8 = g.constant(8, 5);
  PcodeOp *d = g.makeOp("d", CPUI_COPY, 1);
  g.setInput(d, c8, 0);
  Varnode *root = g.uniqueOut(8, d);
  g.insertEnd(d, b0);
  root->calcCover();
  g.observe("dirty_flag_cycle", root);
}

static void runNoCoverObject(FixtureArchitecture &arch)
{
  Graph g(arch, "no_cover_object", 0x5700);
  BlockBasic *b0 = g.makeBlock();
  Varnode *c8 = g.constant(8, 5);
  PcodeOp *d = g.makeOp("d", CPUI_COPY, 1);
  g.setInput(d, c8, 0);
  Varnode *root = g.uniqueOut(8, d);
  g.insertEnd(d, b0);
  // hasCover() holds, but no Cover object exists yet; the dirty bit is set
  // directly the way production mutations do before a Cover is allocated.
  root->setFlags(Varnode::coverdirty);
  g.observe("no_cover_object", root);
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=COVER-REBUILD-SELFLOCK-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    runInputRoot(arch);
    runPhiPredecessorFill(arch);
    runDefinedLinear(arch);
    runSlot2SelfRefDouble(arch);
    runSlot2Single(arch);
    runImpliedChain(arch);
    runImpliedMultiequalReader(arch);
    runDirtyFlagCycle(arch);
    runNoCoverObject(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
