/*
 * HERITAGE-OWNERSHIP-0001: locked Ghidra 12.0.4 Funcdata::opHeritage /
 * Heritage::heritage ownership-boundary oracle.
 *
 * The fixture drives THREE consecutive `fd.opHeritage()` boundary calls
 * (pass 0 -> 1 -> 2 -> 3) on the same Funcdata through the production
 * wrapper (funcdata.hh:462 -> Heritage::heritage, heritage.cc:2663-2758)
 * and observes the ownership-boundary state after every pass: the pass
 * counter (public Funcdata::getHeritagePass, funcdata.hh:231) and, for the
 * inert SSA cases, the complete op-list / Varnode-bank projection through
 * the public PcodeOpBank/VarnodeBank iteration APIs.
 *
 * Observation-scope note (mirrored in the metadata envelope): the Ghidra
 * classes Funcdata and Heritage declare their state members in the
 * UNLABELED default-private access region, so a `#define private public`
 * fixture shim cannot expose `Heritage::maxdepth` / `globaldisjoint`.
 * Those fields are therefore Rust-asserted in the comparand fixture and
 * source-verified here (heritage.cc:218-224 ctor maxdepth=-1;
 * heritage.cc:2676-2772 rebuilds the ADT exactly when maxdepth==-1, i.e.
 * once at pass 1, and LocationMap merges are content-identical); they are
 * not part of the byte-compared stdout.
 *
 * Cases:
 *   empty_entry           one entry block, no IR; proves the pass counter
 *                         advances exactly once per boundary call and the
 *                         IR is untouched.
 *   register_free_promote a free register read SSA'd by canonical rename
 *                         (input promotion + def-use rewiring + free
 *                         deletion); full byte-compared state projection.
 *   phi_cycle_selfref     MULTIEQUAL self-reference cycle (cover-fixture
 *                         slot2 topology with a loop-carried def-use cycle
 *                         m_out -> r -> t3 -> m). Restricted projection:
 *                         this is the no-hang witness; Rugra's
 *                         placeMultiequals still places a redundant
 *                         parentless phi here (registered
 *                         HERITAGE-ADT-RENAME-0001), so the op/vn
 *                         projection is not byte-compared yet.
 */

#include <bits/stdc++.h>

#include "architecture.hh"
#include "cover.hh"
#include "database.hh"
#include "funcdata.hh"
#include "heritage.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"

using namespace ghidra;

// Test-only observation shim. Funcdata's private section is an UNLABELED
// default-private region, so the `#define private public` trick used by
// other fixtures cannot expose `fd.heritage`. This shim re-declares the
// exact locked-oracle member sequence of Funcdata (funcdata.hh:57-95) in
// the same order with the same complete types, so a reinterpret_cast can
// reach the Heritage member to perform the one production startProcessing
// step a synthetic-graph fixture cannot reach otherwise:
// `heritage.buildInfoList()` (funcdata.cc:166). Layout is pinned to oracle
// commit e40ed13014025f82488b1f8f7bca566894ac376b, verified by the runner.
struct FuncdataHeritageShim {
  uint4 flags;
  uint4 clean_up_index;
  uint4 high_level_index;
  uint4 cast_phase_index;
  uint4 minLanedSize;
  int4 size;
  Architecture *glb;
  FunctionSymbol *functionSymbol;
  string name;
  string displayName;
  Address baseaddr;
  FuncProto funcp;
  ScopeLocal *localmap;
  vector<FuncCallSpecs *> qlst;
  vector<JumpTable *> jumpvec;
  VarnodeBank vbank;
  PcodeOpBank obank;
  BlockGraph bblocks;
  BlockGraph sblocks;
  Heritage heritage;
};

static Heritage &heritageOf(Funcdata &fd)
{
  return reinterpret_cast<FuncdataHeritageShim *>(&fd)->heritage;
}

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

// Opcode abbreviation shared with the Rust comparand (both sides map their
// own enum; only the fixture's five opcodes are needed).
static const char *opcodeName(OpCode opc)
{
  switch (opc) {
  case CPUI_COPY: return "COPY";
  case CPUI_INT_ADD: return "INT_ADD";
  case CPUI_INT_OR: return "INT_OR";
  case CPUI_INT_MULT: return "INT_MULT";
  case CPUI_MULTIEQUAL: return "MULTIEQUAL";
  default: return "OTHER";
  }
}

// Varnode descriptor shared with the Rust comparand:
//   constant  -> C<size>
//   register  -> R<hex-offset>:<I|W|F>
//   unique    -> U<size>:<I|W|F>
//   stack     -> S<hex-offset>:<I|W|F>
//   ram       -> M<hex-offset>:<I|W|F>
// Absolute unique offsets are deliberately not printed (allocation bases
// differ between the two implementations); the identity-relevant state
// (size, def-use class) is.
static std::string vnDescriptor(const Varnode *vn)
{
  std::ostringstream out;
  AddrSpace *spc = vn->getSpace();
  if (vn->isConstant()) {
    out << 'C' << vn->getSize();
    return out.str();
  }
  char code = 'X';
  if (spc->getType() == IPTR_SPACEBASE)
    code = 'S';
  else if (spc->getName() == "register")
    code = 'R';
  else if (spc->getType() == IPTR_INTERNAL)
    code = 'U';
  else if (spc->getName() == "ram")
    code = 'M';
  out << code;
  if (code == 'R' || code == 'S' || code == 'M')
    out << hex << vn->getOffset() << dec;
  else
    out << vn->getSize();
  out << ':';
  if (vn->isInput())
    out << 'I';
  else if (vn->isWritten())
    out << 'W';
  else
    out << 'F';
  return out.str();
}

class Graph {
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  std::map<PcodeOp *, std::string> opNames;
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
    // The creation-order indices here are a deterministic, distinct
    // precondition matching the Rust comparand's explicit index argument.
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

  Varnode *freeRegister(uintb offset, int4 size)
  {
    return fd.newVarnode(size, Address(reg, offset));
  }

  Varnode *writtenRegister(uintb offset, int4 size, PcodeOp *op)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    fd.opSetOutput(op, vn);
    return op->getOut();
  }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot)
  {
    fd.opSetInput(op, vn, slot);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block)
  {
    fd.opInsertEnd(op, block);
  }

  // Production pre-state: Funcdata::structureReset (funcdata_block.cc:703)
  // computes loop structure + forward dominators before ActionHeritage;
  // those two BlockGraph steps are public and are applied directly here.
  void prepareStructure(void)
  {
    vector<FlowBlock *> rootlist;
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.structureLoops(rootlist);
    blocks.calcForwardDominator(rootlist);
    // startProcessing's heritage step (funcdata.cc:166): the per-space
    // HeritageInfo list is built BEFORE the first ActionHeritage pass.
    heritageOf(fd).buildInfoList();
  }

  // Three consecutive opHeritage boundary calls, recording the public pass
  // counter after each pass.
  void runThreePasses(int4 *passSeq)
  {
    prepareStructure();
    for (int4 i = 0; i < 3; ++i) {
      fd.opHeritage();
      passSeq[i] = fd.getHeritagePass();
    }
  }

  std::string opList(void)
  {
    std::ostringstream out;
    bool first = true;
    for (PcodeOpTree::const_iterator iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
      const PcodeOp *op = (*iter).second;
      if (!first)
        out << ';';
      first = false;
      std::map<PcodeOp *, std::string>::const_iterator name =
          opNames.find(const_cast<PcodeOp *>(op));
      out << (name == opNames.end() ? std::string("phi") : name->second)
          << '.' << opcodeName(op->code()) << '(';
      for (int4 slot = 0; slot < op->numInput(); ++slot) {
        if (slot != 0)
          out << ',';
        out << vnDescriptor(op->getIn(slot));
      }
      out << ')';
    }
    return out.str();
  }

  int4 opCount(void)
  {
    int4 count = 0;
    for (PcodeOpTree::const_iterator iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter)
      count += 1;
    return count;
  }

  std::string vnList(void)
  {
    std::vector<std::string> parts;
    for (VarnodeLocSet::const_iterator iter = fd.beginLoc(); iter != fd.endLoc(); ++iter)
      parts.push_back(vnDescriptor(*iter));
    std::sort(parts.begin(), parts.end());
    std::ostringstream out;
    for (size_t i = 0; i < parts.size(); ++i) {
      if (i != 0)
        out << ',';
      out << parts[i];
    }
    return out.str();
  }

  int4 vnCount(void)
  {
    int4 count = 0;
    for (VarnodeLocSet::const_iterator iter = fd.beginLoc(); iter != fd.endLoc(); ++iter)
      count += 1;
    return count;
  }
};

static void runEmptyEntry(FixtureArchitecture &arch)
{
  Graph g(arch, "empty_entry", 0x5000);
  g.makeBlock();
  int4 passSeq[3];
  g.runThreePasses(passSeq);
  std::cout << "case=empty_entry"
            << "|pass=" << passSeq[0] << ',' << passSeq[1] << ',' << passSeq[2]
            << "|ops=" << g.opCount()
            << "|vns=" << g.vnCount() << '\n';
}

static void runRegisterFreePromote(FixtureArchitecture &arch)
{
  Graph g(arch, "register_free_promote", 0x5100);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0, b1);
  // Two separate size-4 constants: Funcdata::opSetInput clones a constant
  // that already has a descendant (funcdata_op.cc opSetInput), so the two
  // readers get distinct constants exactly as raw p-code would.
  Varnode *c4a = g.constant(4, 7);
  Varnode *c4b = g.constant(4, 7);
  Varnode *c8 = g.constant(8, 5);
  // Raw p-code creates a distinct free Varnode per read of the same
  // register (Ghidra invariant: a free Varnode has at most one descendant,
  // varnode.cc addDescend).
  Varnode *f1 = g.freeRegister(0x30, 8);
  Varnode *f2 = g.freeRegister(0x30, 8);
  PcodeOp *d1 = g.makeOp("d1", CPUI_INT_ADD, 2);
  g.setInput(d1, f1, 0);
  g.setInput(d1, c4a, 1);
  g.writtenRegister(0x30, 8, d1);
  g.insertEnd(d1, b0);
  PcodeOp *w2 = g.makeOp("w2", CPUI_COPY, 1);
  g.setInput(w2, c8, 0);
  g.uniqueOut(8, w2);
  g.insertEnd(w2, b0);
  PcodeOp *r1 = g.makeOp("r1", CPUI_INT_OR, 2);
  g.setInput(r1, f2, 0);
  g.setInput(r1, c4b, 1);
  g.uniqueOut(8, r1);
  g.insertEnd(r1, b1);
  int4 passSeq[3];
  g.runThreePasses(passSeq);
  std::cout << "case=register_free_promote"
            << "|pass=" << passSeq[0] << ',' << passSeq[1] << ',' << passSeq[2]
            << "|ops=" << g.opCount()
            << "|oplist=" << g.opList()
            << "|vns=" << g.vnCount()
            << "|vnlist=" << g.vnList() << '\n';
}

static void runPhiCycleSelfRef(FixtureArchitecture &arch)
{
  Graph g(arch, "phi_cycle_selfref", 0x5200);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  BlockBasic *b3 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b1, b2);
  g.edge(b2, b1);
  g.edge(b2, b3);
  Varnode *c8 = g.constant(8, 5);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *d0 = g.makeOp("d0", CPUI_COPY, 1);
  g.setInput(d0, c8, 0);
  g.uniqueOut(8, d0);
  g.insertEnd(d0, b0);
  Varnode *f = g.freeRegister(0x28, 8);
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 2);
  Varnode *mOut = g.writtenRegister(0x28, 8, m);
  g.setInput(m, f, 0);
  PcodeOp *r = g.makeOp("r", CPUI_INT_ADD, 2);
  Varnode *t3 = g.writtenRegister(0x28, 8, r);
  g.setInput(r, mOut, 0);
  g.setInput(r, c4, 1);
  g.setInput(m, t3, 1);
  g.insertEnd(m, b1);
  g.insertEnd(r, b2);
  PcodeOp *o = g.makeOp("o", CPUI_INT_OR, 2);
  g.setInput(o, mOut, 0);
  g.setInput(o, c4, 1);
  g.uniqueOut(8, o);
  g.insertEnd(o, b3);
  int4 passSeq[3];
  g.runThreePasses(passSeq);
  // Restricted projection: the no-hang witness. Reaching this print proves
  // all three boundary calls returned on the phi self-reference cycle.
  std::cout << "case=phi_cycle_selfref"
            << "|pass=" << passSeq[0] << ',' << passSeq[1] << ',' << passSeq[2]
            << "|completed=1" << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=HERITAGE-OWNERSHIP-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    runEmptyEntry(arch);
    runRegisterFreePromote(arch);
    runPhiCycleSelfRef(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
