/*
 * HERITAGE-FLAGFREE-SSA-0001: locked Ghidra 12.0.4 oracle for the SLEIGH
 * BOOL flag/byte free-read SSA-ification chain.
 *
 * Production shape (x86-64 SLEIGH jcc semantics): a conditional branch
 * compiles to BOOL_NEGATE/BOOL_OR/BOOL_AND reading the raw 1-byte flag
 * registers of the register space (and SLEIGH unique temporaries), each
 * read being a FRESH free Varnode with exactly one descendant
 * (PcodeEmitFd::dump -> Funcdata::newVarnode -> VarnodeBank::create,
 * varnode.cc:1250-1258). Varnode::addDescend (varnode.cc:330-338) throws
 * "Free varnode has multiple descendants" for that state, so Heritage must
 * SSA-ify every such read BEFORE the cast phase: heritage()'s candidate
 * collection keeps free-with-descendant Varnodes (heritage.cc:2704), collect
 * puts them on the read list (cc:340-341), guard marks them active
 * (cc:1164-1175) and renameRecurse replaces them with the dominating write
 * or a promoted input and deletes the consumed free (cc:2493-2521).
 *
 * The fixture drives ONE `fd.opHeritage()` boundary call per case and
 * observes the complete post-pass projection:
 *
 *   - bool_in: the descriptor of the BOOL op's flag input after rename
 *     (written+defining-opcode, promoted input, or phi output),
 *   - free_with_reader: count of remaining free Varnodes WITH descendants
 *     over the whole bank (the varnode.cc:334-336 throw precondition —
 *     must be 0 for the heritaged spaces),
 *   - full op list with per-slot input descriptors,
 *   - phi projection (case C),
 *   - sorted Varnode descriptor multiset.
 *
 * Cases:
 *   flagfree_bool_read_written   flag written (INT_SUB -> reg 0x206:1) then
 *                                read by BOOL_NEGATE (jne on ZF form); the
 *                                read links to the write.
 *   flagfree_bool_read_unwritten read before any write (function entry
 *                                condition); empty-stack input promotion
 *                                (cc:2499-2502).
 *   flagfree_bool_diamond        two-arm flag writes merged at a join whose
 *                                BOOL read takes the MULTIEQUAL output
 *                                (cc:2631-2642 + cc:2531-2552).
 *
 * Architecture/compiler spec/prestate mirror the ADT-RENAME fixture: the
 * synthetic blocks have no cover so MULTIEQUAL SeqNums are null-pc.
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

// Test-only observation shim (same contract as the ADT-RENAME fixture):
// re-declares the locked-oracle member sequence of Funcdata (funcdata.hh:57-95)
// to reach the Heritage member for `heritage.buildInfoList()` (funcdata.cc:166).
// Layout pinned to oracle commit e40ed13014025f82488b1f8f7bca566894ac376b,
// verified by the runner.
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

static const char *opcodeName(OpCode opc)
{
  switch (opc) {
  case CPUI_COPY: return "COPY";
  case CPUI_INT_ADD: return "INT_ADD";
  case CPUI_INT_SUB: return "INT_SUB";
  case CPUI_INT_OR: return "INT_OR";
  case CPUI_BOOL_NEGATE: return "BOOL_NEGATE";
  case CPUI_BOOL_AND: return "BOOL_AND";
  case CPUI_BOOL_OR: return "BOOL_OR";
  case CPUI_CBRANCH: return "CBRANCH";
  case CPUI_MULTIEQUAL: return "MULTIEQUAL";
  default: return "OTHER";
  }
}

// Varnode descriptor shared with the Rust comparand:
//   constant  -> C<size>:<hex-value>
//   register  -> R<hex-offset>:<size>:<I|W|F>[+<def-opcode>]
//   unique    -> U<size>:<I|W|F>[+<def-opcode>]
static std::string vnDescriptor(const Varnode *vn)
{
  std::ostringstream out;
  AddrSpace *spc = vn->getSpace();
  if (vn->isConstant()) {
    out << 'C' << vn->getSize() << ':' << hex << vn->getOffset() << dec;
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
  if (code == 'R' || code == 'S' || code == 'M') {
    out << hex << vn->getOffset() << dec << ':' << vn->getSize();
  }
  else {
    out << vn->getSize();
  }
  out << ':';
  if (vn->isInput())
    out << 'I';
  else if (vn->isWritten()) {
    out << 'W' << '+' << opcodeName(vn->getDef()->code());
  }
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
    return blocks.newBlockBasic(&fd);
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

  Varnode *uniqueOut(int4 size, PcodeOp *op) { return fd.newUniqueOut(size, op); }

  Varnode *constant(int4 size, uintb value) { return fd.newConstant(size, value); }

  // PcodeEmitFd::dump read form (funcdata.cc:878-908): every input is a
  // FRESH free Varnode per reference — the single-descendant invariant the
  // flag reads arrive with.
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

  void setInput(PcodeOp *op, Varnode *vn, int4 slot) { fd.opSetInput(op, vn, slot); }

  void insertEnd(PcodeOp *op, BlockBasic *block) { fd.opInsertEnd(op, block); }

  // Production pre-state: structureReset (loop structure + forward
  // dominators) then startProcessing's heritage.buildInfoList
  // (funcdata.cc:166).
  void prepareStructure(void)
  {
    vector<FlowBlock *> rootlist;
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.structureLoops(rootlist);
    blocks.calcForwardDominator(rootlist);
    heritageOf(fd).buildInfoList();
  }

  int4 opCountAll(void)
  {
    int4 count = 0;
    for (PcodeOpTree::const_iterator iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
      if (!(*iter).second->isDead())
        count += 1;
    }
    return count;
  }

  std::string opList(void)
  {
    std::ostringstream out;
    bool first = true;
    for (PcodeOpTree::const_iterator iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
      const PcodeOp *op = (*iter).second;
      if (op->isDead())
        continue;
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

  // Whole-bank free-with-descendant census: the varnode.cc:334-336 throw
  // precondition over ALL spaces (annotation/constant excepted).
  int4 freeWithReader(void)
  {
    int4 count = 0;
    for (VarnodeLocSet::const_iterator iter = fd.beginLoc(); iter != fd.endLoc(); ++iter) {
      const Varnode *vn = *iter;
      if (vn->isConstant() || vn->isAnnotation())
        continue;
      if (vn->isFree() && !vn->hasNoDescend())
        count += 1;
    }
    return count;
  }

  std::string vnMultiset(void)
  {
    std::vector<std::string> parts;
    for (VarnodeLocSet::const_iterator iter = fd.beginLoc(); iter != fd.endLoc(); ++iter) {
      const Varnode *vn = *iter;
      if (vn->isAnnotation())
        continue;
      parts.push_back(vnDescriptor(vn));
    }
    std::sort(parts.begin(), parts.end());
    std::ostringstream out;
    for (size_t i = 0; i < parts.size(); ++i) {
      if (i != 0)
        out << ',';
      out << parts[i];
    }
    return out.str();
  }

  std::string phiProjection(void)
  {
    std::ostringstream out;
    const BlockGraph &blocks = fd.getBasicBlocks();
    bool first = true;
    for (int4 b = 0; b < blocks.getSize(); ++b) {
      const BlockBasic *bl = (const BlockBasic *)blocks.getBlock(b);
      int4 pos = 0;
      for (list<PcodeOp *>::const_iterator oiter = bl->beginOp(); oiter != bl->endOp(); ++oiter, ++pos) {
        const PcodeOp *op = *oiter;
        if (op->code() != CPUI_MULTIEQUAL)
          continue;
        if (!first)
          out << ';';
        first = false;
        out << "b" << b << "@p" << pos << '(';
        const Varnode *outvn = op->getOut();
        out << vnDescriptor(outvn);
        out << ")[";
        for (int4 j = 0; j < op->numInput(); ++j) {
          if (j != 0)
            out << ',';
          const FlowBlock *pred = bl->getIn(j);
          out << 's' << j << '<' << vnDescriptor(op->getIn(j))
              << ">#p" << pred->getIndex();
        }
        out << ']';
      }
    }
    return out.str();
  }
};

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);

  FixtureArchitecture arch;

  std::cout << "schema=1|fixture=HERITAGE-FLAGFREE-SSA-0001|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // ---- case A: flag written then read (jne-on-ZF form) ----
  {
    Graph g(arch, "flagfree_written", 0x1000);
    BlockBasic *b0 = g.makeBlock();

    PcodeOp *w = g.makeOp("w", CPUI_INT_SUB, 2);
    g.setInput(w, g.constant(1, 0x0), 0);
    g.setInput(w, g.constant(1, 0x1), 1);
    g.writtenRegister(0x206, 1, w);
    g.insertEnd(w, b0);

    PcodeOp *n = g.makeOp("n", CPUI_BOOL_NEGATE, 1);
    g.setInput(n, g.freeRegister(0x206, 1), 0);
    g.uniqueOut(1, n);
    g.insertEnd(n, b0);

    PcodeOp *c = g.makeOp("c", CPUI_CBRANCH, 2);
    g.setInput(c, g.constant(8, 0x2000), 0);
    g.setInput(c, n->getOut(), 1);
    g.insertEnd(c, b0);

    g.prepareStructure();
    g.fd.opHeritage();

    const Varnode *boolIn = n->getIn(0);
    std::cout << "case=flagfree_bool_read_written"
              << "|pass=" << g.fd.getHeritagePass()
              << "|ops=" << g.opCountAll()
              << "|bool_in=" << vnDescriptor(boolIn)
              << "|free_with_reader=" << g.freeWithReader()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }

  // ---- case B: read before any write (entry condition) ----
  {
    Graph g(arch, "flagfree_unwritten", 0x2000);
    BlockBasic *b0 = g.makeBlock();

    PcodeOp *n = g.makeOp("n", CPUI_BOOL_NEGATE, 1);
    g.setInput(n, g.freeRegister(0x207, 1), 0);
    g.uniqueOut(1, n);
    g.insertEnd(n, b0);

    PcodeOp *c = g.makeOp("c", CPUI_CBRANCH, 2);
    g.setInput(c, g.constant(8, 0x3000), 0);
    g.setInput(c, n->getOut(), 1);
    g.insertEnd(c, b0);

    g.prepareStructure();
    g.fd.opHeritage();

    const Varnode *boolIn = n->getIn(0);
    std::cout << "case=flagfree_bool_read_unwritten"
              << "|pass=" << g.fd.getHeritagePass()
              << "|ops=" << g.opCountAll()
              << "|bool_in=" << vnDescriptor(boolIn)
              << "|free_with_reader=" << g.freeWithReader()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }

  // ---- case C: two-arm flag writes merged at a join ----
  {
    Graph g(arch, "flagfree_diamond", 0x3000);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    BlockBasic *b2 = g.makeBlock();
    BlockBasic *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b0, b2);
    g.edge(b1, b3);
    g.edge(b2, b3);

    PcodeOp *w1 = g.makeOp("w1", CPUI_INT_SUB, 2);
    g.setInput(w1, g.constant(1, 0x2), 0);
    g.setInput(w1, g.constant(1, 0x3), 1);
    g.writtenRegister(0x206, 1, w1);
    g.insertEnd(w1, b1);

    PcodeOp *w2 = g.makeOp("w2", CPUI_INT_OR, 2);
    g.setInput(w2, g.constant(1, 0x4), 0);
    g.setInput(w2, g.constant(1, 0x5), 1);
    g.writtenRegister(0x206, 1, w2);
    g.insertEnd(w2, b2);

    PcodeOp *n = g.makeOp("n", CPUI_BOOL_NEGATE, 1);
    g.setInput(n, g.freeRegister(0x206, 1), 0);
    g.uniqueOut(1, n);
    g.insertEnd(n, b3);

    PcodeOp *c = g.makeOp("c", CPUI_CBRANCH, 2);
    g.setInput(c, g.constant(8, 0x4000), 0);
    g.setInput(c, n->getOut(), 1);
    g.insertEnd(c, b3);

    g.prepareStructure();
    g.fd.opHeritage();

    const Varnode *boolIn = n->getIn(0);
    std::cout << "case=flagfree_bool_diamond"
              << "|pass=" << g.fd.getHeritagePass()
              << "|ops=" << g.opCountAll()
              << "|bool_in=" << vnDescriptor(boolIn)
              << "|free_with_reader=" << g.freeWithReader()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }
  return 0;
}
