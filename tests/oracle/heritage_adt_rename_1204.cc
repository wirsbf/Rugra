/*
 * HERITAGE-ADT-RENAME-0001: locked Ghidra 12.0.4 placeMultiequals/rename
 * per-object phi oracle.
 *
 * The fixture drives THREE consecutive `fd.opHeritage()` boundary calls
 * (pass 0 -> 1 -> 2 -> 3) on the same Funcdata through the production
 * wrapper (funcdata.hh:462 -> Heritage::heritage, heritage.cc:2663-2758)
 * and observes, after the full sequence, the complete per-object phi
 * projection plus the whole op/Varnode projection:
 *
 *   - phi creation order and block-begin position (opInsertBegin of a
 *     MULTIEQUAL lands at index 0, so multiple phis of one merge block
 *     appear in REVERSE creation order — heritage.cc:2631-2642),
 *   - phi storage (address space + offset + size of the output and of
 *     every placeholder input, heritage.cc:2634/2638),
 *   - input identity after rename (which write/input feeds each slot,
 *     via the defining opcode in the descriptor),
 *   - the reverse-predecessor-slot mapping (phi slot j of the merge
 *     block reads the value flowing over the merge block's in-edge j —
 *     renameRecurse cc:2531-2552),
 *   - the phi-cycle old-marker skip (a loop-carried MULTIEQUAL input
 *     that is already written is NOT re-replaced, cc:2538).
 *
 * Cases:
 *   adt_diamond_phi   diamond CFG with three heritaged register ranges
 *                     (0x10:8, 0x20:4, 0x30:1) written on both arms and
 *                     free-read after the join; the GetStr block2/5 phi
 *                     form (phi at a join feeding a reader, both arm
 *                     writes wired by reverse predecessor slot).
 *   phi_cycle_oldmark ownership-fixture slot topology (b0->b1->b2->b1,
 *                     b2->b3) with a manually created MULTIEQUAL "m" and
 *                     a loop-carried write t3 feeding m's slot 1; full
 *                     projection (the HERITAGE-OWNERSHIP phi_cycle case
 *                     was restricted to a no-hang witness because Rugra
 *                     placed a redundant parentless phi there).
 *
 * Note: the synthetic blocks have no address-range cover, so
 * BlockBasic::getStart() returns the null Address (block.cc:2319-2326);
 * the MULTIEQUAL ops created by placeMultiequals therefore carry null-pc
 * SeqNums and sort first in the PcodeOpTree, ordered by creation uniq.
 * The Rust comparand mirrors this with start_addr = Address(0).
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

// Test-only observation shim (same contract as the ownership fixture):
// Funcdata's private section is an UNLABELED default-private region, so a
// `#define private public` shim cannot expose `fd.heritage`. This shim
// re-declares the exact locked-oracle member sequence of Funcdata
// (funcdata.hh:57-95) to reach the Heritage member for the one production
// startProcessing step a synthetic fixture cannot reach otherwise:
// `heritage.buildInfoList()` (funcdata.cc:166). Layout pinned to oracle
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

// Opcode abbreviation shared with the Rust comparand.
static const char *opcodeName(OpCode opc)
{
  switch (opc) {
  case CPUI_COPY: return "COPY";
  case CPUI_INT_ADD: return "INT_ADD";
  case CPUI_INT_OR: return "INT_OR";
  case CPUI_INT_MULT: return "INT_MULT";
  case CPUI_MULTIEQUAL: return "MULTIEQUAL";
  case CPUI_PIECE: return "PIECE";
  case CPUI_SUBPIECE: return "SUBPIECE";
  default: return "OTHER";
  }
}

// Varnode descriptor shared with the Rust comparand:
//   constant  -> C<size>
//   register  -> R<hex-offset>:<size>:<I|W|F>[+<def-opcode>]
//   unique    -> U<size>:<I|W|F>[+<def-opcode>]
// Written varnodes carry their defining opcode so the phi input identity
// (which arm's write feeds which slot) is observable.
static std::string vnDescriptor(const Varnode *vn)
{
  std::ostringstream out;
  AddrSpace *spc = vn->getSpace();
  if (vn->isConstant()) {
    // Constant VALUE is printed so same-size constants stay
    // distinguishable (the refine case's SUBPIECE offset constants 0/2
    // must differ for the within-group order witness).
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
    BlockBasic *block = blocks.newBlockBasic(&fd);
    // Creation-order indices (deterministic precondition matching the
    // Rust comparand's explicit index argument), as in the ownership
    // fixture: production assigns FlowBlock::index via findSpanningTree
    // reverse post-order, which this fixture does not run.
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

  // IOP-space Varnode aliasing an op pointer (PcodeOp::getOpFromConst
  // round-trips this address; op.hh/op.cc).
  Varnode *iopAlias(PcodeOp *target)
  {
    AddrSpace *iop = arch.getSpace(7);
    return fd.newVarnode(4, Address(iop, (uintb)(uintptr_t)target));
  }

  // Create, insert, then destroy an op so it stays in the bank (dead
  // list) but leaves its block — the dead-target state of cc:268-269.
  PcodeOp *deadTarget(BlockBasic *block)
  {
    PcodeOp *t = makeOp("t", CPUI_INT_ADD, 2);
    setInput(t, constant(4, 31), 0);
    setInput(t, constant(4, 33), 1);
    uniqueOut(8, t);
    insertEnd(t, block);
    fd.opDestroy(t);
    return t;
  }

  // INDIRECT marker with a 2-byte register output (previous-heritage
  // evidence smaller than its range) and an IOP input aliasing `target`.
  PcodeOp *indirectMarker(uintb offset, PcodeOp *target, BlockBasic *block)
  {
    PcodeOp *i = makeOp("i", CPUI_INDIRECT, 2);
    setInput(i, constant(4, 35), 0);
    setInput(i, iopAlias(target), 1);
    writtenRegister(offset, 2, i);
    insertEnd(i, block);
    return i;
  }

  // Production pre-state (as in the ownership fixture):
  // Funcdata::structureReset computes loop structure + forward
  // dominators before ActionHeritage, then startProcessing builds the
  // per-space HeritageInfo list (funcdata.cc:166).
  void prepareStructure(void)
  {
    vector<FlowBlock *> rootlist;
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.structureLoops(rootlist);
    blocks.calcForwardDominator(rootlist);
    heritageOf(fd).buildInfoList();
  }

  void runThreePasses(int4 *passSeq, void (*midPass1)(Graph &) = (void (*)(Graph &))0)
  {
    prepareStructure();
    for (int4 i = 0; i < 3; ++i) {
      fd.opHeritage();
      passSeq[i] = fd.getHeritagePass();
      // The revisit case injects previous-heritage markers between the
      // first and second boundary calls, mirroring the inter-Action state
      // that produces an OLD range with fresh free reads (cc:2708-2730).
      if (i == 0 && midPass1 != (void (*)(Graph &))0)
        midPass1(*this);
    }
  }

  std::string opList(void)
  {
    std::ostringstream out;
    bool first = true;
    for (PcodeOpTree::const_iterator iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
      const PcodeOp *op = (*iter).second;
      // Dead ops keep NULL input slots in the tree (funcdata_op.cc
      // opDestroy clears but does not erase them) — they are bank
      // internals, not live p-code, and are excluded from the projection
      // on both sides.
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

  int4 opCount(void)
  {
    int4 count = 0;
    for (PcodeOpTree::const_iterator iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter)
      count += 1;
    return count;
  }

  // Per-object phi projection: for every MULTIEQUAL still parented in a
  // block, in block index order and block op position order, print the
  // output storage, each input's descriptor, and — the
  // reverse-predecessor-slot witness — the index of the merge block's
  // in-edge j predecessor for phi slot j.
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
        AddrSpace *spc = outvn->getSpace();
        char code = 'X';
        if (spc->getName() == "register")
          code = 'R';
        else if (spc->getType() == IPTR_INTERNAL)
          code = 'U';
        out << code << hex << outvn->getOffset() << dec << ':' << outvn->getSize();
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

  int4 phiCount(void)
  {
    int4 count = 0;
    for (PcodeOpTree::const_iterator iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter)
      if ((*iter).second->code() == CPUI_MULTIEQUAL)
        count += 1;
    return count;
  }

  // Creation-order witness: MULTIEQUAL parent blocks in PcodeOpTree
  // (SeqNum/uniq) order, i.e. the order placeMultiequals created them.
  // The oracle's order comes from the depth-ordered PriorityQueue +
  // augment walk (calcMultiequals cc:2448-2463, visitIncr cc:2394-2428),
  // NOT from block index — this field distinguishes the two.
  std::string phiSeqOrder(void)
  {
    std::ostringstream out;
    bool first = true;
    for (PcodeOpTree::const_iterator iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
      const PcodeOp *op = (*iter).second;
      if (op->code() != CPUI_MULTIEQUAL)
        continue;
      if (!first)
        out << ',';
      first = false;
      out << op->getParent()->getIndex();
    }
    return out.str();
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

  // Per-block op-order witness: every parented op's label (fixture name
  // or opcode) in BLOCK LIST order. This is the decisive projection for
  // the concatPieces/splitPieces element-anchor insertion semantics
  // (heritage.cc:516-518/582-587/546/602): pieces keep CREATION order in
  // the block ([P1,P2,P3,X] / [W,S1,S2,S3,Y]); a fixed numeric index per
  // round would reverse them.
  std::string blockOpOrder(void)
  {
    std::ostringstream out;
    const BlockGraph &blocks = fd.getBasicBlocks();
    bool firstb = true;
    for (int4 b = 0; b < blocks.getSize(); ++b) {
      const BlockBasic *bl = (const BlockBasic *)blocks.getBlock(b);
      if (!firstb)
        out << ';';
      firstb = false;
      out << 'b' << b << '=';
      bool firstop = true;
      for (list<PcodeOp *>::const_iterator oiter = bl->beginOp(); oiter != bl->endOp(); ++oiter) {
        const PcodeOp *op = *oiter;
        if (!firstop)
          out << ',';
        firstop = false;
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
    }
    return out.str();
  }
};

// Diamond join: three register ranges written on both arms and free-read
// after the join. placeMultiequals must place one phi per range at the
// merge block beginning (reverse creation order in the block),
// calcMultiequals seeded by both arms' write blocks; rename wires slot j
// to the write of the merge block's in-edge j predecessor and points the
// join-block readers at the phi outputs.
static void runAdtDiamondPhi(FixtureArchitecture &arch)
{
  Graph g(arch, "adt_diamond_phi", 0x5300);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  BlockBasic *b3 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b0, b2);
  g.edge(b1, b3);
  g.edge(b2, b3);
  Varnode *c8 = g.constant(8, 5);
  PcodeOp *d0 = g.makeOp("d0", CPUI_COPY, 1);
  g.setInput(d0, c8, 0);
  g.uniqueOut(8, d0);
  g.insertEnd(d0, b0);
  // Arm 1: three writes (0x10:8 ADD, 0x20:4 MULT, 0x30:1 COPY), each
  // reading a distinct free of its own range.
  Varnode *f1a = g.freeRegister(0x10, 8);
  Varnode *f1b = g.freeRegister(0x20, 4);
  Varnode *f1c = g.freeRegister(0x30, 1);
  Varnode *c41 = g.constant(4, 7);
  PcodeOp *w1a = g.makeOp("w1a", CPUI_INT_ADD, 2);
  g.setInput(w1a, f1a, 0);
  g.setInput(w1a, c41, 1);
  g.writtenRegister(0x10, 8, w1a);
  g.insertEnd(w1a, b1);
  Varnode *c42 = g.constant(4, 9);
  PcodeOp *w1b = g.makeOp("w1b", CPUI_INT_MULT, 2);
  g.setInput(w1b, f1b, 0);
  g.setInput(w1b, c42, 1);
  g.writtenRegister(0x20, 4, w1b);
  g.insertEnd(w1b, b1);
  Varnode *c43 = g.constant(4, 11);
  PcodeOp *w1c = g.makeOp("w1c", CPUI_COPY, 1);
  g.setInput(w1c, f1c, 0);
  g.writtenRegister(0x30, 1, w1c);
  g.insertEnd(w1c, b1);
  // Arm 2: same ranges, different opcodes so slot identity is observable.
  Varnode *f2a = g.freeRegister(0x10, 8);
  Varnode *f2b = g.freeRegister(0x20, 4);
  Varnode *f2c = g.freeRegister(0x30, 1);
  Varnode *c44 = g.constant(4, 13);
  PcodeOp *w2a = g.makeOp("w2a", CPUI_INT_OR, 2);
  g.setInput(w2a, f2a, 0);
  g.setInput(w2a, c44, 1);
  g.writtenRegister(0x10, 8, w2a);
  g.insertEnd(w2a, b2);
  Varnode *c45 = g.constant(4, 15);
  PcodeOp *w2b = g.makeOp("w2b", CPUI_INT_ADD, 2);
  g.setInput(w2b, f2b, 0);
  g.setInput(w2b, c45, 1);
  g.writtenRegister(0x20, 4, w2b);
  g.insertEnd(w2b, b2);
  Varnode *c46 = g.constant(4, 17);
  PcodeOp *w2c = g.makeOp("w2c", CPUI_COPY, 1);
  g.setInput(w2c, f2c, 0);
  g.writtenRegister(0x30, 1, w2c);
  g.insertEnd(w2c, b2);
  // Join: one free read per range (reads the phi output after rename).
  Varnode *f3a = g.freeRegister(0x10, 8);
  Varnode *f3b = g.freeRegister(0x20, 4);
  Varnode *f3c = g.freeRegister(0x30, 1);
  Varnode *c47 = g.constant(4, 19);
  PcodeOp *r1 = g.makeOp("r1", CPUI_INT_OR, 2);
  g.setInput(r1, f3a, 0);
  g.setInput(r1, c47, 1);
  g.uniqueOut(8, r1);
  g.insertEnd(r1, b3);
  Varnode *c48 = g.constant(4, 21);
  PcodeOp *r2 = g.makeOp("r2", CPUI_INT_ADD, 2);
  g.setInput(r2, f3b, 0);
  g.setInput(r2, c48, 1);
  g.uniqueOut(8, r2);
  g.insertEnd(r2, b3);
  Varnode *c49 = g.constant(4, 23);
  PcodeOp *r3 = g.makeOp("r3", CPUI_INT_MULT, 2);
  g.setInput(r3, f3c, 0);
  g.setInput(r3, c49, 1);
  g.uniqueOut(8, r3);
  g.insertEnd(r3, b3);
  int4 passSeq[3];
  g.runThreePasses(passSeq);
  std::cout << "case=adt_diamond_phi"
            << "|pass=" << passSeq[0] << ',' << passSeq[1] << ',' << passSeq[2]
            << "|ops=" << g.opCount()
            << "|phis=" << g.phiCount()
            << "|phi=" << g.phiProjection()
            << "|oplist=" << g.opList()
            << "|vns=" << g.vnCount()
            << "|vnlist=" << g.vnList() << '\n';
}

// Loop-carried phi with an old marker: the manually created MULTIEQUAL m
// is evidence of previous heritage (collect clears new_addresses for its
// range); heritage places a NEW phi at b1's beginning; rename rewrites
// m's slot 0 (free -> promoted input) but SKIPS m's slot 1 (t3 is
// already written — the phi-cycle old-marker skip, cc:2538).
static void runPhiCycleOldmark(FixtureArchitecture &arch)
{
  Graph g(arch, "phi_cycle_oldmark", 0x5400);
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
  std::cout << "case=phi_cycle_oldmark"
            << "|pass=" << passSeq[0] << ',' << passSeq[1] << ',' << passSeq[2]
            << "|ops=" << g.opCount()
            << "|phis=" << g.phiCount()
            << "|phi=" << g.phiProjection()
            << "|oplist=" << g.opList()
            << "|vns=" << g.vnCount()
            << "|vnlist=" << g.vnList() << '\n';
}

// Two nested joins at different dominator depths: the merge vector order
// produced by the depth-ordered PriorityQueue/augment walk is [deeper
// join first] = [b6, b3], while a block-index ordering would give
// [b3, b6]. The phiSeqOrder/seq field distinguishes the two
// implementations; block-index order here would be a semantic
// divergence from calcMultiequals (cc:2448-2463), not an equivalence.
static void runAdtTwoJoinOrder(FixtureArchitecture &arch)
{
  Graph g(arch, "adt_two_join_order", 0x5500);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  BlockBasic *b3 = g.makeBlock();
  BlockBasic *b4 = g.makeBlock();
  BlockBasic *b5 = g.makeBlock();
  BlockBasic *b6 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b0, b2);
  g.edge(b1, b3);
  g.edge(b2, b3);
  g.edge(b3, b4);
  g.edge(b3, b5);
  g.edge(b4, b6);
  g.edge(b5, b6);
  Varnode *c8 = g.constant(8, 5);
  PcodeOp *d0 = g.makeOp("d0", CPUI_COPY, 1);
  g.setInput(d0, c8, 0);
  g.uniqueOut(8, d0);
  g.insertEnd(d0, b0);
  // One register range 0x60:8 with writes at b1 (shallow) and b5 (deep);
  // joins at b3 (depth 2 under b0) and b6 (depth 3 under b3).
  Varnode *f1 = g.freeRegister(0x60, 8);
  Varnode *c41 = g.constant(4, 7);
  PcodeOp *w1 = g.makeOp("w1", CPUI_INT_ADD, 2);
  g.setInput(w1, f1, 0);
  g.setInput(w1, c41, 1);
  g.writtenRegister(0x60, 8, w1);
  g.insertEnd(w1, b1);
  Varnode *f5 = g.freeRegister(0x60, 8);
  Varnode *c42 = g.constant(4, 9);
  PcodeOp *w5 = g.makeOp("w5", CPUI_INT_OR, 2);
  g.setInput(w5, f5, 0);
  g.setInput(w5, c42, 1);
  g.writtenRegister(0x60, 8, w5);
  g.insertEnd(w5, b5);
  Varnode *f6 = g.freeRegister(0x60, 8);
  Varnode *c43 = g.constant(4, 11);
  PcodeOp *r6 = g.makeOp("r6", CPUI_INT_MULT, 2);
  g.setInput(r6, f6, 0);
  g.setInput(r6, c43, 1);
  g.uniqueOut(8, r6);
  g.insertEnd(r6, b6);
  int4 passSeq[3];
  g.runThreePasses(passSeq);
  std::cout << "case=adt_two_join_order"
            << "|pass=" << passSeq[0] << ',' << passSeq[1] << ',' << passSeq[2]
            << "|ops=" << g.opCount()
            << "|phis=" << g.phiCount()
            << "|seq=" << g.phiSeqOrder()
            << "|phi=" << g.phiProjection()
            << "|oplist=" << g.opList()
            << "|vns=" << g.vnCount()
            << "|vnlist=" << g.vnList() << '\n';
}

// Refinement insertion order: an 8-byte register range whose largest
// write is 4 bytes triggers refinement (cc:2610-2616); the refinement
// partitions it into four 2-byte pieces, refineRead splits the free read
// into a 4-piece chain built by concatPieces anchored on the reading op
// (3 PIECE ops in creation order before it), and refineWrite splits each
// write into 2 SUBPIECEs anchored on the element AFTER the write
// (splitPieces cc:582-587/602). The blockOpOrder projection pins both
// orders; a fixed numeric-index insertion would reverse each group.
static void runAdtRefineOrder(FixtureArchitecture &arch)
{
  Graph g(arch, "adt_refine_order", 0x5600);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0, b1);
  Varnode *c8 = g.constant(8, 5);
  PcodeOp *d0 = g.makeOp("d0", CPUI_COPY, 1);
  g.setInput(d0, c8, 0);
  g.uniqueOut(8, d0);
  g.insertEnd(d0, b0);
  // Overlapping 4-byte writes form an 8-byte heritaged range (0x70..0x77)
  // whose max write (4) is smaller than the range: refinement territory.
  Varnode *fa = g.freeRegister(0x70, 4);
  Varnode *c41 = g.constant(4, 7);
  PcodeOp *wa = g.makeOp("wa", CPUI_INT_ADD, 2);
  g.setInput(wa, fa, 0);
  g.setInput(wa, c41, 1);
  g.writtenRegister(0x70, 4, wa);
  g.insertEnd(wa, b0);
  Varnode *fb = g.freeRegister(0x72, 4);
  Varnode *c42 = g.constant(4, 9);
  PcodeOp *wb = g.makeOp("wb", CPUI_INT_OR, 2);
  g.setInput(wb, fb, 0);
  g.setInput(wb, c42, 1);
  g.writtenRegister(0x72, 4, wb);
  g.insertEnd(wb, b0);
  // Full-range free read after the chain: refineRead's 4-piece
  // concatenation lands before this op.
  Varnode *fr = g.freeRegister(0x70, 8);
  Varnode *c43 = g.constant(4, 11);
  PcodeOp *r = g.makeOp("r", CPUI_INT_MULT, 2);
  g.setInput(r, fr, 0);
  g.setInput(r, c43, 1);
  g.uniqueOut(8, r);
  g.insertEnd(r, b1);
  int4 passSeq[3];
  g.runThreePasses(passSeq);
  std::cout << "case=adt_refine_order"
            << "|pass=" << passSeq[0] << ',' << passSeq[1] << ',' << passSeq[2]
            << "|ops=" << g.opCount()
            << "|order=" << g.blockOpOrder()
            << "|oplist=" << g.opList()
            << "|vns=" << g.vnCount()
            << "|vnlist=" << g.vnList() << '\n';
}

// Revisit-position case: after pass 1 heritages range 0x90:4, the
// fixture injects previous-heritage markers (2-byte INDIRECT/MULTIEQUAL
// outputs are collect's "evidence of previous heritage", cc:329-333) plus
// fresh free reads, so pass 2 re-adds the ranges (prev==2 path) and
// removeRevisitedMarkers converts each marker to SUBPIECE at the
// ELEMENT-ANCHORED position:
//   - dead-target INDIRECT mid-block  b1=[.., a2, i, f2] -> [.., a2, S, f2]
//   - dead-target INDIRECT at tail    b2=[a3, i2]        -> [a3, S2]
//   - MULTIEQUAL marker before a full-size MULTIEQUAL
//                                     b3=[m, m2, x]      -> [m2, S3, x]
// The per-op block-order projection pins all three shapes; a numeric
// index computed pre-removal shifts by one (and panics at the tail).
static void injectRevisitMarkers(Graph &g)
{
  Funcdata &fd = g.fd;
  BlockBasic *b1 = (BlockBasic *)fd.getBasicBlocks().getBlock(1);
  BlockBasic *b2 = (BlockBasic *)fd.getBasicBlocks().getBlock(2);
  BlockBasic *b3 = (BlockBasic *)fd.getBasicBlocks().getBlock(3);
  Varnode *c4 = g.constant(4, 37);
  // Range A (0x90:4, OLD): fresh free read + mid-block dead-target
  // INDIRECT marker in b1.
  Varnode *f2 = g.freeRegister(0x90, 4);
  PcodeOp *a2 = g.makeOp("a2", CPUI_INT_MULT, 2);
  g.setInput(a2, f2, 0);
  g.setInput(a2, c4, 1);
  g.uniqueOut(8, a2);
  g.insertEnd(a2, b1);
  PcodeOp *ta = g.deadTarget(b1);
  g.indirectMarker(0x90, ta, b1);
  PcodeOp *f2op = g.makeOp("f2", CPUI_INT_OR, 2);
  g.setInput(f2op, c4, 0);
  g.setInput(f2op, c4, 1);
  g.uniqueOut(8, f2op);
  g.insertEnd(f2op, b1);
  // Range B (0x98:4, NEW): fresh free read + dead-target INDIRECT at the
  // block tail of b2.
  Varnode *fB = g.freeRegister(0x98, 4);
  PcodeOp *a3 = g.makeOp("a3", CPUI_INT_ADD, 2);
  g.setInput(a3, fB, 0);
  g.setInput(a3, c4, 1);
  g.uniqueOut(8, a3);
  g.insertEnd(a3, b2);
  PcodeOp *tb = g.deadTarget(b2);
  g.indirectMarker(0x98, tb, b2);
  // Range C (0xa0:4, NEW): a 2-byte MULTIEQUAL marker followed by a
  // full-size MULTIEQUAL (kept: size >= range clears new_addresses) and
  // a reader, in b3.
  Varnode *fc1 = g.freeRegister(0xa0, 4);
  Varnode *fc2 = g.freeRegister(0xa0, 4);
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 2);
  g.setInput(m, fc1, 0);
  g.setInput(m, fc2, 1);
  g.writtenRegister(0xa0, 2, m);
  g.insertEnd(m, b3);
  Varnode *fd1 = g.freeRegister(0xa0, 4);
  Varnode *fd2 = g.freeRegister(0xa0, 4);
  PcodeOp *m2 = g.makeOp("m2", CPUI_MULTIEQUAL, 2);
  g.setInput(m2, fd1, 0);
  g.setInput(m2, fd2, 1);
  g.writtenRegister(0xa0, 4, m2);
  g.insertEnd(m2, b3);
  Varnode *f4 = g.freeRegister(0xa0, 4);
  PcodeOp *x = g.makeOp("x", CPUI_INT_MULT, 2);
  g.setInput(x, f4, 0);
  g.setInput(x, c4, 1);
  g.uniqueOut(8, x);
  g.insertEnd(x, b3);
}

static void runAdtRevisitPositions(FixtureArchitecture &arch)
{
  Graph g(arch, "adt_revisit_positions", 0x5700);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  BlockBasic *b3 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b1, b2);
  g.edge(b1, b3);
  Varnode *c4 = g.constant(4, 7);
  Varnode *fw = g.freeRegister(0x90, 4);
  PcodeOp *w = g.makeOp("w", CPUI_INT_ADD, 2);
  g.setInput(w, fw, 0);
  g.setInput(w, c4, 1);
  g.writtenRegister(0x90, 4, w);
  g.insertEnd(w, b0);
  Varnode *fr = g.freeRegister(0x90, 4);
  PcodeOp *r = g.makeOp("r", CPUI_INT_OR, 2);
  g.setInput(r, fr, 0);
  g.setInput(r, c4, 1);
  g.uniqueOut(8, r);
  g.insertEnd(r, b1);
  int4 passSeq[3];
  g.runThreePasses(passSeq, injectRevisitMarkers);
  std::cout << "case=adt_revisit_positions"
            << "|pass=" << passSeq[0] << ',' << passSeq[1] << ',' << passSeq[2]
            << "|ops=" << g.opCount()
            << "|order=" << g.blockOpOrder()
            << "|oplist=" << g.opList()
            << "|vns=" << g.vnCount()
            << "|vnlist=" << g.vnList() << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=HERITAGE-ADT-RENAME-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    runAdtDiamondPhi(arch);
    runPhiCycleOldmark(arch);
    runAdtTwoJoinOrder(arch);
    runAdtRefineOrder(arch);
    runAdtRevisitPositions(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
