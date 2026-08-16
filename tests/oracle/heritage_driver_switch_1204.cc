/*
 * HERITAGE-DRIVER-SWITCH-0001: locked Ghidra 12.0.4 oracle for the
 * ActionHeritage -> Funcdata::opHeritage -> Heritage::heritage production
 * driver boundary.
 *
 * The oracle contract under test (coreaction.hh:289 +
 * coreaction.cc:5489-5492): ActionHeritage::apply is a single unconditional
 * `data.opHeritage(); return 0;` inside the repeatapply "mainloop" group —
 * no pass guard, no embedded DeadCode, no second pass. Convergence under
 * per-mainloop-iteration re-entry is a property of Heritage::heritage
 * itself: per-space delay gating (heritage.cc:2687), the LocationMap's
 * space-qualified disjoint cover (heritage.hh:48, `map<Address,SizePass>`
 * keyed by space+offset; `Address::overlap` is -1 across spaces), the
 * prev==2 old-range skip for heritageKnown / no-descend varnodes
 * (heritage.cc:2711-2713), and `pass += 1` exactly once at cc:2757.
 *
 * The fixture drives the production boundary `fd.opHeritage()` (funcdata.hh:462)
 * one or more times per case and observes the complete post-pass projection:
 *
 *   - pass: the pass counter (getHeritagePass, funcdata.hh:231),
 *   - hp_reg / hp_stack: Heritage::heritagePass (heritage.hh:325 =
 *     LocationMap::findPass) at colliding offsets in the register and stack
 *     spaces — the cross-space key identity of the disjoint cover,
 *   - read_in: descriptor of the observed read's input after rename,
 *   - ops / free_with_reader / phis / ops_proj / vn: live op count,
 *     whole-bank free-with-descendant census (the varnode.cc:334-336
 *     throw precondition), phi projection with per-slot predecessor wiring,
 *     full op list, and sorted Varnode multiset.
 *
 * Cases:
 *   switch_written_read     single block: R0x30:8 written then free-read;
 *                           ONE opHeritage (pass 0). The read links to the
 *                           write; register range entered at pass 0.
 *   switch_diamond_reherit  two-arm diamond writes of R0x38:8 merged at a
 *                           join read; THREE opHeritage calls (the
 *                           repeatapply mainloop re-entry shape). Pass
 *                           counter 0->3, phi set and op list must be
 *                           stable across re-runs (idempotence).
 *   switch_cross_space      b0->b1 chain writing+reading BOTH register
 *                           0x30:8 and stack 0x30:8 (SAME offset, two
 *                           spaces); TWO opHeritage calls (stack delay=1
 *                           defers the stack space to pass 1). Each space
 *                           must get its OWN LocationMap entry (hp_reg=0,
 *                           hp_stack=1) and its OWN linked read — the
 *                           space-identity of the cover.
 *   switch_late_free_reentry
 *                           write R0x40:8 + one read, opHeritage (pass 0);
 *                           then a NEW free read of R0x40:8 appears
 *                           (post-heritage churn, the mainloop re-entry
 *                           input) and opHeritage runs again (pass 1).
 *                           The prev==2 old range re-enters (cc:2711-2719)
 *                           and the fresh read must be absorbed by the
 *                           existing write with no new phi (ops stable).
 *   switch_refinement_recollect
 *                           partial-width write shape (x86-64 eax-write +
 *                           rax-read): INT_SUB writes R0x50:4 while an
 *                           8-byte free read consumes R0x50:8, so the
 *                           8-byte range has max write 4 < 8 and
 *                           placeMultiequals refines it (cc:2610-2616)
 *                           into two 4-byte pieces; the oracle's LIVE
 *                           beginLoc/endLoc re-collect (cc:2615) and every
 *                           later piece's collect see the refinement
 *                           pieces created by refineRead/refineWrite
 *                           (cc:1902-1906) in this same walk — an
 *                           entry-frozen snapshot would hide them
 *                           (review M1). The projection (PIECE/SUBPIECE
 *                           op list, per-piece read linking, phi set)
 *                           witnesses the live visibility.
 *
 * Architecture/compiler spec/prestate mirror the FLAGFREE/ADT-RENAME
 * fixtures: the synthetic blocks have no cover so MULTIEQUAL SeqNums are
 * null-pc.
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

// Test-only observation shim (same contract as the FLAGFREE fixture):
// re-declares the locked-oracle member sequence of Funcdata (funcdata.hh:57-95)
// to reach the Heritage member for `heritage.buildInfoList()` (funcdata.cc:166)
// and `heritage.heritagePass()` (heritage.hh:325). Layout pinned to oracle
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
  case CPUI_RETURN: return "RETURN";
  case CPUI_MULTIEQUAL: return "MULTIEQUAL";
  case CPUI_PIECE: return "PIECE";
  case CPUI_SUBPIECE: return "SUBPIECE";
  default: return "OTHER";
  }
}

// Varnode descriptor shared with the Rust comparand:
//   constant  -> C<size>:<hex-value>
//   register  -> R<hex-offset>:<size>:<I|W|F>[+<def-opcode>]
//   stack     -> S<hex-offset>:<size>:<I|W|F>[+<def-opcode>]
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
  AddrSpace *stack;
  std::map<PcodeOp *, std::string> opNames;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const std::string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), stack(a.getSpace(5)),
      nextOffset(0) {}

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
  // reads arrive with.
  Varnode *freeRegister(uintb offset, int4 size)
  {
    return fd.newVarnode(size, Address(reg, offset));
  }

  Varnode *freeStack(uintb offset, int4 size)
  {
    return fd.newVarnode(size, Address(stack, offset));
  }

  Varnode *writtenRegister(uintb offset, int4 size, PcodeOp *op)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    fd.opSetOutput(op, vn);
    return op->getOut();
  }

  Varnode *writtenStack(uintb offset, int4 size, PcodeOp *op)
  {
    Varnode *vn = fd.newVarnode(size, Address(stack, offset));
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

  // Heritage::heritagePass (heritage.hh:325): pass when the (space,offset)
  // was entered into the disjoint cover, or -1.
  int4 heritagePassOf(const Address &addr)
  {
    return heritageOf(fd).heritagePass(addr);
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

  std::cout << "schema=1|fixture=HERITAGE-DRIVER-SWITCH-0001|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // ---- case A: single pass, write then read ----
  {
    Graph g(arch, "switch_written_read", 0x1000);
    BlockBasic *b0 = g.makeBlock();

    PcodeOp *w = g.makeOp("w", CPUI_INT_SUB, 2);
    g.setInput(w, g.constant(1, 0x0), 0);
    g.setInput(w, g.constant(1, 0x1), 1);
    g.writtenRegister(0x30, 8, w);
    g.insertEnd(w, b0);

    PcodeOp *r = g.makeOp("r", CPUI_INT_OR, 2);
    g.setInput(r, g.freeRegister(0x30, 8), 0);
    g.setInput(r, g.constant(8, 0x11), 1);
    g.uniqueOut(8, r);
    g.insertEnd(r, b0);

    PcodeOp *c = g.makeOp("c", CPUI_CBRANCH, 2);
    g.setInput(c, g.constant(8, 0x2000), 0);
    g.setInput(c, r->getOut(), 1);
    g.insertEnd(c, b0);

    g.prepareStructure();
    g.fd.opHeritage();

    const Varnode *readIn = r->getIn(0);
    std::cout << "case=switch_written_read"
              << "|pass=" << g.fd.getHeritagePass()
              << "|hp_reg=" << g.heritagePassOf(Address(g.reg, 0x30))
              << "|hp_stack=" << g.heritagePassOf(Address(g.stack, 0x30))
              << "|read_in=" << vnDescriptor(readIn)
              << "|ops=" << g.opCountAll()
              << "|free_with_reader=" << g.freeWithReader()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }

  // ---- case B: diamond, three re-entry passes ----
  {
    Graph g(arch, "switch_diamond_reherit", 0x2000);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    BlockBasic *b2 = g.makeBlock();
    BlockBasic *b3 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b0, b2);
    g.edge(b1, b3);
    g.edge(b2, b3);

    PcodeOp *w1 = g.makeOp("w1", CPUI_INT_SUB, 2);
    g.setInput(w1, g.constant(8, 0x2), 0);
    g.setInput(w1, g.constant(8, 0x3), 1);
    g.writtenRegister(0x38, 8, w1);
    g.insertEnd(w1, b1);

    PcodeOp *w2 = g.makeOp("w2", CPUI_INT_OR, 2);
    g.setInput(w2, g.constant(8, 0x4), 0);
    g.setInput(w2, g.constant(8, 0x5), 1);
    g.writtenRegister(0x38, 8, w2);
    g.insertEnd(w2, b2);

    PcodeOp *r = g.makeOp("r", CPUI_INT_ADD, 2);
    g.setInput(r, g.freeRegister(0x38, 8), 0);
    g.setInput(r, g.constant(8, 0x6), 1);
    g.uniqueOut(8, r);
    g.insertEnd(r, b3);

    PcodeOp *c = g.makeOp("c", CPUI_CBRANCH, 2);
    g.setInput(c, g.constant(8, 0x3000), 0);
    g.setInput(c, r->getOut(), 1);
    g.insertEnd(c, b3);

    g.prepareStructure();
    // coreaction.cc:5489-5492: mainloop repeatapply re-runs ActionHeritage.
    g.fd.opHeritage();
    g.fd.opHeritage();
    g.fd.opHeritage();

    const Varnode *readIn = r->getIn(0);
    std::cout << "case=switch_diamond_reherit"
              << "|pass=" << g.fd.getHeritagePass()
              << "|hp_reg=" << g.heritagePassOf(Address(g.reg, 0x38))
              << "|hp_stack=" << g.heritagePassOf(Address(g.stack, 0x38))
              << "|read_in=" << vnDescriptor(readIn)
              << "|ops=" << g.opCountAll()
              << "|free_with_reader=" << g.freeWithReader()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }

  // ---- case C: same offset in register and stack spaces ----
  {
    Graph g(arch, "switch_cross_space", 0x3000);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);

    PcodeOp *wr = g.makeOp("wr", CPUI_INT_SUB, 2);
    g.setInput(wr, g.constant(8, 0x7), 0);
    g.setInput(wr, g.constant(8, 0x8), 1);
    g.writtenRegister(0x30, 8, wr);
    g.insertEnd(wr, b0);

    PcodeOp *ws = g.makeOp("ws", CPUI_INT_OR, 2);
    g.setInput(ws, g.constant(8, 0x9), 0);
    g.setInput(ws, g.constant(8, 0xa), 1);
    g.writtenStack(0x30, 8, ws);
    g.insertEnd(ws, b0);

    PcodeOp *rr = g.makeOp("rr", CPUI_INT_ADD, 2);
    g.setInput(rr, g.freeRegister(0x30, 8), 0);
    g.setInput(rr, g.constant(8, 0xb), 1);
    g.uniqueOut(8, rr);
    g.insertEnd(rr, b1);

    PcodeOp *rs = g.makeOp("rs", CPUI_INT_ADD, 2);
    g.setInput(rs, g.freeStack(0x30, 8), 0);
    g.setInput(rs, g.constant(8, 0xc), 1);
    g.uniqueOut(8, rs);
    g.insertEnd(rs, b1);

    PcodeOp *cret = g.makeOp("cret", CPUI_RETURN, 1);
    g.setInput(cret, g.constant(8, 0x4000), 0);
    g.insertEnd(cret, b1);

    g.prepareStructure();
    // Pass 0 heritages register (delay 0); stack is delayed to pass 1
    // (HeritageInfo ctor, heritage.cc:197 IPTR_SPACEBASE delay=1).
    g.fd.opHeritage();
    g.fd.opHeritage();

    const Varnode *readReg = rr->getIn(0);
    const Varnode *readStack = rs->getIn(0);
    std::cout << "case=switch_cross_space"
              << "|pass=" << g.fd.getHeritagePass()
              << "|hp_reg=" << g.heritagePassOf(Address(g.reg, 0x30))
              << "|hp_stack=" << g.heritagePassOf(Address(g.stack, 0x30))
              << "|read_in=" << vnDescriptor(readReg)
              << "|read_in2=" << vnDescriptor(readStack)
              << "|ops=" << g.opCountAll()
              << "|free_with_reader=" << g.freeWithReader()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }

  // ---- case D: late free read absorbed by re-entry (prev==2 OLD range) ----
  {
    Graph g(arch, "switch_late_free_reentry", 0x4000);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);

    PcodeOp *w = g.makeOp("w", CPUI_INT_SUB, 2);
    g.setInput(w, g.constant(8, 0xd), 0);
    g.setInput(w, g.constant(8, 0xe), 1);
    g.writtenRegister(0x40, 8, w);
    g.insertEnd(w, b0);

    PcodeOp *r1 = g.makeOp("r1", CPUI_INT_OR, 2);
    g.setInput(r1, g.freeRegister(0x40, 8), 0);
    g.setInput(r1, g.constant(8, 0xf), 1);
    g.uniqueOut(8, r1);
    g.insertEnd(r1, b1);

    PcodeOp *cret = g.makeOp("cret", CPUI_RETURN, 1);
    g.setInput(cret, g.constant(8, 0x5000), 0);
    g.insertEnd(cret, b1);

    g.prepareStructure();
    g.fd.opHeritage();

    // Post-heritage churn: a brand-new free read of the now-OLD range
    // appears (the fullloop/merge late-free shape the 351/44-WARN family
    // documented). The next mainloop iteration re-runs ActionHeritage.
    PcodeOp *r2 = g.makeOp("r2", CPUI_INT_ADD, 2);
    g.setInput(r2, g.freeRegister(0x40, 8), 0);
    g.setInput(r2, g.constant(8, 0x10), 1);
    g.uniqueOut(8, r2);
    g.insertEnd(r2, b1);

    const int4 opsAfterPass0 = g.opCountAll();
    g.fd.opHeritage();

    const Varnode *lateIn = r2->getIn(0);
    std::cout << "case=switch_late_free_reentry"
              << "|pass=" << g.fd.getHeritagePass()
              << "|hp_reg=" << g.heritagePassOf(Address(g.reg, 0x40))
              << "|hp_stack=" << g.heritagePassOf(Address(g.stack, 0x40))
              << "|read_in=" << vnDescriptor(lateIn)
              << "|ops=" << g.opCountAll()
              << "|ops_after_pass0=" << opsAfterPass0
              << "|free_with_reader=" << g.freeWithReader()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }

  // ---- case E: partial-width write forces refinement; pieces must be
  //      visible to the re-collect (live beginLoc/endLoc windows) ----
  {
    Graph g(arch, "switch_refinement_recollect", 0x5000);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);

    // Partial write: 4 bytes of the 8-byte register slot (the x86-64
    // eax-write shape) -> max write size 4 < range size 8 -> refinement.
    PcodeOp *w = g.makeOp("w", CPUI_INT_SUB, 2);
    g.setInput(w, g.constant(8, 0xd0), 0);
    g.setInput(w, g.constant(8, 0xd1), 1);
    g.writtenRegister(0x50, 4, w);
    g.insertEnd(w, b0);

    // Full-width free read (the rax-read shape).
    PcodeOp *r = g.makeOp("r", CPUI_INT_ADD, 2);
    g.setInput(r, g.freeRegister(0x50, 8), 0);
    g.setInput(r, g.constant(8, 0xd2), 1);
    g.uniqueOut(8, r);
    g.insertEnd(r, b1);

    PcodeOp *cret = g.makeOp("cret", CPUI_RETURN, 1);
    g.setInput(cret, g.constant(8, 0x6000), 0);
    g.insertEnd(cret, b1);

    g.prepareStructure();
    g.fd.opHeritage();

    const Varnode *readIn = r->getIn(0);
    std::cout << "case=switch_refinement_recollect"
              << "|pass=" << g.fd.getHeritagePass()
              << "|hp_reg=" << g.heritagePassOf(Address(g.reg, 0x50))
              << "|hp_stack=" << g.heritagePassOf(Address(g.stack, 0x50))
              << "|read_in=" << vnDescriptor(readIn)
              << "|ops=" << g.opCountAll()
              << "|free_with_reader=" << g.freeWithReader()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }
  return 0;
}
