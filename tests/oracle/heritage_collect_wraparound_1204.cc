/*
 * HERITAGE-COLLECT-WRAPAROUND-0001: locked Ghidra 12.0.4 oracle for the
 * Heritage::collect end-address wraparound clamp (heritage.cc:317-320).
 *
 *   uintb start = memrange.addr.getOffset();
 *   Address endaddr = memrange.addr + memrange.size;   // operator+ wraps
 *   if (endaddr.getOffset() < start) {                 // Wraparound
 *     Address tmp(endaddr.getSpace(),endaddr.getSpace()->getHighest());
 *     enditer = fd->endLoc(tmp);
 *   }
 *   else
 *     enditer = fd->beginLoc(endaddr);
 *
 * When a MemRange crosses the top of its address space, the wrapped end
 * offset falls below the start offset. The oracle does NOT cut the scan at
 * beginLoc(endaddr) (which for a wrapped small offset would terminate the
 * window immediately) — it clamps the window end to endLoc(Address(space,
 * getHighest())), which (varnode.cc:1596-1602) is the lower bound at the
 * NEXT space in order: the collect window runs from start to the END of
 * the range's space.
 *
 * Production reachability: the disjoint cover is fed (addr,size) pairs of
 * real varnodes (heritage.cc:2708-2710), so a wrapping MemRange requires a
 * varnode straddling the top of an 8-byte space (offset 0xffffffffffffffff
 * with size > 1) or exactly the top byte (whose end offset wraps to 0). No
 * real loader emits such locations — the divergence is pre-existing and not
 * r2-introduced — but the branch is real oracle behavior and is pinned here
 * through the production boundary Funcdata::opHeritage (funcdata.hh:462),
 * exactly like the FLAGFREE/ADT-RENAME/CALLGUARD/DRIVER-SWITCH fixtures:
 *
 *   case A wraparound_straddling_write — a 2-byte register write AT the
 *        highest offset plus a 1-byte free read of the same location read
 *        by BOOL_NEGATE (the SLEIGH jcc form). The cover range
 *        [0xffffffffffffffff, +2) wraps to end offset 1; the clamp keeps
 *        BOTH varnodes in the collect window, renameRecurse then resolves
 *        the read through normalizeReadSize (cc:382-412): a 2-byte range
 *        varnode defined by the write is created and the BOOL read becomes
 *        its SUBPIECE. Without the clamp the window is empty, the read
 *        stays free-with-descendant and the census witness is non-zero.
 *
 *   case B nonwrap_control_same_shape — the byte-identical graph at
 *        register 0x206 (endaddr 0x208 does not wrap). Same window
 *        membership, same SUBPIECE link — the differential control proving
 *        the clamp preserves collect behavior rather than changing it.
 *
 *   case C wraparound_exact_top — a 1-byte write exactly at the highest
 *        offset (endaddr wraps to 0 < start) plus a 1-byte free read:
 *        the clamp window contains both and renameRecurse links the read
 *        directly to the write (equal sizes, no SUBPIECE). Pins the
 *        INCLUSIVE top edge: endLoc(space, getHighest()) runs through
 *        offset == highest, it does not stop before it.
 *
 * Observation per case: pass counter, live op count, the BOOL input
 * descriptor after rename, the whole-bank free-with-reader census (the
 * varnode.cc:334-336 throw precondition), phi projection, the full op list
 * in PcodeOpTree order, the sorted Varnode descriptor multiset, and the
 * persistent globaldisjoint cover dump (processor/stack spaces only —
 * unique-space offsets are allocation-dependent and not comparable)
 * proving the wrapping range really entered the cover at pass 0.
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

// Test-only observation shim (same contract as the FLAGFREE/ADT-RENAME
// fixtures): re-declares the locked-oracle member sequence of Funcdata
// (funcdata.hh:57-95) to reach the Heritage member for
// `heritage.buildInfoList()` (funcdata.cc:166) and opHeritage.
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

// Test-only observation shim for the Heritage private data prefix
// (heritage.hh:238-240: Funcdata *fd, LocationMap globaldisjoint, TaskList
// disjoint) to dump the persistent globaldisjoint cover after the pass.
// Same pinned-layout contract as FuncdataHeritageShim; only the prefix up
// to the accessed member affects the offsets.
struct HeritageDataShim {
  Funcdata *fd;
  LocationMap globaldisjoint;
  TaskList disjoint;
};

static LocationMap &globalDisjointOf(Funcdata &fd)
{
  Heritage &h = heritageOf(fd);
  return reinterpret_cast<HeritageDataShim *>(&h)->globaldisjoint;
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
  case CPUI_SUBPIECE: return "SUBPIECE";
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
  // flag reads arrive with. Created AFTER the write so the same-location
  // write/read pair stays two objects (VarnodeBank::create only reuses
  // free varnodes, varnode.cc:1250-1258).
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

  // Persistent globaldisjoint cover (heritage.hh:33) after the pass:
  // name:hexoffset:size:p<pass> for the processor/stack spaces only.
  // Unique-space entries are excluded because their offsets are
  // allocation-dependent; the map is already (space,offset) ordered.
  std::string globalCover(void)
  {
    std::ostringstream out;
    bool first = true;
    LocationMap &cover = globalDisjointOf(fd);
    for (LocationMap::iterator iter = cover.begin(); iter != cover.end(); ++iter) {
      AddrSpace *spc = (*iter).first.getSpace();
      if (spc->getType() != IPTR_PROCESSOR && spc->getType() != IPTR_SPACEBASE)
        continue;
      if (!first)
        out << ',';
      first = false;
      out << spc->getName() << ':' << hex << (*iter).first.getOffset() << dec
          << ':' << (*iter).second.size << ":p" << (*iter).second.pass;
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
  const uintb top = 0xffffffffffffffffU;

  std::cout << "schema=1|fixture=HERITAGE-COLLECT-WRAPAROUND-0001|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // ---- case A: 2-byte write straddling the space top + 1-byte read ----
  {
    Graph g(arch, "wrap_straddle", 0x1000);
    BlockBasic *b0 = g.makeBlock();

    PcodeOp *w = g.makeOp("w", CPUI_INT_SUB, 2);
    g.setInput(w, g.constant(2, 0x0), 0);
    g.setInput(w, g.constant(2, 0x1), 1);
    g.writtenRegister(top, 2, w);
    g.insertEnd(w, b0);

    PcodeOp *n = g.makeOp("n", CPUI_BOOL_NEGATE, 1);
    g.setInput(n, g.freeRegister(top, 1), 0);
    g.uniqueOut(1, n);
    g.insertEnd(n, b0);

    PcodeOp *c = g.makeOp("c", CPUI_CBRANCH, 2);
    g.setInput(c, g.constant(8, 0x2000), 0);
    g.setInput(c, n->getOut(), 1);
    g.insertEnd(c, b0);

    g.prepareStructure();
    g.fd.opHeritage();

    const Varnode *boolIn = n->getIn(0);
    std::cout << "case=wraparound_straddling_write"
              << "|pass=" << g.fd.getHeritagePass()
              << "|ops=" << g.opCountAll()
              << "|bool_in=" << vnDescriptor(boolIn)
              << "|free_with_reader=" << g.freeWithReader()
              << "|gd=" << g.globalCover()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }

  // ---- case B: byte-identical control shape at a normal offset ----
  {
    Graph g(arch, "nonwrap_control", 0x2000);
    BlockBasic *b0 = g.makeBlock();

    PcodeOp *w = g.makeOp("w", CPUI_INT_SUB, 2);
    g.setInput(w, g.constant(2, 0x0), 0);
    g.setInput(w, g.constant(2, 0x1), 1);
    g.writtenRegister(0x206, 2, w);
    g.insertEnd(w, b0);

    PcodeOp *n = g.makeOp("n", CPUI_BOOL_NEGATE, 1);
    g.setInput(n, g.freeRegister(0x206, 1), 0);
    g.uniqueOut(1, n);
    g.insertEnd(n, b0);

    PcodeOp *c = g.makeOp("c", CPUI_CBRANCH, 2);
    g.setInput(c, g.constant(8, 0x3000), 0);
    g.setInput(c, n->getOut(), 1);
    g.insertEnd(c, b0);

    g.prepareStructure();
    g.fd.opHeritage();

    const Varnode *boolIn = n->getIn(0);
    std::cout << "case=nonwrap_control_same_shape"
              << "|pass=" << g.fd.getHeritagePass()
              << "|ops=" << g.opCountAll()
              << "|bool_in=" << vnDescriptor(boolIn)
              << "|free_with_reader=" << g.freeWithReader()
              << "|gd=" << g.globalCover()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }

  // ---- case C: 1-byte write exactly at the top byte + 1-byte read ----
  {
    Graph g(arch, "wrap_exact_top", 0x3000);
    BlockBasic *b0 = g.makeBlock();

    PcodeOp *w = g.makeOp("w", CPUI_INT_SUB, 2);
    g.setInput(w, g.constant(1, 0x0), 0);
    g.setInput(w, g.constant(1, 0x1), 1);
    g.writtenRegister(top, 1, w);
    g.insertEnd(w, b0);

    PcodeOp *n = g.makeOp("n", CPUI_BOOL_NEGATE, 1);
    g.setInput(n, g.freeRegister(top, 1), 0);
    g.uniqueOut(1, n);
    g.insertEnd(n, b0);

    PcodeOp *c = g.makeOp("c", CPUI_CBRANCH, 2);
    g.setInput(c, g.constant(8, 0x4000), 0);
    g.setInput(c, n->getOut(), 1);
    g.insertEnd(c, b0);

    g.prepareStructure();
    g.fd.opHeritage();

    const Varnode *boolIn = n->getIn(0);
    std::cout << "case=wraparound_exact_top"
              << "|pass=" << g.fd.getHeritagePass()
              << "|ops=" << g.opCountAll()
              << "|bool_in=" << vnDescriptor(boolIn)
              << "|free_with_reader=" << g.freeWithReader()
              << "|gd=" << g.globalCover()
              << "|phis=" << g.phiProjection()
              << "|ops_proj=" << g.opList()
              << "|vn=" << g.vnMultiset()
              << std::endl;
  }
  return 0;
}
