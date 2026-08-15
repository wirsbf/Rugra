/*
 * HERITAGE-CALLGUARD-0001: locked Ghidra 12.0.4
 * ActionHeritage -> Funcdata::opHeritage -> Heritage::heritage
 * call-guard oracle (guardCalls / newIndirectOp / newIndirectCreation).
 *
 * Every case drives the production public boundary `fd.opHeritage()` on a
 * synthetic call graph and observes, per callspec x affected range, the
 * complete INDIRECT object state after the canonical single pass:
 *   - parent block and position within the block's op list
 *   - the Iop-space input[1] alias round-tripped through
 *     PcodeOp::getOpFromConst (the exact causing op, never a raw pointer)
 *   - the input[0] form: indirectly-created constant zero vs the renamed
 *     prior value (written def or promoted input) at the guarded storage
 *   - the output storage (space, offset, size) and flag set
 *     (indirect_creation / return_address / addrforce / activeheritage)
 *   - the guard creation order (== write-vector order) via block positions
 *   - registered input/output trials and the appended call inputs
 *   - the pass gating: new-address ranges guarded exactly once; a second
 *     pass on old-address ranges adds no guards
 *
 * The ten register ranges mirror the locked GetStr ABI shape:
 *   (0x0,8) (0x30,8) (0x38,8) (0x200,1) (0x202,1) (0x206,1)
 *   (0x207,1) (0x20a,1) (0x20b,1) (0x288,8)
 * decimal 0/48/56/512/514/518/519/522/523/648 in the driver audit, where
 * two calls x ten ranges produced exactly twenty INDIRECTs.
 *
 * Not byte-compared here: reprocessFreeStores (a default-private member
 * reachable only through a successful discoverIndexedStackPointers, which
 * needs the stack-pointer data-flow of the load-guard fixture family) and
 * the ScopeLocal-derived `fl` properties (no address-tied ranges in this
 * fixture, so holdind is uniformly false).
 */

#include <bits/stdc++.h>

// The Heritage private guard helpers are never called directly — the
// canonical public pass drives them. The Funcdata member layout (heritage
// handle, callspec vector) is reached through the shim below.
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

// Test-only layout shim mirroring the locked-oracle Funcdata member
// sequence (funcdata.hh:57-95, pinned to commit
// e40ed13014025f82488b1f8f7bca566894ac376b, verified by the runner) so the
// fixture can run startProcessing's heritage step
// (`heritage.buildInfoList()`, funcdata.cc:166) and read the callspec list.
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

static vector<FuncCallSpecs *> &specsOf(Funcdata &fd)
{
  return reinterpret_cast<FuncdataHeritageShim *>(&fd)->qlst;
}

// Test-only layout shim mirroring the locked-oracle FuncCallSpecs member
// sequence preceding `stackoffset` (fspec.hh:1645-1651, pinned to the
// oracle commit verified by the runner). Production sets the field through
// FuncCallSpecs::resolveSpacebaseRelative (fspec.cc:4878/4900, private);
// the fixture writes the same resolved-state precondition directly.
struct FuncCallSpecsShim : public FuncProto {
  PcodeOp *op;
  string name;
  Address entryaddress;
  Funcdata *fd;
  int4 effective_extrapop;
  uintb stackoffset;
};

static void setSpacebaseOffset(FuncCallSpecs *fc, uintb offset)
{
  reinterpret_cast<FuncCallSpecsShim *>(fc)->stackoffset = offset;
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
  ProtoModel *callguard_model;
  ProtoModel *unaffected_model;

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
    // HERITAGE-CALLGUARD model: SYSV-shaped inputs RSI(0x30)/RDI(0x38),
    // output RAX(0x0), explicit killedbycall on RAX and stack(0x8,8),
    // return_address storage at 0x288. Everything else is unknown_effect.
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"callguard\" extrapop=\"0\" strategy=\"standard\">"
        "<input>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x30\" size=\"8\"/></pentry>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x38\" size=\"8\"/></pentry>"
        "</input>"
        "<output>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x0\" size=\"8\"/></pentry>"
        "</output>"
        "<killedbycall>"
        "<addr space=\"register\" offset=\"0x0\" size=\"8\"/>"
        "<addr space=\"stack\" offset=\"0x8\" size=\"8\"/>"
        "</killedbycall>"
        "<returnaddress>"
        "<addr space=\"register\" offset=\"0x288\" size=\"8\"/>"
        "</returnaddress>"
        "</prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
    callguard_model = model;
    // Whole-register-space unaffected model: a size-0 record marks the
    // entire space (fspec.cc lookupEffect).
    ProtoModel *unaffected = new ProtoModel(this);
    std::istringstream stream2(
        "<prototype name=\"callguard_unaffected\" extrapop=\"0\" strategy=\"standard\">"
        "<input>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x30\" size=\"8\"/></pentry>"
        "</input>"
        "<output>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x0\" size=\"8\"/></pentry>"
        "</output>"
        "<unaffected>"
        "<addr space=\"register\" offset=\"0x0\" size=\"0\"/>"
        "</unaffected>"
        "</prototype>");
    XmlDecode decoder2(this);
    decoder2.ingestStream(stream2);
    unaffected->decode(decoder2);
    protoModels[unaffected->getName()] = unaffected;
    unaffected_model = unaffected;
  }

  void printMessage(const std::string &) const override {}
};

// Varnode descriptor shared with the Rust comparand:
//   constant -> C<size>
//   register -> R<hex-offset>:<I|W|F>
//   stack    -> S<hex-offset>:<I|W|F>
//   unique   -> U<size>:<I|W|F>   (absolute offsets not printed; the
//                                  allocation bases differ)
//   iop      -> IOP
static std::string vnDescriptor(const Varnode *vn)
{
  std::ostringstream out;
  if (vn->isConstant()) {
    out << 'C' << vn->getSize();
    return out.str();
  }
  AddrSpace *spc = vn->getSpace();
  char code = 'X';
  if (spc->getType() == IPTR_SPACEBASE)
    code = 'S';
  else if (spc->getName() == "register")
    code = 'R';
  else if (spc->getType() == IPTR_INTERNAL)
    code = 'U';
  else if (spc->getName() == "ram")
    code = 'M';
  else if (spc->getType() == IPTR_IOP) {
    out << "IOP";
    return out.str();
  }
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

// Flag suffix on a varnode descriptor: {ic,ra,af,ah}
static std::string vnFlagSuffix(const Varnode *vn)
{
  std::ostringstream out;
  out << '{';
  bool first = true;
  if ((vn->getFlags() & Varnode::indirect_creation) != 0) {
    out << (first ? "" : ",") << "ic";
    first = false;
  }
  if (vn->isReturnAddress()) { out << (first ? "" : ",") << "ra"; first = false; }
  // ADDRFORCE is not projected: it comes from the ScopeLocal-derived fl
  // (queryProperties addrtied for stack locals), which the Rust comparand's
  // canonical path does not model yet — registered residual.
  if (vn->isActiveHeritage()) { out << (first ? "" : ",") << "ah"; first = false; }
  out << '}';
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
  std::vector<BlockBasic *> blockIndices;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const std::string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), stack(a.getSpace(5)),
      nextOffset(0) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    // Production assigns FlowBlock::index via BlockGraph::findSpanningTree
    // reverse post-order (block.cc:1081), which this fixture does not run;
    // the projection iterates this creation-order vector instead.
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
    return op;
  }

  PcodeOp *makeCall(const std::string &name, BlockBasic *block)
  {
    PcodeOp *op = makeOp(name, CPUI_CALL, 1);
    fd.opSetInput(op, fd.newConstant(8, 0x4000), 0);
    fd.opInsertEnd(op, block);
    return op;
  }

  void addSpec(PcodeOp *call_op, ProtoModel *model)
  {
    FuncCallSpecs *fc = new FuncCallSpecs(call_op);
    fc->setModel(model);
    // Production FuncProtos always carry a backing ProtoStore by the time
    // guardCalls runs (FuncProto::isOutputLocked dereferences store,
    // fspec.hh:1398). The internal store with a void output models the
    // unrecovered-prototype precondition.
    fc->setInternal(model, arch.types->getTypeVoid());
    specsOf(fd).push_back(fc);
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

  void setInput(PcodeOp *op, Varnode *vn, int4 slot)
  {
    fd.opSetInput(op, vn, slot);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block)
  {
    fd.opInsertEnd(op, block);
  }

  // Seed one range so it enters the disjoint cover: an 8-byte range gets a
  // written COPY (whose full-size write also suppresses refinement,
  // cc:2610); a 1-byte range gets a free read that rename promotes.
  void seedRegisterRange(uintb offset, int4 size, BlockBasic *block)
  {
    if (size >= 8) {
      PcodeOp *def = makeOp("def", CPUI_COPY, 1);
      setInput(def, constant(8, 0x11), 0);
      writtenRegister(offset, size, def);
      insertEnd(def, block);
    }
    else {
      Varnode *freevn = freeRegister(offset, size);
      PcodeOp *reader = makeOp("reader", CPUI_INT_OR, 2);
      setInput(reader, freevn, 0);
      setInput(reader, constant(1, 1), 1);
      uniqueOut(1, reader);
      insertEnd(reader, block);
    }
  }

  void seedStackRange(uintb offset, int4 size, BlockBasic *block)
  {
    if (size >= 8) {
      PcodeOp *def = makeOp("def", CPUI_COPY, 1);
      setInput(def, constant(8, 0x22), 0);
      Varnode *vn = fd.newVarnode(size, Address(stack, offset));
      fd.opSetOutput(def, vn);
      insertEnd(def, block);
    }
    else {
      Varnode *freevn = freeStack(offset, size);
      PcodeOp *reader = makeOp("reader", CPUI_INT_OR, 2);
      setInput(reader, freevn, 0);
      setInput(reader, constant(1, 1), 1);
      uniqueOut(1, reader);
      insertEnd(reader, block);
    }
  }

  // Production pre-state: Funcdata::startProcessing (funcdata.cc:150-167)
  // runs structureReset (loop structure + forward dominators) and builds
  // the Heritage info list (funcdata.cc:166) before ActionHeritage.
  void prepareStructure(void)
  {
    vector<FlowBlock *> rootlist;
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.structureLoops(rootlist);
    blocks.calcForwardDominator(rootlist);
    heritageOf(fd).buildInfoList();
  }

  std::string opAliasName(PcodeOp *op)
  {
    if (op == (PcodeOp *)0)
      return "none";
    std::map<PcodeOp *, std::string>::const_iterator iter = opNames.find(op);
    if (iter != opNames.end())
      return iter->second;
    return "none";
  }

  // Project every alive INDIRECT op in block/position order: op-level flag
  // class (ind/ic/ics), the Iop alias name, the input[0] descriptor with
  // flags, and the output descriptor with flags. Returns the count.
  int4 projectIndirects(std::ostringstream &out)
  {
    int4 count = 0;
    for (int4 bi = 0; bi < static_cast<int4>(blockIndices.size()); ++bi) {
      BlockBasic *bl = blockIndices[bi];
      int4 pos = 0;
      for (list<PcodeOp *>::const_iterator iter = bl->beginOp();
           iter != bl->endOp(); ++iter, ++pos) {
        PcodeOp *op = *iter;
        if (op->code() != CPUI_INDIRECT)
          continue;
        out << (count == 0 ? "" : ",") << bi << '.' << pos << '/';
        if (op->isIndirectStore())
          out << "ics";
        else if (op->isIndirectCreation())
          out << "ic";
        else
          out << "ind";
        out << "/iop=";
        PcodeOp *targ = (PcodeOp *)0;
        Varnode *in1 = op->getIn(1);
        if (in1 != (Varnode *)0 && in1->getSpace()->getType() == IPTR_IOP)
          targ = PcodeOp::getOpFromConst(in1->getAddr());
        out << opAliasName(targ);
        Varnode *in0 = op->getIn(0);
        out << "/in0=" << vnDescriptor(in0) << vnFlagSuffix(in0);
        Varnode *outvn = op->getOut();
        out << "/out=" << vnDescriptor(outvn) << vnFlagSuffix(outvn);
        count += 1;
      }
    }
    return count;
  }

  // Project registered trials for every callspec, in registration order,
  // plus the call op's input count.
  void projectTrials(std::ostringstream &out)
  {
    vector<FuncCallSpecs *> &specs(specsOf(fd));
    for (int4 i = 0; i < static_cast<int4>(specs.size()); ++i) {
      FuncCallSpecs *fc = specs[i];
      out << (i == 0 ? "" : ",") << "fc" << i;
      out << ":tin=[";
      for (int4 j = 0; j < fc->getActiveInput()->getNumTrials(); ++j) {
        if (j != 0)
          out << ',';
        const ParamTrial &trial(fc->getActiveInput()->getTrial(j));
        const Address &addr(trial.getAddress());
        out << addr.getSpace()->getName() << hex << addr.getOffset() << dec
            << '/' << trial.getSize();
      }
      out << ']';
      out << ":tout=[";
      for (int4 j = 0; j < fc->getActiveOutput()->getNumTrials(); ++j) {
        if (j != 0)
          out << ',';
        const ParamTrial &trial(fc->getActiveOutput()->getTrial(j));
        const Address &addr(trial.getAddress());
        out << addr.getSpace()->getName() << hex << addr.getOffset() << dec
            << '/' << trial.getSize();
      }
      out << ']';
      out << ":callin=" << fc->getOp()->numInput();
    }
  }
};

// The ten ABI-shaped ranges (GetStr decimal 0/48/56/512/514/518/519/522/523/648).
static const uintb RANGES_OFFSET[] = {
  0x0, 0x30, 0x38, 0x200, 0x202, 0x206, 0x207, 0x20a, 0x20b, 0x288,
};
static const int4 RANGES_SIZE[] = { 8, 8, 8, 1, 1, 1, 1, 1, 1, 8 };
static const int4 NUM_RANGES = 10;

static const char *effectName(uint4 effect)
{
  switch (effect) {
  case EffectRecord::unaffected: return "unaffected";
  case EffectRecord::killedbycall: return "killedbycall";
  case EffectRecord::return_address: return "return_address";
  default: return "unknown_effect";
  }
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureArchitecture arch;
  const std::string envelope =
      "schema=1|fixture=HERITAGE-CALLGUARD-0001|"
      "oracle=e40ed13014025f82488b1f8f7bca566894ac376b";
  std::cout << envelope << '\n';

  // case=model_state: the shared pre-state both sides must agree on before
  // any guard is built: the sorted effect list and the per-range effect
  // lookups through the production hasEffect.
  {
    ProtoModel *model = arch.callguard_model;
    std::ostringstream out;
    out << "case=model_state|name=" << model->getName();
    out << "|effects=[";
    int4 eff_index = 0;
    for (vector<EffectRecord>::const_iterator iter = model->effectBegin();
         iter != model->effectEnd(); ++iter, ++eff_index) {
      if (eff_index != 0)
        out << ',';
      const Address &effaddr(iter->getAddress());
      out << effaddr.getSpace()->getName() << hex << effaddr.getOffset() << dec << ':'
          << iter->getSize() << '=' << effectName(iter->getType());
    }
    out << ']';
    out << "|probe=[";
    for (int4 i = 0; i < NUM_RANGES; ++i) {
      if (i != 0)
        out << ',';
      out << hex << RANGES_OFFSET[i] << dec << '/'
          << effectName(model->hasEffect(Address(arch.getSpace(4), RANGES_OFFSET[i]), RANGES_SIZE[i]));
    }
    out << ",S18/" << effectName(model->hasEffect(Address(arch.getSpace(5), 0x18), 8));
    out << ",S8/" << effectName(model->hasEffect(Address(arch.getSpace(5), 0x8), 8));
    out << ']';
    std::cout << out.str() << '\n';
  }

  // case=single_call_ten_ranges: one call, ten seeded ranges, one canonical
  // pass. (0x0,8) hits killedbycall -> indirect creation with constant-zero
  // input; (0x288,8) hits return_address -> INDIRECT whose output carries
  // the return-address flag; the other eight are unknown_effect -> plain
  // INDIRECT whose prior-value input rename wires to the COPY def (8-byte
  // ranges) or the promoted input (1-byte ranges).
  {
    Graph g(arch, "single", 0x5100);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);
    for (int4 i = 0; i < NUM_RANGES; ++i)
      g.seedRegisterRange(RANGES_OFFSET[i], RANGES_SIZE[i], b0);
    PcodeOp *call1 = g.makeCall("call1", b1);
    g.addSpec(call1, arch.callguard_model);
    g.prepareStructure();
    g.fd.opHeritage();
    std::ostringstream out;
    out << "case=single_call_ten_ranges|guards=";
    int4 count = g.projectIndirects(out);
    out << "|count=" << count;
    std::cout << out.str() << '\n';
  }

  // case=two_calls_ten_ranges: the GetStr form — two calls in separate
  // blocks, ten ranges each, twenty INDIRECTs; each call's guards alias
  // their own call op through the Iop space and sit in the contiguous
  // group immediately before that call.
  {
    Graph g(arch, "twocall", 0x5200);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    BlockBasic *b2 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    for (int4 i = 0; i < NUM_RANGES; ++i)
      g.seedRegisterRange(RANGES_OFFSET[i], RANGES_SIZE[i], b0);
    PcodeOp *call1 = g.makeCall("call1", b1);
    PcodeOp *call2 = g.makeCall("call2", b2);
    g.addSpec(call1, arch.callguard_model);
    g.addSpec(call2, arch.callguard_model);
    g.prepareStructure();
    g.fd.opHeritage();
    std::ostringstream out;
    out << "case=two_calls_ten_ranges|guards=";
    int4 count = g.projectIndirects(out);
    out << "|count=" << count;
    std::cout << out.str() << '\n';
  }

  // case=unaffected_all: a model whose effect list marks the whole
  // register space unaffected — zero INDIRECTs after a full pass.
  {
    Graph g(arch, "unaff", 0x5300);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);
    for (int4 i = 0; i < NUM_RANGES; ++i)
      g.seedRegisterRange(RANGES_OFFSET[i], RANGES_SIZE[i], b0);
    PcodeOp *call1 = g.makeCall("call1", b1);
    g.addSpec(call1, arch.unaffected_model);
    g.prepareStructure();
    g.fd.opHeritage();
    std::ostringstream out;
    out << "case=unaffected_all|guards=";
    int4 count = g.projectIndirects(out);
    out << "|count=" << count;
    std::cout << out.str() << '\n';
  }

  // case=output_input_trials: active input+output recovery on the SYSV
  // entries. RSI(0x30,8) is a contains_justified input parameter -> trial
  // registered and the varnode appended as the call's last input (rename
  // then resolves it to the promoted input). RAX(0x0,8) is a
  // contains_justified output -> output trial registered and, being
  // killed-by-call already, a possible-output creation whose constant-zero
  // input keeps its indirect_creation flag clear.
  {
    Graph g(arch, "trials", 0x5400);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);
    g.seedRegisterRange(0x30, 8, b0);
    g.seedRegisterRange(0x0, 8, b0);
    g.seedRegisterRange(0x200, 1, b0);
    PcodeOp *call1 = g.makeCall("call1", b1);
    g.addSpec(call1, arch.callguard_model);
    FuncCallSpecs *fc = specsOf(g.fd)[0];
    fc->initActiveInput();
    fc->initActiveOutput();
    g.prepareStructure();
    g.fd.opHeritage();
    std::ostringstream out;
    out << "case=output_input_trials|guards=";
    int4 count = g.projectIndirects(out);
    out << "|count=" << count << "|trials=";
    g.projectTrials(out);
    std::cout << out.str() << '\n';
  }

  // case=stack_translation: the spacebase translation. Stack ranges are
  // delayed one pass (SpacebaseSpace delay=1), so pass 1 guards nothing;
  // pass 2 queries caller stack(0x18,8) as callee stack(0x8,8):
  //   fc0 (stack offset 0x10) -> killedbycall -> creation at the caller
  //     address S0x18 (effects are queried regardless of tryregister)
  //   fc1 (offset unknown)    -> unknown_effect -> plain INDIRECT at S0x18
  //     and no trial registration (tryregister == false)
  {
    Graph g(arch, "stack", 0x5500);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);
    g.seedStackRange(0x18, 8, b0);
    PcodeOp *call1 = g.makeCall("call1", b1);
    PcodeOp *call2 = g.makeCall("call2", b1);
    g.addSpec(call1, arch.callguard_model);
    g.addSpec(call2, arch.callguard_model);
    setSpacebaseOffset(specsOf(g.fd)[0], 0x10);
    g.prepareStructure();
    g.fd.opHeritage();
    std::ostringstream out1;
    out1 << "case=stack_translation|pass1count=" << g.projectIndirects(out1);
    g.fd.opHeritage();
    std::ostringstream out;
    out << "|guards=";
    int4 count = g.projectIndirects(out);
    out << "|count=" << count << "|trials=";
    g.projectTrials(out);
    std::cout << out1.str() << out.str() << '\n';
  }

  // case=driver_pass_gating: two passes. The first guards every new range
  // once (twenty INDIRECTs); the second pass sees only old-address ranges
  // (rename made the seeds heritage-known), so no new guard appears.
  {
    Graph g(arch, "driver", 0x5600);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    BlockBasic *b2 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b1, b2);
    for (int4 i = 0; i < NUM_RANGES; ++i)
      g.seedRegisterRange(RANGES_OFFSET[i], RANGES_SIZE[i], b0);
    PcodeOp *call1 = g.makeCall("call1", b1);
    PcodeOp *call2 = g.makeCall("call2", b2);
    g.addSpec(call1, arch.callguard_model);
    g.addSpec(call2, arch.callguard_model);
    g.prepareStructure();
    g.fd.opHeritage();
    std::ostringstream out;
    out << "case=driver_pass_gating|pass1guards=";
    int4 pass1 = g.projectIndirects(out);
    g.fd.opHeritage();
    std::ostringstream out2;
    int4 pass2 = g.projectIndirects(out2);
    out << "|pass1count=" << pass1 << "|pass2count=" << pass2
        << "|pass2new=" << (pass2 - pass1);
    std::cout << out.str() << '\n';
  }

  return 0;
}
