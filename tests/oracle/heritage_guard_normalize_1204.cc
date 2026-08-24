/*
 * HERITAGE-GUARD-NORMALIZE-0001: locked Ghidra 12.0.4 oracle for the
 * guard/return normalization slice of Heritage::guard (heritage.cc:1156):
 * the fl queryProperties call (cc:1191), guardReturns wiring (cc:1193) and
 * the highPtrPossible gate (cc:1194), guardReturnsOverlapping (cc:1609),
 * guardReturns (cc:1652), normalizeWriteSize (cc:416) with
 * callOpIndirectEffect (cc:358), and the guard-per-new-range timing
 * (addIndirects = MemRange::newAddresses, cc:1188) across heritage passes
 * (retry/pass counter boundary, cc:2757).
 *
 * All cases drive the production boundary `fd.opHeritage()` after
 * structureLoops/calcForwardDominator/buildInfoList.  Objects are projected
 * only through storage, size, class, defining opcode, per-flag booleans and
 * first-seen alias ids; no raw pointers.
 *
 * Cases:
 *   guard_returns_trial_register  whole-range return storage
 *                                 (characterizeAsOutput = contains_justified):
 *                                 every live non-halt RETURN takes a fresh
 *                                 full-range input (cc:1663-1673); the halt
 *                                 RETURN takes nothing (cc:1669); the trial
 *                                 is registered once at the storage
 *                                 (cc:1664).
 *   guard_returns_overlapping_subpiece
 *                                 range properly contains the return storage
 *                                 (contained_by): a SUBPIECE truncation is
 *                                 inserted before each live RETURN with the
 *                                 truncated output storage (cc:1628-1636);
 *                                 the trial registers at the truncated
 *                                 address with the storage size (cc:1619).
 *   persist_return_copy_suffix   no active output; the range carries the
 *                                 persist property through
 *                                 queryProperties->getProperty (cc:1278):
 *                                 every live RETURN — halt points INCLUDED
 *                                 (cc:1678-1680 has no halt check) — gets a
 *                                 return-copy COPY whose output is
 *                                 address-forced and whose op carries
 *                                 PcodeOp::return_copy (cc:1681-1690).
 *   normalize_write_call_piece   normalizeWriteSize on a CALL-defined
 *                                 partial write: callOpIndirectEffect drives
 *                                 the INDIRECT-creation piece branch
 *                                 (cc:434-437/455-457); the CALL also
 *                                 gets its whole-range unknown-effect
 *                                 INDIRECT from guardCalls (cc:1511-1519).
 *   normalize_write_subpiece_piece
 *                                 normalizeWriteSize on a plain partial
 *                                 write: the piece comes from a SUBPIECE of
 *                                 a fresh full-range free read
 *                                 (cc:460-467) and the final PIECE output
 *                                 replaces the write-list entry (cc:1180).
 *   guard_retry_pass_boundary    stack-space range (delay 1) with a CALL:
 *                                 pass 0 heritages register only; pass 1
 *                                 guards the new stack range (INDIRECT);
 *                                 pass 2 re-runs on the OLD range and adds
 *                                 no new guard (cc:2711-2719 prev==2
 *                                 skip / cc:1188 addIndirects).
 *
 * Architecture/compiler spec mirror the FLAGFREE/CALLGUARD fixtures: the
 * synthetic Translate provides const/other/unique/ram/register/stack/join/
 * iop spaces; ret8 models an 8-byte register:0x0 output, ret4hi a 4-byte
 * register:0x4 output; guardnorm_call has no effect records (unknown).
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

// Test-only observation shim (FLAGFREE/CALLGUARD contract): re-declares the
// locked-oracle member sequence of Funcdata (funcdata.hh:57-95) to reach the
// Heritage member and the qlst call-spec list.  Layout pinned to oracle
// commit e40ed13014025f82488b1f8f7bca566894ac376b, verified by the runner.
struct FuncdataHeritageShim {
  uint4 flags;
  uint4 clean_up_index;
  uint4 high_level_index;
  uint4 cast_phase_index;
  int4 minLanedSize;
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

namespace fixture_access {
template <class Tag>
struct Result {
  static typename Tag::type ptr;
};
template <class Tag>
typename Tag::type Result<Tag>::ptr = nullptr;
template <class Tag, typename Tag::type member>
struct Init {
  static const int value;
};
template <class Tag, typename Tag::type member>
const int Init<Tag, member>::value = (Result<Tag>::ptr = member, 0);
struct QlstTag { typedef vector<FuncCallSpecs *> Funcdata::* type; };
}  // namespace fixture_access

template struct fixture_access::Init<fixture_access::QlstTag, &Funcdata::qlst>;

static vector<FuncCallSpecs *> &specsOf(Funcdata &fd)
{
  return fd.*fixture_access::Result<fixture_access::QlstTag>::ptr;
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
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false,
                              8, 1, 6, AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummy_register.space = reg;
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override {
    return dummy_register;
  }
  string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(map<VarnodeData, string> &) const override {}
  void getUserOpNames(vector<string> &) const override {}
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
  ProtoModel *ret8_model;
  ProtoModel *ret4hi_model;
  ProtoModel *call_model;

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
    // Base default model: the Funcdata ctor's funcp.setScope installs
    // defaultfp, and ScopeLocal::resetLocalWindow dereferences it
    // (fspec.hh:1539/1541), so it must be a valid empty model.
    ProtoModel *base = decodeModel(
        "<prototype name=\"guardnorm_default\" extrapop=\"0\" strategy=\"standard\">"
        "<input/>"
        "<output/>"
        "</prototype>");
    setDefaultModel(base);

    ret8_model = decodeModel(
        "<prototype name=\"guardnorm_ret8\" extrapop=\"0\" strategy=\"standard\">"
        "<input/>"
        "<output>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x0\" size=\"8\"/></pentry>"
        "</output>"
        "</prototype>");
    ret4hi_model = decodeModel(
        "<prototype name=\"guardnorm_ret4hi\" extrapop=\"0\" strategy=\"standard\">"
        "<input/>"
        "<output>"
        "<pentry minsize=\"1\" maxsize=\"4\"><addr space=\"register\" offset=\"0x4\" size=\"4\"/></pentry>"
        "</output>"
        "</prototype>");
    call_model = decodeModel(
        "<prototype name=\"guardnorm_call\" extrapop=\"0\" strategy=\"standard\">"
        "<input/>"
        "<output/>"
        "</prototype>");
  }

  ProtoModel *decodeModel(const char *xml) {
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(xml);
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    return model;
  }

  void printMessage(const string &) const override {}
};

static const char *opcodeName(OpCode opc)
{
  switch (opc) {
  case CPUI_COPY: return "COPY";
  case CPUI_INT_ADD: return "INT_ADD";
  case CPUI_INT_SUB: return "INT_SUB";
  case CPUI_INT_OR: return "INT_OR";
  case CPUI_CALL: return "CALL";
  case CPUI_CALLIND: return "CALLIND";
  case CPUI_RETURN: return "RETURN";
  case CPUI_INDIRECT: return "INDIRECT";
  case CPUI_MULTIEQUAL: return "MULTIEQUAL";
  case CPUI_PIECE: return "PIECE";
  case CPUI_SUBPIECE: return "SUBPIECE";
  default: return "OTHER";
  }
}

class Graph {
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  AddrSpace *stack;
  std::map<PcodeOp *, string> opNames;
  std::vector<BlockBasic *> blockIndices;
  std::map<const Varnode *, int4> aliases;
  int4 nextAlias;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), stack(a.getSpace(5)),
      nextAlias(0), nextOffset(0) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    blockIndices.push_back(block);
    return block;
  }

  void edge(BlockBasic *from, BlockBasic *to)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.addEdge(from, to);
  }

  PcodeOp *makeOp(const string &name, OpCode opcode, int4 inputs)
  {
    Address pc(ram, fd.getAddress().getOffset() + (uintb)nextOffset);
    nextOffset += 1;
    PcodeOp *op = fd.newOp(inputs, pc);
    fd.opSetOpcode(op, opcode);
    opNames.insert(std::make_pair(op, name));
    return op;
  }

  void addSpec(PcodeOp *call_op, ProtoModel *model)
  {
    FuncCallSpecs *fc = new FuncCallSpecs(call_op);
    fc->setModel(model);
    // Production FuncProtos always carry a backing ProtoStore by the time
    // guardCalls runs; the internal store with a void output models the
    // unrecovered-prototype precondition.
    fc->setInternal(model, arch.types->getTypeVoid());
    specsOf(fd).push_back(fc);
  }

  Varnode *uniqueOut(int4 size, PcodeOp *op) { return fd.newUniqueOut(size, op); }
  Varnode *constant(int4 size, uintb value) { return fd.newConstant(size, value); }
  Varnode *freeRegister(uintb offset, int4 size)
  {
    return fd.newVarnode(size, Address(reg, offset));
  }
  Varnode *freeStack(uintb offset, int4 size)
  {
    return fd.newVarnode(size, Address(stack, offset));
  }
  Varnode *freeRam(uintb offset, int4 size)
  {
    return fd.newVarnode(size, Address(ram, offset));
  }
  Varnode *writtenRegister(uintb offset, int4 size, PcodeOp *op)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    fd.opSetOutput(op, vn);
    return op->getOut();
  }
  void setInput(PcodeOp *op, Varnode *vn, int4 slot) { fd.opSetInput(op, vn, slot); }
  void insertEnd(PcodeOp *op, BlockBasic *block) { fd.opInsertEnd(op, block); }

  void prepareStructure(void)
  {
    vector<FlowBlock *> rootlist;
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.structureLoops(rootlist);
    blocks.calcForwardDominator(rootlist);
    heritageOf(fd).buildInfoList();
  }

  string opAliasName(const PcodeOp *op) const
  {
    if (op == (const PcodeOp *)0) return "none";
    std::map<PcodeOp *, string>::const_iterator iter =
        opNames.find(const_cast<PcodeOp *>(op));
    if (iter != opNames.end()) return iter->second;
    return "none";
  }

  int4 alias(const Varnode *vn)
  {
    std::map<const Varnode *, int4>::iterator iter = aliases.find(vn);
    if (iter != aliases.end()) return iter->second;
    int4 id = nextAlias++;
    aliases[vn] = id;
    return id;
  }

  // Space-coded storage + class + defining opcode + flag booleans.  Raw
  // flag words are NOT printed (implementation bit values differ); the
  // semantic booleans are.
  string vnState(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "null";
    ostringstream out;
    out << 'a' << alias(vn) << ':';
    AddrSpace *spc = vn->getSpace();
    if (vn->isConstant())
      out << 'C' << vn->getSize() << ':' << hex << vn->getOffset() << dec;
    else if (spc->getName() == "register")
      out << 'R' << hex << vn->getOffset() << dec << ':' << vn->getSize();
    else if (spc->getType() == IPTR_SPACEBASE)
      out << 'S' << hex << vn->getOffset() << dec << ':' << vn->getSize();
    else if (spc->getType() == IPTR_INTERNAL)
      out << 'U' << vn->getSize();
    else if (spc->getType() == IPTR_IOP)
      out << "IOP" << vn->getSize();
    else if (spc->getName() == "ram")
      out << 'M' << hex << vn->getOffset() << dec << ':' << vn->getSize();
    else
      out << "OTH:" << hex << vn->getOffset() << dec << ':' << vn->getSize();
    char cls = vn->isConstant() ? 'C' : (vn->isAnnotation() ? 'A' :
        (vn->isInput() ? 'I' : (vn->isWritten() ? 'W' : 'F')));
    out << ':' << cls
        << ":def" << (vn->isWritten() ? opcodeName(vn->getDef()->code()) : "-")
        << ":act" << (vn->isActiveHeritage() ? 1 : 0)
        << ":force" << (vn->isAddrForce() ? 1 : 0)
        << ":wmask" << (vn->isWriteMask() ? 1 : 0)
        << ":persist" << (vn->isPersist() ? 1 : 0);
    return out.str();
  }

  // Op projection: alias name + opcode + op-level flag booleans + full
  // input/output states, in slot order.
  string opState(const PcodeOp *op)
  {
    ostringstream out;
    out << opAliasName(op) << '.' << opcodeName(op->code())
        << "{rc=" << (op->isReturnCopy() ? 1 : 0)
        << ",halt=" << hex << op->getHaltType() << dec
        << ",ic=" << (op->isIndirectCreation() ? 1 : 0)
        << ",is=" << (op->isIndirectStore() ? 1 : 0)
        << ",out=" << vnState(op->getOut());
    for (int4 slot = 0; slot < op->numInput(); ++slot)
      out << ",s" << slot << '=' << vnState(op->getIn(slot));
    out << '}';
    return out.str();
  }

  // Every alive op of every block, in block-creation order and in-block
  // execution order.
  string order(void)
  {
    ostringstream out;
    for (size_t bi = 0; bi < blockIndices.size(); ++bi) {
      if (bi != 0) out << ';';
      out << "b" << bi << '[';
      bool first = true;
      for (list<PcodeOp *>::const_iterator iter = blockIndices[bi]->beginOp();
           iter != blockIndices[bi]->endOp(); ++iter) {
        if (!first) out << ',';
        first = false;
        out << opState(*iter);
      }
      out << ']';
    }
    return out.str();
  }

  // Count of alive INDIRECT ops.
  int4 indirectCount(void)
  {
    int4 count = 0;
    for (size_t bi = 0; bi < blockIndices.size(); ++bi) {
      for (list<PcodeOp *>::const_iterator iter = blockIndices[bi]->beginOp();
           iter != blockIndices[bi]->endOp(); ++iter)
        if ((*iter)->code() == CPUI_INDIRECT) count += 1;
    }
    return count;
  }

  // Output-trial projection of the function's own active output:
  // per-trial storage offset/size/slot/killedbycall, in registration order.
  string trialProjection(void)
  {
    ostringstream out;
    ParamActive *active = fd.getActiveOutput();
    if (active == (ParamActive *)0) {
      out << "none";
      return out.str();
    }
    for (int4 i = 0; i < active->getNumTrials(); ++i) {
      if (i != 0) out << ';';
      const ParamTrial &trial(active->getTrial(i));
      out << "t" << i << '=' << hex << trial.getAddress().getOffset() << dec
          << ':' << trial.getSize() << ":slot" << trial.getSlot()
          << ":kb" << (trial.isKilledByCall() ? 1 : 0);
    }
    return out.str();
  }

  int4 heritagePassOf(const Address &addr)
  {
    return heritageOf(fd).heritagePass(addr);
  }
};

int main(void)
{
  std::cout << std::unitbuf;
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  FixtureArchitecture arch;
  std::cout << "schema=1|fixture=HERITAGE-GUARD-NORMALIZE-0001|oracle="
            << "e40ed13014025f82488b1f8f7bca566894ac376b" << std::endl;

  // ---- case 1: whole-range return storage -> RETURN input trial ----
  {
    Graph g(arch, "guard_returns_trial_register", 0x6100);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    BlockBasic *b2 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b0, b2);
    g.fd.getFuncProto().setModel(arch.ret8_model);
    g.fd.initActiveOutput();
    PcodeOp *read = g.makeOp("read", CPUI_INT_OR, 2);
    g.setInput(read, g.freeRegister(0x0, 8), 0);
    g.setInput(read, g.constant(8, 0x21), 1);
    g.uniqueOut(8, read);
    g.insertEnd(read, b0);
    PcodeOp *ret0 = g.makeOp("ret0", CPUI_RETURN, 1);
    g.setInput(ret0, g.constant(8, 0x6100), 0);
    g.insertEnd(ret0, b0);
    PcodeOp *rhalt = g.makeOp("rhalt", CPUI_RETURN, 1);
    g.setInput(rhalt, g.constant(8, 0x6101), 0);
    g.insertEnd(rhalt, b1);
    g.fd.opMarkHalt(rhalt, PcodeOp::missing);
    PcodeOp *ret2 = g.makeOp("ret2", CPUI_RETURN, 1);
    g.setInput(ret2, g.constant(8, 0x6102), 0);
    g.insertEnd(ret2, b2);
    g.prepareStructure();
    g.fd.opHeritage();
    std::cout << "case=guard_returns_trial_register"
              << "|pass=" << g.fd.getHeritagePass()
              << "|hp_reg=" << g.heritagePassOf(Address(g.reg, 0x0))
              << "|trials=" << g.trialProjection()
              << "|ret0_in=" << ret0->numInput()
              << "|ret0_last=" << g.vnState(ret0->getIn(ret0->numInput() - 1))
              << "|rhalt_in=" << rhalt->numInput()
              << "|ret2_in=" << ret2->numInput()
              << "|ret2_last=" << g.vnState(ret2->getIn(ret2->numInput() - 1))
              << "|order=" << g.order() << std::endl;
  }

  // ---- case 2: range contains return storage -> SUBPIECE truncation ----
  {
    Graph g(arch, "guard_returns_overlapping_subpiece", 0x6200);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);
    g.fd.getFuncProto().setModel(arch.ret4hi_model);
    g.fd.initActiveOutput();
    PcodeOp *read = g.makeOp("read", CPUI_INT_ADD, 2);
    g.setInput(read, g.freeRegister(0x0, 8), 0);
    g.setInput(read, g.constant(8, 0x22), 1);
    g.uniqueOut(8, read);
    g.insertEnd(read, b0);
    PcodeOp *ret0 = g.makeOp("ret0", CPUI_RETURN, 1);
    g.setInput(ret0, g.constant(8, 0x6200), 0);
    g.insertEnd(ret0, b0);
    PcodeOp *rhalt = g.makeOp("rhalt", CPUI_RETURN, 1);
    g.setInput(rhalt, g.constant(8, 0x6201), 0);
    g.insertEnd(rhalt, b1);
    g.fd.opMarkHalt(rhalt, PcodeOp::badinstruction);
    g.prepareStructure();
    g.fd.opHeritage();
    std::cout << "case=guard_returns_overlapping_subpiece"
              << "|pass=" << g.fd.getHeritagePass()
              << "|trials=" << g.trialProjection()
              << "|ret0_in=" << ret0->numInput()
              << "|ret0_last=" << g.vnState(ret0->getIn(ret0->numInput() - 1))
              << "|rhalt_in=" << rhalt->numInput()
              << "|order=" << g.order() << std::endl;
  }

  // ---- case 3: persist property -> return-copy COPY suffix (no active
  //      output; halt RETURN included) ----
  {
    // Whole-ram persist property band [0x1000,0x2000].
    arch.symboltab->setPropertyRange(Varnode::persist,
                                     Range(arch.getSpace(3), 0x1000, 0x2000));
    Graph g(arch, "persist_return_copy_suffix", 0x6300);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    g.edge(b0, b1);
    PcodeOp *read = g.makeOp("read", CPUI_INT_OR, 2);
    g.setInput(read, g.freeRam(0x1000, 8), 0);
    g.setInput(read, g.constant(8, 0x23), 1);
    g.uniqueOut(8, read);
    g.insertEnd(read, b0);
    PcodeOp *ret0 = g.makeOp("ret0", CPUI_RETURN, 1);
    g.setInput(ret0, g.constant(8, 0x6300), 0);
    g.insertEnd(ret0, b0);
    PcodeOp *rhalt = g.makeOp("rhalt", CPUI_RETURN, 1);
    g.setInput(rhalt, g.constant(8, 0x6301), 0);
    g.insertEnd(rhalt, b1);
    g.fd.opMarkHalt(rhalt, PcodeOp::missing);
    g.prepareStructure();
    g.fd.opHeritage();
    // The op immediately preceding each RETURN is the return-copy COPY.
    PcodeOp *beforeRet0 = ret0->previousOp();
    PcodeOp *beforeRhalt = rhalt->previousOp();
    std::cout << "case=persist_return_copy_suffix"
              << "|pass=" << g.fd.getHeritagePass()
              << "|trials=" << g.trialProjection()
              << "|before_ret0=" << g.opState(beforeRet0)
              << "|before_rhalt=" << g.opState(beforeRhalt)
              << "|ret0_in=" << ret0->numInput()
              << "|order=" << g.order() << std::endl;
  }

  // ---- case 4: normalizeWriteSize on a CALL-defined partial write ----
  {
    Graph g(arch, "normalize_write_call_piece", 0x6400);
    BlockBasic *b0 = g.makeBlock();
    PcodeOp *call = g.makeOp("call", CPUI_CALL, 1);
    g.setInput(call, g.constant(8, 0x4000), 0);
    g.writtenRegister(0x12, 2, call);
    g.insertEnd(call, b0);
    g.addSpec(call, arch.call_model);
    PcodeOp *read = g.makeOp("read", CPUI_INT_OR, 2);
    g.setInput(read, g.freeRegister(0x10, 4), 0);
    g.setInput(read, g.constant(8, 0x24), 1);
    g.uniqueOut(8, read);
    g.insertEnd(read, b0);
    PcodeOp *ret0 = g.makeOp("ret0", CPUI_RETURN, 1);
    g.setInput(ret0, g.constant(8, 0x6400), 0);
    g.insertEnd(ret0, b0);
    g.prepareStructure();
    g.fd.opHeritage();
    std::cout << "case=normalize_write_call_piece"
              << "|pass=" << g.fd.getHeritagePass()
              << "|hp_reg=" << g.heritagePassOf(Address(g.reg, 0x10))
              << "|call_out=" << g.vnState(call->getOut())
              << "|order=" << g.order() << std::endl;
  }

  // ---- case 5: normalizeWriteSize on a plain partial write (SUBPIECE
  //      piece branch, write-list replacement) ----
  {
    Graph g(arch, "normalize_write_subpiece_piece", 0x6500);
    BlockBasic *b0 = g.makeBlock();
    PcodeOp *w = g.makeOp("w", CPUI_INT_SUB, 2);
    g.setInput(w, g.constant(8, 0x31), 0);
    g.setInput(w, g.constant(8, 0x32), 1);
    g.writtenRegister(0x22, 2, w);
    g.insertEnd(w, b0);
    PcodeOp *read = g.makeOp("read", CPUI_INT_OR, 2);
    g.setInput(read, g.freeRegister(0x20, 4), 0);
    g.setInput(read, g.constant(8, 0x25), 1);
    g.uniqueOut(8, read);
    g.insertEnd(read, b0);
    PcodeOp *ret0 = g.makeOp("ret0", CPUI_RETURN, 1);
    g.setInput(ret0, g.constant(8, 0x6500), 0);
    g.insertEnd(ret0, b0);
    g.prepareStructure();
    g.fd.opHeritage();
    std::cout << "case=normalize_write_subpiece_piece"
              << "|pass=" << g.fd.getHeritagePass()
              << "|w_out=" << g.vnState(w->getOut())
              << "|read_in=" << g.vnState(read->getIn(0))
              << "|order=" << g.order() << std::endl;
  }

  // ---- case 6: guard timing across passes (stack delay 1, CALL guard) ----
  {
    Graph g(arch, "guard_retry_pass_boundary", 0x6600);
    BlockBasic *b0 = g.makeBlock();
    PcodeOp *call = g.makeOp("call", CPUI_CALL, 1);
    g.setInput(call, g.constant(8, 0x4000), 0);
    g.insertEnd(call, b0);
    g.addSpec(call, arch.call_model);
    PcodeOp *read = g.makeOp("read", CPUI_INT_OR, 2);
    g.setInput(read, g.freeStack(0x20, 8), 0);
    g.setInput(read, g.constant(8, 0x26), 1);
    g.uniqueOut(8, read);
    g.insertEnd(read, b0);
    PcodeOp *ret0 = g.makeOp("ret0", CPUI_RETURN, 1);
    g.setInput(ret0, g.constant(8, 0x6600), 0);
    g.insertEnd(ret0, b0);
    g.prepareStructure();
    g.fd.opHeritage();  // pass 0: register spaces only; stack delayed
    const int4 indirectsAfterPass0 = g.indirectCount();
    g.fd.opHeritage();  // pass 1: new stack range -> guard fires
    const int4 indirectsAfterPass1 = g.indirectCount();
    g.fd.opHeritage();  // pass 2: old range -> no new guard
    const int4 indirectsAfterPass2 = g.indirectCount();
    std::cout << "case=guard_retry_pass_boundary"
              << "|pass=" << g.fd.getHeritagePass()
              << "|hp_stack=" << g.heritagePassOf(Address(g.stack, 0x20))
              << "|ind0=" << indirectsAfterPass0
              << "|ind1=" << indirectsAfterPass1
              << "|ind2=" << indirectsAfterPass2
              << "|read_in=" << g.vnState(read->getIn(0))
              << "|order=" << g.order() << std::endl;
  }
  return 0;
}
