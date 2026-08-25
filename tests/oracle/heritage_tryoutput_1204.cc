/*
 * HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS: locked Ghidra 12.0.4 oracle for
 * the output-contains branch of Heritage::tryOutputStackGuard
 * (heritage.cc:1406-1430) — the FOURTH justifiedContain touchpoint
 * (cc:1420), after cc:1336/cc:1358 in guardOutputOverlapStack and the
 * characterization reads in fspec.cc:4344 — and for the proto-store
 * output storage chain that gates it (coreaction.cc:1538-1553
 * setStackOutputLock -> heritage.cc:1487-1494 guardCalls ->
 * fspec.cc:4339-4353/4495-4506 locked storage reads).
 *
 *  - case=stack_output_contains_full: the production
 *    Heritage::tryOutputStackGuard driven directly on a real Funcdata with
 *    one CALL op over six geometries covering every trigger combination of
 *    the branch: justified range (cc:1420 LE constant 0), unjustified
 *    ranges at +2 and at the far end (+4), size==retSize (no SUBPIECE,
 *    cc:1417 gate), a pre-existing call output (cc:1411-1412 reuse), and
 *    the vnFinal==null no-op (pre-existing output with size==retSize —
 *    cc:1426 guard leaves the write list empty while cc:1430 still
 *    returns true). The FuncCallSpecs carries the production pre-state of
 *    the guardCalls cc:1487 gate: a locked non-void output whose storage
 *    Address lives in the spacebase space (coreaction.cc:1546-1549
 *    setStackOutputLock shape), characterized through the production
 *    FuncProto::characterizeAsOutput locked branch (fspec.cc:4339-4353).
 *    The caller/callee translation (cc:1407-1410: diff = addr -
 *    transAddr, retAddr = storage + diff) is staged with stackoffset
 *    0x10: caller 0x1010 == callee 0x1000 + 0x10, so the created output
 *    varnode offset pins the translation. The projection prints every op
 *    of the call block in insertion order (CALL then opInsertAfter'd
 *    SUBPIECE, cc:1424) with the SUBPIECE in[1] constants — the decisive
 *    cc:1420 observation — plus the write-list entries and the cc:1430
 *    return value.
 *  - case=cc1420_constant: the exact cc:1420 call shape
 *    retAddr.justifiedContain(retSize, addr, size, false) on the
 *    caller-perspective return storage of the same geometries in both a
 *    little-endian and a big-endian space (address.cc:138-141 branch key
 *    base->isBigEndian() && !forceleft): LE start distance 0/2/4, BE end
 *    distance 4/2/0.
 *  - case=output_storage_projection: the locked-output storage reads of
 *    FuncProto::characterizeAsOutput (fspec.cc:4339-4353) and
 *    FuncProto::getBiggestContainedOutput (fspec.cc:4495-4506) over five
 *    containment geometries against the locked (stack, 0x1000, 8)
 *    storage: justified subrange, unjustified subrange, disjoint range, a
 *    16-byte range containing the storage (the cc:1398
 *    getBiggestContainedOutput trigger), and a partial overlap.
 *  - case=production_entry_guardcalls: the full production entry — the
 *    ActionFuncLink::funcLinkOutput producer (coreaction.cc:1538-1553:
 *    reads the locked outparam storage; spacebase storage ->
 *    setStackOutputLock(true) and the output varnode is delayed;
 *    register storage -> newVarnodeOut immediately) followed by
 *    Heritage::guardCalls (heritage.cc:1443-1527) over the guarded stack
 *    range with the cc:1466 spacebase rebase (stackoffset 0x10). The
 *    stack-lock geometry upgrades the effect to unaffected: NO INDIRECT
 *    op, the call output is created caller-perspective and truncated by
 *    SUBPIECE; the register-storage control geometry keeps
 *    unknown_effect: an INDIRECT op guards the range (cc:1511-1519).
 *
 * Varnode descriptor shared with the Rust comparand:
 *   constant -> c<size>(<value>); iop -> IOP;
 *   other    -> <hexoffset>:<size>:<I|W|F>{ah}
 * Space letters are deliberately not printed: Rugra's transitional
 * new_varnode_out creates its output varnodes in the register space while
 * Ghidra uses the range space (retAddr) — a registered projected-away
 * divergence (same convention as heritage_subpiece_const_1204) that cannot
 * affect the SUBPIECE constants, the op order, the sizes or the offsets,
 * which are the observations of this fixture.
 */

#include <bits/stdc++.h>

// heritage.hh:294-297 keeps tryOutputStackGuard and guardCalls private
// and coreaction.hh keeps ActionFuncLink::funcLinkOutput private; the
// fixture drives all three directly, so the includes take the class->struct
// access hack (the same pattern as the heritage_subpiece_const_1204 /
// justified_contain_1204 fixtures).
#define class struct
#define private public
#define protected public
#include "architecture.hh"
#include "coreaction.hh"
#include "database.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "heritage.hh"
#include "libdecomp.hh"
#include "op.hh"
#include "opcodes.hh"
#include "space.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef protected
#undef private
#undef class

using namespace ghidra;

// Test-only layout shim mirroring the locked-oracle Funcdata member
// sequence (funcdata.hh:57-95, pinned to commit
// e40ed13014025f82488b1f8f7bca566894ac376b). With the class->struct access
// hack the private members are already public; the shim keeps documentary
// parity with the heritage_subpiece_const_1204 fixture.
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
    insertSpace(new OtherSpace(this, this, OtherSpace::INDEX));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                              8, 1, 3, AddrSpace::hasphysical, 0, 0));
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register",
                                   false, 8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, getSpaceByName("ram"), 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "ram_be", true,
                              8, 1, 6, AddrSpace::hasphysical, 0, 0));
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
  ProtoModel *guard_model;

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
    // Funcdata's ctor runs FuncProto::setScope -> setModel(defaultfp)
    // (fspec.cc:3879-3884) before anything dereferences the model, so a
    // default ProtoModel must exist (same shape as
    // heritage_subpiece_const_1204; its entries are inert for the direct
    // tryOutputStackGuard drive because the output characterization runs
    // on the locked ProtoParameter, not the model).
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"tryoutputguard\" extrapop=\"0\" strategy=\"standard\">"
        "<input>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x30\" size=\"8\"/></pentry>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x38\" size=\"8\"/></pentry>"
        "</input>"
        "<output>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x0\" size=\"8\"/></pentry>"
        "</output>"
        "</prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
    guard_model = model;
  }

  void printMessage(const std::string &) const override {}
};

// Varnode descriptor shared with the Rust comparand (see the file header).
static std::string vnDescriptor(const Varnode *vn)
{
  if (vn == (Varnode *)0)
    return "-";
  if (vn->isConstant()) {
    std::ostringstream out;
    out << 'c' << vn->getSize() << '(' << std::dec << vn->getOffset() << ')';
    return out.str();
  }
  AddrSpace *spc = vn->getSpace();
  if (spc->getType() == IPTR_IOP)
    return "IOP";
  std::ostringstream out;
  out << std::hex << vn->getOffset() << std::dec << ':' << vn->getSize() << ':';
  if (vn->isInput())
    out << 'I';
  else if (vn->isWritten())
    out << 'W';
  else
    out << 'F';
  out << '{';
  if (vn->isActiveHeritage())
    out << "ah";
  out << '}';
  return out.str();
}

// The guarded range lives at caller stack 0x101x; the callee perspective is
// 0x100x (stackoffset 0x10, the guardCalls cc:1466-1468 rebase shape), and
// the locked return storage sits at callee 0x1000 with 8 bytes — the caller
// perspective return storage is [0x1010, 0x1018).
static const uintb STACK_DIFF = 0x10;
static const uintb RET_STORAGE = 0x1000;

struct ToGeom { uintb addr; int4 size; int4 retsz; bool pre_out; };

// The six trigger geometries (addr = caller-perspective range start):
//   0: justified subrange at the return storage start -> cc:1420 LE const 0
//   1: unjustified at +2 -> const 2
//   2: unjustified at the far end (+4) -> const 4
//   3: size == retSize -> no SUBPIECE (cc:1417), created outvn is the write
//   4: pre-existing call output, subrange -> cc:1411-1412 reuse + const 0
//   5: pre-existing call output, size == retSize -> no-op, empty write,
//      cc:1430 still returns true
static const ToGeom TO[] = {
  {0x1010, 4, 8, false},
  {0x1012, 4, 8, false},
  {0x1014, 4, 8, false},
  {0x1010, 8, 8, false},
  {0x1010, 4, 8, true},
  {0x1010, 8, 8, true},
};
static const int4 NUM_TO = 6;

// Drive the production tryOutputStackGuard on one geometry and print the
// full op projection of the call block plus the write-list entries.
static void runTryCase(FixtureArchitecture &arch, const ToGeom &g, int4 index)
{
  Funcdata fd("to", "to", arch.symboltab->getGlobalScope(),
              Address(arch.getSpace(3), 0x6000 + 0x10 * index),
              (FunctionSymbol *)0, 0x20);
  AddrSpace *stack = arch.getSpaceByName("stack");
  BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(&fd);
  PcodeOp *call = fd.newOp(1, fd.getAddress());
  fd.opSetOpcode(call, CPUI_CALL);
  // FuncCallSpecs::FuncCallSpecs reads the direct-call target from in(0).
  fd.opSetInput(call, fd.newConstant(8, 0x4000), 0);
  fd.opInsertEnd(call, block);
  if (g.pre_out)
    fd.newVarnodeOut(g.retsz, Address(stack, RET_STORAGE + STACK_DIFF), call);

  // Production pre-state of the guardCalls cc:1487 gate: FuncCallSpecs with
  // a locked non-void output whose storage Address is in the spacebase
  // space (the ActionFuncLink::funcLinkOutput setStackOutputLock shape,
  // coreaction.cc:1546-1549).
  FuncCallSpecs fc(call);
  fc.setModel(arch.guard_model);
  fc.setInternal(arch.guard_model, arch.types->getTypeVoid());
  ParameterPieces pieces;
  pieces.addr = Address(stack, RET_STORAGE);
  pieces.type = arch.types->getBase(g.retsz, TYPE_INT);
  pieces.flags = ParameterPieces::typelock;
  fc.setOutput(pieces);
  fc.setOutputLock(true);
  fc.setStackOutputLock(true);

  Address addr(stack, g.addr);
  Address transAddr(stack, g.addr - STACK_DIFF);
  int4 occ = fc.characterizeAsOutput(transAddr, g.size);
  vector<Varnode *> write;
  bool res = heritageOf(fd).tryOutputStackGuard(&fc, addr, transAddr, g.size,
                                                occ, write);

  std::cout << "to geom=" << index << " addr=" << std::hex << g.addr << std::dec
       << " size=" << g.size << " ret=" << std::hex << RET_STORAGE << std::dec
       << " retsz=" << g.retsz << " diff=" << STACK_DIFF
       << " retc=" << std::hex << (RET_STORAGE + STACK_DIFF) << std::dec
       << " occ=" << occ << " res=" << (res ? 1 : 0) << '\n';
  int4 pos = 0;
  for (list<PcodeOp *>::const_iterator iter = block->beginOp();
       iter != block->endOp(); ++iter, ++pos) {
    PcodeOp *op = *iter;
    // Opcode number, not name (same convention as
    // heritage_subpiece_const_1204: CALL=7, SUBPIECE=63 are identical on
    // both sides).
    std::cout << "  op" << pos << ' ' << (int4)op->code() << " in=[";
    for (int4 i = 0; i < op->numInput(); ++i) {
      if (i != 0)
        std::cout << ',';
      std::cout << vnDescriptor(op->getIn(i));
    }
    std::cout << "] out=" << vnDescriptor(op->getOut()) << '\n';
  }
  for (int4 i = 0; i < (int4)write.size(); ++i)
    std::cout << "  write" << i << ' ' << vnDescriptor(write[i]) << '\n';
}

// Containment geometries for the locked-branch storage reads (offsets are
// callee-perspective; storage = (stack, 0x1000, 8)):
//   0: justified subrange      -> contains_justified, biggest=-
//   1: unjustified at +2       -> contains_unjustified, biggest=-
//   2: disjoint at +8          -> no_containment, biggest=-
//   3: 16-byte range holding   -> contained_by, biggest=1000:8
//      the storage (the cc:1398 getBiggestContainedOutput trigger)
//   4: partial overlap at +2/8 -> no_containment, biggest=-
struct PrGeom { uintb off; int4 size; };
static const PrGeom PR[] = {
  {0x1000, 4},
  {0x1002, 4},
  {0x1008, 4},
  {0x0ff8, 16},
  {0x1002, 8},
};
static const int4 NUM_PR = 5;

// Drive the production locked-output storage reads —
// FuncProto::characterizeAsOutput and FuncProto::getBiggestContainedOutput
// (fspec.cc:4339-4353 / 4495-4506) — over the containment geometries.
static void runProjectionCase(FixtureArchitecture &arch)
{
  Funcdata fd("pr", "pr", arch.symboltab->getGlobalScope(),
              Address(arch.getSpace(3), 0x6800), (FunctionSymbol *)0, 0x20);
  AddrSpace *stack = arch.getSpaceByName("stack");
  BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(&fd);
  PcodeOp *call = fd.newOp(1, fd.getAddress());
  fd.opSetOpcode(call, CPUI_CALL);
  fd.opSetInput(call, fd.newConstant(8, 0x4000), 0);
  fd.opInsertEnd(call, block);
  FuncCallSpecs fc(call);
  fc.setModel(arch.guard_model);
  fc.setInternal(arch.guard_model, arch.types->getTypeVoid());
  ParameterPieces pieces;
  pieces.addr = Address(stack, RET_STORAGE);
  pieces.type = arch.types->getBase(8, TYPE_INT);
  pieces.flags = ParameterPieces::typelock;
  fc.setOutput(pieces);
  fc.setOutputLock(true);

  for (int4 i = 0; i < NUM_PR; ++i) {
    const PrGeom &g = PR[i];
    int4 occ = fc.characterizeAsOutput(Address(stack, g.off), g.size);
    VarnodeData vdata;
    bool biggest = fc.getBiggestContainedOutput(Address(stack, g.off), g.size, vdata);
    std::cout << "  pr geom=" << i << " off=" << std::hex << g.off << std::dec
              << " size=" << g.size << " occ=" << occ << " biggest=";
    if (biggest)
      std::cout << std::hex << vdata.offset << std::dec << ':' << vdata.size;
    else
      std::cout << '-';
    std::cout << '\n';
  }
}

// Drive the full production entry for one call spec: the
// ActionFuncLink::funcLinkOutput producer (coreaction.cc:1538-1553) then
// Heritage::guardCalls over the guarded stack range (heritage.cc:1443-
// 1527, fl=0, stackoffset 0x10). stack_space=true stages the locked
// storage in the spacebase space (the setStackOutputLock path); false
// stages it in the register space (the immediate-newVarnodeOut control).
static void runGuardCase(FixtureArchitecture &arch, int4 index, bool stack_space)
{
  Funcdata fd("gc", "gc", arch.symboltab->getGlobalScope(),
              Address(arch.getSpace(3), 0x6100 + 0x10 * index),
              (FunctionSymbol *)0, 0x20);
  AddrSpace *stack = arch.getSpaceByName("stack");
  AddrSpace *reg = arch.getSpaceByName("register");
  BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(&fd);
  PcodeOp *call = fd.newOp(1, fd.getAddress());
  fd.opSetOpcode(call, CPUI_CALL);
  fd.opSetInput(call, fd.newConstant(8, 0x4000), 0);
  fd.opInsertEnd(call, block);

  FuncCallSpecs *fc = new FuncCallSpecs(call);
  fc->setModel(arch.guard_model);
  fc->setInternal(arch.guard_model, arch.types->getTypeVoid());
  ParameterPieces pieces;
  pieces.addr = stack_space ? Address(stack, RET_STORAGE) : Address(reg, 0x0);
  pieces.type = arch.types->getBase(8, TYPE_INT);
  pieces.flags = ParameterPieces::typelock;
  fc->setOutput(pieces);
  fc->setOutputLock(true);
  // The Funcdata owns the spec (FlowInfo::setupCallSpecs registration
  // shape, flow.cc:684-686) because guardCalls walks fd->numCalls().
  fd.qlst.push_back(fc);
  // cc:1466-1465: the spacebase rebase offset (FuncCallSpecs::
  // setSpacebaseRelative shape) — caller 0x101x == callee 0x100x + 0x10.
  fc->stackoffset = STACK_DIFF;

  // The producer: coreaction.cc:1521 funcLinkOutput. For the spacebase
  // storage this sets the stack-output lock and delays the output varnode;
  // for the register storage it creates the output varnode immediately at
  // the recorded offset.
  ActionFuncLink::funcLinkOutput(fc, fd);
  std::cout << "gc geom=" << index << " stackspace=" << (stack_space ? 1 : 0)
            << " stacklock=" << (fc->isStackOutputLock() ? 1 : 0)
            << " pre_out=" << (call->getOut() != (Varnode *)0 ? 1 : 0) << '\n';

  vector<Varnode *> write;
  heritageOf(fd).guardCalls(0, Address(stack, 0x1010), 4, write);
  int4 pos = 0;
  for (list<PcodeOp *>::const_iterator iter = block->beginOp();
       iter != block->endOp(); ++iter, ++pos) {
    PcodeOp *op = *iter;
    // Opcode number, not name (CALL=7, INDIRECT=61, SUBPIECE=63 are
    // identical on both sides).
    std::cout << "  op" << pos << ' ' << (int4)op->code() << " in=[";
    for (int4 i = 0; i < op->numInput(); ++i) {
      if (i != 0)
        std::cout << ',';
      std::cout << vnDescriptor(op->getIn(i));
    }
    std::cout << "] out=" << vnDescriptor(op->getOut()) << '\n';
  }
  for (int4 i = 0; i < (int4)write.size(); ++i)
    std::cout << "  write" << i << ' ' << vnDescriptor(write[i]) << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  vector<string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureArchitecture arch;
  std::cout << "schema=1|fixture=HERITAGE-TRYOUTPUT-STACKGUARD-CONTAINS|"
          "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
       << std::endl;

  // ---- case 1: production tryOutputStackGuard, output-contains --------
  std::cout << "case=stack_output_contains_full" << std::endl;
  for (int4 i = 0; i < NUM_TO; ++i)
    runTryCase(arch, TO[i], i);

  // ---- case 2: cc:1420 constants in LE and BE spaces ------------------
  std::cout << "case=cc1420_constant" << std::endl;
  AddrSpace *le = arch.getSpaceByName("stack");
  AddrSpace *be = arch.getSpaceByName("ram_be");
  for (int4 i = 0; i < NUM_TO; ++i) {
    const ToGeom &g = TO[i];
    uintb retc = RET_STORAGE + STACK_DIFF;
    int4 amt_le = Address(le, retc).justifiedContain(
        g.retsz, Address(le, g.addr), g.size, false);
    int4 amt_be = Address(be, retc).justifiedContain(
        g.retsz, Address(be, g.addr), g.size, false);
    std::cout << "  sp geom=" << i << " le=" << amt_le << " be=" << amt_be << '\n';
  }

  // ---- case 3: locked-output storage reads (fspec locked branches) ----
  std::cout << "case=output_storage_projection" << std::endl;
  runProjectionCase(arch);

  // ---- case 4: production entry — funcLinkOutput + guardCalls ---------
  std::cout << "case=production_entry_guardcalls" << std::endl;
  runGuardCase(arch, 0, true);
  runGuardCase(arch, 1, false);

  return 0;
}
