/*
 * PIPE-STACKSTALL-COUNT-0001: locked Ghidra 12.0.4 stackstall fixed-point
 * count feedback oracle (coreaction.cc:5509-5657, action.cc:298-362).
 *
 * The fixture derives the real default pipeline tree
 * (universalAction -> resetDefaults -> getCurrent, exactly as
 * tests/oracle/pipeline_tree_1204.cc does), addresses the stackstall
 * group through the official ':' name path (Action::getSubAction,
 * action.cc:456-479), and drives the group through one external mirror of
 * Action::perform's do-while loop (action.cc:303-350): per pass the
 * group's lcount/count members and every child Action's
 * status/count/lcount/count_tests/count_apply are printed after the pass's
 * ActionGroup::apply (action.cc:506-527) ran each child's perform().
 *
 * The function IR exercises three of the four leaf channels:
 *   - shadowvar: two same-input MULTIEQUALs in one block, at the block's
 *     start address, separated by an INT_ADD that stops ActionMultiCse's
 *     scan (coreaction.cc:834-835) but not ActionShadowVar's
 *     (coreaction.cc:912-914) — the later MULTIEQUAL is rewritten to a
 *     COPY of the earlier one's output (count += 1, cc:945);
 *   - stackptrflow: a repaired "clog" — INT_ADD(sp, LOAD(sp+16)) with the
 *     matching STORE(sp+16, const) before it — the LOAD becomes a COPY of
 *     the stored constant (count += 1, cc:492) and the clean pass sets
 *     analysis_finished (cc:496) after the extrapop-known analyzeExtraPop
 *     early-return (cc:267; the fixture proto model has extrapop="0");
 *   - multicse: two functionally equivalent MULTIEQUALs leading another
 *     block — one is totalReplaced/destroyed (count += 1, cc:873).
 *
 * After the fixed point the group is reset (ActionGroup::reset ->
 * ActionStackPtrFlow::reset clears analysis_finished, coreaction.hh:99)
 * and driven a second time: no leaf reports changes, the group converges
 * in one pass, and stackptrflow's count_tests increments again (the
 * re-analysis that only reset can cause).
 *
 * Deindirect's change branch (CALLIND + persist/externalref, cc:1219-1240)
 * is not exercised; its zero-count channel is observed.
 */

#include <bits/stdc++.h>

// Test-only access is required to read the Action executor statistics and
// the ActionGroup child list (both protected), matching what production
// reaches through the console API.
#define private public
#define protected public
#include "architecture.hh"
#include "coreaction.hh"
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
#undef protected

using namespace ghidra;

// Test-only shim (same pattern as tests/oracle/heritage_ownership_1204.cc):
// Funcdata's private section is an UNLABELED default-private region, so the
// `#define private public` trick cannot expose `fd.heritage`. This shim
// re-declares the exact locked-oracle member sequence of Funcdata
// (funcdata.hh:57-95) to reach the Heritage member for the one production
// startProcessing step a synthetic-graph fixture cannot reach otherwise:
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

class Graph {
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  std::map<PcodeOp *, std::string> opNames;
  std::vector<PcodeOp *> opOrder;
  std::map<Varnode *, std::string> vnNames;
  std::vector<Varnode *> vnOrder;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const std::string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), nextOffset(0) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    block->index = static_cast<int4>(fd.getBasicBlocks().getSize() - 1);
    return block;
  }

  void edge(BlockBasic *from, BlockBasic *to)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.addEdge(from, to);
  }

  // Make an op whose PC offset is pinned (several ops may share one offset;
  // the shadowvar trio must all sit at the block's start address).
  PcodeOp *makeOpAt(const std::string &name, OpCode opcode, int4 inputs, uintb offset)
  {
    Address pc(ram, fd.getAddress().getOffset() + offset);
    PcodeOp *op = fd.newOp(inputs, pc);
    fd.opSetOpcode(op, opcode);
    opNames.insert(std::make_pair(op, name));
    opOrder.push_back(op);
    return op;
  }

  Varnode *uniqueOut(const std::string &name, int4 size, PcodeOp *op)
  {
    Varnode *vn = fd.newUniqueOut(size, op);
    vnNames.insert(std::make_pair(vn, name));
    vnOrder.push_back(vn);
    return vn;
  }

  Varnode *regOut(const std::string &name, int4 size, uintb regoffset, PcodeOp *op)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, regoffset));
    fd.opSetOutput(op, vn);
    vnNames.insert(std::make_pair(vn, name));
    vnOrder.push_back(vn);
    return vn;
  }

  Varnode *constant(int4 size, uintb value)
  {
    return fd.newConstant(size, value);
  }

  Varnode *input(const std::string &name, uintb offset, int4 size)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    vn = fd.setInputVarnode(vn);
    vnNames.insert(std::make_pair(vn, name));
    vnOrder.push_back(vn);
    return vn;
  }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot)
  {
    fd.opSetInput(op, vn, slot);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block)
  {
    fd.opInsertEnd(op, block);
  }

  std::string irText(void)
  {
    std::ostringstream ops;
    ops << '[';
    bool first = true;
    for (std::vector<PcodeOp *>::const_iterator iter = opOrder.begin();
         iter != opOrder.end(); ++iter) {
      PcodeOp *op = *iter;
      if (!first) ops << ',';
      first = false;
      ops << opNames[op]
          << '=' << get_opname(op->code())
          << '/' << op->getSeqNum().getOrder()
          << ",dead=" << (op->isDead() ? 1 : 0);
    }
    ops << ']';
    std::ostringstream vns;
    vns << '[';
    first = true;
    for (std::vector<Varnode *>::const_iterator iter = vnOrder.begin();
         iter != vnOrder.end(); ++iter) {
      Varnode *vn = *iter;
      if (!first) vns << ',';
      first = false;
      vns << vnNames[vn]
          << ":in=" << (vn->isInput() ? 1 : 0)
          << ",wr=" << (vn->isWritten() ? 1 : 0)
          << ",sb=" << (vn->isSpacebase() ? 1 : 0);
    }
    vns << ']';
    return "ops=" + ops.str() + "|vns=" + vns.str();
  }
};

// External mirror of Action::perform's do-while (action.cc:303-350) for a
// rule_repeatapply group, printing the per-pass executor statistics of the
// group and of each child after that pass's ActionGroup::apply.
static void runStackstall(ActionGroup *stack, Funcdata &fd, int4 run)
{
  int4 pass = 0;
  for (;;) {
    pass += 1;
    if (pass == 1) {
      stack->count = 0;          // action.cc:306
      stack->count_tests += 1;   // action.cc:311
    }
    stack->lcount = stack->count;  // action.cc:314
    stack->status = Action::status_repeat;  // apply() restarts its child iterator
    int4 res = stack->apply(fd);  // action.cc:319
    if (stack->lcount < stack->count)  // action.cc:327
      stack->count_apply += 1;         // action.cc:329
    std::cout << "run=" << run << "|pass=" << pass
              << "|lcount=" << stack->lcount
              << "|count=" << stack->count
              << "|res=" << res << '\n';
    for (std::vector<Action *>::const_iterator it = stack->list.begin();
         it != stack->list.end(); ++it) {
      Action *child = *it;
      std::cout << "run=" << run << "|pass=" << pass
                << "|child=" << child->getName()
                << "|status=" << child->getStatus()
                << "|count=" << child->count
                << "|lcount=" << child->lcount
                << "|tests=" << child->getNumTests()
                << "|apply=" << child->getNumApply() << '\n';
    }
    if (res < 0) break;  // action.cc:323-326
    if (!((stack->lcount < stack->count) &&
          ((stack->flags & Action::rule_repeatapply) != 0)))
      break;             // action.cc:350
  }
  std::cout << "run=" << run << "|converged_passes=" << pass
            << "|final_count=" << stack->count
            << "|tests=" << stack->getNumTests()
            << "|apply=" << stack->getNumApply() << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=PIPE-STACKSTALL-COUNT-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;

    // Real default derive (architecture.cc:582-591 buildAction sequence).
    arch.allacts.universalAction(&arch);
    arch.allacts.resetDefaults();
    ActionGroup *root = (ActionGroup *)arch.allacts.getCurrent();
    // Official ':' name-path addressing (action.cc:456-479).
    Action *stackact = root->getSubAction("fullloop:mainloop:stackstall");
    if (stackact == (Action *)0) {
      std::cerr << "stackstall group not found\n";
      return 1;
    }
    ActionGroup *stackstall = (ActionGroup *)stackact;

    // --- Function IR ------------------------------------------------------
    Graph g(arch, "stackstall_count", 0x6000);

    Varnode *sp = g.input("sp", 0, 8);        // stack pointer input (register 0)
    Varnode *x = g.input("x", 0x100, 8);
    Varnode *y = g.input("y", 0x108, 8);
    Varnode *u = g.input("u", 0x110, 8);
    Varnode *v = g.input("v", 0x118, 8);

    // Block b0: shadowvar trigger — m1 and m2 share inputs and sit at the
    // block's start address; the INT_ADD p1 between them stops MultiCse's
    // scan (coreaction.cc:834-835) but not ShadowVar's address-group walk.
    BlockBasic *b0 = g.makeBlock();
    PcodeOp *m1 = g.makeOpAt("m1", CPUI_MULTIEQUAL, 2, 0x10);
    g.setInput(m1, x, 0);
    g.setInput(m1, y, 1);
    g.uniqueOut("t1", 8, m1);
    PcodeOp *p1 = g.makeOpAt("p1", CPUI_INT_ADD, 2, 0x10);
    g.setInput(p1, sp, 0);
    g.setInput(p1, g.constant(8, 16), 1);
    Varnode *ptr = g.uniqueOut("ptr", 8, p1);
    PcodeOp *m2 = g.makeOpAt("m2", CPUI_MULTIEQUAL, 2, 0x10);
    g.setInput(m2, x, 0);
    g.setInput(m2, y, 1);
    g.uniqueOut("t2", 8, m2);
    g.insertEnd(m1, b0);
    g.insertEnd(p1, b0);
    g.insertEnd(m2, b0);
    // Production establishes the block's address ranges in followFlow via
    // Funcdata::setBasicBlockRange; the fixture pins the same precondition
    // so getStart() (block.cc:2319) yields the shadowvar group's address.
    g.fd.setBasicBlockRange(b0, Address(g.ram, g.fd.getAddress().getOffset() + 0x10),
                            Address(g.ram, g.fd.getAddress().getOffset() + 0x10));

    // Block b1: stackptrflow clog — STORE(sp+16, 0x10) before the matching
    // LOAD, then INT_ADD(sp, loaded) whose output lives at the sp register.
    BlockBasic *b1 = g.makeBlock();
    PcodeOp *st = g.makeOpAt("st", CPUI_STORE, 3, 0x20);
    g.setInput(st, g.constant(8, 3), 0);   // spaceid placeholder constant
    g.setInput(st, ptr, 1);
    g.setInput(st, g.constant(8, 0x10), 2);
    g.insertEnd(st, b1);
    PcodeOp *ld = g.makeOpAt("ld", CPUI_LOAD, 2, 0x21);
    g.setInput(ld, g.constant(8, 3), 0);
    g.setInput(ld, ptr, 1);
    Varnode *loaded = g.uniqueOut("loaded", 8, ld);
    g.insertEnd(ld, b1);
    PcodeOp *cadd = g.makeOpAt("cadd", CPUI_INT_ADD, 2, 0x22);
    g.setInput(cadd, sp, 0);
    g.setInput(cadd, loaded, 1);
    g.regOut("sp2", 8, 0, cadd);           // varnode at the sp register location
    g.insertEnd(cadd, b1);

    // Block b2: multicse trigger — two functionally equivalent MULTIEQUALs
    // lead the block so ActionMultiCse's scan reaches both (cc:822-856).
    BlockBasic *b2 = g.makeBlock();
    PcodeOp *m3 = g.makeOpAt("m3", CPUI_MULTIEQUAL, 2, 0x30);
    g.setInput(m3, u, 0);
    g.setInput(m3, v, 1);
    g.uniqueOut("t3", 8, m3);
    PcodeOp *m4 = g.makeOpAt("m4", CPUI_MULTIEQUAL, 2, 0x30);
    g.setInput(m4, u, 0);
    g.setInput(m4, v, 1);
    g.uniqueOut("t4", 8, m4);
    g.insertEnd(m3, b2);
    g.insertEnd(m4, b2);

    g.edge(b0, b1);
    g.edge(b1, b2);

    // Precondition 1: per-space heritage info (production startProcessing,
    // funcdata.cc:166) so RuleEarlyRemoval's deadRemovalAllowedSeen gate
    // (ruleaction.cc:38-40) sees the per-space deadcode delay state.
    heritageOf(g.fd).buildInfoList();
    // Precondition 2: the spacebase flag on the sp input (ActionSpacebase,
    // mainloop :5506, runs before stackstall in production).
    g.fd.spacebase();

    std::cout << "pre|" << g.irText() << '\n';

    runStackstall(stackstall, g.fd, 1);
    std::cout << "post_run1|" << g.irText() << '\n';

    // Reset (ActionGroup::reset -> ActionStackPtrFlow::reset clears
    // analysis_finished, coreaction.hh:99) and drive a second fixed point.
    stackstall->reset(g.fd);
    runStackstall(stackstall, g.fd, 2);
    std::cout << "post_run2|" << g.irText() << '\n';
  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
    return 1;
  }
  return 0;
}
