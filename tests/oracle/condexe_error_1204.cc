// CONDEXE-ERROR-0006 fixture — the ConditionalExecution error channel
// (condexe.cc:242-262 resolveIblockRead, condexe.cc:291-315
// getReplacementRead, condexe.cc:320-357 doReplacement, condexe.cc:457-476
// execute, condexe.cc:478-503 ActionConditionalExe::apply) against the
// locked Ghidra 12.0.4 oracle, driven through the full apply() protocol.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable projections pinned by this fixture (one stdout line per record):
//   err  E1  A COPY in the iblock whose input 0 is written OUTSIDE the
//             iblock by a non-MULTIEQUAL op passes verify()/testOpRead but
//             is illegal for resolveIblockRead: apply() must throw
//             LowlevelError("Conditional execution: Illegal op in iblock")
//             (condexe.cc:261) — verbatim message comparison.
//   state E1  Partial state at the abort point: execute() walks the iblock
//             ops in reverse, so the CBRANCH was already destroyed, the
//             failing COPY survives, its output is still read by exactly one
//             untouched descendant, the iblock is still in the graph with
//             2 in / 2 out edges, and every other block is unchanged.
//   err  E2  The reader's block is dominated by the INIT block instead of
//             the iblock: getReplacementRead's dominator walk advances once
//             (reader -> init) and then leaves the graph at the entry —
//             LowlevelError("Conditional execution: Could not find
//             dominator") (condexe.cc:303) — verbatim message comparison.
//             This exercises the loop-advance leg before the throw.
//   state E2  Same partial-state shape as E1 (message differs).
//   ret  E3  verify() failure (iblock CBRANCH boolean uncorrelated with the
//             init CBRANCH boolean): trial() returns false, apply() returns
//             0 normally, NO exception, and the Funcdata is untouched.
//   state E3  Full pre-state preserved (COPY + CBRANCH still in the iblock).
//   pre  E4  The unreachable-guard case proves its own precondition first:
//             the same E1 diamond (which WOULD abort without the guard) gets
//             fd.structureReset() — the floating b6 (sizeIn()==0) makes
//             findSpanningTree collect two roots, so funcdata_block.cc:713-714
//             sets blocks_unreachable through the production path — and the
//             cached flag is echoed as unreach=1 before apply() runs.
//   ret  E4  ActionConditionalExe::apply hits the condexe.cc:485-486 guard
//             and returns 0 IMMEDIATELY: no ConditionalExecution is
//             constructed (cc:487), no trial/execute runs, NO exception —
//             the pre-guard diamond is a guaranteed E1 abort, so only the
//             guard can produce this clean return.
//   state E4  Zero mutation: full pre-state preserved (COPY + CBRANCH still
//             in the iblock, reader untouched, 2-in/2-out).
//
// E1/E2 inputs double as the doReplacement death-loop regression: the
// resolve chain has no silent-null path in the oracle (it either returns a
// Varnode or throws), so every apply() iteration removes exactly one
// descendant — a Rust port that silently skipped the opSetInput would loop
// forever on these inputs instead of producing the pinned records.
//
// Test-only access drives the real ActionConditionalExe::apply (public,
// action.hh:130); the synthetic FixtureArchitecture/FixtureTranslate legs
// and the `#define private public` / `#define class struct` access rewrite
// follow tests/oracle/condexe_pullback_1204.cc (needed to wire immed_dom
// directly for the dominator chains and to read block op lists).
// Standard headers come first so the access macros cannot leak into libstdc++.
#include <bits/stdc++.h>
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "condexe.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"

namespace {

using namespace ghidra;
using std::cout;
using std::cerr;

class FixtureTranslate final : public Translate {
public:
  VarnodeData dummyRegister;
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this,this));
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"other",false,8,1,1,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new UniqueSpace(this,this,2,0));
    AddrSpace *ram = new AddrSpace(this,this,IPTR_PROCESSOR,"ram",false,8,1,3,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this,this,IPTR_PROCESSOR,"register",false,8,1,4,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this,this,"stack",5,8,ram,1,true);
    insertSpace(stack);
    VarnodeData stackPointer = { reg, 0, 8 };
    addSpacebasePointer(stack,stackPointer,8,true);
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"join",false,8,1,6,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new IopSpace(this,this,7));
    setDefaultCodeSpace(3);
    dummyRegister = { reg, 0, 8 };
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummyRegister; }
  string getRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  void getAllRegisters(map<VarnodeData,string> &) const override {}
  void getUserOpNames(vector<string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &,const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &,const Address &) const override { return 0; }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override { return (PcodeInjectLibrary *)0; }
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
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1",1,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown2",2,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown4",4,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown8",8,TYPE_UNKNOWN,false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst,types,translate);
    symboltab = new Database(this,false);
    symboltab->attachScope(new ScopeInternal(0x101,"",this),(Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    istringstream stream("<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }
  void printMessage(const string &) const override {}
};

class Fixture {
  Funcdata &fd;
  AddrSpace *code;
  AddrSpace *unique;
  vector<FlowBlock *> blocks;
  uintb nextPc;

public:
  explicit Fixture(Funcdata &f)
    : fd(f), code(f.getArch()->getDefaultCodeSpace()),
      unique(f.getArch()->getSpaceByName("unique")), nextPc(0x20000) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);
    blocks.push_back(block);
    return block;
  }

  void edge(BlockBasic *from,BlockBasic *to)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    graph.addEdge(from,to);
  }

  Address allocPc(void)
  {
    Address a(code,nextPc);
    nextPc += 8;
    return a;
  }

  AddrSpace *uniqueSpace(void) const { return unique; }

  // Written varnode at an explicit address: the fixture's own IR-builder leg
  // (mirrors Funcdata::newVarnodeOut minus the assignHigh/laned legs, which
  // are no-ops on a fresh Funcdata with highlevel off and no laned specs).
  Varnode *makeOut(int4 size,AddrSpace *space,uintb offset,PcodeOp *op)
  {
    Varnode *vn = fd.newVarnodeOut(size,Address(space,offset),op);
    return vn;
  }

  Varnode *makeFree(uintb offset,int4 size)
  {
    return fd.newVarnode(size,Address(unique,offset));
  }

  PcodeOp *makeCbranchAt(BlockBasic *blk,Varnode *boolvn,Address pc)
  {
    PcodeOp *op = fd.newOp(2,pc);
    fd.opSetOpcode(op,CPUI_CBRANCH);
    fd.opSetInput(op,fd.newConstant(8,0x4000),0);
    fd.opSetInput(op,boolvn,1);
    fd.opInsertEnd(op,blk);
    return op;
  }

  int4 blockOpCount(BlockBasic *blk) const
  {
    int4 n = 0;
    for(auto it = blk->beginOp(); it != blk->endOp(); ++it)
      ++n;
    return n;
  }

  string name(const FlowBlock *bl) const
  {
    if (bl == (const FlowBlock *)0) return "-";
    for(size_t i=0;i<blocks.size();++i)
      if (blocks[i] == bl) return "b" + to_string(i);
    return "x";
  }

  string inventory(void) const
  {
    ostringstream s;
    for(size_t i=0;i<blocks.size();++i) {
      if (i != 0) s << ',';
      s << 'b' << i << ':' << blockOpCount((BlockBasic *)blocks[i]);
    }
    return s.str();
  }

  string opsOf(BlockBasic *blk) const
  {
    ostringstream s;
    bool first = true;
    for(auto it = blk->beginOp(); it != blk->endOp(); ++it) {
      if (!first) s << ',';
      first = false;
      s << get_opname((*it)->code());
    }
    return s.str();
  }

  static int4 descendCount(const Varnode *vn)
  {
    int4 n = 0;
    for(auto it = vn->beginDescend(); it != vn->endDescend(); ++it)
      ++n;
    return n;
  }
};

// The shared E-cases diamond:
//   b0 init  [COPY bool, CBRANCH bool] -> b1 (prea, empty) / b2 (preb, empty)
//   b1,b2 -> b3 iblock [COPY vnY <- vnW, CBRANCH bool]
//   b3 -> b4 posta [COPY reader vnY] / b5 postb (empty)
//   b6 floats and defines vnW with a COPY (input 0 of the iblock COPY,
//        written OUTSIDE the iblock by a non-MULTIEQUAL op — passes
//        testOpRead cc:126-139 but is illegal for resolveIblockRead cc:261)
// `reader_dom_ib`: wire b4's immed_dom to b3 (E1: legal, the chain reaches
// the illegal-op throw) or to b0 (E2: the walk advances once then leaves the
// graph at the entry, cc:303). `correlate`: use the same written boolean for
// both CBRANCHes (E1/E2: SAME) or an uncorrelated constant for the iblock
// CBRANCH (E3: verifySameCondition fails, cc:88-89).
struct Diamond {
  Fixture f;
  BlockBasic *init;
  BlockBasic *ib;
  Varnode *vnY;

  Diamond(Funcdata &fd,bool reader_dom_ib,bool correlate)
    : f(fd)
  {
    BlockBasic *b0 = f.makeBlock();
    BlockBasic *b1 = f.makeBlock();
    BlockBasic *b2 = f.makeBlock();
    BlockBasic *b3 = f.makeBlock();
    BlockBasic *b4 = f.makeBlock();
    BlockBasic *b5 = f.makeBlock();
    BlockBasic *b6 = f.makeBlock();
    f.edge(b0,b1);
    f.edge(b0,b2);
    f.edge(b1,b3);
    f.edge(b2,b3);
    f.edge(b3,b4);
    f.edge(b3,b5);
    // Shared written boolean defined in b0, read by both CBRANCHes
    // (BooleanExpressionMatch -> SAME, condexe.cc:88-93).
    Varnode *boolvn;
    {
      PcodeOp *boolop = fd.newOp(1,f.allocPc());
      fd.opSetOpcode(boolop,CPUI_COPY);
      boolvn = f.makeOut(1,f.uniqueSpace(),0x900,boolop);
      fd.opSetInput(boolop,fd.newConstant(1,1),0);
      fd.opInsertEnd(boolop,b0);
    }
    f.makeCbranchAt(b0,boolvn,f.allocPc());
    // b6: floating writer of vnW (outside the iblock, non-MULTIEQUAL).
    Varnode *vnW;
    {
      PcodeOp *w = fd.newOp(1,f.allocPc());
      fd.opSetOpcode(w,CPUI_COPY);
      vnW = f.makeOut(4,f.uniqueSpace(),0x1000,w);
      fd.opSetInput(w,fd.newConstant(4,0x41),0);
      fd.opInsertEnd(w,b6);
    }
    // b3 iblock: COPY vnY <- vnW, then CBRANCH bool.
    {
      PcodeOp *c = fd.newOp(1,f.allocPc());
      fd.opSetOpcode(c,CPUI_COPY);
      vnY = f.makeOut(4,f.uniqueSpace(),0x2000,c);
      fd.opSetInput(c,vnW,0);
      fd.opInsertEnd(c,b3);
    }
    if (correlate)
      f.makeCbranchAt(b3,boolvn,f.allocPc());
    else
      f.makeCbranchAt(b3,fd.newConstant(1,0x7a),f.allocPc());
    // b4 posta reader: COPY reading vnY.
    {
      PcodeOp *r = fd.newOp(1,f.allocPc());
      fd.opSetOpcode(r,CPUI_COPY);
      fd.opSetInput(r,vnY,0);
      fd.opInsertEnd(r,b4);
    }
    // Test-only dominator wiring (b0/b3 immed_dom stay null: the entry has
    // no dominator, which is what makes the E2 walk leave the graph).
    if (reader_dom_ib)
      b4->immed_dom = b3;
    else
      b4->immed_dom = b0;
    init = b0;
    ib = b3;
  }
};

void printState(const char *caseId,Funcdata &fd,Diamond &d)
{
  cout << "state|case=" << caseId
       << "|nblocks=" << fd.getBasicBlocks().getSize()
       << "|blocks=" << d.f.inventory()
       << "|ib=" << d.f.name(d.ib)
       << "|ib_ops=" << d.f.opsOf(d.ib)
       << "|ib_in=" << d.ib->sizeIn()
       << "|ib_out=" << d.ib->sizeOut()
       << "|copy_desc=" << Fixture::descendCount(d.vnY) << '\n';
}

void runErrorCase(FixtureArchitecture &architecture,const char *caseId,bool reader_dom_ib)
{
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd(caseId,caseId,global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
  // buildHeritageArray (condexe.cc:23-37, run by ConditionalExecution's
  // constructor inside apply) reads Heritage::numHeritagePasses, which
  // requires the lazy Heritage::infolist; the real pipeline populates it
  // during the first heritage() pass.
  fd.heritage.buildInfoList();
  Diamond d(fd,reader_dom_ib,true);
  ActionConditionalExe action("");
  try {
    int4 r = action.apply(fd);
    cout << "ret|case=" << caseId << "|apply=" << r << "|msg=none\n";
  }
  catch(const LowlevelError &error) {
    cout << "err|case=" << caseId << "|kind=lowlevel|msg=" << error.explain << '\n';
  }
  printState(caseId,fd,d);
}

void runVerifyFailCase(FixtureArchitecture &architecture)
{
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd("E3","E3",global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
  fd.heritage.buildInfoList();
  Diamond d(fd,true,false);
  ActionConditionalExe action("");
  try {
    int4 r = action.apply(fd);
    cout << "ret|case=E3|apply=" << r << "|msg=none\n";
  }
  catch(const LowlevelError &error) {
    cout << "err|case=E3|kind=lowlevel|msg=" << error.explain << '\n';
  }
  printState("E3",fd,d);
}

// E4: the condexe.cc:485-486 unreachable-blocks guard. The diamond is the E1
// shape (same correlate=true, reader_dom_ib=true data flow that aborts with
// the illegal-op LowlevelError when the guard is absent), but before apply()
// the fixture runs the production flag-set path: structureReset's
// findSpanningTree collects every sizeIn()==0 block as a root (block.cc:1028),
// so the floating b6 yields TWO roots and funcdata_block.cc:713-714 sets
// blocks_unreachable. The pre-line echoes the cached flag so a fixture bug
// that failed to set it cannot pass the gate vacuously (an unset flag would
// reproduce the E1 abort, not a clean ret).
void runUnreachableGuardCase(FixtureArchitecture &architecture)
{
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd("E4","E4",global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
  fd.heritage.buildInfoList();
  Diamond d(fd,true,true);
  fd.structureReset();
  cout << "pre|case=E4|unreach=" << (fd.hasUnreachableBlocks() ? 1 : 0) << '\n';
  ActionConditionalExe action("");
  try {
    int4 r = action.apply(fd);
    cout << "ret|case=E4|apply=" << r << "|msg=none\n";
  }
  catch(const LowlevelError &error) {
    cout << "err|case=E4|kind=lowlevel|msg=" << error.explain << '\n';
  }
  printState("E4",fd,d);
}

void run(void)
{
  FixtureArchitecture architecture;
  runErrorCase(architecture,"E1",true);	// illegal iblock op (condexe.cc:261)
  runErrorCase(architecture,"E2",false);	// could not find dominator (condexe.cc:303)
  runVerifyFailCase(architecture);	// verify failure -> trial false, no change
  runUnreachableGuardCase(architecture);	// unreachable blocks -> guard return 0 (condexe.cc:485-486)
}

} // namespace

int main(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  try {
    run();
  }
  catch(const LowlevelError &error) {
    cerr << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  catch(const std::exception &error) {
    cerr << "fixture error: " << error.what() << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
