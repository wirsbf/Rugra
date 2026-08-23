// CONDEXE-PULLBACK-0005 fixture — ConditionalExecution::pullbackOp
// (condexe.cc:160-190) storage/insert-position semantics and its
// testOpRead admission gate (condexe.cc:107-142), against the locked
// Ghidra 12.0.4 oracle.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable projections pinned by this fixture (one stdout line per case):
//   pullback P1/P1b   SUBPIECE in the iblock whose input 0 is defined by a
//                     MULTIEQUAL in the iblock: the duplicate must land in
//                     iblock->In(inbranch) (condexe.cc:171), take the
//                     MULTIEQUAL's inbranch input (cc:172), keep the original
//                     op's address (cc:180) and the original output's address
//                     AND space (cc:182), and be inserted at block END before
//                     the trailing CBRANCH (cc:187 + funcdata_op.cc:435-446).
//                     Projections: block position (idx/nops), SeqNum
//                     (pc:time), addr (space:offset/size).
//   pullback P3       pullback cache (cc:163-165): a second call for the same
//                     inbranch returns the SAME Varnode and inserts nothing.
//   pullback P2       cross-block pullback: input 0 defined OUTSIDE the
//                     iblock -> bl = iblock->getImmedDom() (cc:175), original
//                     output in UNIQUE space (space preservation).
//   pullback P5       input 0 is a constant (not written) -> bl = immedDom
//                     (cc:177-179); insertion into an otherwise-empty block
//                     still precedes the trailing CBRANCH.
//   gate G1..G8       testOpRead (condexe.cc:107-142) driven directly: the
//                     pullback admission gate — INT_ADD/PTRSUB require a
//                     constant input 1 (cc:126-128), input 0 defined by a
//                     non-MULTIEQUAL op inside the iblock is rejected
//                     (cc:131-133), free (incl. constant) input 0 is rejected
//                     (cc:135-136), MULTIEQUAL/COPY input 0 and COPY writeOps
//                     are accepted.
//
// Test-only access drives the private ConditionalExecution stages directly
// (the Rugra comparand exposes fixture_pullback_op / fixture_test_op_read
// glue for the same purpose). ConditionalExecution declares its members with
// the implicit class-private section, so `private -> public` alone cannot
// reach them; `class -> struct` opens the implicit-private section (same
// access-rewrite strategy as tests/oracle/condexe_trueout_1204.cc, whose
// header notes justify that no decompile header uses `template<class ...>`
// or `enum class`).
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
  AddrSpace *reg;
  vector<FlowBlock *> blocks;
  uintb nextPc;

public:
  explicit Fixture(Funcdata &f)
    : fd(f), code(f.getArch()->getDefaultCodeSpace()),
      unique(f.getArch()->getSpaceByName("unique")),
      reg(f.getArch()->getSpaceByName("register")), nextPc(0x20000) {}

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
  AddrSpace *registerSpace(void) const { return reg; }

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

  PcodeOp *makeCbranch(BlockBasic *blk,Varnode *boolvn)
  {
    PcodeOp *op = fd.newOp(2,allocPc());
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
};

string vnDesc(const Varnode *vn)
{
  ostringstream s;
  s << vn->getSpace()->getName() << ':' << hex << vn->getOffset()
    << dec << '/' << vn->getSize();
  return s.str();
}

// Three decisive projections of a pullbackOp call: block position (which
// block, which index inside it), SeqNum order (pc:uniqid), and storage
// address of the duplicate's output and inputs.
void recordPullback(const string &caseId,const Fixture &f,Varnode *outvn)
{
  PcodeOp *op = outvn->getDef();
  BlockBasic *parent = (BlockBasic *)op->getParent();
  int4 idx = -1;
  int4 nops = 0;
  for(auto it = parent->beginOp(); it != parent->endOp(); ++it,++nops)
    if (*it == op) idx = nops;
  const SeqNum &sq = op->getSeqNum();
  cout << "pullback|case=" << caseId
       << "|block=" << f.name(parent)
       << "|idx=" << idx
       << "|nops=" << nops
       << "|opc=" << get_opname(op->code())
       << "|seq=" << hex << sq.getAddr().getOffset() << dec << ':' << sq.getTime()
       << "|out=" << vnDesc(outvn)
       << "|in0=" << vnDesc(op->getIn(0))
       << "|in1=" << vnDesc(op->getIn(1)) << '\n';
}

// P1/P1b/P3: SUBPIECE in the iblock reading a MULTIEQUAL in the iblock.
// prea and preb each hold a leading COPY plus a trailing CBRANCH so the
// END insertion (before the flow break, after the COPY) is distinguishable
// from opInsertBegin (which would land at idx 0, before the COPY).
void runMultiequalPullback(Funcdata &fd)
{
  Fixture f(fd);
  BlockBasic *prea = f.makeBlock();
  BlockBasic *preb = f.makeBlock();
  BlockBasic *ib = f.makeBlock();
  f.edge(prea,ib);			// ib in[0]
  f.edge(preb,ib);			// ib in[1]

  Varnode *vnA;
  Varnode *vnB;
  {					// prea: COPY then CBRANCH
    PcodeOp *copyA = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(copyA,CPUI_COPY);
    vnA = f.makeOut(4,f.uniqueSpace(),0x1000,copyA);
    fd.opSetInput(copyA,fd.newConstant(4,0x41),0);
    fd.opInsertEnd(copyA,prea);
    f.makeCbranch(prea,f.makeFree(0x900,1));
  }
  {					// preb: COPY then CBRANCH
    PcodeOp *copyB = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(copyB,CPUI_COPY);
    vnB = f.makeOut(4,f.uniqueSpace(),0x1100,copyB);
    fd.opSetInput(copyB,fd.newConstant(4,0x42),0);
    fd.opInsertEnd(copyB,preb);
    f.makeCbranch(preb,f.makeFree(0x908,1));
  }
  Varnode *vnM;
  PcodeOp *sub;
  {					// ib: MULTIEQUAL, SUBPIECE, CBRANCH
    PcodeOp *mq = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(mq,CPUI_MULTIEQUAL);
    vnM = f.makeOut(4,f.uniqueSpace(),0x1200,mq);
    fd.opSetInput(mq,vnA,0);
    fd.opSetInput(mq,vnB,1);
    fd.opInsertEnd(mq,ib);

    sub = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(sub,CPUI_SUBPIECE);
    Varnode *vnS = f.makeOut(4,f.registerSpace(),0x300,sub);
    fd.opSetInput(sub,vnM,0);
    fd.opSetInput(sub,fd.newConstant(4,0),1);
    fd.opInsertEnd(sub,ib);

    f.makeCbranch(ib,f.makeFree(0x910,1));
    cout << "pullback|case=P0|ib_nops=" << f.blockOpCount(ib)
         << "|out=" << vnDesc(vnS) << '\n';
  }
  ConditionalExecution condexe(&fd);
  condexe.iblock = ib;
  Varnode *out1 = condexe.pullbackOp(sub,0);
  recordPullback("P1",f,out1);
  Varnode *out1b = condexe.pullbackOp(sub,1);
  recordPullback("P1b",f,out1b);
  // P3: cached pullback for inbranch 0 returns the SAME Varnode, no new op.
  Varnode *again = condexe.pullbackOp(sub,0);
  cout << "pullback|case=P3|same_ptr=" << ((again == out1) ? 1 : 0)
       << "|prea_nops=" << f.blockOpCount(prea)
       << "|ib_nops=" << f.blockOpCount(ib)
       << "|out=" << vnDesc(again) << '\n';
}

// P2: SUBPIECE whose input 0 is defined outside the iblock: the duplicate
// lands in the iblock's immediate dominator (condexe.cc:175) and preserves a
// UNIQUE-space original output address (condexe.cc:182).
void runCrossBlockPullback(Funcdata &fd)
{
  Fixture f(fd);
  BlockBasic *writer = f.makeBlock();
  BlockBasic *ib = f.makeBlock();
  f.edge(writer,ib);
  Varnode *vnC;
  {
    PcodeOp *copyC = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(copyC,CPUI_COPY);
    vnC = f.makeOut(8,f.uniqueSpace(),0x2000,copyC);
    fd.opSetInput(copyC,fd.newConstant(8,0x1122334455667788),0);
    fd.opInsertEnd(copyC,writer);
    f.makeCbranch(writer,f.makeFree(0x918,1));
  }
  PcodeOp *sub2;
  {
    sub2 = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(sub2,CPUI_SUBPIECE);
    f.makeOut(4,f.uniqueSpace(),0x2800,sub2);
    fd.opSetInput(sub2,vnC,0);
    fd.opSetInput(sub2,fd.newConstant(4,1),1);
    fd.opInsertEnd(sub2,ib);
    f.makeCbranch(ib,f.makeFree(0x920,1));
  }
  ib->immed_dom = writer;		// test-only dominator wiring
  ConditionalExecution condexe(&fd);
  condexe.iblock = ib;
  Varnode *out2 = condexe.pullbackOp(sub2,1);	// inbranch irrelevant on this leg
  recordPullback("P2",f,out2);
}

// P5: SUBPIECE whose input 0 is a constant (not written): bl = immedDom
// (condexe.cc:177-179); the target block holds only a CBRANCH, so END
// insertion must still precede the flow break (idx 0, nops 2).
void runConstInputPullback(Funcdata &fd)
{
  Fixture f(fd);
  BlockBasic *writer = f.makeBlock();
  BlockBasic *ib = f.makeBlock();
  f.edge(writer,ib);
  f.makeCbranch(writer,f.makeFree(0x928,1));
  PcodeOp *sub5;
  {
    sub5 = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(sub5,CPUI_SUBPIECE);
    f.makeOut(4,f.registerSpace(),0x340,sub5);
    fd.opSetInput(sub5,fd.newConstant(4,0x1234),0);
    fd.opSetInput(sub5,fd.newConstant(4,0),1);
    fd.opInsertEnd(sub5,ib);
    f.makeCbranch(ib,f.makeFree(0x930,1));
  }
  ib->immed_dom = writer;		// test-only dominator wiring
  ConditionalExecution condexe(&fd);
  condexe.iblock = ib;
  Varnode *out5 = condexe.pullbackOp(sub5,0);
  recordPullback("P5",f,out5);
}

// G1..G8: the testOpRead admission gate (condexe.cc:107-142) driven directly.
// writeOps live in ibG, readers live outside; vn is the writeOp's output.
void runGate(Funcdata &fd)
{
  Fixture f(fd);
  BlockBasic *ib = f.makeBlock();
  BlockBasic *readerBlk = f.makeBlock();
  BlockBasic *domBlk = f.makeBlock();
  bool results[8];

  // Shared written input defined OUTSIDE ib (upop parent != iblock -> pass).
  Varnode *vnX;
  {
    PcodeOp *copyX = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(copyX,CPUI_COPY);
    vnX = f.makeOut(4,f.uniqueSpace(),0x3000,copyX);
    fd.opSetInput(copyX,fd.newConstant(4,0x55),0);
    fd.opInsertEnd(copyX,domBlk);
  }
  auto makeWrite = [&](OpCode opc,Varnode *in0,Varnode *in1,uintb outOff) {
    PcodeOp *op = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(op,opc);
    f.makeOut(4,f.uniqueSpace(),outOff,op);
    fd.opSetInput(op,in0,0);
    fd.opSetInput(op,in1,1);
    fd.opInsertEnd(op,ib);
    return op;
  };
  auto makeReader = [&](Varnode *vn) {
    PcodeOp *op = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(op,CPUI_COPY);
    fd.opSetInput(op,vn,0);
    fd.opInsertEnd(op,readerBlk);
    return op;
  };
  Varnode *freeReg = f.makeFree(0x4000,4);
  Varnode *freeReg2 = f.makeFree(0x4010,4);	// distinct free varnode: free varnodes allow at most one descendant

  ConditionalExecution condexe(&fd);
  condexe.iblock = ib;
  // G1: INT_ADD with constant input 1 -> admitted.
  {
    PcodeOp *w = makeWrite(CPUI_INT_ADD,vnX,fd.newConstant(4,0x10),0x3100);
    results[0] = condexe.testOpRead(w->getOut(),makeReader(w->getOut()));
  }
  // G2: INT_ADD with NON-constant input 1 -> rejected (cc:126-128).
  {
    PcodeOp *w = makeWrite(CPUI_INT_ADD,vnX,freeReg,0x3200);
    results[1] = condexe.testOpRead(w->getOut(),makeReader(w->getOut()));
  }
  // G3: PTRSUB with constant input 1 -> admitted.
  {
    PcodeOp *w = makeWrite(CPUI_PTRSUB,vnX,fd.newConstant(8,0x10),0x3300);
    results[2] = condexe.testOpRead(w->getOut(),makeReader(w->getOut()));
  }
  // G4: PTRSUB with NON-constant input 1 -> rejected.
  {
    PcodeOp *w = makeWrite(CPUI_PTRSUB,vnX,freeReg2,0x3400);
    results[3] = condexe.testOpRead(w->getOut(),makeReader(w->getOut()));
  }
  // G5: SUBPIECE whose input 0 is defined by a non-MULTIEQUAL op INSIDE the
  // iblock -> rejected (cc:131-133).
  {
    PcodeOp *w = makeWrite(CPUI_SUBPIECE,vnX,fd.newConstant(4,0),0x3500);
    PcodeOp *up = makeWrite(CPUI_INT_ADD,vnX,fd.newConstant(4,2),0x3600);
    fd.opSetInput(w,up->getOut(),0);
    results[4] = condexe.testOpRead(w->getOut(),makeReader(w->getOut()));
  }
  // G6: SUBPIECE with constant (free) input 0 -> rejected (cc:135-136:
  // constants are free, isFree() == ((written|input) flags) == 0).
  {
    PcodeOp *w = makeWrite(CPUI_SUBPIECE,fd.newConstant(4,0x1234),fd.newConstant(4,0),0x3700);
    results[5] = condexe.testOpRead(w->getOut(),makeReader(w->getOut()));
  }
  // G7: SUBPIECE whose input 0 is an iblock MULTIEQUAL output -> admitted
  // (cc:131-133 exception).
  {
    PcodeOp *mq = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(mq,CPUI_MULTIEQUAL);
    Varnode *mqout = f.makeOut(4,f.uniqueSpace(),0x3800,mq);
    fd.opSetInput(mq,vnX,0);
    fd.opSetInput(mq,vnX,1);
    fd.opInsertBegin(mq,ib);		// MULTIEQUALs lead the block
    PcodeOp *w = makeWrite(CPUI_SUBPIECE,mqout,fd.newConstant(4,0),0x3900);
    results[6] = condexe.testOpRead(w->getOut(),makeReader(w->getOut()));
  }
  // G8: COPY writeOp -> admitted unconditionally (cc:123).
  {
    PcodeOp *op = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(op,CPUI_COPY);
    f.makeOut(4,f.uniqueSpace(),0x3a00,op);
    fd.opSetInput(op,vnX,0);
    fd.opInsertEnd(op,ib);
    results[7] = condexe.testOpRead(op->getOut(),makeReader(op->getOut()));
  }
  static const char *names[8] = {
    "G1","G2","G3","G4","G5","G6","G7","G8"
  };
  static const char *descs[8] = {
    "intadd_const_in1", "intadd_var_in1", "ptrsub_const_in1", "ptrsub_var_in1",
    "subpiece_upop_in_ib", "subpiece_const_in0", "subpiece_mq_in0", "copy_writeop"
  };
  for(int4 i=0;i<8;++i)
    cout << "gate|case=" << names[i] << "|shape=" << descs[i]
         << "|ok=" << (results[i] ? 1 : 0) << '\n';
}

void run(void)
{
  FixtureArchitecture architecture;
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd("condexe_pullback","condexe_pullback",global,Address(ram,0x60000),
              (FunctionSymbol *)0,0x100);
  // buildHeritageArray (condexe.cc:23-37) reads Heritage::numHeritagePasses,
  // which requires the lazy Heritage::infolist to be populated. The real
  // pipeline guarantees this via the first heritage() pass; replicate the
  // precondition for this synthetic function.
  fd.heritage.buildInfoList();
  runMultiequalPullback(fd);
  runCrossBlockPullback(fd);
  runConstInputPullback(fd);
  runGate(fd);
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
