// FUNCDATA-NODESPLIT-SPACE-0001 fixture — Funcdata::nodeSplit /
// CloneBlockOps::buildVarnodeOutput full-address clone semantics
// (funcdata_block.cc:981-998), against the locked Ghidra 12.0.4 oracle.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Root cause pinned by this fixture (P23/UNLINKED-REF family F1): the oracle
// builds the clone output with `data.newVarnodeOut(opvn->getSize(),
// opvn->getAddr(), cloneOp)` (funcdata_block.cc:988) — a FULL Address whose
// space comes from the original output. A split-Address port that pins the
// register space loses the ram space of a persist global write-back, and the
// STORE/print layers later emit a register0x<addr> token instead of the
// global symbol.
//
// Observable projections pinned by this fixture (fixed stdout order):
//   blocks B*    per nodeSplit case: post-split in-edge counts of the
//                original block b and its duplicate bprime, and op counts of
//                both blocks (nodeSplitBlockEdge edge move + cloneBlock copy;
//                the MULTIEQUAL->COPY conversion of patchInputs
//                (funcdata_block.cc:1053-1059) must not change op counts).
//   clone O*     per cloned op (in bprime order): opcode, SeqNum (pc:time),
//                output storage (space:offset/size or "-"), the
//                buildVarnodeOutput flag projection (the cc:990-993 copy mask
//                plus the out-of-mask sentinels mapped|directwrite|unaffected)
//                in hex, the addlflag projection (the cc:996 fold mask
//                writemask|ptrflow|stack_store plus the out-of-mask sentinels
//                ptrcheck|activeheritage) in hex, and per-input provenance:
//                "clone<k>" when the pointer equals a cloned op output
//                (patchInputs cc:1078-1084 remap), "same" when the pointer
//                equals the PRE-SPLIT original op's same-slot input (constant
//                share cc:1071-1072 / plain share cc:1085), "orig<k>.<i>"
//                when the pointer equals another pre-split original input
//                (the MULTIEQUAL->COPY inedge pick cc:1056), else "ext".
//   orig O*      per surviving op of b: opcode, input count, per-input
//                storage, and whether each input pointer survived the split
//                (patchInputs cc:1057 removes the inedge slot).
//
// Cases: N1 inedge=0 full matrix (MULTIEQUAL + INT_ADD reading the
// MULTIEQUAL + COPY with a ram persist|addrtied output + COPY with a
// register output carrying in-mask and out-of-mask flag/addlflag bits +
// output-less STORE), N2 same matrix split on inedge=1 (the other MULTIEQUAL
// slot), N3 minimal matrix (MULTIEQUAL + STORE) on inedge=0.
//
// nodeSplit / block and varnode accessors used here are public; the raw
// flags/addlflags members need the access rewrite (same strategy as
// tests/oracle/condexe_pullback_1204.cc).
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

// buildVarnodeOutput copy mask (funcdata_block.cc:990-993) plus out-of-mask
// sentinels that must NOT reach the clone: mapped, directwrite, unaffected.
const uint4 VFLAG_PROJ = (Varnode::externref | Varnode::volatil | Varnode::incidental_copy |
                          Varnode::readonly | Varnode::persist | Varnode::addrtied |
                          Varnode::addrforce | Varnode::nolocalalias | Varnode::spacebase |
                          Varnode::indirect_creation | Varnode::return_address |
                          Varnode::precislo | Varnode::precishi |
                          Varnode::mapped | Varnode::directwrite | Varnode::unaffected);
// addlflag fold mask (funcdata_block.cc:996) plus out-of-mask sentinels:
// ptrcheck, activeheritage.
const uint2 AFL_PROJ = static_cast<uint2>(Varnode::writemask | Varnode::ptrflow |
                                          Varnode::stack_store | Varnode::ptrcheck |
                                          Varnode::activeheritage);

int4 blockOpCount(const BlockBasic *bl)
{
  int4 n = 0;
  for(auto it = bl->beginOp(); it != bl->endOp(); ++it)
    ++n;
  return n;
}

class Fixture {
  Funcdata &fd;
  AddrSpace *code;
  AddrSpace *unique;
  AddrSpace *ram;
  AddrSpace *reg;
  vector<BlockBasic *> blocks;
  uintb nextPc;

public:
  explicit Fixture(Funcdata &f)
    : fd(f), code(f.getArch()->getDefaultCodeSpace()),
      unique(f.getArch()->getSpaceByName("unique")),
      ram(f.getArch()->getSpaceByName("ram")),
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
  AddrSpace *ramSpace(void) const { return ram; }
  AddrSpace *registerSpace(void) const { return reg; }

  // Written varnode at an explicit address, exactly the input shape
  // buildVarnodeOutput sees (the real pipeline produces persist ram outputs
  // from Heritage::guardReturns, unique/register outputs from earlier ops).
  Varnode *makeOut(int4 size,AddrSpace *space,uintb offset,PcodeOp *op)
  {
    return fd.newVarnodeOut(size,Address(space,offset),op);
  }
};

string vnDesc(const Varnode *vn)
{
  if (vn == (const Varnode *)0)
    return string("-");
  ostringstream s;
  s << vn->getSpace()->getName() << ':' << hex << vn->getOffset()
    << dec << '/' << vn->getSize();
  return s.str();
}

string opSeq(const PcodeOp *op)
{
  const SeqNum &sq = op->getSeqNum();
  ostringstream s;
  s << hex << sq.getAddr().getOffset() << dec << ':' << sq.getTime();
  return s.str();
}

// Input provenance against the PRE-SPLIT snapshot (see fixture header).
string inputSource(const Varnode *vn,const vector<Varnode *> &cloneOuts,
                   const vector<PcodeOp *> &origOps,
                   const vector<vector<Varnode *> > &origIns,int4 slot)
{
  for(size_t k=0;k<cloneOuts.size();++k)
    if (vn == cloneOuts[k])
      return "clone" + to_string(k);
  for(size_t k=0;k<origOps.size() && k<origIns.size();++k)
    for(size_t i=0;i<origIns[k].size();++i) {
      if (origIns[k][i] == (const Varnode *)0)
        continue;
      if (vn == origIns[k][i]) {
        if ((int4)i == slot && origOps[k] != (PcodeOp *)0)
          return "same";
        return "orig" + to_string(k) + "." + to_string(i);
      }
    }
  return "ext";
}

struct Snapshot {
  vector<PcodeOp *> ops;			// ops of b pre-split, in order
  vector<vector<Varnode *> > ins;		// their inputs pre-split
  vector<Varnode *> outs;			// their outputs pre-split
};

void runCase(FixtureArchitecture &architecture,const string &caseId,int4 inedge,bool full,
             uintb baseaddr)
{
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd("nodesplit_" + caseId,"nodesplit_" + caseId,global,
              Address(ram,baseaddr),(FunctionSymbol *)0,0x100);
  Fixture f(fd);

  BlockBasic *prea = f.makeBlock();		// b in[0]
  BlockBasic *preb = f.makeBlock();		// b in[1]
  BlockBasic *b = f.makeBlock();
  f.edge(prea,b);
  f.edge(preb,b);

  // Exterior writers (outside b; their varnodes must be SHARED into clones).
  Varnode *vnA;
  Varnode *vnB;
  Varnode *vnExt;
  {
    PcodeOp *op = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(op,CPUI_COPY);
    vnA = f.makeOut(4,f.uniqueSpace(),0x1000,op);
    fd.opSetInput(op,fd.newConstant(4,0x11),0);
    fd.opInsertEnd(op,prea);
  }
  {
    PcodeOp *op = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(op,CPUI_COPY);
    vnExt = f.makeOut(4,f.uniqueSpace(),0x5000,op);
    fd.opSetInput(op,fd.newConstant(4,0x55),0);
    fd.opInsertEnd(op,prea);
  }
  {
    PcodeOp *op = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(op,CPUI_COPY);
    vnB = f.makeOut(4,f.uniqueSpace(),0x2000,op);
    fd.opSetInput(op,fd.newConstant(4,0x22),0);
    fd.opInsertEnd(op,preb);
  }

  Varnode *mqOut;
  Varnode *addOut = (Varnode *)0;
  {
    // op0: MULTIEQUAL (patchInputs turns it into a single-input COPY on both
    // the clone and the original).
    PcodeOp *mq = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(mq,CPUI_MULTIEQUAL);
    mqOut = f.makeOut(4,f.uniqueSpace(),0x3000,mq);
    fd.opSetInput(mq,vnA,0);
    fd.opSetInput(mq,vnB,1);
    fd.opInsertEnd(mq,b);
  }
  if (full) {
    // op1: INT_ADD reading the in-block MULTIEQUAL output (clone input must
    // remap to the clone's own COPY output).
    PcodeOp *add = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(add,CPUI_INT_ADD);
    addOut = f.makeOut(4,f.uniqueSpace(),0x4000,add);
    fd.opSetInput(add,mqOut,0);
    fd.opSetInput(add,fd.newConstant(4,0x41),1);
    fd.opInsertEnd(add,b);
    // op2: COPY with a ram persist|addrtied output — the F1 global write-back
    // shape (mapped|unaffected are out-of-mask sentinels).
    PcodeOp *cp = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(cp,CPUI_COPY);
    Varnode *ramOut = f.makeOut(8,f.ramSpace(),0x1000,cp);
    ramOut->setFlags(Varnode::persist | Varnode::addrtied |
                     Varnode::mapped | Varnode::unaffected);
    fd.opSetInput(cp,vnExt,0);
    fd.opInsertEnd(cp,b);
    // op3: COPY with a register output carrying in-mask (volatil) and
    // out-of-mask (directwrite) flags plus in-mask (writemask|ptrflow|
    // stack_store) and out-of-mask (ptrcheck) addlflags.
    PcodeOp *cr = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(cr,CPUI_COPY);
    Varnode *regOut = f.makeOut(4,f.registerSpace(),0x200,cr);
    regOut->setFlags(Varnode::volatil | Varnode::directwrite);
    regOut->addlflags |= (Varnode::writemask | Varnode::ptrflow |
                          Varnode::stack_store | Varnode::ptrcheck);
    fd.opSetInput(cr,fd.newConstant(4,0x77),0);
    fd.opInsertEnd(cr,b);
  }
  {
    // last op: STORE (no output — buildVarnodeOutput early-return path).
    PcodeOp *st = fd.newOp(3,f.allocPc());
    fd.opSetOpcode(st,CPUI_STORE);
    fd.opSetInput(st,vnExt,0);
    fd.opSetInput(st,fd.newConstant(8,0x9000),1);
    fd.opSetInput(st,full ? addOut : mqOut,2);
    fd.opInsertEnd(st,b);
  }

  // Pre-split snapshot.
  Snapshot snap;
  {
    for(auto it=b->beginOp();it!=b->endOp();++it) {
      PcodeOp *op = *it;
      snap.ops.push_back(op);
      vector<Varnode *> ins;
      for(int4 i=0;i<op->numInput();++i)
        ins.push_back(op->getIn(i));
      snap.ins.push_back(ins);
      snap.outs.push_back(op->getOut());
    }
  }
  FlowBlock *a = b->getIn(inedge);		// edge source being split on

  fd.nodeSplit(b,inedge);

  // nodeSplitBlockEdge switched a's out edge to bprime; prea/preb each have
  // exactly one out edge, so bprime is a's sole out target.
  BlockBasic *bprime = (BlockBasic *)a->getOut(0);

  cout << "blocks|case=" << caseId
       << "|bin=" << b->sizeIn()
       << "|bprimein=" << bprime->sizeIn()
       << "|bops=" << blockOpCount(b)
       << "|bprimeops=" << blockOpCount(bprime) << '\n';

  // Clone projections.
  vector<PcodeOp *> cloneOps;
  vector<Varnode *> cloneOuts;
  for(auto it=bprime->beginOp();it!=bprime->endOp();++it) {
    cloneOps.push_back(*it);
    cloneOuts.push_back((*it)->getOut());
  }
  for(size_t k=0;k<cloneOps.size();++k) {
    PcodeOp *op = cloneOps[k];
    const Varnode *out = cloneOuts[k];
    cout << "clone|case=" << caseId
         << "|op=" << k
         << "|opc=" << get_opname(op->code())
         << "|seq=" << opSeq(op)
         << "|out=" << vnDesc(out)
         << "|fl=0x" << hex << (out != (const Varnode *)0 ? (out->flags & VFLAG_PROJ) : 0)
         << "|afl=0x" << (out != (const Varnode *)0 ? (out->addlflags & AFL_PROJ) : 0)
         << dec
         << "|nin=" << op->numInput();
    for(int4 i=0;i<op->numInput();++i) {
      const Varnode *vn = op->getIn(i);
      cout << "|in" << i << '=' << inputSource(vn,cloneOuts,snap.ops,snap.ins,i)
           << ':' << vnDesc(vn);
    }
    cout << '\n';
  }

  // Original-block projections after the split.
  {
    vector<PcodeOp *> postOps;
    for(auto it=b->beginOp();it!=b->endOp();++it)
      postOps.push_back(*it);
    for(size_t k=0;k<postOps.size();++k) {
      PcodeOp *op = postOps[k];
      cout << "orig|case=" << caseId
           << "|op=" << k
           << "|opc=" << get_opname(op->code())
           << "|nin=" << op->numInput();
      for(int4 i=0;i<op->numInput();++i)
        cout << "|in" << i << '=' << vnDesc(op->getIn(i));
      cout << '\n';
    }
  }
}

void run(void)
{
  FixtureArchitecture architecture;
  runCase(architecture,"N1",0,true,0x60000);
  runCase(architecture,"N2",1,true,0x61000);
  runCase(architecture,"N3",0,false,0x62000);
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
