// MERGE-TRIM-LANE-0001 fixture — the phi(X, f(X)) lane-trim chain of
// ActionMergeRequired (RULE-PROPCOPY-ADDRTIED-0001):
//   Funcdata::setHighLevel (funcdata_varnode.cc:595) lazily builds Varnode
//   covers (varnode.cc:233 updateCover -> Cover::rebuild); then
//   Merge::mergeAddrTied + Merge::mergeMarker (merge.cc:609/889) run
//   Merge::mergeOp (merge.cc:719) on every MULTIEQUAL. When two lanes of a
//   phi intersect (the CMOVcc idiom: X live through the cond block while
//   f(X) is computed there), mergeOp calls trimOpInput (merge.cc:692) which
//   inserts a COPY at the END of each lane's incoming block — the
//   branch-local instantiation printed as `if (c) { x = f(x); }`.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Cases (one stdout line group per case):
//   T1  CMOV shape: phi(X, f(X)) with f(X)=INT_RIGHT defined in the cond
//       block b1, then-block b2 empty, phi + reader in join b3. Expected:
//       X/fX covers nonempty, intersect(X,fX)=2 (interval, in b1),
//       trim COPYs inserted at end of b1 (reads X) and end of b2 (reads fX),
//       both marked non-printing by Merge::markInternalCopies.
//   T2  control: f(X) defined inside the then block b2. X and f(X) covers
//       only touch (boundary), no trim COPY, no intersection.
//
// Projections use stable fixture identities (block names b0..b3, varnode
// names X/fX/phiout, op order) — never SeqNums or unique offsets.
// Standard headers come first so the access macros cannot leak into libstdc++.
#include <bits/stdc++.h>
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "merge.hh"
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
  map<const Varnode *,string> vnNames;

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

  Varnode *makeOut(int4 size,AddrSpace *space,uintb offset,PcodeOp *op)
  {
    return fd.newVarnodeOut(size,Address(space,offset),op);
  }

  Varnode *makeConst(int4 size,uintb value) { return fd.newConstant(size,value); }

  PcodeOp *makeCbranch(BlockBasic *blk,Varnode *boolvn)
  {
    PcodeOp *op = fd.newOp(2,allocPc());
    fd.opSetOpcode(op,CPUI_CBRANCH);
    fd.opSetInput(op,fd.newConstant(8,0x4000),0);
    fd.opSetInput(op,boolvn,1);
    fd.opInsertEnd(op,blk);
    return op;
  }

  void nameVn(const Varnode *vn,const string &n) { vnNames[vn] = n; }
  string name(const Varnode *vn) const
  {
    map<const Varnode *,string>::const_iterator iter = vnNames.find(vn);
    return iter == vnNames.end() ? "?" : (*iter).second;
  }
  string name(const FlowBlock *bl) const
  {
    for(size_t i=0;i<blocks.size();++i)
      if (blocks[i] == bl) return "b" + to_string(i);
    return "x";
  }
};

// Max CoverBlock intersect character across the common blocks of the two
// Varnode covers (0 none, 1 boundary, 2 interval). Uses the public
// Cover::intersectByBlock over the union of covered blocks.
int4 coverPairChar(const Varnode *a,const Varnode *b)
{
  const Cover *ca = a->getCover();
  const Cover *cb = b->getCover();
  if (ca == (Cover *)0 || cb == (Cover *)0) return -1;
  int4 res = 0;
  for(int4 blk=0;blk<16;++blk) {
    int4 cha = ca->intersectByBlock(blk,*cb);
    if (cha > res) res = cha;
  }
  return res;
}

void recordCover(const string &caseId,const string &vnName,const Varnode *vn)
{
  const Cover *cov = vn->getCover();
  bool nonempty = cov != (Cover *)0 && cov->begin() != cov->end();
  cout << "cover|case=" << caseId << "|vn=" << vnName
       << "|nonempty=" << (nonempty ? 1 : 0) << '\n';
}

void recordOps(const string &caseId,const Fixture &f,BlockBasic *blk)
{
  cout << "ops|case=" << caseId << "|blk=" << f.name(blk) << "|list=";
  bool first = true;
  list<PcodeOp *>::const_iterator oiter;
  for(oiter = blk->beginOp();oiter != blk->endOp();++oiter) {
    PcodeOp *op = *oiter;
    if (!first) cout << ';';
    first = false;
    cout << get_opname(op->code());
    if (op->getOut() != (Varnode *)0) cout << '(' << f.name(op->getOut()) << ')';
    if (op->numInput() > 0) {
      cout << '<';
      for(int4 i=0;i<op->numInput();++i)
        cout << (i ? "," : "") << f.name(op->getIn(i));
      cout << '>';
    }
  }
  cout << '\n';
}

void recordCopyNp(const string &caseId,const Fixture &f,BlockBasic *blk)
{
  int4 idx = 0;
  list<PcodeOp *>::const_iterator oiter;
  for(oiter = blk->beginOp();oiter != blk->endOp();++oiter,++idx) {
    PcodeOp *op = *oiter;
    if (op->code() != CPUI_COPY) continue;
    cout << "np|case=" << caseId << "|blk=" << f.name(blk) << "|idx=" << idx
         << "|np=" << ((op->flags & PcodeOp::nonprinting) != 0 ? 1 : 0)
         << "|reads=" << f.name(op->getIn(0)) << '\n';
  }
}

// Build the CMOV-post-condexe diamond:
//   b0: X = COPY(0x1234)                      (X: register 0x20)
//   b1: fX = INT_RIGHT(X,16); CBRANCH(bool)   (fX: unique)
//   b2: (empty; fX-here variant for T2 puts the INT_RIGHT here)
//   b3: phi = MULTIEQUAL(X, fX); y = INT_AND(phi,0xff)
// bool input: a free 1-byte varnode read only by the CBRANCH.
// fx_in_then selects the T2 control placement.
void runCase(Funcdata &fd,const string &caseId,bool fx_in_then)
{
  Fixture f(fd);
  BlockBasic *b0 = f.makeBlock();
  BlockBasic *b1 = f.makeBlock();
  BlockBasic *b2 = f.makeBlock();
  BlockBasic *b3 = f.makeBlock();
  BlockBasic *b4 = f.makeBlock();
  f.edge(b0,b1);          // b1 in[0]
  f.edge(b1,b2);          // b2 in[0]   (b1 out[0] — fall-through/then)
  f.edge(b1,b3);          // b3 in[0]   (b1 out[1] — branch/skip)
  f.edge(b2,b3);          // b3 in[1]
  f.edge(b3,b4);          // b4 in[0]

  PcodeOp *defX = fd.newOp(1,f.allocPc());
  fd.opSetOpcode(defX,CPUI_COPY);
  Varnode *X = f.makeOut(4,f.reg,0x20,defX); // Ghidra: funcdata_varnode.cc:104 newVarnodeOut
  fd.opSetInput(defX,f.makeConst(4,0x1234),0);
  fd.opInsertEnd(defX,b0);
  f.nameVn(X,"X");

  Varnode *boolvn = fd.newVarnode(1,Address(f.unique,0x900));
  PcodeOp *fxOp = fd.newOp(2,f.allocPc());
  fd.opSetOpcode(fxOp,CPUI_INT_RIGHT);
  Varnode *fX = f.makeOut(4,f.unique,0x910,fxOp);
  fd.opSetInput(fxOp,X,0);
  fd.opSetInput(fxOp,f.makeConst(4,16),1);
  fd.opInsertEnd(fxOp,fx_in_then ? b2 : b1);
  f.nameVn(fX,"fX");

  f.makeCbranch(b1,boolvn);

  PcodeOp *phi = fd.newOp(2,f.allocPc());
  fd.opSetOpcode(phi,CPUI_MULTIEQUAL);
  Varnode *phiOut = f.makeOut(4,f.reg,0x20,phi);
  fd.opSetInput(phi,X,0);        // lane 0 arrives via b1 (skip edge)
  fd.opSetInput(phi,fX,1);       // lane 1 arrives via b2 (then edge)
  fd.opInsertBegin(phi,b3);
  f.nameVn(phiOut,"phiout");

  PcodeOp *reader = fd.newOp(2,f.allocPc());
  fd.opSetOpcode(reader,CPUI_INT_AND);
  Varnode *y = f.makeOut(4,f.unique,0x920,reader);
  fd.opSetInput(reader,phiOut,0);
  fd.opSetInput(reader,f.makeConst(4,0xff),1);
  fd.opInsertEnd(reader,b4);
  f.nameVn(y,"y");

  // ActionAssignHigh (coreaction.hh:346): Funcdata::setHighLevel.
  fd.setHighLevel();
  recordCover(caseId,"X",X);
  recordCover(caseId,"fX",fX);
  recordCover(caseId,"phiout",phiOut);
  cout << "intersect|case=" << caseId << "|pair=X_fX|char=" << coverPairChar(X,fX) << '\n';
  cout << "intersect|case=" << caseId << "|pair=X_phiout|char=" << coverPairChar(X,phiOut) << '\n';
  cout << "intersect|case=" << caseId << "|pair=fX_phiout|char=" << coverPairChar(fX,phiOut) << '\n';

  // ActionMergeRequired (coreaction.hh:369): mergeAddrTied; groupPartials;
  // mergeMarker. groupPartials has no CONCAT trees here.
  fd.getMerge().mergeAddrTied();
  // Ghidra mergeOp throws LowlevelError from this synthetic case's final
  // forced merge; the observable IR artifacts (trim COPYs, trimOpOutput
  // COPY, phi lane rewiring) are already in place when it throws, and the
  // fixture records only those artifacts (never the exception channel).
  try {
    fd.getMerge().mergeMarker();
  }
  catch(const LowlevelError &) {}
  recordOps(caseId,f,b0);
  recordOps(caseId,f,b1);
  recordOps(caseId,f,b2);
  recordOps(caseId,f,b3);
  recordOps(caseId,f,b4);
  // Lane projection: a lane still reading a fixture varnode prints its name;
  // a lane rewired to a trim COPY prints copy@<block>(<reads>).
  for(int4 slot=0;slot<2;++slot) {
    Varnode *lane = phi->getIn(slot);
    string desc = f.name(lane);
    if (desc == "?" && lane->isWritten() && lane->getDef()->code() == CPUI_COPY) {
      const PcodeOp *c = lane->getDef();
      BlockBasic *pbl = (BlockBasic *)c->getParent();
      desc = "copy@" + f.name(pbl) + "(" + f.name(c->getIn(0)) + ")";
    }
    cout << "phi|case=" << caseId << "|lane" << slot << "=" << desc << '\n';
  }

  // ActionCopyMarker (coreaction.hh:1015): markInternalCopies.
  fd.getMerge().markInternalCopies();
  recordCopyNp(caseId,f,b0);
  recordCopyNp(caseId,f,b1);
  recordCopyNp(caseId,f,b2);
  recordCopyNp(caseId,f,b3);
  recordCopyNp(caseId,f,b4);
}

void run(void)
{
  FixtureArchitecture architecture;
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  {
    Funcdata fd("merge_trim_lane_T1","merge_trim_lane_T1",global,Address(ram,0x60000),
                (FunctionSymbol *)0,0x100);
    runCase(fd,"T1",false);
  }
  {
    Funcdata fd("merge_trim_lane_T2","merge_trim_lane_T2",global,Address(ram,0x62000),
                (FunctionSymbol *)0,0x100);
    runCase(fd,"T2",true);
  }
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
