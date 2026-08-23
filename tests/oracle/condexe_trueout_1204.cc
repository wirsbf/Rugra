// CONDEXE-TRUEOUT-0002 fixture — getTrueOut/getFalseOut purely positional
// semantics (block.hh:299-300) and their condexe consumers, against the
// locked Ghidra 12.0.4 oracle.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable projections pinned by this fixture (one stdout line per case):
//   helper / helper_neg  getTrueOut/getFalseOut edge selection on a 2-out
//                        CBRANCH block under flip in {0,1}, before and after
//                        negateCondition (which toggles flip AND swaps the
//                        out edges, block.cc:2351) including the reverse-index
//                        fixup from swapEdges (block.cc:225-228). Positional
//                        getters must NOT vary with flip.
//   findinit F1..F7      ConditionalExecution::findInitPre (condexe.cc:55-75)
//                        driven directly: init2a_true for true-edge->prea /
//                        true-edge->preb graphs, both init CBRANCH flips,
//                        prea_inslot 0/1, the direct-edge (no intermediate)
//                        shape, and the negative shape where the two paths
//                        meet different 2-out blocks (ok=0).
//   verify V1..V4        the full verify() stage (condexe.cc:402-428) with a
//                        shared boolean varnode (SAME correlation): the
//                        (ib_flip, init_flip) matrix must compose the flip
//                        exactly once into init2a_true / camethruposta_slot.
//   zeropath Z1..Z7      RuleOrPredicate::MultiPredicate::discoverPathIsTrue
//                        (condexe.cc:572-582) driven directly: zero block on
//                        the true out / false out / condBlock-is-zeroBlock
//                        branches, each under both CBRANCH flips (the getter
//                        must ignore flip).
//
// Test-only access drives the private ConditionalExecution/MultiPredicate
// stages directly (the Rugra comparand exposes fixture_find_init_pre /
// fixture_verify / fixture_discover_path_is_true glue for the same purpose).
// ConditionalExecution declares its members with the implicit class-private
// section (no explicit `private:` label), so `private -> public` alone cannot
// reach them; `class -> struct` opens the implicit-private section. No
// decompile header uses `template<class ...>` or `enum class`, and
// <bits/stdc++.h> has already pulled every standard header, so the rewrite
// only touches Ghidra declarations in this translation unit.
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

  PcodeOp *makeCbranch(BlockBasic *blk,Varnode *boolvn,bool flip)
  {
    PcodeOp *op = fd.newOp(2,Address(code,nextPc));
    nextPc += 8;
    fd.opSetOpcode(op,CPUI_CBRANCH);
    fd.opSetInput(op,fd.newConstant(8,0x4000),0);
    fd.opSetInput(op,boolvn,1);
    fd.opInsertEnd(op,blk);
    if (flip)
      op->flipFlag(PcodeOp::boolean_flip);
    return op;
  }

  PcodeOp *makeMultiequal(BlockBasic *blk)
  {
    PcodeOp *op = fd.newOp(2,Address(code,nextPc));
    nextPc += 8;
    fd.opSetOpcode(op,CPUI_MULTIEQUAL);
    fd.opInsertEnd(op,blk);
    return op;
  }

  Varnode *makeBoolVarnode(uintb offset)
  {
    return fd.newVarnode(1,Address(unique,offset));
  }

  void bumpPc(void) { nextPc += 8; }

  Address allocPc(void)
  {
    Address a(code,nextPc);
    nextPc += 8;
    return a;
  }

  string name(const FlowBlock *bl) const
  {
    if (bl == (const FlowBlock *)0) return "-";
    for(size_t i=0;i<blocks.size();++i)
      if (blocks[i] == bl) return "b" + to_string(i);
    return "x";
  }
};

void helperRecord(const string &kind,const string &caseId,const Fixture &f,
                  FlowBlock *h,FlowBlock *t1,FlowBlock *t2,PcodeOp *cb)
{
  ostringstream out;
  out << kind << "|case=" << caseId
      << "|flip=" << (cb->isBooleanFlip() ? 1 : 0)
      << "|true=" << f.name(h->getTrueOut())
      << "|false=" << f.name(h->getFalseOut())
      << "|out0=" << f.name(h->getOut(0))
      << "|out1=" << f.name(h->getOut(1))
      << "|rev0=" << h->getOutRevIndex(0)
      << "|rev1=" << h->getOutRevIndex(1)
      << "|t1_inrev=" << t1->getInRevIndex(0)
      << "|t2_inrev=" << t2->getInRevIndex(0);
  cout << out.str() << '\n';
}

// H1: flip=0 baseline. H2: flip=1 — getters must not move. H3: one
// negateCondition (flip back to 0, out edges swapped, reverse indices fixed).
// H4: second negateCondition (flip 1, edges restored).
void runHelper(Funcdata &fd)
{
  Fixture f(fd);
  BlockBasic *h = f.makeBlock();
  BlockBasic *t1 = f.makeBlock();
  BlockBasic *t2 = f.makeBlock();
  Varnode *bv = f.makeBoolVarnode(0x100);
  PcodeOp *cb = f.makeCbranch(h,bv,false);
  f.edge(h,t1);
  f.edge(h,t2);
  helperRecord("helper","H1",f,h,t1,t2,cb);
  cb->flipFlag(PcodeOp::boolean_flip);
  helperRecord("helper","H2",f,h,t1,t2,cb);
  h->negateCondition(true);
  helperRecord("helper_neg","H3",f,h,t1,t2,cb);
  h->negateCondition(true);
  helperRecord("helper_neg","H4",f,h,t1,t2,cb);
}

enum FindInitVariant { A2PREA, A2PREB, SLOT1, DIRECT, NEGATIVE };

void runFindInitCase(Funcdata &fd,const string &caseId,FindInitVariant variant,
                     bool initFlip,int4 preaInslot)
{
  Fixture f(fd);
  const char *variantName;
  switch(variant) {
  case A2PREA:
    {
      variantName = "a2prea";
      BlockBasic *init = f.makeBlock();
      BlockBasic *prea = f.makeBlock();
      BlockBasic *preb = f.makeBlock();
      BlockBasic *ib = f.makeBlock();
      Varnode *bv = f.makeBoolVarnode(0x110);
      f.makeCbranch(init,bv,initFlip);
      f.edge(init,preb);	// init out[0]
      f.edge(init,prea);	// init out[1] -> prea chain
      f.edge(prea,ib);		// ib in[0]
      f.edge(preb,ib);		// ib in[1]
      ConditionalExecution condexe(&fd);
      condexe.iblock = ib;
      condexe.prea_inslot = preaInslot;
      bool ok = condexe.findInitPre();
      // init2a_true is indeterminate in Ghidra when findInitPre fails (the
      // ctor leaves it unassigned and the assignment at condexe.cc:72 is
      // only reached on the success path); project it only when ok.
      cout << "findinit|case=" << caseId << "|variant=" << variantName
           << "|init_flip=" << (initFlip ? 1 : 0)
           << "|prea_inslot=" << preaInslot
           << "|ok=" << (ok ? 1 : 0);
      if (ok)
        cout << "|init2a_true=" << (condexe.init2a_true ? 1 : 0);
      cout << '\n';
      return;
    }
  case A2PREB:
    {
      variantName = "a2preb";
      BlockBasic *init = f.makeBlock();
      BlockBasic *prea = f.makeBlock();
      BlockBasic *preb = f.makeBlock();
      BlockBasic *ib = f.makeBlock();
      Varnode *bv = f.makeBoolVarnode(0x120);
      f.makeCbranch(init,bv,initFlip);
      f.edge(init,prea);	// init out[0]
      f.edge(init,preb);	// init out[1] -> preb, NOT prea
      f.edge(prea,ib);
      f.edge(preb,ib);
      ConditionalExecution condexe(&fd);
      condexe.iblock = ib;
      condexe.prea_inslot = preaInslot;
      bool ok = condexe.findInitPre();
      // init2a_true is indeterminate in Ghidra when findInitPre fails (the
      // ctor leaves it unassigned and the assignment at condexe.cc:72 is
      // only reached on the success path); project it only when ok.
      cout << "findinit|case=" << caseId << "|variant=" << variantName
           << "|init_flip=" << (initFlip ? 1 : 0)
           << "|prea_inslot=" << preaInslot
           << "|ok=" << (ok ? 1 : 0);
      if (ok)
        cout << "|init2a_true=" << (condexe.init2a_true ? 1 : 0);
      cout << '\n';
      return;
    }
  case SLOT1:
    {
      variantName = "slot1";
      BlockBasic *init = f.makeBlock();
      BlockBasic *prea = f.makeBlock();
      BlockBasic *preb = f.makeBlock();
      BlockBasic *ib = f.makeBlock();
      Varnode *bv = f.makeBoolVarnode(0x130);
      f.makeCbranch(init,bv,initFlip);
      f.edge(init,preb);	// init out[0]
      f.edge(init,prea);	// init out[1] -> prea
      f.edge(preb,ib);		// ib in[0] is preb
      f.edge(prea,ib);		// ib in[1] is prea
      ConditionalExecution condexe(&fd);
      condexe.iblock = ib;
      condexe.prea_inslot = preaInslot;
      bool ok = condexe.findInitPre();
      // init2a_true is indeterminate in Ghidra when findInitPre fails (the
      // ctor leaves it unassigned and the assignment at condexe.cc:72 is
      // only reached on the success path); project it only when ok.
      cout << "findinit|case=" << caseId << "|variant=" << variantName
           << "|init_flip=" << (initFlip ? 1 : 0)
           << "|prea_inslot=" << preaInslot
           << "|ok=" << (ok ? 1 : 0);
      if (ok)
        cout << "|init2a_true=" << (condexe.init2a_true ? 1 : 0);
      cout << '\n';
      return;
    }
  case DIRECT:
    {
      variantName = "direct";
      BlockBasic *init = f.makeBlock();
      BlockBasic *ib = f.makeBlock();
      Varnode *bv = f.makeBoolVarnode(0x140);
      f.makeCbranch(init,bv,initFlip);
      f.edge(init,ib);		// both out edges straight into ib
      f.edge(init,ib);
      ConditionalExecution condexe(&fd);
      condexe.iblock = ib;
      condexe.prea_inslot = preaInslot;
      bool ok = condexe.findInitPre();
      // init2a_true is indeterminate in Ghidra when findInitPre fails (the
      // ctor leaves it unassigned and the assignment at condexe.cc:72 is
      // only reached on the success path); project it only when ok.
      cout << "findinit|case=" << caseId << "|variant=" << variantName
           << "|init_flip=" << (initFlip ? 1 : 0)
           << "|prea_inslot=" << preaInslot
           << "|ok=" << (ok ? 1 : 0);
      if (ok)
        cout << "|init2a_true=" << (condexe.init2a_true ? 1 : 0);
      cout << '\n';
      return;
    }
  case NEGATIVE:
  default:
    {
      variantName = "negative";
      BlockBasic *a = f.makeBlock();
      BlockBasic *b = f.makeBlock();
      BlockBasic *c1 = f.makeBlock();
      BlockBasic *c2 = f.makeBlock();
      BlockBasic *ib = f.makeBlock();
      BlockBasic *extraA = f.makeBlock();
      BlockBasic *extraB = f.makeBlock();
      // Distinct boolean varnodes: findInitPre never correlates them.
      Varnode *bv1 = f.makeBoolVarnode(0x150);
      Varnode *bv2 = f.makeBoolVarnode(0x158);
      f.makeCbranch(a,bv1,initFlip);
      f.makeCbranch(b,bv2,initFlip);
      f.edge(a,c1);
      f.edge(a,extraA);
      f.edge(b,c2);
      f.edge(b,extraB);
      f.edge(c1,ib);
      f.edge(c2,ib);
      ConditionalExecution condexe(&fd);
      condexe.iblock = ib;
      condexe.prea_inslot = preaInslot;
      bool ok = condexe.findInitPre();
      // init2a_true is indeterminate in Ghidra when findInitPre fails (the
      // ctor leaves it unassigned and the assignment at condexe.cc:72 is
      // only reached on the success path); project it only when ok.
      cout << "findinit|case=" << caseId << "|variant=" << variantName
           << "|init_flip=" << (initFlip ? 1 : 0)
           << "|prea_inslot=" << preaInslot
           << "|ok=" << (ok ? 1 : 0);
      if (ok)
        cout << "|init2a_true=" << (condexe.init2a_true ? 1 : 0);
      cout << '\n';
      return;
    }
  }
}

// Full verify() stage with a shared boolean varnode: matchflip composes to
// ib_flip XOR init_flip and complements init2a_true exactly once.
void runVerify(Funcdata &fd)
{
  Fixture f(fd);
  // Writer block producing the shared boolean varnode (both CBRANCHes read
  // the same written Varnode, giving the SAME correlation in
  // BooleanMatch::evaluate via pointer equality).
  BlockBasic *writer = f.makeBlock();
  BlockBasic *init = f.makeBlock();
  BlockBasic *prea = f.makeBlock();
  BlockBasic *preb = f.makeBlock();
  BlockBasic *ib = f.makeBlock();
  BlockBasic *posta = f.makeBlock();
  BlockBasic *postb = f.makeBlock();
  Varnode *bv = (Varnode *)0;
  {
    PcodeOp *wop = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(wop,CPUI_COPY);
    fd.opSetInput(wop,fd.newConstant(1,1),0);
    bv = fd.newUniqueOut(1,wop);
    fd.opInsertEnd(wop,writer);
  }
  PcodeOp *initCb = f.makeCbranch(init,bv,false);
  PcodeOp *ibCb = f.makeCbranch(ib,bv,false);
  f.edge(init,preb);	// init out[0] -> preb (true edge goes to prea)
  f.edge(init,prea);	// init out[1] -> prea; raw init2a_true = true
  f.edge(prea,ib);	// ib in[0] = prea (verify forces prea_inslot=0)
  f.edge(preb,ib);	// ib in[1] = preb
  f.edge(ib,posta);	// ib out[0] -> posta; iblock2posta_true = false
  f.edge(ib,postb);	// ib out[1] -> postb
  const bool ibFlips[] = { false, false, true, true };
  const bool initFlips[] = { false, true, false, true };
  for(int i=0;i<4;++i) {
    if (ibFlips[i])
      ibCb->flipFlag(PcodeOp::boolean_flip);
    if (initFlips[i])
      initCb->flipFlag(PcodeOp::boolean_flip);
    ConditionalExecution condexe(&fd);
    condexe.iblock = ib;
    condexe.cbranch = ibCb;
    bool ok = condexe.verify();
    cout << "verify|case=V" << (i + 1)
         << "|ib_flip=" << (ibFlips[i] ? 1 : 0)
         << "|init_flip=" << (initFlips[i] ? 1 : 0)
         << "|ok=" << (ok ? 1 : 0)
         << "|init2a_true=" << (condexe.init2a_true ? 1 : 0)
         << "|camethruposta_slot=" << condexe.camethruposta_slot
         << "|posta=" << f.name(condexe.posta_block)
         << "|postb=" << f.name(condexe.postb_block) << '\n';
    if (ibFlips[i])
      ibCb->flipFlag(PcodeOp::boolean_flip);
    if (initFlips[i])
      initCb->flipFlag(PcodeOp::boolean_flip);
  }
}

// discoverPathIsTrue driven directly on a MultiPredicate with filled fields.
void runZeroPath(Funcdata &fd)
{
  Fixture f(fd);
  BlockBasic *cond = f.makeBlock();
  BlockBasic *z1 = f.makeBlock();
  BlockBasic *z2 = f.makeBlock();
  Varnode *bv = f.makeBoolVarnode(0x170);
  PcodeOp *cb = f.makeCbranch(cond,bv,false);
  PcodeOp *mq1 = f.makeMultiequal(z1);
  PcodeOp *mq2 = f.makeMultiequal(z2);
  f.edge(cond,z1);	// cond out[0] (false out)
  f.edge(cond,z2);	// cond out[1] (true out)
  struct ZCase { const char *caseId; FlowBlock *zeroBlock; PcodeOp *op; bool flip; };
  const ZCase cases[] = {
    { "Z1", z2, mq2, false },
    { "Z2", z2, mq2, true },
    { "Z3", z1, mq2, false },
    { "Z4", z1, mq2, true },
    { "Z5", cond, mq2, false },
    { "Z6", cond, mq2, true },
    { "Z7", cond, mq1, false },
  };
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
    if (cases[i].flip)
      cb->flipFlag(PcodeOp::boolean_flip);
    RuleOrPredicate::MultiPredicate mp;
    mp.op = cases[i].op;
    mp.zeroBlock = cases[i].zeroBlock;
    mp.condBlock = cond;
    mp.cbranch = cb;
    mp.discoverPathIsTrue();
    cout << "zeropath|case=" << cases[i].caseId
         << "|flip=" << (cases[i].flip ? 1 : 0)
         << "|zero_path_is_true=" << (mp.zeroPathIsTrue ? 1 : 0) << '\n';
    if (cases[i].flip)
      cb->flipFlag(PcodeOp::boolean_flip);
  }
}

void run(void)
{
  FixtureArchitecture architecture;
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd("condexe_trueout","condexe_trueout",global,Address(ram,0x60000),
              (FunctionSymbol *)0,0x100);
  // buildHeritageArray (condexe.cc:23-37) reads Heritage::numHeritagePasses,
  // which requires the lazy Heritage::infolist to be populated. The real
  // pipeline guarantees this via the first heritage() pass; replicate the
  // precondition for this synthetic function.
  fd.heritage.buildInfoList();
  runHelper(fd);
  runFindInitCase(fd,"F1",A2PREA,false,0);
  runFindInitCase(fd,"F2",A2PREA,true,0);
  runFindInitCase(fd,"F3",A2PREB,false,0);
  runFindInitCase(fd,"F4",A2PREB,true,0);
  runFindInitCase(fd,"F5",SLOT1,false,1);
  runFindInitCase(fd,"F6",DIRECT,false,0);
  runFindInitCase(fd,"F7",NEGATIVE,false,0);
  runVerify(fd);
  runZeroPath(fd);
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
