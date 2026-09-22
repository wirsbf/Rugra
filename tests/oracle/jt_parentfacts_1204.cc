// JUMPTABLE-PARENTFACTS-FIXTURE-0001 — both-side B2 fixture for the two
// JumpParentFacts channels of JumpTable::recoverModel (e27e985):
//
//   Channel (1) multistage partial-table -> analyzeGuards usenzmask
//     checkForMultistage (jumptable.cc:2847) sets partialTable=true after
//     the override marks the BRANCHIND; recoverMultistage (cc:2653) then
//     runs recoverAddresses -> recoverModel -> JumpBasic::analyzeGuards
//     with usenezmask = !isPartial() = false (cc:1052). With usenzmask
//     false, CircleRange::pullBack (rangeutil.cc:1022) does NOT take the
//     SUBPIECE nzmask rescue (cc:1053-1065), so the guard chain stops one
//     record earlier. Case M1 pins: stage1 (non-partial) 3 guard records
//     including the SUBPIECE record, stage2 (partial) only 2.
//
//   Channel (2) sibling BRANCHIND identity at i>0 (cc:1083-1091)
//     JumpBasic2's analyzeGuards(rootbl,pathout) walks above the calc-path
//     block; the second CBRANCH's sibling edge target block ending with a
//     BRANCHIND must be compared against jt->getIndirectOp() by identity.
//     P1: sibling edge hits THIS switch block -> guard collection
//     continues (6 records, the g2 chain present).
//     P0: sibling edge hits a block ending with a DIFFERENT BRANCHIND ->
//     break (3 records, g2 chain lost) - the protecting-another-switch
//     path.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Projections use stable fixture identities (block creation ordinals bN,
// varnode names, op opcode names, decimal range sizes, lowercase hex
// labels) — never SeqNums, unique offsets, or raw pointers.
// Standard headers come first so the access macros cannot leak into
// libstdc++. protected must be public alongside private because
// JumpBasic::selectguards is protected (jumptable.hh:377).
#include <bits/stdc++.h>
#define private public
#define protected public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "database.hh"
#include "funcdata.hh"
#include "jumptable.hh"
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
  vector<FlowBlock *> blocks;
  uintb nextPc;
  map<const Varnode *,string> vnNames;
public:
  explicit Fixture(Funcdata &f)
    : fd(f), code(f.getArch()->getDefaultCodeSpace()),
      unique(f.getArch()->getSpaceByName("unique")), nextPc(0x30000) {}

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
  Address allocPc(void) { Address a(code,nextPc); nextPc += 8; return a; }
  Varnode *makeOut(int4 size,AddrSpace *space,uintb offset,PcodeOp *op)
  { return fd.newVarnodeOut(size,Address(space,offset),op); }
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
  PcodeOp *makeOp1(BlockBasic *blk,OpCode oc,Varnode *in0,uintb uoff,int4 osize)
  {
    PcodeOp *op = fd.newOp(1,allocPc());
    fd.opSetOpcode(op,oc);
    makeOut(osize,unique,uoff,op);
    fd.opSetInput(op,in0,0);
    fd.opInsertEnd(op,blk);
    return op;
  }
  PcodeOp *makeOp2(BlockBasic *blk,OpCode oc,Varnode *in0,Varnode *in1,
                   uintb uoff,int4 osize)
  {
    PcodeOp *op = fd.newOp(2,allocPc());
    fd.opSetOpcode(op,oc);
    makeOut(osize,unique,uoff,op);
    fd.opSetInput(op,in0,0);
    fd.opSetInput(op,in1,1);
    fd.opInsertEnd(op,blk);
    return op;
  }
  void nameVn(const Varnode *vn,const string &n) { vnNames[vn] = n; }
  string name(const Varnode *vn) const
  {
    map<const Varnode *,string>::const_iterator it = vnNames.find(vn);
    return it == vnNames.end() ? "?" : (*it).second;
  }
  string name(const FlowBlock *bl) const
  {
    for(size_t i=0;i<blocks.size();++i) if (blocks[i] == bl) return "b" + to_string(i);
    return "x";
  }
};

string modelKind(const JumpTable &jt)
{
  if (jt.jmodel == (JumpModel *)0) return "null";
  if (dynamic_cast<const JumpBasic2 *>(jt.jmodel) != (const JumpBasic2 *)0) return "basic2";
  if (dynamic_cast<const JumpBasic *>(jt.jmodel) != (const JumpBasic *)0) return "basic";
  if (dynamic_cast<const JumpBasicOverride *>(jt.jmodel) != (const JumpBasicOverride *)0) return "override";
  if (dynamic_cast<const JumpAssisted *>(jt.jmodel) != (const JumpAssisted *)0) return "assisted";
  if (dynamic_cast<const JumpModelTrivial *>(jt.jmodel) != (const JumpModelTrivial *)0) return "trivial";
  return "other";
}

// Stage projection: model kind, partialTable, guard records (the
// analyzeGuards observable), address-table size.
void dumpStage(const string &id,const string &phase,JumpTable &jt,Fixture &f)
{
  JumpBasic *jb = dynamic_cast<JumpBasic *>(jt.jmodel);
  cout << "stage|id=" << id << "|phase=" << phase
       << "|model=" << modelKind(jt)
       << "|isPartial=" << (jt.isPartial()?1:0)
       << "|guards=" << (jb == (JumpBasic *)0 ? -1 : (int4)jb->selectguards.size())
       << "|addrN=" << jt.addresstable.size() << '\n';
  if (jb == (JumpBasic *)0) return;
  for(size_t i=0;i<jb->selectguards.size();++i) {
    GuardRecord &g(jb->selectguards[i]);
    cout << "guard|id=" << id << "|phase=" << phase << "|i=" << i
         << "|clear=" << (g.getBranch() == (PcodeOp *)0 ? 1 : 0);
    if (g.getBranch() != (PcodeOp *)0)
      cout << "|cbrBlk=" << f.name(g.getBranch()->getParent());
    if (g.getReadOp() != (PcodeOp *)0)
      cout << "|readOp=" << get_opname(g.getReadOp()->code());
    cout << "|vn=" << f.name(g.vn)
         << "|rngSz=" << g.getRange().getSize() << '\n';
  }
}

void dumpTail(const string &id,JumpTable &jt)
{
  cout << "labels|id=" << id << "|n=" << jt.label.size();
  for(size_t i=0;i<jt.label.size();++i)
    cout << ((i==0)?"|":";") << "lab" << i << "=0x" << hex << jt.label[i] << dec;
  cout << '\n';
}

// ============================================================
// M1 — multistage partial-table channel (cc:1052 / cc:2847 / cc:2653):
//   b0 entry -> b1 guard block
//   b1: w2=COPY(w); x=INT_AND(w2,0xff) [NZMask 0xff]; y=SUBPIECE(x,0);
//       g=INT_EQUAL(y,5); CBRANCH out0->b2 def, out1->b3 switch
//   b3: z=INT_ZEXT(y); a=INT_MULT(z,8); t=INT_ADD(a,0x30000);
//       BRANCHIND(t)
// stage1 (fresh table, usenzmask=true): SUBPIECE nzmask rescue
// (rangeutil.cc:1053-1065, msbset=(mostsigbit_set(0xff)+8)/8=1 <= 1) adds
// the third guard record; checkForMultistage flips partialTable via the
// override mark; recoverMultistage's recovery runs with usenzmask=false
// and drops that record.
// ============================================================
void runM1(FixtureArchitecture &archGlb)
{
  AddrSpace *ram = archGlb.getSpace(3);
  Scope *global = archGlb.symboltab->getGlobalScope();
  Funcdata fd("jt_parentfacts_M1","jt_parentfacts_M1",global,Address(ram,0x60000),
              (FunctionSymbol *)0,0x100);
  Fixture f(fd);
  const string id = "M1";

  BlockBasic *b_entry = f.makeBlock();
  BlockBasic *b_g = f.makeBlock();
  BlockBasic *b_def = f.makeBlock();
  BlockBasic *b_sw = f.makeBlock();
  BlockBasic *b_out = f.makeBlock();
  f.edge(b_entry,b_g);
  f.edge(b_g,b_def);          // b_g out0 (not taken)
  f.edge(b_g,b_sw);           // b_g out1 (taken -> switch)
  f.edge(b_sw,b_out);
  f.edge(b_def,b_out);

  Varnode *w = fd.newVarnode(4,Address(f.unique,0x800));
  f.nameVn(w,"w");
  PcodeOp *cp0 = f.makeOp1(b_g,CPUI_COPY,w,0x808,4);
  Varnode *w2 = cp0->getOut(); f.nameVn(w2,"w2");
  PcodeOp *andOp = f.makeOp2(b_g,CPUI_INT_AND,w2,f.makeConst(4,0xff),0x810,4);
  Varnode *x = andOp->getOut(); f.nameVn(x,"x");
  PcodeOp *subOp = fd.newOp(2,f.allocPc());
  fd.opSetOpcode(subOp,CPUI_SUBPIECE);
  Varnode *y = f.makeOut(1,f.unique,0x820,subOp);
  fd.opSetInput(subOp,x,0);
  fd.opSetInput(subOp,f.makeConst(1,0),1);
  fd.opInsertEnd(subOp,b_g);
  f.nameVn(y,"y");
  PcodeOp *eqOp = f.makeOp2(b_g,CPUI_INT_EQUAL,y,f.makeConst(1,5),0x830,1);
  Varnode *g = eqOp->getOut(); f.nameVn(g,"g");
  f.makeCbranch(b_g,g);

  PcodeOp *zextOp = f.makeOp1(b_sw,CPUI_INT_ZEXT,y,0x840,4);
  Varnode *z = zextOp->getOut(); f.nameVn(z,"z");
  PcodeOp *multOp = f.makeOp2(b_sw,CPUI_INT_MULT,z,f.makeConst(4,8),0x850,4);
  Varnode *a = multOp->getOut(); f.nameVn(a,"a");
  PcodeOp *addOp = f.makeOp2(b_sw,CPUI_INT_ADD,a,f.makeConst(4,0x30000),0x860,4);
  Varnode *t = addOp->getOut(); f.nameVn(t,"t");
  PcodeOp *indOp = fd.newOp(1,f.allocPc());
  fd.opSetOpcode(indOp,CPUI_BRANCHIND);
  fd.opSetInput(indOp,t,0);
  fd.opInsertEnd(indOp,b_sw);

  // ActionNonzeroMask (coreaction.hh:295) runs before stageJumpTable in the
  // real pipeline; the pullBack rescue reads these NZMasks.
  fd.calcNZMask();
  cout << "case|id=" << id << '\n';
  cout << "nzmask|id=" << id << "|vn=x|mask=0x" << hex << x->getNZMask() << dec << '\n';

  JumpTable jt(&archGlb,indOp->getAddr());
  jt.setIndirectOp(indOp);
  fd.getOverride().insertMultistageJump(indOp->getAddr());
  try {
    jt.recoverAddresses(&fd);
    dumpStage(id,"stage1",jt,f);
    bool more = jt.checkForMultistage(&fd);
    cout << "multistage|id=" << id << "|ret=" << (more?1:0)
         << "|isPartial=" << (jt.isPartial()?1:0) << '\n';
    jt.recoverMultistage(&fd);
    dumpStage(id,"stage2",jt,f);
    // ActionSwitchNorm tail (coreaction.cc:4554-4562) — partialTable was
    // cleared by recoverMultistage (cc:2674), so this recovery is
    // non-partial again (usenzmask=true).
    jt.matchModel(&fd);
    dumpStage(id,"match",jt,f);
    jt.recoverLabels(&fd);
    dumpTail(id,jt);
    bool folded = jt.foldInGuards(&fd);
    cout << "fold|id=" << id << "|ret=" << (folded?1:0)
         << "|defaultBlock=" << jt.getDefaultBlock()
         << "|numEntries=" << jt.numEntries() << '\n';
  }
  catch(LowlevelError &err) {
    cout << "exception|id=" << id << "|" << err.explain << '\n';
  }
}

// ============================================================
// P1/P0 — JumpBasic2 sibling BRANCHIND identity channel (cc:1083-1091).
//   sameSib=true  (P1): b_g2 out0 -> b_sw directly (the default COPY rides
//                       this edge); sibling ends with OUR BRANCHIND ->
//                       guard collection CONTINUES past i=1.
//   sameSib=false (P0): b_g2 out0 -> b_alt which ends with a DIFFERENT
//                       BRANCHIND; identity check breaks the walk.
// Layout (block creation order fixed for stable ordinals):
//   b0 entry, b1 g2, b2 alt, b3 calc, b4 else, b5 sw, b6 def2, b7 out
//   b1: q=COPY(x); g2b=INT_LESS(q,10); [P1: cd=COPY(0x7777)]; CBRANCH
//   b3: z=INT_AND(0xfff,0xff); z2=COPY(z); g1b=INT_EQUAL(z2,0x30); CBRANCH
//   b5: me=MULTIEQUAL(cd,z in-edge order); BRANCHIND(me)
// The address tree under me has no ispoint leaf (INT_AND of constants), so
// JumpBasic's PathMeld falls back to the single me varnode (cc:586-590);
// JumpBasic fails (me's unguarded range exceeds max_jumptable_size) and
// JumpBasic2 fires with rootbl=b3/pathout (cc:1696-1697).
// ============================================================
void runP(FixtureArchitecture &archGlb,bool sameSib)
{
  AddrSpace *ram = archGlb.getSpace(3);
  Scope *global = archGlb.symboltab->getGlobalScope();
  string id = sameSib ? "P1" : "P0";
  Funcdata fd("jt_parentfacts_"+id,"jt_parentfacts_"+id,global,Address(ram,0x60000),
              (FunctionSymbol *)0,0x100);
  Fixture f(fd);

  BlockBasic *b_entry = f.makeBlock();
  BlockBasic *b_g2 = f.makeBlock();
  BlockBasic *b_alt = f.makeBlock();
  BlockBasic *b_calc = f.makeBlock();
  BlockBasic *b_else = f.makeBlock();
  BlockBasic *b_sw = f.makeBlock();
  BlockBasic *b_def2 = f.makeBlock();
  BlockBasic *b_out = f.makeBlock();

  if (sameSib) {
    f.edge(b_entry,b_g2);
    f.edge(b_g2,b_sw);         // b_g2 out0: direct into OUR switch
    f.edge(b_g2,b_calc);       // b_g2 out1: calc path
    f.edge(b_calc,b_else);     // b_calc out0
    f.edge(b_calc,b_sw);       // b_calc out1 -> switch
    f.edge(b_sw,b_out);
    f.edge(b_else,b_out);
  } else {
    f.edge(b_entry,b_g2);
    f.edge(b_entry,b_def2);
    f.edge(b_g2,b_alt);        // b_g2 out0: ANOTHER switch
    f.edge(b_g2,b_calc);       // b_g2 out1: calc path
    f.edge(b_calc,b_else);
    f.edge(b_calc,b_sw);
    f.edge(b_def2,b_sw);
    f.edge(b_sw,b_out);
    f.edge(b_else,b_out);
    f.edge(b_alt,b_out);
  }

  cout << "case|id=" << id << '\n';

  Varnode *x = fd.newVarnode(4,Address(f.unique,0x800));
  f.nameVn(x,"x");

  Varnode *cd;
  if (sameSib) {
    PcodeOp *cdOp = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(cdOp,CPUI_COPY);
    cd = f.makeOut(4,f.unique,0x820,cdOp);
    fd.opSetInput(cdOp,f.makeConst(4,0x7777),0);
    fd.opInsertEnd(cdOp,b_g2);
    f.nameVn(cd,"cd");
  } else {
    PcodeOp *cdOp = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(cdOp,CPUI_COPY);
    cd = f.makeOut(4,f.unique,0x820,cdOp);
    fd.opSetInput(cdOp,f.makeConst(4,0x7777),0);
    fd.opInsertEnd(cdOp,b_def2);
    f.nameVn(cd,"cd");
    PcodeOp *altOp = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(altOp,CPUI_BRANCHIND);
    Varnode *altv = fd.newVarnode(4,Address(f.unique,0x860));
    fd.opSetInput(altOp,altv,0);
    fd.opInsertEnd(altOp,b_alt);
  }

  PcodeOp *cq = fd.newOp(1,f.allocPc());
  fd.opSetOpcode(cq,CPUI_COPY);
  Varnode *q = f.makeOut(4,f.unique,0x808,cq);
  fd.opSetInput(cq,x,0);
  fd.opInsertEnd(cq,b_g2);
  f.nameVn(q,"q");
  PcodeOp *lt2 = f.makeOp2(b_g2,CPUI_INT_LESS,q,f.makeConst(4,10),0x818,1);
  Varnode *g2b = lt2->getOut(); f.nameVn(g2b,"g2b");
  f.makeCbranch(b_g2,g2b);

  PcodeOp *zOp = f.makeOp2(b_calc,CPUI_INT_AND,f.makeConst(4,0xfff),f.makeConst(4,0xff),0x830,4);
  Varnode *z = zOp->getOut(); f.nameVn(z,"z");
  PcodeOp *cz2 = fd.newOp(1,f.allocPc());
  fd.opSetOpcode(cz2,CPUI_COPY);
  Varnode *z2 = f.makeOut(4,f.unique,0x838,cz2);
  fd.opSetInput(cz2,z,0);
  fd.opInsertEnd(cz2,b_calc);
  f.nameVn(z2,"z2");
  PcodeOp *eq1 = f.makeOp2(b_calc,CPUI_INT_EQUAL,z2,f.makeConst(4,0x30),0x840,1);
  Varnode *g1b = eq1->getOut(); f.nameVn(g1b,"g1b");
  f.makeCbranch(b_calc,g1b);

  PcodeOp *meOp = fd.newOp(2,f.allocPc());
  fd.opSetOpcode(meOp,CPUI_MULTIEQUAL);
  Varnode *me = f.makeOut(4,f.unique,0x850,meOp);
  if (sameSib) {
    fd.opSetInput(meOp,cd,0);   // rides the b_g2 -> b_sw edge (in-edge 0)
    fd.opSetInput(meOp,z,1);    // rides the b_calc -> b_sw edge (in-edge 1)
  } else {
    fd.opSetInput(meOp,z,0);    // b_sw in-edges: [b_calc, b_def2]
    fd.opSetInput(meOp,cd,1);
  }
  fd.opInsertBegin(meOp,b_sw);
  f.nameVn(me,"me");
  PcodeOp *indOp = fd.newOp(1,f.allocPc());
  fd.opSetOpcode(indOp,CPUI_BRANCHIND);
  fd.opSetInput(indOp,me,0);
  fd.opInsertEnd(indOp,b_sw);

  fd.calcNZMask();

  JumpTable jt(&archGlb,indOp->getAddr());
  jt.setIndirectOp(indOp);
  try {
    jt.recoverAddresses(&fd);
    dumpStage(id,"stage1",jt,f);
    cout << "topo|id=" << id << "|swSizeIn=" << b_sw->sizeIn()
         << "|g2Out0=" << f.name(b_g2->getOut(0)) << '\n';
    jt.matchModel(&fd);
    dumpStage(id,"match",jt,f);
    jt.recoverLabels(&fd);
    dumpTail(id,jt);
    bool folded = jt.foldInGuards(&fd);
    cout << "fold|id=" << id << "|ret=" << (folded?1:0)
         << "|defaultBlock=" << jt.getDefaultBlock()
         << "|numEntries=" << jt.numEntries() << '\n';
  }
  catch(LowlevelError &err) {
    cout << "exception|id=" << id << "|" << err.explain << '\n';
  }
}

} // namespace

int main(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  try {
    FixtureArchitecture archGlb;
    runM1(archGlb);
    runP(archGlb,true);
    runP(archGlb,false);
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
