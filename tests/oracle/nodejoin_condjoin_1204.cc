/*
 * NODEJOIN-F2/F3/F4/F5: locked Ghidra 12.0.4 ConditionalJoin behavior
 * oracle (blockaction.cc:1912-2102, 2326-2364).
 *
 * Drives the production ActionNodeJoin::apply over synthetic diamond CFGs
 * and prints a structural projection of the result: the action's change
 * count, the reordered block list (indices, in/out neighbor indices, and
 * each block's ops with structural varnode descriptors).  Fixture varnodes
 * carry stable labels; join-created outputs are described by their defining
 * op's (block, position); constants by offset.
 *
 * Cases:
 *   A_samecond    two CBRANCH blocks, identical condition Varnode (F3:
 *                 findDups cc:1926-1927 is a COMPLETE match -> full join)
 *   B_mergeable   identical INT_LESS conditions + exit MULTIEQUAL merging
 *                 v1/v2 (F2: checkExitBlock/setupMultiequals/moveCbranch/
 *                 cutDownMultiequals all observable)
 *   C_flip        booleanFlip on cbranch1 (F4 gate cc:1920)
 *   D_unwritten   distinct constant conditions (F4 gate cc:1930)
 *   E_spacebase   spacebase flag on cond1 (F4 gate cc:1932)
 *   F_fel2        INT_ADD(r1,r2) vs INT_ADD(r3,r4) distinct written inputs
 *                 (F4 gate cc:1938, functionalEqualityLevel==2)
 *   G_subpiece    identical SUBPIECE defs (F4 gate cc:1940)
 *   H_copy        identical COPY defs (F4 gate cc:1941)
 *   I_triple      three same-condition diamonds (F5: dynamic graph.getSize
 *                 bound cc:2334 — the join block rejoins)
 */
#include <cstdio>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#define private public
#define protected public
#include "architecture.hh"
#include "blockaction.hh"
#include "coreaction.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#undef private
#undef protected

using namespace ghidra;
using std::map;
using std::string;
using std::vector;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;
public:
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
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack,stack_pointer,8,true);
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"join",false,8,1,6,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new IopSpace(this,this,7));
    setDefaultCodeSpace(3);
    dummy_register.space = reg;
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummy_register; }
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
    types->setCoreType("xunknown1",1,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown2",2,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown4",4,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown8",8,TYPE_UNKNOWN,false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst,types,translate);
    symboltab = new Database(this,false);
    symboltab->attachScope(new ScopeInternal(0x101,"",this),(Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }
  void printMessage(const string &message) const override {
    std::cerr << message << '\n';
  }
};

struct Fixture {
  FixtureArchitecture *arch;
  Funcdata *fd;
  BlockGraph *graph;
  AddrSpace *ram;
  map<Varnode *,string> labels;   // fixture-created varnodes
  map<PcodeOp *,string> oplabels; // fixture-created ops (defs of labeled vns)

  BlockBasic *mkBlock(uintb off) {
    BlockBasic *b = graph->newBlockBasic(fd);
    return b;
  }
  Varnode *mkConst(int4 sz,uintb val) { return fd->newConstant(sz,val); }
  // Written varnode defined by opcode(inputs...) inserted at end of blk.
  Varnode *mkWritten(const string &label, OpCode opc, vector<Varnode *> ins,
                     BlockBasic *blk, uintb opoff) {
    PcodeOp *op = fd->newOp(ins.size(),Address(ram,opoff));
    fd->opSetOpcode(op,opc);
    Varnode *out = fd->newUniqueOut(8,op);
    for(int4 i=0;i<ins.size();++i) fd->opSetInput(op,ins[i],i);
    fd->opInsertEnd(op,blk);
    labels[out] = label;
    return out;
  }
  // Unwritten varnode at a ram address (address-tied).
  Varnode *mkAddr(const string &label, uintb off) {
    Varnode *vn = fd->newVarnode(8,Address(ram,off));
    labels[vn] = label;
    return vn;
  }
  PcodeOp *mkCbranch(BlockBasic *blk, Varnode *cond, uintb opoff,
                     bool flip) {
    PcodeOp *cb = fd->newOp(2,Address(ram,opoff));
    fd->opSetOpcode(cb,CPUI_CBRANCH);
    fd->opSetInput(cb,mkConst(8,0x3000),0);
    fd->opSetInput(cb,cond,1);
    if (flip) cb->setFlag(PcodeOp::boolean_flip);
    fd->opInsertEnd(cb,blk);
    return cb;
  }
  // Build a diamond: b1 = [def1?, cbranch(cond1)], b2 = [def2?, cbranch(cond2)],
  // exita = [MULTIEQUAL(v1,v2)?, INT_ADD stop?], exitb = [].
  struct DefSpec {
    bool present;
    OpCode opc;
    vector<Varnode *> ins;
    string outlabel;
  };
  void diamond(const DefSpec &def1, Varnode *cond1, bool flip1,
               const DefSpec &def2, Varnode *cond2, bool flip2,
               const DefSpec &vdef1, const DefSpec &vdef2) {
    BlockBasic *b1 = mkBlock(0x1000);
    BlockBasic *b2 = mkBlock(0x2000);
    BlockBasic *exita = mkBlock(0x3000);
    BlockBasic *exitb = mkBlock(0x4000);
    if (def1.present) {
      Varnode *out = mkWritten(def1.outlabel,def1.opc,def1.ins,b1,0x1100);
      if (cond1 == (Varnode *)0) cond1 = out;
    }
    if (def2.present) {
      Varnode *out = mkWritten(def2.outlabel,def2.opc,def2.ins,b2,0x2100);
      if (cond2 == (Varnode *)0) cond2 = out;
    }
    Varnode *v1 = (Varnode *)0;
    Varnode *v2 = (Varnode *)0;
    if (vdef1.present) v1 = mkWritten(vdef1.outlabel,vdef1.opc,vdef1.ins,b1,0x1110);
    if (vdef2.present) v2 = mkWritten(vdef2.outlabel,vdef2.opc,vdef2.ins,b2,0x2110);
    mkCbranch(b1,cond1,0x1010,flip1);
    mkCbranch(b2,cond2,0x2010,flip2);
    if (v1 != (Varnode *)0) {
      PcodeOp *me = fd->newOp(2,Address(ram,0x3010));
      fd->opSetOpcode(me,CPUI_MULTIEQUAL);
      fd->opSetInput(me,v1,0);
      fd->opSetInput(me,v2,1);
      fd->opInsertEnd(me,exita);
      PcodeOp *stop = fd->newOp(2,Address(ram,0x3020));
      fd->opSetOpcode(stop,CPUI_INT_ADD);
      fd->opSetInput(stop,mkConst(8,1),0);
      fd->opSetInput(stop,mkConst(8,2),1);
      fd->opInsertEnd(stop,exita);
    }
    graph->addEdge(b1,exita);
    graph->addEdge(b1,exitb);
    graph->addEdge(b2,exita);
    graph->addEdge(b2,exitb);
  }
  DefSpec nodef() { DefSpec d; d.present=false; d.opc=CPUI_COPY; return d; }
  DefSpec def(OpCode opc, vector<Varnode *> ins, const string &label) {
    DefSpec d; d.present=true; d.opc=opc; d.ins=ins; d.outlabel=label; return d;
  }

  string vdesc(Varnode *vn) {
    if (vn == (Varnode *)0) return "<null>";
    map<Varnode *,string>::iterator iter = labels.find(vn);
    if (iter != labels.end()) return iter->second;
    if (vn->isConstant()) {
      std::ostringstream s;
      s << "const:0x" << std::hex << vn->getOffset() << std::dec
        << ':' << vn->getSize();
      return s.str();
    }
    PcodeOp *def = vn->getDef();
    if (def != (PcodeOp *)0) {
      BlockBasic *par = (BlockBasic *)def->getParent();
      if (par != (BlockBasic *)0) {
        const BlockGraph &bg = fd->getBasicBlocks();
        int4 bpos = -1;
        for(int4 i=0;i<bg.getSize();++i)
          if (bg.getBlock(i) == par) { bpos = i; break; }
        int4 opos = 0;
        list<PcodeOp *>::const_iterator oiter,oend;
        for(oiter=par->beginOp(),oend=par->endOp();oiter!=oend;++oiter,++opos)
          if (*oiter == def) break;
        std::ostringstream s;
        s << "def:B" << bpos << ':' << opos;
        return s.str();
      }
      return "def:dead";
    }
    std::ostringstream s;
    s << "vn:0x" << std::hex << vn->getOffset() << std::dec << ':' << vn->getSize();
    return s.str();
  }

  void print(const string &name, ActionNodeJoin &ajoin) {
    const BlockGraph &bg = fd->getBasicBlocks();
    std::cout << "== case " << name << '\n';
    std::cout << "count=" << ajoin.count << '\n';
    std::cout << "blocks=" << bg.getSize() << '\n';
    for(int4 i=0;i<bg.getSize();++i) {
      FlowBlock *bl = bg.getBlock(i);
      std::cout << "block " << i << ": in=[";
      for(int4 e=0;e<bl->sizeIn();++e) {
        if (e) std::cout << ',';
        // Positional neighbor identity: FlowBlock::index is only assigned
        // by findSpanningTree, so pre-join blocks would all print 0.
        int4 npos = -1;
        for(int4 j=0;j<bg.getSize();++j)
          if (bg.getBlock(j) == bl->getIn(e)) { npos = j; break; }
        std::cout << npos;
      }
      std::cout << "] out=[";
      for(int4 e=0;e<bl->sizeOut();++e) {
        if (e) std::cout << ',';
        int4 npos = -1;
        for(int4 j=0;j<bg.getSize();++j)
          if (bg.getBlock(j) == bl->getOut(e)) { npos = j; break; }
        std::cout << npos;
      }
      std::cout << "] ops=[";
      BlockBasic *bb = (BlockBasic *)bl;
      int4 opos = 0;
      list<PcodeOp *>::const_iterator oiter,oend;
      for(oiter=bb->beginOp(),oend=bb->endOp();oiter!=oend;++oiter,++opos) {
        if (opos) std::cout << ';';
        PcodeOp *op = *oiter;
        std::cout << get_opname(op->code()) << '(';
        for(int4 s=0;s<op->numInput();++s) {
          if (s) std::cout << ',';
          std::cout << vdesc(op->getIn(s));
        }
        std::cout << ')';
        if (op->getOut() != (Varnode *)0)
          std::cout << "->" << vdesc(op->getOut());
      }
      std::cout << "]\n";
    }
  }
};

Fixture *newFixture(const string &name) {
  Fixture *f = new Fixture();
  f->arch = new FixtureArchitecture();
  f->fd = new Funcdata(name,name,f->arch->symboltab->getGlobalScope(),
                       Address(f->arch->getSpace(3),0x5000),(FunctionSymbol *)0,0x40);
  f->graph = &const_cast<BlockGraph &>(f->fd->getBasicBlocks());
  f->ram = f->arch->getSpace(3);
  return f;
}

void runCase(const string &name) {
  Fixture *f = newFixture(name);
  Fixture &fx = *f;
  AddrSpace *ram = fx.ram;
  Funcdata &fd = *fx.fd;

  if (name == "A_samecond") {
    BlockBasic *pre = fx.mkBlock(0x0800);
    Varnode *k1 = fd.newConstant(8,1);
    Varnode *k2 = fd.newConstant(8,2);
    Varnode *cond = fx.mkWritten("cond",CPUI_INT_LESS,{k1,k2},pre,0x0810);
    fx.diamond(fx.nodef(),cond,false,fx.nodef(),cond,false,
               fx.nodef(),fx.nodef());
  } else if (name == "B_mergeable") {
    Varnode *k1 = fd.newConstant(8,1);
    Varnode *k2 = fd.newConstant(8,2);
    Varnode *c7 = fd.newConstant(8,7);
    Varnode *c8 = fd.newConstant(8,8);
    fx.diamond(fx.def(CPUI_INT_LESS,{k1,k2},"cond1"),(Varnode *)0,false,
               fx.def(CPUI_INT_LESS,{k1,k2},"cond2"),(Varnode *)0,false,
               fx.def(CPUI_COPY,{c7},"v1"),fx.def(CPUI_COPY,{c8},"v2"));
  } else if (name == "C_flip") {
    Varnode *k1 = fd.newConstant(8,1);
    Varnode *k2 = fd.newConstant(8,2);
    BlockBasic *b1v = fx.mkBlock(0x1000);
    BlockBasic *b2v = fx.mkBlock(0x2000);
    Varnode *cond1 = fx.mkWritten("cond1",CPUI_INT_LESS,{k1,k2},b1v,0x1100);
    Varnode *cond2 = fx.mkWritten("cond2",CPUI_INT_LESS,{k1,k2},b2v,0x2100);
    fx.diamond(fx.nodef(),cond1,true,fx.nodef(),cond2,false,
               fx.nodef(),fx.nodef());
  } else if (name == "D_unwritten") {
    Varnode *c1 = fd.newConstant(8,11);
    Varnode *c2 = fd.newConstant(8,22);
    fx.diamond(fx.nodef(),c1,false,fx.nodef(),c2,false,
               fx.nodef(),fx.nodef());
  } else if (name == "E_spacebase") {
    Varnode *k1 = fd.newConstant(8,1);
    Varnode *k2 = fd.newConstant(8,2);
    BlockBasic *b1v = fx.mkBlock(0x1000);
    BlockBasic *b2v = fx.mkBlock(0x2000);
    Varnode *cond1 = fx.mkWritten("cond1",CPUI_INT_LESS,{k1,k2},b1v,0x1100);
    cond1->setFlags(Varnode::spacebase);
    Varnode *cond2 = fx.mkWritten("cond2",CPUI_INT_LESS,{k1,k2},b2v,0x2100);
    fx.diamond(fx.nodef(),cond1,false,fx.nodef(),cond2,false,
               fx.nodef(),fx.nodef());
  } else if (name == "F_fel2") {
    BlockBasic *pre = fx.mkBlock(0x0800);
    Varnode *r1 = fx.mkWritten("r1",CPUI_INT_NEGATE,{fd.newConstant(8,1)},pre,0x0810);
    Varnode *r2 = fx.mkWritten("r2",CPUI_INT_NEGATE,{fd.newConstant(8,2)},pre,0x0820);
    Varnode *r3 = fx.mkWritten("r3",CPUI_INT_NEGATE,{fd.newConstant(8,3)},pre,0x0830);
    Varnode *r4 = fx.mkWritten("r4",CPUI_INT_NEGATE,{fd.newConstant(8,4)},pre,0x0840);
    fx.diamond(fx.def(CPUI_INT_ADD,{r1,r2},"cond1"),(Varnode *)0,false,
               fx.def(CPUI_INT_ADD,{r3,r4},"cond2"),(Varnode *)0,false,
               fx.nodef(),fx.nodef());
  } else if (name == "G_subpiece" || name == "H_copy") {
    Varnode *x = fd.newConstant(8,5);
    OpCode opc = (name == "G_subpiece") ? CPUI_SUBPIECE : CPUI_COPY;
    // SUBPIECE takes (x, const 0); COPY takes (x). A 0-input COPY would
    // drive Ghidra's functionalEqualityLevel off uninitialized stack slots
    // (res1[0]/res2[0] are read unconditionally) — not a reachable
    // production shape, so the fixture uses realistic arities.
    vector<Varnode *> ins;
    vector<Varnode *> ins2;
    ins.push_back(x);
    ins2.push_back(x);
    if (opc == CPUI_SUBPIECE) {
      ins.push_back(fd.newConstant(8,0));
      ins2.push_back(fd.newConstant(8,0));
    }
    fx.diamond(fx.def(opc,ins,"cond1"),(Varnode *)0,false,
               fx.def(opc,ins2,"cond2"),(Varnode *)0,false,
               fx.nodef(),fx.nodef());
  } else if (name == "I_triple") {
    BlockBasic *pre = fx.mkBlock(0x0800);
    Varnode *k1 = fd.newConstant(8,1);
    Varnode *k2 = fd.newConstant(8,2);
    Varnode *cond = fx.mkWritten("cond",CPUI_INT_LESS,{k1,k2},pre,0x0810);
    BlockBasic *b1 = fx.mkBlock(0x1000);
    BlockBasic *b2 = fx.mkBlock(0x2000);
    BlockBasic *b3 = fx.mkBlock(0x2800);
    BlockBasic *exita = fx.mkBlock(0x3000);
    BlockBasic *exitb = fx.mkBlock(0x4000);
    fx.mkCbranch(b1,cond,0x1010,false);
    fx.mkCbranch(b2,cond,0x2010,false);
    fx.mkCbranch(b3,cond,0x2810,false);
    fx.graph->addEdge(b1,exita);
    fx.graph->addEdge(b1,exitb);
    fx.graph->addEdge(b2,exita);
    fx.graph->addEdge(b2,exitb);
    fx.graph->addEdge(b3,exita);
    fx.graph->addEdge(b3,exitb);
  } else {
    std::cerr << "unknown case " << name << '\n';
    return;
  }

  ActionNodeJoin ajoin("fixture");
  ajoin.perform(fd);
  fx.print(name,ajoin);
}

} // namespace

int main(int argc,char **argv) {
  vector<string> spec_paths;
  startDecompilerLibrary(spec_paths);
  vector<string> cases;
  if (argc > 1) {
    for(int4 i=1;i<argc;++i) cases.push_back(argv[i]);
  } else {
    const char *all[] = {"A_samecond","B_mergeable","C_flip","D_unwritten",
                         "E_spacebase","F_fel2","G_subpiece","H_copy","I_triple"};
    for(int4 i=0;i<9;++i) cases.push_back(all[i]);
  }
  for(size_t i=0;i<cases.size();++i) {
    try { runCase(cases[i]); }
    catch (const ghidra::LowlevelError &e) {
      std::cout << "== case " << cases[i] << "\nEXC " << e.explain << '\n';
    }
  }
  return 0;
}
