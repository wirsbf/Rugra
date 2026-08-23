/*
 * HERITAGE-FREE-SSA-FIXTURE-0001
 *
 * Locked Ghidra 12.0.4 behavior fixture for the free-Varnode boundary shared
 * by Heritage::collect/placeMultiequals/renameRecurse/rename and
 * Varnode::addDescend.  Every PcodeOp inspected for ordering is inserted in a
 * BlockBasic first; the fixture never compares detached/uninitialised SeqNum
 * ordering.  Pointer values are normalized only to first-seen alias ids.  The
 * traversal order, slot order and alias relations are otherwise preserved.
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

// Funcdata's private prefix is unlabeled.  This locked-layout observation shim
// reaches only Heritage::buildInfoList(), the startProcessing step at
// funcdata.cc:166 that a synthetic Funcdata cannot otherwise invoke.
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
  VarnodeData dummyRegister;
public:
  FixtureTranslate(void) {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false,
                              8, 1, 1, AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this, this, "stack", 5, 8,
                                                ram, 1, true);
    insertSpace(stack);
    VarnodeData stackPointer;
    stackPointer.space = reg;
    stackPointer.offset = 0;
    stackPointer.size = 8;
    addSpacebasePointer(stack, stackPointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false,
                              8, 1, 6, AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummyRegister.space = reg;
    dummyRegister.offset = 0;
    dummyRegister.size = 8;
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummyRegister; }
  string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
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
  FixtureArchitecture(void) {
    FixtureTranslate *trans = new FixtureTranslate();
    translate = trans;
    copySpaces(trans);
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

static const char *opcodeName(OpCode opc)
{
  switch(opc) {
  case CPUI_COPY: return "COPY";
  case CPUI_INT_ADD: return "INT_ADD";
  case CPUI_INT_OR: return "INT_OR";
  case CPUI_INDIRECT: return "INDIRECT";
  case CPUI_MULTIEQUAL: return "MULTIEQUAL";
  default: return "OTHER";
  }
}

static size_t descendCount(const Varnode *vn)
{
  return (size_t)distance(vn->beginDescend(),vn->endDescend());
}

class Graph {
  map<const Varnode *,int4> aliases;
  int4 nextAlias;
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  uintb nextPc;
  map<PcodeOp *,string> opNames;
  map<BlockBasic *,string> blockNames;

  Graph(FixtureArchitecture &a,const string &name,uintb base)
    : nextAlias(0),
      fd(name,name,a.symboltab->getGlobalScope(),Address(a.getSpace(3),base),
         (FunctionSymbol *)0,0x40),
      arch(a),ram(a.getSpace(3)),reg(a.getSpace(4)),nextPc(base) {}

  BlockBasic *block(const string &name) {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *result = blocks.newBlockBasic(&fd);
    blockNames[result] = name;
    return result;
  }
  void edge(BlockBasic *from,BlockBasic *to) {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.addEdge(from,to);
  }
  PcodeOp *op(const string &name,OpCode opc,int4 inputs) {
    PcodeOp *result = fd.newOp(inputs,Address(ram,nextPc++));
    fd.opSetOpcode(result,opc);
    opNames[result] = name;
    return result;
  }
  Varnode *constant(int4 size,uintb value) { return fd.newConstant(size,value); }
  Varnode *freeReg(uintb offset,int4 size) {
    return fd.newVarnode(size,Address(reg,offset));
  }
  Varnode *regOut(PcodeOp *op,uintb offset,int4 size) {
    fd.opSetOutput(op,fd.newVarnode(size,Address(reg,offset)));
    return op->getOut();
  }
  Varnode *uniqueOut(PcodeOp *op,int4 size) { return fd.newUniqueOut(size,op); }
  void input(PcodeOp *op,Varnode *vn,int4 slot) { fd.opSetInput(op,vn,slot); }
  void append(PcodeOp *op,BlockBasic *bl) { fd.opInsertEnd(op,bl); }
  void prepare(void) {
    vector<FlowBlock *> roots;
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.structureLoops(roots);
    blocks.calcForwardDominator(roots);
    heritageOf(fd).buildInfoList();
  }
  string opName(const PcodeOp *op) const {
    map<PcodeOp *,string>::const_iterator iter = opNames.find(const_cast<PcodeOp *>(op));
    if (iter != opNames.end()) return iter->second;
    if (op != (const PcodeOp *)0 && op->code() == CPUI_MULTIEQUAL) return "phi";
    return "unknown";
  }
  string blockName(const FlowBlock *bl) const {
    map<BlockBasic *,string>::const_iterator iter =
      blockNames.find((BlockBasic *)const_cast<FlowBlock *>(bl));
    return iter == blockNames.end() ? "unknown" : iter->second;
  }
  int4 alias(const Varnode *vn) {
    map<const Varnode *,int4>::iterator iter = aliases.find(vn);
    if (iter != aliases.end()) return iter->second;
    int4 id = nextAlias++;
    aliases[vn] = id;
    return id;
  }
  string vnState(const Varnode *vn) {
    if (vn == (const Varnode *)0) return "null";
    ostringstream out;
    out << 'a' << alias(vn) << ':';
    AddrSpace *spc = vn->getSpace();
    if (vn->isConstant())
      out << 'C' << vn->getSize() << ':' << hex << vn->getOffset() << dec;
    else if (spc->getName() == "register")
      out << 'R' << hex << vn->getOffset() << dec << ':' << vn->getSize();
    else if (spc->getType() == IPTR_INTERNAL)
      out << 'U' << vn->getSize();
    else if (spc->getType() == IPTR_IOP)
      out << "IOP" << vn->getSize();
    else
      out << spc->getName() << ':' << hex << vn->getOffset() << dec << ':' << vn->getSize();
    char cls = vn->isConstant() ? 'C' : (vn->isAnnotation() ? 'A' :
      (vn->isInput() ? 'I' : (vn->isWritten() ? 'W' : 'F')));
    out << ':' << cls << ":d" << descendCount(vn)
        << ":f" << hex << vn->getFlags() << dec
        << ":act" << (vn->isActiveHeritage() ? 1 : 0)
        << ":known" << (vn->isHeritageKnown() ? 1 : 0)
        << ":def" << (vn->isWritten() ? opName(vn->getDef()) : "-");
    return out.str();
  }
  string order(void) {
    ostringstream out;
    const BlockGraph &blocks = fd.getBasicBlocks();
    for(int4 i=0;i<blocks.getSize();++i) {
      if (i != 0) out << ';';
      const BlockBasic *bl = (const BlockBasic *)blocks.getBlock(i);
      out << blockName(bl) << '#' << bl->getIndex() << "=[";
      bool firstOp = true;
      for(list<PcodeOp *>::const_iterator iter=bl->beginOp();iter!=bl->endOp();++iter) {
        PcodeOp *cur = *iter;
        if (!firstOp) out << ',';
        firstOp = false;
        out << opName(cur) << '.' << opcodeName(cur->code()) << "{out="
            << vnState(cur->getOut());
        for(int4 slot=0;slot<cur->numInput();++slot)
          out << ",s" << slot << '=' << vnState(cur->getIn(slot));
        out << '}';
      }
      out << ']';
    }
    return out.str();
  }
  bool inBank(const Varnode *needle) const {
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter)
      if (*iter == needle) return true;
    return false;
  }
  int4 freeWithReader(void) const {
    int4 count = 0;
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter) {
      const Varnode *vn = *iter;
      if (!vn->isConstant() && !vn->isAnnotation() && vn->isFree() && !vn->hasNoDescend())
        count += 1;
    }
    return count;
  }
};

static string beforeState(const Varnode *vn)
{
  ostringstream out;
  out << "free=" << (vn->isFree() ? 1 : 0)
      << ",desc=" << descendCount(vn)
      << ",flags=" << hex << vn->getFlags() << dec
      << ",active=" << (vn->isActiveHeritage() ? 1 : 0)
      << ",known=" << (vn->isHeritageKnown() ? 1 : 0)
      << ",def=" << (vn->getDef() == (PcodeOp *)0 ? "none" : "set");
  return out.str();
}

int main(void)
{
  std::cout << std::unitbuf;
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  FixtureArchitecture arch;
  std::cout << "schema=1|fixture=HERITAGE-FREE-SSA-FIXTURE-0001|oracle="
            << "e40ed13014025f82488b1f8f7bca566894ac376b" << std::endl;

  // Empty rename stack: the one free read is replaced with a new formal input.
  {
    Graph g(arch,"single_free_promotion",0x6100);
    BlockBasic *entry = g.block("entry");
    PcodeOp *read = g.op("read",CPUI_COPY,1);
    Varnode *oldFree = g.freeReg(0x100,8);
    g.input(read,oldFree,0);
    g.uniqueOut(read,8);
    g.append(read,entry);
    string pre = beforeState(oldFree);
    g.prepare();
    g.fd.opHeritage();
    Varnode *promoted = read->getIn(0);
    std::cout << "case=single_free_promotion|pre=" << pre
         << "|pass=" << g.fd.getHeritagePass()
         << "|old_bank=" << (g.inBank(oldFree) ? 1 : 0)
         << "|new=" << g.vnState(promoted)
         << "|new_is_old=" << (promoted == oldFree ? 1 : 0)
         << "|free_with_reader=" << g.freeWithReader()
              << "|order=" << g.order() << std::endl;
  }

  // Varnode::addDescend must throw before changing the free Varnode when a
  // second reader is installed.  Both ops are already alive in a block.
  {
    Graph g(arch,"double_descendant",0x6200);
    BlockBasic *entry = g.block("entry");
    PcodeOp *first = g.op("first",CPUI_COPY,1);
    PcodeOp *second = g.op("second",CPUI_COPY,1);
    g.append(first,entry);
    g.append(second,entry);
    Varnode *freeVn = g.freeReg(0x110,8);
    g.input(first,freeVn,0);
    string pre = beforeState(freeVn);
    string error = "none";
    try {
      g.input(second,freeVn,0);
    }
    catch(const LowlevelError &err) {
      error = err.explain;
    }
    std::cout << "case=double_descendant_error|pre=" << pre
         << "|error=" << error
         << "|post=" << beforeState(freeVn)
         << "|first_alias=" << (first->getIn(0) == freeVn ? 1 : 0)
         << "|second_null=" << (second->getIn(0) == (Varnode *)0 ? 1 : 0)
         << "|bank=" << (g.inBank(freeVn) ? 1 : 0)
              << "|order=" << g.order() << std::endl;
  }

  // If an INDIRECT output is the current stack top and its IOP points at the
  // op being renamed, the target reads the value below it: both ops happen at
  // the same time (heritage.cc:2506-2517).
  {
    Graph g(arch,"indirect_simultaneous",0x6300);
    BlockBasic *entry = g.block("entry");
    PcodeOp *prior = g.op("prior",CPUI_COPY,1);
    g.input(prior,g.constant(8,0x21),0);
    Varnode *priorOut = g.regOut(prior,0x120,8);
    g.append(prior,entry);
    PcodeOp *target = g.op("target",CPUI_INT_ADD,2);
    Varnode *oldFree = g.freeReg(0x120,8);
    g.input(target,oldFree,0);
    g.input(target,g.constant(8,0x22),1);
    g.uniqueOut(target,8);
    PcodeOp *ind = g.op("ind",CPUI_INDIRECT,2);
    g.input(ind,priorOut,0);
    g.input(ind,g.fd.newVarnodeIop(target),1);
    Varnode *indOut = g.regOut(ind,0x120,8);
    g.append(ind,entry);
    g.append(target,entry);
    string pre = beforeState(oldFree);
    g.prepare();
    g.fd.opHeritage();
    Varnode *targetIn = target->getIn(0);
    std::cout << "case=indirect_simultaneous|pre=" << pre
         << "|pass=" << g.fd.getHeritagePass()
         << "|old_bank=" << (g.inBank(oldFree) ? 1 : 0)
         << "|target_in=" << g.vnState(targetIn)
         << "|alias_prior=" << (targetIn == priorOut ? 1 : 0)
         << "|alias_indirect=" << (targetIn == indOut ? 1 : 0)
         << "|prior_desc=" << descendCount(priorOut)
         << "|ind_desc=" << descendCount(indOut)
         << "|free_with_reader=" << g.freeWithReader()
              << "|order=" << g.order() << std::endl;
  }

  // Natural loop SSA: placeMultiequals creates a loop-header phi and
  // renameRecurse fills each slot through the predecessor edge's reverse
  // index.  The slot sequence is emitted without sorting.
  {
    Graph g(arch,"loop_phi_reverse_slot",0x6400);
    BlockBasic *entry = g.block("entry");
    BlockBasic *header = g.block("header");
    BlockBasic *body = g.block("body");
    BlockBasic *exit = g.block("exit");
    g.edge(entry,header);
    g.edge(header,body);
    g.edge(header,exit);
    g.edge(body,header);
    PcodeOp *init = g.op("init",CPUI_COPY,1);
    g.input(init,g.constant(8,1),0);
    Varnode *initOut = g.regOut(init,0x130,8);
    g.append(init,entry);
    vector<Varnode *> oldReads;
    PcodeOp *headRead = g.op("head_read",CPUI_INT_OR,2);
    oldReads.push_back(g.freeReg(0x130,8));
    g.input(headRead,oldReads.back(),0);
    g.input(headRead,g.constant(8,2),1);
    g.uniqueOut(headRead,8);
    g.append(headRead,header);
    PcodeOp *step = g.op("step",CPUI_INT_ADD,2);
    oldReads.push_back(g.freeReg(0x130,8));
    g.input(step,oldReads.back(),0);
    g.input(step,g.constant(8,3),1);
    Varnode *stepOut = g.regOut(step,0x130,8);
    g.append(step,body);
    PcodeOp *exitRead = g.op("exit_read",CPUI_COPY,1);
    oldReads.push_back(g.freeReg(0x130,8));
    g.input(exitRead,oldReads.back(),0);
    g.uniqueOut(exitRead,8);
    g.append(exitRead,exit);
    ostringstream pre;
    for(size_t i=0;i<oldReads.size();++i) {
      if (i != 0) pre << ';';
      pre << 'r' << i << '{' << beforeState(oldReads[i]) << '}';
    }
    g.prepare();
    g.fd.opHeritage();
    PcodeOp *phi = (PcodeOp *)0;
    for(list<PcodeOp *>::const_iterator iter=header->beginOp();iter!=header->endOp();++iter) {
      if ((*iter)->code() == CPUI_MULTIEQUAL) { phi = *iter; break; }
    }
    ostringstream slots;
    if (phi != (PcodeOp *)0) {
      for(int4 slot=0;slot<phi->numInput();++slot) {
        if (slot != 0) slots << ';';
        const FlowBlock *pred = header->getIn(slot);
        Varnode *in = phi->getIn(slot);
        slots << 's' << slot << "<pred=" << g.blockName(pred)
              << ",in=" << g.vnState(in)
              << ",is_init=" << (in == initOut ? 1 : 0)
              << ",is_step=" << (in == stepOut ? 1 : 0) << '>';
      }
    }
    int4 removed = 0;
    for(size_t i=0;i<oldReads.size();++i)
      if (!g.inBank(oldReads[i])) removed += 1;
    std::cout << "case=loop_phi_reverse_slot|pre=" << pre.str()
         << "|pass=" << g.fd.getHeritagePass()
         << "|phi=" << (phi == (PcodeOp *)0 ? 0 : 1)
         << "|slots=" << slots.str()
         << "|head_alias_phi=" << (phi != (PcodeOp *)0 && headRead->getIn(0) == phi->getOut() ? 1 : 0)
         << "|body_alias_phi=" << (phi != (PcodeOp *)0 && step->getIn(0) == phi->getOut() ? 1 : 0)
         << "|exit_alias_phi=" << (phi != (PcodeOp *)0 && exitRead->getIn(0) == phi->getOut() ? 1 : 0)
         << "|old_removed=" << removed << '/' << oldReads.size()
         << "|free_with_reader=" << g.freeWithReader()
              << "|order=" << g.order() << std::endl;
  }
  return 0;
}
