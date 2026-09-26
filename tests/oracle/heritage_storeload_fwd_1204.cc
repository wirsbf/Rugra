/*
 * HERITAGE-STORELOAD-FWD-FIXTURE-0001 (KUNABUGS-STORELOAD-FWD-0001)
 *
 * Locked Ghidra 12.0.4 behavior fixture for the pre-heritage stack
 * store->load forwarding chain (kuna losses LOSS-237 shape):
 *   Heritage::discoverIndexedStackPointers -> generateLoadGuard
 *   (heritage.cc:986-1102/909-917), the guard() addIndirects half
 *   (heritage.cc:1188-1198) -> guardStores INDIRECT insertion
 *   (cc:1538-1559) and guardLoads COPY-guard insertion (cc:1570-1601),
 *   renaming of the COPY-guard input to the traced stack version
 *   (cc:2489-2561), then analyzeNewLoadGuards (cc:834-900) and
 *   handleNewLoadCopies -> findAddressForces/propagateCopyAway
 *   (cc:619-730) eliminating the guard COPY and address-forcing the
 *   boundary writes inside the analyzed guard window.
 *
 * The stack space carries delay=1 (SpacebaseSpace ctor), so the fixture
 * runs TWO canonical Funcdata::opHeritage passes: pass 0 heritages the
 * register space (the free index varnode is promoted to a formal input),
 * pass 1 performs the stack-space discovery/guard/rename/elimination.
 *
 * The function-local scope is the real construction-path ScopeLocal
 * (funcdata.cc:66-70) with the "fixture" proto model installed before
 * resetLocalWindow, so the local window is the model's default
 * localrange [highest-999999,highest] union paramrange [0,511]; the
 * observed slot stack:0x40 sits inside the param half, so
 * Scope::queryProperties answers mapped|addrtied and the guardLoads
 * addrtied gate opens.  The indexed pointer base is 0x30, so the
 * analyzed guard window [0x30,0x102f] CONTAINS the slot and the
 * handleNewLoadCopies address-force marking is observable on the
 * surviving write varnodes.
 *
 * Cases:
 *   fwd_indexed_load  - full chain: two slot writes, a constant-offset
 *                       STORE (INDIRECT guard), an indexed LOAD (load
 *                       guard COPY placed, renamed to the INDIRECT
 *                       output, then propagated away; last write
 *                       address-forced).
 *   const_load_no_fwd - negative control: the LOAD pointer is a plain
 *                       constant offset (traversals==0), so no load
 *                       guard exists, no COPY is placed, no address
 *                       force lands; the STORE INDIRECT still appears.
 *   phi_fwd           - the slot is written in both arms of a branch
 *                       and read by an indexed LOAD after the join:
 *                       the guard COPY renames to the join MULTIEQUAL
 *                       and both arm writes are address-forced.
 *
 * Normalization: object pointers become deterministic first-seen alias
 * ids; LOAD/STORE space constants print their decoded space name (the
 * oracle encodes the AddrSpace pointer, the comparand a numeric space
 * id); unique-space offsets and raw iop offsets are omitted.  All op
 * order, slot order, flags, descendant counts, alias relations and the
 * guard records are preserved.
 */

#include <bits/stdc++.h>

#define private public
#define protected public
#define class struct
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "fspec.hh"
#include "heritage.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varmap.hh"
#include "varnode.hh"
#undef class
#undef protected
#undef private

using namespace ghidra;

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
    stackPointer.offset = 0x20;	// matches the comparand's canonical RSP
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
  case CPUI_LOAD: return "LOAD";
  case CPUI_STORE: return "STORE";
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
  AddrSpace *stack;
  uintb nextPc;
  map<PcodeOp *,string> opNames;
  map<BlockBasic *,string> blockNames;

  Graph(FixtureArchitecture &a,const string &name,uintb base)
    : nextAlias(0),
      fd(name,name,a.symboltab->getGlobalScope(),Address(a.getSpace(3),base),
         (FunctionSymbol *)0,0x40),
      arch(a),ram(a.getSpace(3)),reg(a.getSpace(4)),stack(a.getSpace(5)),
      nextPc(base) {
    // funcdata.cc:66-70 built the real ScopeLocal with an empty
    // (model-less) window; install the fixture model and rebuild the
    // window exactly as the production pipeline does before any
    // Varnode is created.
    fd.getFuncProto().setModel(arch.protoModels["fixture"]);
    fd.getScopeLocal()->resetLocalWindow();
  }

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
  Varnode *spaceConst(void) {
    // STORE/LOAD input(0) space constant: the AddrSpace pointer encoded
    // as the constant value (varnode.hh:426 getSpaceFromConst).
    return fd.newConstant(8,(uintb)(uintptr_t)stack);
  }
  Varnode *freeReg(uintb offset,int4 size) {
    return fd.newVarnode(size,Address(reg,offset));
  }
  Varnode *spacebaseInput(void) {
    Varnode *sp = fd.newVarnode(8,Address(reg,0x20));
    fd.setInputVarnode(sp);
    return sp;
  }
  Varnode *stackOut(PcodeOp *op,uintb offset,int4 size) {
    return fd.newVarnodeOut(size,Address(stack,offset),op);
  }
  Varnode *uniqueOut(PcodeOp *op,int4 size) { return fd.newUniqueOut(size,op); }
  void input(PcodeOp *op,Varnode *vn,int4 slot) { fd.opSetInput(op,vn,slot); }
  void append(PcodeOp *op,BlockBasic *bl) { fd.opInsertEnd(op,bl); }
  void prepare(void) {
    vector<FlowBlock *> roots;
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.structureLoops(roots);
    blocks.calcForwardDominator(roots);
    fd.heritage.buildInfoList();
  }
  string opName(const PcodeOp *op) const {
    map<PcodeOp *,string>::const_iterator iter = opNames.find(const_cast<PcodeOp *>(op));
    if (iter != opNames.end()) return iter->second;
    if (op != (const PcodeOp *)0 && op->code() == CPUI_MULTIEQUAL) return "phi";
    if (op != (const PcodeOp *)0 && op->code() == CPUI_INDIRECT) return "indirect";
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
  string vnState(const Varnode *vn)
  {
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
  string spaceConstState(const Varnode *vn)
  {
    // The LOAD/STORE space constant: print the DECODED space name so the
    // oracle's AddrSpace-pointer encoding and the comparand's numeric
    // space-id encoding observe identically.
    ostringstream out;
    out << "SPC:" << vn->getSpaceFromConst()->getName();
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
            << (cur->getOut() != (Varnode *)0 ? vnState(cur->getOut()) : string("null"));
        for(int4 slot=0;slot<cur->numInput();++slot) {
          Varnode *invn = cur->getIn(slot);
          if (slot == 0 && (cur->code()==CPUI_LOAD || cur->code()==CPUI_STORE)) {
            out << ",s" << slot << '=' << spaceConstState(invn);
            continue;
          }
          out << ",s" << slot << '=' << vnState(invn);
        }
        out << '}';
      }
      out << ']';
    }
    return out.str();
  }
  string census(void) {
    // Per-space varnode census of the whole bank: written/free/input
    // counts for ram/register/stack/unique/iop/const.  Catches deletions
    // (renamed-away frees, destroyed guard outputs) and promotions.
    static const char *names[] = {"ram","register","stack","unique","iop","const"};
    ostringstream out;
    for(int4 i=0;i<6;++i) {
      if (i != 0) out << ',';
      int4 w=0,f=0,inp=0,c=0;
      for(VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter) {
        const Varnode *vn = *iter;
        if (vn->getSpace()->getName() != names[i]) continue;
        if (vn->isWritten()) w += 1;
        else if (vn->isConstant()) { c += 1; continue; }
        else if (vn->isInput()) inp += 1;
        else if (!vn->isAnnotation()) f += 1;
      }
      out << names[i] << ":W" << w << "/F" << f << "/I" << inp << "/C" << c;
    }
    return out.str();
  }
  string guards(void) {
    ostringstream out;
    bool first = true;
    for(list<LoadGuard>::const_iterator iter=fd.heritage.loadGuard.begin();
        iter!=fd.heritage.loadGuard.end();++iter) {
      const LoadGuard &guard(*iter);
      if (!first) out << ';';
      first = false;
      out << "pb=" << hex << guard.pointerBase << dec
          << ",min=" << hex << guard.minimumOffset << dec
          << ",max=" << hex << guard.maximumOffset << dec
          << ",step=" << guard.step
          << ",st=" << guard.analysisState
          << ",op=" << opName(guard.op);
    }
    return out.str();
  }
  string dumpLine(const string &casename,const string &phase) {
    ostringstream out;
    out << "case=" << casename << "|phase=" << phase
        << "|pass=" << fd.getHeritagePass()
        << "|restart=" << (fd.hasRestartPending() ? 1 : 0)
        << "|guards=" << guards()
        << "|sguards=" << fd.heritage.storeGuard.size()
        << "|copyops=" << fd.heritage.loadCopyOps.size()
        << "|census=" << census()
        << "|order=" << order();
    return out.str();
  }
};

// Case 1: full store->load forwarding chain on stack slot 0x40.
static void case_fwd_indexed_load(FixtureArchitecture &arch)
{
  Graph g(arch,"fwd_indexed_load",0x7100);
  BlockBasic *entry = g.block("entry");
  Varnode *sp = g.spacebaseInput();
  PcodeOp *add0 = g.op("add0",CPUI_INT_ADD,2);	// sp + 0x30
  g.input(add0,sp,0);
  g.input(add0,g.constant(8,0x30),1);
  Varnode *t0 = g.uniqueOut(add0,8);
  PcodeOp *addst = g.op("addst",CPUI_INT_ADD,2);	// sp + 0x40 (STORE ptr)
  g.input(addst,sp,0);
  g.input(addst,g.constant(8,0x40),1);
  Varnode *t1 = g.uniqueOut(addst,8);
  PcodeOp *addidx = g.op("addidx",CPUI_INT_ADD,2);	// (sp+0x30) + idx
  g.input(addidx,t0,0);
  g.input(addidx,g.freeReg(0x100,8),1);
  Varnode *t2 = g.uniqueOut(addidx,8);
  PcodeOp *wA = g.op("wA",CPUI_COPY,1);			// slot write 1
  g.input(wA,g.constant(8,0x21),0);
  Varnode *waOut = g.stackOut(wA,0x40,8);
  PcodeOp *wB = g.op("wB",CPUI_COPY,1);			// slot write 2
  g.input(wB,g.constant(8,0x22),0);
  Varnode *wbOut = g.stackOut(wB,0x40,8);
  PcodeOp *st = g.op("st",CPUI_STORE,3);		// STORE stack slot
  g.input(st,g.spaceConst(),0);
  g.input(st,t1,1);
  g.input(st,g.constant(8,0x31),2);
  PcodeOp *ld = g.op("ld",CPUI_LOAD,2);			// indexed LOAD
  g.input(ld,g.spaceConst(),0);
  g.input(ld,t2,1);
  g.uniqueOut(ld,8);
  g.append(add0,entry);
  g.append(addst,entry);
  g.append(addidx,entry);
  g.append(wA,entry);
  g.append(wB,entry);
  g.append(st,entry);
  g.append(ld,entry);
  std::cout << "case=fwd_indexed_load|phase=pre|order=" << g.order() << std::endl;
  g.prepare();
  g.fd.opHeritage();
  std::cout << g.dumpLine("fwd_indexed_load","p0") << std::endl;
  g.fd.opHeritage();
  std::cout << g.dumpLine("fwd_indexed_load","p1") << std::endl;
  // Post-pass forwarding invariants (observed directly):
  //  - the STORE's INDIRECT input reads the LAST slot write;
  //  - the guard COPY was placed and eliminated (no COPY op before ld);
  //  - the last write is address-forced (inside the analyzed window).
  PcodeOp *indirectOp = (PcodeOp *)0;
  PcodeOp *loadOp = (PcodeOp *)0;
  for(list<PcodeOp *>::const_iterator iter=entry->beginOp();iter!=entry->endOp();++iter) {
    if ((*iter)->code() == CPUI_INDIRECT) indirectOp = *iter;
    if ((*iter)->code() == CPUI_LOAD) loadOp = *iter;
  }
  bool indirectReadsLastWrite = false;
  bool copyAdjacentBeforeLoad = false;
  if (indirectOp != (PcodeOp *)0)
    indirectReadsLastWrite = (indirectOp->getIn(0) == wbOut);
  if (loadOp != (PcodeOp *)0) {
    // The guard COPY is inserted directly before the LOAD and must be
    // propagated away by handleNewLoadCopies: the op immediately
    // preceding the LOAD is the STORE, not a COPY.
    list<PcodeOp *>::iterator iter=entry->beginOp();
    for(;iter!=entry->endOp();++iter) {
      list<PcodeOp *>::iterator next = iter;
      ++next;
      if (next != entry->endOp() && *next == loadOp) {
        copyAdjacentBeforeLoad = ((*iter)->code() == CPUI_COPY);
        break;
      }
    }
  }
  std::cout << "case=fwd_indexed_load|phase=check"
            << "|indirect_in_is_last_write=" << (indirectReadsLastWrite ? 1 : 0)
            << "|copy_adjacent_before_load=" << (copyAdjacentBeforeLoad ? 1 : 0)
            << "|last_write_addrforced=" << (wbOut->isAddrForce() ? 1 : 0)
            << "|first_write_addrforced=" << (waOut->isAddrForce() ? 1 : 0)
            << std::endl;
}

// Case 2: negative control — the LOAD pointer is a constant offset, so
// discoverIndexedStackPointers never creates a load guard and no
// forwarding machinery fires.
static void case_const_load_no_fwd(FixtureArchitecture &arch)
{
  Graph g(arch,"const_load_no_fwd",0x7200);
  BlockBasic *entry = g.block("entry");
  Varnode *sp = g.spacebaseInput();
  PcodeOp *addst = g.op("addst",CPUI_INT_ADD,2);	// sp + 0x40 (STORE ptr)
  g.input(addst,sp,0);
  g.input(addst,g.constant(8,0x40),1);
  Varnode *t1 = g.uniqueOut(addst,8);
  PcodeOp *addc = g.op("addc",CPUI_INT_ADD,2);		// sp + 0x40 (LOAD ptr)
  g.input(addc,sp,0);
  g.input(addc,g.constant(8,0x40),1);
  Varnode *t3 = g.uniqueOut(addc,8);
  PcodeOp *wA = g.op("wA",CPUI_COPY,1);
  g.input(wA,g.constant(8,0x21),0);
  Varnode *waOut = g.stackOut(wA,0x40,8);
  PcodeOp *wB = g.op("wB",CPUI_COPY,1);
  g.input(wB,g.constant(8,0x22),0);
  Varnode *wbOut = g.stackOut(wB,0x40,8);
  PcodeOp *st = g.op("st",CPUI_STORE,3);
  g.input(st,g.spaceConst(),0);
  g.input(st,t1,1);
  g.input(st,g.constant(8,0x31),2);
  PcodeOp *ld = g.op("ld",CPUI_LOAD,2);
  g.input(ld,g.spaceConst(),0);
  g.input(ld,t3,1);
  g.uniqueOut(ld,8);
  g.append(addst,entry);
  g.append(addc,entry);
  g.append(wA,entry);
  g.append(wB,entry);
  g.append(st,entry);
  g.append(ld,entry);
  std::cout << "case=const_load_no_fwd|phase=pre|order=" << g.order() << std::endl;
  g.prepare();
  g.fd.opHeritage();
  std::cout << g.dumpLine("const_load_no_fwd","p0") << std::endl;
  g.fd.opHeritage();
  std::cout << g.dumpLine("const_load_no_fwd","p1") << std::endl;
  PcodeOp *indirectOp = (PcodeOp *)0;
  for(list<PcodeOp *>::const_iterator iter=entry->beginOp();iter!=entry->endOp();++iter) {
    if ((*iter)->code() == CPUI_INDIRECT) indirectOp = *iter;
  }
  bool indirectReadsLastWrite = false;
  if (indirectOp != (PcodeOp *)0)
    indirectReadsLastWrite = (indirectOp->getIn(0) == wbOut);
  std::cout << "case=const_load_no_fwd|phase=check"
            << "|indirect_in_is_last_write=" << (indirectReadsLastWrite ? 1 : 0)
            << "|last_write_addrforced=" << (wbOut->isAddrForce() ? 1 : 0)
            << "|first_write_addrforced=" << (waOut->isAddrForce() ? 1 : 0)
            << std::endl;
}

// Case 3: the slot is written in both branch arms and read by an indexed
// LOAD after the join — the guard COPY renames to the join MULTIEQUAL
// and both arm writes are address-forced.
static void case_phi_fwd(FixtureArchitecture &arch)
{
  Graph g(arch,"phi_fwd",0x7300);
  BlockBasic *entry = g.block("entry");
  BlockBasic *thenB = g.block("thenB");
  BlockBasic *elseB = g.block("elseB");
  BlockBasic *joinB = g.block("joinB");
  g.edge(entry,thenB);
  g.edge(entry,elseB);
  g.edge(thenB,joinB);
  g.edge(elseB,joinB);
  Varnode *sp = g.spacebaseInput();
  PcodeOp *add0 = g.op("add0",CPUI_INT_ADD,2);	// sp + 0x30
  g.input(add0,sp,0);
  g.input(add0,g.constant(8,0x30),1);
  Varnode *t0 = g.uniqueOut(add0,8);
  PcodeOp *addidx = g.op("addidx",CPUI_INT_ADD,2);	// (sp+0x30) + idx
  g.input(addidx,t0,0);
  g.input(addidx,g.freeReg(0x100,8),1);
  Varnode *t2 = g.uniqueOut(addidx,8);
  PcodeOp *wT = g.op("wT",CPUI_COPY,1);			// then-arm slot write
  g.input(wT,g.constant(8,0x21),0);
  Varnode *wtOut = g.stackOut(wT,0x40,8);
  PcodeOp *wE = g.op("wE",CPUI_COPY,1);			// else-arm slot write
  g.input(wE,g.constant(8,0x22),0);
  Varnode *weOut = g.stackOut(wE,0x40,8);
  PcodeOp *ld = g.op("ld",CPUI_LOAD,2);			// indexed LOAD after join
  g.input(ld,g.spaceConst(),0);
  g.input(ld,t2,1);
  g.uniqueOut(ld,8);
  g.append(add0,entry);
  g.append(addidx,entry);
  g.append(wT,thenB);
  g.append(wE,elseB);
  g.append(ld,joinB);
  std::cout << "case=phi_fwd|phase=pre|order=" << g.order() << std::endl;
  g.prepare();
  g.fd.opHeritage();
  std::cout << g.dumpLine("phi_fwd","p0") << std::endl;
  g.fd.opHeritage();
  std::cout << g.dumpLine("phi_fwd","p1") << std::endl;
  PcodeOp *phi = (PcodeOp *)0;
  for(list<PcodeOp *>::const_iterator iter=joinB->beginOp();iter!=joinB->endOp();++iter) {
    if ((*iter)->code() == CPUI_MULTIEQUAL) { phi = *iter; break; }
  }
  bool phiReadsBothWrites = false;
  if (phi != (PcodeOp *)0 && phi->numInput() == 2)
    phiReadsBothWrites = ((phi->getIn(0) == wtOut && phi->getIn(1) == weOut) ||
                          (phi->getIn(0) == weOut && phi->getIn(1) == wtOut));
  std::cout << "case=phi_fwd|phase=check"
            << "|phi_exists=" << (phi != (PcodeOp *)0 ? 1 : 0)
            << "|phi_reads_both_writes=" << (phiReadsBothWrites ? 1 : 0)
            << "|then_write_addrforced=" << (wtOut->isAddrForce() ? 1 : 0)
            << "|else_write_addrforced=" << (weOut->isAddrForce() ? 1 : 0)
            << std::endl;
}

int main(void)
{
  std::cout << std::unitbuf;
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  FixtureArchitecture arch;
  std::cout << "schema=1|fixture=HERITAGE-STORELOAD-FWD-0001|oracle="
            << "e40ed13014025f82488b1f8f7bca566894ac376b" << std::endl;
  case_fwd_indexed_load(arch);
  case_const_load_no_fwd(arch);
  case_phi_fwd(arch);
  return 0;
}
