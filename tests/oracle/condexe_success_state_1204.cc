// CONDEXE-SUCCESS-STATE-0001 fixture — the ConditionalExecution success
// channel (condexe.cc:23-37 buildHeritageArray, condexe.cc:392 the
// heritageyes gate in testRemovability, condexe.cc:339-349 the
// space-preserving RETURN replacement in doReplacement, condexe.cc:478-503
// ActionConditionalExe::apply's live BlockGraph traversal and numhits ->
// Action::count) against the locked Ghidra 12.0.4 oracle, driven through
// the full apply() protocol on diamonds whose data-flow RESOLVES (the
// CONDEXE-ERROR-0006 companion pinned the aborts; this pins the folds).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable projections pinned by this fixture (one stdout line per record):
//   heritage S1p0..S1p3  Per-space buildHeritageArray at heritage pass
//             0/1/2/3: ram/register/unique flip true at pass 1, stack
//             (delay=1, SpacebaseSpace ctor dl) only at pass 2. Proves the
//             per-space numHeritagePasses(spc) = pass - delay arithmetic of
//             condexe.cc:34 and the !isHeritaged skip of cc:33.
//   pre/ret/state/multi/edges S2  A 3-diamond chain (A -> B -> C) with
//             iblocks at consecutive creation indices 3/4/5. The live
//             `for(i=0;i<bblocks.getSize();++i)` loop (cc:492) re-reads the
//             graph every iteration across the do-while rounds: every
//             execute() runs removeFromFlowSplit -> structureReset ->
//             findSpanningTree, which REORDERS the blocklist to reverse
//             post-order (block.cc:1135 `list = rpostorder`), so the cursor
//             walks a re-listed graph after each fold (the pre record pins
//             the post-reset RPO, the state record the final order after
//             four resets). The `multi` record's creation-order
//             (unique-offset sorted) parent list b8,b13,b18 pins the actual
//             fold order A,B,C under those reorders; `ret` pins count=3
//             (numhits -> Action::count, cc:496/501); `state` the final
//             16-block graph; and `edges` the reciprocal pre->post relinks
//             of all three removeFromFlowSplit calls (swap=false straight
//             mapping, block.cc:1584-1589). Note: for well-formed diamonds
//             the RPO successor of a folded iblock is always one of its own
//             1-in/1-out path blocks, so an index skip can never strand a
//             TRIALABLE block — fold order is invariant under the live vs
//             per-round-snapshot distinction; the records pin the live
//             reorder/relist behavior itself (byte-equality of pre/state
//             orders and the multi creation order).
//   ret/return S3  A diamond whose iblock MULTIEQUAL output (unique:0x2000)
//             is read by a RETURN input 1: doReplacement's RETURN leg
//             (cc:339-349) creates a COPY whose output PRESERVES the
//             CPUI_RETURN storage address including its address space
//             (cc:343 newVarnodeOut) — ret_in1 == copy_out ==
//             unique:0x2000:4, copy_in0 = the camethruposta-side
//             MULTIEQUAL input const:0x5, posta op list [COPY, RETURN],
//             count=1.
//   ret/state S4p0/S4p1  The cc:392 heritageyes gate: an iblock COPY
//             with NO descendants is removable only when its space has had
//             a heritage pass. At pass=0 (no heritage) trial rejects the
//             block (count=0, diamond intact, ib still MULTIEQUAL,CBRANCH
//             2-in/2-out); at pass=1 it folds (count=1, iblock gone).
//
// Test-only access drives the real ActionConditionalExe::apply (public,
// action.hh:130); `count` is read through a probe subclass (protected
// member, action.hh:60) instead of an access rewrite; heritageyes is read
// through the `#define private public` rewrite after constructing
// ConditionalExecution directly (its constructor is public, condexe.hh:124).
// The FixtureTranslate/FixtureArchitecture skeleton, the `#define private
// public` / `#define class struct` access rewrite and the dominator wiring
// follow tests/oracle/condexe_error_1204.cc (S2/S3/S4 use the PRODUCTION
// dominator computation: one fd.structureReset() before apply — the chains
// are single-entry so rootlist stays size 1 and the unreachable guard is
// proven NOT to fire by the pre record).
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

// Reads the protected Action::count accumulator (action.hh:60) through a
// subclass probe — apply() itself is public and unmodified.
class CountProbe : public ActionConditionalExe {
public:
  CountProbe(void) : ActionConditionalExe("") {}
  int4 getCount(void) const { return count; }
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

  PcodeOp *makeCbranchAt(BlockBasic *blk,Varnode *boolvn,Address pc)
  {
    PcodeOp *op = fd.newOp(2,pc);
    fd.opSetOpcode(op,CPUI_CBRANCH);
    fd.opSetInput(op,fd.newConstant(8,0x4000),0);
    fd.opSetInput(op,boolvn,1);
    fd.opInsertEnd(op,blk);
    return op;
  }

  string name(const FlowBlock *bl) const
  {
    if (bl == (const FlowBlock *)0) return "-";
    for(size_t i=0;i<blocks.size();++i)
      if (blocks[i] == bl) return "b" + to_string(i);
    return "x";
  }

  // Current-graph inventory: iterates the LIVE block list (removed iblocks
  // are deleted by BlockGraph::removeBlock and must not be touched), naming
  // each block by its creation ordinal.
  string graphInventory(void) const
  {
    const BlockGraph &graph = fd.getBasicBlocks();
    ostringstream s;
    for(int4 i=0;i<graph.getSize();++i) {
      if (i != 0) s << ',';
      const BlockBasic *bb = (const BlockBasic *)graph.getBlock(i);
      int4 nops = 0;
      for(auto it = bb->beginOp(); it != bb->endOp(); ++it)
        ++nops;
      s << name(bb) << ':' << nops;
    }
    return s.str();
  }

  string opsOf(const FlowBlock *bl) const
  {
    const BlockBasic *bb = (const BlockBasic *)bl;
    ostringstream s;
    bool first = true;
    for(auto it = bb->beginOp(); it != bb->endOp(); ++it) {
      if (!first) s << ',';
      first = false;
      s << get_opname((*it)->code());
    }
    return s.str();
  }

  static string vname(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "-";
    ostringstream s;
    s << vn->getSpace()->getName() << ":0x" << hex << vn->getOffset()
      << ':' << dec << vn->getSize();
    return s.str();
  }

  // The MULTIEQUAL ops still alive in a block: (output unique offset for
  // creation-order sorting, input projection list), in op-list order.
  struct MultiEntry { uintb off; string ins; };
  vector<MultiEntry> multisOf(const FlowBlock *bl) const
  {
    const BlockBasic *bb = (const BlockBasic *)bl;
    vector<MultiEntry> result;
    for(auto it = bb->beginOp(); it != bb->endOp(); ++it) {
      PcodeOp *op = *it;
      if (op->code() != CPUI_MULTIEQUAL) continue;
      MultiEntry e;
      e.off = op->getOut()->getOffset();
      for(int4 i=0;i<op->numInput();++i) {
        if (i != 0) e.ins += '+';
        e.ins += vname(op->getIn(i));
      }
      result.push_back(e);
    }
    return result;
  }
};

// ---------------------------------------------------------------------------
// S1: per-space buildHeritageArray (condexe.cc:23-37).
// The shared heritaged spaces both sides model, in the fixed print order:
// ram, register, unique, stack. The stack space is built with delay=1
// (SpacebaseSpace ctor dl parameter, translate.hh:181), so
// numHeritagePasses(stack) = pass - 1 (heritage.cc:2788): stack only turns
// true at pass 2, the other three at pass 1, none at pass 0 (the negative
// pass -1 of cc:2782-2784 stays "not yet heritaged" = false).
// ---------------------------------------------------------------------------
void runHeritageCase(FixtureArchitecture &architecture,const char *caseId,int4 pass)
{
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd(caseId,caseId,global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
  // buildHeritageArray reads Heritage::numHeritagePasses, which requires the
  // lazy Heritage::infolist; the real pipeline populates it during the first
  // heritage() pass. The fixture builds it and drives the pass counter.
  fd.heritage.buildInfoList();
  fd.heritage.pass = pass;
  ConditionalExecution condexe(&fd);
  const char *names[] = { "ram", "register", "unique", "stack" };
  cout << "heritage|case=" << caseId;
  for(int4 i=0;i<4;++i) {
    AddrSpace *spc = architecture.getSpaceByName(names[i]);
    cout << '|' << names[i] << '='
         << (condexe.heritageyes[spc->getIndex()] ? 1 : 0);
  }
  cout << '\n';
}

// ---------------------------------------------------------------------------
// S2: live BlockGraph traversal + numhits -> Action::count
// (condexe.cc:487-501). Block creation order (19 blocks):
//   b0 A_init, b1 A_pre1, b2 A_pre2, b3 A_ib, b4 B_ib, b5 C_ib,
//   b6 A_posta, b7 A_postb, b8 B_init, b9 B_pre1, b10 B_pre2,
//   b11 B_posta, b12 B_postb, b13 C_init, b14 C_pre1, b15 C_pre2,
//   b16 C_posta, b17 C_postb, b18 exit_merge
// with the CFG chain A_init -> (A_pres) -> A_ib -> (A_posts) -> B_init ->
// (B_pres) -> B_ib -> (B_posts) -> C_init -> (C_pres) -> C_ib -> (C_posts)
// -> exit_merge. Each init computes its OWN boolean (boolA/boolB/boolC, so
// adjacent-diamond trials like B_init-as-iblock fail verifySameCondition),
// each iblock holds MULTIEQUAL vnX = PHI(5, 9) whose reader COPY lives in
// the NEXT merge block (2 in-edges -> getNewMulti). The three iblocks at
// consecutive indices 3/4/5 exercise the LIVE bblocks.getSize()/getBlock(i)
// reference reads (cc:488, one relist per execute; the cursor consumes the
// relisted table every iteration). The pinned fold order is A, B, C,
// pinned pointer-free by the new-MULTIEQUAL unique-offset creation order
// b8, b13, b18 (see the multi record below).
// ---------------------------------------------------------------------------
struct Chain {
  Fixture f;
  BlockBasic *init[3];		// A/B/C init blocks (b0, b8, b13)
  BlockBasic *ib[3];		// A/B/C iblocks   (b3, b4, b5)
  BlockBasic *merge[3];		// reader merges   (b8, b13, b18)
  BlockBasic *pre1[3];		// prea-side 1in/1out blocks (b1, b9, b14)
  BlockBasic *pre2[3];
  BlockBasic *posta[3];
  BlockBasic *postb[3];
  BlockBasic *exitMerge;

  Chain(Funcdata &fd) : f(fd)
  {
    // Creation order is load-bearing: A_ib=b3, B_ib=b4, C_ib=b5 consecutive.
    BlockBasic *b[19];
    for(int4 i=0;i<19;++i) b[i] = f.makeBlock();
    // Wiring by name for readability.
    init[0] = b[0]; pre1[0] = b[1]; pre2[0] = b[2]; ib[0] = b[3];
    ib[1] = b[4]; ib[2] = b[5];
    posta[0] = b[6]; postb[0] = b[7]; merge[0] = b[8];
    init[1] = merge[0]; pre1[1] = b[9]; pre2[1] = b[10];
    posta[1] = b[11]; postb[1] = b[12]; merge[1] = b[13];
    init[2] = merge[1]; pre1[2] = b[14]; pre2[2] = b[15];
    posta[2] = b[16]; postb[2] = b[17]; exitMerge = b[18]; merge[2] = b[18];
    // Edges in EXACTLY this order (slot 0/1 assignment is load-bearing for
    // init2a_true / camethruposta_slot / the reciprocal relinks).
    for(int4 d=0;d<3;++d) {
      f.edge(init[d],pre1[d]); f.edge(init[d],pre2[d]);
      f.edge(pre1[d],ib[d]);   f.edge(pre2[d],ib[d]);
      f.edge(ib[d],posta[d]);  f.edge(ib[d],postb[d]);
    }
    // A's posts flow into B's init; B's into C's init; C's into exit_merge.
    f.edge(posta[0],init[1]); f.edge(postb[0],init[1]);
    f.edge(posta[1],init[2]); f.edge(postb[1],init[2]);
    f.edge(posta[2],exitMerge); f.edge(postb[2],exitMerge);
    // Per-diamond ops. Bool constants differ (1/2/3) so cross-diamond
    // verifySameCondition calls are UNCORRELATED; the iblock MULTIEQUALs
    // share the input constants 5 and 9.
    Varnode *boolvn[3];
    for(int4 d=0;d<3;++d) {
      PcodeOp *boolop = fd.newOp(1,f.allocPc());
      fd.opSetOpcode(boolop,CPUI_COPY);
      boolvn[d] = f.makeOut(1,f.uniqueSpace(),0x900 + 0x10*d,boolop);
      fd.opSetInput(boolop,fd.newConstant(1,d+1),0);
      fd.opInsertEnd(boolop,init[d]);
    }
    for(int4 d=0;d<3;++d) {
      // The iblock: MULTIEQUAL vnX = PHI(5,9), then CBRANCH on this
      // diamond's boolean (correlated with the init CBRANCH).
      PcodeOp *multi = fd.newOp(2,f.allocPc());
      fd.opSetOpcode(multi,CPUI_MULTIEQUAL);
      Varnode *vnX = f.makeOut(4,f.uniqueSpace(),0x2000 + 0x10*d,multi);
      fd.opSetInput(multi,fd.newConstant(4,5),0);
      fd.opSetInput(multi,fd.newConstant(4,9),1);
      fd.opInsertEnd(multi,ib[d]);
      f.makeCbranchAt(ib[d],boolvn[d],f.allocPc());
      // The reader COPY in the NEXT merge block (A->B_init, B->C_init,
      // C->exit_merge): its 2 in-edges route getReplacementRead through
      // getNewMulti, creating the order-observable new MULTIEQUAL.
      PcodeOp *reader = fd.newOp(1,f.allocPc());
      fd.opSetOpcode(reader,CPUI_COPY);
      fd.opSetInput(reader,vnX,0);
      fd.opInsertEnd(reader,merge[d]);
      // Init CBRANCH last (block terminator).
      f.makeCbranchAt(init[d],boolvn[d],f.allocPc());
    }
  }
};

void runLiveTraversalCase(FixtureArchitecture &architecture)
{
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd("S2","S2",global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
  // buildHeritageArray reads Heritage::numHeritagePasses, which requires
  // the lazy Heritage::infolist (heritage.hh:257 indexes it bare); the real
  // pipeline populates it during the first heritage() pass.
  fd.heritage.buildInfoList();
  Chain chain(fd);
  // Production dominator computation before apply (single entry b0 ->
  // rootlist size 1 -> the cc:485-486 guard does NOT fire, proven by pre).
  fd.structureReset();
  cout << "pre|case=S2|nblocks=" << fd.getBasicBlocks().getSize()
       << "|order=" << chain.f.graphInventory()
       << "|unreach=" << (fd.hasUnreachableBlocks() ? 1 : 0) << '\n';
  CountProbe action;
  int4 r = action.apply(fd);
  cout << "ret|case=S2|apply=" << r << "|count=" << action.getCount() << '\n';
  cout << "state|case=S2|nblocks=" << fd.getBasicBlocks().getSize()
       << "|blocks=" << chain.f.graphInventory() << '\n';
  // The three new MULTIEQUALs (one per merge block), sorted by their output
  // unique offset = creation order: the live walk folds A (round 1), B
  // (round 1, post-A relist), C (round 1, post-B relist) — b8, b13, b18.
  // The order is computed side-locally (monotonic unique allocator), so the
  // projection stays pointer-free while pinning the fold sequence.
  struct Entry { string block; uintb off; string detail; };
  vector<Entry> entries;
  for(int4 d=0;d<3;++d) {
    vector<Fixture::MultiEntry> multis = chain.f.multisOf(chain.merge[d]);
    for(size_t k=0;k<multis.size();++k) {
      Entry e;
      e.block = chain.f.name(chain.merge[d]);
      e.off = multis[k].off;
      e.detail = e.block + "_in=" + multis[k].ins;
      entries.push_back(e);
    }
  }
  stable_sort(entries.begin(),entries.end(),
              [](const Entry &a,const Entry &b){ return a.off < b.off; });
  cout << "multi|case=S2|order=";
  for(size_t i=0;i<entries.size();++i) {
    if (i != 0) cout << ',';
    cout << entries[i].block;
  }
  for(size_t i=0;i<entries.size();++i)
    cout << '|' << entries[i].detail;
  cout << '\n';
  // Reciprocal pre->post relinks of the three removeFromFlowSplit calls
  // (swap=false: In(0)->Out(0)=posta, In(1)->Out(1)=postb, block.cc:1584-1589).
  cout << "edges|case=S2";
  for(int4 d=0;d<3;++d) {
    cout << '|' << chain.f.name(chain.pre1[d]) << '=' << chain.f.name(chain.pre1[d]->getOut(0))
         << ';' << chain.f.name(chain.pre2[d]) << '=' << chain.f.name(chain.pre2[d]->getOut(0));
  }
  cout << '\n';
}

// ---------------------------------------------------------------------------
// S3: space-preserving RETURN replacement (condexe.cc:339-349). The iblock
// MULTIEQUAL output vnR (unique:0x2000:4) is read by a RETURN's input 1 in
// the posta block. doReplacement's RETURN leg creates a COPY whose output
// preserves vnR's storage INCLUDING its unique space (cc:343); the COPY's
// input 0 resolves through the posta path (camethruposta side) to the
// MULTIEQUAL input const 5.
// ---------------------------------------------------------------------------
void runReturnCase(FixtureArchitecture &architecture)
{
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd("S3","S3",global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
  fd.heritage.buildInfoList();
  Fixture f(fd);
  BlockBasic *b0 = f.makeBlock();	// init
  BlockBasic *b1 = f.makeBlock();	// pre1
  BlockBasic *b2 = f.makeBlock();	// pre2
  BlockBasic *b3 = f.makeBlock();	// iblock
  BlockBasic *b4 = f.makeBlock();	// posta (RETURN)
  BlockBasic *b5 = f.makeBlock();	// postb
  f.edge(b0,b1); f.edge(b0,b2);
  f.edge(b1,b3); f.edge(b2,b3);
  f.edge(b3,b4); f.edge(b3,b5);
  Varnode *boolvn;
  {
    PcodeOp *boolop = fd.newOp(1,f.allocPc());
    fd.opSetOpcode(boolop,CPUI_COPY);
    boolvn = f.makeOut(1,f.uniqueSpace(),0x900,boolop);
    fd.opSetInput(boolop,fd.newConstant(1,1),0);
    fd.opInsertEnd(boolop,b0);
  }
  Varnode *vnR;
  {
    PcodeOp *multi = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(multi,CPUI_MULTIEQUAL);
    vnR = f.makeOut(4,f.uniqueSpace(),0x2000,multi);
    fd.opSetInput(multi,fd.newConstant(4,5),0);
    fd.opSetInput(multi,fd.newConstant(4,9),1);
    fd.opInsertEnd(multi,b3);
  }
  f.makeCbranchAt(b3,boolvn,f.allocPc());
  {
    PcodeOp *ret = fd.newOp(2,f.allocPc());
    fd.opSetOpcode(ret,CPUI_RETURN);
    fd.opSetInput(ret,fd.newConstant(1,0),0);
    fd.opSetInput(ret,vnR,1);
    fd.opInsertEnd(ret,b4);
  }
  f.makeCbranchAt(b0,boolvn,f.allocPc());
  fd.structureReset();
  CountProbe action;
  int4 r = action.apply(fd);
  cout << "ret|case=S3|apply=" << r << "|count=" << action.getCount() << '\n';
  // Find the RETURN and the COPY feeding its input 1 (the new COPY is
  // inserted immediately before the RETURN, cc:345).
  PcodeOp *retop = (PcodeOp *)0;
  PcodeOp *copyop = (PcodeOp *)0;
  for(auto it = b4->beginOp(); it != b4->endOp(); ++it) {
    PcodeOp *op = *it;
    if (op->code() == CPUI_RETURN) retop = op;
    if (op->code() == CPUI_COPY) copyop = op;
  }
  cout << "return|case=S3|ret_in1=" << Fixture::vname(retop->getIn(1))
       << "|copy_out=" << Fixture::vname(copyop->getOut())
       << "|copy_in0=" << Fixture::vname(copyop->getIn(0))
       << "|posta_ops=" << f.opsOf(b4)
       << "|nblocks=" << fd.getBasicBlocks().getSize() << '\n';
}

// ---------------------------------------------------------------------------
// S4: the cc:392 heritageyes gate. Identical heritage-gated diamonds at
// heritage pass 0 (no space has had a pass: trial must reject the iblock)
// and pass 1 (unique space has: the fold proceeds).
// ---------------------------------------------------------------------------
struct GateDiamond {
  Fixture f;
  BlockBasic *init;
  BlockBasic *ib;
  GateDiamond(Funcdata &fd) : f(fd)
  {
    init = f.makeBlock();
    BlockBasic *pre1 = f.makeBlock();
    BlockBasic *pre2 = f.makeBlock();
    ib = f.makeBlock();
    BlockBasic *posta = f.makeBlock();
    BlockBasic *postb = f.makeBlock();
    f.edge(init,pre1); f.edge(init,pre2);
    f.edge(pre1,ib);   f.edge(pre2,ib);
    f.edge(ib,posta);  f.edge(ib,postb);
    Varnode *boolvn;
    {
      PcodeOp *boolop = fd.newOp(1,f.allocPc());
      fd.opSetOpcode(boolop,CPUI_COPY);
      boolvn = f.makeOut(1,f.uniqueSpace(),0x900,boolop);
      fd.opSetInput(boolop,fd.newConstant(1,1),0);
      fd.opInsertEnd(boolop,init);
    }
    // COPY with NO descendants: testRemovability's non-MULTIEQUAL branch
    // reaches the heritageyes[vn->getSpace()->getIndex()] read (cc:392).
    // (A no-descendant MULTIEQUAL would bypass the gate — the cc:368
    // branch has no heritage check.)
    {
      PcodeOp *copyop = fd.newOp(1,f.allocPc());
      fd.opSetOpcode(copyop,CPUI_COPY);
      Varnode *vnX = f.makeOut(4,f.uniqueSpace(),0x2000,copyop);
      fd.opSetInput(copyop,fd.newConstant(4,5),0);
      (void)vnX;
      fd.opInsertEnd(copyop,ib);
    }
    f.makeCbranchAt(ib,boolvn,f.allocPc());
    f.makeCbranchAt(init,boolvn,f.allocPc());
  }
};

string fNullSafeOps(Funcdata &fd,GateDiamond &d)
{
  // The iblock is DELETED by removeFromFlowSplit after a successful fold
  // (BlockGraph::removeBlock frees it), so probe graph residency by pointer
  // identity through the live list before touching it.
  const BlockGraph &graph = fd.getBasicBlocks();
  for(int4 i=0;i<graph.getSize();++i)
    if (graph.getBlock(i) == d.ib) return d.f.opsOf(d.ib);
  return "(gone)";
}

void runGateCase(FixtureArchitecture &architecture,const char *caseId,int4 pass)
{
  AddrSpace *ram = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd(caseId,caseId,global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
  GateDiamond d(fd);
  fd.heritage.buildInfoList();
  fd.heritage.pass = pass;
  CountProbe action;
  int4 r = action.apply(fd);
  cout << "ret|case=" << caseId << "|apply=" << r
       << "|count=" << action.getCount()
       << "|nblocks=" << fd.getBasicBlocks().getSize()
       << "|ib_ops=" << fNullSafeOps(fd,d) << '\n';
}

void run(void)
{
  FixtureArchitecture architecture;
  runHeritageCase(architecture,"S1p0",0);	// no heritage yet: all false
  runHeritageCase(architecture,"S1p1",1);	// delay-0 spaces true, stack false
  runHeritageCase(architecture,"S1p2",2);	// stack (delay 1) turns true
  runHeritageCase(architecture,"S1p3",3);
  runLiveTraversalCase(architecture);	// live traversal + count (A,B,C)
  runReturnCase(architecture);		// space-preserving RETURN replacement
  runGateCase(architecture,"S4p0",0);	// cc:392 rejects: no heritage
  runGateCase(architecture,"S4p1",1);	// cc:392 admits: fold proceeds
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
