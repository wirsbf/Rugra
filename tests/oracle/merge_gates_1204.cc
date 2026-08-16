/*
 * MERGE-PREEXISTING-GATES-0001: locked Ghidra 12.0.4 oracle for the five
 * pre-existing merge-family gate gaps (four-round review, 2026-08-16).
 *
 *  case_indirect_addrforce  Merge::mergeIndirect (merge.cc:846-882): the
 *      isAddrForce gate, the mergeTestRequired + merge(in_high,out_high)
 *      attempts with the INPUT side surviving, snipOutputInterference
 *      (collectInputs walk over previousOp-INDIRECT chain, merge.cc:783-839)
 *      and the allocateCopyTrim fallback that snips the INDIRECT itself.
 *  case_dominant_copy       buildDominantCopy (merge.cc:1151-1238) reached
 *      through the production path mergeOp phase-1 trims -> copyTrims ->
 *      processCopyTrims -> processHighDominantCopy, driving the
 *      domCopyIsNew branch and the final direct
 *      high->merge(domHigh,(HighIntersectTest*)0,true) at :1236.
 *  case_multientry_gate     mergeMultiEntry (merge.cc:908-963): the
 *      mergeTestRequired gate at :936 with setMergeProblems/setUnmerged and
 *      the warningHeader report at :950-961.
 *  case_cross_space_order   HighVariable::compareJustLoc (variable.cc:439-
 *      443) as the Address total order (space index first, address.hh:375):
 *      raw comparator booleans on cross-space pairs plus the merged
 *      HighVariable instance order after mergeOpcode(CPUI_COPY).
 *
 * The fifth gate (merge_highs (Some,Some) piece arm vs oracle throw /
 * mergeGroups, variable.cc:699-711) is Ghidra-side unreachable through
 * Merge::merge callers (mergeTestAdjacent rejects both-piece speculative
 * candidates, merge.cc:208-209; the non-speculative path requires
 * VariablePiece groups that this locked pipeline state never forms) — no
 * oracle case can drive it; see metadata coverage.
 *
 * Stages mirror the production universal action tree order
 * (coreaction.cc:5717-5727): assignhigh, mergerequired (mergeAddrTied +
 * groupPartials + mergeMarker), multientry, mergecopy, dominantcopy,
 * mergeadjacent.
 */

#include <bits/stdc++.h>

#define private public
#include "architecture.hh"
#include "comment.hh"
#include "database.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "merge.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#include "funcdata.hh"
#undef private

using namespace ghidra;
using std::cerr;
using std::cout;
using std::istringstream;
using std::map;
using std::ostringstream;
using std::set;
using std::string;
using std::vector;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;
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
    // Architecture::Init (which invokes the buildXxx virtuals) is bypassed
    // by this fixture, so the comment database is installed directly —
    // mergeMultiEntry's warningHeader (funcdata.cc:143) writes into it.
    commentdb = new CommentDatabaseInternal();
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

class Graph {
public:
  Funcdata fd;
  AddrSpace *ram;
  AddrSpace *reg;
  AddrSpace *unique;
  int4 nextPc;
  vector<BlockBasic *> blocks;

  Graph(FixtureArchitecture &a, const string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x100),
      ram(a.getSpace(3)), reg(a.getSpace(4)), unique(a.getSpace(2)), nextPc(0) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &bgraph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = bgraph.newBlockBasic(&fd);
    // Production assigns FlowBlock::index via BlockGraph::findSpanningTree
    // reverse post-order (block.cc:1081); this fixture does not run it, so
    // assign creation-order indices matching the Rust comparand's explicit
    // BlockBasic index argument (same convention as merge_persistent_1204).
    block->index = static_cast<int4>(blocks.size());
    blocks.push_back(block);
    return block;
  }

  void setDom(BlockBasic *child, BlockBasic *parent)
  {
    // Production computes immediate dominators in BlockGraph::calcReachable
    // / buildDomTree; the fixture installs the diamond dominators directly
    // so FlowBlock::findCommonBlock (block.cc:736) behaves as in production.
    child->immed_dom = parent;
  }

  void edge(BlockBasic *from, BlockBasic *to)
  {
    BlockGraph &bgraph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    bgraph.addEdge(from, to);
  }

  PcodeOp *makeOp(OpCode opcode, int4 inputs)
  {
    Address pc(ram, fd.getAddress().getOffset() + static_cast<uintb>(nextPc));
    nextPc += 1;
    PcodeOp *op = fd.newOp(inputs, pc);
    fd.opSetOpcode(op, opcode);
    return op;
  }

  Varnode *constant(int4 size, uintb value) { return fd.newConstant(size, value); }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot) { fd.opSetInput(op, vn, slot); }

  Varnode *registerOut(int4 size, uintb offset, PcodeOp *op)
  {
    return fd.newVarnodeOut(size, Address(reg, offset), op);
  }

  Varnode *uniqueOut(int4 size, uintb offset, PcodeOp *op)
  {
    return fd.newVarnodeOut(size, Address(unique, offset), op);
  }

  Varnode *iopConst(PcodeOp *op) { return fd.newVarnodeIop(op); }

  void insertEnd(PcodeOp *op, BlockBasic *block) { fd.opInsertEnd(op, block); }
  void insertBefore(PcodeOp *op, PcodeOp *follow) { fd.opInsertBefore(op, follow); }

  // Varnode storage rendering for the IR-shape projection. Unique-space
  // (IPTR_INTERNAL) varnodes print as "u" — their offsets are allocator
  // state and are normalized away; constants print their value; the iop
  // annotation prints "iop"; everything else prints "<space index>:<hex>".
  static string vnText(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "none";
    if (vn->getSpace()->getType() == IPTR_CONSTANT)
      return "k" + std::to_string(vn->getOffset());
    if (vn->getSpace()->getType() == IPTR_IOP)
      return "iop";
    if (vn->getSpace()->getType() == IPTR_INTERNAL)
      return "u";
    ostringstream out;
    out << vn->getSpace()->getIndex() << ':' << std::hex << vn->getOffset();
    return out.str();
  }

  static string opText(PcodeOp *op)
  {
    ostringstream out;
    out << static_cast<int4>(op->code()) << '(';
    for(int4 i=0;i<op->numInput();++i) {
      if (i != 0) out << ',';
      out << vnText(op->getIn(i));
    }
    out << ")->" << vnText(op->getOut());
    return out.str();
  }

  string opsText(void) const
  {
    ostringstream out;
    for(size_t b=0;b<blocks.size();++b) {
      if (b != 0) out << ' ';
      out << 'b' << b << "=[";
      bool first = true;
      for(list<PcodeOp *>::const_iterator iter = blocks[b]->beginOp();
          iter != blocks[b]->endOp(); ++iter) {
        if (!first) out << ';';
        first = false;
        out << opText(*iter);
      }
      out << ']';
    }
    return out.str();
  }

  // (The trims channel is projected implicitly: every trim COPY allocated by
  // Merge::allocateCopyTrim appears in the ops= dump of its block. Merge's
  // copyTrims list is class-default private — merge.hh:81 — and cannot be
  // exposed via the access-define trick, same limitation merge_persistent_1204
  // recorded for testCache counts.)

  // Per-instance def-opcode + mergeGroup of a HighVariable, in the
  // HighVariable's instance order (compareJustLoc, variable.cc:439).
  string highShapeText(const Varnode *vn) const
  {
    const HighVariable *high = vn->getHigh();
    ostringstream out;
    out << '[';
    for(int4 i=0;i<high->numInstances();++i) {
      if (i != 0) out << '/';
      const Varnode *inst = high->getInstance(i);
      int4 defcode = -1;
      if (inst->isWritten() && inst->getDef() != (PcodeOp *)0)
        defcode = static_cast<int4>(inst->getDef()->code());
      out << defcode << ':' << inst->getMergeGroup();
    }
    out << ']';
    return out.str();
  }

  string commentsText(FixtureArchitecture &arch) const
  {
    ostringstream out;
    out << '[';
    bool first = true;
    CommentDatabaseInternal *db =
      dynamic_cast<CommentDatabaseInternal *>(arch.commentdb);
    if (db != (CommentDatabaseInternal *)0) {
      // CommentSet is sorted by (funcaddr, addr, uniq); dump every stored
      // warningheader text for this function.
      for(CommentSet::const_iterator iter = db->beginComment(fd.getAddress());
          iter != db->endComment(fd.getAddress()); ++iter) {
        const Comment *com = *iter;
        if (com->getType() != Comment::warningheader) continue;
        if (!first) out << ';';
        first = false;
        out << com->getText();
      }
    }
    out << ']';
    return out.str();
  }

  void observe(const string &caseName, const string &stage,
               const vector<string> &names, const vector<Varnode *> &vns)
  {
    ostringstream grouping;
    for(size_t i = 0; i < vns.size(); ++i) {
      if (i != 0) grouping << '/';
      grouping << names[i] << ':' << vns[i]->getHigh()->numInstances();
    }
    ostringstream sameHigh;
    for(size_t i = 0; i < vns.size(); ++i) {
      for(size_t j = i + 1; j < vns.size(); ++j) {
        sameHigh << names[i] << names[j] << '='
                 << (vns[i]->getHigh() == vns[j]->getHigh() ? 1 : 0) << ',';
      }
    }
    string sameHighText = sameHigh.str();
    if(!sameHighText.empty()) sameHighText.pop_back();
    ostringstream groups;
    for(size_t i = 0; i < vns.size(); ++i) {
      if (i != 0) groups << '/';
      groups << names[i] << ':' << vns[i]->getMergeGroup();
    }
    ostringstream shapes;
    for(size_t i = 0; i < vns.size(); ++i) {
      if (i != 0) shapes << '/';
      shapes << names[i] << highShapeText(vns[i]);
    }
    cout << "case=" << caseName
         << "|stage=" << stage
         << "|instances=" << grouping.str()
         << "|groups=" << groups.str()
         << "|same_high=" << sameHighText
         << "|ops=" << opsText()
         << "|shape=" << shapes.str()
         << '\n';
  }
};

// -------------------------------------------------------------------------
// case_indirect_addrforce: INDIRECT output marked addrforce, with the input
// A still live past the INDIRECT (R = INT_ADD A after it), so the first
// merge(in_high,out_high) fails the cover test; the effect op (LOAD) reads
// nothing of the output high, so snipOutputInterference finds nothing; the
// allocateCopyTrim fallback snips the INDIRECT input and re-merges.
// -------------------------------------------------------------------------
void runIndirectAddrForce(FixtureArchitecture &arch)
{
  Graph g(arch, "indirect_addrforce", 0x7400);
  BlockBasic *b0 = g.makeBlock();

  // b0: op1 A = COPY const
  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnA = g.registerOut(4, 0x10, op1);
  g.setInput(op1, g.constant(4, 0x51), 0);
  g.insertEnd(op1, b0);
  // b0: opE E = LOAD(const, const)   -- the op causing the indirect effect
  PcodeOp *opE = g.makeOp(CPUI_LOAD, 2);
  Varnode *vnE = g.registerOut(4, 0x30, opE);
  g.setInput(opE, g.constant(8, 3), 0);
  g.setInput(opE, g.constant(8, 0x90), 1);
  g.insertEnd(opE, b0);
  // b0: indop I = INDIRECT(A, iop(opE)), placed BEFORE the effect op
  // (Funcdata::newIndirectOp, funcdata_op.cc:696).
  PcodeOp *indop = g.makeOp(CPUI_INDIRECT, 2);
  Varnode *vnI = g.registerOut(4, 0x20, indop);
  g.setInput(indop, vnA, 0);
  g.setInput(indop, g.iopConst(opE), 1);
  g.insertBefore(indop, opE);
  vnI->setAddrForce();
  // b0: R = INT_ADD A, 1  (keeps A live past the INDIRECT -> cover clash)
  PcodeOp *opR = g.makeOp(CPUI_INT_ADD, 2);
  Varnode *vnR = g.registerOut(4, 0x40, opR);
  g.setInput(opR, vnA, 0);
  g.setInput(opR, g.constant(4, 1), 1);
  g.insertEnd(opR, b0);

  vector<string> names;
  names.push_back("A"); names.push_back("I");
  vector<Varnode *> vns;
  vns.push_back(vnA); vns.push_back(vnI);

  g.fd.setHighLevel();
  g.observe("indirect_addrforce", "assignhigh", names, vns);
  {
    g.fd.getMerge().mergeAddrTied();
    g.fd.getMerge().groupPartials();
    g.fd.getMerge().mergeMarker();
  }
  g.observe("indirect_addrforce", "mergerequired", names, vns);
}

// -------------------------------------------------------------------------
// case_dominant_copy: diamond b0 -> {b1,b2} -> b3. V (typelocked int) feeds
// both MULTIEQUAL slots of O (typelocked uint); mergeTestRequired fails for
// both slots, so mergeOp phase 1 inserts trim COPYs T0 (end of b1) and T1
// (end of b2); phase 3 merges O/T0/T1 into one high. ActionMergeCopy skips
// the trims (typelock conflict). ActionDominantCopy then sees 2 COPYs into
// that high from the same V, buildDominantCopy allocates the dominant COPY
// in b0 (domCopyIsNew) and closes with the direct null-testCache speculative
// merge at merge.cc:1236.
// -------------------------------------------------------------------------
void runDominantCopy(FixtureArchitecture &arch)
{
  Graph g(arch, "dominant_copy", 0x7500);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  BlockBasic *b2 = g.makeBlock();
  BlockBasic *b3 = g.makeBlock();
  g.edge(b0, b1);
  g.edge(b0, b2);
  g.edge(b1, b3);
  g.edge(b2, b3);
  g.setDom(b1, b0);
  g.setDom(b2, b0);
  g.setDom(b3, b0);

  Datatype *ctInt = arch.types->getBase(4, TYPE_INT);
  Datatype *ctUint = arch.types->getBase(4, TYPE_UINT);

  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnV = g.registerOut(4, 0x10, op1);
  g.setInput(op1, g.constant(4, 0x61), 0);
  g.insertEnd(op1, b0);
  vnV->updateType(ctInt, true, true);

  PcodeOp *me = g.makeOp(CPUI_MULTIEQUAL, 2);
  Varnode *vnO = g.registerOut(4, 0x20, me);
  g.setInput(me, vnV, 0);
  g.setInput(me, vnV, 1);
  g.insertEnd(me, b3);
  vnO->updateType(ctUint, true, true);

  vector<string> names;
  names.push_back("V"); names.push_back("O");
  vector<Varnode *> vns;
  vns.push_back(vnV); vns.push_back(vnO);

  g.fd.setHighLevel();
  g.observe("dominant_copy", "assignhigh", names, vns);
  {
    g.fd.getMerge().mergeAddrTied();
    g.fd.getMerge().groupPartials();
    g.fd.getMerge().mergeMarker();
  }
  g.observe("dominant_copy", "mergerequired", names, vns);
  g.fd.getMerge().mergeOpcode(CPUI_COPY);
  g.observe("dominant_copy", "mergecopy", names, vns);
  g.fd.getMerge().processCopyTrims();
  g.observe("dominant_copy", "dominantcopy", names, vns);
  g.fd.getMerge().mergeAdjacent();
  g.observe("dominant_copy", "mergeadjacent", names, vns);
}

// -------------------------------------------------------------------------
// case_multientry_gate: one Symbol with two whole-size entries (unique
// 0x100 / 0x200); M1/M2 are linked to distinct entries, with type-locked
// DIFFERENT types, so mergeTestRequired(high,newHigh) fails at merge.cc:109
// and the :936-947 path must setMergeProblems + setUnmerged + emit the
// warningHeader text.
// -------------------------------------------------------------------------
void runMultiEntryGate(FixtureArchitecture &arch)
{
  Graph g(arch, "multientry_gate", 0x7600);
  BlockBasic *b0 = g.makeBlock();

  Datatype *ctInt = arch.types->getBase(8, TYPE_INT);
  Datatype *ctUint = arch.types->getBase(8, TYPE_UINT);

  PcodeOp *op1 = g.makeOp(CPUI_LOAD, 2);
  Varnode *vnM1 = g.uniqueOut(8, 0x100, op1);
  g.setInput(op1, g.constant(8, 3), 0);
  g.setInput(op1, g.constant(8, 0x1000), 1);
  g.insertEnd(op1, b0);
  vnM1->updateType(ctInt, true, true);

  PcodeOp *op2 = g.makeOp(CPUI_LOAD, 2);
  Varnode *vnM2 = g.uniqueOut(8, 0x200, op2);
  g.setInput(op2, g.constant(8, 3), 0);
  g.setInput(op2, g.constant(8, 0x2000), 1);
  g.insertEnd(op2, b0);
  vnM2->updateType(ctUint, true, true);

  // One Symbol, two whole-size entries at the varnode storage locations.
  // Each entry's use point is its varnode's defining op address: Ghidra's
  // findLinkedVarnodes (funcdata_varnode.cc:1268) accepts a Varnode only if
  // its use point falls within the entry's uselimit (entry->inUse).
  Scope *local = g.fd.getScopeLocal();
  SymbolEntry *entry1 = local->addSymbol("multi", ctInt, vnM1->getAddr(),
                                         op1->getAddr());
  Symbol *sym = entry1->getSymbol();
  local->addMapPoint(sym, vnM2->getAddr(), op2->getAddr());

  vector<string> names;
  names.push_back("M1"); names.push_back("M2");
  vector<Varnode *> vns;
  vns.push_back(vnM1); vns.push_back(vnM2);

  g.fd.setHighLevel();
  g.observe("multientry_gate", "assignhigh", names, vns);
  {
    g.fd.getMerge().mergeAddrTied();
    g.fd.getMerge().groupPartials();
    g.fd.getMerge().mergeMarker();
  }
  g.observe("multientry_gate", "mergerequired", names, vns);
  g.fd.getMerge().mergeMultiEntry();
  ostringstream extra;
  extra << "case=multientry_gate|stage=multientry"
        << "|merge_problems=" << (sym->hasMergeProblems() ? 1 : 0)
        << "|unmerged_M2=" << (vnM2->getHigh()->isUnmerged() ? 1 : 0)
        << "|warn=" << g.commentsText(arch)
        << '\n';
  cout << extra.str();
  g.observe("multientry_gate", "postmultientry", names, vns);
}

// -------------------------------------------------------------------------
// case_cross_space_order: compareJustLoc is Address::operator< — space index
// first (address.hh:375-393), offset second. T lives at unique:0x5000, V at
// register:0x10; unique(index 2) < register(index 4), so T orders BEFORE V
// despite the larger offset. mergeOpcode(CPUI_COPY) merges them (same
// type/size, disjoint boundary covers); the merged HighVariable's instance
// order must be [T, V].
// -------------------------------------------------------------------------
void runCrossSpaceOrder(FixtureArchitecture &arch)
{
  Graph g(arch, "cross_space_order", 0x7700);
  BlockBasic *b0 = g.makeBlock();

  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnV = g.registerOut(4, 0x10, op1);
  g.setInput(op1, g.constant(4, 0x71), 0);
  g.insertEnd(op1, b0);

  PcodeOp *op2 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnT = g.uniqueOut(4, 0x5000, op2);
  g.setInput(op2, vnV, 0);
  g.insertEnd(op2, b0);

  cout << "case=cross_space_order|stage=cmp"
       << "|cmp_TV=" << (HighVariable::compareJustLoc(vnT, vnV) ? 1 : 0)
       << "|cmp_VT=" << (HighVariable::compareJustLoc(vnV, vnT) ? 1 : 0)
       << "|cmp_VV=" << (HighVariable::compareJustLoc(vnV, vnV) ? 1 : 0)
       << '\n';

  vector<string> names;
  names.push_back("V"); names.push_back("T");
  vector<Varnode *> vns;
  vns.push_back(vnV); vns.push_back(vnT);

  g.fd.setHighLevel();
  g.observe("cross_space_order", "assignhigh", names, vns);
  g.fd.getMerge().mergeOpcode(CPUI_COPY);
  g.observe("cross_space_order", "mergecopy", names, vns);
}

} // namespace

int main()
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  try {
    FixtureArchitecture architecture;
    runIndirectAddrForce(architecture);
    runDominantCopy(architecture);
    runMultiEntryGate(architecture);
    runCrossSpaceOrder(architecture);
  }
  catch(const LowlevelError &error) {
    cerr << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
