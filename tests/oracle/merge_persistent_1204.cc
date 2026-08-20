/*
 * MERGE-PERSISTENT-STATE-0001: locked Ghidra 12.0.4 persistent Merge oracle.
 *
 * The fixture builds the same synthetic def-use/CFG graph twice (one case
 * per graph) and runs the production merge-family Action sequence of the
 * universal action tree exactly as the pipeline orders it:
 *
 *   ActionAssignHigh    (coreaction.hh:346, funcdata.cc:595 setHighLevel)
 *   ActionMergeRequired (coreaction.hh:369: mergeAddrTied + groupPartials
 *                        + mergeMarker on the ONE persistent
 *                        data.getMerge() object)
 *   ActionMergeCopy     (coreaction.hh:392: mergeOpcode(CPUI_COPY))
 *   ActionMergeAdjacent (coreaction.hh:381: mergeAdjacent)
 *
 * Every apply() dereferences data.getMerge() — the by-value Funcdata member
 * `covermerge` (funcdata.hh:96).  This fixture currently projects only:
 *
 *   high grouping  numInstances + shared-HighVariable identity booleans
 *   covers         per-Varnode rebuilt Cover as [blk:uindex-uindex,...]
 *
 * It does NOT print testCache/copyTrims/protoPartial state or clear-lifecycle
 * transitions.  Those channels remain outside this projection and are bound
 * to MERGE-PERSISTENCE-CHANNELS-0001 and its child TODOs.  A byte-identical
 * line here must not be interpreted as proof of the full persistent state.
 *
 * case_copy_shadow_ladder: two COPYs from one source whose outputs'
 * read-ranges interleave.  Ghidra's transitive Varnode::copyShadow
 * (varnode.cc:977) recognizes the whole ladder as one shadow family and
 * merges all three Varnodes at mergecopy — a decision that requires the
 * covers lazily built during the Action and the persistent testCache,
 * which is precisely the premise the standalone Actions run under in the
 * real pipeline.  The locked oracle output shows instances=3/3/3 at the
 * mergecopy stage.
 *
 * case_disjoint_copy: single COPY whose input/output share no live range
 * beyond the boundary point; both implementations must merge.
 *
 * case_pipeline_tail: the ladder graph driven through the full production
 * tail including ActionMergeType's mergeByDatatype (coreaction.hh:414-415)
 * on the one persistent getMerge() object, so the cross-Action channel
 * hand-off itself is under observation end to end.
 *
 * case_type_gate / case_float_trunc_cast / case_char_gate_null /
 * case_char_gate_char: the merge.cc:1001 canonical local-type gate.  The
 * shift-amount slot override (typeop.cc:1513-1514 getBaseNoChar) and the
 * FLOAT_TRUNC ctor pair (typeop.cc:1913 (TYPE_INT,TYPE_FLOAT)) are pinned
 * across BOTH core-type registration worlds of type.cc:3619-3626: with no
 * registered 1-byte INT core type (type_nochar null, type.cc:3131) the
 * nochar lookup IS the plain base (type.cc:3624) and even a 1-byte shift
 * amount passes the gate; with the production "int1"+"char" pair
 * (sleigh_arch.cc:204-241) the registered type_nochar differs from the
 * ASCII char in typecache[1][INT] (type.cc:3220-3229) and the 1-byte pair
 * is rejected while size!=1 pairs still pass.
 */

#include <bits/stdc++.h>

#define private public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
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
  // char_core_types uses deliberately custom names for the same properties
  // as the production SLEIGH core-type pair (sleigh_arch.cc:204-241), proving
  // the type.cc:3619-3626 decision is property/identity based, not name based:
  // the non-ASCII 1-byte TYPE_INT fills type_nochar (type.cc:3220-3221),
  // while the ASCII char-print TYPE_INT claims
  // typecache[1][TYPE_INT] (type.cc:3225-3229), so getBaseNoChar(1,
  // TYPE_INT) != getBase(1, TYPE_INT). The default (false) keeps the
  // original registration where no 1-byte INT core type exists at all and
  // type_nochar stays null (type.cc:3131) — getBaseNoChar falls through to
  // the plain base (type.cc:3624) and the two are the same pointer.
  FixtureArchitecture(bool char_core_types = false) {
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
    if (char_core_types) {
      types->setCoreType("signed_byte_custom",1,TYPE_INT,false);
      types->setCoreType("ascii_glyph_custom",1,TYPE_INT,true);
    }
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
    // BlockBasic index argument (same convention as cover_rebuild_1204).
    block->index = static_cast<int4>(blocks.size());
    blocks.push_back(block);
    return block;
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

  Varnode *inputReg(uintb offset, int4 size)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    return fd.setInputVarnode(vn);
  }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot) { fd.opSetInput(op, vn, slot); }

  Varnode *registerOut(int4 size, uintb offset, PcodeOp *op)
  {
    return fd.newVarnodeOut(size, Address(reg, offset), op);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block) { fd.opInsertEnd(op, block); }

  // Force the lazy cover build for observation (Varnode::getCover side
  // effect, varnode.hh:202), then render the CoverBlock map.
  static string endpoint(uintm value)
  {
    if (value == 0) return "b";
    if (value == ~((uintm)0)) return "e";
    return std::to_string(value);
  }

  static string coverText(Varnode *vn)
  {
    if (!vn->hasCover()) return "[nocover]";
    vn->updateCover();
    if (vn->cover == (Cover *)0) return "[null]";
    ostringstream out;
    out << '[';
    bool first = true;
    for (map<int4, CoverBlock>::const_iterator iter = vn->cover->begin();
         iter != vn->cover->end(); ++iter) {
      if (!first) out << ',';
      first = false;
      out << (*iter).first << ':'
          << endpoint(CoverBlock::getUIndex((*iter).second.getStart())) << '-'
          << endpoint(CoverBlock::getUIndex((*iter).second.getStop()));
    }
    out << ']';
    return out.str();
  }

  void observe(const string &caseName, const string &stage,
               const vector<string> &names, const vector<Varnode *> &vns)
  {
    ostringstream grouping;
    for (size_t i = 0; i < vns.size(); ++i) {
      if (i != 0) grouping << '/';
      grouping << vns[i]->getHigh()->numInstances();
    }
    ostringstream sameHigh;
    for (size_t i = 0; i < vns.size(); ++i) {
      for (size_t j = i + 1; j < vns.size(); ++j) {
        sameHigh << names[i] << names[j] << '='
                 << (vns[i]->getHigh() == vns[j]->getHigh() ? 1 : 0) << ',';
      }
    }
    string sameHighText = sameHigh.str();
    if (!sameHighText.empty()) sameHighText.pop_back();
    // Per-Varnode forced merge group (varnode.hh:186 getMergeGroup): the
    // speculative (merge.cc:1571 isspeculative=true) absorption moves the
    // absorbed members into separate merge classes (variable.cc:640-646),
    // which exposes both the survivor side and the class semantics.
    ostringstream groups;
    for (size_t i = 0; i < vns.size(); ++i) {
      if (i != 0) groups << '/';
      groups << names[i] << ':' << vns[i]->getMergeGroup();
    }
    ostringstream covers;
    for (size_t i = 0; i < vns.size(); ++i) {
      if (i != 0) covers << ' ';
      covers << names[i] << '=' << coverText(vns[i]);
    }
    cout << "case=" << caseName
         << "|stage=" << stage
         << "|instances=" << grouping.str()
         << "|groups=" << groups.str()
         << "|same_high=" << sameHighText
         << "|covers=" << covers.str() << '\n';
  }

  // The production Action sequence of coreaction.hh:5717/5718/5722/5726,
  // one persistent getMerge() object per Funcdata.
  void runActions(const string &caseName,
                  const vector<string> &names, const vector<Varnode *> &vns)
  {
    fd.setHighLevel(); // ActionAssignHigh (coreaction.hh:346)
    observe(caseName, "assignhigh", names, vns);
    { // ActionMergeRequired (coreaction.hh:369-370)
      fd.getMerge().mergeAddrTied();
      fd.getMerge().groupPartials();
      fd.getMerge().mergeMarker();
    }
    observe(caseName, "mergerequired", names, vns);
    { // ActionMergeCopy (coreaction.hh:392)
      fd.getMerge().mergeOpcode(CPUI_COPY);
    }
    observe(caseName, "mergecopy", names, vns);
    { // ActionMergeAdjacent (coreaction.hh:381)
      fd.getMerge().mergeAdjacent();
    }
    observe(caseName, "mergeadjacent", names, vns);
  }
};

void runCopyShadowLadder(FixtureArchitecture &arch)
{
  Graph g(arch, "copy_shadow_ladder", 0x7000);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0, b1);

  // b0: op1 vnP = COPY const
  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnP = g.registerOut(4, 0x10, op1);
  g.setInput(op1, g.constant(4, 0x11), 0);
  g.insertEnd(op1, b0);
  // b1: op2 vnQ1 = COPY vnP
  PcodeOp *op2 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnQ1 = g.registerOut(4, 0x20, op2);
  g.setInput(op2, vnP, 0);
  g.insertEnd(op2, b1);
  // b1: op3 vnQ2 = COPY vnP
  PcodeOp *op3 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnQ2 = g.registerOut(4, 0x30, op3);
  g.setInput(op3, vnP, 0);
  g.insertEnd(op3, b1);
  // b1: op4 tA = INT_ADD vnP, const   (keeps vnP live past op3)
  PcodeOp *op4 = g.makeOp(CPUI_INT_ADD, 2);
  Varnode *tA = g.registerOut(4, 0x40, op4);
  g.setInput(op4, vnP, 0);
  g.setInput(op4, g.constant(4, 1), 1);
  g.insertEnd(op4, b1);
  // b1: op5 tB = INT_ADD vnQ2, const  (last read of vnQ2)
  PcodeOp *op5 = g.makeOp(CPUI_INT_ADD, 2);
  Varnode *tB = g.registerOut(4, 0x50, op5);
  g.setInput(op5, vnQ2, 0);
  g.setInput(op5, g.constant(4, 2), 1);
  g.insertEnd(op5, b1);
  // b1: op6 tC = INT_ADD vnQ1, const  (last read of vnQ1, after vnQ2's)
  PcodeOp *op6 = g.makeOp(CPUI_INT_ADD, 2);
  Varnode *tC = g.registerOut(4, 0x60, op6);
  g.setInput(op6, vnQ1, 0);
  g.setInput(op6, g.constant(4, 3), 1);
  g.insertEnd(op6, b1);

  vector<string> names;
  names.push_back("P"); names.push_back("Q1"); names.push_back("Q2");
  names.push_back("tA"); names.push_back("tB"); names.push_back("tC");
  vector<Varnode *> vns;
  vns.push_back(vnP); vns.push_back(vnQ1); vns.push_back(vnQ2);
  vns.push_back(tA); vns.push_back(tB); vns.push_back(tC);
  g.runActions("copy_shadow_ladder", names, vns);
}

void runDisjointCopy(FixtureArchitecture &arch)
{
  Graph g(arch, "disjoint_copy", 0x7100);
  BlockBasic *b0 = g.makeBlock();
  // b0: op1 vnX = COPY const
  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnX = g.registerOut(4, 0x10, op1);
  g.setInput(op1, g.constant(4, 0x21), 0);
  g.insertEnd(op1, b0);
  // b0: op2 vnY = COPY vnX  (mergecopy candidate, no other reads)
  PcodeOp *op2 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnY = g.registerOut(4, 0x20, op2);
  g.setInput(op2, vnX, 0);
  g.insertEnd(op2, b0);

  vector<string> names;
  names.push_back("X");
  names.push_back("Y");
  vector<Varnode *> vns;
  vns.push_back(vnX);
  vns.push_back(vnY);
  g.runActions("disjoint_copy", names, vns);
}

// case_pipeline_tail: the same ladder graph driven through the full
// production tail of the merge family — assignhigh, mergerequired,
// mergecopy, mergeadjacent, then ActionMergeType's mergeByDatatype
// (coreaction.hh:414-415) — so the persistent channels must survive every
// Action boundary exactly as the single getMerge() object carries them.
void runPipelineTail(FixtureArchitecture &arch)
{
  Graph g(arch, "pipeline_tail", 0x7200);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0, b1);

  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnP = g.registerOut(4, 0x10, op1);
  g.setInput(op1, g.constant(4, 0x31), 0);
  g.insertEnd(op1, b0);
  PcodeOp *op2 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnQ1 = g.registerOut(4, 0x20, op2);
  g.setInput(op2, vnP, 0);
  g.insertEnd(op2, b1);
  PcodeOp *op3 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnQ2 = g.registerOut(4, 0x30, op3);
  g.setInput(op3, vnP, 0);
  g.insertEnd(op3, b1);
  PcodeOp *op4 = g.makeOp(CPUI_INT_ADD, 2);
  Varnode *tA = g.registerOut(4, 0x40, op4);
  g.setInput(op4, vnP, 0);
  g.setInput(op4, g.constant(4, 1), 1);
  g.insertEnd(op4, b1);
  PcodeOp *op5 = g.makeOp(CPUI_INT_ADD, 2);
  Varnode *tB = g.registerOut(4, 0x50, op5);
  g.setInput(op5, vnQ2, 0);
  g.setInput(op5, g.constant(4, 2), 1);
  g.insertEnd(op5, b1);
  PcodeOp *op6 = g.makeOp(CPUI_INT_ADD, 2);
  Varnode *tC = g.registerOut(4, 0x60, op6);
  g.setInput(op6, vnQ1, 0);
  g.setInput(op6, g.constant(4, 3), 1);
  g.insertEnd(op6, b1);

  vector<string> names;
  names.push_back("P"); names.push_back("Q1"); names.push_back("Q2");
  names.push_back("tA"); names.push_back("tB"); names.push_back("tC");
  vector<Varnode *> vns;
  vns.push_back(vnP); vns.push_back(vnQ1); vns.push_back(vnQ2);
  vns.push_back(tA); vns.push_back(tB); vns.push_back(tC);

  g.fd.setHighLevel();
  g.observe("pipeline_tail", "assignhigh", names, vns);
  {
    g.fd.getMerge().mergeAddrTied();
    g.fd.getMerge().groupPartials();
    g.fd.getMerge().mergeMarker();
  }
  g.observe("pipeline_tail", "mergerequired", names, vns);
  {
    g.fd.getMerge().mergeOpcode(CPUI_COPY);
  }
  g.observe("pipeline_tail", "mergecopy", names, vns);
  {
    g.fd.getMerge().mergeAdjacent();
  }
  g.observe("pipeline_tail", "mergeadjacent", names, vns);
  {
    // ActionMergeType (coreaction.hh:414-415)
    g.fd.getMerge().mergeByDatatype(g.fd.beginLoc(), g.fd.endLoc());
  }
  g.observe("pipeline_tail", "mergetype", names, vns);
}

// case_type_gate: pins the two merge.cc:1001 canonical-type-gate
// behaviors the round-3 review flagged. The INT_LEFT shift amount of the
// same size as the output (size 4 != 1) passes the gate — getBaseNoChar(4,
// INT) returns the same canonical entry as getBase(4, INT) (type.cc:3619-
// 3626) — and merges at mergeadjacent (boundary-only covers). The
// FLOAT_TRUNC input of the same size is REJECTED: typeop.cc:1913 declares
// (TYPE_INT, TYPE_FLOAT), so getBase(4,TYPE_INT) != getBase(4,TYPE_FLOAT).
void runTypeGate(FixtureArchitecture &arch)
{
  Graph g(arch, "type_gate", 0x7300);
  BlockBasic *b0 = g.makeBlock();

  Varnode *vnBig = g.inputReg(0x08, 8);
  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnSh = g.registerOut(4, 0x10, op1);
  g.setInput(op1, g.constant(4, 0x41), 0);
  g.insertEnd(op1, b0);
  PcodeOp *op2 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnF = g.registerOut(4, 0x18, op2);
  g.setInput(op2, g.constant(4, 0x42), 0);
  g.insertEnd(op2, b0);
  PcodeOp *op3 = g.makeOp(CPUI_INT_LEFT, 2);
  Varnode *tSh = g.registerOut(4, 0x30, op3);
  g.setInput(op3, vnBig, 0);
  g.setInput(op3, vnSh, 1);
  g.insertEnd(op3, b0);
  PcodeOp *op4 = g.makeOp(CPUI_FLOAT_TRUNC, 1);
  Varnode *tF = g.registerOut(4, 0x38, op4);
  g.setInput(op4, vnF, 0);
  g.insertEnd(op4, b0);

  vector<string> names;
  names.push_back("SH"); names.push_back("F"); names.push_back("TSH"); names.push_back("TF");
  vector<Varnode *> vns;
  vns.push_back(vnSh); vns.push_back(vnF); vns.push_back(tSh); vns.push_back(tF);
  g.runActions("type_gate", names, vns);
}

// case_float_trunc_cast: isolates the merge.cc:1001 FLOAT_TRUNC gate entry.
// The op is cast-shaped (same 4-byte size on input and output), so a wrong
// ctor-table pair like (TYPE_INT, TYPE_INT) would let the gate pass and TF
// would merge with F2 at mergeadjacent exactly like the control COPY pair
// SHX/C merges at mergecopy; with the locked pair (TYPE_INT, TYPE_FLOAT)
// (typeop.cc:1913) the gate rejects the pair and TF stays alone.
void runFloatTruncCast(FixtureArchitecture &arch)
{
  Graph g(arch, "float_trunc_cast", 0x7400);
  BlockBasic *b0 = g.makeBlock();

  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnShx = g.registerOut(4, 0x10, op1);
  g.setInput(op1, g.constant(4, 0x51), 0);
  g.insertEnd(op1, b0);
  PcodeOp *op2 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnF2 = g.registerOut(4, 0x18, op2);
  g.setInput(op2, g.constant(4, 0x52), 0);
  g.insertEnd(op2, b0);
  PcodeOp *op3 = g.makeOp(CPUI_FLOAT_TRUNC, 1);
  Varnode *tF = g.registerOut(4, 0x30, op3);
  g.setInput(op3, vnF2, 0);
  g.insertEnd(op3, b0);
  PcodeOp *op4 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnC = g.registerOut(4, 0x38, op4);
  g.setInput(op4, vnShx, 0);
  g.insertEnd(op4, b0);

  vector<string> names;
  names.push_back("SHX"); names.push_back("F2"); names.push_back("TF"); names.push_back("C");
  vector<Varnode *> vns;
  vns.push_back(vnShx); vns.push_back(vnF2); vns.push_back(tF); vns.push_back(vnC);
  g.runActions("float_trunc_cast", names, vns);
}

// case_char_gate_null / case_char_gate_char: the 1-byte Int char
// determination of type.cc:3619-3626. The same graph runs under two core-
// type registrations; only the INT_LEFT shift-amount slots observe the
// difference (typeop.cc:1513-1514 slot-1 getBaseNoChar):
//   - null world (no 1-byte INT core type): type_nochar stays null
//     (type.cc:3131), so getBaseNoChar(1,TYPE_INT) IS getBase(1,TYPE_INT)
//     (type.cc:3624) — the gate passes and T1 merges with its 1-byte shift
//     amount SH1, exactly like the 4-byte control T4/SH4.
//   - char world ("int1"+"char" registered, sleigh_arch.cc:204-241):
//     type_nochar = "int1" (type.cc:3220-3221) while typecache[1][INT] is
//     the ASCII "char" (type.cc:3228-3229), so the pointers differ — the
//     gate REJECTS the 1-byte pair (T1 stays alone) while the 4-byte
//     control T4/SH4 (getBaseNoChar(4,INT) == getBase(4,INT)) still merges.
void runCharGate(FixtureArchitecture &arch, const string &caseName, uintb base)
{
  Graph g(arch, caseName, base);
  BlockBasic *b0 = g.makeBlock();

  Varnode *vnBig = g.inputReg(0x08, 8);
  PcodeOp *op1 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnSh1 = g.registerOut(1, 0x10, op1);
  g.setInput(op1, g.constant(1, 0x61), 0);
  g.insertEnd(op1, b0);
  PcodeOp *op2 = g.makeOp(CPUI_COPY, 1);
  Varnode *vnSh4 = g.registerOut(4, 0x20, op2);
  g.setInput(op2, g.constant(4, 0x62), 0);
  g.insertEnd(op2, b0);
  PcodeOp *op3 = g.makeOp(CPUI_INT_LEFT, 2);
  Varnode *t1 = g.registerOut(1, 0x30, op3);
  g.setInput(op3, vnBig, 0);
  g.setInput(op3, vnSh1, 1);
  g.insertEnd(op3, b0);
  PcodeOp *op4 = g.makeOp(CPUI_INT_LEFT, 2);
  Varnode *t4 = g.registerOut(4, 0x38, op4);
  g.setInput(op4, vnBig, 0);
  g.setInput(op4, vnSh4, 1);
  g.insertEnd(op4, b0);

  vector<string> names;
  names.push_back("SH1"); names.push_back("T1"); names.push_back("SH4"); names.push_back("T4");
  vector<Varnode *> vns;
  vns.push_back(vnSh1); vns.push_back(t1); vns.push_back(vnSh4); vns.push_back(t4);
  g.runActions(caseName, names, vns);
}

} // namespace

int main()
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  try {
    FixtureArchitecture architecture;
    runCopyShadowLadder(architecture);
    runDisjointCopy(architecture);
    runPipelineTail(architecture);
    runTypeGate(architecture);
    runFloatTruncCast(architecture);
    runCharGate(architecture, "char_gate_null", 0x7500);
    FixtureArchitecture charArchitecture(true);
    runCharGate(charArchitecture, "char_gate_char", 0x7600);
  }
  catch(const LowlevelError &error) {
    cerr << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
