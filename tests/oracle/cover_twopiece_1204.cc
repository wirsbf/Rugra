/*
 * COVER-TWOPIECE-RESIDUAL-0001: locked Ghidra 12.0.4 CoverBlock two-piece
 * (wrap-around) oracle.
 *
 * Part A drives CoverBlock directly (construct / merge / contain / boundary /
 * intersect) through every one-piece/two-piece quadrant of cover.cc:59-184,
 * including the pointer-identity discriminators Ghidra recovers from the raw
 * PcodeOp* (begin/end/input sentinels, MULTIEQUAL marker stops).  Part B
 * drives the production Varnode::updateCover -> Cover::rebuild path on
 * synthetic def-use/CFG graphs whose join-block MULTIEQUAL readers produce
 * the wrap-around state (ustop < ustart) of cover.cc:584-599, and one
 * production Cover::merge that unions a one-piece and a two-piece block.
 *
 * Endpoints are printed as pointer-identity classes: b (begin sentinel),
 * e (end sentinel), i (input sentinel), 0m (MULTIEQUAL marker op, getUIndex
 * collapses to 0), or the decimal SeqNum order of a real op.
 */

#include <bits/stdc++.h>

// Test-only access is required to read CoverBlock::start/stop and
// Varnode::cover directly, matching what production Ghidra reaches through
// friend-only APIs.
#define private public
#include "architecture.hh"
#include "cover.hh"
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

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                                   AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false, 8, 1, 4,
                                   AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1, 6,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummy_register.space = getSpace(4);
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
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
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const std::string &) const override {}
};

// Pointer-identity classification of a CoverBlock endpoint. The three
// Ghidra sentinels print b/e/i; a MULTIEQUAL marker prints 0m (getUIndex is
// 0 but the marker identity survives); every other op prints its SeqNum
// order (the getUIndex projection).
static std::string id(const PcodeOp *p)
{
  if (p == (const PcodeOp *)0) return "b";
  if (p == (const PcodeOp *)1) return "e";
  if (p == (const PcodeOp *)2) return "i";
  if (p->isMarker() && p->code() == CPUI_MULTIEQUAL)
    return std::to_string(CoverBlock::getUIndex(p)) + "m";
  return std::to_string(CoverBlock::getUIndex(p));
}

static std::string cbstate(const CoverBlock &cb)
{
  return id(cb.getStart()) + "-" + id(cb.getStop());
}

static std::string b01(int4 v)
{
  if (v == 0) return "0";
  if (v == 1) return "1";
  return "2";
}

class Graph {
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  std::map<PcodeOp *, std::string> opNames;
  std::vector<PcodeOp *> opOrder;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const std::string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), nextOffset(0) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    // Production assigns FlowBlock::index via BlockGraph::findSpanningTree
    // reverse post-order; creation-order indices are the deterministic
    // precondition shared with the Rust comparand (BLOCK-INDEX-ASSIGN-0001).
    block->index = static_cast<int4>(blocks.getSize()) - 1;
    return block;
  }

  void edge(BlockBasic *from, BlockBasic *to)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    blocks.addEdge(from, to);
  }

  PcodeOp *makeOp(const std::string &name, OpCode opcode, int4 inputs)
  {
    Address pc(ram, fd.getAddress().getOffset() + (uintb)nextOffset);
    nextOffset += 1;
    PcodeOp *op = fd.newOp(inputs, pc);
    fd.opSetOpcode(op, opcode);
    opNames.insert(std::make_pair(op, name));
    opOrder.push_back(op);
    return op;
  }

  Varnode *uniqueOut(int4 size, PcodeOp *op)
  {
    return fd.newUniqueOut(size, op);
  }

  Varnode *constant(int4 size, uintb value)
  {
    return fd.newConstant(size, value);
  }

  Varnode *input(const std::string &, uintb offset, int4 size)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    return fd.setInputVarnode(vn);
  }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot)
  {
    fd.opSetInput(op, vn, slot);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block)
  {
    fd.opInsertEnd(op, block);
  }

  std::string orders(void) const
  {
    std::ostringstream out;
    out << '[';
    bool first = true;
    for (std::vector<PcodeOp *>::const_iterator iter = opOrder.begin();
         iter != opOrder.end(); ++iter) {
      if (!first) out << ',';
      first = false;
      out << opNames.find(*iter)->second << '='
          << (*iter)->getSeqNum().getOrder();
    }
    out << ']';
    return out.str();
  }

  std::string coverText(Varnode *root)
  {
    if (root->cover == (Cover *)0)
      return "[null]";
    std::ostringstream out;
    out << '[';
    bool first = true;
    for (std::map<int4, CoverBlock>::const_iterator iter = root->cover->begin();
         iter != root->cover->end(); ++iter) {
      if (!first) out << ',';
      first = false;
      out << (*iter).first << ':' << cbstate((*iter).second);
    }
    out << ']';
    return out.str();
  }
};

// ---------------------------------------------------------------------------
// Part A: CoverBlock unit-level two-piece semantics.
// Five ordinary ops inserted into one block produce SeqNum orders 2..6.
// ---------------------------------------------------------------------------

struct PartA {
  Graph *g;
  PcodeOp *o2, *o3, *o4, *o5, *o6;

  PartA(Graph *graph) : g(graph) {
    BlockBasic *blk = g->makeBlock();
    o2 = g->makeOp("o2", CPUI_INT_ADD, 2);
    g->insertEnd(o2, blk);
    o3 = g->makeOp("o3", CPUI_INT_ADD, 2);
    g->insertEnd(o3, blk);
    o4 = g->makeOp("o4", CPUI_INT_ADD, 2);
    g->insertEnd(o4, blk);
    o5 = g->makeOp("o5", CPUI_INT_ADD, 2);
    g->insertEnd(o5, blk);
    o6 = g->makeOp("o6", CPUI_INT_ADD, 2);
    g->insertEnd(o6, blk);
  }

  // contain/boundary sampled at b (begin sentinel), 2..6 (real orders), and
  // e (end sentinel): the projection-domain values 0,2,3,4,5,6,~0.
  std::string containSamples(const CoverBlock &cb) const
  {
    std::ostringstream out;
    out << '[';
    out << "b:" << b01(cb.contain((const PcodeOp *)0) ? 1 : 0) << ',';
    out << "2:" << b01(cb.contain(o2) ? 1 : 0) << ',';
    out << "3:" << b01(cb.contain(o3) ? 1 : 0) << ',';
    out << "4:" << b01(cb.contain(o4) ? 1 : 0) << ',';
    out << "5:" << b01(cb.contain(o5) ? 1 : 0) << ',';
    out << "6:" << b01(cb.contain(o6) ? 1 : 0) << ',';
    out << "e:" << b01(cb.contain((const PcodeOp *)1) ? 1 : 0);
    out << ']';
    return out.str();
  }

  std::string boundarySamples(const CoverBlock &cb) const
  {
    std::ostringstream out;
    out << '[';
    out << "b:" << cb.boundary((const PcodeOp *)0) << ',';
    out << "2:" << cb.boundary(o2) << ',';
    out << "3:" << cb.boundary(o3) << ',';
    out << "4:" << cb.boundary(o4) << ',';
    out << "5:" << cb.boundary(o5) << ',';
    out << "6:" << cb.boundary(o6) << ',';
    out << "e:" << cb.boundary((const PcodeOp *)1) << ',';
    out << "i:" << cb.boundary((const PcodeOp *)2);
    out << ']';
    return out.str();
  }
};

static void runPartA(FixtureArchitecture &arch)
{
  {
    Graph g(arch, "a1_construct", 0x6000);
    PartA a(&g);
    CoverBlock cb;
    std::string fresh = cbstate(cb);
    std::string emptyFresh = b01(cb.empty() ? 1 : 0);
    cb.setBegin(a.o3);
    std::string afterBegin = cbstate(cb);
    cb.setEnd(a.o5);
    std::string afterEnd = cbstate(cb);
    std::cout << "case=a1_construct|orders=" << g.orders()
              << "|fresh=" << fresh << "|fresh_empty=" << emptyFresh
              << "|after_begin=" << afterBegin
              << "|after_end=" << afterEnd
              << "|contain=" << a.containSamples(cb)
              << "|boundary=" << a.boundarySamples(cb) << '\n';
  }
  {
    Graph g(arch, "a2_twopiece_construct", 0x6100);
    PartA a(&g);
    CoverBlock cb;
    cb.setBegin(a.o6);
    cb.setEnd(a.o2);
    std::cout << "case=a2_twopiece_construct|state=" << cbstate(cb)
              << "|empty=" << b01(cb.empty() ? 1 : 0)
              << "|contain=" << a.containSamples(cb)
              << "|boundary=" << a.boundarySamples(cb) << '\n';
  }
  {
    // Start is the begin sentinel: boundary at the sentinel uindex must NOT
    // report a defining point (pointer-level start != 0 test, cover.cc:137),
    // while the input sentinel block reports 2 for both uindex-0 probes.
    Graph g(arch, "a3_boundary_sentinels", 0x6200);
    PartA a(&g);
    CoverBlock cb;
    cb.setBegin((const PcodeOp *)0);
    cb.setEnd(a.o3);
    std::string beginStart = cbstate(cb);
    std::string bb = b01((int4)cb.boundary((const PcodeOp *)0));
    std::string bi = b01((int4)cb.boundary((const PcodeOp *)2));
    std::string b3 = b01((int4)cb.boundary(a.o3));
    CoverBlock inputBlock;
    inputBlock.setBegin((const PcodeOp *)2);
    inputBlock.setEnd((const PcodeOp *)2);
    std::string inputState = cbstate(inputBlock);
    std::string ib0 = b01((int4)inputBlock.boundary((const PcodeOp *)0));
    std::string ib2 = b01((int4)inputBlock.boundary((const PcodeOp *)2));
    std::string icontain = b01(inputBlock.contain((const PcodeOp *)0) ? 1 : 0);
    std::cout << "case=a3_boundary_sentinels|begin_start=" << beginStart
              << "|boundary_b=" << bb << "|boundary_i=" << bi
              << "|boundary_3=" << b3
              << "|input_state=" << inputState
              << "|input_boundary_b=" << ib0
              << "|input_boundary_i=" << ib2
              << "|input_contain_b=" << icontain << '\n';
  }
  {
    // Disjoint merge: one-piece [3,4] takes the two-piece [6,2]'s stop,
    // producing the wrap [3,2] (cover.cc:175-181).
    Graph g(arch, "a4_merge_disjoint_wrap", 0x6300);
    PartA a(&g);
    CoverBlock x;
    x.setBegin(a.o3);
    x.setEnd(a.o4);
    CoverBlock y;
    y.setBegin(a.o6);
    y.setEnd(a.o2);
    x.merge(y);
    std::cout << "case=a4_merge_disjoint_wrap|merged=" << cbstate(x)
              << "|empty=" << b01(x.empty() ? 1 : 0)
              << "|contain=" << a.containSamples(x)
              << "|boundary=" << a.boundarySamples(x) << '\n';
  }
  {
    // internal4 wrap: start at uindex 0 merging into a stop=end-sentinel
    // interval picks the other start and leaves stop -> [4,3] wrap.
    Graph g(arch, "a5_merge_internal4_wrap", 0x6400);
    PartA a(&g);
    CoverBlock x;
    x.setBegin((const PcodeOp *)0);
    x.setEnd(a.o3);
    CoverBlock y;
    y.setBegin(a.o4);
    y.setEnd((const PcodeOp *)1);
    std::string preX = cbstate(x);
    std::string preY = cbstate(y);
    x.merge(y);
    std::cout << "case=a5_merge_internal4_wrap|pre_x=" << preX
              << "|pre_y=" << preY
              << "|merged=" << cbstate(x)
              << "|empty=" << b01(x.empty() ? 1 : 0)
              << "|contain=" << a.containSamples(x) << '\n';
  }
  {
    // internal3 setAll: u2start==0 with this.stop==end sentinel and mutual
    // containment covers the entire block; equal-start mutual containment
    // keeps the wider interval.
    Graph g(arch, "a6_merge_setall", 0x6500);
    PartA a(&g);
    CoverBlock x;
    x.setBegin(a.o3);
    x.setEnd((const PcodeOp *)1);
    CoverBlock y;
    y.setBegin((const PcodeOp *)0);
    y.setEnd(a.o5);
    x.merge(y);
    std::string setAll = cbstate(x);
    CoverBlock p;
    p.setBegin(a.o2);
    p.setEnd(a.o6);
    CoverBlock q;
    q.setBegin(a.o2);
    q.setEnd(a.o4);
    p.merge(q);
    std::cout << "case=a6_merge_setall|setall=" << setAll
              << "|setall_contain=" << a.containSamples(x)
              << "|equal_start=" << cbstate(p) << '\n';
  }
  {
    // intersect quadrants (cover.cc:59-102).
    Graph g(arch, "a7_intersect_quadrants", 0x6600);
    PartA a(&g);
    CoverBlock x1; x1.setBegin(a.o3); x1.setEnd(a.o5);
    CoverBlock y1; y1.setBegin(a.o4); y1.setEnd(a.o6);
    CoverBlock x2; x2.setBegin(a.o3); x2.setEnd(a.o4);
    CoverBlock y2; y2.setBegin(a.o5); y2.setEnd(a.o6);
    CoverBlock x3; x3.setBegin(a.o3); x3.setEnd(a.o4);
    CoverBlock y3; y3.setBegin(a.o4); y3.setEnd(a.o6);
    CoverBlock x4; x4.setBegin(a.o3); x4.setEnd(a.o4);
    CoverBlock y4; y4.setBegin(a.o6); y4.setEnd(a.o2);
    CoverBlock x5; x5.setBegin(a.o2); x5.setEnd(a.o3);
    CoverBlock y5; y5.setBegin(a.o6); y5.setEnd(a.o2);
    CoverBlock x6; x6.setBegin(a.o5); x6.setEnd((const PcodeOp *)1);
    CoverBlock y6; y6.setBegin(a.o6); y6.setEnd(a.o2);
    CoverBlock x7; x7.setBegin(a.o6); x7.setEnd(a.o2);
    CoverBlock y7; y7.setBegin(a.o5); y7.setEnd(a.o3);
    std::cout << "case=a7_intersect_quadrants"
              << "|one_one_overlap=" << x1.intersect(y1)
              << "|one_one_disjoint=" << x2.intersect(y2)
              << "|one_one_touch=" << x3.intersect(y3)
              << "|one_two_gap=" << x4.intersect(y4)
              << "|one_two_touch=" << x5.intersect(y5)
              << "|one_two_interval=" << x6.intersect(y6)
              << "|two_two=" << x7.intersect(y7) << '\n';
  }
  {
    // Merging into an empty block copies the two-piece identity wholesale.
    Graph g(arch, "a8_merge_empty_copy", 0x6700);
    PartA a(&g);
    CoverBlock x;
    CoverBlock y;
    y.setBegin(a.o6);
    y.setEnd(a.o2);
    x.merge(y);
    std::cout << "case=a8_merge_empty_copy|merged=" << cbstate(x)
              << "|empty=" << b01(x.empty() ? 1 : 0)
              << "|contain=" << a.containSamples(x) << '\n';
  }
}

// ---------------------------------------------------------------------------
// Part B: production rebuild paths producing two-piece state.
// ---------------------------------------------------------------------------

static void runB1(FixtureArchitecture &arch, const char *name, uintb base,
                  bool withLateReader)
{
  Graph g(arch, name, base);
  BlockBasic *b0 = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0, b1);
  Varnode *c8 = g.constant(8, 5);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *d = g.makeOp("d", CPUI_COPY, 1);
  g.setInput(d, c8, 0);
  Varnode *root = g.uniqueOut(8, d);
  g.insertEnd(d, b1);
  PcodeOp *filler = g.makeOp("filler", CPUI_INT_ADD, 2);
  g.setInput(filler, c4, 0);
  g.setInput(filler, c4, 1);
  g.uniqueOut(4, filler);
  g.insertEnd(filler, b1);
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 2);
  g.setInput(m, root, 0);
  g.setInput(m, c4, 1);
  g.uniqueOut(8, m);
  g.insertEnd(m, b1);
  if (withLateReader) {
    PcodeOp *r2 = g.makeOp("r2", CPUI_INT_ADD, 2);
    g.setInput(r2, root, 0);
    g.setInput(r2, c4, 1);
    g.uniqueOut(8, r2);
    g.insertEnd(r2, b1);
  }
  root->calcCover();
  root->updateCover();
  std::cout << "case=" << name << "|orders=" << g.orders()
            << "|cover=" << g.coverText(root) << '\n';
}

static void runB3(FixtureArchitecture &arch)
{
  Graph g(arch, "b3_multiequal_tip_precise", 0x6a00);
  BlockBasic *b0a = g.makeBlock();
  BlockBasic *b0b = g.makeBlock();
  BlockBasic *b1 = g.makeBlock();
  g.edge(b0a, b1);
  g.edge(b0b, b1);
  Varnode *c8 = g.constant(8, 5);
  Varnode *c4 = g.constant(4, 7);
  Varnode *i0 = g.input("i0", 0x30, 4);
  PcodeOp *tdef = g.makeOp("tdef", CPUI_COPY, 1);
  g.setInput(tdef, c8, 0);
  Varnode *t1 = g.uniqueOut(8, tdef);
  g.insertEnd(tdef, b0a);
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 2);
  g.setInput(m, t1, 0);
  g.setInput(m, i0, 1);
  g.uniqueOut(8, m);
  g.insertEnd(m, b1);
  PcodeOp *r2 = g.makeOp("r2", CPUI_INT_ADD, 2);
  g.setInput(r2, i0, 0);
  g.setInput(r2, c4, 1);
  g.uniqueOut(8, r2);
  g.insertEnd(r2, b1);
  i0->calcCover();
  i0->updateCover();
  std::cout << "case=b3_multiequal_tip_precise|orders=" << g.orders()
            << "|cover=" << g.coverText(i0) << '\n';
}

static void runB4(FixtureArchitecture &arch)
{
  Graph g(arch, "b4_merge_wrap_internal", 0x6b00);
  // The MULTIEQUAL lives in a block that must have an in-edge: its slot
  // recursion reads bl->getIn(slot), so the join block cannot be the entry.
  BlockBasic *bEntry = g.makeBlock();
  BlockBasic *b0 = g.makeBlock();
  g.edge(bEntry, b0);
  Varnode *c8 = g.constant(8, 5);
  Varnode *c4 = g.constant(4, 7);
  PcodeOp *dA = g.makeOp("dA", CPUI_COPY, 1);
  g.setInput(dA, c8, 0);
  Varnode *vA = g.uniqueOut(8, dA);
  g.insertEnd(dA, b0);
  PcodeOp *dB = g.makeOp("dB", CPUI_COPY, 1);
  g.setInput(dB, c8, 0);
  Varnode *vB = g.uniqueOut(8, dB);
  g.insertEnd(dB, b0);
  PcodeOp *m = g.makeOp("m", CPUI_MULTIEQUAL, 2);
  g.setInput(m, vB, 0);
  g.setInput(m, c4, 1);
  g.uniqueOut(8, m);
  g.insertEnd(m, b0);
  vA->calcCover();
  vA->updateCover();
  vB->calcCover();
  vB->updateCover();
  std::string coverA = g.coverText(vA);
  std::string coverB = g.coverText(vB);
  // Production Cover::merge (variable.cc internal-cover union path).
  vA->cover->merge(*vB->cover);
  std::cout << "case=b4_merge_wrap_internal|orders=" << g.orders()
            << "|cover_a=" << coverA << "|cover_b=" << coverB
            << "|merged=" << g.coverText(vA) << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=COVER-TWOPIECE-RESIDUAL-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    runPartA(arch);
    runB1(arch, "b1_wrap_join_multiequal_reader", 0x6800, false);
    runB1(arch, "b2_wrap_then_contained_reader", 0x6900, true);
    runB3(arch);
    runB4(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
