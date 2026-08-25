/*
 * GAPD-COUNTERS-1204: locked Ghidra 12.0.4 oracle for the two return-fold
 * chain counter gaps (TODO COREACTION-BASEEXPLICIT-NUMINST-0001 and
 * COREACTION-MARKIMPLIED-COUNT-0001).
 *
 * Contract under test:
 *
 *  (1) coreaction.cc:3020-3021 — ActionMarkExplicit::baseExplicit returns -1
 *      (explicit) for any member of a HighVariable holding more than one
 *      instance, BEFORE the addr-tied rule: a merged SSA version must not be
 *      inlined into a consumer.  The fixture force-merges a two-member
 *      exact-location stack cluster through the production mergerequired
 *      (mergeAddrTied) path, so at markexplicit both members share one
 *      2-instance HighVariable.  m1 carries NO property flags (no addrtied,
 *      no mapped) and has one descendant, so every other baseExplicit exit
 *      leaves it unmarked; ONLY the numInstances rule can mark it explicit.
 *
 *  (2) coreaction.cc:3434 + action.cc:362 — ActionMarkImplied::apply
 *      increments the inherited Action::count once per candidate popped from
 *      the DFS stack (each Varnode marked either explicit or implied) and
 *      returns 0; Action::perform returns the accumulated count.  The
 *      fixture observes the perform result directly (act=markimplied|res=N)
 *      plus the per-varnode post projection.
 *
 * Prestate: one block b0 with six ops in SeqNum order
 *   r0 m2 = COPY(9)        stack:0x200, addrtied (gates the cluster)
 *   r1 q2 = INT_ADD(m2,2)  unique, no descendants  -> explicit (hasNoDescend)
 *   r2 m1 = COPY(5)        stack:0x200, raw (property tail cleared)
 *   r3 q1 = INT_ADD(m1,1)  unique, no descendants  -> explicit (hasNoDescend)
 *   r4 z1 = INT_MULT(3,4)  unique, 1 descendant   -> implied candidate
 *   r5 w1 = INT_OR(z1,8)   unique, no descendants  -> explicit (hasNoDescend)
 * m2/m1 covers [r0..r1] / [r2..r3] are disjoint, so the forced merge
 * succeeds without snipping.  z1's def inputs are all constants, so
 * checkImpliedCover never consults a cover (cover-lazy-safe observation).
 * Expected: markexplicit res=5 (m2,m1,q2,q1,w1), markimplied res=1 (z1
 * implied); post hi=2 for both stack members, m1 ex=1 without at=1.
 */

#include <bits/stdc++.h>

// Test-only access is required to read the Action executor statistics and
// to install the addrtied property flag the way queryProperties does for
// in-scope stack locals, matching what production reaches through the
// console API.
#define private public
#define protected public
#include "architecture.hh"
#include "coreaction.hh"
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
#undef protected

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
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
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

class Graph {
public:
  Funcdata fd;
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *stack;
  std::map<Varnode *, std::string> vnNames;
  std::vector<Varnode *> vnOrder;
  int4 nextOffset;

  Graph(FixtureArchitecture &a, const std::string &name, uintb base)
    : fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), base),
         (FunctionSymbol *)0, 0x20),
      arch(a), ram(a.getSpace(3)), stack(a.getSpace(5)),
      nextOffset(0) {}

  // Production newVarnodeOut creation (funcdata_varnode.cc:104) with the
  // queryProperties tail result cleared, so neither member is addrtied or
  // mapped at creation (mirroring the raw-bank Rust creation path).  The
  // addrtied gate for the forced merge is installed explicitly on m2 below,
  // reproducing the production arrival of the property before the merge
  // group runs.
  Varnode *stackVarOut(int4 size, uintb offset, PcodeOp *op)
  {
    Varnode *vn = fd.newVarnodeOut(size, Address(stack, offset), op);
    vn->clearFlags(Varnode::addrtied | Varnode::mapped);
    return vn;
  }

  BlockBasic *makeBlock(void)
  {
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    // Production assigns FlowBlock::index via BlockGraph::findSpanningTree
    // reverse post-order (block.cc:1081), which this fixture does not run.
    // Assign creation-order indices as a deterministic, distinct precondition
    // matching the Rust comparand's explicit BlockBasic index argument.
    block->index = static_cast<int4>(fd.getBasicBlocks().getSize() - 1);
    return block;
  }

  PcodeOp *makeOp(const std::string &, OpCode opcode, int4 inputs)
  {
    Address pc(ram, fd.getAddress().getOffset() + (uintb)nextOffset);
    nextOffset += 1;
    PcodeOp *op = fd.newOp(inputs, pc);
    fd.opSetOpcode(op, opcode);
    return op;
  }

  Varnode *constant(int4 size, uintb value)
  {
    return fd.newConstant(size, value);
  }

  void setInput(PcodeOp *op, Varnode *vn, int4 slot)
  {
    fd.opSetInput(op, vn, slot);
  }

  void insertEnd(PcodeOp *op, BlockBasic *block)
  {
    fd.opInsertEnd(op, block);
  }

  std::string irText(void)
  {
    std::ostringstream vns;
    vns << '[';
    bool first = true;
    for (std::vector<Varnode *>::const_iterator iter = vnOrder.begin();
         iter != vnOrder.end(); ++iter) {
      Varnode *vn = *iter;
      if (!first) vns << ',';
      first = false;
      HighVariable *high = vn->high;
      vns << vnNames[vn]
          << ":in=" << (vn->isInput() ? 1 : 0)
          << ",wr=" << (vn->isWritten() ? 1 : 0)
          << ",ex=" << (vn->isExplicit() ? 1 : 0)
          << ",im=" << (vn->isImplied() ? 1 : 0)
          << ",at=" << (vn->isAddrTied() ? 1 : 0)
          << ",hi=" << (high != (HighVariable *)0 ? (int4)high->numInstances() : -1);
    }
    vns << ']';
    return "vns=" + vns.str();
  }
};

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=GAPD-COUNTERS-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;

    // Build the raw universal action tree exactly as production does
    // (architecture.cc:582-591 buildAction -> universalAction), then derive
    // a fully-populated root through the public group API so the merge
    // children are unfiltered (action.cc:391-406).
    arch.allacts.universalAction(&arch);
    const char *allmembers[] = {
      "base", "protorecovery", "protorecovery_a", "protorecovery_b",
      "deindirect", "localrecovery", "deadcode", "typerecovery",
      "stackptrflow", "blockrecovery", "stackvars", "deadcontrolflow",
      "switchnorm", "cleanup", "splitcopy", "splitpointer", "merge",
      "dynamic", "casts", "analysis", "fixateglobals", "fixateproto",
      "constsequence", "segment", "returnsplit", "nodejoin", "doubleload",
      "doubleprecis", "unreachable", "subvar", "floatprecision",
      "conditionalexe", "normalizebranches", "noproto", "normalanalysis",
      "siganalysis", (const char *)0 };
    arch.allacts.setGroup("all", allmembers);
    ActionGroup *root = (ActionGroup *)arch.allacts.setCurrent("all");
    std::vector<Action *> &children = root->list;
    std::vector<Action *>::iterator start = children.begin();
    while (start != children.end() && (*start)->getName() != "assignhigh")
      ++start;
    std::vector<Action *>::iterator stop = start;
    while (stop != children.end() && (*stop)->getName() != "markimplied")
      ++stop;
    if (start == children.end() || stop == children.end()) {
      std::cerr << "merge-group sequence missing\n";
      return 1;
    }
    ++stop; // markimplied inclusive
    std::ostringstream seq;
    bool first = true;
    for (std::vector<Action *>::iterator iter = start; iter != stop; ++iter) {
      if (!first) seq << ',';
      first = false;
      seq << (*iter)->getName();
    }
    std::cout << "seq=" << seq.str() << '\n';

    // Minimal Funcdata: stack address 0x200 holds two same-size written
    // Varnodes in one exact-location range: m2 (COPY output, addrtied gate)
    // and m1 (COPY output, raw).  m2 is created FIRST so its def SeqNum
    // sorts before m1's, keeping the cluster head the gated member on both
    // sides.  Covers [r0..r1] and [r2..r3] are disjoint, so the forced
    // mergeAddrTied pass at mergerequired builds the 2-instance HighVariable
    // without snipping.  z1 (INT_MULT of two constants, one descendant) is
    // the sole markimplied candidate.
    Graph g(arch, "gapd_counters", 0x6000);
    BlockBasic *b0 = g.makeBlock();
    Datatype *ct4 = arch.types->getBase(4, TYPE_INT);

    Varnode *c9 = g.constant(4, 9);
    PcodeOp *r0 = g.makeOp("r0", CPUI_COPY, 1);
    g.setInput(r0, c9, 0);
    Varnode *m2 = g.stackVarOut(4, 0x200, r0);
    m2->updateType(ct4);
    // Gate the exact-location cluster: the addrtied property production
    // installs on in-scope stack locals before the merge group runs.
    m2->setFlags(Varnode::addrtied);
    g.insertEnd(r0, b0);

    Varnode *c2 = g.constant(4, 2);
    PcodeOp *r1 = g.makeOp("r1", CPUI_INT_ADD, 2);
    g.setInput(r1, m2, 0);
    g.setInput(r1, c2, 1);
    Varnode *q2 = g.fd.newUniqueOut(4, r1);
    q2->updateType(ct4);
    g.insertEnd(r1, b0);

    Varnode *c5 = g.constant(4, 5);
    PcodeOp *r2 = g.makeOp("r2", CPUI_COPY, 1);
    g.setInput(r2, c5, 0);
    Varnode *m1 = g.stackVarOut(4, 0x200, r2);
    m1->updateType(ct4);
    g.insertEnd(r2, b0);

    Varnode *c1 = g.constant(4, 1);
    PcodeOp *r3 = g.makeOp("r3", CPUI_INT_ADD, 2);
    g.setInput(r3, m1, 0);
    g.setInput(r3, c1, 1);
    Varnode *q1 = g.fd.newUniqueOut(4, r3);
    q1->updateType(ct4);
    g.insertEnd(r3, b0);

    Varnode *c3 = g.constant(4, 3);
    Varnode *c4 = g.constant(4, 4);
    PcodeOp *r4 = g.makeOp("r4", CPUI_INT_MULT, 2);
    g.setInput(r4, c3, 0);
    g.setInput(r4, c4, 1);
    Varnode *z1 = g.fd.newUniqueOut(4, r4);
    z1->updateType(ct4);
    g.insertEnd(r4, b0);

    Varnode *c8 = g.constant(4, 8);
    PcodeOp *r5 = g.makeOp("r5", CPUI_INT_OR, 2);
    g.setInput(r5, z1, 0);
    g.setInput(r5, c8, 1);
    Varnode *w1 = g.fd.newUniqueOut(4, r5);
    w1->updateType(ct4);
    g.insertEnd(r5, b0);

    g.vnNames[m2] = "m2";
    g.vnNames[m1] = "m1";
    g.vnNames[q2] = "q2";
    g.vnNames[q1] = "q1";
    g.vnNames[z1] = "z1";
    g.vnNames[w1] = "w1";
    g.vnOrder.push_back(m2);
    g.vnOrder.push_back(m1);
    g.vnOrder.push_back(q2);
    g.vnOrder.push_back(q1);
    g.vnOrder.push_back(z1);
    g.vnOrder.push_back(w1);

    std::cout << "pre|" << g.irText() << '\n';

    // Drive the merge-group children assignhigh..markimplied through
    // Action::perform in tree order, catching the LowlevelError exits the
    // way the console decompiler boundary does.  The decisive observations
    // are act=markexplicit|res=5 (m2,m1,q2,q1,w1 — m1 via the numInstances
    // rule only) and act=markimplied|res=1 (z1 popped once and implied).
    const char *verdict = "PIPELINE-OK";
    for (std::vector<Action *>::iterator iter = start; iter != stop; ++iter) {
      Action *action = *iter;
      int4 res = 0;
      const char *exc = "none";
      try {
        res = action->perform(g.fd);
      }
      catch (LowlevelError &error) {
        exc = error.explain.c_str();
        verdict = "PIPELINE-THREW";
      }
      std::cout << "act=" << action->getName()
                << "|res=" << res
                << "|exc=" << exc << '\n';
      if (std::string(exc) != "none")
        break;
    }

    std::cout << "post|" << g.irText() << '\n';
    std::cout << "verdict=" << verdict << '\n';
  }
  catch (LowlevelError &error) {
    std::cerr << "fixture lowlevel error: " << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
