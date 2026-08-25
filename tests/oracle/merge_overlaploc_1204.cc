/*
 * MERGE-OVERLAPLOC-FLAGUNION-1204: locked Ghidra 12.0.4 oracle for the
 * overlapLoc flag-union gate semantics (TODO MERGE-OVERLAPLOC-FLAGUNION-0001).
 *
 * Contract under test (instrumented against the locked oracle):
 *
 *  (1) varnode.cc:1791-1819 VarnodeBank::overlapLoc — the uint4 flags
 *      return value is the union of getFlags() over the HEAD varnode of
 *      each visited exact-location run: the initial read (:1798) plus one
 *      OR per subsequent run head (:1813). The iterator jumps via
 *      endLoc(size,addr,written) (:1800/:1815) past EVERY same-location
 *      member, so later members of the same run NEVER contribute to the
 *      gate.
 *
 *  (2) merge.cc:629-643 Merge::mergeAddrTied — the cluster is gated by
 *      (flags & Varnode::addrtied) on that head-union. A cluster whose
 *      first run head is raw but whose SECOND run head (at an overlapping
 *      address) carries addrtied must still be force-merged: both runs go
 *      through unifyAddress + mergeRangeMust. A cluster whose ONLY
 *      addrtied varnode is a non-head same-location member must NOT be
 *      merged.
 *
 * Prestate (positive case "cross_run_head_union"): one block b0, ops in
 * SeqNum order
 *   r0 a = COPY(7)  stack:0x200 sz4, RAW head of run 1
 *   r1 b = COPY(5)  stack:0x200 sz4, addrtied (non-head member of run 1)
 *   r2 c = COPY(3)  stack:0x202 sz4, addrtied head of run 2 (overlaps
 *                    run 1's maxOff 0x203)
 * Expected: overlapLoc(a) flags include addrtied (from run head c);
 * mergeRangeMust merges run 1's members a+b into one 2-instance
 * HighVariable; run 2 holds c alone (1 instance); a.high == b.high,
 * a.high != c.high.
 *
 * Prestate (negative case "same_loc_later_member_no_gate"): one block b0
 *   r0 a = COPY(7)  stack:0x200 sz4, RAW head
 *   r1 b = COPY(5)  stack:0x200 sz4, addrtied (later member only)
 *   (no other run) Expected: gate fails, no merge; hi=1 for both.
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
  // queryProperties tail result cleared, so no member is addrtied or
  // mapped at creation (mirroring the raw-bank Rust creation path). The
  // addrtied gates are installed explicitly below, reproducing the
  // production arrival of the property before the merge group runs.
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

  std::string sameText(void)
  {
    std::ostringstream out;
    bool first = true;
    for (size_t i = 0; i < vnOrder.size(); ++i) {
      for (size_t j = i + 1; j < vnOrder.size(); ++j) {
        if (!first) out << ';';
        first = false;
        out << vnNames[vnOrder[i]] << '~' << vnNames[vnOrder[j]] << '='
            << (vnOrder[i]->high == vnOrder[j]->high ? 1 : 0);
      }
    }
    return "same=" + out.str();
  }
};

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=MERGE-OVERLAPLOC-FLAGUNION-1204|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;

    // Build the raw universal action tree exactly as production does
    // (coreaction.cc:5462 universalAction), then derive a fully-populated
    // root through the public group API so the merge children are
    // unfiltered (action.cc:391-406).
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

    // ---- Positive case: cross-run head union gates the cluster ----
    // a (raw head, run 1 @0x200), b (addrtied NON-head member of run 1),
    // c (addrtied head of run 2 @0x202, overlapping run 1's maxOff 0x203).
    // overlapLoc(a) unions a's raw flags with run-head c's addrtied at
    // varnode.cc:1813, so the cluster IS merged: run 1's a+b form one
    // 2-instance HighVariable; run 2's c stays separate.
    {
      Graph g(arch, "cross_run_head_union", 0x6000);
      BlockBasic *b0 = g.makeBlock();
      Datatype *ct4 = arch.types->getBase(4, TYPE_INT);

      Varnode *c7 = g.constant(4, 7);
      PcodeOp *r0 = g.makeOp("r0", CPUI_COPY, 1);
      g.setInput(r0, c7, 0);
      Varnode *a = g.stackVarOut(4, 0x200, r0);
      a->updateType(ct4);
      g.insertEnd(r0, b0);

      Varnode *c5 = g.constant(4, 5);
      PcodeOp *r1 = g.makeOp("r1", CPUI_COPY, 1);
      g.setInput(r1, c5, 0);
      Varnode *b = g.stackVarOut(4, 0x200, r1);
      b->updateType(ct4);
      b->setFlags(Varnode::addrtied); // non-head member gate (must NOT count)
      g.insertEnd(r1, b0);

      Varnode *c3 = g.constant(4, 3);
      PcodeOp *r2 = g.makeOp("r2", CPUI_COPY, 1);
      g.setInput(r2, c3, 0);
      Varnode *c = g.stackVarOut(4, 0x202, r2);
      c->updateType(ct4);
      c->setFlags(Varnode::addrtied); // run-2 head gate (must count)
      g.insertEnd(r2, b0);

      g.vnNames[a] = "a";
      g.vnNames[b] = "b";
      g.vnNames[c] = "c";
      g.vnOrder.push_back(a);
      g.vnOrder.push_back(b);
      g.vnOrder.push_back(c);

      std::cout << "case=cross_run_head_union|pre|" << g.irText() << '|' << g.sameText() << '\n';
      const char *verdict = "PIPELINE-OK";
      // rule_onceperfunc children latch status_end after the first perform
      // (action.cc:352-356); reset each child for this Funcdata exactly as
      // ActionRestartGroup::reset cascades (action.cc:408-416) so the
      // second case runs the real apply bodies.
      for (std::vector<Action *>::iterator iter = start; iter != stop; ++iter)
        (*iter)->reset(g.fd);
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
        std::cout << "case=cross_run_head_union|act=" << action->getName()
                  << "|res=" << res
                  << "|exc=" << exc << '\n';
        if (std::string(exc) != "none")
          break;
      }
      std::cout << "case=cross_run_head_union|post|" << g.irText() << '|' << g.sameText() << '\n';
      std::cout << "case=cross_run_head_union|verdict=" << verdict << '\n';
    }

    // ---- Negative case: same-location later member does NOT gate ----
    // a (raw head @0x200), b (addrtied later member @0x200, same run).
    // overlapLoc(a) never reads b's flags (the endLoc(written) jump at
    // varnode.cc:1800 skips every same-location member), so the gate
    // fails and NO merge happens.
    {
      Graph g(arch, "same_loc_later_member_no_gate", 0x7000);
      BlockBasic *b0 = g.makeBlock();
      Datatype *ct4 = arch.types->getBase(4, TYPE_INT);

      Varnode *c7 = g.constant(4, 7);
      PcodeOp *r0 = g.makeOp("r0", CPUI_COPY, 1);
      g.setInput(r0, c7, 0);
      Varnode *a = g.stackVarOut(4, 0x200, r0);
      a->updateType(ct4);
      g.insertEnd(r0, b0);

      Varnode *c5 = g.constant(4, 5);
      PcodeOp *r1 = g.makeOp("r1", CPUI_COPY, 1);
      g.setInput(r1, c5, 0);
      Varnode *b = g.stackVarOut(4, 0x200, r1);
      b->updateType(ct4);
      b->setFlags(Varnode::addrtied); // later member only — must NOT gate
      g.insertEnd(r1, b0);

      g.vnNames[a] = "a";
      g.vnNames[b] = "b";
      g.vnOrder.push_back(a);
      g.vnOrder.push_back(b);

      std::cout << "case=same_loc_later_member_no_gate|pre|" << g.irText() << '|' << g.sameText() << '\n';
      const char *verdict = "PIPELINE-OK";
      // Reset the latched status_end from the first case so every child
      // applies to this second, independent Funcdata.
      for (std::vector<Action *>::iterator iter = start; iter != stop; ++iter)
        (*iter)->reset(g.fd);
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
        std::cout << "case=same_loc_later_member_no_gate|act=" << action->getName()
                  << "|res=" << res
                  << "|exc=" << exc << '\n';
        if (std::string(exc) != "none")
          break;
      }
      std::cout << "case=same_loc_later_member_no_gate|post|" << g.irText() << '|' << g.sameText() << '\n';
      std::cout << "case=same_loc_later_member_no_gate|verdict=" << verdict << '\n';
    }
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
