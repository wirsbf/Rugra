/*
 * MERGE-FORCEMERGE-PANIC-0001: locked Ghidra 12.0.4 oracle for the merge
 * action survival contract (coreaction.cc:5717-5727 / coreaction.hh:414).
 *
 * The regression: Rugra's ActionMergeType::apply used to call the legacy
 * Merge::merge_all monolith, which re-runs Merge::mergeAddrTied AFTER
 * ActionMarkImplied has set the implied flag, so Merge::mergeTestMust
 * (merge.cc:241-247) throws "Cannot force merge of range" for an implied
 * member of an address-tied exact-location range.  Ghidra never builds
 * that state: mergeAddrTied runs exactly once, inside ActionMergeRequired
 * (coreaction.cc:5718), which is sequenced BEFORE ActionMarkImplied
 * (:5720), and ActionMergeType (:5727) runs only
 * data.getMerge().mergeByDatatype(beginLoc,endLoc) (coreaction.hh:414).
 *
 * The fixture builds the raw universal Action tree through the production
 * ActionDatabase::universalAction, then drives the merge-group children
 * assignhigh..mergetype in tree order on a minimal Funcdata whose stack
 * address 0x100 holds two same-size written Varnodes created through the
 * raw bank (no property tail): a1 (COPY output) and s1 (SUBPIECE output
 * feeding INT_ADD).  The cluster is ungated at mergerequired, so the one
 * and only mergeAddrTied pass skips it; after markimplied marks s1
 * implied, the addrtied|mapped property is installed on a1 mid-sequence
 * (the arrival timing ActionDynamicSymbols' setSymbolProperties produces
 * in the real regression), and ActionMergeType must then still complete
 * without a LowlevelError: mergeByDatatype never calls mergeRangeMust.
 * Every act line records whether the oracle threw, so a Rugra panic or
 * re-entered mergeAddrTied shows up as an exc=/verdict= divergence.
 */

#include <bits/stdc++.h>

// Test-only access is required to read the Action executor statistics
// and to install the addrtied property flag the way queryProperties does
// for in-scope stack locals, matching what production reaches through the
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

  // Production newVarnodeOut creation (funcdata_varnode.cc:104, the
  // heritage.cc:440/461/485 creation path) with the queryProperties tail
  // result cleared, so neither member is addrtied at mergerequired time
  // (mirroring the raw-bank Rust creation path).  The addrtied|mapped
  // property arrives later (see the install step below), reproducing the
  // arrival timing of the real regression where the mapped addrtied
  // flag lands between markimplied and mergetype.
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
  std::cout << "schema=1|fixture=MERGE-FORCEMERGE-PANIC-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
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
    while (stop != children.end() && (*stop)->getName() != "mergetype")
      ++stop;
    if (start == children.end() || stop == children.end()) {
      std::cerr << "merge-group sequence missing\n";
      return 1;
    }
    ++stop; // mergetype inclusive
    std::ostringstream seq;
    bool first = true;
    for (std::vector<Action *>::iterator iter = start; iter != stop; ++iter) {
      if (!first) seq << ',';
      first = false;
      seq << (*iter)->getName();
    }
    std::cout << "seq=" << seq.str() << '\n';

    // Minimal Funcdata: stack address 0x100 holds two same-size written
    // Varnodes in one exact-location range: a1 (COPY output, addrtied) and
    // s1 (SUBPIECE output feeding INT_ADD).  a1's cover is its def point
    // only; s1's cover spans def..read; both are in one block with
    // r0 < r1 < r2, so the first (and only) mergeAddrTied force-merge
    // succeeds without intersection.
    Graph g(arch, "merge_forcepanic", 0x6000);
    BlockBasic *b0 = g.makeBlock();
    Datatype *ct4 = arch.types->getBase(4, TYPE_INT);

    Varnode *c4x = g.constant(4, 5);
    PcodeOp *r0 = g.makeOp("r0", CPUI_COPY, 1);
    g.setInput(r0, c4x, 0);
    Varnode *a1 = g.stackVarOut(4, 0x100, r0);
    a1->updateType(ct4);
    g.insertEnd(r0, b0);

    Varnode *c8a = g.constant(8, 0x11223344);
    PcodeOp *r1 = g.makeOp("r1", CPUI_SUBPIECE, 2);
    g.setInput(r1, c8a, 0);
    g.setInput(r1, g.constant(1, 0), 1);
    Varnode *s1 = g.stackVarOut(4, 0x100, r1);
    s1->updateType(ct4);
    g.insertEnd(r1, b0);

    PcodeOp *r2 = g.makeOp("r2", CPUI_INT_ADD, 2);
    g.setInput(r2, s1, 0);
    g.setInput(r2, g.constant(4, 7), 1);
    Varnode *t2 = g.fd.newUniqueOut(4, r2);
    t2->updateType(ct4);
    g.insertEnd(r2, b0);

    g.vnNames[a1] = "a1";
    g.vnNames[s1] = "s1";
    g.vnNames[t2] = "t2";
    g.vnOrder.push_back(a1);
    g.vnOrder.push_back(s1);
    g.vnOrder.push_back(t2);

    std::cout << "pre|" << g.irText() << '\n';

    // Drive the merge-group children through Action::perform in tree
    // order, catching the LowlevelError exits the way the console
    // decompiler boundary does.  Every act line must show exc=none on
    // the locked oracle: the only mergeAddrTied pass (inside
    // mergerequired, before markimplied) skips the ungated cluster, and
    // mergetype runs mergeByDatatype only, so the addrtied+implied
    // member never reaches mergeTestMust.
    const char *verdict = "PIPELINE-OK";
    std::vector<Action *>::iterator mid = start;
    while (mid != stop && (*mid)->getName() != std::string("mergeadjacent"))
      ++mid;
    for (std::vector<Action *>::iterator iter = start; iter != stop; ++iter) {
      if (iter == mid) {
        // Install the addrtied|mapped property on a1 mid-sequence,
        // exactly as ActionDynamicSymbols' setSymbolProperties lands it
        // between markimplied and mergeadjacent in the real pipeline
        // (the panic dump carries Varnode::mapped).  Both sides perform
        // the identical installation.
        a1->setFlags(Varnode::addrtied | Varnode::mapped);
        std::cout << "install=addrtied:mapped:a1\n";
      }
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
