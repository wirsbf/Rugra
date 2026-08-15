/*
 * PIPE-MERGETYPE-ORDER-0001: locked Ghidra 12.0.4 post-cleanup action
 * order oracle (coreaction.cc:5712-5738).
 *
 * The fixture builds the raw universal Action tree through the production
 * ActionDatabase::universalAction, enumerates the ordered child sequence
 * after the cleanup pool (the "prefercomplement" child through "stop"),
 * performs each child in tree order through Action::perform on a minimal
 * Funcdata holding two same-type input Varnodes whose disjoint-cover
 * speculative merge is only legal for ActionMergeType (mergeByDatatype),
 * and prints the per-child executor statistics together with the complete
 * IR projection before and after the sequence.  The byte-comparable
 * observation proves the merge happens exactly once, late in the sequence,
 * and is not masked by any dirty-flag shortcut.
 */

#include <bits/stdc++.h>

// Test-only access is required to read the Action executor statistics
// (count/lcount are protected) and the ActionDatabase root map, matching
// what production reaches through the console API.
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
  AddrSpace *reg;
  std::map<PcodeOp *, std::string> opNames;
  std::vector<PcodeOp *> opOrder;
  std::map<Varnode *, std::string> vnNames;
  std::vector<Varnode *> vnOrder;
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
    // reverse post-order (block.cc:1081), which this fixture does not run.
    // Assign creation-order indices as a deterministic, distinct precondition
    // matching the Rust comparand's explicit BlockBasic index argument.
    block->index = static_cast<int4>(fd.getBasicBlocks().getSize() - 1);
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

  Varnode *uniqueOut(const std::string &name, int4 size, PcodeOp *op)
  {
    Varnode *vn = fd.newUniqueOut(size, op);
    vnNames.insert(std::make_pair(vn, name));
    vnOrder.push_back(vn);
    return vn;
  }

  Varnode *constant(int4 size, uintb value)
  {
    return fd.newConstant(size, value);
  }

  Varnode *input(const std::string &name, uintb offset, int4 size)
  {
    Varnode *vn = fd.newVarnode(size, Address(reg, offset));
    vn = fd.setInputVarnode(vn);
    vnNames.insert(std::make_pair(vn, name));
    vnOrder.push_back(vn);
    return vn;
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
          << ",hi=" << (high != (HighVariable *)0 ? (int4)high->numInstances() : -1);
    }
    vns << ']';
    std::ostringstream ops;
    ops << '[';
    first = true;
    for (std::vector<PcodeOp *>::const_iterator iter = opOrder.begin();
         iter != opOrder.end(); ++iter) {
      PcodeOp *op = *iter;
      if (!first) ops << ',';
      first = false;
      ops << opNames[op] << '=' << get_opname(op->code())
          << '/' << op->getSeqNum().getOrder();
    }
    ops << ']';
    Varnode *t1 = vnOrder[0];
    Varnode *t2 = vnOrder[1];
    int4 pairTemps = 0;
    if (t1->high != (HighVariable *)0 && t1->high == t2->high)
      pairTemps = 1;
    return "vns=" + vns.str() + "|ops=" + ops.str() +
           "|merge_temps=" + std::to_string(pairTemps);
  }
};

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=PIPE-MERGETYPE-ORDER-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;

    // Build the raw universal action tree exactly as production does
    // (architecture.cc:582-591 buildAction → universalAction), then derive a
    // fully-populated root through the public group API: setGroup("all", ...)
    // lists every base group in the raw tree, so setCurrent("all") returns a
    // clone of universal with no child filtered (ActionGroup::clone keeps
    // order and nesting; action.cc:391-406).  This observes the raw
    // universal post-cleanup order, not the default decompile subset.
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
    while (start != children.end() && (*start)->getName() != "prefercomplement")
      ++start;
    if (start == children.end()) {
      std::cerr << "post-cleanup sequence missing\n";
      return 1;
    }
    std::ostringstream seq;
    bool first = true;
    for (std::vector<Action *>::iterator iter = start; iter != children.end(); ++iter) {
      if (!first) seq << ',';
      first = false;
      seq << (*iter)->getName();
    }
    std::cout << "seq=" << seq.str() << '\n';

    // Minimal Funcdata whose only legal speculative merge is the two
    // same-Datatype 8-byte written temporaries with disjoint covers.  The
    // temporaries are defined from constants so MergeAdjacent's
    // mergeTestBasic gate (merge.cc:255) rejects every input on both sides
    // without any size trick that would trigger cast insertion.
    Graph g(arch, "merge_order", 0x6000);
    BlockBasic *b0 = g.makeBlock();
    BlockBasic *b1 = g.makeBlock();
    BlockBasic *b2 = g.makeBlock();
    g.edge(b0, b1);
    g.edge(b0, b2);
    Datatype *ct8 = arch.types->getBase(8, TYPE_INT);
    Varnode *c8a = g.constant(8, 5);
    Varnode *c8b = g.constant(8, 7);
    PcodeOp *r1 = g.makeOp("r1", CPUI_INT_ADD, 2);
    g.setInput(r1, c8a, 0);
    g.setInput(r1, c8b, 1);
    Varnode *t1 = g.uniqueOut("t1", 8, r1);
    t1->updateType(ct8);
    g.insertEnd(r1, b1);
    PcodeOp *r2 = g.makeOp("r2", CPUI_INT_XOR, 2);
    g.setInput(r2, c8a, 0);
    g.setInput(r2, c8b, 1);
    Varnode *t2 = g.uniqueOut("t2", 8, r2);
    t2->updateType(ct8);
    g.insertEnd(r2, b2);

    std::cout << "pre|" << g.irText() << '\n';

    // Drive each post-cleanup child through Action::perform in tree order,
    // exactly as ActionGroup::apply does (action.cc:511-527).
    for (std::vector<Action *>::iterator iter = start; iter != children.end(); ++iter) {
      Action *action = *iter;
      int4 res = action->perform(g.fd);
      std::cout << "act=" << action->getName()
                << "|status=" << action->getStatus()
                << "|count=" << action->count
                << "|lcount=" << action->lcount
                << "|tests=" << action->getNumTests()
                << "|apply=" << action->getNumApply()
                << "|res=" << res << '\n';
    }

    std::cout << "post|" << g.irText() << '\n';
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
