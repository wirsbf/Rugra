/*
 * MERGE-ADDRTIED-GATES-0001: locked Ghidra 12.0.4 oracle for
 * Merge::mergeAddrTied (merge.cc:609-648).
 *
 * This fixture constructs real Funcdata, VarnodeBank, PcodeOp, Varnode,
 * HighVariable, VariablePiece, and VariableGroup objects.  Each case enters
 * through Funcdata::setHighLevel followed by Funcdata::getMerge().mergeAddrTied.
 * The output is a stable projection of the pre/post object graph; it never
 * substitutes a model of the merge algorithm for the production entry point.
 */

#include <bits/stdc++.h>

#define private public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "merge.hh"
#include "op.hh"
#include "space.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "variable.hh"
#include "varnode.hh"
#undef private

using namespace ghidra;
using std::cerr;
using std::cout;
using std::istringstream;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;

public:
  FixtureTranslate()
  {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new OtherSpace(this, this, OtherSpace::INDEX));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack =
        new SpacebaseSpace(this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stackPointer = {reg, 0, 8};
    addSpacebasePointer(stack, stackPointer, 8, true);
    insertSpace(new JoinSpace(this, this, 6));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummyRegister = {reg, 0, 8};
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override
  {
    return dummyRegister;
  }
  string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *, uintb, int4) const override
  {
    return "";
  }
  void getAllRegisters(map<VarnodeData, string> &) const override {}
  void getUserOpNames(vector<string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override
  {
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
  FixtureArchitecture()
  {
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
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
    istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const string &) const override {}
};

struct TrackedNode {
  string label;
  Varnode *vn;
  string cluster;
};

class Graph {
  int4 nextPc;
  BlockBasic *block;

public:
  Funcdata fd;
  AddrSpace *other;
  AddrSpace *unique;
  AddrSpace *ram;
  AddrSpace *reg;
  AddrSpace *stack;
  AddrSpace *join;
  vector<TrackedNode> nodes;

  Graph(FixtureArchitecture &arch, const string &name, uintb base)
      : nextPc(0), block((BlockBasic *)0),
        fd(name, name, arch.symboltab->getGlobalScope(),
           Address(arch.getSpace(3), base), (FunctionSymbol *)0, 0x100),
        other(arch.getSpace(1)), unique(arch.getSpace(2)), ram(arch.getSpace(3)),
        reg(arch.getSpace(4)), stack(arch.getSpace(5)), join(arch.getSpace(6))
  {
    BlockGraph &bgraph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    block = bgraph.newBlockBasic(&fd);
    block->index = 0;
  }

  Varnode *written(const string &label, AddrSpace *space, uintb offset, int4 size,
                   const string &cluster, bool addrTied, bool implied = false)
  {
    Address pc(ram, fd.getAddress().getOffset() + static_cast<uintb>(nextPc));
    nextPc += 1;
    PcodeOp *op = fd.newOp(1, pc);
    fd.opSetOpcode(op, CPUI_COPY);
    Varnode *vn = fd.newVarnodeOut(size, Address(space, offset), op);
    fd.opSetInput(op, fd.newConstant(size, static_cast<uintb>(nextPc)), 0);
    fd.opInsertEnd(op, block);
    if (addrTied)
      vn->setFlags(Varnode::addrtied);
    if (implied)
      vn->setImplied();
    nodes.push_back(TrackedNode{label, vn, cluster});
    return vn;
  }

  Varnode *input(const string &label, AddrSpace *space, uintb offset, int4 size,
                 const string &cluster, bool addrTied)
  {
    Varnode *vn = fd.newVarnode(size, Address(space, offset));
    vn = fd.setInputVarnode(vn);
    if (addrTied)
      vn->setFlags(Varnode::addrtied);
    nodes.push_back(TrackedNode{label, vn, cluster});
    return vn;
  }

  static string spaceTypeName(const AddrSpace *space)
  {
    switch (space->getType()) {
    case IPTR_PROCESSOR:
      return "processor";
    case IPTR_SPACEBASE:
      return "spacebase";
    case IPTR_INTERNAL:
      return "internal";
    case IPTR_CONSTANT:
      return "constant";
    case IPTR_JOIN:
      return "join";
    case IPTR_IOP:
      return "iop";
    case IPTR_FSPEC:
      return "fspec";
    default:
      return "other-type";
    }
  }

  static string hexOffset(uintb value)
  {
    ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
  }

  string labelOf(const Varnode *vn) const
  {
    for (const TrackedNode &node : nodes) {
      if (node.vn == vn)
        return node.label;
    }
    ostringstream out;
    out << "anon@" << vn->getSpace()->getIndex() << ':' << hexOffset(vn->getOffset())
        << ':' << vn->getSize();
    return out.str();
  }

  string nodesText(void) const
  {
    ostringstream out;
    for (size_t i = 0; i < nodes.size(); ++i) {
      const TrackedNode &node = nodes[i];
      const Varnode *vn = node.vn;
      if (i != 0)
        out << ',';
      out << node.label << '@' << vn->getSpace()->getIndex() << ':'
          << spaceTypeName(vn->getSpace()) << ':' << hexOffset(vn->getOffset())
          << ':' << vn->getSize() << ":f" << hexOffset(vn->getFlags()) << ":a"
          << (((vn->getFlags() & Varnode::addrtied) != 0) ? 1 : 0) << "i"
          << (vn->isInput() ? 1 : 0) << "w" << (vn->isWritten() ? 1 : 0)
          << "m" << (vn->isImplied() ? 1 : 0) << ':' << node.cluster;
    }
    return out.str();
  }

  string sameText(void) const
  {
    ostringstream out;
    bool first = true;
    for (size_t i = 0; i < nodes.size(); ++i) {
      for (size_t j = i + 1; j < nodes.size(); ++j) {
        if (!first)
          out << ';';
        first = false;
        out << nodes[i].label << '~' << nodes[j].label << '='
            << (nodes[i].vn->getHigh() == nodes[j].vn->getHigh() ? 1 : 0);
      }
    }
    return out.str();
  }

  string highsText(void) const
  {
    ostringstream out;
    for (size_t i = 0; i < nodes.size(); ++i) {
      if (i != 0)
        out << ';';
      HighVariable *high = nodes[i].vn->getHigh();
      out << nodes[i].label << '[';
      for (int4 j = 0; j < high->numInstances(); ++j) {
        if (j != 0)
          out << ',';
        out << labelOf(high->getInstance(j));
      }
      out << "]:hf" << hexOffset(high->highflags) << ":mc"
          << high->numMergeClasses << ":s" << (high->symbol == (Symbol *)0 ? 0 : 1);
    }
    return out.str();
  }

  string canonicalGroupLabel(const VariableGroup *group) const
  {
    string result;
    for (const TrackedNode &node : nodes) {
      HighVariable *high = node.vn->getHigh();
      if (high->piece == (VariablePiece *)0 || high->piece->getGroup() != group)
        continue;
      if (result.empty() || node.label < result)
        result = node.label;
    }
    return result.empty() ? "anon" : result;
  }

  string representativeName(const HighVariable *high) const
  {
    string result;
    for (int4 i = 0; i < high->numInstances(); ++i) {
      string label = labelOf(high->getInstance(i));
      if (result.empty() || label < result)
        result = label;
    }
    return result.empty() ? "anon" : result;
  }

  string orderedGroupText(const VariableGroup *group) const
  {
    vector<VariablePiece *> pieces;
    std::set<VariablePiece *> seen;
    for (const TrackedNode &node : nodes) {
      VariablePiece *piece = node.vn->getHigh()->piece;
      if (piece != (VariablePiece *)0 && piece->getGroup() == group &&
          seen.insert(piece).second)
        pieces.push_back(piece);
    }
    std::sort(pieces.begin(), pieces.end(), [](const VariablePiece *left,
                                                const VariablePiece *right) {
      if (left->getOffset() != right->getOffset())
        return left->getOffset() < right->getOffset();
      return left->getSize() < right->getSize();
    });
    ostringstream out;
    out << '[';
    bool first = true;
    for (VariablePiece *piece : pieces) {
      if (!first)
        out << ',';
      first = false;
      out << piece->getOffset() << ':' << piece->getSize() << ':'
          << representativeName(piece->getHigh());
    }
    out << ']';
    return out.str();
  }

  string piecesText(void) const
  {
    ostringstream out;
    for (size_t i = 0; i < nodes.size(); ++i) {
      if (i != 0)
        out << ';';
      HighVariable *high = nodes[i].vn->getHigh();
      VariablePiece *piece = high->piece;
      out << nodes[i].label << ':';
      if (piece == (VariablePiece *)0) {
        out << "-:" << nodes[i].vn->getSize() << ":-:-:-";
      }
      else {
        out << piece->getOffset() << ':' << piece->getSize() << ':'
            << piece->getGroup()->getSize() << ':'
            << canonicalGroupLabel(piece->getGroup()) << ':'
            << orderedGroupText(piece->getGroup());
      }
    }
    return out.str();
  }

  void observe(const string &caseName, const string &stage, const string &error) const
  {
    ostringstream topology;
    topology << "vn" << std::distance(fd.beginLoc(), fd.endLoc())
             << ":alive" << std::distance(fd.beginOpAlive(), fd.endOpAlive())
             << ":dead" << std::distance(fd.beginOpDead(), fd.endOpDead());
    cout << "case=" << caseName << "|stage=" << stage << "|error=" << error
         << "|topology=" << topology.str() << "|nodes=" << nodesText()
         << "|same=" << sameText()
         << "|highs=" << highsText() << "|pieces=" << piecesText() << '\n';
  }
};

// IPTR_PROCESSOR (register, ram, OTHER) and IPTR_SPACEBASE (stack) are
// processed.  IPTR_INTERNAL (unique) and IPTR_JOIN are skipped as whole
// spaces even when their first exact-location member carries ADDRTIED.
void runSpaceTypeGate(FixtureArchitecture &arch)
{
  Graph g(arch, "merge_addrtied_space_type_gate", 0x8100);
  g.written("R0", g.reg, 0x20, 4, "s0", true);
  g.written("R1", g.reg, 0x20, 4, "s0", false);
  g.written("M0", g.ram, 0x120, 4, "s1", true);
  g.written("M1", g.ram, 0x120, 4, "s1", false);
  g.written("O0", g.other, 0x220, 4, "s2", true);
  g.written("O1", g.other, 0x220, 4, "s2", false);
  g.written("S0", g.stack, 0x320, 4, "s3", true);
  g.written("S1", g.stack, 0x320, 4, "s3", false);
  g.written("U0", g.unique, 0x420, 4, "s4", true);
  g.written("U1", g.unique, 0x420, 4, "s4", false);
  g.written("J0", g.join, 0x520, 4, "s5", true);
  g.written("J1", g.join, 0x520, 4, "s5", false);

  g.fd.setHighLevel();
  g.observe("space_type_gate", "before", "none");
  g.fd.getMerge().mergeAddrTied();
  g.observe("space_type_gate", "after", "none");
}

// overlapLoc unions only the first Varnode flags from each exact (addr,size)
// run.  N has no ADDRTIED member.  L carries ADDRTIED only on its later SSA
// member, so neither exact run reaches mergeRangeMust.
void runAddrTiedFirstMemberGate(FixtureArchitecture &arch)
{
  Graph g(arch, "merge_addrtied_first_member_gate", 0x8200);
  g.written("N0", g.reg, 0x40, 4, "f0", false);
  g.written("N1", g.reg, 0x40, 4, "f0", false);
  g.written("L0", g.reg, 0x50, 4, "f1", false);
  g.written("L1", g.reg, 0x50, 4, "f1", true);

  g.fd.setHighLevel();
  g.observe("addrtied_first_member_gate", "before", "none");
  g.fd.getMerge().mergeAddrTied();
  g.observe("addrtied_first_member_gate", "after", "none");
}

// A[0,8] overlaps B[4,8], and B extends the inclusive maximum so C[10,2]
// joins the same maximal cluster.  D starts at byte 12 and is not pulled in.
// Every exact run has two SSA instances.  ADDRTIED on A's first member drives
// exact-run merges followed by mixed-size VariableGroup offsets 0/4/10.
void runTransitiveOverlapGroup(FixtureArchitecture &arch)
{
  Graph g(arch, "merge_addrtied_transitive_overlap", 0x8300);
  g.input("AI", g.reg, 0x100, 8, "c0", true);
  g.written("A0", g.reg, 0x100, 8, "c0", false);
  g.written("A1", g.reg, 0x100, 8, "c0", false);
  g.written("B0", g.reg, 0x104, 8, "c0", false);
  g.written("B1", g.reg, 0x104, 8, "c0", false);
  g.written("C0", g.reg, 0x10a, 2, "c0", false);
  g.written("C1", g.reg, 0x10a, 2, "c0", false);
  g.written("D0", g.reg, 0x10c, 2, "c1", false);
  g.written("D1", g.reg, 0x10c, 2, "c1", false);

  g.fd.setHighLevel();
  g.observe("transitive_overlap_group", "before", "none");
  g.fd.getMerge().mergeAddrTied();
  g.observe("transitive_overlap_group", "after", "none");
}

// mergeRangeMust validates each exact-run member in location order.  I0 is
// valid and survives; I1 is implied, so mergeTestMust throws the exact locked
// LowlevelError before the two HighVariables are combined.
void runForcedImpliedError(FixtureArchitecture &arch)
{
  Graph g(arch, "merge_addrtied_forced_implied", 0x8400);
  g.written("I0", g.reg, 0x180, 4, "e0", true);
  g.written("I1", g.reg, 0x180, 4, "e0", false, true);

  g.fd.setHighLevel();
  g.observe("forced_implied_error", "before", "none");
  string error = "none";
  try {
    g.fd.getMerge().mergeAddrTied();
  }
  catch (const LowlevelError &caught) {
    error = caught.explain;
  }
  g.observe("forced_implied_error", "after", error);
}

} // namespace

int main()
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  try {
    FixtureArchitecture architecture;
    runSpaceTypeGate(architecture);
    runAddrTiedFirstMemberGate(architecture);
    runTransitiveOverlapGroup(architecture);
    runForcedImpliedError(architecture);
  }
  catch (const LowlevelError &error) {
    cerr << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
