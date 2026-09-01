/* SUBFLOAT-TRANSFORM-RESIDUAL-0001: locked Ghidra 12.0.4 oracle fixture.
 *
 * Exercises the real RuleSubfloatConvert::applyOp (subflow.cc:3489-3507)
 * driving the full SubfloatFlow trace + TransformManager::apply
 * (subflow.cc:3070-3481, transform.cc:756-765) over non-constant and
 * constant FLOAT_FLOAT2FLOAT conversions:
 *   widen       — non-const 4->8 widening with a downstream FLOAT2FLOAT
 *                 terminator: op replaced by COPY of the preexisting 4-byte
 *                 input, terminator retargeted in place.
 *   narrow      — non-const 8->4 narrowing from an INT2FLOAT source with a
 *                 FLOAT_TRUNC terminator: INT2FLOAT replaced at precision 4,
 *                 narrowing FLOAT2FLOAT becomes a preexisting COPY.
 *   constNarrow — constant narrowing: the constant root never enters the
 *                 worklist (subflow.cc:3206-3212), doTrace's terminator
 *                 gate (cc:3479) rejects -> no change.
 *   constWidenNoTerm — constant widening whose widened output has no float
 *                 reader: no terminator is ever seen -> no change.
 *   constWiden  — constant widening with a downstream FLOAT2FLOAT
 *                 terminator: the constant is re-encoded (kept verbatim:
 *                 input size == precision, cc:3396-3397) and the conversion
 *                 folds through the transform.
 *   exceedBlock — FLOAT_ADD over two full-precision doubles feeding the
 *                 narrowing: maxPrecision (cc:3079-3175) reports 8 through
 *                 the COPY chain, exceedsPrecision (cc:3186) rejects.
 *   arithPass   — FLOAT_ADD over two FLOAT2FLOAT-widened 4-byte constants:
 *                 maxPrecision reports 4 through the FLOAT2FLOAT defs, the
 *                 add is rebuilt at precision 4 and both source conversions
 *                 collapse to COPYs.
 *   compareGuard— FLOAT_EQUAL over the traced lane and another widened
 *                 constant: preexistingGuard (transform.hh:246) accepts the
 *                 slot-0 visit and rejects the slot-1 revisit.
 *   repeatSlot  — FLOAT_EQUAL reading the same traced Varnode on both
 *                 slots: getRepeatSlot (op.cc:93-111) maps the second
 *                 descendant visit to input slot 1, which the guard rejects
 *                 so exactly one preexisting placeholder is built.
 */
#include "architecture.hh"
#include "capability.hh"
#include "float.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "subflow.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"

#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;

public:
  FixtureTranslate()
  {
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
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stackPointer;
    stackPointer.space = reg;
    stackPointer.offset = 0;
    stackPointer.size = 8;
    addSpacebasePointer(stack, stackPointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false,
                              8, 1, 6, AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummyRegister.space = reg;
    dummyRegister.offset = 0;
    dummyRegister.size = 8;
    /* SubfloatFlow resolves its precision format through
     * Translate::getFloatFormat (translate.cc:979-989), which scans the
     * floatformats vector; register IEEE754 single/double exactly like the
     * x86 spec so sizes 4/8 resolve and everything else returns NULL. */
    floatformats.push_back(FloatFormat(4));
    floatformats.push_back(FloatFormat(8));
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override {
    return dummyRegister;
  }
  string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
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
  FixtureArchitecture()
  {
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
    max_basetype_size = 10;
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

  void printMessage(const string &) const override {}
};

/* Full-IR projection over one basic block: ops in block order, each with
 * opcode/address/seqnum/liveness/parent/output/inputs, then every touched
 * varnode with create-index/size/space/constant-ness/free/input/written/
 * def/descendants, then the bank counters. Mirrors the Rust twin's
 * GraphProjection byte for byte. */
struct GraphProjection {
  vector<PcodeOp *> ops;
  map<PcodeOp *, int4> opIndex;
  vector<Varnode *> vars;
  map<Varnode *, int4> varIndex;

  explicit GraphProjection(BlockBasic *block)
  {
    for (list<PcodeOp *>::const_iterator iter = block->beginOp(); iter != block->endOp(); ++iter) {
      opIndex[*iter] = ops.size();
      ops.push_back(*iter);
    }
    for (vector<PcodeOp *>::const_iterator iter = ops.begin(); iter != ops.end(); ++iter) {
      PcodeOp *op = *iter;
      touch(op->getOut());
      for (int4 slot = 0; slot < op->numInput(); ++slot)
        touch(op->getIn(slot));
    }
  }

  void touch(Varnode *vn)
  {
    if (vn == (Varnode *)0 || varIndex.find(vn) != varIndex.end()) return;
    varIndex[vn] = vars.size();
    vars.push_back(vn);
  }

  string varName(Varnode *vn) const
  {
    if (vn == (Varnode *)0) return "_";
    map<Varnode *, int4>::const_iterator iter = varIndex.find(vn);
    if (iter == varIndex.end()) return "x";
    ostringstream out;
    out << 'v' << (*iter).second;
    return out.str();
  }

  string opName(PcodeOp *op) const
  {
    if (op == (PcodeOp *)0) return "_";
    map<PcodeOp *, int4>::const_iterator iter = opIndex.find(op);
    if (iter == opIndex.end()) return "x";
    ostringstream out;
    out << 'o' << (*iter).second;
    return out.str();
  }

  string render(const Funcdata *fd, BlockBasic *block) const
  {
    ostringstream out;
    out << "ops[";
    for (int4 i = 0; i < (int4)ops.size(); ++i) {
      if (i != 0) out << ';';
      PcodeOp *op = ops[i];
      out << 'o' << i << ':' << (int4)op->code()
          << "@" << op->getAddr().getOffset()
          << "/t" << op->getSeqNum().getTime()
          << "/r" << op->getSeqNum().getOrder()
          << "/d" << (op->isDead() ? 1 : 0)
          << "/p" << (op->getParent() == block ? block->getIndex() : -1)
          << "/o" << varName(op->getOut()) << "/i";
      for (int4 slot = 0; slot < op->numInput(); ++slot) {
        if (slot != 0) out << ',';
        out << varName(op->getIn(slot));
      }
    }
    out << "]vars[";
    for (int4 i = 0; i < (int4)vars.size(); ++i) {
      if (i != 0) out << ';';
      Varnode *vn = vars[i];
      out << 'v' << i << ":c" << vn->getCreateIndex()
          << "/s" << vn->getSize()
          << "/sp" << vn->getSpace()->getIndex()
          << "/k" << (vn->isConstant() ? 1 : 0);
      if (vn->isConstant()) out << ':' << vn->getOffset();
      out << "/f" << (vn->isFree() ? 1 : 0)
          << "/n" << (vn->isInput() ? 1 : 0)
          << "/w" << (vn->isWritten() ? 1 : 0)
          << "/d" << opName(vn->getDef()) << "/u";
      bool first = true;
      for (list<PcodeOp *>::const_iterator iter = vn->beginDescend(); iter != vn->endDescend(); ++iter) {
        if (!first) out << ',';
        first = false;
        out << opName(*iter);
      }
    }
    out << "]count=" << ops.size()
        << ',' << vars.size()
        << ',' << std::distance(fd->beginOpAlive(), fd->endOpAlive())
        << ',' << std::distance(fd->beginOpDead(), fd->endOpDead())
        << ',' << std::distance(fd->beginOpAll(), fd->endOpAll())
        << ',' << fd->numVarnodes();
    return out.str();
  }
};

string snapshot(const Funcdata *fd, BlockBasic *block)
{
  GraphProjection projection(block);
  return projection.render(fd, block);
}

/* Liveness projection of the fixture-built ops after the rule ran: the
 * block projection drops destroyed ops, so their dead flag is printed
 * separately (original build order). */
string origLiveness(const vector<PcodeOp *> &ops)
{
  ostringstream out;
  for (int4 i = 0; i < (int4)ops.size(); ++i) {
    if (i != 0) out << ',';
    out << 'o' << i << ':' << (ops[i]->isDead() ? 1 : 0);
  }
  return out.str();
}

struct Fixture {
  FixtureArchitecture *architecture;
  Funcdata *fd;
  BlockBasic *block;
  vector<PcodeOp *> built;

  Fixture(FixtureArchitecture *a, const char *name, uintb address)
      : architecture(a)
  {
    fd = new Funcdata(name, "", architecture->symboltab->getGlobalScope(),
                      Address(architecture->getSpace(3), address),
                      (FunctionSymbol *)0, 0);
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    block = graph.newBlockBasic(fd);
  }

  ~Fixture() { delete fd; }

  PcodeOp *outputOp(OpCode opcode, uintb pc, int4 outputSize)
  {
    Address address(fd->getArch()->getDefaultCodeSpace(), pc);
    PcodeOp *op = fd->newOp(1, address);
    fd->opSetOpcode(op, opcode);
    fd->newUniqueOut(outputSize, op);
    fd->opInsertEnd(op, block);
    built.push_back(op);
    return op;
  }

  PcodeOp *binaryOp(OpCode opcode, uintb pc, int4 outputSize)
  {
    Address address(fd->getArch()->getDefaultCodeSpace(), pc);
    PcodeOp *op = fd->newOp(2, address);
    fd->opSetOpcode(op, opcode);
    fd->newUniqueOut(outputSize, op);
    fd->opInsertEnd(op, block);
    built.push_back(op);
    return op;
  }

  void run(const char *label, PcodeOp *trigger)
  {
    string before = snapshot(fd, block);
    RuleSubfloatConvert rule("probe");
    int4 ret = rule.applyOp(trigger, *fd);
    string after = snapshot(fd, block);
    std::cout << label << "|ret=" << ret
              << "|irSame=" << ((before == after) ? 1 : 0)
              << "|orig=" << origLiveness(built)
              << "|before=" << before
              << "|after=" << after << '\n';
  }
};

void runWiden(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_widen", 0x1000);
  PcodeOp *copy = fixture.outputOp(CPUI_COPY, 0x5000, 4);
  fixture.fd->opSetInput(copy, fixture.fd->newConstant(4, 0x3F800000), 0);
  PcodeOp *widen = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 8);
  fixture.fd->opSetInput(widen, copy->getOut(), 0);
  PcodeOp *term = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5008, 4);
  fixture.fd->opSetInput(term, widen->getOut(), 0);
  fixture.run("widen", widen);
}

void runNarrow(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_narrow", 0x1100);
  PcodeOp *int2float = fixture.outputOp(CPUI_FLOAT_INT2FLOAT, 0x5000, 8);
  fixture.fd->opSetInput(int2float, fixture.fd->newConstant(8, 0x40000000), 0);
  PcodeOp *narrow = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 4);
  fixture.fd->opSetInput(narrow, int2float->getOut(), 0);
  PcodeOp *trunc = fixture.outputOp(CPUI_FLOAT_TRUNC, 0x5008, 8);
  fixture.fd->opSetInput(trunc, narrow->getOut(), 0);
  fixture.run("narrow", narrow);
}

void runConstNarrow(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_constnarrow", 0x1200);
  PcodeOp *narrow = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 4);
  fixture.fd->opSetInput(narrow, fixture.fd->newConstant(8, 0x3FF0000000000000LL), 0);
  PcodeOp *trunc = fixture.outputOp(CPUI_FLOAT_TRUNC, 0x5004, 8);
  fixture.fd->opSetInput(trunc, narrow->getOut(), 0);
  fixture.run("constNarrow", narrow);
}

void runConstWidenNoTerm(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_constwiden_noterm", 0x1300);
  PcodeOp *widen = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 8);
  fixture.fd->opSetInput(widen, fixture.fd->newConstant(4, 0x3F800000), 0);
  fixture.run("constWidenNoTerm", widen);
}

void runConstWiden(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_constwiden", 0x1400);
  PcodeOp *widen = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 8);
  fixture.fd->opSetInput(widen, fixture.fd->newConstant(4, 0x3F800000), 0);
  PcodeOp *term = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 4);
  fixture.fd->opSetInput(term, widen->getOut(), 0);
  fixture.run("constWiden", widen);
}

void runExceedBlock(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_exceed", 0x1500);
  PcodeOp *left = fixture.outputOp(CPUI_COPY, 0x5000, 8);
  fixture.fd->opSetInput(left, fixture.fd->newConstant(8, 0x3FF0000000000000LL), 0);
  PcodeOp *right = fixture.outputOp(CPUI_COPY, 0x5004, 8);
  fixture.fd->opSetInput(right, fixture.fd->newConstant(8, 0x4000000000000000LL), 0);
  PcodeOp *add = fixture.binaryOp(CPUI_FLOAT_ADD, 0x5008, 8);
  fixture.fd->opSetInput(add, left->getOut(), 0);
  fixture.fd->opSetInput(add, right->getOut(), 1);
  PcodeOp *narrow = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x500C, 4);
  fixture.fd->opSetInput(narrow, add->getOut(), 0);
  PcodeOp *trunc = fixture.outputOp(CPUI_FLOAT_TRUNC, 0x5010, 8);
  fixture.fd->opSetInput(trunc, narrow->getOut(), 0);
  fixture.run("exceedBlock", narrow);
}

void runArithPass(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_arithpass", 0x1600);
  PcodeOp *leftw = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 8);
  fixture.fd->opSetInput(leftw, fixture.fd->newConstant(4, 0x3F800000), 0);
  PcodeOp *rightw = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 8);
  fixture.fd->opSetInput(rightw, fixture.fd->newConstant(4, 0x40000000), 0);
  PcodeOp *add = fixture.binaryOp(CPUI_FLOAT_ADD, 0x5008, 8);
  fixture.fd->opSetInput(add, leftw->getOut(), 0);
  fixture.fd->opSetInput(add, rightw->getOut(), 1);
  PcodeOp *narrow = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x500C, 4);
  fixture.fd->opSetInput(narrow, add->getOut(), 0);
  PcodeOp *trunc = fixture.outputOp(CPUI_FLOAT_TRUNC, 0x5010, 8);
  fixture.fd->opSetInput(trunc, narrow->getOut(), 0);
  fixture.run("arithPass", narrow);
}

void runCompareGuard(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_compare", 0x1700);
  PcodeOp *copy = fixture.outputOp(CPUI_COPY, 0x5000, 4);
  fixture.fd->opSetInput(copy, fixture.fd->newConstant(4, 0x3F800000), 0);
  PcodeOp *widen = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5004, 8);
  fixture.fd->opSetInput(widen, copy->getOut(), 0);
  PcodeOp *otherw = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5008, 8);
  fixture.fd->opSetInput(otherw, fixture.fd->newConstant(4, 0x40400000), 0);
  PcodeOp *less = fixture.binaryOp(CPUI_FLOAT_LESS, 0x500C, 1);
  fixture.fd->opSetInput(less, widen->getOut(), 0);
  fixture.fd->opSetInput(less, otherw->getOut(), 1);
  fixture.run("compareGuard", widen);
}

void runRepeatSlot(FixtureArchitecture *architecture)
{
  Fixture fixture(architecture, "subfloat_repeat", 0x1800);
  PcodeOp *widen = fixture.outputOp(CPUI_FLOAT_FLOAT2FLOAT, 0x5000, 8);
  fixture.fd->opSetInput(widen, fixture.fd->newConstant(4, 0x3F800000), 0);
  PcodeOp *equal = fixture.binaryOp(CPUI_FLOAT_EQUAL, 0x5004, 1);
  fixture.fd->opSetInput(equal, widen->getOut(), 0);
  fixture.fd->opSetInput(equal, widen->getOut(), 1);
  fixture.run("repeatSlot", widen);
}

} // anonymous namespace

int main(void)
{
  std::cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  std::cout << "schema=1|fixture=SUBFLOAT-TRANSFORM-1204"
            << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    runWiden(&architecture);
    runNarrow(&architecture);
    runConstNarrow(&architecture);
    runConstWidenNoTerm(&architecture);
    runConstWiden(&architecture);
    runExceedBlock(&architecture);
    runArithPass(&architecture);
    runCompareGuard(&architecture);
    runRepeatSlot(&architecture);
  }
  catch (const LowlevelError &error) {
    std::cout << "exception|phase=run|what=" << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cout << "exception|phase=run|what=" << error.what() << '\n';
    return 1;
  }
  return 0;
}
