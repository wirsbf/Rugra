/* INFERTYPES-CALLINPUT-LOCAL-0001 (TYPEOP-LOCALTYPE-DISPATCH-0001 D2):
 * locked Ghidra 12.0.4 oracle for the CALL/CALLIND input local-type seeding
 * inside ActionInferTypes::buildLocaltypes, exercised through the production
 * pipeline (startTypeRecovery + ActionInferTypes::apply x2) and through the
 * production TypeOp local dispatch (PcodeOp::inputTypeLocal).
 *
 * Case matrix (B5-D2 design):
 *   C1  CALL param0 locked int4, 4-byte argument          -> int4 seed
 *   C2  CALL param0 locked int8, 4-byte argument          -> size gate rejects (unknown4)
 *   C3  CALL param0 unlocked "this" pointer (ptr->struct) -> this-pointer seed
 *   C4  CALL param0 locked void                           -> void gate rejects (unknown4)
 *   C5  CALLIND param0 locked int8, 4-byte argument       -> no size gate (asymmetry), int8 seed
 *   C5S0 CALLIND slot 0                                   -> code pointer local
 *   C6  argument feeds locked-ptr CALL (C6A) then locked-uint8 CALL (C6B)
 *                                                          -> typeOrder-min merge
 *   C7  stop-up chain                                     -> UNTESTED (out of D2 lease)
 *   C8  CALL param0 completely unlocked                   -> canonical UNKNOWN base
 *   OUT1 C1 output with type-locked callspec output       -> locked output seed
 */
#include <bits/stdc++.h>

#include "architecture.hh"
#include "capability.hh"
#include "coreaction.hh"
#include "database.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"

using namespace std;
using namespace ghidra;

namespace fixture_access {

template <typename Tag>
struct Result {
  static typename Tag::type ptr;
};
template <typename Tag>
typename Tag::type Result<Tag>::ptr;

template <typename Tag, typename Tag::type member>
struct Init {
  static const int value;
};
template <typename Tag, typename Tag::type member>
const int Init<Tag, member>::value = (Result<Tag>::ptr = member, 0);

struct QlstTag { typedef vector<FuncCallSpecs *> Funcdata::* type; };

}  // namespace fixture_access

template struct fixture_access::Init<fixture_access::QlstTag, &Funcdata::qlst>;

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
    // Architecture::restoreFromSpec inserts the FSPEC space separately from
    // copySpaces (architecture.cc:632); the callspec annotation varnodes
    // created by Funcdata::newVarnodeCallSpecs resolve their space through
    // glb->getFspecSpace(), so the fixture must install it too.
    insertSpace(new FspecSpace(this, fixtureTranslate, numSpaces()));
    max_basetype_size = 10;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
    // Install the x86-64-gcc-style <size_alignment_map> (entries 1,2,4,8,16;
    // index 0 stays -1 exactly like TypeFactory::decodeAlignmentMap,
    // type.cc:4619-4641). The setupSizes default map's alignMap[0]=0 divides
    // by zero on the first size-0 structure canonicalization
    // (getPrimitiveAlignSize, type.cc:3312-3320), so the decoded map replaces
    // it — mirroring the Rugra comparand's factory bootstrap.
    {
      istringstream organizationStream(
          "<data_organization>"
          "<size_alignment_map>"
          "<entry size=\"1\" alignment=\"1\"/>"
          "<entry size=\"2\" alignment=\"2\"/>"
          "<entry size=\"4\" alignment=\"4\"/>"
          "<entry size=\"8\" alignment=\"8\"/>"
          "<entry size=\"16\" alignment=\"16\"/>"
          "</size_alignment_map>"
          "</data_organization>");
      XmlDecode organizationDecoder(this);
      organizationDecoder.ingestStream(organizationStream);
      types->decodeDataOrganization(organizationDecoder);
    }
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

namespace {

string metaName(const Datatype *type)
{
  string result;
  metatype2string(type->getMetatype(), result);
  return result;
}

string typeToken(const Datatype *type)
{
  if (type == (Datatype *)0) return "null";
  return metaName(type) + std::to_string(type->getSize());
}

ParameterPieces pieces(AddrSpace *space, uintb offset, Datatype *type, uint4 flags)
{
  ParameterPieces result;
  result.addr = Address(space, offset);
  result.type = type;
  result.flags = flags;
  return result;
}

struct Observed {
  string label;
  Varnode *vn;
};

string typeSnapshot(const vector<Observed> &cells)
{
  ostringstream stream;
  for (size_t index = 0; index < cells.size(); ++index) {
    if (index != 0) stream << ',';
    stream << cells[index].label << ':' << typeToken(cells[index].vn->getType());
  }
  return stream.str();
}

string sameBefore(const vector<Observed> &cells, const vector<Datatype *> &before)
{
  ostringstream stream;
  for (size_t index = 0; index < cells.size(); ++index) {
    if (index != 0) stream << ',';
    stream << cells[index].label << ':'
           << (cells[index].vn->getType() == before[index] ? 1 : 0);
  }
  return stream.str();
}

vector<Datatype *> snapshotTypes(const vector<Observed> &cells)
{
  vector<Datatype *> result;
  for (size_t index = 0; index < cells.size(); ++index)
    result.push_back(cells[index].vn->getType());
  return result;
}

bool callspecsResolve(const vector<pair<PcodeOp *, FuncCallSpecs *> > &sites,
                      const Funcdata &fd)
{
  for (size_t index = 0; index < sites.size(); ++index) {
    if (fd.getCallSpecs(sites[index].first) != sites[index].second) return false;
  }
  return true;
}

string opLabel(const map<const PcodeOp *, string> &labels, const PcodeOp *op)
{
  map<const PcodeOp *, string>::const_iterator found = labels.find(op);
  if (found == labels.end()) return "?";
  return found->second;
}

string descendantOrder(const map<const PcodeOp *, string> &labels, const Varnode *source)
{
  ostringstream stream;
  bool first = true;
  for (list<PcodeOp *>::const_iterator iter = source->beginDescend();
       iter != source->endDescend(); ++iter) {
    if (!first) stream << ',';
    first = false;
    stream << opLabel(labels, *iter);
  }
  return stream.str();
}

string blockOrder(const map<const PcodeOp *, string> &labels, const BlockBasic *block)
{
  ostringstream stream;
  bool first = true;
  for (list<PcodeOp *>::const_iterator iter = block->beginOp();
       iter != block->endOp(); ++iter) {
    if (!first) stream << ',';
    first = false;
    stream << opLabel(labels, *iter);
  }
  return stream.str();
}

string defToken(const Varnode *vn)
{
  const PcodeOp *def = vn->getDef();
  return (def == (const PcodeOp *)0) ? "input" : "def";
}

string probeToken(PcodeOp *op, int4 slot, const Datatype *expected)
{
  const Datatype *actual = op->inputTypeLocal(slot);
  ostringstream stream;
  stream << typeToken(actual) << '/' << (actual == expected ? 1 : 0);
  return stream.str();
}

}  // namespace

int main(void)
{
  cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  cout << "schema=1|fixture=INFERTYPES-CALLINPUT-LOCAL-0001"
       << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    AddrSpace *reg = architecture.getSpace(4);
    Scope *global = architecture.symboltab->getGlobalScope();
    Funcdata fd("callinput_fixture", "callinput_fixture", global,
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x40);
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    fd.setBasicBlockRange(block, Address(ram, 0x5000), Address(ram, 0x5020));
    vector<FuncCallSpecs *> &qlst =
        fd.*fixture_access::Result<fixture_access::QlstTag>::ptr;

    Datatype *voidType = architecture.types->getTypeVoid();
    Datatype *int4Type = architecture.types->getBase(4, TYPE_INT);
    Datatype *int8Type = architecture.types->getBase(8, TYPE_INT);
    Datatype *uint8Type = architecture.types->getBase(8, TYPE_UINT);
    Datatype *unknown4Type = architecture.types->getBase(4, TYPE_UNKNOWN);
    TypeStruct *objectType = architecture.types->getTypeStruct("FixtureObject");
    Datatype *objectPointer = architecture.types->getTypePointer(8, objectType, 1);
    Datatype *codePointer = architecture.types->getTypePointer(
        8, architecture.types->getTypeCode(), 1);

    map<const PcodeOp *, string> opLabels;
    vector<pair<PcodeOp *, FuncCallSpecs *> > sites;

    // makeCall: one CALL op with a fresh 1-argument input varnode, a spec
    // whose param0 carries the given type/flags, all registered in qlst.
    // Mirror of tests/oracle/callspec_identity_lifecycle_1204.cc:120-131.
    struct CallResult { PcodeOp *op; FuncCallSpecs *spec; Varnode *arg; };
    auto makeCall = [&](const string &label, int4 argSize, uintb argOffset,
                        Datatype *paramType, uint4 paramFlags,
                        Varnode *sharedArg = (Varnode *)0) -> CallResult {
      static int site = 0;
      PcodeOp *op = fd.newOp(2, Address(ram, 0x5010 + site));
      site += 1;
      fd.opSetOpcode(op, CPUI_CALL);
      Varnode *arg = sharedArg;
      if (arg == (Varnode *)0) {
        arg = fd.newVarnode(argSize, Address(reg, argOffset));
        fd.setInputVarnode(arg);
      }
      fd.opSetInput(op, arg, 1);
      // FuncCallSpecs(PcodeOp*) reads in(0) as the direct-call entry
      // (fspec.cc:4933-4941), so bind a code ref first — the same
      // construction order as callspec_identity_lifecycle_1204.cc:123-127.
      fd.opSetInput(op, fd.newCodeRef(Address(ram, 0x9000 + site)), 0);
      FuncCallSpecs *spec = new FuncCallSpecs(op);
      // setInternal allocates the ProtoStore setParam/setOutput write into
      // (fspec.cc:3746) and installs the void output, matching the pinned D1
      // fixture's construction.
      spec->setInternal(architecture.defaultfp, voidType);
      spec->setParam(0, "param0", pieces(reg, 0x0, paramType, paramFlags));
      qlst.push_back(spec);
      fd.opSetInput(op, fd.newVarnodeCallSpecs(spec), 0);
      fd.opInsertEnd(op, block);
      opLabels[op] = label;
      sites.push_back(make_pair(op, spec));
      return CallResult{op, spec, arg};
    };

    CallResult c1 = makeCall("C1", 4, 0x400, int4Type, ParameterPieces::typelock);
    // C1 output: type-locked callspec output seeds the CALL output varnode.
    Varnode *out1 = fd.newUniqueOut(8, c1.op);
    c1.spec->setOutput(pieces(reg, 0x0, objectPointer, ParameterPieces::typelock));

    CallResult c2 = makeCall("C2", 4, 0x410, int8Type, ParameterPieces::typelock);
    CallResult c3 = makeCall("C3", 8, 0x420, objectPointer, ParameterPieces::isthis);
    CallResult c4 = makeCall("C4", 4, 0x430, voidType, ParameterPieces::typelock);

    // C5: CALLIND — spec resolved through Funcdata::getCallSpecs(op), input 0
    // is the real code-pointer varnode (no fspec annotation).
    PcodeOp *op5 = fd.newOp(2, Address(ram, 0x5020));
    fd.opSetOpcode(op5, CPUI_CALLIND);
    Varnode *p5 = fd.newVarnode(8, Address(reg, 0x440));
    fd.setInputVarnode(p5);
    fd.opSetInput(op5, p5, 0);
    Varnode *a5 = fd.newVarnode(4, Address(reg, 0x450));
    fd.setInputVarnode(a5);
    fd.opSetInput(op5, a5, 1);
    FuncCallSpecs *spec5 = new FuncCallSpecs(op5);
    spec5->setInternal(architecture.defaultfp, voidType);
    spec5->setParam(0, "param0", pieces(reg, 0x0, int8Type, ParameterPieces::typelock));
    qlst.push_back(spec5);
    fd.opInsertEnd(op5, block);
    opLabels[op5] = "C5";
    sites.push_back(make_pair(op5, spec5));

    CallResult c6a = makeCall("C6A", 8, 0x460, objectPointer, ParameterPieces::typelock);
    // C6B reuses C6A's argument varnode: the shared argument feeds both
    // calls, C6A bound first so the descendant order is C6A,C6B.
    CallResult c6b = makeCall("C6B", 8, 0x460, uint8Type, ParameterPieces::typelock,
                              c6a.arg);
    (void)c6b;

    CallResult c8 = makeCall("C8", 4, 0x470, int4Type, 0);

    vector<Observed> cells;
    cells.push_back(Observed{"A1", c1.arg});
    cells.push_back(Observed{"A2", c2.arg});
    cells.push_back(Observed{"A3", c3.arg});
    cells.push_back(Observed{"A4", c4.arg});
    cells.push_back(Observed{"A5", a5});
    cells.push_back(Observed{"P5", p5});
    cells.push_back(Observed{"A6", c6a.arg});
    cells.push_back(Observed{"A8", c8.arg});
    cells.push_back(Observed{"OUT1", out1});

    string order = blockOrder(opLabels, block);
    string a6Descendants = descendantOrder(opLabels, c6a.arg);
    ostringstream defs;
    for (size_t index = 0; index < cells.size(); ++index) {
      if (index != 0) defs << ',';
      defs << cells[index].label << ':' << defToken(cells[index].vn);
    }
    cout << "pre|types=" << typeSnapshot(cells)
         << "|defs=" << defs.str()
         << "|block_order=" << order
         << "|a6_descendants=" << a6Descendants
         << "|callspecs=" << (callspecsResolve(sites, fd) ? 1 : 0)
         << "|dispatch=C1:" << probeToken(c1.op, 1, int4Type)
         << ",C2:" << probeToken(c2.op, 1, unknown4Type)
         << ",C5S0:" << probeToken(op5, 0, codePointer)
         << ",C5S1:" << probeToken(op5, 1, int8Type)
         << ",C8:" << probeToken(c8.op, 1, unknown4Type) << '\n';
    cout << "case7|status=UNTESTED|scope=stop-up-three-layer|"
         << "note=PcodeOp.stop_type_propagation+Varnode.stop_uppropagation+"
         << "propagateTypeEdge gate out of D2 lease (VARNODE-STOPUP-FLAGS-0001)\n";

    vector<Datatype *> preTypes = snapshotTypes(cells);
    fd.startTypeRecovery();
    ActionInferTypes action("typerecovery");
    action.reset(fd);
    int4 firstReturn = action.apply(fd);
    vector<Datatype *> firstTypes = snapshotTypes(cells);
    cout << "pass1|return=" << firstReturn
         << "|exception=none"
         << "|types=" << typeSnapshot(cells)
         << "|same_before=" << sameBefore(cells, preTypes)
         << "|block_order_stable=" << (blockOrder(opLabels, block) == order ? 1 : 0)
         << "|a6_descendants_stable="
         << (descendantOrder(opLabels, c6a.arg) == a6Descendants ? 1 : 0)
         << "|callspecs=" << (callspecsResolve(sites, fd) ? 1 : 0) << '\n';

    int4 secondReturn = action.apply(fd);
    bool typesStable = true;
    for (size_t index = 0; index < cells.size(); ++index)
      typesStable &= cells[index].vn->getType() == firstTypes[index];
    cout << "pass2|return=" << secondReturn
         << "|exception=none"
         << "|types=" << typeSnapshot(cells)
         << "|same_before=" << sameBefore(cells, firstTypes)
         << "|types_stable=" << (typesStable ? 1 : 0)
         << "|block_order_stable=" << (blockOrder(opLabels, block) == order ? 1 : 0)
         << "|a6_descendants_stable="
         << (descendantOrder(opLabels, c6a.arg) == a6Descendants ? 1 : 0)
         << "|callspecs=" << (callspecsResolve(sites, fd) ? 1 : 0) << '\n';
  }
  catch (const LowlevelError &error) {
    cout << "exception|phase=after_pre|what=" << error.explain << '\n';
    return 1;
  }
  catch (const exception &error) {
    cout << "exception|phase=after_pre|what=" << error.what() << '\n';
    return 1;
  }
  return 0;
}
