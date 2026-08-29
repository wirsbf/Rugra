/* INFERTYPES-SETTLE-0001: ActionInferTypes interning/settling fixture.
 *
 * Exercises the float-conversion chain and the LOAD/STORE pointer edges that
 * drive TypeOp::propagateToPointer/propagateFromPointer (typeop.cc:186-228),
 * then applies ActionInferTypes (coreaction.cc:5374-5416) repeatedly and
 * observes the per-round Varnode type table together with the pointer
 * identity stability against the previous round. The oracle's writeBack
 * settles because every propagated Datatype is TypeFactory-interned: a
 * stable table plus stable pointer identities from round to round is the
 * observable contract the "Type propagation algorithm not settling"
 * warning (coreaction.cc:5390-5392) depends on.
 */
#include <bits/stdc++.h>

#include "architecture.hh"
#include "capability.hh"
#include "coreaction.hh"
#include "database.hh"
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

class FixtureProgress final : public TypeStruct {
public:
  explicit FixtureProgress(const vector<TypeField> &fields)
  {
    name = "ProgressData";
    displayName = name;
    setFields(fields, 16, 8);
    markComplete();
  }
};

struct RoundCell {
  string label;
  Varnode *target;
  Datatype *type;
};

static string metaName(const Datatype *type)
{
  string result;
  metatype2string(type->getMetatype(), result);
  return result;
}

/* Byte-comparable projection: per-cell metatype/size plus whether the
 * Datatype pointer is identical to the previous round (the interned-instance
 * stability writeBack settles on). */
static string roundSnapshot(const vector<RoundCell> &cells)
{
  ostringstream stream;
  for (vector<RoundCell>::const_iterator cell = cells.begin();
       cell != cells.end(); ++cell) {
    if (cell != cells.begin()) stream << ',';
    stream << cell->label << ':' << metaName(cell->target->getType())
           << cell->target->getType()->getSize()
           << "/same_prev=" << (cell->target->getType() == cell->type);
  }
  return stream.str();
}

int main(void)
{
  cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  cout << "schema=1|fixture=INFERTYPES-SETTLE-0001"
       << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    AddrSpace *reg = architecture.getSpace(4);
    Scope *global = architecture.symboltab->getGlobalScope();
    Funcdata fd("infertypes_settle", "infertypes_settle", global,
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x40);
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    fd.setBasicBlockRange(block, Address(ram, 0x5000), Address(ram, 0x5010));

    /* An 8-byte int input feeding the float chain. */
    Varnode *counterInput = fd.newVarnode(4, Address(reg, 0x100));
    counterInput = fd.setInputVarnode(counterInput);

    /* f2 = FLOAT_FLOAT2FLOAT(INT2FLOAT(counter) * const) : 4 -> 8 widening
     * (the RuleSubfloatConvert trigger shape). */
    PcodeOp *int2float = fd.newOp(1, Address(ram, 0x5000));
    fd.opSetOpcode(int2float, CPUI_FLOAT_INT2FLOAT);
    fd.opSetInput(int2float, counterInput, 0);
    Varnode *float4 = fd.newUniqueOut(4, int2float);
    fd.opInsertEnd(int2float, block);

    PcodeOp *fmul = fd.newOp(2, Address(ram, 0x5002));
    fd.opSetOpcode(fmul, CPUI_FLOAT_MULT);
    fd.opSetInput(fmul, float4, 0);
    Varnode *scale = fd.newConstant(4, 0x3f800000);
    fd.opSetInput(fmul, scale, 1);
    Varnode *product4 = fd.newUniqueOut(4, fmul);
    fd.opInsertEnd(fmul, block);

    PcodeOp *f2f = fd.newOp(1, Address(ram, 0x5004));
    fd.opSetOpcode(f2f, CPUI_FLOAT_FLOAT2FLOAT);
    fd.opSetInput(f2f, product4, 0);
    Varnode *double8 = fd.newUniqueOut(8, f2f);
    fd.opInsertEnd(f2f, block);

    /* A type-locked 8-byte struct pointer drives the pointer propagation
     * edges: LOAD (propagateFromPointer) and STORE (propagateToPointer). */
    Datatype *longType = architecture.types->getBase(8, TYPE_INT);
    vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "total", longType));
    fields.push_back(TypeField(1, 8, "prev", longType));
    FixtureProgress progress(fields);
    Datatype *progressPointer = architecture.types->getTypePointer(8, &progress, 1);

    Varnode *pointerInput = fd.newVarnode(8, Address(reg, 0x180));
    pointerInput = fd.setInputVarnode(pointerInput);
    pointerInput->updateType(progressPointer, true, false);

    PcodeOp *load = fd.newOp(2, Address(ram, 0x5006));
    fd.opSetOpcode(load, CPUI_LOAD);
    fd.opSetInput(load, fd.newConstant(4, ram->getIndex()), 0);
    fd.opSetInput(load, pointerInput, 1);
    Varnode *loaded8 = fd.newUniqueOut(8, load);
    fd.opInsertEnd(load, block);

    PcodeOp *store = fd.newOp(3, Address(ram, 0x5008));
    fd.opSetOpcode(store, CPUI_STORE);
    fd.opSetInput(store, fd.newConstant(4, ram->getIndex()), 0);
    fd.opSetInput(store, pointerInput, 1);
    fd.opSetInput(store, double8, 2);
    fd.opInsertEnd(store, block);

    vector<RoundCell> cells;
    const char *labels[] = { "counter", "float4", "product4", "double8",
                             "pointer", "loaded8" };
    Varnode *targets[] = { counterInput, float4, product4, double8,
                           pointerInput, loaded8 };
    for (int4 index = 0; index < 6; ++index) {
      cells.push_back(RoundCell{labels[index], targets[index],
                                targets[index]->getType()});
    }
    cout << "pre|types=" << roundSnapshot(cells) << '\n';

    fd.startTypeRecovery();
    ActionInferTypes action("typerecovery");
    action.reset(fd);
    for (int4 round = 1; round <= 8; ++round) {
      int4 result = action.apply(fd);
      cout << "round" << round << "|return=" << result
           << "|types=" << roundSnapshot(cells) << '\n';
      for (vector<RoundCell>::iterator cell = cells.begin();
           cell != cells.end(); ++cell)
        cell->type = cell->target->getType();
    }
  }
  catch (const LowlevelError &error) {
    cout << "exception|phase=run|what=" << error.explain << '\n';
    return 1;
  }
  catch (const exception &error) {
    cout << "exception|phase=run|what=" << error.what() << '\n';
    return 1;
  }
  return 0;
}
