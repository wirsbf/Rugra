/* PTRSUB-OUTPUT-TOKEN-0001: locked Ghidra 12.0.4
 * TypeOpPtrsub::getOutputToken and its production ActionSetCasts::castOutput
 * caller.  The direct matrix observes field-sensitive token shape and
 * canonical identity.  The action projection observes selected def-use and
 * type fields before and after a no-op and a required output CAST.  The infer
 * canary then runs one production ActionInferTypes pass over an unlocked
 * SPACEBASE PTRSUB with STOP_TYPE_PROPAGATION.  The selected raw streams are
 * byte-identical; full mapped-function and architecture residuals remain
 * explicitly outside this fixture's MATCH projection.
 */
#include <bits/stdc++.h>

#define private public
#define protected public
#include "action.hh"
#include "architecture.hh"
#include "coreaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "printc.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef protected
#undef private

using namespace ghidra;

static std::string factoryCoreState(TypeFactory *factory);

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
  const VarnodeData &getRegister(const std::string &) const override {
    return dummyRegister;
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
  std::string factoryBootstrapState;

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
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
    types->cacheCoreTypes();
    factoryBootstrapState = factoryCoreState(types);
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
    print->initializeFromArchitecture();
  }

  void printMessage(const std::string &) const override {}
};

class FixtureStruct final : public TypeStruct {
public:
  FixtureStruct(const std::string &nm, const std::vector<TypeField> &fields,
                int4 size, int4 alignment)
  {
    name = nm;
    displayName = nm;
    setFields(fields, size, alignment);
    markComplete();
  }
};

static std::string metaToken(type_metatype meta)
{
  switch (meta) {
  case TYPE_VOID: return "void";
  case TYPE_PTR: return "ptr";
  case TYPE_ARRAY: return "array";
  case TYPE_STRUCT: return "struct";
  case TYPE_SPACEBASE: return "spacebase";
  case TYPE_BOOL: return "bool";
  case TYPE_INT: return "int";
  case TYPE_UINT: return "uint";
  case TYPE_UNKNOWN: return "unknown";
  default: return "other";
  }
}

static std::string typeProj(const Datatype *ct)
{
  if (ct == (const Datatype *)0)
    return "null";
  if (ct->getMetatype() == TYPE_PTR) {
    const TypePointer *pointer = (const TypePointer *)ct;
    return "ptr" + std::to_string(pointer->getSize()) + "w" +
           std::to_string(pointer->getWordSize()) + "->" +
           typeProj(pointer->getPtrTo());
  }
  return metaToken(ct->getMetatype()) + std::to_string(ct->getSize());
}

static std::string factoryCoreState(TypeFactory *factory)
{
  static const char *names[] = {
      "xunknown1", "xunknown2", "xunknown4", "xunknown8", "int4", "int8"};
  std::ostringstream out;
  std::vector<Datatype *> dependentOrder;
  factory->dependentOrder(dependentOrder);
  out << "count:" << dependentOrder.size() << ";order:";
  for (size_t i = 0; i < dependentOrder.size(); ++i) {
    if (i != 0)
      out << ',';
    out << dependentOrder[i]->getName();
  }
  out << ';';
  out << "sizes:" << factory->getSizeOfInt() << ','
      << factory->getSizeOfLong() << ',' << factory->getSizeOfChar() << ','
      << factory->getSizeOfWChar() << ',' << factory->getSizeOfPointer() << ','
      << factory->getSizeOfAltPointer() << ";align:";
  for (uint4 size = 0; size <= 8; ++size) {
    if (size != 0)
      out << ',';
    out << factory->getAlignment(size);
  }
  out << ";types:";
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    Datatype *type = factory->findByName(names[i]);
    if (type == (Datatype *)0)
      throw LowlevelError("missing locked core type");
    if (i != 0)
      out << ',';
    out << type->getName() << ':' << type->getSize() << ':'
        << metaToken(type->getMetatype()) << ":0x" << std::hex
        << type->getId() << std::dec << ':' << type->getAlignment() << ':'
        << type->getAlignSize() << ":0x" << std::hex << type->flags
        << std::dec << ":cache"
        << (factory->getBase(type->getSize(), type->getMetatype()) == type ? 1 : 0);
  }
  return out.str();
}

static std::string opToken(OpCode opcode)
{
  switch (opcode) {
  case CPUI_PTRSUB: return "ptrsub";
  case CPUI_CAST: return "cast";
  default: return "other";
  }
}

static void printScale(const char *name, uintb val, uint4 ws)
{
  std::cout << "scale|case=" << name << "|val=0x" << std::hex << val
            << std::dec << "|ws=" << ws << "|result=0x" << std::hex
            << AddrSpace::addressToByte(val, ws) << std::dec << '\n';
}

struct DirectCase {
  std::string name;
  PcodeOp *op;
  Datatype *expectedToken;
  Datatype *expectedPointee;
};

static PcodeOp *makePtrsub(Funcdata &fd, BlockBasic *block, AddrSpace *ram,
                           Varnode *base, uintb rawOffset, uintb pc,
                           Datatype *outType)
{
  PcodeOp *op = fd.newOp(2, Address(ram, pc));
  fd.opSetOpcode(op, CPUI_PTRSUB);
  fd.opSetInput(op, base, 0);
  fd.opSetInput(op, fd.newConstant(8, rawOffset), 1);
  Varnode *out = fd.newUniqueOut(8, op);
  out->updateType(outType);
  fd.opInsertEnd(op, block);
  return op;
}

static Varnode *typedInput(Funcdata &fd, AddrSpace *reg, uintb offset,
                           Datatype *type)
{
  Varnode *vn = fd.newVarnode(8, Address(reg, offset));
  vn = fd.setInputVarnode(vn);
  vn->updateType(type, true, false);
  return vn;
}

static void runDirect(FixtureArchitecture &architecture,
                      Datatype *progress, Datatype *outer,
                      Datatype *int8Type, const std::string &factoryState)
{
  AddrSpace *ram = architecture.getSpace(3);
  AddrSpace *reg = architecture.getSpace(4);
  Funcdata fd("ptrsub_token_direct", "ptrsub_token_direct",
              architecture.symboltab->getGlobalScope(), Address(ram, 0x5000),
              (FunctionSymbol *)0, 0x40);
  BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(&fd);
  fd.setBasicBlockRange(block, Address(ram, 0x5000), Address(ram, 0x5010));

  Datatype *progressPtr = architecture.types->getTypePointer(8, progress, 1);
  Datatype *progressPtrW2 = architecture.types->getTypePointer(8, progress, 2);
  Datatype *outerPtr = architecture.types->getTypePointer(8, outer, 1);
  Datatype *unknown1 = architecture.types->getBase(1, TYPE_UNKNOWN);
  Datatype *unknownPtrW1 = architecture.types->getTypePointer(8, unknown1, 1);
  Datatype *unknownPtrW2 = architecture.types->getTypePointer(8, unknown1, 2);
  Datatype *fieldPtrW1 = architecture.types->getTypePointer(8, int8Type, 1);
  Datatype *fieldPtrW2 = architecture.types->getTypePointer(8, int8Type, 2);
  Datatype *int4Type = architecture.types->getBase(4, TYPE_INT);
  Datatype *field4PtrW1 = architecture.types->getTypePointer(8, int4Type, 1);
  Datatype *scalarPtrW1 = architecture.types->getTypePointer(8, int8Type, 1);

  Varnode *progressIn = typedInput(fd, reg, 0x100, progressPtr);
  Varnode *progressInW2 = typedInput(fd, reg, 0x108, progressPtrW2);
  Varnode *outerIn = typedInput(fd, reg, 0x110, outerPtr);
  Varnode *integerIn = typedInput(fd, reg, 0x118, int8Type);
  Varnode *scalarIn = typedInput(fd, reg, 0x120, scalarPtrW1);

  std::vector<DirectCase> cases;
  cases.push_back({"exact0", makePtrsub(fd, block, ram, progressIn, 0, 0x5000, int8Type), fieldPtrW1, int8Type});
  cases.push_back({"exact8", makePtrsub(fd, block, ram, progressIn, 8, 0x5001, int8Type), fieldPtrW1, int8Type});
  cases.push_back({"inside12", makePtrsub(fd, block, ram, progressIn, 12, 0x5002, int8Type), unknownPtrW1, unknown1});
  cases.push_back({"nested12", makePtrsub(fd, block, ram, outerIn, 12, 0x5003, int8Type), unknownPtrW1, unknown1});
  cases.push_back({"hole28", makePtrsub(fd, block, ram, progressIn, 28, 0x5004, int8Type), unknownPtrW1, unknown1});
  cases.push_back({"size32", makePtrsub(fd, block, ram, progressIn, 32, 0x5005, int8Type), unknownPtrW1, unknown1});
  cases.push_back({"negative1", makePtrsub(fd, block, ram, progressIn, ~(uintb)0, 0x5006, int8Type), unknownPtrW1, unknown1});
  cases.push_back({"wordsize2", makePtrsub(fd, block, ram, progressInW2, 4, 0x5007, int8Type), fieldPtrW2, int8Type});
  cases.push_back({"wordsize2_inside", makePtrsub(fd, block, ram, progressInW2, 6, 0x5008, int8Type), unknownPtrW2, unknown1});
  cases.push_back({"wordsize2_wrap", makePtrsub(fd, block, ram, progressInW2, ((uintb)1) << 63, 0x5009, int8Type), fieldPtrW2, int8Type});
  cases.push_back({"wordsize2_wrap_nonzero", makePtrsub(fd, block, ram, progressInW2, (((uintb)1) << 63) + 4, 0x500a, int8Type), fieldPtrW2, int8Type});
  cases.push_back({"exact24", makePtrsub(fd, block, ram, progressIn, 24, 0x500b, int8Type), field4PtrW1, int4Type});
  cases.push_back({"scalar0", makePtrsub(fd, block, ram, scalarIn, 0, 0x500c, int8Type), unknownPtrW1, unknown1});
  cases.push_back({"nonpointer", makePtrsub(fd, block, ram, integerIn, 8, 0x500d, int8Type), int8Type, (Datatype *)0});

  fd.setHighLevel();
  CastStrategy *strategy = architecture.print->getCastStrategy();
  for (size_t index = 0; index < cases.size(); ++index) {
    const DirectCase &item = cases[index];
    Datatype *token = item.op->getOpcode()->getOutputToken(item.op, strategy);
    Datatype *pointee = token->getMetatype() == TYPE_PTR
        ? ((TypePointer *)token)->getPtrTo() : (Datatype *)0;
    Datatype *repeat = item.op->getOpcode()->getOutputToken(item.op, strategy);
    Datatype *local = item.op->outputTypeLocal();
    if (local != item.op->getOpcode()->getOutputLocal(item.op))
      throw LowlevelError("PTRSUB direct/dispatch local identity diverged");
    std::cout << "direct|case=" << item.name
              << "|token=" << typeProj(token)
              << "|token_identity=" << (token == item.expectedToken ? 1 : 0)
              << "|pointee_present=" << (pointee != (Datatype *)0 ? 1 : 0)
              << "|pointee_identity=" << (pointee == item.expectedPointee ? 1 : 0)
              << "|repeat_identity=" << (repeat == token ? 1 : 0)
              << "|local=" << typeProj(local)
              << "|local_identity=" << (local == int8Type ? 1 : 0)
              << "|local_core=" << (local->isCoreType() ? 1 : 0);
    if (index == 0)
      std::cout << "|factory_core=" << factoryState;
    std::cout << '\n';
  }
}

static std::string blockOps(BlockBasic *block)
{
  std::ostringstream out;
  out << '[';
  bool first = true;
  for (std::list<PcodeOp *>::const_iterator iter = block->beginOp();
       iter != block->endOp(); ++iter) {
    if (!first) out << ',';
    first = false;
    out << opToken((*iter)->code()) << '@' << std::hex
        << (*iter)->getAddr().getOffset() << std::dec;
  }
  out << ']';
  return out.str();
}

class ProbeSetCasts final : public ActionSetCasts {
public:
  ProbeSetCasts() : ActionSetCasts("fixture")
  {
    // Direct apply() bypasses Action::perform(), which normally initializes
    // the inherited counters before invoking the virtual method.
    count = 0;
    lcount = 0;
  }

  int4 countNow(void) const { return count; }

  // Fixture adapter for Rugra's externalized Action base-state bridge.  In
  // Ghidra, Action::count remains an inherited field and Action::perform
  // consumes it in place.  Rugra transfers the same delta to ActionState, so
  // the Rust leaf exposes take_count_delta().  Read-and-clear here compares
  // that transfer boundary without claiming this helper is a Ghidra method.
  int4 takeCountDelta(void)
  {
    int4 result = count;
    count = 0;
    return result;
  }
};

static void runAction(FixtureArchitecture &architecture,
                      Datatype *progress, Datatype *int8Type)
{
  AddrSpace *ram = architecture.getSpace(3);
  AddrSpace *reg = architecture.getSpace(4);
  Funcdata fd("ptrsub_castoutput", "ptrsub_castoutput",
              architecture.symboltab->getGlobalScope(), Address(ram, 0x6000),
              (FunctionSymbol *)0, 0x20);
  BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(&fd);
  fd.setBasicBlockRange(block, Address(ram, 0x6000), Address(ram, 0x6002));

  Datatype *progressPtr = architecture.types->getTypePointer(8, progress, 1);
  Datatype *int4Type = architecture.types->getBase(4, TYPE_INT);
  Datatype *fieldPtr = architecture.types->getTypePointer(8, int8Type, 1);
  Datatype *otherPtr = architecture.types->getTypePointer(8, int4Type, 1);
  Varnode *base = typedInput(fd, reg, 0x200, progressPtr);
  PcodeOp *equalOp = makePtrsub(fd, block, ram, base, 8, 0x6000, fieldPtr);
  PcodeOp *mismatchOp = makePtrsub(fd, block, ram, base, 8, 0x6001, otherPtr);
  Varnode *equalOut = equalOp->getOut();
  Varnode *mismatchOut = mismatchOp->getOut();
  fd.setHighLevel();

  std::cout << "action_pre|case=paired|ops=" << blockOps(block)
            << "|equal_def=" << opToken(equalOut->getDef()->code())
            << "|mismatch_def=" << opToken(mismatchOut->getDef()->code())
            << "|equal_type=" << typeProj(equalOut->getType())
            << "|mismatch_type=" << typeProj(mismatchOut->getType()) << '\n';

  ProbeSetCasts action;
  int4 result = action.apply(fd);
  int4 countBeforeDelta = action.countNow();
  int4 deltaFirst = action.takeCountDelta();
  int4 countAfterDelta = action.countNow();
  int4 deltaSecond = action.takeCountDelta();
  PcodeOp *mismatchDef = mismatchOut->getDef();
  Varnode *mid = mismatchOp->getOut();
  PcodeOp *midUse = mid->loneDescend();
  int4 castCount = 0;
  for (std::list<PcodeOp *>::const_iterator iter = block->beginOp();
       iter != block->endOp(); ++iter)
    if ((*iter)->code() == CPUI_CAST) castCount += 1;

  std::cout << "action_post|case=paired|result=" << result
            << "|count_before_delta=" << countBeforeDelta
            << "|delta_first=" << deltaFirst
            << "|count_after_delta=" << countAfterDelta
            << "|delta_second=" << deltaSecond
            << "|ops=" << blockOps(block) << "|casts=" << castCount
            << "|equal_same=" << (equalOp->getOut() == equalOut ? 1 : 0)
            << "|equal_def=" << opToken(equalOut->getDef()->code())
            << "|mismatch_def=" << opToken(mismatchDef->code())
            << "|mismatch_out_same=" << (mismatchDef->getOut() == mismatchOut ? 1 : 0)
            << "|mid_new=" << (mid != mismatchOut ? 1 : 0)
            << "|mid_def=" << opToken(mid->getDef()->code())
            << "|mid_use=" << (midUse == mismatchDef ? "cast" : "other")
            << "|cast_input_mid=" << (mismatchDef->getIn(0) == mid ? 1 : 0)
            << "|mid_implied=" << (mid->isImplied() ? 1 : 0)
            << "|mid_type=" << typeProj(mid->getType())
            << "|final_type=" << typeProj(mismatchOut->getType()) << '\n';
}

static void runInferLocal(FixtureArchitecture &architecture)
{
  AddrSpace *ram = architecture.getSpace(3);
  AddrSpace *reg = architecture.getSpace(4);
  Funcdata fd("ptrsub_spacebase_local", "ptrsub_spacebase_local",
              architecture.symboltab->getGlobalScope(), Address(ram, 0x7000),
              (FunctionSymbol *)0, 0x10);
  BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(&fd);
  fd.setBasicBlockRange(block, Address(ram, 0x7000), Address(ram, 0x7000));

  Varnode *base = fd.newVarnode(8, Address(reg, 0x300));
  base = fd.setInputVarnode(base);
  base->flags |= Varnode::spacebase;
  PcodeOp *op = fd.newOp(2, Address(ram, 0x7000));
  fd.opSetOpcode(op, CPUI_PTRSUB);
  fd.opSetInput(op, base, 0);
  fd.opSetInput(op, fd.newConstant(8, 8), 1);
  Varnode *out = fd.newUniqueOut(8, op);
  op->setStopTypePropagation();
  fd.opInsertEnd(op, block);

  std::cout << "infer_pre|case=spacebase_ptrsub_local"
            << "|base_spacebase=" << (base->isSpacebase() ? 1 : 0)
            << "|base_type=" << typeProj(base->getType())
            << "|out_type=" << typeProj(out->getType())
            << "|out_stop=" << (out->stopsUpPropagation() ? 1 : 0)
            << "|def_stop=" << (op->stopsTypePropagation() ? 1 : 0) << '\n';

  fd.startTypeRecovery();
  ActionInferTypes action("typerecovery");
  action.reset(fd);
  int4 result = action.apply(fd);
  Datatype *int8Type = architecture.types->getBase(8, TYPE_INT);
  std::cout << "infer_post|case=spacebase_ptrsub_local"
            << "|result=" << result
            << "|base_spacebase=" << (base->isSpacebase() ? 1 : 0)
            << "|base_type=" << typeProj(base->getType())
            << "|out_type=" << typeProj(out->getType())
            << "|out_identity=" << (out->getType() == int8Type ? 1 : 0)
            << "|out_stop=" << (out->stopsUpPropagation() ? 1 : 0)
            << "|def=" << opToken(out->getDef()->code()) << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::cout << "schema=1|fixture=PTRSUB-OUTPUT-TOKEN-0001"
            << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    std::vector<std::string> specPaths;
    startDecompilerLibrary(specPaths);
    printScale("normal", 5, 2);
    printScale("wrap_zero", ((uintb)1) << 63, 2);
    printScale("wrap_nonzero", (((uintb)1) << 63) + 4, 2);
    printScale("max_product", ~(uintb)0, ~(uint4)0);
    printScale("zero_wordsize", ~(uintb)0, 0);
    FixtureArchitecture architecture;
    Datatype *int8Type = architecture.types->getBase(8, TYPE_INT);
    Datatype *int4Type = architecture.types->getBase(4, TYPE_INT);
    std::vector<TypeField> progressFields;
    progressFields.push_back(TypeField(0, 0, "total", int8Type));
    progressFields.push_back(TypeField(1, 8, "prev", int8Type));
    progressFields.push_back(TypeField(2, 16, "point", int8Type));
    progressFields.push_back(TypeField(3, 24, "width", int4Type));
    Datatype *progress = new FixtureStruct("ProgressData", progressFields, 32, 8);

    std::vector<TypeField> innerFields;
    innerFields.push_back(TypeField(0, 0, "head", int4Type));
    innerFields.push_back(TypeField(1, 4, "leaf", int4Type));
    Datatype *inner = new FixtureStruct("Inner", innerFields, 8, 4);
    std::vector<TypeField> outerFields;
    outerFields.push_back(TypeField(0, 0, "prefix", int8Type));
    outerFields.push_back(TypeField(1, 8, "inner", inner));
    Datatype *outer = new FixtureStruct("Outer", outerFields, 16, 8);

    runDirect(architecture, progress, outer, int8Type,
              architecture.factoryBootstrapState);
    runAction(architecture, progress, int8Type);
    runInferLocal(architecture);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  catch (const LowlevelError &error) {
    std::cerr << "fixture LowlevelError: " << error.explain << '\n';
    return 1;
  }
  catch (const DecoderError &error) {
    std::cerr << "fixture DecoderError: " << error.explain << '\n';
    return 1;
  }
  return 0;
}
