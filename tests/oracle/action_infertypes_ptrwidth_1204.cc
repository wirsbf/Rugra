/* ACTION-INFERTYPES-PTRWIDTH-0001: production ActionInferTypes width fixture. */
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
    setFields(fields, 32, 8);
    markComplete();
  }
};

struct Cell {
  string label;
  int4 width;
  bool isLoad;
  PcodeOp *op;
  Varnode *space;
  Varnode *target;
  Datatype *beforeType;
  uint4 beforeFlags;
};

static string metaName(const Datatype *type)
{
  string result;
  metatype2string(type->getMetatype(), result);
  return result;
}

static string normalizedType(const Cell &cell, const TypeStruct *progress)
{
  Datatype *type = cell.target->getType();
  if (type == progress) return "S32";
  if (type->getSize() == cell.width &&
      (type->getMetatype() == TYPE_UNKNOWN ||
       type->getMetatype() == TYPE_ARRAY))
    return "U" + std::to_string(cell.width);
  return metaName(type) + std::to_string(type->getSize());
}

static string operationOrder(const vector<Cell> &cells,
                             const list<PcodeOp *> &operations)
{
  ostringstream stream;
  bool first = true;
  for (list<PcodeOp *>::const_iterator iter = operations.begin();
       iter != operations.end(); ++iter) {
    if (!first) stream << ',';
    first = false;
    string label = "?";
    for (vector<Cell>::const_iterator cell = cells.begin(); cell != cells.end(); ++cell)
      if (cell->op == *iter) label = cell->label;
    stream << label;
  }
  return stream.str();
}

static string blockOrder(const vector<Cell> &cells, const BlockBasic *block)
{
  list<PcodeOp *> operations;
  for (list<PcodeOp *>::const_iterator iter = block->beginOp();
       iter != block->endOp(); ++iter)
    operations.push_back(*iter);
  return operationOrder(cells, operations);
}

static string descendantOrder(const vector<Cell> &cells, const Varnode *source)
{
  list<PcodeOp *> descendants;
  for (list<PcodeOp *>::const_iterator iter = source->beginDescend();
       iter != source->endDescend(); ++iter)
    descendants.push_back(*iter);
  return operationOrder(cells, descendants);
}

static bool targetDescendantShape(const Cell &cell)
{
  list<PcodeOp *>::const_iterator iter = cell.target->beginDescend();
  if (cell.isLoad)
    return iter == cell.target->endDescend();
  if (iter == cell.target->endDescend() || *iter != cell.op)
    return false;
  ++iter;
  return iter == cell.target->endDescend();
}

static string typeSnapshot(const vector<Cell> &cells, const TypeStruct *progress)
{
  ostringstream stream;
  for (vector<Cell>::const_iterator cell = cells.begin(); cell != cells.end(); ++cell) {
    if (cell != cells.begin()) stream << ',';
    stream << cell->label << ':' << normalizedType(*cell, progress)
           << "/raw=" << metaName(cell->target->getType())
           << "/size=" << cell->target->getType()->getSize()
           << "/same_before=" << (cell->target->getType() == cell->beforeType)
           << "/same_progress=" << (cell->target->getType() == progress)
           << "/flags=" << cell->target->getFlags()
           << "/descendants=" << distance(cell->target->beginDescend(),
                                            cell->target->endDescend())
           << "/desc_shape=" << targetDescendantShape(*cell);
  }
  return stream.str();
}

static bool topologyStable(const vector<Cell> &cells, const Varnode *source,
                           const BlockBasic *block)
{
  if (!source->isInput() || source->isWritten() || !source->isTypeLock() ||
      source->isMark() || source->stopsUpPropagation())
    return false;
  for (vector<Cell>::const_iterator cell = cells.begin(); cell != cells.end(); ++cell) {
    if (cell->op->getIn(1) != source || cell->op->getParent() != block ||
        cell->op->getIn(0) != cell->space || !cell->space->isConstant() ||
        cell->op->isDead() || cell->target == source ||
        cell->target->getFlags() != cell->beforeFlags ||
        cell->target->isTypeLock() || cell->target->isMark() ||
        cell->target->stopsUpPropagation() || !targetDescendantShape(*cell))
      return false;
    for (vector<Cell>::const_iterator other = cells.begin(); other != cell; ++other)
      if (cell->op == other->op || cell->space == other->space ||
          cell->target == other->target)
        return false;
    if (cell->isLoad) {
      if (cell->op->code() != CPUI_LOAD || cell->op->getOut() != cell->target ||
          !cell->target->isWritten() || cell->target->isInput() ||
          cell->target->getDef() != cell->op)
        return false;
    }
    else {
      if (cell->op->code() != CPUI_STORE || cell->op->getIn(2) != cell->target ||
          cell->target->isWritten() || cell->target->isInput() ||
          cell->target->getDef() != (PcodeOp *)0)
        return false;
    }
  }
  return true;
}

int main(void)
{
  cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  cout << "schema=1|fixture=ACTION-INFERTYPES-PTRWIDTH-0001"
       << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    AddrSpace *reg = architecture.getSpace(4);
    Scope *global = architecture.symboltab->getGlobalScope();
    Funcdata fd("action_ptrwidth", "action_ptrwidth", global,
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x40);
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    fd.setBasicBlockRange(block, Address(ram, 0x5000), Address(ram, 0x5005));

    Datatype *longType = architecture.types->getBase(8, TYPE_INT);
    Datatype *intType = architecture.types->getBase(4, TYPE_INT);
    vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "total", longType));
    fields.push_back(TypeField(1, 8, "prev", longType));
    fields.push_back(TypeField(2, 16, "point", longType));
    fields.push_back(TypeField(3, 24, "width", intType));
    TypeStruct *progress = new FixtureProgress(fields);
    Datatype *progressPointer =
        architecture.types->getTypePointer(8, progress, 1);

    Varnode *source = fd.newVarnode(8, Address(reg, 0x100));
    source = fd.setInputVarnode(source);
    source->updateType(progressPointer, true, false);
    Datatype *sourceType = source->getType();
    uint4 sourceFlags = source->getFlags();

    vector<Cell> cells;
    const char *labels[] = { "L16", "L4", "L32", "S16", "S4", "S32" };
    const int4 widths[] = { 16, 4, 32, 16, 4, 32 };
    for (int4 index = 0; index < 6; ++index) {
      bool isLoad = index < 3;
      PcodeOp *op = fd.newOp(isLoad ? 2 : 3, Address(ram, 0x5000 + index));
      fd.opSetOpcode(op, isLoad ? CPUI_LOAD : CPUI_STORE);
      Varnode *space = fd.newConstant(4, ram->getIndex());
      fd.opSetInput(op, space, 0);
      fd.opSetInput(op, source, 1);
      Varnode *target;
      if (isLoad)
        target = fd.newUniqueOut(widths[index], op);
      else {
        target = fd.newVarnode(widths[index], Address(reg, 0x200 + index * 0x40));
        fd.opSetInput(op, target, 2);
      }
      fd.opInsertEnd(op, block);
      cells.push_back(Cell{labels[index], widths[index], isLoad, op, space, target,
                           target->getType(), target->getFlags()});
    }

    string order = blockOrder(cells, block);
    string descendants = descendantOrder(cells, source);
    cout << "pre|types=" << typeSnapshot(cells, progress)
         << "|block_order=" << order
         << "|pointer_desc_order=" << descendants
         << "|source_type_identity=" << (source->getType() == sourceType)
         << "|source_flags=" << sourceFlags
         << "|source_descendants=" << distance(source->beginDescend(), source->endDescend())
         << "|topology=" << topologyStable(cells, source, block) << '\n';

    fd.startTypeRecovery();
    ActionInferTypes action("typerecovery");
    action.reset(fd);
    int4 firstReturn = action.apply(fd);
    vector<Datatype *> firstTypes;
    for (vector<Cell>::const_iterator cell = cells.begin(); cell != cells.end(); ++cell)
      firstTypes.push_back(cell->target->getType());
    cout << "pass1|return=" << firstReturn
         << "|exception=none"
         << "|types=" << typeSnapshot(cells, progress)
         << "|source_type_identity=" << (source->getType() == sourceType)
         << "|source_flags_stable=" << (source->getFlags() == sourceFlags)
         << "|block_order_stable=" << (blockOrder(cells, block) == order)
         << "|pointer_desc_order_stable=" << (descendantOrder(cells, source) == descendants)
         << "|topology=" << topologyStable(cells, source, block) << '\n';

    int4 secondReturn = action.apply(fd);
    bool typesStable = true;
    for (size_t index = 0; index < cells.size(); ++index)
      typesStable &= cells[index].target->getType() == firstTypes[index];
    cout << "pass2|return=" << secondReturn
         << "|exception=none"
         << "|types_stable=" << typesStable
         << "|source_type_identity=" << (source->getType() == sourceType)
         << "|source_flags_stable=" << (source->getFlags() == sourceFlags)
         << "|block_order_stable=" << (blockOrder(cells, block) == order)
         << "|pointer_desc_order_stable=" << (descendantOrder(cells, source) == descendants)
         << "|topology=" << topologyStable(cells, source, block) << '\n';
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
