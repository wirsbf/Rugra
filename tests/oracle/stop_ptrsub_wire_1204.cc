/* STOP-PTRSUB-WIRE-0001: ActionInferTypes STOP seal + PTRSUB downChain wiring.
 *
 * Bilateral fixture: one Funcdata drives ActionInferTypes through the
 * production pipeline on a graph that exercises
 *   - buildLocaltypes' needsBlock -> setStopUpPropagation
 *     (coreaction.cc:5030-5031) for a PTRSUB flagged stop_type_propagation,
 *   - propagateTypeEdge's stopsUpPropagation guard (coreaction.cc:5093),
 *   - TypeOpPtrsub::propagateType -> propagateAddIn2Out -> downChain
 *     (typeop.cc:2375/1215) producing the field pointer + ephemeral
 *     getTypePointerRel form (type.cc:4016),
 *   - the INT_ADD pointer arm (typeop.cc:1200) and the INT_SUB null arm
 *     (typeop.cc:317-321).
 */
#include <bits/stdc++.h>

// Test-only access rewrite for friend-only setters. Standard headers are
// included first so the visibility rewrite never touches libstdc++.
#define private public
#include "architecture.hh"
#include "coreaction.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef private

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

static string metaToken(type_metatype meta)
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
  default: return "other";
  }
}

/// Normalized projection shared with the Rust side: base types print as
/// metatype+size tokens; pointers print the pointed-to projection plus the
/// relative-pointer container state (parent name and byte offset) when the
/// dynamic type is TypePointerRel.
static string typeProj(const Datatype *ct)
{
  if (ct == (const Datatype *)0) return "null";
  if (ct->getMetatype() == TYPE_PTR) {
    const TypePointer *p = (const TypePointer *)ct;
    string res = "ptr" + to_string(p->getSize()) + "->" + typeProj(p->getPtrTo());
    const TypePointerRel *rel = dynamic_cast<const TypePointerRel *>(ct);
    if (rel != (const TypePointerRel *)0)
      res += "|rel=" + rel->getParent()->getName() + ":" + to_string(rel->getByteOffset());
    return res;
  }
  return metaToken(ct->getMetatype()) + to_string(ct->getSize());
}

struct Cell {
  string label;
  Varnode *vn;
};

static string snapshot(const vector<Cell> &cells)
{
  ostringstream stream;
  for (size_t i = 0; i < cells.size(); ++i) {
    if (i != 0) stream << ',';
    stream << cells[i].label << ':'
           << typeProj(cells[i].vn->getType())
           << "/stop=" << (cells[i].vn->stopsUpPropagation() ? 1 : 0);
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
  cout << "schema=1|fixture=STOP-PTRSUB-WIRE-0001"
       << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    AddrSpace *reg = architecture.getSpace(4);
    Scope *global = architecture.symboltab->getGlobalScope();
    Funcdata fd("stop_ptrsub_wire", "stop_ptrsub_wire", global,
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x40);
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    fd.setBasicBlockRange(block, Address(ram, 0x5000), Address(ram, 0x5009));

    Datatype *longType = architecture.types->getBase(8, TYPE_INT);
    vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "total", longType));
    fields.push_back(TypeField(1, 8, "prev", longType));
    fields.push_back(TypeField(2, 16, "point", longType));
    TypeStruct *progress = new FixtureProgress(fields);
    Datatype *progressPointer =
        architecture.types->getTypePointer(8, progress, 1);

    Varnode *bar = fd.newVarnode(8, Address(reg, 0x100));
    bar = fd.setInputVarnode(bar);
    bar->updateType(progressPointer, true, false);

    // LOAD space constants carry the AddrSpace POINTER as the constant
    // offset: VarnodeData::getSpaceFromConst (pcoderaw.hh:101-103) casts the
    // offset straight back to `AddrSpace*`, and TypeOpLoad::propagateType's
    // inslot==-1 arm dereferences it.
    Varnode *spaceConst = fd.newConstant(4, (uintb)(uintp)ram);
    vector<Cell> cells;
    int4 seq = 0;

    // Helper lambdas building each case's op chain.
    auto makePtrsub = [&](uintb off, bool stop) -> Varnode * {
      PcodeOp *op = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
      fd.opSetOpcode(op, CPUI_PTRSUB);
      fd.opSetInput(op, bar, 0);
      fd.opSetInput(op, fd.newConstant(8, off), 1);
      Varnode *out = fd.newUniqueOut(8, op);
      fd.opInsertEnd(op, block);
      if (stop)
        op->setStopTypePropagation();
      return out;
    };
    auto makeLoad = [&](Varnode *addr) -> Varnode * {
      PcodeOp *op = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
      fd.opSetOpcode(op, CPUI_LOAD);
      fd.opSetInput(op, spaceConst, 0);
      fd.opSetInput(op, addr, 1);
      Varnode *out = fd.newUniqueOut(8, op);
      fd.opInsertEnd(op, block);
      return out;
    };

    // A: sealed PTRSUB (stop flag on the op, as RulePtrArith sets it) + LOAD.
    Varnode *tA = makePtrsub(8, true);
    Varnode *vA = makeLoad(tA);
    // B: identical PTRSUB without the stop flag (control).
    Varnode *tB = makePtrsub(8, false);
    Varnode *vB = makeLoad(tB);
    // C: INT_SUB consumes the pointer — base TypeOp::propagateType returns
    // null (typeop.cc:317-321): no pointer reaches the output.
    PcodeOp *subOp = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
    fd.opSetOpcode(subOp, CPUI_INT_SUB);
    fd.opSetInput(subOp, bar, 0);
    fd.opSetInput(subOp, fd.newConstant(8, 8), 1);
    Varnode *tC = fd.newUniqueOut(8, subOp);
    fd.opInsertEnd(subOp, block);
    // Consumer that cannot retype tC: a comparison against a constant. (A
    // LOAD consumer would let TypeOpLoad's inslot==-1 reverse edge retype the
    // address as a pointer to the loaded value, masking the null arm.)
    PcodeOp *eqCOp = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
    fd.opSetOpcode(eqCOp, CPUI_INT_EQUAL);
    fd.opSetInput(eqCOp, tC, 0);
    fd.opSetInput(eqCOp, fd.newConstant(8, 0), 1);
    Varnode *vC = fd.newUniqueOut(1, eqCOp);
    fd.opInsertEnd(eqCOp, block);
    // D: INT_ADD pointer arm runs the same propagateAddIn2Out downChain.
    PcodeOp *addOp = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
    fd.opSetOpcode(addOp, CPUI_INT_ADD);
    fd.opSetInput(addOp, bar, 0);
    fd.opSetInput(addOp, fd.newConstant(8, 8), 1);
    Varnode *tD = fd.newUniqueOut(8, addOp);
    fd.opInsertEnd(addOp, block);
    Varnode *vD = makeLoad(tD);
    // E/F: propagateTypeEdge cc:5093 seal check. q is the output of a
    // STOP-flagged PTRSUB from an untyped input (so its local temp stays
    // int8); q2 is the same shape without the stop flag. The INT_EQUAL
    // across-input arm passes bar's plain ProgressData* through unchanged on
    // both sides (typeop.cc:976-981: only the PointerRel form is downgraded):
    // without the seal the sibling input takes the pointer; with the seal the
    // edge is rejected at coreaction.cc:5093.
    Varnode *z = fd.newVarnode(8, Address(reg, 0x140));
    z = fd.setInputVarnode(z);
    Varnode *z2 = fd.newVarnode(8, Address(reg, 0x180));
    z2 = fd.setInputVarnode(z2);
    Varnode *q = [&]() {
      PcodeOp *op = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
      fd.opSetOpcode(op, CPUI_PTRSUB);
      fd.opSetInput(op, z, 0);
      fd.opSetInput(op, fd.newConstant(8, 8), 1);
      Varnode *out = fd.newUniqueOut(8, op);
      fd.opInsertEnd(op, block);
      op->setStopTypePropagation();
      return out;
    }();
    Varnode *q2 = [&]() {
      PcodeOp *op = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
      fd.opSetOpcode(op, CPUI_PTRSUB);
      fd.opSetInput(op, z2, 0);
      fd.opSetInput(op, fd.newConstant(8, 8), 1);
      Varnode *out = fd.newUniqueOut(8, op);
      fd.opInsertEnd(op, block);
      return out;
    }();
    PcodeOp *eqOp = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
    fd.opSetOpcode(eqOp, CPUI_INT_EQUAL);
    fd.opSetInput(eqOp, bar, 0);
    fd.opSetInput(eqOp, q, 1);
    Varnode *cEQ = fd.newUniqueOut(1, eqOp);
    fd.opInsertEnd(eqOp, block);
    PcodeOp *eq2Op = fd.newOp(2, Address(ram, 0x5000 + (seq++)));
    fd.opSetOpcode(eq2Op, CPUI_INT_EQUAL);
    fd.opSetInput(eq2Op, bar, 0);
    fd.opSetInput(eq2Op, q2, 1);
    Varnode *cEQ2 = fd.newUniqueOut(1, eq2Op);
    fd.opInsertEnd(eq2Op, block);

    cells.push_back(Cell{"tA", tA});
    cells.push_back(Cell{"tB", tB});
    cells.push_back(Cell{"tC", tC});
    cells.push_back(Cell{"tD", tD});
    cells.push_back(Cell{"vA", vA});
    cells.push_back(Cell{"vB", vB});
    cells.push_back(Cell{"vC", vC});
    cells.push_back(Cell{"vD", vD});
    cells.push_back(Cell{"q", q});
    cells.push_back(Cell{"q2", q2});
    cells.push_back(Cell{"cEQ", cEQ});
    cells.push_back(Cell{"cEQ2", cEQ2});

    cout << "pre|" << snapshot(cells) << '\n';

    fd.startTypeRecovery();
    ActionInferTypes action("typerecovery");
    action.reset(fd);
    vector<Datatype *> firstTypes;
    for (size_t i = 0; i < cells.size(); ++i)
      firstTypes.push_back(cells[i].vn->getType());
    for (int4 pass = 1; pass <= 8; ++pass) {
      action.apply(fd);
      if (pass == 1) {
        for (size_t i = 0; i < cells.size(); ++i)
          firstTypes[i] = cells[i].vn->getType();
        cout << "pass1|" << snapshot(cells) << '\n';
      }
      else if (pass == 2)
        cout << "pass2|" << snapshot(cells) << '\n';
      else if (pass == 8) {
        bool stable = true;
        for (size_t i = 0; i < cells.size(); ++i)
          stable &= (cells[i].vn->getType() == firstTypes[i]);
        cout << "pass8|" << snapshot(cells)
             << "|types_stable_since_pass1=" << (stable ? 1 : 0) << '\n';
      }
    }
  }
  catch (const LowlevelError &error) {
    cout << "exception|what=" << error.explain << '\n';
    return 1;
  }
  catch (const exception &error) {
    cout << "exception|what=" << error.what() << '\n';
    return 1;
  }
  return 0;
}
