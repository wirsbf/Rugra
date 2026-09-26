/*
 * Locked Ghidra 12.0.4 oracle for WORKPKG-UNMAP-TYPEUNION-0003 /
 * CURLCANON-UNIONSTORE-ARBITRATION-0001: the union-store arbitration
 * foundation family of type.cc, exercised through the REAL scoring and
 * resolution machinery:
 *
 *   - TypeStruct::nearestArrayedComponentForward  (type.cc:1698-1740)
 *   - TypeStruct::nearestArrayedComponentBackward (type.cc:1669-1696)
 *   - TypePointer::testForArraySlack              (type.cc:990-1005)
 *   - TypeUnion::resolveInFlow / findResolve       (type.cc:2125/2137)
 *   - TypeUnion::resolveTruncation (write side)    (type.cc:2147-2177)
 *   - TypeUnion::findTruncation (read-only consult)(type.cc:2185-2199)
 *   - TypePointer::resolveInFlow (union pointee)   (type.cc:1177-1190)
 *   - TypeStruct::scoreSingleComponent            (type.cc:1893-1927)
 *       COPY/INDIRECT arm, LOAD/STORE arm, and the CALL arm
 *       (type.cc:1913-1925) through a REAL FuncCallSpecs with a locked
 *       input parameter / locked output whose data-type IS the parent
 *   - TypeArray::resolveInFlow                    (type.cc:1283-1296)
 *   - TypePartialUnion::resolveInFlow/findResolve (type.cc:2498/2517)
 *
 * Records (stdout, one line per observation):
 *
 *   walk.fwd.before    SLACK off=-2  -> the arr field, newoff=-6, elSize=4
 *   walk.fwd.midskip   SLACK off=2   -> middle of non-struct skipped, arr
 *                      at newoff=-2 (type.cc:1710-1713 skip arm)
 *   walk.fwd.nested    NEST off=2    -> middle of a STRUCT field descends
 *                      (no skip), returning the subfield `in` (the SLACK
 *                      struct) with newoff=-2, elSize from the inner walk
 *   walk.fwd.cutoff    PLAIN off=-200 -> first field diff 200 > 128 break
 *   walk.bwd.hit       SLACK off=6   -> arr at newoff=2
 *   walk.bwd.remain    NEST off=20   -> the non-first `in` field probes its
 *                      TAIL (remain = size-1, type.cc:1686), the inner walk
 *                      finds arr; the outer returns `in`, newoff=20
 *   walk.bwd.cutoff    SLACK off=200 -> diff 188 > 128 break
 *   slack.*            TypePointer::testForArraySlack: array short-circuit,
 *                      struct forward/backward hits, nested hit, plain
 *                      miss, 128-cutoff miss
 *   union.whole.*      COPY read of a union Varnode with an UNlocked
 *                      output: testSimpleCases returns true (unionresolve.cc
 *                      :130-136), fieldNum=-1, resolve/findResolve return
 *                      the union, findTruncation consults nothing (miss)
 *   union.field.*      COPY read with the output typelocked to field a's
 *                      int4: full ScoreUnionFields scoring
 *                      (scoreLockedType +5+3 for a, -5 for the whole,
 *                      -1 for b), resolve/findResolve return int4,
 *                      findTruncation(0,4) hits field a at newoff 0,
 *                      findTruncation(0,8) spans ("Truncation spans more
 *                      than one field", type.cc:2194-2195)
 *   ptr.whole.resolve  pointer-to-union read with unlocked output:
 *                      testSimpleCases COPY arm -> the pointer itself
 *   ptr.field.resolve  pointer-to-union read with the output typelocked
 *                      pointer-to-int4: scoring builds the field pointer
 *                      via ResolvedUnion(parent,fldNum,typegrp)
 *                      (unionresolve.cc:51-54) -> "int *"
 *   box.copy.lock      single-field struct COPY, slot 0, output typelocked
 *                      to the parent: scoreSingleComponent -1 (whole)
 *   box.copy.default   unlocked output: 0 (component) -> field x (long)
 *   box.load.lock      LOAD with the address input typelocked
 *                      pointer-to-parent, slot -1: getTypeReadFacing
 *                      consults findResolve (varnode.cc:639-645) -> -1
 *   box.store.lock     STORE with the address input typelocked
 *                      pointer-to-parent, slot 2 -> -1
 *   box.call.lock      CALL with the parent at input slot 1 and a REAL
 *                      FuncCallSpecs whose locked input parameter(0)
 *                      data-type IS the parent -> -1 (type.cc:1913-1924)
 *   box.call.default   CALL with no call-specs (getCallSpecs null,
 *                      funcdata.cc:484-496) -> 0 (component)
 *   box.call.output    CALL writing the parent (slot -1) with a locked
 *                      output data-type == parent -> -1 (type.cc:1920-1924)
 *   arr.copy.lock      size-1 array (needs_resolution, type.hh:937-944)
 *                      COPY with output typelocked to the array -> -1
 *   arr.copy.default   unlocked output -> 0 -> the element (long)
 *   pu2.field          TypePartialUnion over a union with a 2-byte field:
 *                      resolveTruncation scores the implied truncation
 *                      (unionresolve.cc:1083-1108), field c wins, the
 *                      walk lands on int2 exactly
 *   pu2.consult        findResolve on the SAME edge: the container walk
 *                      reads the cached (union,op,slot) resolution
 *   pu4.stripped       partial over a union with only 4-byte fields: the
 *                      truncation resolves to field a but the walk cannot
 *                      shrink int4 to 2 bytes -> the stripped twin
 *                      (getBase(2,TYPE_UNKNOWN) = "undefined2")
 *
 * Object graph: BfdArchitecture over the pinned curl binary (same
 * construction pattern as printc_subpiece_fieldextract_1204.cc); the
 * GetStr Funcdata hosts every op; each op is inserted into a fresh
 * BlockBasic so op->getParent()->getFuncdata() is reachable
 * (type.cc:2128). Every fixture type is built exactly once under a
 * unique fixture_rf_* name. The call-specs cells use the PUBLIC
 * production-shaped path only: FuncCallSpecs(op) + FuncProto::setInternal
 * + FuncProto::setPieces with the cspec's "__stdcall" model (the x86-64
 * SysV default) + Funcdata::newVarnodeCallSpecs wiring, exactly as
 * FlowInfo::setupCallSpecs builds a locked call site. The model's
 * assignParameterStorage provably preserves an 8-byte struct parameter and
 * an 8-byte struct return EXACTLY (probe_callspec: param0_same=1,
 * output_same=1), so the locked parameter data-type IS the parent object
 * with no wrapping.
 */

#include <bits/stdc++.h>
#include <bfd.h>
#include <errno.h>
#include <termios.h>
#include <zlib.h>

// TypePointer::testForArraySlack is protected (type.hh:402) and only called
// from TypePointer::isPtrsubMatching within type.cc; the fixture re-exposes
// it the same way setcasts_output_bank_1204.cc reaches protected surfaces —
// a surgical access override scoped to this one header.
#define protected public
#include "type.hh"
#undef protected
#include "architecture.hh"
#include "bfd_arch.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "unionresolve.hh"

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::runtime_error;
using std::string;
using std::vector;

// Fixture types, each built EXACTLY ONCE (findAdd throws on redefinition
// of a completed name, type.cc:3421-3423).
struct FixtureTypes {
  Datatype *int2;
  Datatype *int4;
  Datatype *uint4;
  Datatype *int8;
  TypeUnion *unionU;   // fixture_rf_union { int4 a; uint4 b }
  TypeUnion *unionU2;  // fixture_rf_union2 { int2 c; int4 d }
  TypeStruct *box;     // fixture_rf_box { long x }  (needs_resolution)
  TypeArray *arr;      // long[1] size-1 array (needs_resolution)
  TypeStruct *slack;   // fixture_rf_slack { int4 pad; int4[2] arr; int4 tail }
  TypeStruct *nest;    // fixture_rf_nest { fixture_rf_slack in; long t }
  TypeStruct *plain;   // fixture_rf_plain { long p; long q }
  TypePartialUnion *partialU2;  // fixture_rf_union2 off 0 sz 2
  TypePartialUnion *partialU;   // fixture_rf_union  off 0 sz 2
  TypePointer *ptrToU;          // fixture_rf_union *
  TypePointer *ptrToInt4;       // int *

  explicit FixtureTypes(TypeFactory *types)
  {
    int2 = types->getBase(2, TYPE_INT);
    int4 = types->getBase(4, TYPE_INT);
    uint4 = types->getBase(4, TYPE_UINT);
    int8 = types->getBase(8, TYPE_INT);
    unionU = types->getTypeUnion("fixture_rf_union");
    {
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "a", int4));
      fd.push_back(TypeField(1, 0, "b", uint4));
      types->setFields(fd, unionU, 4, 4, 0);
    }
    unionU2 = types->getTypeUnion("fixture_rf_union2");
    {
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "c", int2));
      fd.push_back(TypeField(1, 0, "d", int4));
      types->setFields(fd, unionU2, 4, 4, 0);
    }
    box = types->getTypeStruct("fixture_rf_box");
    {
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "x", int8));
      types->setFields(fd, box, 8, 8, 0);
    }
    arr = types->getTypeArray(1, int8);
    slack = types->getTypeStruct("fixture_rf_slack");
    {
      TypeArray *intArray2 = types->getTypeArray(2, int4);
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "pad", int4));
      fd.push_back(TypeField(1, 4, "arr", intArray2));
      fd.push_back(TypeField(2, 12, "tail", int4));
      types->setFields(fd, slack, 16, 4, 0);
    }
    nest = types->getTypeStruct("fixture_rf_nest");
    {
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "in", slack));
      fd.push_back(TypeField(1, 16, "t", int8));
      types->setFields(fd, nest, 24, 8, 0);
    }
    plain = types->getTypeStruct("fixture_rf_plain");
    {
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "p", int8));
      fd.push_back(TypeField(1, 8, "q", int8));
      types->setFields(fd, plain, 16, 8, 0);
    }
    partialU2 = types->getTypePartialUnion(unionU2, 0, 2);
    partialU = types->getTypePartialUnion(unionU, 0, 2);
    ptrToU = types->getTypePointer(8, unionU, 1);
    ptrToInt4 = types->getTypePointer(8, int4, 1);
  }
};

// printRaw as a string (Ghidra's printRaw takes an ostream).
string pr(const Datatype *ct)
{
  std::ostringstream ss;
  ct->printRaw(ss);
  return ss.str();
}

// Name-independent metatype token for the stripped-twin record.
const char *mtName(type_metatype m)
{
  switch (m) {
  case TYPE_INT: return "int";
  case TYPE_UINT: return "uint";
  case TYPE_BOOL: return "bool";
  case TYPE_FLOAT: return "float";
  case TYPE_PTR: return "ptr";
  case TYPE_ARRAY: return "array";
  case TYPE_STRUCT: return "struct";
  case TYPE_UNION: return "union";
  case TYPE_PARTIALUNION: return "partialunion";
  default: return "unknown";
  }
}

void emitWalk(const char *label, Datatype *comp, int8 newoff, int8 elSize)
{
  if (comp == (Datatype *)0) {
    cout << label << "=miss\n";
    return;
  }
  cout << label << "=[" << pr(comp) << "] newoff=" << newoff
       << " elSize=" << elSize << '\n';
}

void runWalkSweep(const FixtureTypes &ft)
{
  int8 newoff;
  int8 elSize;
  Datatype *comp;

  comp = ft.slack->nearestArrayedComponentForward(-2, &newoff, &elSize);
  emitWalk("walk.fwd.before", comp, newoff, elSize);
  comp = ft.slack->nearestArrayedComponentForward(2, &newoff, &elSize);
  emitWalk("walk.fwd.midskip", comp, newoff, elSize);
  comp = ft.nest->nearestArrayedComponentForward(2, &newoff, &elSize);
  emitWalk("walk.fwd.nested", comp, newoff, elSize);
  comp = ft.plain->nearestArrayedComponentForward(-200, &newoff, &elSize);
  emitWalk("walk.fwd.cutoff", comp, newoff, elSize);
  comp = ft.slack->nearestArrayedComponentBackward(6, &newoff, &elSize);
  emitWalk("walk.bwd.hit", comp, newoff, elSize);
  comp = ft.nest->nearestArrayedComponentBackward(20, &newoff, &elSize);
  emitWalk("walk.bwd.remain", comp, newoff, elSize);
  comp = ft.slack->nearestArrayedComponentBackward(200, &newoff, &elSize);
  emitWalk("walk.bwd.cutoff", comp, newoff, elSize);

  cout << "slack.array=" << (TypePointer::testForArraySlack(ft.arr, 0) ? 1 : 0) << '\n';
  cout << "slack.fwd=" << (TypePointer::testForArraySlack(ft.slack, -2) ? 1 : 0) << '\n';
  cout << "slack.bwd=" << (TypePointer::testForArraySlack(ft.slack, 6) ? 1 : 0) << '\n';
  cout << "slack.nested=" << (TypePointer::testForArraySlack(ft.nest, 20) ? 1 : 0) << '\n';
  cout << "slack.plain=" << (TypePointer::testForArraySlack(ft.plain, 6) ? 1 : 0) << '\n';
  cout << "slack.cutoff=" << (TypePointer::testForArraySlack(ft.plain, 200) ? 1 : 0) << '\n';
}

// Op-builder: every op lives in a fresh BlockBasic of the GetStr Funcdata
// so op->getParent()->getFuncdata() is reachable (type.cc:2128/1932/1286).
struct OpFixture {
  Funcdata &fd;
  Architecture *glb;
  AddrSpace *regSpace;
  AddrSpace *codeSpace;
  uintb pc;

  OpFixture(Funcdata &f, Architecture *g, uintb basePc)
    : fd(f), glb(g), pc(basePc)
  {
    regSpace = glb->getSpaceByName("register");
    codeSpace = glb->getDefaultCodeSpace();
    if (regSpace == (AddrSpace *)0 || codeSpace == (AddrSpace *)0)
      throw runtime_error("fixture requires register and code spaces");
  }

  BlockBasic *freshBlock()
  {
    return const_cast<BlockGraph &>(fd.getBasicBlocks()).newBlockBasic(&fd);
  }

  PcodeOp *newOpInBlock(int4 numInputs)
  {
    PcodeOp *op = fd.newOp(numInputs, Address(codeSpace, pc));
    pc += 0x10;
    return op;
  }

  // A typed register-space Varnode; `lock` installs the typelock flag
  // (Varnode::updateType(ct,lock,over), varnode.cc:474-487).
  Varnode *typedRegVn(Datatype *ct, int4 vnSize, uintb regOff, bool lock)
  {
    Varnode *vn = fd.newVarnode(vnSize, Address(regSpace, regOff));
    vn->updateType(ct, lock, true);
    return vn;
  }

  // COPY reading `inVn` at slot 0; the output is a fresh unique Varnode,
  // optionally typelocked to `outType`.
  PcodeOp *copyReading(Varnode *inVn, Datatype *outType)
  {
    PcodeOp *op = newOpInBlock(1);
    fd.opSetOpcode(op, CPUI_COPY);
    fd.opSetInput(op, inVn, 0);
    Varnode *out = fd.newUniqueOut(inVn->getSize(), op);
    if (outType != (Datatype *)0)
      out->updateType(outType, true, true);
    fd.opInsertEnd(op, freshBlock());
    return op;
  }

  // Install a FuncCallSpecs on `callOp` with a locked input parameter
  // whose data-type IS `paramType`, and/or a locked output data-type
  // `outType`. The PUBLIC production-shaped path (FlowInfo::setupCallSpecs
  // minus the flow): FuncCallSpecs(op) + setInternal + setPieces with the
  // cspec "__stdcall" model — assignParameterStorage preserves an 8-byte
  // struct parameter/return EXACTLY (probe_callspec evidence) — then the
  // newVarnodeCallSpecs wiring so Funcdata::getCallSpecs(op) finds the
  // spec through the FSPEC-space annotation.
  void attachCallSpecs(PcodeOp *callOp, Datatype *paramType, Datatype *outType)
  {
    ProtoModel *model = glb->getModel("__stdcall");
    if (model == (ProtoModel *)0)
      throw runtime_error("fixture requires the __stdcall prototype model");
    FuncCallSpecs *fc = new FuncCallSpecs(callOp);
    fc->setInternal(model, glb->types->getTypeVoid());
    PrototypePieces pieces;
    pieces.model = model;
    pieces.name = "fixture_rf_call";
    pieces.outtype = (outType != (Datatype *)0) ? outType : glb->types->getTypeVoid();
    if (paramType != (Datatype *)0) {
      pieces.intypes.push_back(paramType);
      pieces.innames.push_back("p0");
    }
    pieces.firstVarArgSlot = -1;
    fc->setPieces(pieces);
    fd.opSetInput(callOp, fd.newVarnodeCallSpecs(fc), 0);
  }
};

void runUnionCells(Funcdata &fd, Architecture *glb, const FixtureTypes &ft)
{
  // ---- whole-member arbitration (testSimpleCases COPY arm) ----
  {
    OpFixture fx(fd, glb, 0x5000);
    Varnode *vn = fx.typedRegVn(ft.unionU, 4, 0x40, true);
    PcodeOp *op = fx.copyReading(vn, (Datatype *)0);
    Datatype *res = ft.unionU->resolveInFlow(op, 0);
    cout << "union.whole.resolve=[" << pr(res) << "]\n";
    res = ft.unionU->findResolve(op, 0);
    cout << "union.whole.findres=[" << pr(res) << "]\n";
    int8 newoff;
    const TypeField *field = ft.unionU->findTruncation(0, 4, op, 0, newoff);
    cout << "union.whole.trunc=" << (field == (const TypeField *)0 ? "miss" : "hit") << '\n';
  }
  // ---- field-win arbitration (full ScoreUnionFields scoring) ----
  {
    OpFixture fx(fd, glb, 0x6000);
    Varnode *vn = fx.typedRegVn(ft.unionU, 4, 0x48, true);
    PcodeOp *op = fx.copyReading(vn, ft.int4);
    Datatype *res = ft.unionU->resolveInFlow(op, 0);
    cout << "union.field.resolve=[" << pr(res) << "]\n";
    res = ft.unionU->findResolve(op, 0);
    cout << "union.field.findres=[" << pr(res) << "]\n";
    int8 newoff;
    const TypeField *field = ft.unionU->findTruncation(0, 4, op, 0, newoff);
    if (field == (const TypeField *)0)
      cout << "union.field.trunc.hit=miss\n";
    else
      cout << "union.field.trunc.hit=" << field->name << " newoff=" << newoff << '\n';
    field = ft.unionU->findTruncation(0, 8, op, 0, newoff);
    cout << "union.field.trunc.span=" << (field == (const TypeField *)0 ? "miss" : "hit") << '\n';
  }
  // ---- pointer-to-union arms (type.cc:1177-1202) ----
  {
    OpFixture fx(fd, glb, 0x7000);
    Varnode *vn = fx.typedRegVn(ft.ptrToU, 8, 0x50, true);
    PcodeOp *op = fx.copyReading(vn, (Datatype *)0);
    Datatype *res = ft.ptrToU->resolveInFlow(op, 0);
    cout << "ptr.whole.resolve=[" << pr(res) << "]\n";
  }
  {
    OpFixture fx(fd, glb, 0x8000);
    Varnode *vn = fx.typedRegVn(ft.ptrToU, 8, 0x58, true);
    PcodeOp *op = fx.copyReading(vn, ft.ptrToInt4);
    Datatype *res = ft.ptrToU->resolveInFlow(op, 0);
    cout << "ptr.field.resolve=[" << pr(res) << "]\n";
  }
}

void runScoreCells(Funcdata &fd, Architecture *glb, const FixtureTypes &ft)
{
  // box.copy.lock: COPY slot 0 with the OUTPUT typelocked to the parent.
  {
    OpFixture fx(fd, glb, 0x9000);
    Varnode *vn = fx.typedRegVn(ft.box, 8, 0x60, true);
    PcodeOp *op = fx.copyReading(vn, ft.box);
    Datatype *res = ft.box->resolveInFlow(op, 0);
    cout << "box.copy.lock=[" << pr(res) << "]\n";
  }
  // box.copy.default: unlocked output -> the component.
  {
    OpFixture fx(fd, glb, 0xa000);
    Varnode *vn = fx.typedRegVn(ft.box, 8, 0x68, true);
    PcodeOp *op = fx.copyReading(vn, (Datatype *)0);
    Datatype *res = ft.box->resolveInFlow(op, 0);
    cout << "box.copy.default=[" << pr(res) << "]\n";
  }
  // box.load.lock: LOAD, address input typelocked pointer-to-parent,
  // slot -1 (the output side).
  {
    OpFixture fx(fd, glb, 0xb000);
    TypeFactory *types = glb->types;
    TypePointer *ptrToBox = types->getTypePointer(8, ft.box, 1);
    PcodeOp *op = fx.newOpInBlock(2);
    fd.opSetOpcode(op, CPUI_LOAD);
    fd.opSetInput(op, fd.newConstant(1, 0), 0);
    Varnode *addr = fx.typedRegVn(ptrToBox, 8, 0x70, true);
    fd.opSetInput(op, addr, 1);
    fd.newUniqueOut(8, op);
    fd.opInsertEnd(op, fx.freshBlock());
    Datatype *res = ft.box->resolveInFlow(op, -1);
    cout << "box.load.lock=[" << pr(res) << "]\n";
  }
  // box.store.lock: STORE, address input typelocked pointer-to-parent,
  // slot 2 (the value input).
  {
    OpFixture fx(fd, glb, 0xc000);
    TypeFactory *types = glb->types;
    TypePointer *ptrToBox = types->getTypePointer(8, ft.box, 1);
    PcodeOp *op = fx.newOpInBlock(3);
    fd.opSetOpcode(op, CPUI_STORE);
    fd.opSetInput(op, fd.newConstant(1, 0), 0);
    Varnode *addr = fx.typedRegVn(ptrToBox, 8, 0x78, true);
    fd.opSetInput(op, addr, 1);
    Varnode *value = fx.typedRegVn(ft.box, 8, 0x80, true);
    fd.opSetInput(op, value, 2);
    fd.opInsertEnd(op, fx.freshBlock());
    Datatype *res = ft.box->resolveInFlow(op, 2);
    cout << "box.store.lock=[" << pr(res) << "]\n";
  }
  // box.call.lock: CALL with the parent at input slot 1 and a REAL
  // FuncCallSpecs whose locked input parameter IS the parent.
  {
    OpFixture fx(fd, glb, 0xd000);
    PcodeOp *op = fx.newOpInBlock(2);
    fd.opSetOpcode(op, CPUI_CALL);
    fd.opSetInput(op, fd.newConstant(8, 0x1000), 0);
    Varnode *arg = fx.typedRegVn(ft.box, 8, 0x88, true);
    fd.opSetInput(op, arg, 1);
    fd.newUniqueOut(1, op);
    fd.opInsertEnd(op, fx.freshBlock());
    fx.attachCallSpecs(op, ft.box, (Datatype *)0);
    Datatype *res = ft.box->resolveInFlow(op, 1);
    cout << "box.call.lock=[" << pr(res) << "]\n";
  }
  // box.call.default: no call-specs at all (getCallSpecs -> null).
  {
    OpFixture fx(fd, glb, 0xe000);
    PcodeOp *op = fx.newOpInBlock(2);
    fd.opSetOpcode(op, CPUI_CALL);
    fd.opSetInput(op, fd.newConstant(8, 0x1000), 0);
    Varnode *arg = fx.typedRegVn(ft.box, 8, 0x90, true);
    fd.opSetInput(op, arg, 1);
    fd.newUniqueOut(1, op);
    fd.opInsertEnd(op, fx.freshBlock());
    Datatype *res = ft.box->resolveInFlow(op, 1);
    cout << "box.call.default=[" << pr(res) << "]\n";
  }
  // box.call.output: CALL writing the parent (slot -1) with a locked
  // output data-type == parent.
  {
    OpFixture fx(fd, glb, 0xf000);
    PcodeOp *op = fx.newOpInBlock(1);
    fd.opSetOpcode(op, CPUI_CALL);
    fd.opSetInput(op, fd.newConstant(8, 0x1000), 0);
    Varnode *out = fd.newUniqueOut(8, op);
    out->updateType(ft.box, true, true);
    fd.opInsertEnd(op, fx.freshBlock());
    fx.attachCallSpecs(op, (Datatype *)0, ft.box);
    Datatype *res = ft.box->resolveInFlow(op, -1);
    cout << "box.call.output=[" << pr(res) << "]\n";
  }
  // arr.copy.lock / arr.copy.default: size-1 array parent.
  {
    OpFixture fx(fd, glb, 0x10000);
    Varnode *vn = fx.typedRegVn(ft.arr, 8, 0x98, true);
    PcodeOp *op = fx.copyReading(vn, ft.arr);
    Datatype *res = ft.arr->resolveInFlow(op, 0);
    cout << "arr.copy.lock=[" << pr(res) << "]\n";
  }
  {
    OpFixture fx(fd, glb, 0x11000);
    Varnode *vn = fx.typedRegVn(ft.arr, 8, 0xa0, true);
    PcodeOp *op = fx.copyReading(vn, (Datatype *)0);
    Datatype *res = ft.arr->resolveInFlow(op, 0);
    cout << "arr.copy.default=[" << pr(res) << "]\n";
  }
}

void runPartialCells(Funcdata &fd, Architecture *glb, const FixtureTypes &ft)
{
  // pu2.field: partial over a union with a 2-byte field; the implied
  // truncation scores field c and the walk lands on int2 exactly.
  {
    OpFixture fx(fd, glb, 0x12000);
    Varnode *vn = fx.typedRegVn(ft.partialU2, 2, 0xa8, true);
    PcodeOp *op = fx.copyReading(vn, ft.int2);
    Datatype *res = ft.partialU2->resolveInFlow(op, 0);
    cout << "pu2.field=[" << pr(res) << "]\n";
    // pu2.consult: findResolve on the SAME edge reads the cached
    // (union,op,slot) resolution written by the resolveInFlow above.
    res = ft.partialU2->findResolve(op, 0);
    cout << "pu2.consult=[" << pr(res) << "]\n";
  }
  // pu4.stripped: partial over a union with only 4-byte fields; the
  // truncation resolves to field a but int4 cannot shrink to 2 bytes, so
  // the walk falls off the end and returns the stripped twin. The record
  // is name-independent (size + metatype): the stripped twin is built by
  // the factory's internal getBase(sz,TYPE_UNKNOWN), whose core name is
  // environment-dependent (C++ SleighArchitecture default "xunknown2" vs
  // the Java/headless coreBuiltin the Rust factory mirrors), while the
  // semantic content — the stripped 2-byte unknown twin — is identical.
  {
    OpFixture fx(fd, glb, 0x13000);
    Varnode *vn = fx.typedRegVn(ft.partialU, 2, 0xb0, true);
    PcodeOp *op = fx.copyReading(vn, ft.int2);
    Datatype *res = ft.partialU->resolveInFlow(op, 0);
    cout << "pu4.stripped=size=" << res->getSize()
         << " mt=" << mtName(res->getMetatype()) << '\n';
  }
}

void run(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary, "default", &cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw runtime_error("runtime architecture/compiler drifted: " + architecture.archid);
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->getName() != "GetStr" ||
        fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
      throw runtime_error("GetStr input identity drifted");

    FixtureTypes ft(architecture.types);
    runWalkSweep(ft);
    runUnionCells(*fd, &architecture, ft);
    runScoreCells(*fd, &architecture, ft);
    runPartialCells(*fd, &architecture, ft);
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: typeunion_resolveflow_1204 <spec-dir> <binary>\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
  }
  catch (std::exception &err) {
    cerr << "fixture failed: " << err.what() << '\n';
    return 1;
  }
  return 0;
}
