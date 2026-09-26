/*
 * MIGW1-TYPEOP-0002: locked Ghidra 12.0.4 per-op TypeOp::push dispatch
 * oracle — one observable render for every routed op-code family.
 *
 * Drives the production PrintC::emitExpression (printc.cc:2468-2495) over
 * synthetic constant-leaf expression graphs built through production
 * Funcdata APIs (Scope::addFunction -> newOp / opSetOpcode / opSetInput /
 * newUniqueOut / newConstant / Varnode::updateType / setImplied /
 * setHighLevel), exactly like printc_intnot_token_1204.cc.  Top-level ops
 * have NO output varnode so emitExpression skips the assignment arm
 * (printc.cc:2471-2476); sub-expression outputs are implied, so the RPN
 * recurse drain (printlanguage.cc:514-540) dispatches each defining op
 * through `defOp->getOpcode()->push(this, defOp, op)` — the exact virtual
 * TypeOp push hop this fixture locks.
 *
 * Coverage (typeop.hh push anchors; the case name names the route):
 *   - printc.hh:283-308/310-312/313-321 opBinary one-liners: 23 INT_/BOOL_
 *     binary tokens (equal/not_equal/less_than/less_equal/binary_plus/
 *     binary_minus/bitwise_and/bitwise_or/bitwise_xor/shift_left/
 *     shift_right/shift_sright/multiply/divide/modulo/boolean_and/
 *     boolean_or/boolean_xor) + 8 FLOAT_ binary tokens (same instances).
 *   - printc.hh:296-297/322 opUnary one-liners: INT_2COMP/INT_NEGATE
 *     (unary_minus/bitwise_not) + FLOAT_NEG (unary_minus).
 *   - printc.hh:293-295/317/323-324/328-330/333/343-344 opFunc one-liners:
 *     CARRY4/SCARRY4/SBORROW4 (getOperatorName appends in(0) size,
 *     typeop.cc:1340-1378), NAN/ABS/SQRT/CEIL/FLOOR/ROUND (ctor names,
 *     typeop.cc:1775-1936), CONCAT44 (typeop.cc:2048-2056), POPCOUNT /
 *     LZCOUNT (typeop.cc:2558/2565).
 *   - printc.cc:786/799 opIntZext/opIntSext: the ZEXT44/SEXT44 opFunc
 *     fallbacks (same-size in/out defeats isZextCast/isSextCast) and the
 *     (uint4)/(int4) typecast arms (uint1->uint4 / int1->int4 recognized
 *     casts, read by an INT_AND so readOp is non-null).
 *   - printc.cc:814-828 opBoolNegate: the full three-branch chain —
 *     boolean_not on a non-flippable constant input, the token flip
 *     !(a==b) -> a != b via negatetoken + opBinary's negate prelude
 *     (printlanguage.cc:539-545), and the double-negation cancellation
 *     (branch 1 consumes the outer negatetoken, the inner comparison
 *     prints unflipped).
 *   - printc.cc:830 opFloatInt2Float / printc.hh:326-327
 *     opFloatFloat2Float/opFloatTrunc -> opTypeCast `(uint4)` forms.
 *   - printc.cc:872-877 opSubpiece opFunc fallback SUB44 (same-size
 *     in/out defeats isSubpieceCast).
 *   - printc.cc:880-893 opPtradd plain binary_plus form (PRINT_LOAD_VALUE
 *     clear; in(1)/in(0) pushed, in(2) never printed).
 *
 * Types: all leaves/outputs typed via TypeFactory bases (uint4/int4/uint1/
 * int1 registered as core types); float opcodes ride uint4-typed operands —
 * every routed token/name decision above is type-blind, and the one
 * type-dependent family (ZEXT/SEXT/INT2FLOAT/FLOAT2FLOAT/TRUNC) uses the
 * explicit base types so both sides print the same cast spellings.
 */

#include "architecture.hh"
#include "capability.hh"
#include "comment.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "printc.hh"
#include "prettyprint.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace ghidra;

namespace {

// Synthetic LE 64-bit architecture, same space layout as
// printc_intnot_token_1204.cc: const=0, other=1, unique=2, ram=3, register=4,
// stack=5, join=6, iop=7.
class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false,
                              8, 1, 1, AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register",
                                   false, 8, 1, 4, AddrSpace::hasphysical,
                                   0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this, this, "stack", 5, 8,
                                               ram, 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false,
                              8, 1, 6, AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummy_register.space = reg;
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override {
    return 0;
  }
  int4 printAssembly(AssemblyEmit &, const Address &) const override {
    return 0;
  }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override {
    return (Translate *)0;
  }
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
    types->setCoreType("void", 1, TYPE_VOID, false);
    types->setCoreType("bool", 1, TYPE_BOOL, false);
    types->setCoreType("uint1", 1, TYPE_UINT, false);
    types->setCoreType("int1", 1, TYPE_INT, false);
    types->setCoreType("uint4", 4, TYPE_UINT, false);
    types->setCoreType("uint8", 8, TYPE_UINT, false);
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
    types->setCoreType("float8", 8, TYPE_FLOAT, false);
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

// Swap the default EmitMarkup for the plain-text EmitNoMarkup stream and
// re-expose the protected printc.cc:2468 emitExpression for direct
// expression-level rendering (same pattern as printc_intnot_token_1204).
class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *g)
      : PrintC(g, "typeop-push-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  std::string renderExpression(const PcodeOp *op) {
    std::ostringstream output;
    setOutputStream(&output);
    emitExpression(op);
    emit->flush();
    return output.str();
  }
};

struct ExprBuilder {
  FixtureArchitecture &arch;
  Funcdata &fd;
  AddrSpace *ram;
  Datatype *uint1_ty;
  Datatype *int1_ty;
  Datatype *uint4_ty;
  Datatype *int4_ty;
  uintb pc;

  ExprBuilder(FixtureArchitecture &a, Funcdata &f)
      : arch(a), fd(f), ram(a.getSpace(3)),
        uint1_ty(a.types->getBase(1, TYPE_UINT)),
        int1_ty(a.types->getBase(1, TYPE_INT)),
        uint4_ty(a.types->getBase(4, TYPE_UINT)),
        int4_ty(a.types->getBase(4, TYPE_INT)), pc(0x1000) {}

  Varnode *constantT(uintb val, int4 size, Datatype *dt) {
    Varnode *vn = fd.newConstant(size, val);
    vn->updateType(dt, true, false);
    return vn;
  }

  Varnode *constant4(uintb val) { return constantT(val, 4, uint4_ty); }

  PcodeOp *makeOp(OpCode opc, int4 inputs) {
    PcodeOp *op = fd.newOp(inputs, Address(ram, pc));
    pc += 4;
    fd.opSetOpcode(op, opc);
    return op;
  }

  // Unary op with an implied output (inlined at the use site).
  Varnode *unary(OpCode opc, Varnode *in0, int4 outsize, Datatype *outtype) {
    PcodeOp *op = makeOp(opc, 1);
    fd.opSetInput(op, in0, 0);
    Varnode *out = fd.newUniqueOut(outsize, op);
    out->updateType(outtype, true, false);
    out->setImplied();
    return out;
  }

  // Binary op with an implied output.
  Varnode *binary(OpCode opc, Varnode *in0, Varnode *in1) {
    PcodeOp *op = makeOp(opc, 2);
    fd.opSetInput(op, in0, 0);
    fd.opSetInput(op, in1, 1);
    Varnode *out = fd.newUniqueOut(4, op);
    out->updateType(uint4_ty, true, false);
    out->setImplied();
    return out;
  }

  // Top-level op with NO output: emitExpression skips the assignment arm
  // (printc.cc:2471-2476) and emits only the operator token stream.
  PcodeOp *topBinary(OpCode opc, Varnode *in0, Varnode *in1) {
    PcodeOp *op = makeOp(opc, 2);
    fd.opSetInput(op, in0, 0);
    fd.opSetInput(op, in1, 1);
    return op;
  }

  PcodeOp *topUnary(OpCode opc, Varnode *in0) {
    PcodeOp *op = makeOp(opc, 1);
    fd.opSetInput(op, in0, 0);
    return op;
  }

  PcodeOp *topPtradd(Varnode *in0, Varnode *in1, Varnode *in2) {
    PcodeOp *op = makeOp(CPUI_PTRADD, 3);
    fd.opSetInput(op, in0, 0);
    fd.opSetInput(op, in1, 1);
    fd.opSetInput(op, in2, 2);
    return op;
  }

  void finish(void) { fd.setHighLevel(); }
};

Funcdata &newFuncdata(FixtureArchitecture &arch, const std::string &name,
                      uintb offset) {
  AddrSpace *ram = arch.getSpace(3);
  FunctionSymbol *symbol =
      arch.symboltab->getGlobalScope()->addFunction(Address(ram, offset),
                                                    name);
  Funcdata *fdp = symbol->getFunction();
  if (fdp == (Funcdata *)0)
    throw LowlevelError("failed to construct fixture Funcdata: " + name);
  return *fdp;
}

std::string runCase(FixtureArchitecture &arch, const std::string &name,
                    void (*build)(ExprBuilder &, PcodeOp **)) {
  Funcdata &fd = newFuncdata(arch, "fx_" + name, 0x1000);
  ExprBuilder b(arch, fd);
  PcodeOp *top = (PcodeOp *)0;
  build(b, &top);
  b.finish();
  FixturePrintC printer(&arch);
  std::string text = printer.renderExpression(top);
  return "case=" + name + "|text=" + text;
}

// ---- opBinary one-liners (printc.hh:283-321) ----

void buildBinIntEqual(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_EQUAL, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntNotEqual(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_NOTEQUAL, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntLess(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_LESS, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntSless(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_SLESS, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntLessEqual(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_LESSEQUAL, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntSlessEqual(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_SLESSEQUAL, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntAdd(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_ADD, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntSub(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_SUB, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntAnd(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_AND, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntOr(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_OR, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntXor(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_XOR, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntLeft(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_LEFT, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntRight(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_RIGHT, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntSright(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_SRIGHT, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntMult(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_MULT, b.constant4(0x11), b.constant4(0x22));
}
void buildBinIntDiv(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_DIV, b.constant4(0x22), b.constant4(0x11));
}
void buildBinIntSdiv(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_SDIV, b.constant4(0x22), b.constant4(0x11));
}
void buildBinIntRem(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_REM, b.constant4(0x22), b.constant4(0x11));
}
void buildBinIntSrem(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_SREM, b.constant4(0x22), b.constant4(0x11));
}
void buildBinBoolAnd(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_BOOL_AND, b.constant4(0x11), b.constant4(0x22));
}
void buildBinBoolOr(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_BOOL_OR, b.constant4(0x11), b.constant4(0x22));
}
void buildBinBoolXor(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_BOOL_XOR, b.constant4(0x11), b.constant4(0x22));
}
void buildBinFloatEqual(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_FLOAT_EQUAL, b.constant4(0x11), b.constant4(0x22));
}
void buildBinFloatNotEqual(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_FLOAT_NOTEQUAL, b.constant4(0x11), b.constant4(0x22));
}
void buildBinFloatLess(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_FLOAT_LESS, b.constant4(0x11), b.constant4(0x22));
}
void buildBinFloatLessEqual(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_FLOAT_LESSEQUAL, b.constant4(0x11), b.constant4(0x22));
}
void buildBinFloatAdd(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_FLOAT_ADD, b.constant4(0x11), b.constant4(0x22));
}
void buildBinFloatDiv(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_FLOAT_DIV, b.constant4(0x22), b.constant4(0x11));
}
void buildBinFloatMult(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_FLOAT_MULT, b.constant4(0x11), b.constant4(0x22));
}
void buildBinFloatSub(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_FLOAT_SUB, b.constant4(0x22), b.constant4(0x11));
}

// ---- opUnary one-liners (printc.hh:296-297/322) ----

void buildUnInt2comp(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_INT_2COMP, b.constant4(0x10));
}
void buildUnIntNegate(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_INT_NEGATE, b.constant4(0x10));
}
void buildUnFloatNeg(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_FLOAT_NEG, b.constant4(0x10));
}

// ---- opFunc one-liners (printc.hh:293-295/317/323-324/328-330/333/343-344) ----

void buildFuncIntCarry(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_CARRY, b.constant4(0x11), b.constant4(0x22));
}
void buildFuncIntScarry(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_SCARRY, b.constant4(0x11), b.constant4(0x22));
}
void buildFuncIntSborrow(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_INT_SBORROW, b.constant4(0x11), b.constant4(0x22));
}
void buildFuncFloatNan(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_FLOAT_NAN, b.constant4(0x10));
}
void buildFuncFloatAbs(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_FLOAT_ABS, b.constant4(0x10));
}
void buildFuncFloatSqrt(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_FLOAT_SQRT, b.constant4(0x10));
}
void buildFuncFloatCeil(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_FLOAT_CEIL, b.constant4(0x10));
}
void buildFuncFloatFloor(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_FLOAT_FLOOR, b.constant4(0x10));
}
void buildFuncFloatRound(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_FLOAT_ROUND, b.constant4(0x10));
}
void buildFuncPiece(ExprBuilder &b, PcodeOp **top) {
  *top = b.topBinary(CPUI_PIECE, b.constant4(0x11), b.constant4(0x22));
}
void buildFuncPopcount(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_POPCOUNT, b.constant4(0x10));
}
void buildFuncLzcount(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_LZCOUNT, b.constant4(0x10));
}

// ---- printc.cc:786 opIntZext / printc.cc:799 opIntSext ----
// opIntZext/opIntSext read op->getOut() (def-facing cast type), so every
// case renders them as implied operands of a top INT_AND — the recurse hop
// (printlanguage.cc:532) passes the AND as readOp.  Same-size in/out
// defeats the cast recognizers -> ZEXT44/SEXT44 opFunc; the widening forms
// (uint1->uint4 / int1->int4) are recognized casts.

// The AND's other operand is a SIZE-8 constant: bigger than the promotion
// size (both fixture TypeFactories derive sizeOfInt=4 from the 8-byte
// stack pointer, capped at 4; Rugra's CastStrategyC pins 4), so
// isExtensionCastImplied takes the cast.cc:281-285 explicit-cast branch on
// BOTH sides — the opTypeCast arm renders deterministically.
void buildZextNocast(ExprBuilder &b, PcodeOp **top) {
  Varnode *z = b.unary(CPUI_INT_ZEXT, b.constant4(0x10), 4, b.uint4_ty);
  *top = b.topBinary(CPUI_INT_AND, z,
                     b.constantT(0x22, 8, b.arch.types->getBase(8, TYPE_UINT)));
}
void buildZextCast(ExprBuilder &b, PcodeOp **top) {
  Varnode *z = b.unary(CPUI_INT_ZEXT, b.constantT(0x10, 1, b.uint1_ty), 4, b.uint4_ty);
  *top = b.topBinary(CPUI_INT_AND, z,
                     b.constantT(0x22, 8, b.arch.types->getBase(8, TYPE_UINT)));
}
void buildSextNocast(ExprBuilder &b, PcodeOp **top) {
  Varnode *s = b.unary(CPUI_INT_SEXT, b.constantT(0x10, 4, b.int4_ty), 4, b.int4_ty);
  *top = b.topBinary(CPUI_INT_AND, s,
                     b.constantT(0x22, 8, b.arch.types->getBase(8, TYPE_UINT)));
}
void buildSextCast(ExprBuilder &b, PcodeOp **top) {
  Varnode *s = b.unary(CPUI_INT_SEXT, b.constantT(0x10, 1, b.int1_ty), 4, b.int4_ty);
  *top = b.topBinary(CPUI_INT_AND, s,
                     b.constantT(0x22, 8, b.arch.types->getBase(8, TYPE_UINT)));
}
// The HIDE arm: a PTRADD reader hits isExtensionCastImplied's unconditional
// PTRADD break (cast.cc:263-264 -> return true) on both sides, so the
// recognized extension is hidden (opHiddenFunc) and only the operand
// renders — `0x10 + 0x22`.
void buildZextHide(ExprBuilder &b, PcodeOp **top) {
  Varnode *z = b.unary(CPUI_INT_ZEXT, b.constantT(0x10, 1, b.uint1_ty), 4, b.uint4_ty);
  *top = b.topPtradd(z, b.constant4(0x22), b.constant4(0x0));
}

// ---- printc.cc:814-828 opBoolNegate full decision chain ----

// Branch 3: input is a constant (not an implied comparison) -> boolean_not.
void buildBoolnegPlain(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnary(CPUI_BOOL_NEGATE, b.constant4(0x10));
}
// Branch 2: implied INT_EQUAL input -> negatetoken rides, opBinary's flip
// prelude (printlanguage.cc:539-545) turns `==` into `!=`.
void buildBoolnegFlip(ExprBuilder &b, PcodeOp **top) {
  Varnode *eq = b.binary(CPUI_INT_EQUAL, b.constant4(0x11), b.constant4(0x22));
  *top = b.topUnary(CPUI_BOOL_NEGATE, eq);
}
// Branch 1 under branch 2: the inner BOOL_NEGATE consumes the outer
// negatetoken (printc.cc:817-819) and prints the comparison unflipped —
// double negation cancels.
void buildBoolnegDouble(ExprBuilder &b, PcodeOp **top) {
  Varnode *eq = b.binary(CPUI_INT_EQUAL, b.constant4(0x11), b.constant4(0x22));
  Varnode *inner = b.unary(CPUI_BOOL_NEGATE, eq, 4, b.uint4_ty);
  *top = b.topUnary(CPUI_BOOL_NEGATE, inner);
}

// ---- printc.cc:830 opFloatInt2Float + printc.hh:326-327 cast forms ----

void buildFloatInt2Float(ExprBuilder &b, PcodeOp **top) {
  Varnode *c = b.unary(CPUI_FLOAT_INT2FLOAT, b.constant4(0x10), 4, b.uint4_ty);
  *top = b.topBinary(CPUI_INT_AND, c, b.constant4(0x22));
}
void buildFloatFloat2Float(ExprBuilder &b, PcodeOp **top) {
  Varnode *c = b.unary(CPUI_FLOAT_FLOAT2FLOAT, b.constant4(0x10), 4, b.uint4_ty);
  *top = b.topBinary(CPUI_INT_AND, c, b.constant4(0x22));
}
void buildFloatTrunc(ExprBuilder &b, PcodeOp **top) {
  Varnode *c = b.unary(CPUI_FLOAT_TRUNC, b.constant4(0x10), 4, b.uint4_ty);
  *top = b.topBinary(CPUI_INT_AND, c, b.constant4(0x22));
}

// ---- printc.cc:872-877 opSubpiece opFunc fallback ----
// opSubpiece reads op->getOut() (isSubpieceCast), so the SUBPIECE renders
// as an implied operand of a top INT_AND.  Same-size in/out defeats the
// cast recognizer -> SUB44 opFunc.

void buildSubpieceTrunc(ExprBuilder &b, PcodeOp **top) {
  // SUBPIECE with a NONZERO truncation offset: isSubpieceCast returns
  // false at its first guard (cast.cc: "if (offset != 0) return false"),
  // so opSubpiece falls through to the opFunc arm -> SUB48(0x11223344, 0x1).
  PcodeOp *op = b.makeOp(CPUI_SUBPIECE, 2);
  b.fd.opSetInput(op, b.constant4(0x11223344), 0);
  b.fd.opSetInput(op, b.constant4(0x1), 1);
  Varnode *out = b.fd.newUniqueOut(8, op);
  out->updateType(b.arch.types->getBase(8, TYPE_FLOAT), true, false);
  out->setImplied();
  *top = b.topBinary(CPUI_INT_AND, out, b.constant4(0x22));
}

// ---- printc.cc:880-893 opPtradd plain binary_plus form ----

void buildPtraddPlain(ExprBuilder &b, PcodeOp **top) {
  *top = b.topPtradd(b.constant4(0x11), b.constant4(0x22),
                     b.constant4(0x0));
}

struct CaseEntry {
  const char *name;
  void (*build)(ExprBuilder &, PcodeOp **);
};

}  // namespace

int main(void) {
  std::cout << std::unitbuf;
  try {
    // Production console entry (libdecomp.cc:23-27): initialize IDs and all
    // capability singletons so the c-language PrintC capability is
    // registered before any PrintC is constructed.
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    FixtureArchitecture arch;

    static const CaseEntry cases[] = {
      {"bin_int_equal", buildBinIntEqual},
      {"bin_int_not_equal", buildBinIntNotEqual},
      {"bin_int_less", buildBinIntLess},
      {"bin_int_sless", buildBinIntSless},
      {"bin_int_lessequal", buildBinIntLessEqual},
      {"bin_int_slessequal", buildBinIntSlessEqual},
      {"bin_int_add", buildBinIntAdd},
      {"bin_int_sub", buildBinIntSub},
      {"bin_int_and", buildBinIntAnd},
      {"bin_int_or", buildBinIntOr},
      {"bin_int_xor", buildBinIntXor},
      {"bin_int_left", buildBinIntLeft},
      {"bin_int_right", buildBinIntRight},
      {"bin_int_sright", buildBinIntSright},
      {"bin_int_mult", buildBinIntMult},
      {"bin_int_div", buildBinIntDiv},
      {"bin_int_sdiv", buildBinIntSdiv},
      {"bin_int_rem", buildBinIntRem},
      {"bin_int_srem", buildBinIntSrem},
      {"bin_bool_and", buildBinBoolAnd},
      {"bin_bool_or", buildBinBoolOr},
      {"bin_bool_xor", buildBinBoolXor},
      {"bin_float_equal", buildBinFloatEqual},
      {"bin_float_not_equal", buildBinFloatNotEqual},
      {"bin_float_less", buildBinFloatLess},
      {"bin_float_lessequal", buildBinFloatLessEqual},
      {"bin_float_add", buildBinFloatAdd},
      {"bin_float_div", buildBinFloatDiv},
      {"bin_float_mult", buildBinFloatMult},
      {"bin_float_sub", buildBinFloatSub},
      {"un_int_2comp", buildUnInt2comp},
      {"un_int_negate", buildUnIntNegate},
      {"un_float_neg", buildUnFloatNeg},
      {"func_int_carry", buildFuncIntCarry},
      {"func_int_scarry", buildFuncIntScarry},
      {"func_int_sborrow", buildFuncIntSborrow},
      {"func_float_nan", buildFuncFloatNan},
      {"func_float_abs", buildFuncFloatAbs},
      {"func_float_sqrt", buildFuncFloatSqrt},
      {"func_float_ceil", buildFuncFloatCeil},
      {"func_float_floor", buildFuncFloatFloor},
      {"func_float_round", buildFuncFloatRound},
      {"func_piece", buildFuncPiece},
      {"func_popcount", buildFuncPopcount},
      {"func_lzcount", buildFuncLzcount},
      {"zext_same", buildZextNocast},
      {"zext_hide", buildZextHide},
      {"zext_widen", buildZextCast},
      {"sext_same", buildSextNocast},
      {"sext_widen", buildSextCast},
      {"boolneg_plain", buildBoolnegPlain},
      {"boolneg_flip", buildBoolnegFlip},
      {"boolneg_double", buildBoolnegDouble},
      {"float_int2float", buildFloatInt2Float},
      {"float_float2float", buildFloatFloat2Float},
      {"float_trunc", buildFloatTrunc},
      {"subpiece_trunc", buildSubpieceTrunc},
      {"ptradd_plain", buildPtraddPlain},
  };

  std::cout
      << "schema=1|fixture=MIGW1-TYPEOP-PUSH-0002|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
      << std::endl;
    for (const CaseEntry *entry = cases;
         entry != cases + sizeof(cases) / sizeof(cases[0]); ++entry) {
      std::cout << runCase(arch, entry->name, entry->build) << '\n';
    }
  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
    return 1;
  }
  return 0;
}
