/*
 * PRINTC-INTNOT-TOKEN-0001: locked Ghidra 12.0.4 PrintC unary-prefix
 * operator token-order oracle (GLOBWORD-C4-INTNOT-TOKEN-0001).
 *
 * Drives the production PrintC::emitExpression (printc.cc:2468-2495) over
 * synthetic constant-leaf expression graphs built through production
 * Funcdata APIs (Scope::addFunction -> newOp / opSetOpcode / opSetInput /
 * newUniqueOut / newConstant / Varnode::updateType / setImplied /
 * setHighLevel).  Every top-level op has NO output varnode, so emitExpression
 * skips the assignment arm (printc.cc:2471-2476) and emits the bare
 * expression — the pure operator/operand token order under the RPN drain.
 *
 * The unary operators ride the RPN stack exactly as PrintLanguage::opUnary
 * prescribes (printlanguage.cc:566-573: pushOp + pushVn, never a direct
 * emit), and PrintLanguage::emitOp prints a unary_prefix token at
 * visited==0 (printlanguage.cc:338-342) — i.e. immediately BEFORE its
 * operand — with the pending parent binary token emitted at its own stage
 * by the entry emitOp(revpol.back()) (printlanguage.cc:143/171).
 *
 * Cases (all constants typed uint4 so both pushConstant paths take the
 * TYPE_UINT -> push_integer unsigned arm, printc.cc:1750-1757):
 *   intnot_deref   AND(ADD(LOAD(0x20), 0xfefefeff), NEGATE(LOAD(0x20)))
 *                  -> the GLOBWORD-C4 curl shape: the NEGATE is the AND's
 *                     in(1), drained AFTER the ADD subtree; an eager `~`
 *                     emit would land between the constant and ` & `.
 *   intnot_const   NEGATE(0x10)                     -> `~0x10`
 *   int2comp_const INT_2COMP(0x10) (unary_minus)    -> `-0x10`
 *   intnot_left    OR(NEGATE(0x30), ADD(0x11, 0x22))-> `~0x30 | 0x11 + 0x22`
 *   intnot_addright ADD(0x11, NEGATE(0x10))        -> `0x11 + ~0x10`
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
// printc_format_1204.cc: const=0, other=1, unique=2, ram=3, register=4,
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
    types->setCoreType("uint4", 4, TYPE_UINT, false);
    types->setCoreType("uint8", 8, TYPE_UINT, false);
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
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
// expression-level rendering (same pattern as printc_subpiece_fieldextract).
class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *g)
      : PrintC(g, "printc-intnot-1204") {
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
  AddrSpace *reg;
  Datatype *uint4;
  uintb pc;

  ExprBuilder(FixtureArchitecture &a, Funcdata &f)
      : arch(a), fd(f), ram(a.getSpace(3)), reg(a.getSpace(4)),
        uint4(a.types->getBase(4, TYPE_UINT)), pc(0x1000) {}

  Varnode *constant4(uintb val) {
    Varnode *vn = fd.newConstant(4, val);
    vn->updateType(uint4, true, false);
    return vn;
  }

  PcodeOp *makeOp(OpCode opc, int4 inputs) {
    PcodeOp *op = fd.newOp(inputs, Address(ram, pc));
    pc += 4;
    fd.opSetOpcode(op, opc);
    return op;
  }

  // A LOAD whose address input is the constant `addr` (opLoad only ever
  // pushes in(1), printc.cc:487-489, so in(0) is a never-printed
  // placeholder).  The output is implied so the defining op is inlined by
  // PrintLanguage::recurse (printlanguage.cc:526-533).
  Varnode *loadOf(uintb addr) {
    PcodeOp *load = makeOp(CPUI_LOAD, 2);
    fd.opSetInput(load, fd.newConstant(8, 3), 0);
    fd.opSetInput(load, constant4(addr), 1);
    Varnode *out = fd.newUniqueOut(4, load);
    out->updateType(uint4, true, false);
    out->setImplied();
    return out;
  }

  // Unary op with an implied output (inlined at the use site).
  Varnode *unary(OpCode opc, Varnode *in0) {
    PcodeOp *op = makeOp(opc, 1);
    fd.opSetInput(op, in0, 0);
    Varnode *out = fd.newUniqueOut(4, op);
    out->updateType(uint4, true, false);
    out->setImplied();
    return out;
  }

  // Binary op with an implied output.
  Varnode *binary(OpCode opc, Varnode *in0, Varnode *in1) {
    PcodeOp *op = makeOp(opc, 2);
    fd.opSetInput(op, in0, 0);
    fd.opSetInput(op, in1, 1);
    Varnode *out = fd.newUniqueOut(4, op);
    out->updateType(uint4, true, false);
    out->setImplied();
    return out;
  }

  // Top-level op with NO output: emitExpression skips the assignment arm
  // (printc.cc:2471-2476) and emits only the operator token stream.
  PcodeOp *topNoOut(OpCode opc, int4 inputs) {
    PcodeOp *op = makeOp(opc, inputs);
    return op;
  }

  // Top-level unary op with no output wired to one input.
  PcodeOp *topUnaryNoOut(OpCode opc, Varnode *in0) {
    PcodeOp *op = topNoOut(opc, 1);
    fd.opSetInput(op, in0, 0);
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

// AND(ADD(LOAD(0x20), 0xfefefeff), NEGATE(LOAD(0x20))) — the GLOBWORD-C4
// curl shape: `*0x20 + 0xfefefeff & ~*0x20`.
void buildIntnotDeref(ExprBuilder &b, PcodeOp **top) {
  Varnode *loadA = b.loadOf(0x20);
  Varnode *add = b.binary(CPUI_INT_ADD, loadA, b.constant4(0xfefefeff));
  Varnode *loadB = b.loadOf(0x20);
  Varnode *neg = b.unary(CPUI_INT_NEGATE, loadB);
  *top = b.topNoOut(CPUI_INT_AND, 2);
  b.fd.opSetInput(*top, add, 0);
  b.fd.opSetInput(*top, neg, 1);
}

// NEGATE(0x10) — `~0x10`.
void buildIntnotConst(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnaryNoOut(CPUI_INT_NEGATE, b.constant4(0x10));
}

// INT_2COMP(0x10) — unary_minus token: `-0x10`.
void buildInt2compConst(ExprBuilder &b, PcodeOp **top) {
  *top = b.topUnaryNoOut(CPUI_INT_2COMP, b.constant4(0x10));
}

// OR(NEGATE(0x30), ADD(0x11, 0x22)) — unary as the LEFT operand:
// `~0x30 | 0x11 + 0x22`.
void buildIntnotLeft(ExprBuilder &b, PcodeOp **top) {
  Varnode *neg = b.unary(CPUI_INT_NEGATE, b.constant4(0x30));
  Varnode *add = b.binary(CPUI_INT_ADD, b.constant4(0x11),
                          b.constant4(0x22));
  *top = b.topNoOut(CPUI_INT_OR, 2);
  b.fd.opSetInput(*top, neg, 0);
  b.fd.opSetInput(*top, add, 1);
}

// ADD(0x11, NEGATE(0x10)) — unary as the RIGHT operand: `0x11 + ~0x10`.
void buildIntnotAddright(ExprBuilder &b, PcodeOp **top) {
  Varnode *neg = b.unary(CPUI_INT_NEGATE, b.constant4(0x10));
  *top = b.topNoOut(CPUI_INT_ADD, 2);
  b.fd.opSetInput(*top, b.constant4(0x11), 0);
  b.fd.opSetInput(*top, neg, 1);
}

}  // namespace

int main(void) {
  std::cout << std::unitbuf;
  std::cout << "schema=1|fixture=PRINTC-INTNOT-TOKEN-0001"
            << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    // Production console entry (libdecomp.cc:23-27): initialize IDs and all
    // capability singletons so the c-language PrintC capability is
    // registered before any PrintC is constructed.
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    FixtureArchitecture arch;
    std::cout << runCase(arch, "intnot_deref", buildIntnotDeref) << '\n';
    std::cout << runCase(arch, "intnot_const", buildIntnotConst) << '\n';
    std::cout << runCase(arch, "int2comp_const", buildInt2compConst) << '\n';
    std::cout << runCase(arch, "intnot_left", buildIntnotLeft) << '\n';
    std::cout << runCase(arch, "intnot_addright", buildIntnotAddright)
              << '\n';
  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
    return 1;
  }
  return 0;
}
