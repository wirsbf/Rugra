/*
 * PRINTC-FORMAT-0001: locked Ghidra 12.0.4 PrintC::docFunction pure-format
 * oracle (function-header brace layout, parameter join spacing, comma
 * spacing, body indent policy).
 *
 * The fixture drives the production PrintC::docFunction over a synthetic
 * Funcdata built through production APIs (Funcdata ctor / startProcessing /
 * FuncProto::setOutput / FuncProto::setParam / newOp / opSetOpcode /
 * opInsertEnd) and captures the full EmitNoMarkup byte stream.  Cases cover:
 *   - void_empty        : void return, no params, no body statements
 *   - void_return_body  : void return, single RETURN statement
 *   - ptr_int_params    : int return, `char *pattern` + `int pos` params
 *   - int_char2_params  : int return, `int argc` + `char **argv` params
 *   - dotdotdot_param   : void return, `char *fmt` + `...`
 *   - base_join_param   : long return, `long x` (non-pointer join spacing)
 */

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

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

using namespace ghidra;

namespace {

// Test-only access is required to set Funcdata::flags (processing_started)
// without driving the full followFlow/structureReset pipeline that
// ActionStart performs in production. Explicit template instantiation
// ignores member access control, mirroring the access pattern of the
// printc_terminal_1204 fixture.
struct FuncdataFlagsTag {
  using type = uint4 Funcdata::*;
  friend type access(FuncdataFlagsTag);
};

template <typename Tag, typename Tag::type Member>
struct PrivateAccess {
  friend typename Tag::type access(Tag) { return Member; }
};

template struct PrivateAccess<FuncdataFlagsTag, &Funcdata::flags>;

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
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
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1, 6,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummy_register.space = getSpace(4);
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
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
  FixtureArchitecture() {
    FixtureTranslate *fixture_translate = new FixtureTranslate();
    translate = fixture_translate;
    copySpaces(fixture_translate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    // Core-type set mirrors production SleighArchitecture::buildCoreTypes
    // (sleigh_arch.cc:215-237) so getTypeChar/getBase resolve like a real
    // c-language architecture.
    types->setCoreType("void", 1, TYPE_VOID, false);
    types->setCoreType("bool", 1, TYPE_BOOL, false);
    types->setCoreType("uint1", 1, TYPE_UINT, false);
    types->setCoreType("uint2", 2, TYPE_UINT, false);
    types->setCoreType("uint4", 4, TYPE_UINT, false);
    types->setCoreType("uint8", 8, TYPE_UINT, false);
    types->setCoreType("int1", 1, TYPE_INT, false);
    types->setCoreType("int2", 2, TYPE_INT, false);
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
    types->setCoreType("float4", 4, TYPE_FLOAT, false);
    types->setCoreType("float8", 8, TYPE_FLOAT, false);
    types->setCoreType("float10", 10, TYPE_FLOAT, false);
    types->setCoreType("float16", 16, TYPE_FLOAT, false);
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("code", 1, TYPE_CODE, false);
    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("wchar2", 2, TYPE_INT, true);
    types->setCoreType("wchar4", 4, TYPE_INT, true);
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
    // docFunction -> CommentSorter::setupFunctionList dereferences the
    // architecture comment database; production sleigh_arch.cc:244 installs
    // the internal (empty) implementation, which is what this fixture needs.
    commentdb = new CommentDatabaseInternal();
  }

  void printMessage(const std::string &) const override {}
};

// Subclass only to swap the emitter for the plain-text EmitNoMarkup stream
// (PrintLanguage::emit is protected; PrintC's constructor installs an
// EmitMarkup by default).
class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *g) : PrintC(g, "printc-format-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  // docFunction with the flat print mod (structured block emission is not
  // part of this format fixture; flat keeps docFunction's precondition
  // `!isSet(flat) && hasNoStructBlocks` satisfied).
  void renderFlat(const Funcdata *fd, std::ostream &out) {
    setOutputStream(&out);
    setMod(PrintLanguage::flat);
    docFunction(fd);
  }
};

Datatype *typesByName(FixtureArchitecture &arch, const std::string &nm) {
  if (nm == "char")
    return arch.types->getTypeChar(1);
  if (nm == "char*")
    return arch.types->getTypePointer(8, arch.types->getTypeChar(1), 1);
  if (nm == "char**")
    return arch.types->getTypePointer(
        8, arch.types->getTypePointer(8, arch.types->getTypeChar(1), 1), 1);
  if (nm == "int")
    // Named atomic "int" (the gcc cspec typemap spelling of int4).
    return arch.types->getBase(4, TYPE_INT, "int");
  if (nm == "long")
    return arch.types->getBase(8, TYPE_INT, "long");
  throw LowlevelError("unknown fixture type: " + nm);
}

// One decompiled function rendered through the production docFunction path.
// The Funcdata is created through the production symbol-table entry point
// (Scope::addFunction, database.cc:1615) so it carries a real FunctionSymbol
// — emitFunctionDeclaration dereferences it via emitSymbolScope.
std::string render(FixtureArchitecture &arch, const std::string &name,
                   const std::string &ret,
                   const std::vector<std::pair<std::string, Datatype *>> &params,
                   bool with_return, bool dotdotdot) {
  AddrSpace *ram = arch.getSpace(3);
  FunctionSymbol *symbol =
      arch.symboltab->getGlobalScope()->addFunction(Address(ram, 0x1000), name);
  Funcdata *fdp = symbol->getFunction();
  if (fdp == (Funcdata *)0)
    throw LowlevelError("failed to construct fixture Funcdata");
  Funcdata &fd = *fdp;
  FuncProto &proto = fd.getFuncProto();
  if (ret != "void") {
    ParameterPieces piece;
    piece.addr = Address(arch.getSpace(4), 0);
    piece.type = typesByName(arch, ret);
    piece.flags = 0;
    proto.setOutput(piece);
  }
  AddrSpace *reg = arch.getSpace(4);
  for (int4 i = 0; i < (int4)params.size(); ++i) {
    ParameterPieces piece;
    piece.addr = Address(reg, 8 * (i + 1));
    piece.type = params[i].second;
    piece.flags = 0;
    proto.setParam(i, params[i].first, piece);
  }
  if (dotdotdot)
    proto.setDotdotdot(true);

  if (with_return) {
    PcodeOp *op = fd.newOp(0, Address(arch.getSpace(3), 0x1000));
    fd.opSetOpcode(op, CPUI_RETURN);
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    fd.opInsertEnd(op, block);
  }

  // docFunction requires the processing_started flag (set in production by
  // ActionStart::funcStart, before any flow analysis) and, without
  // structuring, the flat print mod. 0x8 is Funcdata::processing_started
  // (funcdata.hh:61).
  (fd.*access(FuncdataFlagsTag{})) |= 0x8;
  FixturePrintC printer(&arch);
  std::ostringstream output;
  printer.renderFlat(&fd, output);
  return output.str();
}

std::string toHex(const std::string &value) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (const unsigned char byte : value)
    stream << std::setw(2) << static_cast<unsigned int>(byte);
  return stream.str();
}

} // namespace

int main(int argc, char **argv) {
  const bool raw = argc == 2 && std::string(argv[1]) == "--raw";
  try {
    // Production console entry (libdecomp.cc:23-27) initializes the
    // attribute/element IDs and all capability singletons, which registers
    // the c-language PrintC capability that Architecture::base installs as
    // the default printer (architecture.cc:171).
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    FixtureArchitecture arch;
  Datatype *chr_ptr = typesByName(arch, "char*");
  Datatype *chr_ptr2 = typesByName(arch, "char**");
  Datatype *int4 = typesByName(arch, "int");
  Datatype *lng = typesByName(arch, "long");

  struct Case {
    std::string name;
    std::string ret;
    std::vector<std::pair<std::string, Datatype *>> params;
    bool with_return;
    bool dotdotdot;
  };
  const std::vector<Case> cases = {
      {"void_empty", "void", {}, false, false},
      {"void_return_body", "void", {}, true, false},
      {"ptr_int_params", "int", {{"pattern", chr_ptr}, {"pos", int4}}, true, false},
      {"int_char2_params", "int", {{"argc", int4}, {"argv", chr_ptr2}}, true, false},
      {"dotdotdot_param", "void", {{"fmt", chr_ptr}}, true, true},
      {"base_join_param", "long", {{"x", lng}}, true, false},
  };

    for (const Case &tc : cases) {
      const std::string out =
          render(arch, "fxn", tc.ret, tc.params, tc.with_return, tc.dotdotdot);
      std::cout << tc.name << '=';
      if (raw)
        std::cout << toHex(out);
      else
        std::cout << out.size();
      std::cout << '\n';
    }
  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << std::endl;
    return 2;
  }
  return 0;
}
