/*
 * Locked Ghidra 12.0.4 PrintC::buildTypeStack / pushTypeStart / pushTypeEnd
 * / pushPrototypeInputs / genericTypeName oracle for
 * PTRSUB-TYPED-DECL-RESIDUAL-0001.
 *
 * The E2E differential blamed bare declarations (`pCVar29;`, ` in_RCX;`) on
 * symbols whose Datatype is an ANONYMOUS TypePointer (empty name): Ghidra's
 * pushTypeStart never renders the pointer's own name — buildTypeStack
 * (printc.cc:143-164) drills anonymous PTR/ARRAY/CODE layers down to a named
 * base (or terminates on another anonymous metatype), the base atom spells
 * getDisplayName or PrintC::genericTypeName (printc.cc:3373-3399:
 * unkint<size>/unkuint<size>/unkbyte<size>/unkfloat<size>/BADSPACEBASE/
 * BADTYPE), and each PTR layer then contributes one ptr_expr `*`
 * (printc.cc:290-302).  pushTypeEnd (printc.cc:313-346) closes any
 * ptr-group parenthesized under an ARRAY/CODE parent at the identifier, then
 * walks the same drill emitting the array_expr `[n]` suffixes and the CODE
 * `function_call` parens, whose payload is pushPrototypeInputs
 * (printc.cc:169-197).
 *
 * The fixture architecture is self-contained (FixtureTranslate +
 * FixtureArchitecture, the same pattern as ptrsub_switch_cast_1204.cc): no
 * BFD loader, no external binary, no sleigh spec root.  The Funcdata for the
 * declaration-walk cases is constructed directly — the Funcdata constructor
 * attaches a default ScopeLocal for any named function (funcdata.cc:57-71),
 * which is all ActionNameVars::perform needs.
 *
 * Two observation surfaces:
 *
 *   stage=start — the unit projection of pushTypeStart itself: a FixturePrintC
 *     subclass drives pushTypeStart(ct,false) + Atom("x") + pushTypeEnd(ct) +
 *     recurse() (the emitVarDecl call sequence, printc.cc:2502-2505) directly
 *     with factory data-types, so anonymous shapes that the factory would
 *     dedup (an unnamed TypeBase) and CODE shapes are exercised without any
 *     varnode/symbol machinery.
 *
 *   stage=decls — the production declaration walk exactly as
 *     printc_symbol_decl_1204.cc drives it: register temporaries typed with
 *     factory ANONYMOUS pointers/arrays, ActionNameVars, then
 *     emitLocalVarDecls -> emitScopeVarDecls -> emitVarDeclStatement ->
 *     emitVarDecl. This is the E2E bug shape (the in_RCX bare declaration).
 *
 * Cases (stage=start unless noted):
 *   - anon_ptr_char        : factory anonymous char*  — the production shape.
 *   - anon_ptr_multi       : anonymous uint2** — multi-level ptr_expr run.
 *   - anon_ptr_struct      : anonymous pointer to a NAMED struct.
 *   - named_ptr_contrast   : NAMED pointer (getTypePointer 4-arg overload):
 *                            buildTypeStack stops at the named layer.
 *   - anon_array_int       : factory anonymous int4[4] — array_expr payload.
 *   - anon_ptr_array_elem  : anonymous pointer to anonymous int4[4] array —
 *                            the parenthesized declarator `int4 (*x) [4]`.
 *   - anon_array_ptr_elem  : anonymous array of anonymous int4* pointers
 *                            (mixed ARRAY/PTR chain, no parenthesized
 *                            declarator) — `int4 *x [2]`.
 *   - anon_base_int        : direct TypeBase(4,TYPE_INT)   -> unkint4.
 *   - anon_base_uint       : direct TypeBase(8,TYPE_UINT)  -> unkuint8.
 *   - anon_base_unknown    : direct TypeBase(1,TYPE_UNKNOWN) -> unkbyte1.
 *   - anon_base_float      : direct TypeBase(4,TYPE_FLOAT) -> unkfloat4.
 *   - anon_code_noproto    : anonymous TypeCode without prototype (drills to
 *                            the architecture's canonical void); recorded at
 *                            stage=startonly because Ghidra 12.0.4's
 *                            pushTypeEnd loops forever on this shape
 *                            (printc.cc:337-339 never advances ct).
 *   - anon_code_proto      : anonymous TypeCode with an int4(void) prototype
 *                            (drills to the output type).
 *   - anon_code_params     : anonymous TypeCode with inputs (anonymous char*
 *                            + int4) — pushPrototypeInputs inside
 *                            pushTypeEnd's function_call parens.
 *   - anon_ptr_char / anon_ptr_multi / anon_ptr_struct / anon_array_int also
 *     record stage=decls through the full ActionNameVars walk.
 *
 * Pointer/hash values are identity keys only.  The captured text is
 * transport-normalized identically on both sides (outer whitespace stripped,
 * inner line breaks replaced with '~').
 */

#include "architecture.hh"
#include "coreaction.hh"
#include "libdecomp.hh"
#include "printc.hh"
#include "prettyprint.hh"
#include "translate.hh"

#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

// Minimal standalone Translate: constant/other/unique/ram(3)/register(4)/
// stack(5, spacebase over ram)/join(6)/iop(7), default code space 3 — the
// space layout ActionNameVars and the register temporaries need.
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
    insertSpace(new AddrSpace(this, this, IPTR_JOIN, "join", false,
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

// Standalone Architecture: a TypeFactory with the named core types the cases
// drill to (char/uint2/int4/int8 + the xunknownN sizes), an instruction
// registry, a Database with one global scope, and a default ProtoModel for
// PrototypePieces.  Core types MUST be registered so the factory bases are
// NAMED — an unregistered getBase(s,m) dedups to an anonymous TypeBase
// (type.cc TypeBase(s,m) leaves the name empty), which would silently turn
// the case into a genericTypeName probe.
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
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    // Production "undefinedN" spellings so the untyped unique-out symbols
    // the decls cases create get the same default-name prefix character as
    // the x86 spec ('u' from "undefined8") — ptrsub's xunknownN spelling
    // would name them xVar1 instead of uVar1.
    types->setCoreType("undefined1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("undefined2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("undefined4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("undefined8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("uint1", 1, TYPE_UINT, false);
    types->setCoreType("uint2", 2, TYPE_UINT, false);
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("uint4", 4, TYPE_UINT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
    types->setCoreType("uint8", 8, TYPE_UINT, false);
    types->setCoreType("float4", 4, TYPE_FLOAT, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    // Stack-slot pentry rules so FuncProto::updateAllTypes can assign
    // storage for both inputs and the output (an empty <input/><output/>
    // model throws ParamUnassignedError, leaving every prototype output as
    // the substitution void and the CODE cases degenerate to `void x(void)`).
    // align="8" makes the entries multi-slot: an alignment-0 pentry can only
    // ever assign slot 0 (fspec.cc:456-458), so the SECOND input parameter
    // would fail assignment.
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\">"
        "<input><pentry minsize=\"1\" maxsize=\"500\" align=\"8\">"
        "<addr space=\"stack\" offset=\"0\"/></pentry></input>"
        "<output><pentry minsize=\"1\" maxsize=\"500\" align=\"8\">"
        "<addr space=\"stack\" offset=\"1000\"/></pentry></output>"
        "</prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
    print->initializeFromArchitecture();
  }

  void printMessage(const std::string &) const override {}
};

// Subclass to (a) expose the protected pushTypeStart/pushTypeEnd entries and
// (b) swap the default EmitMarkup emitter for the plain-text EmitNoMarkup
// stream (PrintLanguage::emit is protected; PrintC's constructor installs an
// EmitMarkup by default).
class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *g)
    : PrintC(g, "printc-anonymous-pointer-decl-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  // printc.cc:2502-2505 emitVarDecl's push sequence, driven directly with a
  // plain syntax atom standing in for pushSymbol's identifier.
  void renderTypeDecl(Datatype *ct, const string &ident, std::ostream &out) {
    setOutputStream(&out);
    pushTypeStart(ct, false);
    pushAtom(Atom(ident, syntax, EmitMarkup::var_color));
    pushTypeEnd(ct);
    recurse();
  }

  // Start-only projection for the proto-less anonymous TypeCode: Ghidra
  // 12.0.4's pushTypeEnd never advances `ct` on that shape (printc.cc:337-339
  // pushes a blank atom but leaves ct the CODE type), so the full pair would
  // loop forever; the start half alone still observes buildTypeStack's
  // cc:158-159 no-proto drill (the canonical void substitution).
  void renderTypeStartOnly(Datatype *ct, std::ostream &out) {
    setOutputStream(&out);
    pushTypeStart(ct, false);
    recurse();
  }

  // printc.cc:2260 — drive exactly the local-declaration walk docFunction
  // performs at printc.cc:2656, including the pushScope(fd->getScopeLocal())
  // entered at printc.cc:2597.
  void renderLocalVarDecls(const Funcdata *fd, std::ostream &out) {
    setOutputStream(&out);
    pushScope(fd->getScopeLocal());
    emitLocalVarDecls(fd);
    popScope();
  }
};

// A complete named struct built directly (getTypeStruct leaves an incomplete
// zero-size shell that SIGFPEs in TypeFactory::findAdd); the shape matches
// ptrsub_switch_cast_1204.cc's FixtureStruct.
class FixtureStruct final : public TypeStruct {
public:
  FixtureStruct(const string &nm, const vector<TypeField> &fields,
                int4 size, int4 alignment)
  {
    name = nm;
    displayName = nm;
    setFields(fields, size, alignment);
    markComplete();
  }
};

// A TypeCode exposing the protected setPrototype(pieces) entry so the params
// case can bypass the factory's anonymous-TypeCode dedup (getTypeCode would
// return the already-registered int4(void) type).
class FixtureTypeCode final : public TypeCode {
public:
  FixtureTypeCode() : TypeCode() {}

  void setPieces(TypeFactory *tfact, const PrototypePieces &sig) {
    setPrototype(tfact, sig, tfact->getTypeVoid());
    markComplete();
  }
};

class Fixture {
  Funcdata &fd;
  vector<Varnode *> varnodes;
  map<Varnode *, string> varnodeNames;

public:
  explicit Fixture(Funcdata &func)
    : fd(func)
  {
  }

  void rememberVarnode(Varnode *vn, const string &name)
  {
    if (varnodeNames.insert(std::make_pair(vn, name)).second)
      varnodes.push_back(vn);
  }

  Varnode *makeWritten(const string &name, int4 size, uintb offset, uintb pc,
                       uintb value)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(1, Address(codeSpace, pc));
    fd.opSetOpcode(op, CPUI_COPY);
    Varnode *input = fd.newConstant(size, value);
    fd.opSetInput(op, input, 0);
    Varnode *vn = fd.newVarnode(size, registerSpace, offset);
    fd.opSetOutput(op, vn);
    PcodeOp *use = fd.newOp(1, Address(codeSpace, pc + 0x10));
    fd.opSetOpcode(use, CPUI_COPY);
    fd.opSetInput(use, vn, 0);
    fd.newUniqueOut(size, use);
    rememberVarnode(vn, name);
    return vn;
  }

  void setType(Varnode *vn, Datatype *ct)
  {
    vn->updateType(ct);
  }

  void assignHighs(void)
  {
    for(vector<Varnode *>::const_iterator iter = varnodes.begin();
        iter != varnodes.end(); ++iter) {
      if ((*iter)->getHigh() == (HighVariable *)0)
        throw std::runtime_error("varnode has no high");
    }
  }

  // Captured decl text, transport-normalized identically on both sides:
  // outer whitespace stripped, inner line breaks replaced with '~'.
  void renderDecls(Architecture *glb, const string &caseName)
  {
    FixturePrintC printer(glb);
    ostringstream out;
    printer.renderLocalVarDecls(&fd, out);
    std::cout << "case=" << caseName << "|stage=decls|text="
              << normalize(out.str()) << "\n";
    std::cout.flush();
  }

  void run(Architecture *glb, const string &caseName)
  {
    fd.setHighLevel();
    assignHighs();
    ActionNameVars action("analysis");
    action.perform(fd);
    renderDecls(glb, caseName);
  }

  static string normalize(const string &text)
  {
    string trimmed = text;
    while (!trimmed.empty() &&
           (trimmed[0] == '\n' || trimmed[0] == ' ' || trimmed[0] == '\r'))
      trimmed.erase(0, 1);
    while (!trimmed.empty() &&
           (trimmed[trimmed.size()-1] == '\n' ||
            trimmed[trimmed.size()-1] == ' ' ||
            trimmed[trimmed.size()-1] == '\r'))
      trimmed.erase(trimmed.size()-1, 1);
    for(size_t i = 0; i < trimmed.size(); ++i)
      if (trimmed[i] == '\n')
        trimmed[i] = '~';
    return trimmed;
  }
};

void renderStart(Architecture *glb, const string &caseName, Datatype *ct)
{
  FixturePrintC printer(glb);
  ostringstream out;
  printer.renderTypeDecl(ct, "x", out);
  std::cout << "case=" << caseName << "|stage=start|text="
            << Fixture::normalize(out.str()) << "\n";
  std::cout.flush();
}

void renderStartOnly(Architecture *glb, const string &caseName, Datatype *ct)
{
  FixturePrintC printer(glb);
  ostringstream out;
  printer.renderTypeStartOnly(ct, out);
  std::cout << "case=" << caseName << "|stage=startonly|text="
            << Fixture::normalize(out.str()) << "\n";
  std::cout.flush();
}

// The Funcdata constructor attaches a default ScopeLocal for a named
// function (funcdata.cc:57-71) — the same shell shape BfdArchitecture's
// queryFunction produced in printc_symbol_decl_1204.cc.
static Funcdata *makeFuncdata(FixtureArchitecture &arch)
{
  AddrSpace *ram = arch.getSpace(3);
  Funcdata *fd = new Funcdata("GetStr", "GetStr",
                              arch.symboltab->getGlobalScope(),
                              Address(ram, 0x36d0), (FunctionSymbol *)0, 0);
  return fd;
}

// stage=start + stage=decls for the factory anonymous pointer shapes: the
// production bug class (in_RCX-style bare declarations).
void runAnonPtrChar(Funcdata *fd, Architecture *glb)
{
  TypeFactory *types = glb->types;
  Datatype *charType = types->getTypeChar(1);
  Datatype *ptr = types->getTypePointer(8, charType, 1);
  renderStart(glb, "anon_ptr_char", ptr);

  fd->clear();
  Fixture fixture(*fd);
  Varnode *pc = fixture.makeWritten("pc", 8, 0x60, 0x1030, 0x2a);
  fixture.setType(pc, types->getTypePointer(8, charType, 1));
  fixture.run(glb, "anon_ptr_char");
}

void runAnonPtrMulti(Funcdata *fd, Architecture *glb)
{
  TypeFactory *types = glb->types;
  Datatype *ushortType = types->getBase(2, TYPE_UINT);
  Datatype *inner = types->getTypePointer(8, ushortType, 1);
  Datatype *outer = types->getTypePointer(8, inner, 1);
  renderStart(glb, "anon_ptr_multi", outer);

  fd->clear();
  Fixture fixture(*fd);
  Varnode *ppu = fixture.makeWritten("ppu", 8, 0x60, 0x1030, 0x2a);
  fixture.setType(ppu, outer);
  fixture.run(glb, "anon_ptr_multi");
}

void runAnonPtrStruct(Funcdata *fd, Architecture *glb)
{
  TypeFactory *types = glb->types;
  vector<TypeField> fields;
  fields.push_back(TypeField(0, 0, "next",
                             types->getTypePointer(8, types->getBase(8, TYPE_UINT), 1)));
  TypeStruct *structure = new FixtureStruct("fixture_list", fields, 8, 8);
  renderStart(glb, "anon_ptr_struct",
              types->getTypePointer(8, structure, 1));

  fd->clear();
  Fixture fixture(*fd);
  Varnode *ps = fixture.makeWritten("ps", 8, 0x60, 0x1030, 0x2a);
  fixture.setType(ps, types->getTypePointer(8, structure, 1));
  fixture.run(glb, "anon_ptr_struct");
}

// Named pointer (getTypePointer 4-arg overload, type.cc): buildTypeStack
// stops at the named layer — the contrast case for Rugra's composed-name
// pointer spelling ("char *").
void runNamedPtrContrast(Funcdata * /*fd*/, Architecture *glb)
{
  TypeFactory *types = glb->types;
  Datatype *charType = types->getTypeChar(1);
  renderStart(glb, "named_ptr_contrast",
              types->getTypePointer(8, charType, 1, "char *"));
}

void runAnonArrayInt(Funcdata *fd, Architecture *glb)
{
  TypeFactory *types = glb->types;
  Datatype *intType = types->getBase(4, TYPE_INT);
  Datatype *array = types->getTypeArray(16, intType);
  renderStart(glb, "anon_array_int", array);

  fd->clear();
  Fixture fixture(*fd);
  Varnode *a = fixture.makeWritten("a", 16, 0x60, 0x1030, 0x2a);
  fixture.setType(a, array);
  fixture.run(glb, "anon_array_int");
}

// Pointer to an anonymous array: the mixed PTR/ARRAY modifier chain
// (parenthesized declarator).
void runAnonPtrArrayElem(Architecture *glb)
{
  TypeFactory *types = glb->types;
  Datatype *intType = types->getBase(4, TYPE_INT);
  Datatype *array = types->getTypeArray(16, intType);
  renderStart(glb, "anon_ptr_array_elem",
              types->getTypePointer(8, array, 1));
}

// Array of pointers: the mixed ARRAY/PTR chain in the opposite order (no
// parenthesized declarator).
void runAnonArrayPtrElem(Architecture *glb)
{
  TypeFactory *types = glb->types;
  Datatype *intType = types->getBase(4, TYPE_INT);
  Datatype *element = types->getTypePointer(8, intType, 1);
  renderStart(glb, "anon_array_ptr_elem", types->getTypeArray(2, element));
}

// Direct TypeBase constructions (empty name) never reachable through the
// factory's dedup tree — the genericTypeName spellings.
void runAnonBaseGenerics(Architecture *glb)
{
  renderStart(glb, "anon_base_int", new TypeBase(4, TYPE_INT));
  renderStart(glb, "anon_base_uint", new TypeBase(8, TYPE_UINT));
  renderStart(glb, "anon_base_unknown", new TypeBase(1, TYPE_UNKNOWN));
  renderStart(glb, "anon_base_float", new TypeBase(4, TYPE_FLOAT));
}

// Anonymous TypeCode shapes: buildTypeStack's TYPE_CODE drill
// (printc.cc:154-160) — the output type with a prototype, the architecture's
// canonical void without one.  The factory's getTypeCode() returns the NAMED
// "code" core type, so the drill is exercised with directly constructed
// anonymous TypeCode objects / getTypeCode(pieces).
void runAnonCode(Architecture *glb)
{
  // Start-only: the pair-driven record would hang — see
  // FixturePrintC::renderTypeStartOnly.
  renderStartOnly(glb, "anon_code_noproto", new TypeCode());

  TypeFactory *types = glb->types;
  PrototypePieces pieces;
  pieces.model = glb->defaultfp;
  pieces.name = "";
  pieces.outtype = types->getBase(4, TYPE_INT);
  pieces.intypes.clear();
  pieces.innames.clear();
  pieces.firstVarArgSlot = -1;
  renderStart(glb, "anon_code_proto", types->getTypeCode(pieces));

  // A prototype with input types drives pushPrototypeInputs (printc.cc:169)
  // inside pushTypeEnd's function_call parens: an anonymous char* param
  // (recursive pushTypeStart noident) and a named int4 param, comma-joined.
  // Built directly (not through getTypeCode) — the factory's findAdd dedups
  // anonymous TypeCode objects and would return the int4(void) type above.
  pieces.intypes.push_back(types->getTypePointer(8, types->getTypeChar(1), 1));
  pieces.intypes.push_back(types->getBase(4, TYPE_INT));
  FixtureTypeCode *codeParams = new FixtureTypeCode();
  codeParams->setPieces(types, pieces);
  renderStart(glb, "anon_code_params", codeParams);
}

void run(void)
{
  std::vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  {
    FixtureArchitecture architecture;
    Funcdata *fd = makeFuncdata(architecture);
    if (fd->getName() != "GetStr" ||
        fd->getAddress().getOffset() != 0x36d0)
      throw std::runtime_error("GetStr input identity drifted");

    runAnonPtrChar(fd, &architecture);
    runAnonPtrMulti(fd, &architecture);
    runAnonPtrStruct(fd, &architecture);
    runNamedPtrContrast(fd, &architecture);
    runAnonArrayInt(fd, &architecture);
    runAnonPtrArrayElem(&architecture);
    runAnonArrayPtrElem(&architecture);
    runAnonBaseGenerics(&architecture);
    runAnonCode(&architecture);
    delete fd;
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(void)
{
  try {
    run();
    return 0;
  }
  catch(const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
