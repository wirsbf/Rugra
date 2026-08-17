/*
 * Locked Ghidra 12.0.4 oracle for PRINTC-SUBPIECE-FIELDEXTRACT-0001:
 * the PrintC::opSubpiece doesSpecialPrinting field-extraction branch
 * (printc.cc:843-878) plus its three adjacency predicates:
 *   (b) Datatype::isPieceStructured   (type.hh:929-935, metatype <= TYPE_ARRAY)
 *   (c) CastStrategyC::isSubpieceCast (cast.cc:411-432, PartialStruct/
 *       PartialUnion input arms at cast.cc:416-418)
 *
 * Cases (stdout record, one line per observation):
 *   - piece.*     : isPieceStructured() for struct/union/array/partialstruct/
 *                   partialunion/enum/partialenum/int/uint/pointer. This is
 *                   the REAL oracle answer for the TypeEnum constructor
 *                   metatype normalization (type.hh:489-494): an enum
 *                   instance reports TYPE_UINT/TYPE_INT internally, and
 *                   TypePartialEnum (type.cc:2255-2262, which routes through
 *                   the same TypeEnum ctor with TYPE_PARTIALENUM) reports
 *                   TYPE_UINT — so neither is piece-structured.
 *   - cast.*      : isSubpieceCast(out,in,offset) for the partial arms, the
 *                   enum mapping, and the struct-input rejection.
 *   - armA/armB   : the two printc.cc:846-871 bodies, driven op-level via
 *                   the public virtual PrintC::opSubpiece (printc.hh:334):
 *                     armA.field     — explicit Varnode + high Symbol ->
 *                                     pushPartialSymbol (printc.cc:1947)
 *                                     -> "S.hi"
 *                     armA.array     — array element walk -> "S.arr[0]"
 *                     armA.synthetic — failed descent + failed allowCast ->
 *                                     unnamedField -> "S.lo._2_2_"
 *                     armB.field     — non-explicit Varnode + Symbol ->
 *                                     findTruncation/object_member arm
 *                                     (printc.cc:862-868) -> "S.lo"
 *
 * Object graph: GetStr Funcdata over the pinned curl binary (BfdArchitecture,
 * same construction pattern as printc_symbol_decl_1204.cc): a register-space
 * Varnode typed with the fixture struct, defined by a COPY of a constant and
 * read by the fixture SUBPIECE; a dynamic Symbol "S" attached via
 * Funcdata::buildDynamicSymbol (funcdata_varnode.cc:1283) + HighVariable::
 * symbolDirty + ScopeLocal::renameSymbol; SPECIAL_PRINT set via
 * Funcdata::opMarkSpecialPrint (funcdata.hh:483).
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "printc.hh"
#include "prettyprint.hh"
#include "type.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

// Swap the default EmitMarkup for the plain-text EmitNoMarkup stream
// (PrintLanguage::emit is protected; PrintC's constructor installs an
// EmitMarkup by default) — same pattern as printc_symbol_decl_1204.cc.
// Re-exposes the protected PrintC::opSubpiece entry for op-level rendering.
class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *g) : PrintC(g, "printc-subpiece-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  string renderOpSubpiece(const PcodeOp *op, Scope *localScope)
  {
    ostringstream output;
    setOutputStream(&output);
    // printc.cc:2597: pushScope(fd->getScopeLocal()) before emitting —
    // without it pushSymbolScope qualifies every local symbol with the
    // function namespace ("GetStr::S" instead of "S").
    pushScope(localScope);
    opSubpiece(op);
    popScope();
    emit->flush();
    return output.str();
  }
};

// All factory types are built EXACTLY ONCE per process: a second
// getTypeStruct/getTypeUnion call on a completed name makes findAdd throw
// "Trying to alter definition of type" (type.cc:3421-3423), and setFields
// requires an incomplete structure (type.cc:3482-3483).
struct FixtureTypes {
  TypeStruct *pairStruct;
  TypeStruct *arrStruct;
  TypeUnion *altUnion;
  TypeArray *intArray2;
  TypePartialStruct *pairPartial;
  TypePartialUnion *altPartialUnion;
  TypeEnum *modeEnum;
  TypePartialEnum *modePartialEnum;
  Datatype *int4;
  Datatype *int8;
  Datatype *uint4;
  Datatype *intPointer;

  explicit FixtureTypes(TypeFactory *types)
  {
    int4 = types->getBase(4, TYPE_INT);
    int8 = types->getBase(8, TYPE_INT);
    uint4 = types->getBase(4, TYPE_UINT);
    pairStruct = types->getTypeStruct("fixture_pair");
    {
      vector<TypeField> fields;
      fields.push_back(TypeField(0, 0, "lo", int4));
      fields.push_back(TypeField(1, 4, "hi", int4));
      types->setFields(fields, pairStruct, 8, 4, 0);
    }
    arrStruct = types->getTypeStruct("fixture_arr");
    {
      intArray2 = types->getTypeArray(2, int4);
      vector<TypeField> arrFields;
      arrFields.push_back(TypeField(0, 0, "arr", intArray2));
      // The tail field keeps field[0] from filling the whole structure:
      // TypeStruct::setFields sets needs_resolution when field[0] spans the
      // entire struct (type.cc:1569-1571), which would route the SUBPIECE
      // walk through findResolve (printc.cc:1967-1971).
      arrFields.push_back(TypeField(1, 8, "tail", int4));
      types->setFields(arrFields, arrStruct, 12, 4, 0);
    }
    altUnion = types->getTypeUnion("fixture_alt");
    {
      vector<TypeField> ufields;
      ufields.push_back(TypeField(0, 0, "a", int4));
      ufields.push_back(TypeField(1, 0, "b", uint4));
      types->setFields(ufields, altUnion, 4, 4, 0);
    }
    pairPartial = types->getTypePartialStruct(pairStruct, 4, 4);
    altPartialUnion = types->getTypePartialUnion(altUnion, 0, 2);
    modeEnum = types->getTypeEnum("fixture_mode");
    modePartialEnum = types->getTypePartialEnum(modeEnum, 0, 2);
    intPointer = types->getTypePointer(8, int4, 1);
  }
};

struct SubpieceFixture {
  Funcdata &fd;
  Architecture *glb;
  AddrSpace *registerSpace;
  AddrSpace *codeSpace;
  uintb pc;

  SubpieceFixture(Funcdata &f, Architecture *g, uintb basePc)
    : fd(f), glb(g), pc(basePc)
  {
    registerSpace = glb->getSpaceByName("register");
    codeSpace = glb->getDefaultCodeSpace();
    if (registerSpace == (AddrSpace *)0 || codeSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires register and code spaces");
  }

  // Build a struct-typed register Varnode carrying a whole-map Symbol:
  //  1. addSymbol("S", structType, register addr, usepoint) +
  //     setAttribute(typelock) on the local scope, THEN
  //  2. fd.newVarnode(8, register addr) — newVarnode's localmap->
  //     queryProperties finds the type-locked entry and
  //     Varnode::setSymbolProperties (varnode.cc:409-421) sets the mapentry,
  //     forces the struct type, and propagates
  //     HighVariable::setSymbol (varnode.cc:416-417).
  // Returns the SUBPIECE PcodeOp; the offset constant selects the extracted
  // byte range on the little-endian x86:64 target (lsb == byteOff).
  PcodeOp *buildSubpiece(TypeStruct *containerType, const char *symbolName,
                         uintb regOffset, int4 truncLsb, bool explicitVn)
  {
    SymbolEntry *entry = fd.getScopeLocal()->addSymbol(
        symbolName, containerType, Address(registerSpace, regOffset), Address());
    fd.getScopeLocal()->setAttribute(entry->getSymbol(), Varnode::typelock);
    Varnode *vn = fd.newVarnode(8, Address(registerSpace, regOffset));
    if (vn->getSymbolEntry() == (SymbolEntry *)0)
      throw std::runtime_error("type-locked symbol did not attach to the varnode");
    PcodeOp *defop = fd.newOp(1, Address(codeSpace, pc));
    pc += 0x10;
    fd.opSetOpcode(defop, CPUI_COPY);
    fd.opSetInput(defop, fd.newConstant(8, 0x1122334455667788), 0);
    fd.opSetOutput(defop, vn);
    PcodeOp *sub = fd.newOp(2, Address(codeSpace, pc));
    pc += 0x10;
    fd.opSetOpcode(sub, CPUI_SUBPIECE);
    fd.opSetInput(sub, vn, 0);
    fd.opSetInput(sub, fd.newConstant(1, (uintb)truncLsb), 1);
    fd.newUniqueOut(4, sub);
    fd.setHighLevel();
    if (vn->getHigh()->getSymbol() == (Symbol *)0)
      throw std::runtime_error("symbol did not attach to the high");
    if (explicitVn)
      vn->setExplicit();
    fd.opMarkSpecialPrint(sub);
    return sub;
  }

  string render(PcodeOp *sub)
  {
    FixturePrintC printer(glb);
    return printer.renderOpSubpiece(sub, fd.getScopeLocal());
  }
};

void runPieceStructuredSweep(const FixtureTypes &ft)
{
  std::cout << "piece.struct=" << (ft.pairStruct->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.union=" << (ft.altUnion->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.array=" << (ft.intArray2->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.partialstruct=" << (ft.pairPartial->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.partialunion=" << (ft.altPartialUnion->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.enum=" << (ft.modeEnum->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.partialenum=" << (ft.modePartialEnum->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.int=" << (ft.int4->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.uint=" << (ft.uint4->isPieceStructured() ? 1 : 0) << '\n';
  std::cout << "piece.pointer=" << (ft.intPointer->isPieceStructured() ? 1 : 0) << '\n';
}

void runCastSweep(Architecture *glb, const FixtureTypes &ft)
{
  FixturePrintC printer(glb);
  CastStrategy *cs = printer.getCastStrategy();
  std::cout << "cast.int_int_0=" << (cs->isSubpieceCast(ft.int4, ft.int8, 0) ? 1 : 0) << '\n';
  std::cout << "cast.int_partialstruct_0=" << (cs->isSubpieceCast(ft.int4, ft.pairPartial, 0) ? 1 : 0) << '\n';
  std::cout << "cast.int_partialunion_0=" << (cs->isSubpieceCast(ft.int4, ft.altPartialUnion, 0) ? 1 : 0) << '\n';
  std::cout << "cast.int_partialstruct_2=" << (cs->isSubpieceCast(ft.int4, ft.pairPartial, 2) ? 1 : 0) << '\n';
  std::cout << "cast.int_struct_0=" << (cs->isSubpieceCast(ft.int4, ft.pairStruct, 0) ? 1 : 0) << '\n';
  std::cout << "cast.int_enum_0=" << (cs->isSubpieceCast(ft.int4, ft.modeEnum, 0) ? 1 : 0) << '\n';
  std::cout << "cast.enum_int8_0=" << (cs->isSubpieceCast(ft.modeEnum, ft.int8, 0) ? 1 : 0) << '\n';
  std::cout << "cast.partialstruct_out_0=" << (cs->isSubpieceCast(ft.pairPartial, ft.int8, 0) ? 1 : 0) << '\n';
}

void runSubpieceArms(Funcdata &fd, Architecture *glb, const FixtureTypes &ft)
{
  // armA.field: explicit vn, symbol S over fixture_pair, lsb=4 -> S.hi
  {
    SubpieceFixture fx(fd, glb, 0x5000);
    PcodeOp *sub = fx.buildSubpiece(ft.pairStruct, "S", 0x40, 4, true);
    std::cout << "armA.field=" << fx.render(sub) << '\n';
  }
  // armA.array: explicit vn, symbol A over fixture_arr, lsb=0, outsize 4
  // -> struct descent (.arr) + array element ([0]) -> A.arr[0]
  {
    SubpieceFixture fx(fd, glb, 0x6000);
    PcodeOp *sub = fx.buildSubpiece(ft.arrStruct, "A", 0x48, 0, true);
    std::cout << "armA.array=" << fx.render(sub) << '\n';
  }
  // armA.synthetic: explicit vn, symbol Y over fixture_pair, lsb=2, outsize
  // 4. findTruncation(2,4): getFieldIter(2) -> lo, noff=2, 2+4 > 4 -> null,
  // so the first struct descent fails entirely and the synthetic
  // unnamedField(2,4) entry is taken at the struct level: Y._2_4_.
  {
    SubpieceFixture fx(fd, glb, 0x7000);
    PcodeOp *sub = fx.buildSubpiece(ft.pairStruct, "Y", 0x50, 2, true);
    std::cout << "armA.synthetic=" << fx.render(sub) << '\n';
  }
  // armB.field: NON-explicit vn (high still has symbol B so pushVn resolves
  // through pushSymbolDetail), lsb=0, outsize 4 -> findTruncation(0,4) ->
  // field lo, offset==0 -> "B.lo"
  {
    SubpieceFixture fx(fd, glb, 0x8000);
    PcodeOp *sub = fx.buildSubpiece(ft.pairStruct, "B", 0x58, 0, false);
    std::cout << "armB.field=" << fx.render(sub) << '\n';
  }
}

void run(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary, "default", &std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw std::runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->getName() != "GetStr" ||
        fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
      throw std::runtime_error("GetStr input identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " + architecture.archid);

    FixtureTypes fixtureTypes(architecture.types);
    runPieceStructuredSweep(fixtureTypes);
    runCastSweep(&architecture, fixtureTypes);
    runSubpieceArms(*fd, &architecture, fixtureTypes);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: printc_subpiece_fieldextract_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch(const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const ghidra::RecovError &error) {
    // RecovError is the base of LowlevelError.
    std::cerr << "Ghidra RecovError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
