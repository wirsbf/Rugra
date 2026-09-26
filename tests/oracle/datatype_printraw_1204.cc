/*
 * Locked Ghidra 12.0.4 oracle for DATATYPE-PRINTRAW-0001
 * (lane DATATYPEPR, found by lane MIGW-DATABASE).
 *
 * Exercises the complete virtual printRaw family of type.cc under the
 * locked oracle e40ed13014025f82488b1f8f7bca566894ac376b:
 *
 *   Datatype::printRaw          type.cc:139-146   base fallback (name / unkbyte<size>)
 *   TypePointer::printRaw       type.cc:910-918   ptrto, " *", optional "(<spacename>)"
 *   TypeArray::printRaw         type.cc:1204-1209 arrayof, " [<arraysize>]"
 *   TypePartialEnum::printRaw   type.cc:2264-2269 parent, "[off=<off>,sz=<size>]"
 *   TypePartialStruct::printRaw type.cc:2356-2361 container, "[off=<off>,sz=<size>]"
 *   TypePartialUnion::printRaw  type.cc:2433-2438 container, "[off=<off>,sz=<size>]"
 *   TypePointerRel::printRaw    type.cc:2597-2606 ptrto, " *+", offset, "[", parent, "]"
 *   TypeCode::printRaw          type.cc:2772-2780 name-or-"funcptr", "()"
 *
 * Subclasses WITHOUT a printRaw override (TypeVoid, TypeBase, TypeEnum,
 * TypeStruct, TypeUnion, TypeSpacebase) are pinned to the base-class
 * fallback through virtual dispatch.  Pointer identity is never printed;
 * only names, sizes, offsets, counts, and the exact separator characters
 * reach stdout.  All constructors are the public ones from type.hh; the
 * named TypeCode case mirrors the (private)
 * TypeFactory::getTypeCode(const string&) body field-for-field through a
 * subclass, because type.hh has no public named TypeCode constructor.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "space.hh"
#include "type.hh"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::string;
using std::vector;

/// A production BfdArchitecture over the fixture binary, so the type
/// factory and the spec-derived address spaces are all real (same shape
/// as the database_scope_tree_1204 harness).
class FixtureArchitecture final : public BfdArchitecture {
public:
  FixtureArchitecture(const string &filename, const string &target,
                      std::ostream *estream)
    : BfdArchitecture(filename, target, estream) {}
};

/// Named TypeCode built exactly the way the (private)
/// TypeFactory::getTypeCode(const string&) (type.hh:796, body at
/// type.cc:3711-3719) builds it: generic TypeCode plus name,
/// displayName, hashName id, and markComplete.  The fields are
/// protected, so the mirror goes through a subclass; printRaw still
/// dispatches virtually to TypeCode::printRaw.
class FixtureCode final : public TypeCode {
public:
  explicit FixtureCode(const string &nm) : TypeCode() {
    name = nm;
    displayName = nm;
    id = Datatype::hashName(nm);
    markComplete();
  }
};

/// Render one observation line: the printRaw bytes between markers, so
/// leading/trailing separator spacing is byte-visible.
void emit(const string &id, const Datatype *dt)
{
  std::ostringstream s;
  dt->printRaw(s);
  std::cout << "case=" << id << "|[" << s.str() << "]|\n";
}

void run(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    std::ostringstream diagnostics;
    FixtureArchitecture arch(binary, "default", &diagnostics);
    DocumentStorage store;
    arch.init(store);
    if (arch.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " + arch.archid);

    AddrSpace *ram = arch.getSpaceByName("ram");
    AddrSpace *stack = arch.getSpaceByName("stack");

    // ---- base-class fallback (type.cc:139-146) ----
    TypeBase baseNamed(4, TYPE_INT, "myint");
    emit("base_named", &baseNamed);
    TypeBase baseUnnamed(5, TYPE_UNKNOWN);
    emit("base_unnamed", &baseUnnamed);
    TypeBase baseUnnamedZero(0, TYPE_UNKNOWN);
    emit("base_unnamed_zero", &baseUnnamedZero);
    TypeVoid voidDefault;
    emit("void_default", &voidDefault);
    TypeEnum enumNamed(4, TYPE_INT, "Col");
    emit("enum_named", &enumNamed);
    TypeEnum enumUnnamed(4, TYPE_INT);
    emit("enum_unnamed", &enumUnnamed);
    TypeStruct structIncomplete;
    emit("struct_incomplete", &structIncomplete);
    TypeUnion unionIncomplete;
    emit("union_incomplete", &unionIncomplete);
    TypeSpacebase spacebaseRam(ram, Address(ram, 0x1000), &arch);
    emit("spacebase_ram", &spacebaseRam);
    TypeSpacebase spacebaseNoSpace(&arch);
    emit("spacebase_nospace", &spacebaseNoSpace);

    // ---- TypePointer::printRaw (type.cc:910-918) ----
    TypePointer ptrPlain(8, &baseNamed, 1);
    emit("ptr_plain", &ptrPlain);
    TypePointer ptrToUnnamed(8, &baseUnnamed, 1);
    emit("ptr_to_unnamed", &ptrToUnnamed);
    TypePointer ptrSpaceRam(&baseNamed, ram);
    emit("ptr_space_ram", &ptrSpaceRam);
    TypePointer ptrSpaceStack(&baseNamed, stack);
    emit("ptr_space_stack", &ptrSpaceStack);
    TypePointer ptrChain(8, &ptrPlain, 1);
    emit("ptr_chain", &ptrChain);
    TypePointer ptrWordsize4(8, &baseNamed, 4);
    emit("ptr_wordsize4", &ptrWordsize4);

    // ---- TypeArray::printRaw (type.cc:1204-1209) ----
    TypeArray arrayInt3(3, &baseNamed);
    emit("array_int3", &arrayInt3);
    TypeBase baseUnnamed7(7, TYPE_UNKNOWN);
    TypeArray arrayUnnamed(4, &baseUnnamed7);
    emit("array_unnamed", &arrayUnnamed);
    TypeArray arrayOfPtr(3, &ptrPlain);
    emit("array_of_ptr", &arrayOfPtr);
    TypePointer ptrToArray(8, &arrayInt3, 1);
    emit("ptr_to_array", &ptrToArray);
    TypeArray arrayOfArray(2, &arrayInt3);
    emit("array_of_array", &arrayOfArray);

    // ---- TypeCode::printRaw (type.cc:2772-2780) ----
    TypeCode codeAnon;
    emit("code_anon", &codeAnon);
    FixtureCode codeNamed("mycode");
    emit("code_named", &codeNamed);
    TypePointer ptrToCode(8, &codeAnon, 1);
    emit("ptr_to_code", &ptrToCode);

    // ---- TypePartial*::printRaw (type.cc:2264/2356/2433) ----
    TypeBase strip(4, TYPE_UNKNOWN, "undefined4");
    TypePartialStruct partialStruct(&arrayInt3, 4, 4, &strip);
    emit("partial_struct", &partialStruct);
    TypePartialStruct partialStructNeg(&arrayInt3, -3, 4, &strip);
    emit("partial_struct_negoff", &partialStructNeg);
    TypePartialEnum partialEnum(&enumNamed, 1, 2, &strip);
    emit("partial_enum", &partialEnum);
    TypePartialUnion partialUnion(&unionIncomplete, 0, 8, &strip);
    emit("partial_union", &partialUnion);

    // ---- TypePointerRel::printRaw (type.cc:2597-2606) ----
    TypePointerRel ptrrelZero(8, &baseNamed, 1, &arrayInt3, 0);
    emit("ptrrel_zero", &ptrrelZero);
    TypePointerRel ptrrelOff16(8, &baseNamed, 1, &arrayInt3, 16);
    emit("ptrrel_off16", &ptrrelOff16);
    TypePointerRel ptrrelNeg(8, &baseNamed, 1, &arrayInt3, -8);
    emit("ptrrel_neg", &ptrrelNeg);
    TypePointer ptrToPtrrel(8, &ptrrelZero, 1);
    emit("ptr_to_ptrrel", &ptrToPtrrel);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: datatype_printraw_1204 SPEC_ROOT BINARY" << std::endl;
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  } catch (const LowlevelError &error) {
    std::cerr << "datatype_printraw_1204: LowlevelError: " << error.explain << std::endl;
    return 1;
  } catch (const RecovError &error) {
    std::cerr << "datatype_printraw_1204: RecovError: " << error.explain << std::endl;
    return 1;
  } catch (const std::exception &error) {
    std::cerr << "datatype_printraw_1204: " << error.what() << std::endl;
    return 1;
  }
}
