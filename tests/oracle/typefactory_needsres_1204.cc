/*
 * Locked Ghidra 12.0.4 oracle for TYPEFACTORY-NEEDSRES-SINGLEFIELD-0001:
 * the complete needs_resolution setting matrix on the TypeFactory paths.
 *
 * Setting sites probed (stdout record, one line per observation, value is
 * needsResolution() ? 1 : 0):
 *
 *   set.*       — TypeFactory::setFields(fd, TypeStruct*, newSize, newAlign,
 *                 flags) with an EXPLICIT newSize (type.cc:3479-3490), whose
 *                 core is TypeStruct::setFields (type.cc:1563-1574):
 *                   set.single.fills    {long x@0}   newSize 8 -> 8==8 -> 1
 *                   set.single.notfills {int x@0}    newSize 8 -> 4!=8 -> 0
 *                   set.single.offset   {long x@4}   newSize 8 -> 8==8 -> 1
 *                       (the field OFFSET is not part of the condition)
 *                   set.multi           {int,int}    newSize 8 -> 2 fields -> 0
 *   grammar.*   — the CParse::newStruct derivation (grammar.cc:2798-2799):
 *                 TypeStruct::assignFieldOffsets derives newSize/newAlign
 *                 from the fields, then setFields is called with them.
 *                   grammar.single  {long x}       derived newSize 8 -> 1
 *                   grammar.multi   {int; int}     derived newSize 8 -> 0
 *   dec.*       — the XML decode path. TypeStruct::decodeFields tail
 *                 (type.cc:1874-1877) sets the flag on single-field-fills
 *                 against the decoded `size` attribute, and
 *                 TypeFactory::decodeStruct re-evaluates the same condition
 *                 through factory setFields when filling the stub
 *                 (type.cc:4355). TypeArray::decode (type.cc:1341-1342)
 *                 sets the flag for arraysize==1.
 *                   dec.single.fills    size=8  {long x@0}          -> 1
 *                   dec.single.notfills size=12 {int x@0}           -> 0
 *                   dec.multi           size=8  {int,int}           -> 0
 *                   dec.arr.size1       size=4  arraysize=1 int     -> 1
 *   arr.factory — TypeFactory::getArray(1, int) — the inline TypeArray
 *                 ctor arm (type.hh:937-944, "array of size 1 ... treated
 *                 as the element data-type") sets the flag             -> 1
 *   ptr.*       — TypePointer::calcSubmeta inheritance (type.cc:1051-
 *                 1052): a pointer to a needsResolution pointee inherits
 *                 the flag, unless the pointee is itself a pointer.
 *                   ptr.inner  = getTypePointer(8, single-field struct) -> 1
 *                   ptr.ptrptr = getTypePointer(8, ptr.inner)          -> 0
 *                   ptr.plain  = getTypePointer(8, long)               -> 0
 *   union.setfields — TypeUnion ctor (type.hh:551) starts with
 *                 type_incomplete|needs_resolution and TypeUnion::
 *                 setFields (type.cc:2002-2009) never touches flags     -> 1
 *
 * Object graph: BfdArchitecture over the pinned curl binary (same
 * construction pattern as printc_subpiece_fieldextract_1204.cc); the
 * architecture's production TypeFactory builds each fixture type exactly
 * once under a unique fixture_nres_* name (a second getTypeStruct/
 * setFields round on a completed name trips findAdd's "Trying to alter
 * definition of type", type.cc:3421-3423).
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "type.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::istringstream;
using std::runtime_error;
using std::string;
using std::vector;

int flagOf(const Datatype *ct)
{
  return ct->needsResolution() ? 1 : 0;
}

// Decode one <type> element (inline child types, no <typeref> ids needed)
// through the public TypeFactory::decodeType entry (type.hh:827) and hand
// the decoded Datatype back for observation.
Datatype *decodeTypeXml(Architecture &architecture, TypeFactory *types, const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  return types->decodeType(decoder);
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
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw runtime_error("runtime architecture/compiler drifted: " + architecture.archid);
    TypeFactory *types = architecture.types;

    Datatype *typeInt4 = types->getBase(4, TYPE_INT);
    Datatype *typeInt8 = types->getBase(8, TYPE_INT);

    // --- set-path: TypeFactory::setFields with explicit newSize ---
    TypeStruct *fillsStruct = types->getTypeStruct("fixture_nres_fills");
    {
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "x", typeInt8));
      types->setFields(fd, fillsStruct, 8, 8, 0);
    }
    cout << "set.single.fills=" << flagOf(fillsStruct) << '\n';
    {
      TypeStruct *st = types->getTypeStruct("fixture_nres_notfills");
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "x", typeInt4));
      types->setFields(fd, st, 8, 4, 0);
      cout << "set.single.notfills=" << flagOf(st) << '\n';
    }
    {
      TypeStruct *st = types->getTypeStruct("fixture_nres_offset");
      vector<TypeField> fd;
      fd.push_back(TypeField(4, 4, "x", typeInt8));
      types->setFields(fd, st, 8, 8, 0);
      cout << "set.single.offset=" << flagOf(st) << '\n';
    }
    {
      TypeStruct *st = types->getTypeStruct("fixture_nres_multi");
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "lo", typeInt4));
      fd.push_back(TypeField(4, 4, "hi", typeInt4));
      types->setFields(fd, st, 8, 4, 0);
      cout << "set.multi=" << flagOf(st) << '\n';
    }

    // --- grammar-path: newSize derived via assignFieldOffsets ---
    {
      TypeStruct *st = types->getTypeStruct("fixture_nres_gram1");
      vector<TypeField> fd;
      fd.emplace_back(0, -1, "x", typeInt8); // offset -1 == "unassigned"
      int4 newSize;
      int4 newAlign;
      TypeStruct::assignFieldOffsets(fd, newSize, newAlign);
      types->setFields(fd, st, newSize, newAlign, 0);
      cout << "grammar.single=" << flagOf(st) << '\n';
    }
    {
      TypeStruct *st = types->getTypeStruct("fixture_nres_gram2");
      vector<TypeField> fd;
      fd.emplace_back(0, -1, "lo", typeInt4);
      fd.emplace_back(0, -1, "hi", typeInt4);
      int4 newSize;
      int4 newAlign;
      TypeStruct::assignFieldOffsets(fd, newSize, newAlign);
      types->setFields(fd, st, newSize, newAlign, 0);
      cout << "grammar.multi=" << flagOf(st) << '\n';
    }

    // --- decode-path: TypeStruct::decodeFields tail / TypeArray::decode ---
    Datatype *decFills = decodeTypeXml(architecture, types,
      "<type name=\"fixture_nres_dec_fills\" size=\"8\" metatype=\"struct\">"
      "<field name=\"x\" offset=\"0\">"
      "<type name=\"long\" size=\"8\" metatype=\"int\"/>"
      "</field></type>");
    cout << "dec.single.fills=" << flagOf(decFills) << '\n';
    Datatype *decNotfills = decodeTypeXml(architecture, types,
      "<type name=\"fixture_nres_dec_notfills\" size=\"12\" metatype=\"struct\">"
      "<field name=\"x\" offset=\"0\">"
      "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
      "</field></type>");
    cout << "dec.single.notfills=" << flagOf(decNotfills) << '\n';
    Datatype *decMulti = decodeTypeXml(architecture, types,
      "<type name=\"fixture_nres_dec_multi\" size=\"8\" metatype=\"struct\">"
      "<field name=\"lo\" offset=\"0\">"
      "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
      "</field>"
      "<field name=\"hi\" offset=\"4\">"
      "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
      "</field></type>");
    cout << "dec.multi=" << flagOf(decMulti) << '\n';
    Datatype *decArr1 = decodeTypeXml(architecture, types,
      "<type name=\"fixture_nres_dec_arr1\" size=\"4\" metatype=\"array\" arraysize=\"1\">"
      "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
      "</type>");
    cout << "dec.arr.size1=" << flagOf(decArr1) << '\n';

    // --- factory array ctor: no flag on the non-decode path ---
    TypeArray *factoryArr1 = types->getTypeArray(1, typeInt4);
    cout << "arr.factory=" << flagOf(factoryArr1) << '\n';

    // --- pointer inheritance: TypePointer::calcSubmeta arm ---
    TypePointer *ptrInner = types->getTypePointer(8, fillsStruct, 1);
    cout << "ptr.inner=" << flagOf(ptrInner) << '\n';
    TypePointer *ptrPtr = types->getTypePointer(8, ptrInner, 1);
    cout << "ptr.ptrptr=" << flagOf(ptrPtr) << '\n';
    TypePointer *ptrPlain = types->getTypePointer(8, typeInt8, 1);
    cout << "ptr.plain=" << flagOf(ptrPlain) << '\n';

    // --- grammar over-fire regression cell: an XML-decoded UNROUNDED struct
    // (size 5, alignment 4, alignSize 8) as a single grammar field. Ghidra's
    // assignFieldOffsets newSize is calcAlignSize(8,4)=8 != 5, so the flag
    // must stay CLEAR even though max(offset+getSize)=5 would fire a naive
    // derivation (type.cc:1971-1993 + 1569-1571).
    Datatype *pad5 = decodeTypeXml(architecture, types,
      "<type name=\"fixture_nres_pad5\" size=\"5\" metatype=\"struct\">"
      "<field name=\"lo\" offset=\"0\">"
      "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
      "</field>"
      "<field name=\"hi\" offset=\"4\">"
      "<type size=\"1\" metatype=\"int\"/>"
      "</field></type>");
    {
      TypeStruct *st = types->getTypeStruct("fixture_nres_over");
      vector<TypeField> fd;
      fd.emplace_back(0, -1, "p", pad5);
      int4 newSize;
      int4 newAlign;
      TypeStruct::assignFieldOffsets(fd, newSize, newAlign);
      types->setFields(fd, st, newSize, newAlign, 0);
      cout << "grammar.overfire=" << flagOf(st) << '\n';
    }
    // --- nested single-field propagation: inner flag set by the grammar
    // path; the outer single field of inner (size 4 == newSize 4) flags too.
    {
      TypeStruct *inner = types->getTypeStruct("fixture_nres_nestin");
      vector<TypeField> fdIn;
      fdIn.emplace_back(0, -1, "x", typeInt4);
      int4 newSize;
      int4 newAlign;
      TypeStruct::assignFieldOffsets(fdIn, newSize, newAlign);
      types->setFields(fdIn, inner, newSize, newAlign, 0);
      TypeStruct *outer = types->getTypeStruct("fixture_nres_nestout");
      vector<TypeField> fdOut;
      fdOut.emplace_back(0, -1, "i", inner);
      TypeStruct::assignFieldOffsets(fdOut, newSize, newAlign);
      types->setFields(fdOut, outer, newSize, newAlign, 0);
      cout << "grammar.nested=inner:" << flagOf(inner)
           << ",outer:" << flagOf(outer) << '\n';
    }
    // --- pointer ordering: a pointer built while the struct is still an
    // incomplete stub never inherits the flag (calcSubmeta runs at
    // construction only; recalcPointerSubmeta fixes submeta, not flags).
    // After the grammar definition the SAME pointer stays clear, while a
    // differently-sized new pointer inherits the flag.
    {
      TypeStruct *pre = types->getTypeStruct("fixture_nres_pre");
      TypePointer *stubPtr = types->getTypePointer(8, pre, 1);
      vector<TypeField> fd;
      fd.emplace_back(0, -1, "x", typeInt8);
      int4 newSize;
      int4 newAlign;
      TypeStruct::assignFieldOffsets(fd, newSize, newAlign);
      types->setFields(fd, pre, newSize, newAlign, 0);
      TypePointer *cachedPtr = types->getTypePointer(8, pre, 1);
      TypePointer *newPtr = types->getTypePointer(4, pre, 1);
      cout << "ptr.ordering=stub:" << flagOf(stubPtr)
           << ",struct:" << flagOf(pre)
           << ",cached:" << flagOf(cachedPtr)
           << ",new:" << flagOf(newPtr) << '\n';
    }

    // --- decode acceptance tail: overlap throw-out + incomplete residue ---
    // Overlapping second field is dropped (type.cc:1849-1860, warning only),
    // leaving a single filling field: flag set, complete.
    {
      Datatype *overlap = decodeTypeXml(architecture, types,
        "<type name=\"fixture_nres_dec_overlap\" size=\"4\" metatype=\"struct\">"
        "<field name=\"x\" offset=\"0\">"
        "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
        "</field>"
        "<field name=\"y\" offset=\"0\">"
        "<type size=\"1\" metatype=\"int\"/>"
        "</field></type>");
      cout << "dec.overlap=fields:" << overlap->numDepend()
           << ",needsres:" << flagOf(overlap)
           << ",incomplete:" << (overlap->isIncomplete() ? 1 : 0) << '\n';
    }
    // Equal-offset fields: the FIRST survives, the second is overlap-dropped.
    {
      Datatype *keepfirst = decodeTypeXml(architecture, types,
        "<type name=\"fixture_nres_dec_keepfirst\" size=\"1\" metatype=\"struct\">"
        "<field name=\"x\" offset=\"0\">"
        "<type size=\"1\" metatype=\"int\"/>"
        "</field>"
        "<field name=\"y\" offset=\"0\">"
        "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
        "</field></type>");
      cout << "dec.overlap.keepfirst=fields:" << keepfirst->numDepend()
           << ",needsres:" << flagOf(keepfirst)
           << ",incomplete:" << (keepfirst->isIncomplete() ? 1 : 0) << '\n';
    }
    // No fields: the factory type stays incomplete (decodeStruct transfers
    // the scratch's incomplete state via setFields, type.cc:4350-4356).
    {
      Datatype *empty8 = decodeTypeXml(architecture, types,
        "<type name=\"fixture_nres_dec_empty8\" size=\"8\" metatype=\"struct\"/>");
      cout << "dec.incomplete.empty=fields:" << empty8->numDepend()
           << ",needsres:" << flagOf(empty8)
           << ",incomplete:" << (empty8->isIncomplete() ? 1 : 0) << '\n';
    }
    // size="0" (old-style incomplete marker) with no fields: incomplete.
    {
      Datatype *zero = decodeTypeXml(architecture, types,
        "<type name=\"fixture_nres_dec_zero\" size=\"0\" metatype=\"struct\"/>");
      cout << "dec.incomplete.zero=fields:" << zero->numDepend()
           << ",needsres:" << flagOf(zero)
           << ",incomplete:" << (zero->isIncomplete() ? 1 : 0) << '\n';
    }
    // --- decode rejection texts (LowlevelError::explain, verbatim) ---
    {
      const char *records[] = {
        "dec.err.order",
        "dec.err.fit",
        "dec.err.void",
        "dec.err.name",
        "dec.err.namevoid",
      };
      const char *documents[] = {
        "<type name=\"fixture_nres_dec_errorder\" size=\"8\" metatype=\"struct\">"
        "<field name=\"x\" offset=\"4\">"
        "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
        "</field>"
        "<field name=\"y\" offset=\"0\">"
        "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
        "</field></type>",
        "<type name=\"fixture_nres_dec_errfit\" size=\"4\" metatype=\"struct\">"
        "<field name=\"z\" offset=\"2\">"
        "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
        "</field></type>",
        "<type name=\"fixture_nres_dec_errvoid\" size=\"4\" metatype=\"struct\">"
        "<field name=\"x\" offset=\"0\"><void/></field></type>",
        "<type name=\"fixture_nres_dec_errname\" size=\"4\" metatype=\"struct\">"
        "<field name=\"\" offset=\"0\">"
        "<type name=\"int\" size=\"4\" metatype=\"int\"/>"
        "</field></type>",
        "<type name=\"fixture_nres_dec_errnamevoid\" size=\"4\" metatype=\"struct\">"
        "<field name=\"\" offset=\"0\"><void/></field></type>",
      };
      for(int4 i=0;i<5;++i) {
        try {
          decodeTypeXml(architecture, types, documents[i]);
          cout << records[i] << "=<none>\n";
        }
        catch(const LowlevelError &error) {
          cout << records[i] << '=' << error.explain << '\n';
        }
      }
    }

    // --- union: ctor flag survives TypeUnion::setFields ---
    TypeUnion *nu = types->getTypeUnion("fixture_nres_union");
    {
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "a", typeInt4));
      types->setFields(fd, nu, 4, 4, 0);
    }
    cout << "union.setfields=" << flagOf(nu) << '\n';
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: typefactory_needsres_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch (const ghidra::RecovError &error) {
    // RecovError is the base of LowlevelError.
    std::cerr << "Ghidra RecovError: " << error.explain << '\n';
  }
  catch (const exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
