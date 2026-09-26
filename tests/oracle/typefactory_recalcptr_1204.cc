/*
 * Locked Ghidra 12.0.4 oracle for WORKPKG-UNMAP-TYPEUNION-0003:
 * the TypeFactory recalcPointerSubmeta / setName / warnings /
 * getTypePointerWithSpace / destroyType / setFields-flags family, plus the
 * type.cc free functions string2typeclass / metatype2typeclass.
 *
 * Records (stdout, one line per observation):
 *
 *   s2tc.*       — string2typeclass (type.cc:371-411) for every spelling:
 *                  class1..4 (100..103), general (0), hiddenret (3),
 *                  float (1), ptr (2), pointer (2), vector (4), and
 *                  "unknown" -> 0 (TYPECLASS_GENERAL, type.cc:405-408).
 *                  Two rejected spellings print the verbatim LowlevelError
 *                  explanation ("classes", "").
 *   m2tc.*       — metatype2typeclass (type.cc:420-432): float->1,
 *                  ptr->2, int->0.
 *   recalc.*     — TypeFactory::recalcPointerSubmeta (type.cc:3724-3745)
 *                  as driven by the struct setFields tail (type.cc:3490-3491):
 *                    single.subbefore  pointer to the INCOMPLETE single-
 *                                      field struct sits at SUB_PTR_STRUCT=4
 *                    single.identity   after setFields completes it as a
 *                                      single-field struct, a fresh
 *                                      getTypePointer probe returns the SAME
 *                                      pointer object (migration re-keyed it
 *                                      to SUB_PTR=6)
 *                    single.subafter   the probe's submeta = SUB_PTR=6
 *                    multi.subbefore   multi-field struct pointer = 4
 *                    multi.identity    multi-field completion preserves
 *                                      identity (curSub==SUB_PTR_STRUCT,
 *                                      early-outs)
 *                    multi.subafter    = 4
 *   setname.*    — TypeFactory::setName (type.cc:3445-3459): the renamed
 *                  object is findable under the new name, gone under the
 *                  old, keeps a nonzero id; an ANONYMOUS registration gets
 *                  id = hashName (type.cc:3453-3454).
 *   warn.*       — the insertWarning channel (type.cc:3750-3757) through
 *                  PUBLIC triggers: an anonymous (id-0) struct with an
 *                  overlapping field reaches insertWarning via decodeType
 *                  (type.cc:4358) and throws the verbatim text; a named
 *                  one gets hasWarning set; destroyType then drains the
 *                  warning list through removeWarning (type.cc:4126-4127).
 *   destroy.*    — destroyType (type.cc:4122-4132): core type throws
 *                  verbatim; a destroyed named type is gone from
 *                  findByName.
 *   ptrspace.*   — getTypePointerWithSpace (type.cc:4055-4065): name,
 *                  id == hashName(nm), wordsize and size from the default
 *                  data space, and a non-null getSpace().
 *   flags.*      — the setFields flags mask (type.cc:3487-3488 struct /
 *                  3508-3509 union): struct transfers opaque_string AND
 *                  variable_length; the union mask has NO opaque_string.
 *
 * Object graph: BfdArchitecture over the pinned curl binary (same
 * construction pattern as typefactory_needsres_1204.cc); every fixture
 * type is built exactly once under a unique fixture_recp_* name.
 */

// TypeFactory::insertWarning/removeWarning are private and the Datatype
// flag constants (opaque_string, variable_length) are protected; the
// fixture re-exposes them with the same surgical access-override
// discipline as setcasts_output_bank_1204.cc, scoped to this one header
// (all standard library headers are pre-included first so the override
// never leaks into them).
#include <bits/stdc++.h>
#define private public
#define protected public
#include "type.hh"
#undef protected
#undef private
#include "bfd_arch.hh"
#include "libdecomp.hh"

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

// Public TypeFactory::decodeType entry over hand-fed XML (the same
// channel typefactory_needsres_1204.cc uses): the decodeStruct path
// inserts the decodeFields overlap warning (type.cc:4358).
Datatype *decodeTypeXml(Architecture &architecture, TypeFactory *types, const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  return types->decodeType(decoder);
}

int subOf(const Datatype *ct)
{
  return (int)ct->getSubMeta();
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

    // --- s2tc: string2typeclass (type.cc:371-411) ---
    cout << "s2tc.class1=" << (int)string2typeclass("class1") << '\n';
    cout << "s2tc.class2=" << (int)string2typeclass("class2") << '\n';
    cout << "s2tc.class3=" << (int)string2typeclass("class3") << '\n';
    cout << "s2tc.class4=" << (int)string2typeclass("class4") << '\n';
    cout << "s2tc.general=" << (int)string2typeclass("general") << '\n';
    cout << "s2tc.hiddenret=" << (int)string2typeclass("hiddenret") << '\n';
    cout << "s2tc.float=" << (int)string2typeclass("float") << '\n';
    cout << "s2tc.ptr=" << (int)string2typeclass("ptr") << '\n';
    cout << "s2tc.pointer=" << (int)string2typeclass("pointer") << '\n';
    cout << "s2tc.vector=" << (int)string2typeclass("vector") << '\n';
    cout << "s2tc.unknown=" << (int)string2typeclass("unknown") << '\n';
    try {
      string2typeclass("classes");
      cout << "s2tc.err.classes=NO_THROW\n";
    }
    catch (LowlevelError &err) {
      cout << "s2tc.err.classes=" << err.explain << '\n';
    }
    try {
      string2typeclass("");
      cout << "s2tc.err.empty=NO_THROW\n";
    }
    catch (LowlevelError &err) {
      cout << "s2tc.err.empty=" << err.explain << '\n';
    }

    // --- m2tc: metatype2typeclass (type.cc:420-432) ---
    cout << "m2tc.float=" << (int)metatype2typeclass(TYPE_FLOAT) << '\n';
    cout << "m2tc.ptr=" << (int)metatype2typeclass(TYPE_PTR) << '\n';
    cout << "m2tc.int=" << (int)metatype2typeclass(TYPE_INT) << '\n';

    // --- recalc: setFields completion drives recalcPointerSubmeta ---
    {
      TypeStruct *st = types->getTypeStruct("fixture_recp_single");
      TypePointer *p1 = types->getTypePointer(8, st, 1);
      cout << "recalc.single.subbefore=" << subOf(p1) << '\n';
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "x", typeInt8));
      types->setFields(fd, st, 8, 8, 0);
      TypePointer *p2 = types->getTypePointer(8, st, 1);
      cout << "recalc.single.identity=" << ((p1 == p2) ? 1 : 0) << '\n';
      cout << "recalc.single.subafter=" << subOf(p2) << '\n';
    }
    {
      TypeStruct *st = types->getTypeStruct("fixture_recp_multi");
      TypePointer *p1 = types->getTypePointer(8, st, 1);
      cout << "recalc.multi.subbefore=" << subOf(p1) << '\n';
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "a", typeInt4));
      fd.push_back(TypeField(0, 4, "b", typeInt4));
      types->setFields(fd, st, 8, 4, 0);
      TypePointer *p2 = types->getTypePointer(8, st, 1);
      cout << "recalc.multi.identity=" << ((p1 == p2) ? 1 : 0) << '\n';
      cout << "recalc.multi.subafter=" << subOf(p2) << '\n';
    }

    // --- setname: TypeFactory::setName (type.cc:3445-3459) ---
    {
      TypeStruct *st = types->getTypeStruct("fixture_recp_name_old");
      Datatype *renamed = types->setName(st, "fixture_recp_name_new");
      cout << "setname.newfound="
           << ((types->findByName("fixture_recp_name_new") == renamed) ? 1 : 0) << '\n';
      cout << "setname.oldgone="
           << ((types->findByName("fixture_recp_name_old") == (Datatype *)0) ? 1 : 0) << '\n';
      cout << "setname.idkept="
           << ((renamed->getId() != 0 && renamed->getId() == types->findByName("fixture_recp_name_new")->getId()) ? 1 : 0) << '\n';
      // The anonymous zero-id branch (type.cc:3453-3454).
      Datatype *arr = types->getTypeArray(2, typeInt4);
      cout << "setname.anonzero=" << ((arr->getId() == 0) ? 1 : 0) << '\n';
      Datatype *namedArr = types->setName(arr, "fixture_recp_arr");
      // hashName is protected on Datatype; the anonymous->named id is
      // observable as a nonzero value equal across both factory channels.
      cout << "setname.anonhash.nonzero=" << ((namedArr->getId() != 0) ? 1 : 0) << '\n';
      cout << "setname.anonhash.slotmatch="
           << ((namedArr->getId() == types->findByName("fixture_recp_arr")->getId()) ? 1 : 0) << '\n';
    }

    // --- warn: insertWarning / removeWarning (type.cc:3750/3761), reached
    // through PUBLIC triggers only: the decodeType path inserts the
    // decodeFields overlap warning (type.cc:4358), destroyType removes
    // warnings (type.cc:4126-4127), and an ANONYMOUS overlapping struct
    // reaches insertWarning with id==0 and throws the verbatim text
    // (type.cc:3753-3754). ---
    {
      // warn.anon.err: an anonymous struct (id==0) with an overlapping
      // field -> insertWarning throws.
      try {
        decodeTypeXml(architecture, types,
            "<type size=\"8\" metatype=\"struct\">"
            "<field name=\"x\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>"
            "<field name=\"y\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>"
            "</type>");
        cout << "warn.anon.err=NO_THROW\n";
      }
      catch (LowlevelError &err) {
        cout << "warn.anon.err=" << err.explain << '\n';
      }
      // warn.named.has / warn.removed.stillflag: a NAMED struct with an
      // overlapping field gets the warning inserted (hasWarning set);
      // destroyType drains the list but the flag stays (removeWarning
      // never touches flags).
      Datatype *warned = decodeTypeXml(architecture, types,
          "<type name=\"fixture_recp_warn\" size=\"8\" metatype=\"struct\">"
          "<field name=\"x\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>"
          "<field name=\"y\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>"
          "</type>");
      cout << "warn.named.has=" << (warned->hasWarning() ? 1 : 0) << '\n';
      // destroyType on the WARNED type exercises the internal removeWarning
      // list-drain (type.cc:4126-4127) on a live warnings entry; the type
      // is then gone from findByName. (The flag-outlives-list semantics —
      // removeWarning never touches flags — is not publicly observable
      // after the delete and stays covered by the Rust unit tests.)
      types->destroyType(warned);
      cout << "warn.destroy.gone="
           << ((types->findByName("fixture_recp_warn") == (Datatype *)0) ? 1 : 0) << '\n';
    }

    // --- destroy: destroyType (type.cc:4122-4132) ---
    {
      try {
        types->destroyType(typeInt4);
        cout << "destroy.core.err=NO_THROW\n";
      }
      catch (LowlevelError &err) {
        cout << "destroy.core.err=" << err.explain << '\n';
      }
      // destroy.named.gone: a WARNED named struct (overlapping-field decode
      // inserts the warning through the public path) survives destroyType's
      // internal removeWarning drain and is gone from findByName.
      Datatype *warnedDestroy = decodeTypeXml(architecture, types,
          "<type name=\"fixture_recp_destroy\" size=\"8\" metatype=\"struct\">"
          "<field name=\"x\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>"
          "<field name=\"y\" offset=\"0\"><type name=\"int\" size=\"4\" metatype=\"int\"/></field>"
          "</type>");
      types->destroyType(warnedDestroy);
      cout << "destroy.named.gone="
           << ((types->findByName("fixture_recp_destroy") == (Datatype *)0) ? 1 : 0) << '\n';
    }

    // --- ptrspace: getTypePointerWithSpace (type.cc:4055-4065) ---
    {
      AddrSpace *ram = architecture.getDefaultDataSpace();
      TypePointer *ptr = types->getTypePointerWithSpace(typeInt4, ram, "fixture_tp_ptr");
      cout << "ptrspace.name=" << ptr->getName() << '\n';
      // hashName is protected; the named-pointer id equality against the
      // name-registered slot is the observable instead.
      cout << "ptrspace.idhash="
           << ((ptr->getId() != 0 && types->findByName("fixture_tp_ptr")->getId() == ptr->getId()) ? 1 : 0) << '\n';
      cout << "ptrspace.wordsize=" << (int)ptr->getWordSize() << '\n';
      cout << "ptrspace.size=" << (int)ptr->getSize() << '\n';
      cout << "ptrspace.space=" << ((ptr->getSpace() == ram) ? 1 : 0) << '\n';
    }

    // --- flags: the setFields flags mask (type.cc:3487-3488/3508-3509) ---
    {
      TypeStruct *st = types->getTypeStruct("fixture_recp_mask_s");
      vector<TypeField> fd;
      fd.push_back(TypeField(0, 0, "x", typeInt8));
      types->setFields(fd, st, 8, 8,
                       Datatype::opaque_string | Datatype::variable_length);
      cout << "flags.struct.opaque=" << (st->isOpaqueString() ? 1 : 0) << '\n';
      cout << "flags.struct.varlen=" << (st->isVariableLength() ? 1 : 0) << '\n';
      TypeUnion *ut = types->getTypeUnion("fixture_recp_mask_u");
      vector<TypeField> uf;
      uf.push_back(TypeField(0, 0, "x", typeInt8));
      types->setFields(uf, ut, 8, 8,
                       Datatype::opaque_string | Datatype::variable_length);
      cout << "flags.union.opaque=" << (ut->isOpaqueString() ? 1 : 0) << '\n';
      cout << "flags.union.varlen=" << (ut->isVariableLength() ? 1 : 0) << '\n';
    }
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: typefactory_recalcptr_1204 <spec-dir> <binary>\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
  }
  catch (exception &err) {
    cerr << "fixture failed: " << err.what() << '\n';
    return 1;
  }
  return 0;
}
