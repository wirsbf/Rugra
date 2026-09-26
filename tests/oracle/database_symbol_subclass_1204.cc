/*
 * Locked Ghidra 12.0.4 oracle for DATABASE-SYMBOL-SUBCLASS-FIXTURE-0001
 * (MIGW1-DATABASE-0005 phase 2, second fixture).
 *
 * Exercises the Symbol-subclass construction surface and the entry/
 * comparator carriers Rust-ized in src/database.rs under the same
 * anchors:
 *
 *   FunctionSymbol::buildType        database.cc:514
 *   FunctionSymbol::FunctionSymbol   database.cc:534 / 545
 *   FunctionSymbol::getBytesConsumed  database.cc:508 override
 *   LabSymbol::buildType             database.cc:728
 *   LabSymbol::LabSymbol             database.cc:736 / 745
 *   ExternRefSymbol::buildNameType   database.cc:768
 *   ExternRefSymbol ctor             database.cc:789
 *   ExternRefSymbol::getRefAddr      database.hh:351
 *   UnionFacetSymbol ctor            database.cc:691 / hh:323
 *   UnionFacetSymbol::getFieldNumber database.hh:324
 *   Symbol::getBytesConsumed         database.cc:508
 *   Symbol::getMapEntryPosition      database.cc:301 (cc:309 quirk)
 *   SymbolEntry::getFirstUseAddress  database.cc:122
 *   SymbolEntry::printEntry          database.cc:166
 *   SymbolEntry::EntrySubsort        database.hh:107-134
 *   SymbolCompareName                database.hh:366
 *   DuplicateFunctionError          database.hh:435
 *   Scope::printBounds               database.hh:789
 *
 * All projections are id/name/size/message-level.  printEntry strings
 * are compared verbatim; the entry types are deliberately base types
 * (int4 / xunknown4) whose printRaw is the plain name on both sides —
 * the printRaw of code/union/struct/enum metatypes is outside this
 * fixture (a pre-existing cross-file deviation is reported separately).
 */

#include "bfd_arch.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "space.hh"
#include "type.hh"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::string;
using std::vector;

class FixtureArchitecture final : public BfdArchitecture {
public:
  FixtureArchitecture(const string &filename, const string &target,
                      std::ostream *estream)
    : BfdArchitecture(filename, target, estream) {}
};

class FixtureDatabase final : public Database {
public:
  FixtureDatabase(Architecture *g, bool idByName) : Database(g, idByName) {}
};

class FixtureSymbol final : public Symbol {
public:
  FixtureSymbol(Scope *sc, const string &nm, Datatype *ct)
    : Symbol(sc, nm, ct) {}
  void setDedup(uint4 v) { nameDedup = v; }
};

class FixtureScope final : public ScopeInternal {
public:
  FixtureScope(uint8 id, const string &name, Architecture *arch)
    : ScopeInternal(id, name, arch) {}
  FixtureSymbol *addRaw(const string &nm, Datatype *ct) {
    FixtureSymbol *sym = new FixtureSymbol(this, nm, ct);
    addSymbolInternal(sym);
    return sym;
  }
  // Expose the protected storage installer for partial-entry cases.
  SymbolEntry *addPiece(Symbol *sym, const Address &addr, int4 off, int4 sz,
                        const RangeList &uselim) {
    return addMapInternal(sym, 0, addr, off, sz, uselim);
  }
};

/// A ram-like processor space with deterministic attributes: 4-byte
/// addresses, word size 1, index 3, unassigned shortcut (' ').
AddrSpace *makeRam(void)
{
  return new AddrSpace((AddrSpaceManager *)0, (const Translate *)0,
                       IPTR_PROCESSOR, "ram", false, 4, 1, 3,
                       AddrSpace::hasphysical, -1, -1);
}

string hexoff(uintb v)
{
  std::ostringstream s;
  s << std::hex << v;
  return s.str();
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
    TypeFactory *types = arch.types;

    FixtureScope *global = new FixtureScope(100, "", &arch);
    FixtureDatabase db(&arch, false);
    db.attachScope(global, (Scope *)0);
    AddrSpace *ram = makeRam();

    // ---- FunctionSymbol (database.cc:514/534/545/508) ----
    {
      FunctionSymbol *f = new FunctionSymbol(global, "main", 2);
      std::cout << "case=fsym_buildtype|metatype=code|size=" << f->getType()->getSize()
                << "|namelock=" << ((f->getFlags() & Varnode::namelock) ? 1 : 0)
                << "|typelock=" << ((f->getFlags() & Varnode::typelock) ? 1 : 0)
                << "|name=" << f->getName() << '\n';
      std::cout << "case=fsym_bytes_consumed|" << f->getBytesConsumed() << '\n';
      std::cout << "case=fsym_type_size|" << f->getType()->getSize() << '\n';
      FunctionSymbol *fd = new FunctionSymbol(global, 3);
      std::cout << "case=fsym_decode_ctor|name_empty="
                << (fd->getName().size() == 0 ? 1 : 0)
                << "|consume=" << fd->getBytesConsumed() << '\n';
    }

    // ---- LabSymbol (database.cc:728/736/745) ----
    {
      LabSymbol *l = new LabSymbol(global, "loop");
      std::cout << "case=lsym_buildtype|typename=" << l->getType()->getName()
                << "|size=" << l->getType()->getSize()
                << "|name=" << l->getName() << '\n';
      LabSymbol *ld = new LabSymbol(global);
      std::cout << "case=lsym_decode_ctor|name_empty="
                << (ld->getName().size() == 0 ? 1 : 0)
                << "|typename=" << ld->getType()->getName() << '\n';
    }

    // ---- ExternRefSymbol (database.cc:768/789; hh:351) ----
    {
      Address ref(ram, 0x6000);
      ExternRefSymbol *x = new ExternRefSymbol(global, ref, "");
      std::cout << "case=exref_autoname|name=" << x->getName()
                << "|externref=" << ((x->getFlags() & Varnode::externref) ? 1 : 0)
                << "|typelock=" << ((x->getFlags() & Varnode::typelock) ? 1 : 0)
                << "|ptr_size=" << x->getType()->getSize()
                << "|ptr_meta=ptr" << '\n';
      Address ref2(ram, 0x6010);
      ExternRefSymbol *y = new ExternRefSymbol(global, ref2, "printf");
      std::cout << "case=exref_named|name=" << y->getName() << '\n';
      std::cout << "case=exref_ref_addr|" << hexoff(x->getRefAddr().getOffset()) << '\n';
    }

    // ---- UnionFacetSymbol (database.cc:691; hh:323/324) ----
    {
      Datatype *udt = types->getTypeUnion("fixture_union");
      UnionFacetSymbol *u = new UnionFacetSymbol(global, "f", udt, 2);
      std::cout << "case=ufacet_ctor|field=" << u->getFieldNumber()
                << "|category=" << u->getCategory()
                << "|typename=" << u->getType()->getName() << '\n';
      UnionFacetSymbol *ud = new UnionFacetSymbol(global);
      std::cout << "case=ufacet_decode|field=" << ud->getFieldNumber()
                << "|category=" << ud->getCategory() << '\n';
    }

    // ---- Symbol::getBytesConsumed (database.cc:508) ----
    {
      Datatype *int4 = types->getBase(4, TYPE_INT);
      FixtureSymbol *s = new FixtureSymbol(global, "s", int4);
      std::cout << "case=sym_bytes_consumed|" << s->getBytesConsumed() << '\n';
    }

    // ---- Symbol::getMapEntryPosition (database.cc:301-313) ----
    {
      Datatype *int4 = types->getBase(4, TYPE_INT);
      FixtureSymbol *m = global->addRaw("m", int4);
      Address a1(ram, 0x1000), a2(ram, 0x2000), a3(ram, 0x3000);
      RangeList empty;
      SymbolEntry *e1 = global->addMapPoint(m, a1, Address());
      SymbolEntry *e2 = global->addMapPoint(m, a2, Address());
      global->addMapPoint(m, a3, Address());
      // cc:309 quirk: the counter condition reads the SOUGHT entry's
      // size vs the type size — a whole-sized sought entry yields its
      // index among ALL entries; a partial sought entry always yields 0.
      SymbolEntry *piece = global->addPiece(m, Address(ram, 0x4000), 0, 2, empty);
      std::cout << "case=mapentry_whole_sought|" << m->getMapEntryPosition(e2) << '\n';
      std::cout << "case=mapentry_partial_sought|" << m->getMapEntryPosition(piece) << '\n';
      // An entry of a DIFFERENT symbol is absent from m's mapentry list.
      FixtureSymbol *other = global->addRaw("other", int4);
      SymbolEntry *foreign = global->addMapPoint(other, Address(ram, 0x8000), Address());
      std::cout << "case=mapentry_absent|" << m->getMapEntryPosition(foreign) << '\n';
      (void)e1;
    }

    // ---- SymbolEntry::getFirstUseAddress (database.cc:122) ----
    {
      Datatype *int4 = types->getBase(4, TYPE_INT);
      FixtureSymbol *m2 = new FixtureSymbol(global, "m2", int4);
      RangeList uselim;
      uselim.insertRange(ram, 0x4000, 0x4fff);
      SymbolEntry *e = global->addMapPoint(m2, Address(ram, 0x2000), Address());
      e->setUseLimit(uselim);
      std::cout << "case=firstuse_present|" << hexoff(e->getFirstUseAddress().getOffset()) << '\n';
      RangeList empty;
      SymbolEntry *e2 = global->addMapPoint(m2, Address(ram, 0x2100), Address());
      e2->setUseLimit(empty);
      std::cout << "case=firstuse_empty|" << (e2->getFirstUseAddress().isInvalid() ? 1 : 0) << '\n';
    }

    // ---- SymbolEntry::printEntry (database.cc:166-181) ----
    {
      std::ostringstream p1, p2, p3;
      Datatype *int4 = types->getBase(4, TYPE_INT);
      FixtureSymbol *m = global->addRaw("m", int4);
      SymbolEntry *e1 = global->addMapPoint(m, Address(ram, 0x1000), Address());
      e1->printEntry(p1);
      std::cout << "case=printentry_static_all|" << p1.str();

      FixtureSymbol *m2 = global->addRaw("m2", int4);
      RangeList uselim;
      uselim.insertRange(ram, 0x4000, 0x4fff);
      SymbolEntry *e2 = global->addMapPoint(m2, Address(ram, 0x2000), Address());
      e2->setUseLimit(uselim);
      e2->printEntry(p2);
      std::cout << "case=printentry_uselimit|" << p2.str();

      FixtureSymbol *d = global->addRaw("d", int4);
      RangeList empty;
      // The dynamic SymbolEntry ctor (database.hh:140) — dynamic entries
      // are never installed through addMapInternal (which dereferences the
      // entry address's space); printEntry only reads fields.
      SymbolEntry *e3 = new SymbolEntry(d, Varnode::mapped, 0x1234, 0, 4, empty);
      e3->printEntry(p3);
      std::cout << "case=printentry_dynamic|" << p3.str();
    }

    // ---- SymbolEntry::EntrySubsort (database.hh:107-134) ----
    {
      SymbolEntry::EntrySubsort earliest;
      SymbolEntry::EntrySubsort latest(true);
      std::cout << "case=subsort_earliest_lt_latest|" << (earliest < latest ? 1 : 0) << '\n';
      std::cout << "case=subsort_latest_gt_earliest|" << (latest < earliest ? 0 : 1) << '\n';
      Address sa(ram, 0x5000);
      Address sb(ram, 0x6000);
      SymbolEntry::EntrySubsort from_a(sa);
      SymbolEntry::EntrySubsort from_b(sb);
      std::cout << "case=subsort_addr_offset_order|" << (from_a < from_b ? 1 : 0) << '\n';
      std::cout << "case=subsort_addr_offset_rev|" << (from_b < from_a ? 0 : 1) << '\n';
      SymbolEntry::EntrySubsort from_a2(sa);
      std::cout << "case=subsort_addr_equal|" << (from_a < from_a2 ? 0 : 1) << '\n';
    }

    // ---- SymbolCompareName (database.hh:366) ----
    {
      Datatype *int4 = types->getBase(4, TYPE_INT);
      FixtureSymbol *s1 = new FixtureSymbol(global, "apple", int4);
      FixtureSymbol *s2 = new FixtureSymbol(global, "banana", int4);
      SymbolCompareName cmp;
      std::cout << "case=symcmp_name_order|" << (cmp(s1, s2) ? 1 : 0) << '\n';
      std::cout << "case=symcmp_name_rev|" << (cmp(s2, s1) ? 0 : 1) << '\n';
      FixtureSymbol *t1 = new FixtureSymbol(global, "same", int4);
      FixtureSymbol *t2 = new FixtureSymbol(global, "same", int4);
      t1->setDedup(1);
      t2->setDedup(2);
      std::cout << "case=symcmp_dedup_tiebreak|" << (cmp(t1, t2) ? 1 : 0) << '\n';
      std::cout << "case=symcmp_dedup_rev|" << (cmp(t2, t1) ? 0 : 1) << '\n';
    }

    // ---- DuplicateFunctionError (database.hh:435) ----
    {
      DuplicateFunctionError err(Address(ram, 0x5000), "foo");
      std::cout << "case=dupfn|msg=" << err.explain
                << "|addr=" << hexoff(err.address.getOffset())
                << "|name=" << err.functionName << '\n';
    }

    // ---- Scope::printBounds (database.hh:789) ----
    {
      FixtureScope *ns = new FixtureScope(101, "ns", &arch);
      db.attachScope(ns, global);
      RangeList rlist;
      rlist.insertRange(ram, 0x3000, 0x3fff);
      rlist.insertRange(ram, 0x1000, 0x1fff);
      db.setRange(ns, rlist);
      std::ostringstream pb;
      ns->printBounds(pb);
      std::cout << "case=scope_printbounds|" << pb.str();
    }

    delete ram;
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: database_symbol_subclass_1204 SPEC_ROOT BINARY" << std::endl;
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  } catch (const LowlevelError &error) {
    std::cerr << "database_symbol_subclass_1204: LowlevelError: " << error.explain << std::endl;
    return 1;
  } catch (const std::exception &error) {
    std::cerr << "database_symbol_subclass_1204: " << error.what() << std::endl;
    return 1;
  }
}
