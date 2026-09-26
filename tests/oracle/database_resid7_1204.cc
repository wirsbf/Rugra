/*
 * Locked Ghidra 12.0.4 oracle for DATABASE-RESID7-FIXTURE-0001
 * (MIGW1-DATABASE-0005 residual-seven closure lane, wt/database7).
 *
 * Exercises the seven residual surfaces left UNTESTED by the
 * MIGW-DATABASE lane report (2026-09-26, section 五):
 *
 *   ScopeInternal::addDynamicMapInternal   database.cc:1874-1887 (whole-count)
 *   ScopeInternal::categorySanity          database.cc:1992-2018
 *   ScopeInternal multiEntrySet surface    database.hh:813/865-866
 *                                           (SymbolNameTree = name order,
 *                                            SymbolCompareName hh:358-373)
 *   ScopeInternal::resolveExternalRefFunction
 *                                          database.cc:2362-2366
 *                                            (-> queryFunction cc:1287 ->
 *                                             mapScope cc:3185 with an
 *                                             empty resolvemap returns the
 *                                             query scope itself ->
 *                                             stackFunction cc:1009 ->
 *                                             findFunction cc:2321)
 *   Scope::childrenBegin/childrenEnd       database.hh:765-766
 *                                           (ScopeMap = map<uint8,Scope*>,
 *                                            hh:439 — unique-id order)
 *   ScopeInternal::printEntries            database.cc:2791-2804
 *                                           (maptable walk, ascending
 *                                            space index, per-space list
 *                                            order)
 *   Scope::decodeWrappingAttributes        database.hh:714-719 — NOT a case
 *                                           here: the database-layer base
 *                                           body is literally `{}` (no
 *                                           reads, no state), so there is
 *                                           no observable to diverge; the
 *                                           only override is ScopeLocal
 *                                           (varmap.cc:479), a varmap.rs
 *                                           lease handed over separately.
 *
 * All projections are id/name/size/message-level: pointer values are never
 * printed. printEntry strings are compared verbatim; entry types are base
 * types (int4) whose printRaw is the plain name on both sides. The two
 * custom spaces are constructed with explicit indexes 3 (ram) and 4 (rom)
 * and the same deterministic attributes on both comparands.
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

/// A production BfdArchitecture over the fixture binary, so the type
/// factory, spec-derived sizes, the default spaces (maptable sizing) and
/// the untouched production symbol table (empty resolvemap) are all real.
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
  uint4 dedup(void) const { return nameDedup; }
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
  void addInternal(Symbol *sym) { addSymbolInternal(sym); }
  SymbolEntry *addDyn(Symbol *sym, uint4 exfl, uint8 hash, int4 off, int4 sz,
                      const RangeList &uselim) {
    return addDynamicMapInternal(sym, exfl, hash, off, sz, uselim);
  }
  void remMaps(Symbol *sym) { removeSymbolMappings(sym); }
};

/// A ram-like processor space with deterministic attributes: 4-byte
/// addresses, word size 1, index 3, unassigned shortcut.
AddrSpace *makeSpace(const string &nm, int4 index)
{
  return new AddrSpace((AddrSpaceManager *)0, (const Translate *)0,
                       IPTR_PROCESSOR, nm, false, 4, 1, index,
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
    Datatype *itype = types->getBase(4, TYPE_INT);
    AddrSpace *ram = makeSpace("ram", 3);
    AddrSpace *rom = makeSpace("rom", 4);
    RangeList empty;

    // ---- addDynamicMapInternal whole-count (database.cc:1874-1887) ----
    {
      FixtureScope *scope = new FixtureScope(130, "dyn", &arch);
      FixtureSymbol *a = scope->addRaw("a", itype);
      scope->addDyn(a, 0, 0x1234, 0, 4, empty);	// whole (sz == type size)
      std::cout << "case=dyn_whole_1|multi=" << (a->isMultiEntry() ? 1 : 0) << '\n';
      std::ostringstream p;
      a->getMapEntry(0)->printEntry(p);
      std::cout << "case=dyn_print|" << p.str();
      scope->addDyn(a, 0, 0x1235, 0, 4, empty);	// second whole
      std::cout << "case=dyn_whole_2|multi=" << (a->isMultiEntry() ? 1 : 0) << '\n';
      scope->addDyn(a, 0, 0x1236, 0, 4, empty);	// third whole
      std::cout << "case=dyn_whole_3|multi=" << (a->isMultiEntry() ? 1 : 0) << '\n';
      scope->addDyn(a, 0, 0x1237, 0, 2, empty);	// partial: wholeCount stays
      std::cout << "case=dyn_partial_add|multi=" << (a->isMultiEntry() ? 1 : 0) << '\n';
      std::ostringstream p2;
      a->getMapEntry(3)->printEntry(p2);
      std::cout << "case=dyn_print_partial|" << p2.str();
      scope->remMaps(a);			// database.cc:2134 wholeCount = 0
      std::cout << "case=dyn_removed|multi=" << (a->isMultiEntry() ? 1 : 0) << '\n';
      scope->addDyn(a, 0, 0x1238, 0, 4, empty);	// fresh whole after reset
      std::cout << "case=dyn_readd|multi=" << (a->isMultiEntry() ? 1 : 0) << '\n';
      delete scope;
    }

    // ---- multiEntrySet iteration order (database.hh:813, 865-866;
    //      SymbolCompareName database.hh:358-373) ----
    {
      FixtureScope *scope = new FixtureScope(131, "order", &arch);
      // Insertion order deliberately scrambled vs. name order; the
      // duplicate "alpha" gets nameDedup 1 from insertNameTree
      // (database.cc:2712-2727) automatically.
      FixtureSymbol *zeta = scope->addRaw("zeta", itype);
      FixtureSymbol *alpha = scope->addRaw("alpha", itype);
      FixtureSymbol *mid = scope->addRaw("mid", itype);
      FixtureSymbol *alpha2 = scope->addRaw("alpha", itype);
      FixtureSymbol *solo = scope->addRaw("solo", itype);
      uintb base = 0x1000;
      FixtureSymbol *fives[5] = { zeta, alpha, mid, alpha2, solo };
      for (int4 i = 0; i < 5; ++i) {
        // Two whole entries for the first four symbols, one for solo,
        // at distinct addresses so the two insertions never overlap.
        int4 whole = (i < 4) ? 2 : 1;
        for (int4 j = 0; j < whole; ++j)
          scope->addMapPoint(fives[i], Address(ram, base + 0x10 * j), Address());
        base += 0x100;
      }
      std::ostringstream names;
      int4 count = 0;
      SymbolNameTree::const_iterator iter = scope->beginMultiEntry();
      SymbolNameTree::const_iterator enditer = scope->endMultiEntry();
      for (; iter != enditer; ++iter) {
        if (count > 0) names << ',';
        FixtureSymbol *fs = (FixtureSymbol *)*iter;
        names << fs->getName() << '#' << fs->dedup();
        ++count;
      }
      std::cout << "case=multientry_order|" << names.str() << '\n';
      std::cout << "case=multientry_count|" << count << '\n';
      delete scope;
    }

    // ---- categorySanity (database.cc:1992-2018) ----
    {
      FixtureScope *scope = new FixtureScope(132, "cats", &arch);
      FixtureSymbol *s1 = scope->addRaw("s1", itype);
      FixtureSymbol *s2 = scope->addRaw("s2", itype);
      FixtureSymbol *s3 = scope->addRaw("s3", itype);
      FixtureSymbol *s4 = scope->addRaw("s4", itype);
      FixtureSymbol *s5 = scope->addRaw("s5", itype);
      scope->setCategory(s1, 1, 0);		// category 1: [s1,s2,s3]
      scope->setCategory(s2, 1, 0);
      scope->setCategory(s3, 1, 0);
      scope->setCategory(s4, 2, 0);		// category 2: [s4,s5]
      scope->setCategory(s5, 2, 0);
      std::cout << "case=cat_pre|c1=" << scope->getCategorySize(1)
                << "|c2=" << scope->getCategorySize(2) << '\n';
      scope->removeSymbol(s2);		// NULL hole at index 1 (cc:2141-2146)
      std::cout << "case=cat_null_hole|c1=" << scope->getCategorySize(1) << '\n';
      scope->categorySanity();		// condemns category 1 entirely
      std::cout << "case=cat_post|c1=" << scope->getCategorySize(1)
                << "|c2=" << scope->getCategorySize(2)
                << "|s1=" << s1->getCategory()
                << "|s3=" << s3->getCategory()
                << "|s4=" << s4->getCategory()
                << "|s5=" << s5->getCategory() << '\n';
      delete scope;
    }

    // ---- resolveExternalRefFunction (database.cc:2362-2366) ----
    {
      FixtureScope *scope = new FixtureScope(133, "refs", &arch);
      FunctionSymbol *f = new FunctionSymbol(scope, "fn", 2);
      scope->addInternal(f);
      scope->addMapPoint(f, Address(ram, 0x1000), Address());
      // The production symboltab's resolvemap is empty (no namespace
      // scopes attached), so mapScope returns the query scope itself
      // (database.cc:3187-3188) and stackFunction starts at this scope.
      ExternRefSymbol *x = new ExternRefSymbol(scope, Address(ram, 0x1000), "printf");
      Funcdata *fd = scope->resolveExternalRefFunction(x);
      std::cout << "case=resolve_hit|name=" << fd->getName()
                << "|addr=" << hexoff(fd->getAddress().getOffset()) << '\n';
      ExternRefSymbol *x2 = new ExternRefSymbol(scope, Address(ram, 0x9000), "miss");
      Funcdata *fd2 = scope->resolveExternalRefFunction(x2);
      std::cout << "case=resolve_miss|" << (fd2 != (Funcdata *)0 ? 1 : 0) << '\n';
      delete scope;
    }

    // ---- childrenBegin/childrenEnd order (database.hh:765-766,
    //      ScopeMap map<uint8,Scope*> hh:439) ----
    {
      // Production registration path (Database::attachScope cc:2946 →
      // the private Scope::attachScope cc:857 upsert on the id-keyed
      // ScopeMap); a duplicate id re-attach is unreachable here because
      // Database::attachScope throws on the idmap insert first.
      FixtureScope *global = new FixtureScope(200, "", &arch);
      FixtureDatabase db(&arch, false);
      db.attachScope(global, (Scope *)0);
      FixtureScope *c105 = new FixtureScope(105, "c105", &arch);
      FixtureScope *c101 = new FixtureScope(101, "c101", &arch);
      FixtureScope *c103 = new FixtureScope(103, "c103", &arch);
      db.attachScope(c105, global);		// scrambled insertion order
      db.attachScope(c101, global);
      db.attachScope(c103, global);
      std::ostringstream ids;
      int4 count = 0;
      ScopeMap::const_iterator iter = global->childrenBegin();
      ScopeMap::const_iterator enditer = global->childrenEnd();
      for (; iter != enditer; ++iter) {
        if (count > 0) ids << ',';
        ids << (int4)(*iter).first;
        ++count;
      }
      std::cout << "case=children_ids|" << ids.str() << '\n';
      std::cout << "case=children_count|" << count << '\n';
    }

    // ---- printEntries multi-space order (database.cc:2791-2804) ----
    {
      FixtureScope *scope = new FixtureScope(134, "multi", &arch);
      FixtureSymbol *m1 = scope->addRaw("m1", itype);
      FixtureSymbol *m2 = scope->addRaw("m2", itype);
      FixtureSymbol *m3 = scope->addRaw("m3", itype);
      FixtureSymbol *m4 = scope->addRaw("m4", itype);
      // Interleaved ram(3)/rom(4) insertions; the walk must group by
      // ascending space index, preserving per-space insertion order.
      scope->addMapPoint(m1, Address(ram, 0x1000), Address());
      scope->addMapPoint(m2, Address(rom, 0x2000), Address());
      scope->addMapPoint(m3, Address(ram, 0x3000), Address());
      scope->addMapPoint(m4, Address(rom, 0x1000), Address());
      std::ostringstream pe;
      scope->printEntries(pe);
      std::cout << "case=printentries_multi|" << pe.str();

      FixtureScope *single = new FixtureScope(135, "onlyrom", &arch);
      FixtureSymbol *r1 = single->addRaw("r1", itype);
      FixtureSymbol *r2 = single->addRaw("r2", itype);
      single->addMapPoint(r1, Address(rom, 0x6000), Address());
      single->addMapPoint(r2, Address(rom, 0x7000), Address());
      std::ostringstream pe2;
      single->printEntries(pe2);
      std::cout << "case=printentries_single|" << pe2.str();
      delete scope;
      delete single;
    }
  }
  shutdownDecompilerLibrary();
}

} // namespace

extern "C" void module_compile_stub(void) {}

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: database_resid7_1204 <specdir> <binary>\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
  } catch (ghidra::LowlevelError &err) {
    std::cerr << "lowlevel: " << err.explain << '\n';
    return 1;
  } catch (std::exception &err) {
    std::cerr << "std: " << err.what() << '\n';
    return 1;
  }
  return 0;
}
