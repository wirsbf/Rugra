/*
 * Locked Ghidra 12.0.4 oracle for DATABASE-SCOPE-TREE-FIXTURE-0001
 * (MIGW1-DATABASE-0005 phase 2).
 *
 * Exercises the Scope name/tree query surface Rust-ized in
 * src/database.rs under the same anchors:
 *
 *   Scope::hashScopeName           database.cc:880-895
 *   Scope::resolveScope            database.cc:1315-1345
 *   Scope::isSubScope              database.cc:1432-1441
 *   Scope::getFullName             database.cc:1443-1454
 *   Scope::getScopePath            database.cc:1458-1474
 *   Scope::findDistinguishingScope database.cc:1481-1504
 *   Symbol::getResolutionDepth     database.cc:323-360
 *   ScopeInternal::isNameUsed      database.cc:2417-2432
 *   Scope::overrideSizeLockType    database.cc:1387-1397
 *   Scope::resetSizeLockType       database.cc:1402-1408
 *   Scope::attachScope             database.cc:857-862
 *   Scope::detachScope             database.cc:866-872
 *   Database::clearReferences      database.cc:2893-2904
 *   Database::adjustCaches         database.cc:2975-2982
 *
 * All projections are id/name/size/message-level: pointer values are
 * never printed.  Tree ids are chosen explicitly so both comparands see
 * identical uniqueIds.  Data-type identity prints as name+size (never
 * the raw metatype enum: Ghidra and Rust order their metatype enums
 * differently).
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
/// factory, spec-derived sizes, and the default spaces are all real.
/// (The scope trees below deliberately attach to STANDALONE
/// FixtureDatabases so the production symbol table is never mutated.)
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
  using Symbol::checkSizeTypeLock;
};

class FixtureScope final : public ScopeInternal {
public:
  FixtureScope(uint8 id, const string &name, Architecture *arch)
    : ScopeInternal(id, name, arch) {}

  static int4 countChildren(const Scope *scope) {
    int4 count = 0;
    ScopeMap::const_iterator iter = scope->childrenBegin();
    ScopeMap::const_iterator enditer = scope->childrenEnd();
    for (; iter != enditer; ++iter)
      ++count;
    return count;
  }
  FixtureSymbol *addRaw(const string &nm, Datatype *ct) {
    FixtureSymbol *sym = new FixtureSymbol(this, nm, ct);
    addSymbolInternal(sym);
    return sym;
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

string hex64(uint8 v)
{
  std::ostringstream s;
  s << std::hex << std::setw(16) << std::setfill('0') << v;
  return s.str();
}

// database.cc:880-895 — hashScopeName is a Scope private whose raw
// value is observable through its production caller
// Database::findCreateScopeFromSymbolName (database.cc:3165: `uint8
// nameId = Scope::hashScopeName(start->uniqueId, scopename)`): the id
// of the scope that call CREATES under a pinned parent id IS the hash.
Scope *hashViaProduction(FixtureDatabase &db, Scope *parent, const string &nm)
{
  string base;
  return db.findCreateScopeFromSymbolName(nm + "::tail", "::", base, parent);
}

void emitHashCases(FixtureArchitecture &arch)
{
  // The crc cascade, including the signed-char feed for name bytes
  // >= 0x80 (cc:887-890: `uint4 val = nm[i]` reads a signed char, so
  // high bytes sign-extend into the uint4).
  FixtureScope *global = new FixtureScope(100, "", &arch);
  FixtureDatabase db(&arch, true);
  db.attachScope(global, (Scope *)0);
  FixtureScope *big = new FixtureScope(0x1122334455667788ULL, "p", &arch);
  db.attachScope(big, global);
  FixtureScope *feed = new FixtureScope(0xfedcba9876543210ULL, "q", &arch);
  db.attachScope(feed, big);

  std::cout << "case=hash_name_zero_alpha|" << hex64(hashViaProduction(db, global, "alpha")->getId()) << '\n';
  std::cout << "case=hash_name_mixed|" << hex64(hashViaProduction(db, big, "a")->getId()) << '\n';
  // NOTE: the empty-name hash input has no production observable:
  // findCreateScopeFromSymbolName routes "" through attachScope, which
  // rejects empty non-global scope names (database.cc:2958-2959), and
  // no other production caller exposes the raw hash.  The Rust unit
  // test pins value determinism for that input only.
  // The signed-char feed is exercised with the two high bytes \xc3\xbf
  // (both >= 0x80, so both sign-extend into the uint4, cc:887-890):
  // the Rust comparand's name channel is a UTF-8 &str, and a lone \xff
  // byte is not representable there — the bilateral pair must feed the
  // same byte sequence on both sides.
  std::cout << "case=hash_name_signed_byte|" << hex64(hashViaProduction(db, global, "\xc3\xbf")->getId()) << '\n';
  std::cout << "case=hash_name_signed_bytes|" << hex64(hashViaProduction(db, feed, "a\xc2\x80z")->getId()) << '\n';
  // The empty-name case left an ""-named child under global (id =
  // hash(100,"")); clean up deterministically so later cases see the
  // same tree.
}

// global(100,"") :: a(101) :: b(102); a :: c(103)
struct Tree {
  FixtureDatabase *db;
  FixtureScope *global, *a, *b, *c;
};

Tree makeTree(FixtureArchitecture &arch, bool idByName = false)
{
  FixtureScope *global = new FixtureScope(100, "", &arch);
  FixtureScope *a = new FixtureScope(101, "a", &arch);
  FixtureScope *b = new FixtureScope(102, "b", &arch);
  FixtureScope *c = new FixtureScope(103, "c", &arch);
  FixtureDatabase *db = new FixtureDatabase(&arch, idByName);
  db->attachScope(global, (Scope *)0);
  db->attachScope(a, global);
  db->attachScope(b, a);
  db->attachScope(c, a);
  Tree t = {db, global, a, b, c};
  return t;
}

void emitResolveCases(FixtureArchitecture &arch)
{
  Tree t = makeTree(arch, true); // idByName: the hash-strategy cases need it
  FixtureDatabase *db = t.db;
  FixtureScope *global = t.global, *a = t.a, *b = t.b;

  // database.cc:1336-1343 — linear scan branch.
  std::cout << "case=resolve_linear_hit|" << (global->resolveScope("a", false) == a ? "101" : "other") << '\n';
  std::cout << "case=resolve_linear_miss|" << (global->resolveScope("zzz", false) == (Scope *)0 ? "null" : "nonnull") << '\n';
  std::cout << "case=resolve_linear_nested|" << (a->resolveScope("b", false) == b ? "102" : "other") << '\n';

  // database.cc:1326-1334 — decimal direct id branch.  Child 101 is
  // addressable by the string "101"; trailing junk parses the prefix
  // (istringstream >> semantics).
  std::cout << "case=resolve_decimal_hit|" << (global->resolveScope("101", false) == a ? "101" : "other") << '\n';
  std::cout << "case=resolve_decimal_prefix|" << (global->resolveScope("101x", false) == a ? "101" : "other") << '\n';
  std::cout << "case=resolve_decimal_miss|" << (global->resolveScope("999", false) == (Scope *)0 ? "null" : "nonnull") << '\n';

  // database.cc:1318-1325 — hash strategy branch: child keyed by the
  // hash of its name under the parent id, returned only on name match.
  Scope *hashed = hashViaProduction(*db, global, "hashed");
  uint8 key = hashed->getId();
  std::cout << "case=resolve_hash_hit|" << (global->resolveScope("hashed", true) == hashed ? hex64(key) : "other") << '\n';
  std::cout << "case=resolve_hash_name_mismatch|" << (global->resolveScope("other", true) == (Scope *)0 ? "null" : "nonnull") << '\n';
  std::cout << "case=resolve_hash_absent|" << (global->resolveScope("nokey", true) == (Scope *)0 ? "null" : "nonnull") << '\n';

  delete db; // deletes the whole tree recursively
}

void emitTreeCases(FixtureArchitecture &arch)
{
  Tree t = makeTree(arch);
  FixtureDatabase *db = t.db;
  FixtureScope *global = t.global, *a = t.a, *b = t.b, *c = t.c;

  // database.cc:1443-1454.
  std::cout << "case=fullname_b|" << b->getFullName() << '\n';
  std::cout << "case=fullname_a|" << a->getFullName() << '\n';
  std::cout << "case=fullname_global_len|" << global->getFullName().size() << '\n';

  // database.cc:1458-1474 — path includes global and self.
  {
    vector<const Scope *> path;
    b->getScopePath(path);
    std::cout << "case=scopespath_b|";
    for (int4 i = 0; i < path.size(); ++i) {
      if (i != 0)
        std::cout << ",";
      std::cout << path[i]->getId();
    }
    std::cout << '\n';
  }

  // database.cc:1432-1441.
  std::cout << "case=issub_self|" << (b->isSubScope(b) ? 1 : 0) << '\n';
  std::cout << "case=issub_parent|" << (b->isSubScope(a) ? 1 : 0) << '\n';
  std::cout << "case=issub_global|" << (b->isSubScope(global) ? 1 : 0) << '\n';
  std::cout << "case=issub_reverse|" << (a->isSubScope(b) ? 1 : 0) << '\n';
  std::cout << "case=issub_global_of_child|" << (global->isSubScope(b) ? 1 : 0) << '\n';

  // database.cc:1481-1504.
  std::cout << "case=distinguish_same|" << (b->findDistinguishingScope(b) == (const Scope *)0 ? "null" : "nonnull") << '\n';
  std::cout << "case=distinguish_parent|" << (b->findDistinguishingScope(a) == b ? "102" : "other") << '\n';
  std::cout << "case=distinguish_child|" << (a->findDistinguishingScope(b) == (const Scope *)0 ? "null" : "nonnull") << '\n';
  std::cout << "case=distinguish_sibling|" << (b->findDistinguishingScope(c) == b ? "102" : "other") << '\n';
  std::cout << "case=distinguish_sibling_rev|" << (c->findDistinguishingScope(b) == c ? "103" : "other") << '\n';
  std::cout << "case=distinguish_from_global|" << (b->findDistinguishingScope(global) == a ? "101" : "other") << '\n';
  std::cout << "case=distinguish_global_from|" << (global->findDistinguishingScope(b) == (const Scope *)0 ? "null" : "nonnull") << '\n';

  // database.cc:857-862 / 866-872 — attach/detach observables via the
  // production registration path (Database::attachScope →
  // Scope::attachScope; Database::deleteScope → clearReferences +
  // Scope::detachScope).
  FixtureScope *extra = new FixtureScope(200, "extra", &arch);
  db->attachScope(extra, a);
  std::cout << "case=attach_child_count|" << FixtureScope::countChildren(a) << '\n';
  std::cout << "case=attach_child_parent_alias|" << (extra->getParent() == a ? 1 : 0) << '\n';
  db->deleteScope(extra);
  std::cout << "case=detach_child_count|" << FixtureScope::countChildren(a) << '\n';

  delete t.db;
}

void emitResolutionDepthCases(FixtureArchitecture &arch)
{
  // global :: ns(110) :: inner(111); symbol "x" in ns.
  TypeBase integerType(4, TYPE_INT, "fixture_i32");
  FixtureScope *global = new FixtureScope(100, "", &arch);
  FixtureScope *ns = new FixtureScope(110, "ns", &arch);
  FixtureScope *inner = new FixtureScope(111, "inner", &arch);
  FixtureDatabase *db = new FixtureDatabase(&arch, false);
  db->attachScope(global, (Scope *)0);
  db->attachScope(ns, global);
  db->attachScope(inner, ns);
  FixtureSymbol *x = ns->addRaw("x", &integerType);

  // database.cc:326 — same scope.
  std::cout << "case=resdepth_same|" << x->getResolutionDepth(ns) << '\n';
  // database.cc:327-335 — null use scope: full path minus global.
  std::cout << "case=resdepth_null|" << x->getResolutionDepth((const Scope *)0) << '\n';
  // database.cc:343-358 — ancestor use, no collision: ns is an
  // ancestor of inner (findDistinguishingScope → null) and "x" is not
  // used in inner.
  std::cout << "case=resdepth_ancestor|" << x->getResolutionDepth(inner) << '\n';
  // Memo repeat (database.hh:190-191): the second query with the same
  // use scope short-circuits and must return the same value.
  std::cout << "case=resdepth_memo_repeat|" << x->getResolutionDepth(inner) << '\n';

  // Collision (database.cc:357-358): a same-named symbol in the use
  // scope forces one more distinguishing name.  Fresh symbol, because
  // the memo would otherwise answer stale.
  FixtureSymbol *x2 = ns->addRaw("x2", &integerType);
  inner->addRaw("x2", &integerType);
  std::cout << "case=resdepth_collision|" << x2->getResolutionDepth(inner) << '\n';

  // Sibling use scope: quick check 4 (same parents) → distinguish ns.
  FixtureScope *sib = new FixtureScope(112, "sib", &arch);
  db->attachScope(sib, global);
  std::cout << "case=resdepth_sibling|" << x->getResolutionDepth(sib) << '\n';

  delete db;
}

void emitSizeLockCases(FixtureArchitecture &arch)
{
  TypeFactory *types = arch.types;
  Datatype *unknown4 = types->getBase(4, TYPE_UNKNOWN);
  Datatype *int4 = types->getBase(4, TYPE_INT);
  Datatype *int8 = types->getBase(8, TYPE_INT);
  FixtureScope *global = new FixtureScope(100, "", &arch);
  FixtureDatabase *db = new FixtureDatabase(&arch, false);
  db->attachScope(global, (Scope *)0);

  // A size-locked symbol: typelock + unknown type (size_typelock on).
  FixtureSymbol *locked = global->addRaw("locked", unknown4);
  global->setAttribute(locked, Varnode::typelock);
  locked->checkSizeTypeLock();
  std::cout << "case=sizelock_flag|" << (locked->isSizeTypeLocked() ? 1 : 0) << '\n';

  // database.cc:1387-1397 — same-size override succeeds.
  try {
    global->overrideSizeLockType(locked, int4);
    std::cout << "case=override_ok|ok|name=" << locked->getType()->getName()
              << "|size=" << locked->getType()->getSize() << '\n';
  } catch (LowlevelError &err) {
    std::cout << "case=override_ok|error:" << err.explain << '\n';
  }
  // Different size throws with the exact message.
  try {
    global->overrideSizeLockType(locked, int8);
    std::cout << "case=override_size_mismatch|no-throw" << '\n';
  } catch (LowlevelError &err) {
    std::cout << "case=override_size_mismatch|" << err.explain << '\n';
  }
  // database.cc:1402-1408 — reset restores the unknown base of the
  // same size.
  global->resetSizeLockType(locked);
  std::cout << "case=reset_sizelock|name=" << locked->getType()->getName()
            << "|size=" << locked->getType()->getSize() << '\n';
  // Reset of an already-unknown type is a no-op (cc:1405).
  global->resetSizeLockType(locked);
  std::cout << "case=reset_sizelock_idempotent|name=" << locked->getType()->getName() << '\n';

  // Not size-locked symbol → the other exact message.
  FixtureSymbol *plain = global->addRaw("plain", int4);
  try {
    global->overrideSizeLockType(plain, int4);
    std::cout << "case=override_not_locked|no-throw" << '\n';
  } catch (LowlevelError &err) {
    std::cout << "case=override_not_locked|" << err.explain << '\n';
  }

  delete db;
}

void emitClearReferenceCases(FixtureArchitecture &arch)
{
  AddrSpace *ram = makeRam();
  Tree t = makeTree(arch);
  FixtureDatabase *db = t.db;
  FixtureScope *global = t.global, *a = t.a, *b = t.b;

  // Ownership ranges so the resolvemap has entries: a owns
  // [0x1000,0x1fff] (Database::setRange → fillResolve).
  RangeList rlist;
  rlist.insertRange(ram, 0x1000, 0x1fff);
  db->setRange(a, rlist);
  Address probe(ram, 0x1800);
  std::cout << "case=mapscope_owner|" << (db->mapScope(global, probe, Address()) == a ? "101" : "other") << '\n';

  // database.cc:2893-2904 — clearReferences is a Database private whose
  // recursion (children first, then idmap.erase, then clearResolve for
  // non-global scopes) is observable through its production caller
  // Database::deleteScope (database.cc:2988).  b first: b owns no
  // ranges, so only the idmap entry goes; then a: the recursion covers
  // c and removes a's resolvemap ranges.
  db->deleteScope(b);
  std::cout << "case=clearref_resolve_b|" << (db->resolveScope(102) == (Scope *)0 ? "null" : "nonnull") << '\n';
  db->deleteScope(a);
  std::cout << "case=clearref_resolve_a|" << (db->resolveScope(101) == (Scope *)0 ? "null" : "nonnull") << '\n';
  std::cout << "case=clearref_resolve_c|" << (db->resolveScope(103) == (Scope *)0 ? "null" : "nonnull") << '\n';
  std::cout << "case=clearref_mapscope_default|" << (db->mapScope(global, probe, Address()) == global ? "global" : "other") << '\n';

  delete db;
  delete ram;
}

void emitAdjustCachesCase(FixtureArchitecture &arch)
{
  // database.cc:2975-2982 — every scope in the idmap adjusts; with the
  // stub architecture this is observable as a no-throw sweep whose
  // scope membership is unchanged.
  Tree t = makeTree(arch);
  t.db->adjustCaches();
  std::cout << "case=adjust_caches|ok|scopes=" << (t.db->resolveScope(100) != 0) << (t.db->resolveScope(101) != 0) << (t.db->resolveScope(102) != 0) << (t.db->resolveScope(103) != 0) << '\n';
  delete t.db;
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
    emitHashCases(arch);
    emitResolveCases(arch);
    emitTreeCases(arch);
    emitResolutionDepthCases(arch);
    emitSizeLockCases(arch);
    emitClearReferenceCases(arch);
    emitAdjustCachesCase(arch);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: database_scope_tree_1204 SPEC_ROOT BINARY" << std::endl;
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  } catch (const LowlevelError &error) {
    std::cerr << "database_scope_tree_1204: LowlevelError: " << error.explain << std::endl;
    return 1;
  } catch (const RecovError &error) {
    std::cerr << "database_scope_tree_1204: RecovError: " << error.explain << std::endl;
    return 1;
  } catch (const std::exception &error) {
    std::cerr << "database_scope_tree_1204: " << error.what() << std::endl;
    return 1;
  }
}
