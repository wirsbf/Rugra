/*
 * Locked Ghidra 12.0.4 ScopeLocal query-layer oracle for
 * SCOPELOCAL-QUERY-0001 r2.
 *
 * Discriminating cases for the entry-granular query semantics behind
 * ScopeInternal::findOverlap (database.cc:2392), ScopeInternal::findAddr
 * (database.cc:2224), ScopeInternal::findContainer (database.cc:2250) and
 * Scope::queryProperties / stackContainer (database.cc:1263, 943):
 *
 *   setup                     space indices of the live architecture — the
 *                             EntrySubsort useindex dimension
 *                             (database.hh:109) and the per-space maptable
 *                             dimension (database.cc:2227) both key on them.
 *   equal_subsort_*           two entries with an IDENTICAL range AND
 *                             subsort: the second insert's rangemap parts
 *                             bracket the first (hinted insert before the
 *                             equal element, tail insert after —
 *                             rangemap.hh:223-277), so BOTH the forward
 *                             findOverlap walk and the backward findAddr
 *                             walk answer the SECOND inserted.
 *   wide_narrow_*             the (last, subsort) cell owner vs the
 *                             exact-start descending walk; inUse is uselimit
 *                             RANGE containment (database.cc:119), not
 *                             single-address equality.
 *   multi_uselimit_*          an entry whose uselimit holds two disjoint
 *                             code ranges: the second range admits a
 *                             usepoint (subsort still from the first range);
 *                             the gap admits none.
 *   cross_space_storage       an entry stored in ram never answers a stack
 *                             query (maptable per space).
 *   multi_mapping / removal   ONE symbol with two mappings: both entries
 *                             answer their own query, removeSymbol drops
 *                             both, and a survivor keeps answering.
 *   find_container_*          smallest container wins; exact size
 *                             short-circuits; equal-size equal-subsort tie
 *                             resolves to the LAST inserted (backward walk).
 *   partial_offset_piece      a join symbol's stack piece entries carry
 *                             getOffset() != 0 and precislo/precishi
 *                             extraflags (database.cc:1156-1177).
 *   qp_*                      the three queryProperties flag branches
 *                             (database.cc:1269-1280): getAllFlags,
 *                             scope-owned mapped|addrtied(|persist)|property,
 *                             and bare property; plus the parent (global
 *                             scope) walk of stackContainer and the
 *                             constant-space short-circuit (database.cc:950).
 *   marknotmapped_window      markNotMapped removes the overlapping symbols
 *                             and splits the scope's ownership window
 *                             (varmap.cc:510-546), flipping a later
 *                             scope-only queryProperties into the
 *                             property-only branch.
 *
 * Symbols are installed through public production paths (Scope::addSymbol /
 * addMapPoint / addDynamicSymbol / SymbolEntry::setUseLimit /
 * Database::setPropertyRange / Scope::addRange / ScopeLocal::markNotMapped /
 * Scope::removeSymbol) on the real BfdArchitecture ScopeLocal of function
 * GetStr; every observable is the query return identity (symbol name, entry
 * first/last/offset, flags, answering scope).
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "funcdata.hh"
#include "libdecomp.hh"

#include <iomanip>
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

void dumpEntryQuery(const string &caseName, const char *kind, AddrSpace *spc,
                    uintb offset, int4 size, const Address &usepoint,
                    const SymbolEntry *entry)
{
  ostringstream out;
  out << "case=" << caseName << "|kind=" << kind
      << "|query=0x" << std::hex << offset << ':' << size;
  if (usepoint.isInvalid())
    out << "|up=inv";
  else
    out << "|up=0x" << std::hex << usepoint.getOffset();
  if (entry == (const SymbolEntry *)0) {
    out << "|result=null";
  }
  else {
    out << "|result=" << entry->getSymbol()->getName()
        << "|first=0x" << std::hex << entry->getFirst()
        << "|last=0x" << std::hex << entry->getLast()
        << "|off=" << std::dec << entry->getOffset()
        << "|sz=" << std::dec << entry->getSize();
  }
  std::cout << out.str() << '\n';
  std::cout.flush();
}

const char *scopeName(int4 which)
{
  switch (which) {
  case 0: return "none";
  case 1: return "this";
  case 2: return "parent";
  }
  return "?";
}

void dumpQueryProperties(const string &caseName, AddrSpace *spc, uintb offset,
                         int4 size, const Address &usepoint, SymbolEntry *entry,
                         uint4 flags, int4 answeredScope)
{
  ostringstream out;
  out << "case=" << caseName << "|kind=qp"
      << "|query=0x" << std::hex << offset << ':' << size;
  if (usepoint.isInvalid())
    out << "|up=inv";
  else
    out << "|up=0x" << std::hex << usepoint.getOffset();
  if (entry == (SymbolEntry *)0) {
    out << "|result=null";
  }
  else {
    out << "|result=" << entry->getSymbol()->getName()
        << "|first=0x" << std::hex << entry->getFirst()
        << "|last=0x" << std::hex << entry->getLast()
        << "|off=" << std::dec << entry->getOffset();
  }
  out << "|flags=0x" << std::hex << flags
      << "|scope=" << scopeName(answeredScope);
  std::cout << out.str() << '\n';
  std::cout.flush();
}

// One queryProperties observation. Every observable comes from the REAL
// Scope::queryProperties (database.cc:1263) — entry identity and flags are
// its return value; the answering-scope field is derived from that return:
// an entry's owning scope, else the persist bit (only the global parent's
// scope-only branch sets it, database.cc:1274-1275), else the
// mapped|addrtied bits of a scope-only answer, else nothing answered.
struct QpResult {
  SymbolEntry *entry;
  uint4 flags;
  int4 answeredScope; // 0 none, 1 this, 2 parent
};

QpResult queryPropertiesObserved(ScopeLocal *lm, const Address &addr,
                                 int4 size, const Address &usepoint,
                                 Architecture *glb)
{
  QpResult res;
  res.entry = lm->queryProperties(addr, size, usepoint, res.flags);
  if (res.entry != (SymbolEntry *)0) {
    res.answeredScope =
        (res.entry->getSymbol()->getScope() == (const Scope *)lm) ? 1 : 2;
    return res;
  }
  if ((res.flags & Varnode::persist) != 0) {
    res.answeredScope = 2;
    return res;
  }
  if ((res.flags & (Varnode::mapped | Varnode::addrtied)) ==
      (Varnode::mapped | Varnode::addrtied)) {
    res.answeredScope = 1;
    return res;
  }
  res.answeredScope = 0;
  return res;
}

void runCases(Funcdata &fd)
{
  AddrSpace *stack = fd.getArch()->getStackSpace();
  AddrSpace *code = fd.getArch()->getDefaultCodeSpace();
  AddrSpace *unique = fd.getArch()->getUniqueSpace();
  AddrSpace *constspc = fd.getArch()->getConstantSpace();
  TypeFactory *types = fd.getArch()->types;
  ScopeLocal *lm = fd.getScopeLocal();
  Scope *globals = fd.getArch()->symboltab->getGlobalScope();

  // setup: the EntrySubsort useindex dimension and the per-space maptable
  // dimension both key on these live indices.
  {
    ostringstream out;
    out << "case=setup|const_index=" << std::dec << constspc->getIndex()
        << "|ram_index=" << code->getIndex()
        << "|stack_index=" << stack->getIndex()
        << "|unique_index=" << unique->getIndex();
    std::cout << out.str() << '\n';
    std::cout.flush();
  }

  // equal_subsort: two entries with identical range AND identical subsort.
  lm->addSymbol("first_es", types->getBase(8, TYPE_INT),
                Address(stack, 0x300), Address(code, 0x1000));
  lm->addSymbol("second_es", types->getBase(8, TYPE_INT),
                Address(stack, 0x300), Address(code, 0x1000));
  dumpEntryQuery("equal_subsort_overlap", "overlap", stack, 0x302, 2,
                 Address(), lm->findOverlap(Address(stack, 0x302), 2));
  dumpEntryQuery("equal_subsort_findaddr", "findaddr", stack, 0x300, 8,
                 Address(code, 0x1000),
                 lm->findAddr(Address(stack, 0x300), Address(code, 0x1000)));

  // wide/narrow double order: wide [0x320,0x32f] uselimit [0x1100,0x11ff]
  // (subsort (3,0x1100)), narrow [0x328,0x32b] uselimit [0x1000,0x10ff]
  // (subsort (3,0x1000)). The shared cell [0x328,0x32b] answers NARROW —
  // the EntrySubsort minimum — even though wide was inserted first and has
  // the smaller start.
  lm->addSymbol("wide", types->getBase(16, TYPE_INT),
                Address(stack, 0x320), Address(code, 0x1100));
  {
    Symbol *sym = lm->findAddr(Address(stack, 0x320), Address(code, 0x1100))->getSymbol();
    RangeList ul;
    ul.insertRange(code, 0x1100, 0x11ff);
    sym->getMapEntry(0)->setUseLimit(ul);
  }
  lm->addSymbol("narrow", types->getBase(4, TYPE_INT),
                Address(stack, 0x328), Address(code, 0x1000));
  {
    Symbol *sym = lm->findAddr(Address(stack, 0x328), Address(code, 0x1000))->getSymbol();
    RangeList ul;
    ul.insertRange(code, 0x1000, 0x10ff);
    sym->getMapEntry(0)->setUseLimit(ul);
  }
  dumpEntryQuery("wide_narrow_overlap", "overlap", stack, 0x329, 2,
                 Address(), lm->findOverlap(Address(stack, 0x329), 2));
  // The wide-only cell [0x320,0x327] answers wide.
  dumpEntryQuery("wide_narrow_overlap_wide_cell", "overlap", stack, 0x322, 2,
                 Address(), lm->findOverlap(Address(stack, 0x322), 2));
  // Mid-range usepoint of narrow's uselimit: inUse is RANGE containment.
  dumpEntryQuery("wide_narrow_findaddr_midrange", "findaddr", stack, 0x328, 4,
                 Address(code, 0x1050),
                 lm->findAddr(Address(stack, 0x328), Address(code, 0x1050)));
  // A usepoint inside wide's uselimit admits wide at its own start.
  dumpEntryQuery("wide_narrow_findaddr_wide_use", "findaddr", stack, 0x320, 4,
                 Address(code, 0x1150),
                 lm->findAddr(Address(stack, 0x320), Address(code, 0x1150)));
  // A usepoint before wide's uselimit starts admits nothing at 0x320.
  dumpEntryQuery("wide_narrow_findaddr_nouse", "findaddr", stack, 0x320, 4,
                 Address(code, 0x1050),
                 lm->findAddr(Address(stack, 0x320), Address(code, 0x1050)));

  // multi_uselimit: "spread" [0x340,0x347] with two disjoint code ranges.
  lm->addSymbol("spread", types->getBase(8, TYPE_INT),
                Address(stack, 0x340), Address(code, 0x1000));
  {
    Symbol *sym = lm->findAddr(Address(stack, 0x340), Address(code, 0x1000))->getSymbol();
    RangeList ul;
    ul.insertRange(code, 0x1000, 0x100f);
    ul.insertRange(code, 0x2000, 0x200f);
    sym->getMapEntry(0)->setUseLimit(ul);
  }
  dumpEntryQuery("multi_uselimit_second_range", "findaddr", stack, 0x340, 8,
                 Address(code, 0x2005),
                 lm->findAddr(Address(stack, 0x340), Address(code, 0x2005)));
  dumpEntryQuery("multi_uselimit_gap", "findaddr", stack, 0x340, 8,
                 Address(code, 0x1500),
                 lm->findAddr(Address(stack, 0x340), Address(code, 0x1500)));

  // cross_space_storage: an entry in ram never answers a stack query.
  lm->addSymbol("ramsym", types->getBase(8, TYPE_INT),
                Address(code, 0x4000), Address());
  dumpEntryQuery("cross_space_stack_query", "overlap", stack, 0x4000, 8,
                 Address(), lm->findOverlap(Address(stack, 0x4000), 8));
  dumpEntryQuery("cross_space_ram_query", "overlap", code, 0x4002, 4,
                 Address(), lm->findOverlap(Address(code, 0x4002), 4));

  // multi_mapping: one symbol, two mappings; then removal of both.
  SymbolEntry *two_e1 = lm->addSymbol("two", types->getBase(4, TYPE_INT),
                                      Address(stack, 0x500), Address());
  lm->addMapPoint(two_e1->getSymbol(), Address(stack, 0x510), Address());
  lm->addSymbol("third", types->getBase(4, TYPE_INT),
                Address(stack, 0x520), Address());
  dumpEntryQuery("multi_mapping_first", "overlap", stack, 0x501, 2,
                 Address(), lm->findOverlap(Address(stack, 0x501), 2));
  dumpEntryQuery("multi_mapping_second", "overlap", stack, 0x513, 2,
                 Address(), lm->findOverlap(Address(stack, 0x513), 2));
  lm->removeSymbol(two_e1->getSymbol());
  dumpEntryQuery("remove_requery_first", "overlap", stack, 0x501, 2,
                 Address(), lm->findOverlap(Address(stack, 0x501), 2));
  dumpEntryQuery("remove_requery_second", "overlap", stack, 0x513, 2,
                 Address(), lm->findOverlap(Address(stack, 0x513), 2));
  dumpEntryQuery("remove_requery_survivor", "overlap", stack, 0x522, 2,
                 Address(), lm->findOverlap(Address(stack, 0x522), 2));

  // find_container: smallest container, exact-size break, equal tie.
  lm->addSymbol("bigc", types->getBase(16, TYPE_INT),
                Address(stack, 0x600), Address());
  lm->addSymbol("smallc", types->getBase(4, TYPE_INT),
                Address(stack, 0x604), Address());
  {
    QpResult r = queryPropertiesObserved(lm, Address(stack, 0x605), 2,
                                         Address(), fd.getArch());
    dumpQueryProperties("find_container_smallest", stack, 0x605, 2, Address(),
                        r.entry, r.flags, r.answeredScope);
  }
  lm->addSymbol("tieA", types->getBase(8, TYPE_INT),
                Address(stack, 0x620), Address());
  lm->addSymbol("tieB", types->getBase(8, TYPE_INT),
                Address(stack, 0x620), Address());
  {
    QpResult r = queryPropertiesObserved(lm, Address(stack, 0x622), 4,
                                         Address(), fd.getArch());
    dumpQueryProperties("find_container_equal_tie", stack, 0x622, 4, Address(),
                        r.entry, r.flags, r.answeredScope);
  }

  // partial_offset_piece: a join symbol's stack pieces carry getOffset()!=0
  // and precislo/precishi extraflags (database.cc:1156-1177). Pieces are
  // listed most-significant first (higher stack address on x86 LE).
  {
    vector<VarnodeData> pieces;
    VarnodeData hi;
    hi.space = stack;
    hi.offset = 0x644;
    hi.size = 4;
    VarnodeData lo;
    lo.space = stack;
    lo.offset = 0x640;
    lo.size = 4;
    pieces.push_back(hi);
    pieces.push_back(lo);
    JoinRecord *rec = fd.getArch()->findAddJoin(pieces, 0);
    lm->addSymbol("piecesym", types->getBase(8, TYPE_INT),
                  rec->getUnified().getAddr(), Address());
  }
  {
    QpResult r = queryPropertiesObserved(lm, Address(stack, 0x645), 2,
                                         Address(), fd.getArch());
    dumpQueryProperties("partial_offset_piece_hi", stack, 0x645, 2, Address(),
                        r.entry, r.flags, r.answeredScope);
  }

  // qp_local_symbol: the answering entry's getAllFlags (typelock folded in).
  lm->addSymbol("locked", types->getBase(4, TYPE_INT),
                Address(stack, 0x100), Address());
  lm->setAttribute(lm->findOverlap(Address(stack, 0x100), 4)->getSymbol(),
                   Varnode::typelock);
  {
    QpResult r = queryPropertiesObserved(lm, Address(stack, 0x102), 2,
                                         Address(), fd.getArch());
    dumpQueryProperties("qp_local_symbol", stack, 0x102, 2, Address(),
                        r.entry, r.flags, r.answeredScope);
  }

  // qp_scope_only / marknotmapped_window: the local scope owns [0x900,0x9ff],
  // a plain victim symbol sits inside, and a readonly property range covers
  // it. The victim is installed BEFORE the property range so the addMap
  // property fold (database.cc:1153) never contaminates its symbol flags;
  // the property is then observable only through the query-time getProperty
  // of the scope-only / property-only branches.
  fd.getArch()->symboltab->addRange(lm, stack, 0x900, 0x9ff);
  lm->addSymbol("victim", types->getBase(4, TYPE_INT),
                Address(stack, 0x900), Address());
  {
    Range ro(stack, 0x900, 0x9ff);
    fd.getArch()->symboltab->setPropertyRange(Varnode::readonly, ro);
  }
  {
    QpResult r = queryPropertiesObserved(lm, Address(stack, 0x902), 1,
                                         Address(), fd.getArch());
    dumpQueryProperties("qp_scope_symbol_victim", stack, 0x902, 1, Address(),
                        r.entry, r.flags, r.answeredScope);
  }
  lm->markNotMapped(stack, 0x900, 4, false);
  {
    QpResult r = queryPropertiesObserved(lm, Address(stack, 0x902), 1,
                                         Address(), fd.getArch());
    dumpQueryProperties("marknotmapped_window", stack, 0x902, 1, Address(),
                        r.entry, r.flags, r.answeredScope);
  }
  // Still inside the (now split) owned window: scope-only branch.
  {
    QpResult r = queryPropertiesObserved(lm, Address(stack, 0x910), 1,
                                         Address(), fd.getArch());
    dumpQueryProperties("qp_scope_only_property", stack, 0x910, 1, Address(),
                        r.entry, r.flags, r.answeredScope);
  }

  // qp_parent_symbol: the global scope's symbol answers through the local
  // scope's query (persist set by addMap, database.cc:1131-1132).
  globals->addSymbol("gpar", types->getBase(8, TYPE_INT),
                     Address(code, 0x7f001000), Address());
  {
    QpResult r = queryPropertiesObserved(lm, Address(code, 0x7f001002), 2,
                                         Address(), fd.getArch());
    dumpQueryProperties("qp_parent_symbol", code, 0x7f001002, 2, Address(),
                        r.entry, r.flags, r.answeredScope);
  }
  // qp_none: unique space — no symbol, no scope ownership anywhere.
  {
    QpResult r = queryPropertiesObserved(lm, Address(unique, 0x9000), 1,
                                         Address(), fd.getArch());
    dumpQueryProperties("qp_none", unique, 0x9000, 1, Address(),
                        r.entry, r.flags, r.answeredScope);
  }
  // qp_constant: constant addresses never enter a scope (database.cc:950).
  {
    QpResult r = queryPropertiesObserved(lm, Address(constspc, 0x10), 1,
                                         Address(), fd.getArch());
    dumpQueryProperties("qp_constant", constspc, 0x10, 1, Address(),
                        r.entry, r.flags, r.answeredScope);
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
      throw std::runtime_error("runtime architecture/compiler drifted: " +
                               architecture.archid);
    runCases(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: scopelocal_query_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "scopelocal_query_1204: LowlevelError: "
              << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "scopelocal_query_1204: " << error.what() << '\n';
    return 1;
  }
}
