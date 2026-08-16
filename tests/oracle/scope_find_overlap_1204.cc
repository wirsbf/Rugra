/*
 * Locked Ghidra 12.0.4 ScopeInternal::findOverlap oracle for
 * SCOPE-FINDOVERLAP-KEY-0001 / SCOPE-FINDOVERLAP-DYNAMIC-0001.
 *
 * Discriminating cases for the rangemap partition-owner semantics
 * (database.cc:2392 + rangemap.hh:411-423) and the dynamic-entry
 * invisibility (database.cc:1866-1876):
 *
 *   partition_usepoint  two overlapping static symbols in one partition
 *                       unit with different first use-points: the winner
 *                       is the EntrySubsort-minimum record covering the
 *                       unit containing the query start — NOT the
 *                       minimum-start record overlapping the query
 *                       (the pre-fix Rugra behavior).
 *   addrtied_wins       an address-tied symbol (empty uselimit, minimal
 *                       subsort) versus a use-limited symbol over the
 *                       same unit: address-tied wins regardless of
 *                       insertion order.
 *   gap_query           query start is uncovered; the leftmost partition
 *                       unit starting after the query start answers if
 *                       it begins before the query end.
 *   dynamic_null        a dynamic symbol exists but never enters the
 *                       static map table: a query at its modeled stack
 *                       offset answers null.
 *   dynamic_no_shadow   a static symbol must answer even though a
 *                       dynamic symbol exists.
 *
 * Symbols are installed through public production paths
 * (Scope::addSymbol / Scope::addDynamicSymbol) on the real
 * BfdArchitecture ScopeLocal; every observable is the findOverlap return
 * identity (name, first, last, isDynamic).
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

void dumpQuery(const string &caseName, ScopeLocal *lm, AddrSpace *stack,
               uintb offset, int4 size)
{
  SymbolEntry *entry = lm->findOverlap(Address(stack, offset), size);
  ostringstream out;
  out << "case=" << caseName
      << "|query=0x" << std::hex << offset << ':' << size;
  if (entry == (SymbolEntry *)0) {
    out << "|result=null";
  }
  else {
    out << "|result=" << entry->getSymbol()->getName()
        << "|first=0x" << std::hex << entry->getFirst()
        << "|last=0x" << entry->getLast()
        << "|dyn=" << (entry->isDynamic() ? 1 : 0);
  }
  std::cout << out.str() << '\n';
  std::cout.flush();
}

void runCases(Funcdata &fd)
{
  AddrSpace *stack = fd.getArch()->getStackSpace();
  AddrSpace *code = fd.getArch()->getDefaultCodeSpace();
  TypeFactory *types = fd.getArch()->types;
  ScopeLocal *lm = fd.getScopeLocal();

  // case partition_usepoint: "wide" [0x300,0x30f] usepoint 0x1010,
  // "narrow" [0x308,0x30b] usepoint 0x1000. Query start 0x309 lands in
  // partition unit [0x308,0x30b]; both records cover it; EntrySubsort
  // (usepoint) picks "narrow". Minimum-start overlap would pick "wide".
  lm->addSymbol("wide", types->getBase(16, TYPE_INT),
                Address(stack, 0x300), Address(code, 0x1010));
  lm->addSymbol("narrow", types->getBase(4, TYPE_INT),
                Address(stack, 0x308), Address(code, 0x1000));
  dumpQuery("partition_usepoint", lm, stack, 0x309, 2);
  dumpQuery("partition_usepoint_far", lm, stack, 0x300, 2);

  // case addrtied_wins: "used" (usepoint) is inserted first so any
  // insertion-order tie-break would favor it; the address-tied "tied"
  // has the minimal subsort and must win the shared unit [0x320,0x327].
  lm->addSymbol("used", types->getBase(8, TYPE_INT),
                Address(stack, 0x320), Address(code, 0x1000));
  lm->addSymbol("tied", types->getBase(8, TYPE_INT),
                Address(stack, 0x320), Address());
  dumpQuery("addrtied_wins", lm, stack, 0x322, 4);

  // case gap_query: query starts at uncovered 0x338; the leftmost
  // partition unit intersecting [0x338,0x347] is [0x340,0x343] ("gapend").
  lm->addSymbol("gapend", types->getBase(4, TYPE_INT),
                Address(stack, 0x340), Address(code, 0x1000));
  lm->addSymbol("gapfar", types->getBase(4, TYPE_INT),
                Address(stack, 0x344), Address(code, 0x1001));
  dumpQuery("gap_query", lm, stack, 0x338, 0x10);
  // A query that ends before the first unit starts answers null.
  dumpQuery("gap_query_short", lm, stack, 0x338, 0x6);

  // case dynamic_*: dynamic symbols never enter the static map table
  // (addDynamicMapInternal pushes to dynamicentry), so a stack query at
  // offset 0 answers null and a later static symbol is not shadowed.
  lm->addDynamicSymbol("dyn", types->getBase(4, TYPE_INT),
                       Address(code, 0x1000), 0x1234);
  dumpQuery("dynamic_null", lm, stack, 0x0, 8);
  lm->addSymbol("staticfar", types->getBase(4, TYPE_INT),
                Address(stack, 0x360), Address(code, 0x1000));
  dumpQuery("dynamic_no_shadow", lm, stack, 0x360, 4);
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
    std::cerr << "usage: scope_find_overlap_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "scope_find_overlap_1204: LowlevelError: "
              << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "scope_find_overlap_1204: " << error.what() << '\n';
    return 1;
  }
}
