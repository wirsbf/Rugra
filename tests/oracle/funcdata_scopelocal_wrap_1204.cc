/*
 * Locked Ghidra 12.0.4 ScopeInternal::findOverlap wrap-domain oracle for
 * FUNCDATA-SCOPELOCALOVERFLOW-0001 / FUNCDATA-SCOPELOCAL-WRAP-0001.
 *
 * database.cc:2397 evaluates `addr.getOffset()+size-1` in the uint8
 * (uint64) modular domain: an int4 size converts by sign extension and
 * both operators wrap (C++ unsigned arithmetic). Stack-space offsets near
 * 2^64 — negative stack slots, e.g. a canary at stack -8 stored as
 * 0xfffffffffffffff8 — make the add wrap, and a size 0 query makes the
 * sub wrap one below the point. These cases pin the oracle's answers on
 * the wrap boundary, where a checked (non-modular) Rust translation traps
 * in the debug profile and a `p < first+size` containment rewrite misses
 * the record whose first+size wraps to 0.
 *
 * Cases (all queries against the REAL ScopeLocal maptable of function
 * GetStr, symbols installed through the public production path
 * Scope::addSymbol with an invalid usepoint — address-tied storage,
 * subsort (0,0)):
 *
 *   wrap_top_full       findOverlap(stack, 0xfffffffffffffff8, 8):
 *                       last = -8 + 8 - 1 wraps in uint8 domain... it does
 *                       NOT wrap: -8+8 = 0 offset 0xfffffffffffffff8 + 8
 *                       = 0x1_0000000000000000 wraps to 0, then -1 wraps
 *                       back to 0xffffffffffffffff. Answer: top8.
 *   wrap_top_last_byte  findOverlap(stack, 0xffffffffffffffff, 1):
 *                       point+size wraps to 0, -1 wraps to
 *                       0xffffffffffffffff. Answer: top8.
 *   wrap_top_from_below findOverlap(stack, 0xfffffffffffffff6, 4):
 *                       [..f6, ..f9] overlaps [..f8, ..ff]. Answer: top8.
 *   neg_size_below      findOverlap(stack, 0x1000, -8):
 *                       modular last = 0xff7 < point → null.
 *   zero_size_top       findOverlap(stack, 0xfffffffffffffff8, 0):
 *                       last = point - 1 < point → null.
 *   low_hit             findOverlap(stack, 0x104, 4): sanity that the
 *                       normal in-range path keeps answering low8.
 *   nonoverlap_above    findOverlap(stack, 0x10, 8): neither record → null.
 */

#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;

void dumpOverlap(const string &caseName, AddrSpace *spc, uintb offset,
                 int4 size, const SymbolEntry *entry)
{
  ostringstream out;
  out << "case=" << caseName << "|kind=overlap|query=0x" << std::hex
      << offset << ':' << std::dec << size << "|up=inv";
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

void runCases(Funcdata &fd)
{
  AddrSpace *stack = fd.getArch()->getStackSpace();
  TypeFactory *types = fd.getArch()->types;
  ScopeLocal *lm = fd.getScopeLocal();

  // Address-tied symbols (invalid usepoint → empty uselimit, subsort
  // (0,0), database.cc:1149-1150): top8 = the top-of-stack 8-byte record
  // [0xfffffffffffffff8, 0xffffffffffffffff], low8 = [0x100, 0x107].
  lm->addSymbol("top8", types->getBase(8, TYPE_INT),
                Address(stack, 0xfffffffffffffff8ULL), Address());
  lm->addSymbol("low8", types->getBase(8, TYPE_INT),
                Address(stack, 0x100), Address());

  dumpOverlap("wrap_top_full", stack, 0xfffffffffffffff8ULL, 8,
              lm->findOverlap(Address(stack, 0xfffffffffffffff8ULL), 8));
  dumpOverlap("wrap_top_last_byte", stack, 0xffffffffffffffffULL, 1,
              lm->findOverlap(Address(stack, 0xffffffffffffffffULL), 1));
  dumpOverlap("wrap_top_from_below", stack, 0xfffffffffffffff6ULL, 4,
              lm->findOverlap(Address(stack, 0xfffffffffffffff6ULL), 4));
  dumpOverlap("neg_size_below", stack, 0x1000, -8,
              lm->findOverlap(Address(stack, 0x1000), -8));
  dumpOverlap("zero_size_top", stack, 0xfffffffffffffff8ULL, 0,
              lm->findOverlap(Address(stack, 0xfffffffffffffff8ULL), 0));
  dumpOverlap("low_hit", stack, 0x104, 4,
              lm->findOverlap(Address(stack, 0x104), 4));
  dumpOverlap("nonoverlap_above", stack, 0x10, 8,
              lm->findOverlap(Address(stack, 0x10), 8));
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
    std::cerr << "usage: funcdata_scopelocal_wrap_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "funcdata_scopelocal_wrap_1204: LowlevelError: "
              << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "funcdata_scopelocal_wrap_1204: " << error.what() << '\n';
    return 1;
  }
}
