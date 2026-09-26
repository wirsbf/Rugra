/*
 * CSPEC-GLOBAL-DB-0001: locked Ghidra 12.0.4 global-scope Database
 * write-path oracle (CSPEC-GLOBAL-APPLY-0001 B2 fixture).  Loads the real
 * production x86-64-gcc.cspec through a full BfdArchitecture::init (which
 * drives Architecture::parseCompilerConfig -> decodeGlobal ->
 * addToGlobalScope -> Database::addRange), then prints the Database-side
 * observations the Rust fixture must reproduce byte for byte from the
 * same cspec bytes:
 *   - DBTREE: the global scope's space-keyed ownership tree through the
 *     public Scope::printBounds (set<Range> sorted by (space index,
 *     first), one "<space>: <first hex>-<last hex>" line per range,
 *     address.cc:283/588),
 *   - QPROP: Scope::queryProperties flag folds (database.cc:1263-1281)
 *     at representative (space, offset, size) probes —
 *     ram inside the <global> range (mapped|addrtied|persist),
 *     register inside the cspec register window (same fold),
 *     register/unique outside any owned range (property-only), OTHER
 *     inside its whole-space range (fold), const (stackContainer's
 *     cc:950 isConstant bail -> property-only).
 *
 * Probe offsets in ram are confined to the pinned curl binary's sole
 * PF_W segment (vaddr 0x16c48..0x18680): the loader readonly property
 * ranges (fillinReadOnlyFromLoader) live in the R/RX segments only, so
 * both sides fold getProperty()==0 there and the observation stays on
 * the global-range fold this fixture owns.
 */
#include "bfd_arch.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "xml.hh"

#include <fstream>
#include <iostream>
#include <list>
#include <sstream>
#include <stdexcept>
#include <string>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::getline;
using std::istringstream;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

void copyFile(const string &from, const string &to)
{
  ifstream in(from.c_str(), std::ios::binary);
  if (!in)
    throw runtime_error("cannot open " + from);
  ofstream out(to.c_str(), std::ios::binary);
  out << in.rdbuf();
  if (!out)
    throw runtime_error("cannot write " + to);
}

// Private working copy of the spec set (never mutates the input
// directory): specpaths.findFile resolves by first-registered directory.
string makeWorkSpecDir(const string &specDirectory)
{
  char templatePath[] = "/tmp/cspec-global-db-work.XXXXXX";
  const char *created = ::mkdtemp(templatePath);
  if (created == (const char *)0)
    throw runtime_error("mkdtemp failed");
  const string dir(created);
  const char *names[] = {"x86.ldefs", "x86-64.pspec", "x86-64.sla", "x86-64-gcc.cspec"};
  for (int i = 0; i < 4; ++i)
    copyFile(specDirectory + "/" + names[i], dir + "/" + names[i]);
  return dir;
}

struct Probe
{
  const char *spaceName;
  uintb offset;
  int4 size;
};

void runFixture(const string &specDirectory, const string &binary)
{
  const string workDir = makeWorkSpecDir(specDirectory);
  vector<string> specPaths;
  specPaths.push_back(workDir);
  startDecompilerLibrary(specPaths);
  BfdArchitecture arch(binary, "default", &std::cerr);
  DocumentStorage documents;
  arch.init(documents);

  cout << "SCHEMA|1\n";

  // The global scope's ownership tree: Scope::printBounds (database.hh:789
  // -> RangeList::printBounds address.cc:588, per-Range address.cc:283).
  {
    const Scope *globalScope = arch.symboltab->getGlobalScope();
    ostringstream buffer;
    globalScope->printBounds(buffer);
    istringstream lines(buffer.str());
    string line;
    while (getline(lines, line)) {
      if (line == "all")
        continue;
      cout << "DBTREE|" << line << "\n";
    }
  }

  // queryProperties folds at the probe grid. flags print as 0x%08x so the
  // Varnode bit positions (addrtied=0x8000, persist=0x4000,
  // mapped=0x200000) are directly visible; the usepoint is the invalid
  // Address() (the newVarnode call-site form, funcdata_varnode.cc:148-166).
  static const Probe probes[] = {
    {"ram", 0x17000, 8},
    {"ram", 0x18000, 1},
    {"register", 0x1094, 4},
    {"register", 0x1080, 2},
    {"register", 0x1096, 2},
    {"unique", 0x100, 4},
    {"OTHER", 0x10, 1},
    {"const", 0x5, 1},
  };
  const Scope *globalScope = arch.symboltab->getGlobalScope();
  for (int4 i = 0; i < 8; ++i) {
    const Probe &probe = probes[i];
    AddrSpace *spc = arch.getSpaceByName(probe.spaceName);
    if (spc == (AddrSpace *)0)
      throw runtime_error(string("missing space: ") + probe.spaceName);
    Address addr(spc, probe.offset);
    Address usepoint;
    uint4 flags = 0;
    SymbolEntry *entry = globalScope->queryProperties(addr, probe.size, usepoint, flags);
    cout << "QPROP|" << probe.spaceName << "|0x" << std::hex << probe.offset
         << "|" << std::dec << probe.size << "|0x" << std::hex << flags
         << "|" << std::dec << (entry == (SymbolEntry *)0 ? 0 : 1) << "\n";
  }
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: cspec_global_db_1204 <spec-directory> <binary>\n";
    return 2;
  }
  try {
    runFixture(argv[1], argv[2]);
    return 0;
  }
  catch (LowlevelError &error) {
    cerr << error.explain << '\n';
  }
  catch (DecoderError &error) {
    cerr << error.explain << '\n';
  }
  catch (exception &error) {
    cerr << error.what() << '\n';
  }
  return 1;
}
