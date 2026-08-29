/*
 * FUNCDATA-CANONICAL-ARCH-0001: locked Ghidra 12.0.4 Funcdata constructor
 * oracle.  Boots the production x86-64 SLEIGH/BFD architecture (same
 * BfdArchitecture path as the callspec_identity fixture), then constructs
 * two Funcdata objects through the real constructor
 * (funcdata.cc:34-82) and prints the constructor invariants that Rugra's
 * Funcdata::new canonical-Architecture binding restores:
 *
 *   - glb is never null: `glb = scope->getArch();` (funcdata.cc:48) runs
 *     unconditionally in the constructor initializer; there is no
 *     arch-less construction path in the oracle (verified in-fixture:
 *     fd.getArch() == scope->getArch() == &architecture, exit 1 on
 *     violation; the scope/owner identity cannot be printed on the Rugra
 *     side because Rugra's constructor has no Scope parameter yet —
 *     FUNCDATA-LOCALSCOPE-OWNERSHIP-0001 — so only the symmetric
 *     observations are printed and diffed).
 *   - the ctor consumes the constructor-time glb for the stack space
 *     (funcdata.cc:54 `AddrSpace *stackid = glb->getStackSpace();`),
 *     printed as the space name.
 *   - minLanedSize is assigned from the same glb (funcdata.cc:49) but is
 *     spec-dependent (16 on the booted x86-64 SLEIGH architecture, -1 on
 *     a spec-less default), so the raw value is not a wiring observable;
 *     the Rugra mirror asserts the wiring in-binary instead
 *     (fd.min_laned_size == glb->getMinimumLanedRegisterSize()).
 *   - SplitDatatype likewise reads the constructor-time Architecture
 *     (subflow.cc:2704-2707, default config struct|array|pointer from
 *     architecture.cc:1430-1432), but its state is private with no
 *     getters, so that observation lives in the Rugra mirror's in-binary
 *     assertions rather than the diffed stdout.
 *   - Both Funcdata share one Architecture pointer (single-database
 *     invariant), mirrored by Rugra's shared canonical instance.
 */
#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "sleigh_arch.hh"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::ostringstream;
using std::string;
using std::vector;

void runFixture(const string &specRoot, const string &binary)
{
  startDecompilerLibrary(vector<string>(1, specRoot));
  {
    ostringstream diagnostics;
    BfdArchitecture architecture(binary, "default", &diagnostics);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Scope *global = architecture.symboltab->getGlobalScope();

    // funcdata.cc:34-82: real constructor chain; nm != "" also exercises
    // the ScopeLocal attach tail (funcdata.cc:57-70).
    Address entry(architecture.getDefaultCodeSpace(), 0x1000);
    Funcdata fd("f", "f", global, entry, (FunctionSymbol *)0, 0x10);

    const Architecture *arch = fd.getArch();
    // In-fixture identity checks that the Rugra mirror cannot print
    // symmetrically (no constructor-time Scope on the Rugra side).
    if (arch == (const Architecture *)0 || arch != global->getArch() ||
        arch != (const Architecture *)&architecture ||
        fd.getScopeLocal() == (const ScopeLocal *)0) {
      cerr << "constructor invariant violated: glb != scope->getArch()"
              " or local scope missing\n";
      exit(1);
    }
    cout << "case=construct"
         << " arch_nonnull=" << (arch != (const Architecture *)0)
         << '\n';
    // minLanedSize is assigned from the same constructor-time glb
    // (funcdata.cc:49) but is spec-dependent (16 on the booted x86-64
    // SLEIGH architecture, -1 on a spec-less default), so the raw value is
    // not a wiring observable and stays out of the diffed projection.
    cout << "case=stack"
         << " space_name=" << arch->getStackSpace()->getName()
         << '\n';

    // SplitDatatype reads the same constructor-time Architecture
    // (subflow.cc:2704-2707), but all of its state is private in the
    // oracle with no getters, so the default-config split flags are not
    // printable here; the Rugra mirror asserts them in-binary instead and
    // the subflow.cc source read is the C++-side evidence.

    Address entry2(architecture.getDefaultCodeSpace(), 0x2000);
    Funcdata fd2("g", "g", global, entry2, (FunctionSymbol *)0, 0x10);
    cout << "case=share"
         << " arch_identity_shared=" << (fd2.getArch() == fd.getArch())
         << '\n';
  }
  shutdownDecompilerLibrary();
}

}  // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 2) {
    std::cerr << "usage: funcdata_canonical_arch_1204 SPEC_ROOT\n";
    return 2;
  }
  try {
    runFixture(argv[1], argv[0]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch (const DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
