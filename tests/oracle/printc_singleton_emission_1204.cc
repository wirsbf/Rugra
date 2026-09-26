// PRINTC-UNMAP-SINGLETON-0001 fixture — the printc singleton emission
// family against locked Ghidra 12.0.4.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Work-package WORKPKG-UNMAP-PRINTC-0004 item coverage (bilateral, the
// directly-constructible singletons; the IR-bound checkAddressOfCast /
// pushImpliedField arms are Rust-unit-covered and registered for a
// follow-up full-IR bilateral fixture):
//
//   push_float          (printc.cc:1380-1424) — the full FloatFormat chain
//                       through a REAL BfdArchitecture translate
//                       (getFloatFormat sizes 4/8, FLOAT_UNKNOWN for the
//                       unregistered size 2), the infinity/nan sign arms,
//                       the ".0" suffix arm, and the force_scinote arm.
//   setCommentStyle     (printc.cc:2350-2361) — c/cplusplus//"/*"//"//"
//                       arms + the LowlevelError rejection, observed through
//                       emitLineComment's delimiter tokens.
//   genericFunctionName (printc.cc:3359-3366) — the printRaw digit rule at
//                       32-bit and 64-bit entry addresses.
//   emitSymbolScope     (printc.cc:233-259) — a BFD function symbol at
//                       depth 0 (the global-scope curscope fast path).
//   pushMismatchSymbol  (printc.cc:2067-2083) — the off==0 `_name` arm and
//                       the off!=0 unnamed-location arm.
//   pushTypePointerRel  (printc.hh:365-370) — the ADJ function-call token
//                       pair, completed by two trailing atoms.
//   doEmitWideCharPrefix(printc.cc:1504-1507) — the 'L' prefix on wide
//                       char constants (2-byte char type).
//
// Observation: one line per case, `case=<name>|out=<text>` with the
// emitter stream flushed per case (single-atom pushes emit immediately,
// printlanguage.cc:161-166 pushAtom empty-stack arm).
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "comment.hh"
#include "funcdata.hh"
#include "printc.hh"
#include "variable.hh"

#include <iostream>
#include <sstream>
#include <string>

namespace {

using namespace ghidra;

class FixturePrintC final : public PrintC {
public:
  FixturePrintC(Architecture *glb)
      : PrintC(glb, "printc-singleton-emission-1204") {
    // Same emitter class as the Rust fixture side (EmitNoMarkup): the
    // singleton cases observe raw token text, and the incomplete
    // pushTypePointerRel token pair cannot trip the pretty printer's
    // flush group invariant (prettyprint.cc:1200) the way the full
    // opPtrsub flow never does.
    emit = new EmitNoMarkup();
  }

  // Trampolines over the protected emission entry points.
  std::string pushFloat(uintb val, int4 sz) {
    std::ostringstream hold;
    setOutputStream(&hold);
    push_float(val, sz, syntax, (const Varnode *)0, (const PcodeOp *)0);
    emit->flush();
    return hold.str();
  }

  std::string pushFloatScinote(uintb val, int4 sz) {
    std::ostringstream hold;
    setOutputStream(&hold);
    pushMod();
    setMod(force_scinote);
    push_float(val, sz, syntax, (const Varnode *)0, (const PcodeOp *)0);
    popMod();
    emit->flush();
    return hold.str();
  }

  std::string pushMismatch(const Symbol *sym, int4 off, int4 sz,
                           const Varnode *vn) {
    std::ostringstream hold;
    setOutputStream(&hold);
    pushMismatchSymbol(sym, off, sz, vn, (const PcodeOp *)0);
    emit->flush();
    return hold.str();
  }

  std::string pushPtrRel(uintb index) {
    std::ostringstream hold;
    setOutputStream(&hold);
    pushTypePointerRel((const PcodeOp *)0);
    // Complete the function_call postsurround token with its two
    // operand atoms (the base symbol and the index integer), so the
    // pretty printer's group bookkeeping balances at flush.
    pushAtom(Atom("base", vartoken, EmitMarkup::no_color));
    push_integer(index, 4, false, syntax, (const Varnode *)0,
                 (const PcodeOp *)0);
    emit->flush();
    return hold.str();
  }

  std::string emitScopeOf(const Symbol *sym) {
    std::ostringstream hold;
    setOutputStream(&hold);
    emitSymbolScope(sym);
    emit->flush();
    return hold.str();
  }

  std::string renderComment(const std::string &style, bool &threw) {
    std::ostringstream hold;
    setOutputStream(&hold);
    threw = false;
    try {
      setCommentStyle(style);
    } catch (LowlevelError &) {
      threw = true;
      return std::string();
    }
    Address addr;
    Comment comm(Comment::user2, addr, addr, 0, "fixture body");
    emitLineComment(0, &comm);
    emit->flush();
    return hold.str();
  }

  std::string genericName(const Address &addr) {
    return genericFunctionName(addr);
  }

  std::string pushWideChar(uintb val, Datatype *ct) {
    std::ostringstream hold;
    setOutputStream(&hold);
    pushCharConstant(val, ct, syntax, (const Varnode *)0, (const PcodeOp *)0);
    emit->flush();
    return hold.str();
  }
};

} // namespace

int runCases(BfdArchitecture &architecture);

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: printc_singleton_emission_1204 SPEC_ROOT BINARY\n";
    return 2;
  }
  try {
    std::vector<std::string> specPaths;
    specPaths.push_back(argv[1]);
    startDecompilerLibrary(specPaths);
    BfdArchitecture architecture(argv[2], "default", &std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    return runCases(architecture);
  } catch (const LowlevelError &err) {
    std::cerr << "FIXTURE-LOWLEVEL: " << err.explain << '\n';
    return 3;
  } catch (const std::exception &err) {
    std::cerr << "FIXTURE-STD: " << err.what() << '\n';
    return 3;
  }
}

int runCases(BfdArchitecture &architecture) {
  FixturePrintC printer(&architecture);
  printer.initializeFromArchitecture();

  // ---- push_float (printc.cc:1380-1424) ----
  // 4-byte IEEE 754 encodings.
  std::cout << "case=float4.zero|out=" << printer.pushFloat(0x00000000, 4)
            << '\n';
  std::cout << "case=float4.negzero|out=" << printer.pushFloat(0x80000000, 4)
            << '\n';
  std::cout << "case=float4.one|out=" << printer.pushFloat(0x3f800000, 4)
            << '\n';
  std::cout << "case=float4.negone|out=" << printer.pushFloat(0xbf800000, 4)
            << '\n';
  std::cout << "case=float4.half|out=" << printer.pushFloat(0x3f000000, 4)
            << '\n';
  std::cout << "case=float4.two_integral|out=" << printer.pushFloat(0x40000000, 4)
            << '\n';
  std::cout << "case=float4.hundred_integral|out="
            << printer.pushFloat(0x42c80000, 4) << '\n';
  std::cout << "case=float4.pi|out=" << printer.pushFloat(0x40490fdb, 4)
            << '\n';
  std::cout << "case=float4.inf|out=" << printer.pushFloat(0x7f800000, 4)
            << '\n';
  std::cout << "case=float4.neginf|out=" << printer.pushFloat(0xff800000, 4)
            << '\n';
  std::cout << "case=float4.nan|out=" << printer.pushFloat(0x7fc00000, 4)
            << '\n';
  std::cout << "case=float4.negnan|out=" << printer.pushFloat(0xffc00000, 4)
            << '\n';
  std::cout << "case=float4.subnormal|out=" << printer.pushFloat(0x00000001, 4)
            << '\n';
  std::cout << "case=float4.scinote_pi|out="
            << printer.pushFloatScinote(0x40490fdb, 4) << '\n';
  // 8-byte IEEE 754 encodings.
  std::cout << "case=float8.one|out="
            << printer.pushFloat(0x3ff0000000000000ULL, 8) << '\n';
  std::cout << "case=float8.tenth|out="
            << printer.pushFloat(0x3fb999999999999aULL, 8) << '\n';
  std::cout << "case=float8.integral64|out="
            << printer.pushFloat(0x4059000000000000ULL, 8) << '\n';
  std::cout << "case=float8.inf|out="
            << printer.pushFloat(0x7ff0000000000000ULL, 8) << '\n';
  std::cout << "case=float8.negnan|out="
            << printer.pushFloat(0xfff8000000000000ULL, 8) << '\n';
  std::cout << "case=float8.scinote_tenth|out="
            << printer.pushFloatScinote(0x3fb999999999999aULL, 8) << '\n';
  // Unregistered encoding size: FLOAT_UNKNOWN (printc.cc:1385-1387).
  std::cout << "case=float2.unknown|out=" << printer.pushFloat(0x3f80, 2)
            << '\n';

  // ---- setCommentStyle (printc.cc:2350-2361) ----
  bool threw = false;
  std::cout << "case=commentstyle.c|out=" << printer.renderComment("c", threw)
            << "|threw=" << threw << '\n';
  std::cout << "case=commentstyle.cplusplus|out="
            << printer.renderComment("cplusplus", threw) << "|threw=" << threw
            << '\n';
  std::cout << "case=commentstyle.blockslash|out="
            << printer.renderComment("/*custom", threw) << "|threw=" << threw
            << '\n';
  std::cout << "case=commentstyle.lineslash|out="
            << printer.renderComment("//custom", threw) << "|threw=" << threw
            << '\n';
  printer.renderComment("badstyle", threw);
  std::cout << "case=commentstyle.bad|threw=" << threw << '\n';

  // ---- genericFunctionName (printc.cc:3359-3366) ----
  AddrSpace *ram = architecture.getDefaultCodeSpace();
  std::cout << "case=genericname.plt|out="
            << printer.genericName(Address(ram, 0x22e0)) << '\n';
  std::cout << "case=genericname.low|out="
            << printer.genericName(Address(ram, 0x3190)) << '\n';
  std::cout << "case=genericname.high32|out="
            << printer.genericName(Address(ram, 0x123456789)) << '\n';

  // ---- emitSymbolScope (printc.cc:233-259) ----
  // A BFD function symbol lives in the global scope; the fixture printer's
  // scope stack is empty (curscope = the global scope), so the resolution
  // depth is 0 and nothing prints (database.cc:326 scope==useScope).
  Funcdata *mainfd = architecture.symboltab->getGlobalScope()->queryFunction("main");
  if (mainfd != (Funcdata *)0) {
    std::cout << "case=emitsymbolscope.main|out=["
              << printer.emitScopeOf(mainfd->getSymbol()) << "]\n";
  }
  Funcdata *getstr = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
  if (getstr != (Funcdata *)0) {
    std::cout << "case=emitsymbolscope.getstr|out=["
              << printer.emitScopeOf(getstr->getSymbol()) << "]\n";
  }

  // ---- pushMismatchSymbol (printc.cc:2067-2083) ----
  // A bare symbol (display name only) + a bare varnode for the off!=0 arm.
  // Symbol's destructor is protected (scope-owned objects); the fixture
  // heap-allocates and lets the process exit reclaim it.
  Datatype *charType = architecture.types->getBase(1, TYPE_INT);
  Symbol *mismatchSym = new Symbol((Scope *)0, "mismatched", charType);
  Varnode stackVn(1, Address(architecture.getDefaultDataSpace(), 0x10),
                  (Datatype *)0);
  std::cout << "case=mismatch.off0|out="
            << printer.pushMismatch(mismatchSym, 0, 1, (const Varnode *)0)
            << '\n';
  std::cout << "case=mismatch.offpos|out="
            << printer.pushMismatch(mismatchSym, 4, 1, &stackVn) << '\n';

  // ---- pushTypePointerRel (printc.hh:365-370) ----
  std::cout << "case=ptrrel.adj|out=" << printer.pushPtrRel(0)
            << '\n';

  // ---- doEmitWideCharPrefix via pushCharConstant (printc.cc:1504/1606) ----
  Datatype *wideChar = architecture.types->getBase(2, TYPE_INT, "wchar");
  std::cout << "case=widechar.ascii|out="
            << printer.pushWideChar(0x1234, wideChar) << '\n';
  std::cout << "case=widechar.escape|out="
            << printer.pushWideChar(0x0a, wideChar) << '\n';

  return 0;
}
