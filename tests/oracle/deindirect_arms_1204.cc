/*
 * DEINDIRECT-ARMS-1204: locked Ghidra 12.0.4 oracle for
 * FSPEC-DEINDIRECT-TRIGGER-0001 — the three conversion arms of
 * ActionDeindirect::apply (coreaction.cc:1219-1280) and the observable
 * slice of the FuncCallSpecs conversions they drive
 * (fspec.cc:5443-5472 deindirect / fspec.cc:5485-5509 forceSet).
 *
 * Covered projection (all observations through public Ghidra API plus the
 * two fixture-only accessors the runner patches into the throwaway
 * archive): the CALLIND input(0) COPY-chain walk (cc:1231-1232), the
 * external-reference arm (cc:1233-1240, queryExternalRefFunction via the
 * real global scope), the constant arm with the funcptr_align encoding-bit
 * strip (cc:1241-1257, AddrSpace::addressToByte + arch->funcptr_align),
 * the isOverride early return inside deindirect (fspec.cc:5462), the
 * noreturn/inline restart gate (fspec.cc:5461/5471), and the
 * typed-function-pointer forceSet arm (cc:1258-1277,
 * getTypeReadFacing PTR->CODE + TypeCode prototype + isInputLocked).
 *
 * Host: the cptr_b_1204 BfdArchitecture pattern (examples/curl image, the
 * GetStr function), with query targets installed on the real global scope
 * through public Scope::addFunction / Scope::addExternalRef at image-safe
 * high addresses.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "type.hh"

#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

class InspectableDeindirect : public ActionDeindirect {
public:
  InspectableDeindirect(void) : ActionDeindirect("deindirect") {
    // Action::Action leaves count/lcount uninitialized; perform()
    // normally initializes them. This fixture calls apply() directly.
    count = 0;
    lcount = 0;
  }
  int4 fixtureCount(void) const { return count; }
};

class Site {
public:
  Funcdata &fd;
  PcodeOp *op;
  FuncCallSpecs *fc;

  Site(Funcdata &d, AddrSpace *ram, uintb callpc)
    : fd(d), op((PcodeOp *)0), fc((FuncCallSpecs *)0)
  {
    op = fd.newOp(1, Address(ram, callpc));
    fd.opSetOpcode(op, CPUI_CALLIND);
    fc = new FuncCallSpecs(op);
    // Production reality (coreaction.cc:2311-2332): every callspec has
    // passed ActionDefaultParams by the time deindirect runs, so it always
    // carries a model and a proto store; the fixture installs the same
    // setInternal(defaultfp, void) shape (a bare FuncProto has a null
    // store, which the dump's isInputLocked read would dereference).
    fc->setInternal(d.getArch()->defaultfp, d.getArch()->types->getTypeVoid());
    fd.opSetInput(op, fd.newVarnodeCallSpecs(fc), 0);
    fd.fixtureAddToCallList(fc);
    BlockBasic *block = const_cast<BlockGraph &>(fd.getBasicBlocks()).newBlockBasic(&fd);
    fd.opInsertEnd(op, block);
  }

  /// The deindirect observable slice after apply: opcode number (the enum
  /// value is the shared contract with the Rust side), entry address
  /// validity/offset, the adopted display name, the restart flag DELTA
  /// (setRestartPending is Funcdata-global and sticky, so the per-case
  /// observable is "this apply fired a restart"), the input-lock state,
  /// the override flag, and the CALL's input arity.
  void dump(const string &caseName, int4 count, Funcdata &data, bool restartBefore)
  {
    ostringstream out;
    out << "case=" << caseName
        << "|op=" << static_cast<int4>(op->code())
        << "|entry=";
    if (fc->getEntryAddress().isInvalid())
      out << "inv";
    else
      out << "0x" << std::hex << fc->getEntryAddress().getOffset() << std::dec;
    bool restartFired = data.hasRestartPending() && !restartBefore;
    out << "|name=" << fc->getName()
        << "|count=" << count
        << "|restart=" << (restartFired ? 1 : 0)
        << "|inlock=" << (fc->isInputLocked() ? 1 : 0)
        << "|override=" << (fc->isOverride() ? 1 : 0)
        << "|arity=" << op->numInput();
    std::cout << out.str() << '\n';
    std::cout.flush();
  }
};

void runCases(Architecture *glb, Funcdata *fdp)
{
  Funcdata &fd = *fdp;
  AddrSpace *ram = glb->getDefaultCodeSpace();
  Scope *globals = glb->symboltab->getGlobalScope();

  // ---- case const_hit: constant arm resolves through queryFunction ----
  globals->addFunction(Address(ram, 0x60000000), "target_const");
  {
    InspectableDeindirect action;
    Site site(fd, ram, 0x500010);
    Varnode *cnst = fd.newConstant(8, 0x60000000);
    fd.opSetInput(site.op, cnst, 0);
    bool restartBefore = fd.hasRestartPending();
    action.apply(fd);
    site.dump("const_hit", action.fixtureCount(), fd, restartBefore);
  }

  // ---- case const_miss: no function at the constant address ----
  {
    InspectableDeindirect action;
    Site site(fd, ram, 0x500020);
    Varnode *cnst = fd.newConstant(8, 0x60001000);
    fd.opSetInput(site.op, cnst, 0);
    bool restartBefore = fd.hasRestartPending();
    action.apply(fd);
    site.dump("const_miss", action.fixtureCount(), fd, restartBefore);
  }

  // ---- case align_strip: funcptr_align strips the encoding bits ----
  // cc:1245-1249: funcptr_align=2 -> offset >>= 2; offset <<= 2 before the
  // query, so the low bits never reach queryFunction.
  glb->funcptr_align = 2;
  globals->addFunction(Address(ram, 0x60002000), "target_aligned");
  {
    InspectableDeindirect action;
    Site site(fd, ram, 0x500030);
    Varnode *cnst = fd.newConstant(8, 0x60002003);
    fd.opSetInput(site.op, cnst, 0);
    bool restartBefore = fd.hasRestartPending();
    action.apply(fd);
    site.dump("align_strip", action.fixtureCount(), fd, restartBefore);
  }
  glb->funcptr_align = 0;

  // ---- case copy_chain: input(0) resolves through a COPY chain ----
  // cc:1231-1232: the walk follows COPY defs; the arms examine the walked
  // varnode (the constant), not the original COPY output.
  {
    InspectableDeindirect action;
    Site site(fd, ram, 0x500040);
    Varnode *cnst = fd.newConstant(8, 0x60000000);
    PcodeOp *copyop = fd.newOp(1, Address(ram, 0x500041));
    fd.opSetOpcode(copyop, CPUI_COPY);
    Varnode *copyout = fd.newUniqueOut(8, copyop);
    fd.opSetInput(copyop, cnst, 0);
    fd.opInsertBefore(copyop, site.op);
    fd.opSetInput(site.op, copyout, 0);
    bool restartBefore = fd.hasRestartPending();
    action.apply(fd);
    site.dump("copy_chain", action.fixtureCount(), fd, restartBefore);
  }

  // ---- case noreturn: the fspec.cc:5461 gate falls to setRestartPending ----
  globals->addFunction(Address(ram, 0x60003000), "t_noreturn");
  {
    Funcdata *callee = globals->queryFunction(Address(ram, 0x60003000));
    callee->getFuncProto().setNoReturn(true);
  }
  {
    InspectableDeindirect action;
    Site site(fd, ram, 0x500050);
    Varnode *cnst = fd.newConstant(8, 0x60003000);
    fd.opSetInput(site.op, cnst, 0);
    bool restartBefore = fd.hasRestartPending();
    action.apply(fd);
    site.dump("norestart_gate", action.fixtureCount(), fd, restartBefore);
  }

  // ---- case override_site: fspec.cc:5462 early return (no restart, no
  //      late restriction) on a callspec carrying an applied override ----
  globals->addFunction(Address(ram, 0x60004000), "t_override");
  {
    InspectableDeindirect action;
    Site site(fd, ram, 0x500060);
    Varnode *cnst = fd.newConstant(8, 0x60004000);
    fd.opSetInput(site.op, cnst, 0);
    site.fc->setOverride(true);
    bool restartBefore = fd.hasRestartPending();
    action.apply(fd);
    site.dump("override_site", action.fixtureCount(), fd, restartBefore);
  }

  // ---- case extref: external-reference arm (cc:1233-1240) ----
  // The CALLIND input is a persist+externref varnode whose address holds an
  // ExternRefSymbol referring to the real function.
  globals->addFunction(Address(ram, 0x60006000), "ext_target");
  globals->addExternalRef(Address(ram, 0x60005000), Address(ram, 0x60006000), "ex_slot");
  {
    InspectableDeindirect action;
    Site site(fd, ram, 0x500070);
    Varnode *exvn = fd.newVarnode(8, Address(ram, 0x60005000));
    exvn->fixtureSetExternRef();
    fd.opSetInput(site.op, exvn, 0);
    bool restartBefore = fd.hasRestartPending();
    action.apply(fd);
    site.dump("extref", action.fixtureCount(), fd, restartBefore);
  }

  // ---- case funcptr_force: typed-funcptr forceSet arm (cc:1258-1277) ----
  // Type recovery started + input(0) typed PTR->CODE with an attached
  // prototype + callspec not input-locked -> forceSet: prototype override
  // recorded, prototype locked, arity collapses per commitNewInputs.
  fd.startTypeRecovery();
  {
    InspectableDeindirect action;
    Site site(fd, ram, 0x500080);
    Varnode *fpvn = fd.newVarnode(8, Address(ram, 0x60007000));
    PrototypePieces sig;
    sig.model = glb->defaultfp;
    sig.name = "fp_callee";
    sig.outtype = glb->types->getTypeVoid();
    sig.firstVarArgSlot = -1;
    TypeCode *tc = glb->types->getTypeCode(sig);
    TypePointer *ptr = glb->types->getTypePointer(8, tc, 1);
    fpvn->updateType(ptr, true, true);
    fd.opSetInput(site.op, fpvn, 0);
    bool restartBefore = fd.hasRestartPending();
    action.apply(fd);
    site.dump("funcptr_force", action.fixtureCount(), fd, restartBefore);
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
    runCases(&architecture, fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: deindirect_arms_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "deindirect_arms_1204: LowlevelError: " << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "deindirect_arms_1204: " << error.what() << '\n';
    return 1;
  }
}
