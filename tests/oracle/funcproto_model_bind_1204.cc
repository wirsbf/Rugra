/*
 * FUNCPROTO-MODEL-BIND-0001: locked Ghidra 12.0.4 prototype-model binding
 * oracle.  Loads the real production x86-64-gcc.cspec through a full
 * BfdArchitecture::init (Architecture::parseCompilerConfig establishes
 * `defaultfp` at architecture.cc:1337-1347) and observes the canonical
 * model-binding chain the Rust side must reproduce byte for byte:
 *   - ARCH: the resolved default model (name/extrapop) and the __thiscall
 *     alias clone,
 *   - CTOR: the named Funcdata constructor binds the default model
 *     immediately through Scope::addFunction -> FunctionSymbol::getFunction
 *     -> Funcdata::Funcdata -> funcp.setScope (funcdata.cc:48-69,
 *     fspec.cc:3879-3884),
 *   - OVERLAY: the external locked-prototype overlay (DWARF-style lock tail:
 *     input/output/model locks, fspec.cc:3921/3942/1399) observes the model
 *     already in place — never modellocked-without-model,
 *   - UNNAMED: the unnamed Funcdata constructor path keeps a null model
 *     until the ActionPrototypeTypes bind (coreaction.cc:4615-4619),
 *   - CALLSPEC: a fresh FuncCallSpecs starts modelless; the
 *     ActionDefaultParams else-branch (coreaction.cc:2327-2328) binds the
 *     evaluation model via setInternal, after which hasEffect (fspec.cc:4234)
 *     answers with the compiler-spec-declared effects instead of the
 *     conservative unknown_effect.
 */
#include "bfd_arch.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "database.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "xml.hh"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::runtime_error;
using std::string;
using std::vector;

void runFixture(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture arch(binary, "default", &std::cerr);
  DocumentStorage documents;
  arch.init(documents);

  cout << "SCHEMA|1\n";

  // Architecture-side resolution: the default model must exist and the
  // __thiscall alias must have been cloned off it (architecture.cc:1337-1347).
  cout << "ARCH_DEFAULTFP|" << arch.defaultfp->getName() << "\n";
  cout << "ARCH_DEFAULTFP_EXTRAPOP|" << arch.defaultfp->getExtraPop() << "\n";
  cout << "THISCALL_ALIAS|"
       << (arch.protoModels.find("__thiscall") != arch.protoModels.end() ? 1 : 0)
       << "\n";

  // setDefaultModel print-flag side effect (architecture.cc:323-330,
  // rework regression 1): the resolved default is FORCED not to print in
  // declarations; a non-default model keeps the constructor default
  // (isPrinted=true, fspec.cc:2352); re-defaulting restores the previous
  // model's print flag and clears the new one.
  {
    cout << "PRINTFLAG|" << arch.defaultfp->getName() << "|"
         << (arch.defaultfp->printInDecl() ? 1 : 0) << "\n";
    map<string,ProtoModel *>::const_iterator msabi = arch.protoModels.find("MSABI");
    if (msabi != arch.protoModels.end())
      cout << "PRINTFLAG|" << msabi->first << "|" << (msabi->second->printInDecl() ? 1 : 0) << "\n";
    arch.setDefaultModel(arch.protoModels["MSABI"]);
    cout << "PRINTFLAG|" << arch.defaultfp->getName() << "|"
         << (arch.defaultfp->printInDecl() ? 1 : 0) << "\n";
    cout << "PRINTFLAG|__stdcall|" << (arch.protoModels["__stdcall"]->printInDecl() ? 1 : 0) << "\n";
    // Restore the production default for the observations below.
    arch.setDefaultModel(arch.protoModels["__stdcall"]);
  }

  // Named Funcdata constructor chain: Scope::addFunction (database.cc:1615)
  // maps a FunctionSymbol, and FunctionSymbol::getFunction (database.cc:557)
  // runs the real constructor with the scope — which attaches the ScopeLocal
  // and calls funcp.setScope(localmap, baseaddr-1) (funcdata.cc:69-74).
  // setScope installs the Architecture default model because the fresh
  // FuncProto's model is null (fspec.cc:3879-3884).
  Scope *globalScope = arch.symboltab->getGlobalScope();
  FunctionSymbol *sym = globalScope->addFunction(
      Address(arch.getDefaultCodeSpace(), 0x600000), "fixture_model_bind");
  Funcdata *fd = sym->getFunction();
  cout << "CTOR_BIND|" << (fd->getFuncProto().hasModel() ? 1 : 0) << "|"
       << (fd->getFuncProto().hasMatchingModel(arch.defaultfp) ? 1 : 0) << "|"
       << fd->getFuncProto().getModelName() << "|"
       << fd->getFuncProto().getExtraPop() << "\n";

  // External locked-prototype overlay (the DWARF/signature boundary): the
  // lock tail sets input/output/model locks on the already-bound prototype.
  // Observable contract: the model survives the overlay — the locked
  // prototype is never modelless.
  fd->getFuncProto().setInputLock(true);
  fd->getFuncProto().setOutputLock(true);
  fd->getFuncProto().setModelLock(true);
  cout << "OVERLAY_LOCK|" << (fd->getFuncProto().hasModel() ? 1 : 0) << "|"
       << (fd->getFuncProto().hasMatchingModel(arch.defaultfp) ? 1 : 0) << "|"
       << (fd->getFuncProto().isModelLocked() ? 1 : 0) << "|"
       << (fd->getFuncProto().isInputLocked() ? 1 : 0) << "|"
       << (fd->getFuncProto().isOutputLocked() ? 1 : 0) << "\n";

  // Unnamed Funcdata constructor path (funcdata.cc:55-56): an empty name
  // skips the ScopeLocal attach and therefore the setScope model binding —
  // the prototype stays modelless until ActionPrototypeTypes runs.
  {
    Funcdata fd2("", "", globalScope, Address(arch.getDefaultCodeSpace(), 0x600100),
                 (FunctionSymbol *)0);
    cout << "CTOR_UNNAMED|" << (fd2.getFuncProto().hasModel() ? 1 : 0) << "\n";
    // ActionPrototypeTypes::apply binding tail (coreaction.cc:4615-4619):
    // evalfp = evalfp_current ?: defaultfp; bind when not model-locked and
    // not already matching.
    ProtoModel *evalfp = arch.evalfp_current;
    if (evalfp == (ProtoModel *)0)
      evalfp = arch.defaultfp;
    if ((!fd2.getFuncProto().isModelLocked()) && !fd2.getFuncProto().hasMatchingModel(evalfp))
      fd2.getFuncProto().setModel(evalfp);
    cout << "PROTOTYPE_TYPES_BIND|" << (fd2.getFuncProto().hasMatchingModel(arch.defaultfp) ? 1 : 0)
         << "|" << fd2.getFuncProto().getModelName() << "|"
         << fd2.getFuncProto().getExtraPop() << "\n";
  }

  // Call-site chain: flow.cc builds each FuncCallSpecs from the call op
  // itself (flow.cc:723 `new FuncCallSpecs(op)` for CALLIND), which
  // default-constructs its FuncProto base — model null. The
  // ActionDefaultParams else-branch for callees without a Funcdata
  // (coreaction.cc:2327-2328) runs setInternal(evalfp, void) which installs
  // the model (fspec.cc:3891-3898).
  {
    PcodeOp *call_op = fd->newOp(1, Address(arch.getDefaultCodeSpace(), 0x601000));
    fd->opSetOpcode(call_op, CPUI_CALLIND);
    FuncCallSpecs fc(call_op);
    cout << "CALLSPEC_PRE|" << (fc.hasModel() ? 1 : 0) << "\n";
    ProtoModel *evalfp = arch.evalfp_called;
    if (evalfp == (ProtoModel *)0)
      evalfp = arch.defaultfp;
    fc.setInternal(evalfp, arch.types->getTypeVoid());
    cout << "CALLSPEC_POST|" << (fc.hasModel() ? 1 : 0) << "|"
         << (fc.hasMatchingModel(arch.defaultfp) ? 1 : 0) << "|"
         << fc.getModelName() << "|" << fc.getExtraPop() << "\n";

    // hasEffect (fspec.cc:4234) against the compiler-spec-declared effects:
    // killedbycall registers, unaffected registers, unlisted registers
    // (unknown), the injected stack return-address slot, and an unlisted
    // stack range.
    const char *regnames[] = {"RAX", "RBX", "RSP", "RCX"};
    for (int4 i = 0; i < 4; ++i) {
      VarnodeData vd = arch.translate->getRegister(regnames[i]);
      Address addr(vd.space, vd.offset);
      cout << "EFFECT|" << regnames[i] << "|0x" << std::hex << vd.offset << std::dec
           << "|" << vd.size << "|" << fc.hasEffect(addr, vd.size) << "\n";
    }
    {
      Address stack0(arch.getStackSpace(), 0);
      cout << "EFFECT|stack|0x0|8|" << fc.hasEffect(stack0, 8) << "\n";
      Address stack100(arch.getStackSpace(), 0x100);
      cout << "EFFECT|stack|0x100|8|" << fc.hasEffect(stack100, 8) << "\n";
    }

    // Locked-guard observation (rework regression 2, coreaction.cc:2318-2328
    // guards): a bound-then-locked callspec survives a second
    // ActionDefaultParams pass untouched — the outer hasModel() guard skips
    // both the setModel override (cc:2325 requires !isModelLocked()) and
    // setInternal, so the model identity and extrapop are unchanged.
    fc.setModelLock(true);
    {
      ProtoModel *evalfp2 = arch.evalfp_called;
      if (evalfp2 == (ProtoModel *)0)
        evalfp2 = arch.defaultfp;
      if (!fc.hasModel())
        fc.setInternal(evalfp2, arch.types->getTypeVoid());
    }
    cout << "CALLSPEC_REBIND|" << (fc.hasModel() ? 1 : 0) << "|"
         << (fc.hasMatchingModel(arch.defaultfp) ? 1 : 0) << "|"
         << fc.getModelName() << "|" << fc.getExtraPop() << "\n";
  }

  cout << "DONE\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: funcproto_model_bind_1204 <spec-directory> <binary>\n";
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
