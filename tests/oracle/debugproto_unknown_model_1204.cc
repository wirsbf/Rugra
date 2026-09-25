/*
 * PLTSTUB-WARNLOSS-0001 seeding-layer bilateral oracle projection.
 *
 * The locked 12.0.4 golden carries
 *   "WARNING: Unknown calling convention -- yet parameter storage is locked"
 * on 24 .plt.sec stubs with a generic_clib signature and on exactly the
 * void-signature DWARF functions (main_init/main_free/hugehelp), and on no
 * parameterized DWARF function.  The state behind that warning is produced
 * where the platform-side prototype enters the decompiler:
 *
 *   - FuncProto::decode maps an unrecognized ATTRIB_MODEL value through
 *     Architecture::createUnknownModel (fspec.cc:4690-4698,
 *     architecture.cc:1159-1166): an UnknownProtoModel cloning the default
 *     model's behavior, isUnknown()=true, and for the reserved "unknown"
 *     spelling setPrintInDecl(false) (no ": name" suffix in the warning).
 *   - The lock tail is FuncProto::setPieces (fspec.cc:3843-3852):
 *     setModel(pieces.model) + setInputLock(true) + setOutputLock(true)
 *     + setModelLock(true) ("Locking input locks the model",
 *     fspec.cc:3921-3925).
 *   - ActionPrototypeWarnings::apply (coreaction.cc:4901-4908) renders the
 *     warning from isModelUnknown + printModelInDecl + the input/output
 *     locks and files it through Funcdata::warningHeader into the
 *     architecture comment database (funcdata.cc:135-145).
 *
 * This fixture builds the production x86-64-gcc.cspec architecture through
 * BfdArchitecture, materializes the same three function classes with the
 * oracle's own composition (createUnknownModel + FuncProto::setPieces), runs
 * the real ActionPrototypeWarnings, and dumps the complete boundary state:
 * model identity, unknown flag, print flag, default-behavior compatibility,
 * extrapop, the three locks, model-assigned parameter storage, and the filed
 * warning header text.  Pointer values and allocation identities are never
 * printed.
 */
#include "bfd_arch.hh"
#include "coreaction.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "database.hh"
#include "libdecomp.hh"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <cstdlib>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::runtime_error;
using std::string;
using std::vector;

void dumpProto(const char *label, FuncProto &fp)
{
  cout << label
       << "|name=" << fp.getModelName()
       << "|unknown=" << (fp.isModelUnknown() ? 1 : 0)
       << "|printInDecl=" << (fp.printModelInDecl() ? 1 : 0)
       << "|hasModel=" << (fp.hasModel() ? 1 : 0)
       << "|extrapop=" << fp.getExtraPop()
       << "|modelExtraPop=" << fp.getModelExtraPop()
       << "|modellock=" << (fp.isModelLocked() ? 1 : 0)
       << "|inlock=" << (fp.isInputLocked() ? 1 : 0)
       << "|outlock=" << (fp.isOutputLocked() ? 1 : 0)
       << "|params=" << fp.numParams()
       << "|retsize=" << fp.getOutputType()->getSize();
  {
    // Output storage: "none" for an unassigned or void return (a zero-size
    // output has no storage).
    const ProtoParameter *out = fp.getOutput();
    if (out->getType()->getSize() == 0 || out->getAddress().isInvalid())
      cout << "|retStorage=none";
    else
      cout << "|retStorage=" << out->getAddress().getSpace()->getName()
           << "@0x" << std::hex << out->getAddress().getOffset() << std::dec;
  }
  cout << "\n";
  for (int4 i = 0; i < fp.numParams(); ++i) {
    const ProtoParameter *param = fp.getParam(i);
    Address addr = param->getAddress();
    cout << label << "|param|" << i
         << "|" << param->getName()
         << "|" << (addr.isInvalid() ? string("none") : addr.getSpace()->getName())
         << "@0x" << std::hex << addr.getOffset() << std::dec
         << "|size=" << param->getType()->getSize()
         << "|typelock=" << (param->isTypeLocked() ? 1 : 0)
         << "\n";
  }
}

void dumpWarnings(const char *label, Funcdata *fd)
{
  const CommentDatabase *cdb = fd->getArch()->commentdb;
  CommentSet::const_iterator iter = cdb->beginComment(fd->getAddress());
  CommentSet::const_iterator end = cdb->endComment(fd->getAddress());
  int4 count = 0;
  for (; iter != end; ++iter) {
    const Comment *com = *iter;
    cout << label << "|warn|" << count++
         << "|type=" << com->getType()
         << "|" << com->getText() << "\n";
  }
  cout << label << "|warncount|" << count << "\n";
}

// One case: build the function through the Scope::addFunction constructor
// chain (funcdata.cc:34-69, the model-binding ctor), overlay the locked
// platform signature with FuncProto::setPieces (fspec.cc:3843-3852), run the
// real ActionPrototypeWarnings, and dump state + filed warnings.
Funcdata *buildCase(Architecture &arch, Scope *globalScope, const char *nm,
                    uintb offset, ProtoModel *model, Datatype *outtype,
                    const vector<Datatype *> &intypes,
                    const vector<string> &innames)
{
  FunctionSymbol *sym = globalScope->addFunction(
      Address(arch.getDefaultCodeSpace(), offset), nm);
  Funcdata *fd = sym->getFunction();
  FuncProto &fp = fd->getFuncProto();
  fp.setInternal(arch.defaultfp, arch.types->getTypeVoid());
  PrototypePieces pieces;
  pieces.model = model;
  pieces.name = nm;
  pieces.outtype = outtype;
  pieces.intypes = intypes;
  pieces.innames = innames;
  pieces.firstVarArgSlot = -1;
  fp.setPieces(pieces);
  ActionPrototypeWarnings action("fixture");
  action.apply(*fd);
  return fd;
}

void runFixture(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture arch(binary, "default", &std::cerr);
  DocumentStorage documents;
  arch.init(documents);

  cout << "SCHEMA|1\n";
  cout << "ARCH_DEFAULT|" << arch.defaultfp->getName()
       << "|extrapop=" << arch.defaultfp->getExtraPop() << "\n";

  // The reserved unknown model, obtained exactly as FuncProto::decode
  // obtains it for an unrecognized ATTRIB_MODEL value (fspec.cc:4695-4697):
  // registry miss, then Architecture::createUnknownModel (architecture.cc:1159).
  ProtoModel *unknownModel = arch.getModel("unknown");
  cout << "UNKNOWN_PRE|" << (unknownModel == (ProtoModel *)0 ? 0 : 1) << "\n";
  if (unknownModel == (ProtoModel *)0)
    unknownModel = arch.createUnknownModel("unknown");
  cout << "UNKNOWN_POST|name=" << unknownModel->getName()
       << "|isUnknown=" << (unknownModel->isUnknown() ? 1 : 0)
       << "|printInDecl=" << (unknownModel->printInDecl() ? 1 : 0)
       << "|extrapop=" << unknownModel->getExtraPop()
       << "|behaviorDefault=" << (unknownModel->isCompatible(arch.defaultfp) ? 1 : 0)
       << "\n";

  Scope *globalScope = arch.symboltab->getGlobalScope();
  Datatype *voidType = arch.types->getTypeVoid();
  Datatype *voidPtr = arch.types->getTypePointer(8, voidType, 1);
  Datatype *int4Type = arch.types->getBase(4, TYPE_INT);
  Datatype *charPtr = arch.types->getTypePointer(8, arch.types->getBase(1, TYPE_INT), 1);

  // Case A: generic_clib locked signature on a PLT thunk (free):
  // void(void*), unknown calling convention.
  {
    Funcdata *fd = buildCase(arch, globalScope, "free", 0x600000, unknownModel,
                             voidType, vector<Datatype *>(1, voidPtr),
                             vector<string>(1, string("__ptr")));
    dumpProto("PLT_FREE", fd->getFuncProto());
    dumpWarnings("PLT_FREE", fd);
  }

  // Case A2: generic_clib void-list entry (__ctype_b_loc): ushort **(),
  // unknown calling convention, locked void input.
  {
    Datatype *ushortBase = arch.types->getBase(2, TYPE_UINT);
    Datatype *ushortPtrPtr = arch.types->getTypePointer(
        8, arch.types->getTypePointer(8, ushortBase, 1), 1);
    Funcdata *fd = buildCase(arch, globalScope, "__ctype_b_loc", 0x600100,
                             unknownModel, ushortPtrPtr,
                             vector<Datatype *>(), vector<string>());
    dumpProto("PLT_CTYPE", fd->getFuncProto());
    dumpWarnings("PLT_CTYPE", fd);
  }

  // Case B: void-signature DWARF function (main_init): 4-byte enum return,
  // no parameters, unknown calling convention (the golden warning set).
  {
    Funcdata *fd = buildCase(arch, globalScope, "main_init", 0x600200, unknownModel,
                             int4Type, vector<Datatype *>(), vector<string>());
    dumpProto("DWARF_VOID", fd->getFuncProto());
    dumpWarnings("DWARF_VOID", fd);
  }

  // Case C: parameterized DWARF function (GetStr): void(char**,char*) with
  // the resolved default model — no golden warning, no unknown identity.
  {
    vector<Datatype *> intypes;
    intypes.push_back(charPtr);
    intypes.push_back(charPtr);
    vector<string> innames;
    innames.push_back("string");
    innames.push_back("value");
    Funcdata *fd = buildCase(arch, globalScope, "GetStr", 0x600300, arch.defaultfp,
                             voidType, intypes, innames);
    dumpProto("DWARF_PARAMS", fd->getFuncProto());
    dumpWarnings("DWARF_PARAMS", fd);
  }

  cout << "DONE\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: debugproto_unknown_model_1204 <spec-directory> <binary>\n";
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
