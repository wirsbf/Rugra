/*
 * Locked Ghidra 12.0.4 ActionStart/ActionStop lifecycle observation.
 *
 * The fixture deliberately records both the Action-level delegation state and
 * the downstream Funcdata state.  Rugra does not yet own the translator in
 * Funcdata::start_processing, so the complete observation is expected to
 * remain MISMATCH even after the two Action wrappers are corrected.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::runtime_error;
using std::string;
using std::vector;

template<typename Iterator>
long countRange(Iterator begin,Iterator end)

{
  return static_cast<long>(std::distance(begin,end));
}

void dumpState(const char *label,Funcdata &fd,Architecture &architecture,bool heritageInfoBuilt)

{
  AddrSpace *registerSpace = architecture.getSpaceByName("register");
  AddrSpace *stackSpace = architecture.getStackSpace();
  if (registerSpace == (AddrSpace *)0 || stackSpace == (AddrSpace *)0)
    throw runtime_error("fixture requires register and stack spaces");
  std::cout << label
            << ":started=" << fd.isProcStarted()
            << ",complete=" << fd.isProcComplete()
            << ",alive=" << countRange(fd.beginOpAlive(),fd.endOpAlive())
            << ",dead=" << countRange(fd.beginOpDead(),fd.endOpDead())
            << ",ops=" << countRange(fd.beginOpAll(),fd.endOpAll())
            << ",varnodes=" << fd.numVarnodes()
            << ",blocks=" << fd.getBasicBlocks().getSize()
            << ",calls=" << fd.numCalls()
            << ",heritage=" << fd.getHeritagePass()
            << ",register_passes=";
  if (heritageInfoBuilt)
    std::cout << fd.numHeritagePasses(registerSpace);
  else
    std::cout << "na";
  std::cout << ",stack_passes=";
  if (heritageInfoBuilt)
    std::cout << fd.numHeritagePasses(stackSpace);
  else
    std::cout << "na";
  std::cout
            << ",input_locked=" << fd.getFuncProto().isInputLocked()
            << ",output_locked=" << fd.getFuncProto().isOutputLocked()
            << ",model_locked=" << fd.getFuncProto().isModelLocked()
            << '\n';
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->hasNoCode())
      throw runtime_error("GetStr has no code");
    // The ELF symbol is 0x4a bytes, but BfdArchitecture deliberately leaves
    // this Funcdata size at zero.  startProcessing therefore uses the full
    // base-space end address and followFlow stops at the reachable returns.
    if (fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
      throw runtime_error("GetStr input identity drifted: offset=" +
                          std::to_string(fd->getAddress().getOffset()) +
                          " size=" + std::to_string(fd->getSize()));

    dumpState("before_start",*fd,architecture,false);
    ActionStart start("base");
    std::cout << "start_return=" << start.apply(*fd) << '\n';
    dumpState("after_start",*fd,architecture,true);

    PcodeOp *pending = fd->newOp(0,fd->getAddress());
    fd->opSetOpcode(pending,CPUI_COPY);
    std::cout << "stop_dead_before="
              << countRange(fd->beginOpDead(),fd->endOpDead()) << '\n';
    ActionStop stop("base");
    std::cout << "stop_return=" << stop.apply(*fd) << '\n';
    dumpState("after_stop",*fd,architecture,true);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: pipeline_lifecycle_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
