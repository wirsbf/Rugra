/*
 * Locked Ghidra 12.0.4 (e40ed130) OPACTION_DEBUG per-application drill
 * harness for Funcdata "next_url" of examples/curl.
 *
 * Investigation fixture for stage-bisect v2 (per-application modified-op
 * down-drill).  Design: /dev/shm/rugra-tests/sb-drill/DRILL_DESIGN.md.
 *
 * The fixture loads one function with the exact per-function drive protocol
 * of tools/regen_ghidra_golden.py decompileFunction() (full flow range,
 * universal action to completion resuming past breakpoints), but routes the
 * Architecture debug stream into a framing sink so that every native
 * Funcdata::debugModPrint flush becomes one framed application block.
 *
 * Compile ONLY with -DOPACTION_DEBUG (library AND this file); a run produced
 * by a build without the switch, or without recording the switch, is
 * NO_ORACLE for gate purposes (DRILL_DESIGN.md section 2).
 *
 * Oracle mechanisms consumed (locked commit e40ed130):
 *   funcdata.cc:1010-1052   debugModCheck / debugModClear / debugModPrint
 *                           (one glb->printDebug(s.str()) flush per
 *                           application; header "DEBUG <n>: <leafname>",
 *                           <n> starts at 0 and only advances when the
 *                           application modified a traced op)
 *   op.cc:376 printDebug    "<seqnum>: <printRaw>" live ops,
 *                           "<seqnum>: **" dead/unattached ops (verbatim,
 *                           never reformatted by this fixture)
 *   action.cc:317-321,839-845  debugActivate / debugModPrint boundaries
 *                           around Action::apply and Rule::applyOp
 *   architecture.hh:255-256   setDebugStream / printDebug capture point
 *   action.hh:73-104          setBreakPoint(break_start)/clearBreakPoints
 *                           ladder used to bracket tree positions
 *
 * TODO sections (milestones):
 *   M1: load curl/next_url, run the universal tree, capture DEBUG stream,
 *       @BEGIN/@END per application with tree-path prefix.
 *   M2: write /dev/shm/rugra-tests/sb-drill/next_url.oracle.drill.
 *   M3: driven by tools/run_stage_drill_oracle.sh + metadata json.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using namespace ghidra;
using std::runtime_error;
using std::string;

// M1 TODO: framing sink around Architecture::setDebugStream.
// M1 TODO: break_start ladder + pre-order tree walk for path attribution.
// M2 TODO: drill record emission (@BEGIN/@END per application, native DEBUG
//          text verbatim, dead ops keep "<seqnum>: **").

void runFixture(const string &specDirectory,const string &binary)
{
  // M1 TODO: mirror tests/oracle/pipeline_lifecycle_1204.cc loading and
  // tools/regen_ghidra_golden.py decompileFunction() drive protocol.
  (void)specDirectory;
  (void)binary;
  throw runtime_error("stage_drill_1204 skeleton: not implemented yet");
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: stage_drill_1204 SPEC_ROOT CURL_BINARY\n";
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
