/*
 * FSPEC-PARAMLIST-OUTPUT-DISPATCH-0001: locked Ghidra 12.0.4 oracle.
 *
 * Load the production x86-64 gcc compiler spec, then drive the real
 * ProtoModel::deriveOutputMap -> ParamListStandardOut::fillinMap chain.
 * Every publicly observable ParamActive/ParamTrial mutation is serialized.
 */
#include "bfd_arch.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"

#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::string;
using std::vector;

uint4 trialFlags(const ParamTrial &trial)
{
  uint4 flags = 0;
  if (trial.isChecked()) flags |= ParamTrial::checked;
  if (trial.isUsed()) flags |= ParamTrial::used;
  if (trial.isDefinitelyNotUsed()) flags |= ParamTrial::defnouse;
  if (trial.isActive()) flags |= ParamTrial::active;
  if (trial.isUnref()) flags |= ParamTrial::unref;
  if (trial.isKilledByCall()) flags |= ParamTrial::killedbycall;
  if (trial.isRemFormed()) flags |= ParamTrial::rem_formed;
  if (trial.isIndCreateFormed()) flags |= ParamTrial::indcreate_formed;
  if (trial.hasCondExeEffect()) flags |= ParamTrial::condexe_effect;
  if (trial.hasAncestorRealistic()) flags |= ParamTrial::ancestor_realistic;
  if (trial.hasAncestorSolid()) flags |= ParamTrial::ancestor_solid;
  return flags;
}

void dumpActive(const char *phase, ParamActive &active)
{
  cout << phase << "|count=" << active.getNumTrials()
       << "|used=" << active.getNumUsed()
       << "|passes=" << active.getNumPasses()
       << "|maxpass=" << active.getMaxPass()
       << "|fully=" << (active.isFullyChecked() ? 1 : 0)
       << "|final=" << (active.needsFinalCheck() ? 1 : 0)
       << "|recover_subcall=" << (active.isRecoverSubcall() ? 1 : 0)
       << "|join_reverse=" << (active.isJoinReverse() ? 1 : 0) << '\n';
  for (int4 i = 0; i < active.getNumTrials(); ++i) {
    const ParamTrial &trial(active.getTrial(i));
    const ParamEntry *entry = trial.getEntry();
    cout << phase << "_TRIAL|index=" << i
         << "|space=" << trial.getAddress().getSpace()->getName()
         << "|offset=0x" << std::hex << trial.getAddress().getOffset() << std::dec
         << "|size=" << trial.getSize()
         << "|slot=" << trial.getSlot()
         << "|entry_group=" << (entry == (const ParamEntry *)0 ? -1 : entry->getGroup())
         << "|entry_offset=" << trial.getOffset()
         << "|flags=0x" << std::hex << trialFlags(trial) << std::dec << '\n';
  }
}

void runCase(ProtoModel *model, Architecture &arch, const char *name,
             const vector<string> &activeRegisters,
             const vector<string> &inactiveRegisters)
{
  ParamActive active(false);
  cout << "CASE|" << name << '\n';
  for (vector<string>::const_iterator it = activeRegisters.begin();
       it != activeRegisters.end(); ++it) {
    const VarnodeData &reg(arch.translate->getRegister(*it));
    active.registerTrial(Address(reg.space, reg.offset), reg.size);
    active.getTrial(active.getNumTrials() - 1).markActive();
  }
  for (vector<string>::const_iterator it = inactiveRegisters.begin();
       it != inactiveRegisters.end(); ++it) {
    const VarnodeData &reg(arch.translate->getRegister(*it));
    active.registerTrial(Address(reg.space, reg.offset), reg.size);
    active.getTrial(active.getNumTrials() - 1).markInactive();
  }
  dumpActive("BEFORE", active);
  model->deriveOutputMap(&active);
  dumpActive("AFTER", active);
}

void runFixture(const string &specDirectory, const string &binary)
{
  vector<string> specPaths(1, specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture arch(binary, "default", &cerr);
  DocumentStorage documents;
  arch.init(documents);

  ProtoModel *model = arch.defaultfp;
  cout << "SCHEMA|1\n";
  cout << "ORACLE|e40ed13014025f82488b1f8f7bca566894ac376b\n";
  cout << "MODEL|" << model->getName() << "|extrapop=" << model->getExtraPop() << '\n';

  const VarnodeData &xmm0(arch.translate->getRegister("XMM0_Qa"));
  const VarnodeData &rax(arch.translate->getRegister("RAX"));
  const VarnodeData &rcx(arch.translate->getRegister("RCX"));
  cout << "POSSIBLE|XMM0_Qa|" << (model->possibleOutputParam(Address(xmm0.space, xmm0.offset), xmm0.size) ? 1 : 0) << '\n';
  cout << "POSSIBLE|RAX|" << (model->possibleOutputParam(Address(rax.space, rax.offset), rax.size) ? 1 : 0) << '\n';
  cout << "POSSIBLE|RCX|" << (model->possibleOutputParam(Address(rcx.space, rcx.offset), rcx.size) ? 1 : 0) << '\n';

  runCase(model, arch, "float_only", vector<string>(1, "XMM0_Qa"), vector<string>());
  runCase(model, arch, "general_only", vector<string>(1, "RAX"), vector<string>());
  runCase(model, arch, "general_beats_float", vector<string>(1, "RAX"), vector<string>(1, "XMM0_Qa"));
  runCase(model, arch, "invalid_output", vector<string>(1, "RCX"), vector<string>());
  cout << "DONE\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: fspec_paramlist_output_1204 <spec-directory> <binary>\n";
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
