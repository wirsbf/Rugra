/*
 * Locked Ghidra 12.0.4 oracle: CALL in(0) coderef survives
 * ActionDeadCode + ActionVarnodeProps (COREACTION-CALLIN0-CLOBBER-0001).
 *
 * Loads examples/curl via BfdArchitecture, runs the natural flow
 * (Funcdata::followFlow) on my_fwrite @0x3460 (push prologue; direct calls
 * fwrite@plt 0x2500 / fopen@plt 0x24b0; internal branches), so every
 * CPUI_CALL carries a FuncCallSpecs and in(0) is the fspec annotation
 * varnode (flow.cc:683-690 FlowInfo::setupCallSpecs +
 * funcdata_varnode.cc:205 Funcdata::newVarnodeCallSpecs). Then runs
 * ActionDeadCode::apply (coreaction.cc:3925, whose markConsumedParameters
 * cc:3840 pushes consume ~0 on in(0) — "In all cases the first operand is
 * fully consumed") followed by ActionVarnodeProps::apply (coreaction.cc:1282,
 * whose cc:1327-1341 totalReplaceConstant branch must NOT fire on the call
 * target) and projects the control-flow target observables.
 *
 * The runner compiles this file unpatched against the locked libdecomp.a
 * plus the EXTRA-group adapters (bfd_arch/sleigh_arch/loadimage_bfd/
 * inject_sleigh/libdecomp).
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostream;
using std::ostringstream;
using std::string;
using std::vector;

// Action::perform normally initializes the protected counters; these
// fixtures call apply() directly, so they remove that otherwise-observable
// UB the same way the DEADCODE-SELFLOOP-0001 fixture does.
class FixtureDeadCode : public ActionDeadCode {
public:
  FixtureDeadCode(void) : ActionDeadCode("deadcode") { count = 0; lcount = 0; }
};

class FixtureVarnodeProps : public ActionVarnodeProps {
public:
  FixtureVarnodeProps(void) : ActionVarnodeProps("base") { count = 0; lcount = 0; }
};

// ActionDefaultParams("base") runs in the FIRST decompile group
// (coreaction.cc:5480) before the deadcode group and installs the default
// ProtoModel on every FuncCallSpecs (coreaction.cc:2311-2330) — without it
// FuncProto::numParams dereferences a null model. The fixture must drive
// the same base-group ordering the pipeline does.
class FixtureDefaultParams : public ActionDefaultParams {
public:
  FixtureDefaultParams(void) : ActionDefaultParams("base") { count = 0; lcount = 0; }
};

struct Line {
  string kind;
  uintb target;
  int4 constant;
  int4 consumeFull;
  bool operator<(const Line &op) const
  {
    if (kind != op.kind) return kind < op.kind;
    return target < op.target;
  }
};

/// Collect one control-flow target op projection after the
/// DeadCode+VarnodeProps pair. For a CPUI_CALL/CPUI_CALLIND the target
/// varnode is the fspec annotation (its offset is a process-local
/// FuncCallSpecs pointer), so the callee entry address is projected through
/// Funcdata::getCallSpecs instead; for CPUI_BRANCH/CBRANCH in(0) is a real
/// code-ref varnode and its offset projects directly. Consume is projected
/// as "full mask of the varnode size" — the invariant
/// markConsumedParameters establishes for call first operands (cc:3846) and
/// the generic else-branch pushConsumed loop establishes for branch inputs
/// (cc:3985-3989). The annotation-space representation itself (IPTR_FSPEC
/// vs a ram-space coderef varnode) is NOT projected: it is a
/// representation difference of the two pipelines' flow-time anchoring, not
/// of the preserved-target invariant under test.
void collectLine(Funcdata &fd,PcodeOp *op,vector<Line> &lines)

{
  if (op == (PcodeOp *)0) return;
  Varnode *in0 = op->getIn(0);
  if (in0 == (Varnode *)0) return;
  string kind;
  uintb target;
  switch(op->code()) {
  case CPUI_CALL:
  case CPUI_CALLIND:
    {
      kind = "call";
      FuncCallSpecs *fc = fd.getCallSpecs(op);
      target = (fc == (FuncCallSpecs *)0 || fc->getEntryAddress().isInvalid())
          ? 0 : fc->getEntryAddress().getOffset();
      break;
    }
  case CPUI_BRANCH:
    kind = "branch";
    target = in0->getOffset();
    break;
  case CPUI_CBRANCH:
    kind = "cbranch";
    target = in0->getOffset();
    break;
  default:
    return;
  }
  uintb fullMask = calc_mask(in0->getSize());
  Line line;
  line.kind = kind;
  line.target = target;
  line.constant = in0->isConstant() ? 1 : 0;
  line.consumeFull = ((in0->getConsume() & fullMask) == fullMask) ? 1 : 0;
  lines.push_back(line);
}

void run(const string &specDirectory,const string &binary)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("my_fwrite");
    // Loader symbols carry no size (fd->getSize() == 0), so the flow range is
    // pinned to the nm -S size of the symbol.
    static const uintb FIXTURE_SIZE = 0x62;
    if (fd == (Funcdata *)0 || fd->getAddress().getOffset() != 0x3460)
      throw std::runtime_error("my_fwrite fixture identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("architecture/compiler identity drifted");

    // Natural processing entry (funcdata.cc:150-168): followFlow (via which
    // FlowInfo::setupCallSpecs attaches a FuncCallSpecs to every call and
    // swaps in(0) for the fspec annotation varnode, flow.cc:683-690),
    // structureReset, sortCallSpecs, heritage.buildInfoList (required
    // before any deadRemovalAllowed query) and applyDeadCodeDelay. This is
    // the pipeline state every Ghidra decompilation runs its actions on.
    fd->startProcessing();

    // PcodeOpBank::begin(OpCode) only indexes STORE/LOAD/RETURN/CALLOTHER
    // (op.cc:1158-1167 returns alivelist.end() otherwise), so CALL/BRANCH/
    // CBRANCH must be collected from the alive list.
    vector<Line> lines;
    list<PcodeOp *>::const_iterator iter,enditer;
    for(iter=fd->beginOpAlive(),enditer=fd->endOpAlive();iter!=enditer;++iter)
      collectLine(*fd,*iter,lines);
    if (lines.size() < 4)
      throw std::runtime_error("my_fwrite expected two calls and two branches");

    FixtureDefaultParams defaultparams;
    defaultparams.apply(*fd);
    FixtureDeadCode deadcode;
    deadcode.apply(*fd);
    FixtureVarnodeProps props;
    props.apply(*fd);

    // Re-collect after the actions; the projection lines are sorted by
    // (kind,target) because bank insertion order differs between the
    // flow-driven oracle builder and the inject-driven Rugra builder.
    lines.clear();
    for(iter=fd->beginOpAlive(),enditer=fd->endOpAlive();iter!=enditer;++iter)
      collectLine(*fd,*iter,lines);
    std::sort(lines.begin(),lines.end());
    for(size_t i=0;i<lines.size();++i) {
      ostringstream stream;
      stream << lines[i].kind << ":0x" << std::hex << lines[i].target
             << " in0_constant=" << std::dec << lines[i].constant
             << " in0_consume_full=" << lines[i].consumeFull;
      std::cout << stream.str() << "\n";
    }
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: coreaction_callin0_clobber_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1],argv[2]);
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
