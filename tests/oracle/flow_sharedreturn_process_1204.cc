/*
 * Locked Ghidra 12.0.4 consumer fixture for FlowOverride::CALL_RETURN.
 *
 * The fixture uses the pinned curl ELF in two complementary ways:
 *
 *  1. A one-instruction PcodeEmitFd lift calls Funcdata::overrideFlow
 *     directly.  This observes the original PcodeOp pointer, immutable
 *     SeqNum time, and dead-list position before and after the rewrite.  It
 *     also locks opDeadInsertAfter and the synthetic RETURN constant.
 *  2. A fresh FlowInfo runs generateOps/generateBlocks with an Override map
 *     installed before construction.  This observes the production ordering
 *     (query -> lift -> override -> xref): the rewritten CALL owns the
 *     FuncCallSpecs, the synthetic RETURN terminates flow, and the former
 *     external jump target is not visited or recorded as out-of-bounds.
 *
 * hugehelp@0x4a4f and progressbarinit@0x49e7 are positive CALL_RETURN
 * lanes. myprogress@0x365e is a strong negative: its Override map is nonempty
 * (an unrelated entry is present), but the exact site query is NONE and its
 * ordinary intra-function BRANCH must remain unchanged.
 */

#include "bfd_arch.hh"
#include "flow.hh"
#include "libdecomp.hh"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fixture_access {

template <typename Tag>
struct Result {
  static typename Tag::type ptr;
};
template <typename Tag>
typename Tag::type Result<Tag>::ptr;

template <typename Tag, typename Tag::type member>
struct Init {
  static const int value;
};
template <typename Tag, typename Tag::type member>
const int Init<Tag, member>::value = (Result<Tag>::ptr = member, 0);

struct ObankTag { typedef ghidra::PcodeOpBank ghidra::Funcdata::* type; };
struct BblocksTag { typedef ghidra::BlockGraph ghidra::Funcdata::* type; };
struct QlstTag {
  typedef std::vector<ghidra::FuncCallSpecs *> ghidra::Funcdata::* type;
};
struct UnprocessedTag {
  typedef std::vector<ghidra::Address> ghidra::FlowInfo::* type;
};

} // namespace fixture_access

template struct fixture_access::Init<fixture_access::ObankTag,
                                     &ghidra::Funcdata::obank>;
template struct fixture_access::Init<fixture_access::BblocksTag,
                                     &ghidra::Funcdata::bblocks>;
template struct fixture_access::Init<fixture_access::QlstTag,
                                     &ghidra::Funcdata::qlst>;
template struct fixture_access::Init<fixture_access::UnprocessedTag,
                                     &ghidra::FlowInfo::unprocessed>;

namespace {

using namespace ghidra;
using std::runtime_error;
using std::string;
using std::vector;

struct Probe {
  const char *name;
  uintb functionAddress;
  int4 functionSize;
  uintb site;
  uintb mapAddress;
  uint4 mapType;
};

const Probe probes[] = {
  { "hugehelp", 0x4a00, 84, 0x4a4f, 0x4a4f, Override::CALL_RETURN },
  { "progressbarinit", 0x49a0, 94, 0x49e7, 0x49e7, Override::CALL_RETURN },
  { "myprogress", 0x34d0, 497, 0x365e, 0x4a4f, Override::CALL_RETURN }
};

PcodeOpBank &obank(Funcdata *fd)

{
  return fd->*fixture_access::Result<fixture_access::ObankTag>::ptr;
}

BlockGraph &bblocks(Funcdata *fd)

{
  return fd->*fixture_access::Result<fixture_access::BblocksTag>::ptr;
}

vector<FuncCallSpecs *> &qlst(Funcdata *fd)

{
  return fd->*fixture_access::Result<fixture_access::QlstTag>::ptr;
}

const vector<Address> &unprocessed(const FlowInfo &flow)

{
  return flow.*fixture_access::Result<fixture_access::UnprocessedTag>::ptr;
}

const char *opcodeToken(OpCode opcode)

{
  switch(opcode) {
  case CPUI_BRANCH: return "branch";
  case CPUI_CALL: return "call";
  case CPUI_RETURN: return "return";
  default: return "other";
  }
}

const char *overrideToken(uint4 type)

{
  switch(type) {
  case Override::CALL_RETURN: return "callreturn";
  case Override::CALL: return "call";
  case Override::BRANCH: return "branch";
  case Override::RETURN: return "return";
  default: return "none";
  }
}

int4 deadIndex(const Funcdata *fd,const PcodeOp *needle)

{
  int4 index = 0;
  for(list<PcodeOp *>::const_iterator iter=fd->beginOpDead();
      iter!=fd->endOpDead();++iter,++index)
    if (*iter == needle) return index;
  return -1;
}

PcodeOp *findSiteOp(Funcdata *fd,const Address &site,OpCode opcode)

{
  for(PcodeOpTree::const_iterator iter=fd->beginOp(site);
      iter!=fd->endOp(site);++iter) {
    PcodeOp *op = (*iter).second;
    if (op->code() == opcode) return op;
  }
  return (PcodeOp *)0;
}

PcodeOp *nextDead(const Funcdata *fd,const PcodeOp *needle)

{
  for(list<PcodeOp *>::const_iterator iter=fd->beginOpDead();
      iter!=fd->endOpDead();++iter) {
    if (*iter != needle) continue;
    ++iter;
    return iter == fd->endOpDead() ? (PcodeOp *)0 : *iter;
  }
  return (PcodeOp *)0;
}

bool isSyntheticReturn(const PcodeOp *op)

{
  if (op == (const PcodeOp *)0 || op->code() != CPUI_RETURN ||
      op->numInput() != 1)
    return false;
  const Varnode *input = op->getIn(0);
  return input != (const Varnode *)0 && input->isConstant() &&
         input->getSize() == 1 && input->getOffset() == 0;
}

Funcdata *queryFunction(BfdArchitecture &architecture,const Probe &probe)

{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(probe.name);
  if (fd == (Funcdata *)0)
    throw runtime_error(string("function not found: ") + probe.name);
  if (fd->getAddress().getOffset() != probe.functionAddress)
    throw runtime_error(string("function address mismatch: ") + probe.name);
  if (fd->hasNoCode())
    throw runtime_error(string("function has no code: ") + probe.name);
  return fd;
}

struct DirectObservation {
  OpCode rawOpcode;
  string siteSpace;
  uintm rawTime;
  int4 rawDeadIndex;
  uintb rawTarget;
  uint4 query;
  OpCode afterOpcode;
  bool sameIdentity;
  bool sameSeq;
  int4 afterDeadIndex;
  bool hasSynthetic;
  uintm syntheticTime;
  int4 syntheticDeadIndex;
  bool syntheticConstant;
  bool adjacent;
};

DirectObservation observeDirect(const string &binary,const Probe &probe)

{
  BfdArchitecture architecture(binary,"default",&std::cerr);
  DocumentStorage store;
  architecture.init(store);
  architecture.readLoaderSymbols("::");
  Funcdata *fd = queryFunction(architecture,probe);
  AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
  const Address site(codeSpace,probe.site);

  fd->getOverride().insertFlowOverride(Address(codeSpace,probe.mapAddress),
                                       probe.mapType);
  PcodeEmitFd emitter;
  emitter.setFuncdata(fd);
  architecture.translate->oneInstruction(emitter,site);

  PcodeOp *raw = findSiteOp(fd,site,CPUI_BRANCH);
  if (raw == (PcodeOp *)0 || raw->getIn(0)->isConstant())
    throw runtime_error(string("direct lane lacks external BRANCH: ") + probe.name);
  const SeqNum rawSeq(raw->getSeqNum());
  const int4 rawIndex = deadIndex(fd,raw);
  const uintb rawTarget = raw->getIn(0)->getOffset();
  const uint4 query = fd->getOverride().getFlowOverride(site);
  if (query != Override::NONE)
    fd->overrideFlow(site,query);

  PcodeOp *after = query == Override::NONE
      ? findSiteOp(fd,site,CPUI_BRANCH)
      : findSiteOp(fd,site,CPUI_CALL);
  if (after == (PcodeOp *)0)
    throw runtime_error(string("direct lane lacks rewritten primary: ") + probe.name);
  PcodeOp *synthetic = nextDead(fd,after);
  if (synthetic != (PcodeOp *)0 && synthetic->getAddr() != site)
    synthetic = (PcodeOp *)0;

  DirectObservation result;
  result.rawOpcode = CPUI_BRANCH;
  result.siteSpace = rawSeq.getAddr().getSpace()->getName();
  result.rawTime = rawSeq.getTime();
  result.rawDeadIndex = rawIndex;
  result.rawTarget = rawTarget;
  result.query = query;
  result.afterOpcode = after->code();
  result.sameIdentity = (after == raw);
  result.sameSeq = after->getSeqNum() == rawSeq &&
                   after->getAddr() == rawSeq.getAddr();
  result.afterDeadIndex = deadIndex(fd,after);
  result.hasSynthetic = isSyntheticReturn(synthetic);
  result.syntheticTime = result.hasSynthetic ? synthetic->getTime() : 0;
  result.syntheticDeadIndex = result.hasSynthetic ? deadIndex(fd,synthetic) : -1;
  result.syntheticConstant = isSyntheticReturn(synthetic);
  result.adjacent = result.hasSynthetic &&
                    result.syntheticDeadIndex == result.afterDeadIndex + 1;
  return result;
}

struct PipelineObservation {
  bool mapPresent;
  uint4 query;
  OpCode primaryOpcode;
  uintm primaryTime;
  int8 primaryOrder;
  bool hasSynthetic;
  uintm syntheticTime;
  int8 syntheticOrder;
  bool deadAdjacent;
  bool sameBlock;
  bool callspec;
  bool callspecSameOp;
  bool specTarget;
  bool rawTargetVisited;
  bool outOfBounds;
  int4 unprocessedCount;
};

PipelineObservation observePipeline(const string &binary,const Probe &probe,
                                    uintb rawTarget)

{
  BfdArchitecture architecture(binary,"default",&std::cerr);
  DocumentStorage store;
  architecture.init(store);
  architecture.readLoaderSymbols("::");
  Funcdata *fd = queryFunction(architecture,probe);
  AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
  const Address site(codeSpace,probe.site);
  fd->getOverride().insertFlowOverride(Address(codeSpace,probe.mapAddress),
                                       probe.mapType);

  FlowInfo flow(*fd,obank(fd),bblocks(fd),qlst(fd));
  flow.setRange(Address(codeSpace,probe.functionAddress),
                Address(codeSpace,probe.functionAddress + probe.functionSize));
  flow.generateOps();

  const uint4 query = fd->getOverride().getFlowOverride(site);
  const OpCode wanted = query == Override::NONE ? CPUI_BRANCH : CPUI_CALL;
  PcodeOp *primary = findSiteOp(fd,site,wanted);
  if (primary == (PcodeOp *)0)
    throw runtime_error(string("pipeline lane lacks primary op: ") + probe.name);
  PcodeOp *synthetic = nextDead(fd,primary);
  if (synthetic != (PcodeOp *)0 && synthetic->getAddr() != site)
    synthetic = (PcodeOp *)0;
  const bool hasSynthetic = isSyntheticReturn(synthetic);
  const bool adjacent = hasSynthetic &&
                        deadIndex(fd,synthetic) == deadIndex(fd,primary) + 1;

  FuncCallSpecs *spec = primary->code() == CPUI_CALL
      ? fd->getCallSpecs(primary) : (FuncCallSpecs *)0;
  bool targetVisited = true;
  try {
    (void)flow.target(Address(codeSpace,rawTarget));
  }
  catch(const LowlevelError &) {
    targetVisited = false;
  }
  const bool outOfBounds = flow.hasOutOfBounds();
  const int4 unprocessedCount = unprocessed(flow).size();

  // The negative lane stops after generateOps. In this Bfd projection the
  // terminal __stack_chk_fail symbol is not marked no-return, so 0x36c1 is
  // left queued and generateBlocks would fail on that unrelated boundary.
  // Positive CALL_RETURN lanes still complete block generation so their
  // SeqNum::order fields are initialized and observable.
  const bool generatedBlocks = query != Override::NONE;
  if (generatedBlocks)
    flow.generateBlocks();

  PipelineObservation result;
  result.mapPresent = fd->getOverride().hasFlowOverride();
  result.query = query;
  result.primaryOpcode = primary->code();
  result.primaryTime = primary->getTime();
  result.primaryOrder = generatedBlocks
      ? static_cast<int8>(primary->getSeqNum().getOrder()) : -1;
  result.hasSynthetic = hasSynthetic;
  result.syntheticTime = hasSynthetic ? synthetic->getTime() : 0;
  result.syntheticOrder = generatedBlocks && hasSynthetic
      ? static_cast<int8>(synthetic->getSeqNum().getOrder()) : -1;
  result.deadAdjacent = adjacent;
  result.sameBlock = generatedBlocks && hasSynthetic &&
                     primary->getParent() == synthetic->getParent();
  result.callspec = spec != (FuncCallSpecs *)0;
  result.callspecSameOp = result.callspec && spec->getOp() == primary;
  result.specTarget = result.callspec &&
                      spec->getEntryAddress() == Address(codeSpace,rawTarget);
  result.rawTargetVisited = targetVisited;
  result.outOfBounds = outOfBounds;
  result.unprocessedCount = unprocessedCount;
  return result;
}

void printObservation(const Probe &probe,const DirectObservation &direct,
                      const PipelineObservation &pipeline)

{
  const int8 targetDelta = static_cast<int8>(direct.rawTarget) -
                           static_cast<int8>(probe.functionAddress);
  std::cout << "case=" << probe.name << " site_delta="
            << static_cast<int8>(probe.site) -
               static_cast<int8>(probe.functionAddress)
            << " site_space=" << direct.siteSpace << '\n';
  std::cout << "direct raw=" << opcodeToken(direct.rawOpcode)
            << " raw_time=" << direct.rawTime
            << " raw_dead=" << direct.rawDeadIndex
            << " target_delta=" << targetDelta
            << " query=" << overrideToken(direct.query)
            << " after=" << opcodeToken(direct.afterOpcode)
            << " same_identity=" << (direct.sameIdentity ? 1 : 0)
            << " same_seq=" << (direct.sameSeq ? 1 : 0)
            << " after_dead=" << direct.afterDeadIndex
            << " synthetic=" << (direct.hasSynthetic ? 1 : 0)
            << " synthetic_time="
            << (direct.hasSynthetic ? static_cast<int8>(direct.syntheticTime) : -1)
            << " synthetic_dead=" << direct.syntheticDeadIndex
            << " const1_0=" << (direct.syntheticConstant ? 1 : 0)
            << " adjacent=" << (direct.adjacent ? 1 : 0) << '\n';
  std::cout << "pipeline map=" << (pipeline.mapPresent ? 1 : 0)
            << " query=" << overrideToken(pipeline.query)
            << " primary=" << opcodeToken(pipeline.primaryOpcode)
            << " primary_time=" << pipeline.primaryTime
            << " primary_order=" << pipeline.primaryOrder
            << " synthetic=" << (pipeline.hasSynthetic ? 1 : 0)
            << " synthetic_time="
            << (pipeline.hasSynthetic ? static_cast<int8>(pipeline.syntheticTime) : -1)
            << " synthetic_order="
            << pipeline.syntheticOrder
            << " dead_adjacent=" << (pipeline.deadAdjacent ? 1 : 0)
            << " same_block=" << (pipeline.sameBlock ? 1 : 0)
            << " callspec=" << (pipeline.callspec ? 1 : 0);
  // FuncCallSpecs owns a real PcodeOp pointer in Ghidra. Keep this
  // representation class visible: Rugra currently has only an address/index
  // lookup and cannot normalize this identity away. A lane with no callspec
  // has no representation difference to expose.
  if (pipeline.callspec)
    std::cout << " callspec_binding=pointer_identity"
              << " callspec_same_op=" << (pipeline.callspecSameOp ? 1 : 0);
  else
    std::cout << " callspec_binding=none binding_resolves=0";
  std::cout << " spec_target=" << (pipeline.specTarget ? 1 : 0)
            << " target_visited=" << (pipeline.rawTargetVisited ? 1 : 0)
            << " oob=" << (pipeline.outOfBounds ? 1 : 0)
            << " unprocessed=" << pipeline.unprocessedCount << '\n';
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  for(int4 i=0;i<sizeof(probes)/sizeof(probes[0]);++i) {
    DirectObservation direct = observeDirect(binary,probes[i]);
    PipelineObservation pipeline = observePipeline(binary,probes[i],
                                                   direct.rawTarget);
    printObservation(probes[i],direct,pipeline);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: flow_sharedreturn_process_1204 SPEC_ROOT CURL_BINARY\n";
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
