/*
 * Locked Ghidra 12.0.4 oracle for the FlowInfo P-code injection path
 * (flow.cc:1177-1355) and its generateOps wiring (flow.cc:794-795 / 819-820).
 *
 * The locked x86-64 SLEIGH language declares no user-defined p-code ops, so
 * no lifted machine instruction can emit the CALLOTHER that
 * FlowInfo::xrefControlFlow (flow.cc:344-348) would queue on the private
 * injectlist. The fixture therefore seeds one synthetic CALLOTHER per probe
 * directly into a hand-driven FlowInfo (the `#define private public` block
 * below exposes the private injectlist; the Rugra counterpart mirrors this
 * through its documented fixture-observation hook), then runs the REAL
 * generateOps/generateBlocks so the `hasInject()` gates, injectPcode,
 * injectUserOp, doInjection and the whole post-inject bookkeeping execute
 * on genuine lifted p-code.
 *
 * Construction per case (identical on the Rust side):
 *   - payload: PcodeInjectLibrarySleigh::manualCallOtherFixup(opname, "out",
 *     {"in0"}, snippet) — the real SLEIGH snippet compiler;
 *   - userop: UserOpManage::registerOp(new InjectedUserOp(opname, glb,
 *     index, injectid)) with a distinct CALLOTHER index per case;
 *   - CALLOTHER op: newOp(2, probe entry) + newConstant(index) +
 *     newConstant(0x20) inputs + newVarnodeOut(4, ram:0x40) +
 *     startbasic flag (a userop instruction's first op is always an
 *     instruction/block start in a real language);
 *   - FlowInfo flow(fd, obank, bblocks, qlst) + setRange over the default
 *     code space, seeded injectlist, generateOps, generateBlocks.
 *
 *   - inject_cpuid: REAL production path. The x86-64 SLEIGH engine emits
 *                   CALLOTHER(44) for the `cpuid` instruction, so a
 *                   callother-fixup registered through the public
 *                   UserOpManage::manualCallOtherFixup + fd->followFlow
 *                   exercises FlowInfo::xrefControlFlow's CALLOTHER arm
 *                   (flow.cc:344-348) with no fixture seeding at all;
 *                   payload `out = in0;` (single COPY substitution).
 *   - inject_add  : payload `out = in0 + 0x10:4;` (INT_ADD with const
 *                   masking + operand substitution);
 *   - inject_label: payload with an internal conditional branch
 *                   (`if (in0) goto <over>; out = 0x1:4; <over> out = 0x2:4;`)
 *                   exercising label-relative resolution, the xref walk over
 *                   injected control flow, block splitting after the move and
 *                   the multi-op moveSequence.
 *
 * Observation projections, per case: call-spec count, drained-injectlist
 * flag, block graph (ordinals, op counts, ranges, edges), op count and every
 * op in SeqNum order (address delta, time, opcode, startbasic flag, block
 * ordinal, input space:offset tokens, output token).
 */

// Fixture-only private-member access: FlowInfo::injectlist and the
// Funcdata bank members the FlowInfo constructor takes are private, and the
// pinned x86-64 language cannot produce a machine CALLOTHER, so the fixture
// must seed the queue the way SLEIGH-emitted userop instructions would.
// Access is obtained through explicit template instantiation, which is
// exempt from access checking of template arguments (C++11
// [temp.explicit]/12); no header is redefined and no ABI changes.
#include "bfd_arch.hh"
#include "flow.hh"
#include "libdecomp.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace ghidra;

namespace fixture_access {

template <typename Tag>
struct StealResult {
  static typename Tag::type ptr;
};
template <typename Tag>
typename Tag::type StealResult<Tag>::ptr;

template <typename Tag, typename Tag::type member>
struct StealInit {
  static const int init;
};
template <typename Tag, typename Tag::type member>
const int StealInit<Tag, member>::init = (StealResult<Tag>::ptr = member, 0);

struct ObankTag {
  using type = PcodeOpBank Funcdata::*;
};
struct BblocksTag {
  using type = BlockGraph Funcdata::*;
};
struct QlstTag {
  using type = vector<FuncCallSpecs *> Funcdata::*;
};
struct InjectlistTag {
  using type = vector<PcodeOp *> FlowInfo::*;
};
struct RegisterOpTag {
  using type = void (UserOpManage::*)(UserPcodeOp *);
};
} // namespace fixture_access

template struct fixture_access::StealInit<fixture_access::ObankTag, &Funcdata::obank>;
template struct fixture_access::StealInit<fixture_access::BblocksTag, &Funcdata::bblocks>;
template struct fixture_access::StealInit<fixture_access::QlstTag, &Funcdata::qlst>;
template struct fixture_access::StealInit<fixture_access::InjectlistTag, &FlowInfo::injectlist>;
template struct fixture_access::StealInit<fixture_access::RegisterOpTag, &UserOpManage::registerOp>;

extern "C" __attribute__((naked, noinline, used)) void inject_cpuid(void)
{
  __asm__ volatile("cpuid\n\t"
                   "ret");
}

extern "C" __attribute__((naked, noinline, used)) void inject_add(void)
{
  __asm__ volatile("xor %eax,%eax\n\t"
                   "xor %ebx,%ebx\n\t"
                   "ret");
}

extern "C" __attribute__((naked, noinline, used)) void inject_label(void)
{
  __asm__ volatile("xor %eax,%eax\n\t"
                   "xor %ebx,%ebx\n\t"
                   "xor %ecx,%ecx\n\t"
                   "ret");
}

namespace {

int4 ordinalOf(const vector<FlowBlock *> &blocks, const FlowBlock *needle)

{
  for(int4 i=0;i<blocks.size();++i)
    if (blocks[i] == needle) return i;
  return -1;
}

int4 opCount(const FlowBlock *block)

{
  const BlockBasic *basic = dynamic_cast<const BlockBasic *>(block);
  if (basic == (const BlockBasic *)0) return -1;
  int4 count = 0;
  for(list<PcodeOp *>::const_iterator iter=basic->beginOp();iter!=basic->endOp();++iter)
    count += 1;
  return count;
}

std::string deltaString(uintb offset, const Address &base)

{
  int8 delta = (int8)(offset - base.getOffset());
  std::ostringstream s;
  s << delta;
  return s.str();
}

std::string offsetHex(uintb offset)

{
  std::ostringstream s;
  s << std::hex << offset;
  return s.str();
}

// A LOAD/STORE space reference is encoded as a constant holding an
// AddrSpace heap pointer (per-run value); project the referenced space name
// instead, exactly like the flow_containedcall_1204 fixture.
std::string spaceToken(const Varnode *vn, bool spaceRef = false)

{
  if (vn == (const Varnode *)0)
    return "none";
  AddrSpace *spc = vn->getSpace();
  if (spc->getType() == IPTR_CONSTANT) {
    if (spaceRef)
      return "spc:" + vn->getSpaceFromConst()->getName();
    return "const:0x" + offsetHex(vn->getOffset());
  }
  return spc->getName() + ":0x" + offsetHex(vn->getOffset());
}

std::string edgeList(const vector<FlowBlock *> &blocks, const FlowBlock *bl, bool outgoing)

{
  std::ostringstream s;
  const int4 count = outgoing ? bl->sizeOut() : bl->sizeIn();
  s << '[';
  for(int4 slot=0;slot<count;++slot) {
    if (slot != 0) s << ',';
    const FlowBlock *peer = outgoing ? bl->getOut(slot) : bl->getIn(slot);
    const int4 reverse = outgoing ? bl->getOutRevIndex(slot) : bl->getInRevIndex(slot);
    s << ordinalOf(blocks,peer) << ':' << reverse;
  }
  s << ']';
  return s.str();
}

struct CaseSpec {
  const char *func;        // probe symbol
  const char *opname;      // userop name
  int4 userop_index;       // CALLOTHER constant id in input(0)
  const char *snippet;     // payload p-code source
};

const CaseSpec CASES[] = {
  { "inject_cpuid", "cpuid", 44, "out = in0;" },
  { "inject_add", "inject_add_op", 2001, "out = in0 + 0x10:4;" },
  { "inject_label", "inject_label_op", 2002,
    "if (in0) goto <over>; out = 0x1:4; <over> out = 0x2:4;" },
};

void observeCase(BfdArchitecture &architecture, const CaseSpec &spec)

{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(spec.func);
  if (fd == (Funcdata *)0)
    throw std::runtime_error(string("probe function not found: ") + spec.func);
  if (fd->hasNoCode())
    throw std::runtime_error(string("probe function has no code: ") + spec.func);

  vector<string> inname(1, "in0");
  const Address &base = fd->getAddress();
  bool pending = false;
  if (spec.userop_index == 44) {
    // Production path: the engine already registered the unspecialized
    // "cpuid" op from the .sla userop table (UserOpManage::initialize), and
    // manualCallOtherFixup (userop.cc:628-646) allocates the payload and
    // customizes the descriptor into an InjectedUserOp. Flow is then driven
    // by the ordinary Funcdata::followFlow - xrefControlFlow's CALLOTHER arm
    // (flow.cc:344-348) queues the injection on its own.
    architecture.userops.manualCallOtherFixup(spec.opname, "out", inname,
                                              spec.snippet, &architecture);
    fd->followFlow(Address(architecture.getDefaultCodeSpace(), 0),
                   Address(architecture.getDefaultCodeSpace(),
                           architecture.getDefaultCodeSpace()->getHighest()));
    pending = false;
  }
  else {
  // Seeded path: payload via the real SLEIGH snippet compiler
  // (inject_sleigh.cc:504-518), descriptor via explicit-instantiation
  // access to UserOpManage::registerOp (no public registration route for a
  // synthetic index exists).
  int4 injectid = architecture.pcodeinjectlib->manualCallOtherFixup(
      spec.opname, "out", inname, spec.snippet);
  InjectedUserOp *userop = new InjectedUserOp(spec.opname, &architecture,
                                              spec.userop_index, injectid);
  (architecture.userops.*fixture_access::StealResult<fixture_access::RegisterOpTag>::ptr)(userop);

  AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
  AddrSpace *ramSpace = codeSpace;

  // Synthetic CALLOTHER at the probe entry: index, one 4-byte constant
  // operand, output in ram:0x40, block-start flagged (a userop
  // instruction's first op is an instruction start in a real language).
  PcodeOp *callother = fd->newOp(2, base);
  fd->opSetOpcode(callother, CPUI_CALLOTHER);
  fd->opSetInput(callother, fd->newConstant(4, spec.userop_index), 0);
  fd->opSetInput(callother, fd->newConstant(4, 0x20), 1);
  fd->newVarnodeOut(4, Address(ramSpace, 0x40), callother);
  fd->opMarkStartBasic(callother);

  // Hand-driven FlowInfo over the real function (funcdata_op.cc:767-777),
  // with the injectlist seeded before generation.
  FlowInfo flow(*fd, fd->*fixture_access::StealResult<fixture_access::ObankTag>::ptr,
                fd->*fixture_access::StealResult<fixture_access::BblocksTag>::ptr,
                fd->*fixture_access::StealResult<fixture_access::QlstTag>::ptr);
  flow.setRange(Address(codeSpace, 0), Address(codeSpace, codeSpace->getHighest()));
  flow.setMaximumInstructions(100000);
  (flow.*fixture_access::StealResult<fixture_access::InjectlistTag>::ptr).push_back(callother);
  flow.generateOps();
  flow.generateBlocks();
  pending = flow.hasInject();
  }

  std::cout << "case=" << spec.func << '\n';
  std::cout << "callspecs=" << fd->numCalls() << '\n';
  std::cout << "inject_pending=" << (pending ? 1 : 0) << '\n';

  const BlockGraph &graph = fd->getBasicBlocks();
  const vector<FlowBlock *> &blocks = graph.getList();
  std::cout << "blocks=" << blocks.size()
            << " entry=" << ordinalOf(blocks, graph.getStartBlock()) << '\n';
  for(int4 i=0;i<blocks.size();++i) {
    const FlowBlock *block = blocks[i];
    std::cout << "block=" << i
              << " ops=" << opCount(block)
              << " d0=" << deltaString(block->getStart().getOffset(), base)
              << " d1=" << deltaString(block->getStop().getOffset(), base)
              << " in=" << edgeList(blocks, block, false)
              << " out=" << edgeList(blocks, block, true)
              << '\n';
  }

  int4 total = 0;
  for(PcodeOpTree::const_iterator oiter = fd->beginOpAll();oiter != fd->endOpAll();++oiter)
    total += 1;
  std::cout << "ops=" << total << '\n';
  int4 opIndex = 0;
  for(PcodeOpTree::const_iterator oiter = fd->beginOpAll();oiter != fd->endOpAll();++oiter) {
    const PcodeOp *op = (*oiter).second;
    const bool spaceRef = (op->code() == CPUI_LOAD) || (op->code() == CPUI_STORE);
    std::cout << "op=" << opIndex
              << " d=" << deltaString(op->getAddr().getOffset(), base)
              << " t=" << op->getSeqNum().getTime()
              << " opc=" << static_cast<int4>(op->code())
              << " sb=" << (op->isBlockStart() ? 1 : 0)
              << " blk=" << ordinalOf(blocks, op->getParent())
              << " in0=" << spaceToken(op->getIn(0), spaceRef)
              << " in1=" << spaceToken(op->numInput() > 1 ? op->getIn(1) : (const Varnode *)0, spaceRef)
              << " out=" << spaceToken(op->getOut())
              << '\n';
    opIndex += 1;
  }
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: flow_inject_1204 SPEC_ROOT FIXTURE_BINARY\n";
    return 2;
  }
  try {
    startDecompilerLibrary(vector<string>(1,argv[1]));
    for(int4 i=0;i<3;++i)
      {
        std::ostringstream diagnostics;
        BfdArchitecture architecture(argv[2],"default",&diagnostics);
        DocumentStorage store;
        architecture.init(store);
        architecture.readLoaderSymbols("::");
        observeCase(architecture, CASES[i]);
      }
    shutdownDecompilerLibrary();
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
