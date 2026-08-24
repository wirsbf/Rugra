/*
 * Locked Ghidra 12.0.4 oracle for the flow-side no-return/inline wiring of
 * CALLSPEC-NORETURN-WIRE-0001 slice (b). FlowInfo::queryCall
 * (flow.cc:656-672) must copy the resolved callee's flow effects onto the
 * call site (flow.cc:663-664, copyFlowEffects through the
 * !hasModel()||isInline() gate), FlowInfo::checkForFlowModification
 * (flow.cc:636-652) must turn the propagated bit into an artificial
 * PcodeOp::noreturn halt plus the "Subroutine does not return" warning, and
 * FlowInfo::truncateIndirectJump's fail_callother path (flow.cc:745-750)
 * must mark the truncated callspec setNoReturn(true).
 *
 * Cases (all driven on the same fixture binary):
 *   - wireb_noret_user: calls a callee whose FuncProto is marked
 *       setNoReturn(true) before followFlow. Expect: spec noret=1 inline=0
 *       hasmodel=0 (queryCall copied the callee flags through the
 *       !hasModel() gate), a PcodeOp::noreturn artificial halt dead-inserted
 *       right after the CALL, and the "Subroutine does not return" warning.
 *   - wireb_inline_user: calls ITSELF with its own FuncProto marked
 *       setInline(true). queryCall's `otherfunc->getFuncProto().isInline()`
 *       gate copies the inline bit; checkForFlowModification queues the
 *       injectlist entry; injectPcode's inlineSubFunction (flow.cc:1242)
 *       then refuses the self-recursion ("Could not inline here",
 *       flow.cc:1256-1258) so the spec survives with inline=1 and the CALL
 *       stays. This observes the inline bit propagation without depending
 *       on the (unported) inlineFlow clone machine.
 *   - wireb_plain_user: calls an unmarked callee. Expect: spec bits all
 *       clear, no halt, no warning (the copyFlowEffects channel does not
 *       invent bits).
 *   - truncate_fail_callother: a hand-driven FlowInfo runs
 *       truncateIndirectJump(op, JumpTable::fail_callother) on a constructed
 *       BRANCHIND. Expect: CALLIND opcode, callspec with noret=1, the
 *       "Does not return" warning, and a noreturn artificial halt after the
 *       op.
 *   - copy_flow_effects_oneway: direct FuncCallSpecs lifecycle - set both
 *       bits, copyFlowEffects from a clean proto clears both (one-way
 *       clear-then-OR), from {inline,noret} restores both, from {inline}
 *       alone gives {inline=1, noret=0}.
 *
 * Projection, per case: remaining call specs (op/entry deltas, display
 * name, isNoReturn/isInline/hasModel), warning comments (type, address
 * delta, text), and every op in SeqNum order (address delta, opcode,
 * startbasic, halt-type flags). Case 4 additionally projects the truncated
 * op itself. Address deltas are relative to each function's base so the
 * two sides' Address spelling difference (Rugra's legacy spaceless Address)
 * drops out.
 */

// Fixture-only private-member access: the Funcdata bank members the
// FlowInfo constructor takes are private, and no x86-64 machine instruction
// feeds a JumpTable::fail_callother mode through recoverJumpTables, so the
// fixture drives truncateIndirectJump directly the way the recovery loop
// (flow.cc:1445) would. Access is obtained through explicit template
// instantiation, which is exempt from access checking of template
// arguments (C++11 [temp.explicit]/12); no header is redefined and no ABI
// changes.
#include "bfd_arch.hh"
#include "flow.hh"
#include "jumptable.hh"
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
struct TruncateTag {
  using type = void (FlowInfo::*)(PcodeOp *, JumpTable::RecoveryMode);
};
} // namespace fixture_access

template struct fixture_access::StealInit<fixture_access::ObankTag, &Funcdata::obank>;
template struct fixture_access::StealInit<fixture_access::BblocksTag, &Funcdata::bblocks>;
template struct fixture_access::StealInit<fixture_access::QlstTag, &Funcdata::qlst>;
template struct fixture_access::StealInit<fixture_access::TruncateTag, &FlowInfo::truncateIndirectJump>;

/*
 * wireb_noret_user:  call wireb_callee_noret ; ret
 * wireb_callee_noret: ret
 * wireb_inline_user: call wireb_inline_user ; ret   (self call)
 * wireb_plain_user:  call wireb_callee_plain ; ret
 * wireb_callee_plain: ret
 * wireb_trunc_target: ret   (scratch Funcdata for the direct-drive cases)
 */
extern "C" __attribute__((naked, noinline, used)) void wireb_noret_user(void)
{
  __asm__ volatile("call wireb_callee_noret\n\t"
                   "ret");
}

extern "C" __attribute__((naked, noinline, used)) void wireb_callee_noret(void)
{
  __asm__ volatile("ret");
}

extern "C" __attribute__((naked, noinline, used)) void wireb_inline_user(void)
{
  __asm__ volatile("call wireb_inline_user\n\t"
                   "ret");
}

extern "C" __attribute__((naked, noinline, used)) void wireb_plain_user(void)
{
  __asm__ volatile("call wireb_callee_plain\n\t"
                   "ret");
}

extern "C" __attribute__((naked, noinline, used)) void wireb_callee_plain(void)
{
  __asm__ volatile("ret");
}

extern "C" __attribute__((naked, noinline, used)) void wireb_trunc_target(void)
{
  __asm__ volatile("ret");
}

namespace {

using std::runtime_error;
using std::string;
using std::vector;

string deltaString(uintb offset, const Address &base)
{
  int8 delta = (int8)(offset - base.getOffset());
  std::ostringstream s;
  s << delta;
  return s.str();
}

void writeAddressDelta(const Address &address, const Address &base)
{
  if (address.isInvalid()) {
    std::cout << "invalid";
    return;
  }
  std::cout << static_cast<int8>(address.getOffset() - base.getOffset());
}

string input0Token(const PcodeOp *op, const Address &base)
{
  if (op->numInput() == 0)
    return "none";
  const Varnode *vn = op->getIn(0);
  AddrSpace *spc = vn->getSpace();
  if (spc->getType() == IPTR_FSPEC)
    return "callspec";
  if (spc->getType() == IPTR_CONSTANT) {
    if (op->code() == CPUI_LOAD || op->code() == CPUI_STORE) {
      // The space reference encoded as a constant is a per-run heap
      // pointer on this side and a stable index on the Rugra side; project
      // the referenced space name instead (same normalization as
      // flow_tailcall_overtrace_1204).
      return "spc:" + vn->getSpaceFromConst()->getName();
    }
    std::ostringstream s;
    s << "const:" << vn->getOffset();
    return s.str();
  }
  if (spc->getName() == "ram")
    return "ram:" + deltaString(vn->getOffset(), base);
  std::ostringstream s;
  s << spc->getName() << ':' << vn->getOffset();
  return s.str();
}

void observeFunction(Architecture &architecture, const string &name)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(name);
  if (fd == (Funcdata *)0)
    throw runtime_error("probe function not found: " + name);
  if (fd->hasNoCode())
    throw runtime_error("probe function has no code: " + name);

  AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
  fd->followFlow(Address(codeSpace, 0), Address(codeSpace, codeSpace->getHighest()));
  const Address &base = fd->getAddress();

  std::cout << "case=" << name << '\n';
  std::cout << "calls=" << fd->numCalls() << '\n';
  for (int4 i = 0; i < fd->numCalls(); ++i) {
    const FuncCallSpecs *fc = fd->getCallSpecs(i);
    std::cout << "spec=" << i << " op_delta=";
    writeAddressDelta(fc->getOp()->getAddr(), base);
    std::cout << " entry=";
    writeAddressDelta(fc->getEntryAddress(), base);
    std::cout << " name=" << fc->getName();
    // The slice-(b) observables: the flow-effect bits queryCall's
    // copyFlowEffects propagated (flow.cc:663-664) and the hasModel gate
    // input.
    std::cout << " noret=" << (fc->isNoReturn() ? 1 : 0)
              << " inline=" << (fc->isInline() ? 1 : 0)
              << " hasmodel=" << (fc->hasModel() ? 1 : 0) << '\n';
  }

  CommentSet::const_iterator citer, cend;
  citer = architecture.commentdb->beginComment(base);
  cend = architecture.commentdb->endComment(base);
  int4 warnIndex = 0;
  for (; citer != cend; ++citer) {
    const Comment *comment = *citer;
    uint4 type = comment->getType();
    string typeToken = "other";
    if ((type & Comment::warningheader) != 0)
      typeToken = "warningheader";
    else if ((type & Comment::warning) != 0)
      typeToken = "warning";
    std::cout << "warn=" << warnIndex << " type=" << typeToken << " addr_delta=";
    writeAddressDelta(comment->getAddr(), base);
    std::cout << " text=" << comment->getText() << '\n';
    warnIndex += 1;
  }

  int4 opIndex = 0;
  for (PcodeOpTree::const_iterator oiter = fd->beginOpAll(); oiter != fd->endOpAll(); ++oiter) {
    const PcodeOp *op = (*oiter).second;
    // getHaltType (op.hh:171) projects the halt nibble: the artificial
    // noreturn halt from checkForFlowModification/truncateIndirectJump
    // carries PcodeOp::noreturn (0x1000000).
    std::cout << "op=" << opIndex << " addr=";
    writeAddressDelta(op->getAddr(), base);
    std::cout << " opcode=" << static_cast<int4>(op->code())
              << " sb=" << (op->isBlockStart() ? 1 : 0)
              << " halt=" << op->getHaltType()
              << " in0=" << input0Token(op, base) << '\n';
    opIndex += 1;
  }
}

void observeTruncate(Architecture &architecture, const string &name)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(name);
  if (fd == (Funcdata *)0)
    throw runtime_error("truncate target not found: " + name);

  AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
  const Address base(codeSpace, fd->getAddress().getOffset());

  // The op the jump-table recovery loop would hand to truncateIndirectJump
  // (flow.cc:1443-1445): a BRANCHIND at the target's entry. newOp leaves
  // the op in the dead list (PcodeOpBank::create, op.cc:941-950), exactly
  // like a decoded op before generateBlocks; input(0) is the index varnode
  // a decoded BRANCHIND carries (truncateIndirectJump's
  // data.getCallSpecs(op) reads it, funcdata.cc:490).
  PcodeOp *op = fd->newOp(1, base);
  fd->opSetOpcode(op, CPUI_BRANCHIND);
  fd->opSetInput(op, fd->newConstant(8, 0), 0);

  FlowInfo flow(*fd, fd->*fixture_access::StealResult<fixture_access::ObankTag>::ptr,
                fd->*fixture_access::StealResult<fixture_access::BblocksTag>::ptr,
                fd->*fixture_access::StealResult<fixture_access::QlstTag>::ptr);
  flow.setRange(Address(codeSpace, 0), Address(codeSpace, codeSpace->getHighest()));
  // flow.cc:1445 with JumpTable::fail_callother: the address was formed by
  // CALLOTHER, so the truncated call never returns. truncateIndirectJump is
  // private (flow.hh:140); called through the stolen member pointer.
  (flow.*fixture_access::StealResult<fixture_access::TruncateTag>::ptr)(
      op, JumpTable::fail_callother);

  std::cout << "case=truncate_fail_callother\n";
  std::cout << "calls=" << fd->numCalls() << '\n';
  for (int4 i = 0; i < fd->numCalls(); ++i) {
    const FuncCallSpecs *fc = fd->getCallSpecs(i);
    std::cout << "spec=" << i << " op_delta=";
    writeAddressDelta(fc->getOp()->getAddr(), base);
    std::cout << " entry=";
    writeAddressDelta(fc->getEntryAddress(), base);
    // hasModel is deliberately NOT projected here: the C++ side's noParams
    // arm (flow.cc:757-762) binds glb->defaultfp through setInternal, the
    // Rugra side keeps that arm as CALLSPEC-0001.
    std::cout << " noret=" << (fc->isNoReturn() ? 1 : 0)
              << " inline=" << (fc->isInline() ? 1 : 0) << '\n';
  }

  CommentSet::const_iterator citer, cend;
  citer = architecture.commentdb->beginComment(base);
  cend = architecture.commentdb->endComment(base);
  int4 warnIndex = 0;
  for (; citer != cend; ++citer) {
    const Comment *comment = *citer;
    uint4 type = comment->getType();
    string typeToken = "other";
    if ((type & Comment::warningheader) != 0)
      typeToken = "warningheader";
    else if ((type & Comment::warning) != 0)
      typeToken = "warning";
    std::cout << "warn=" << warnIndex << " type=" << typeToken << " addr_delta=";
    writeAddressDelta(comment->getAddr(), base);
    std::cout << " text=" << comment->getText() << '\n';
    warnIndex += 1;
  }

  int4 opIndex = 0;
  for (PcodeOpTree::const_iterator oiter = fd->beginOpAll(); oiter != fd->endOpAll(); ++oiter) {
    const PcodeOp *o = (*oiter).second;
    std::cout << "op=" << opIndex << " addr=";
    writeAddressDelta(o->getAddr(), base);
    std::cout << " opcode=" << static_cast<int4>(o->code())
              << " sb=" << (o->isBlockStart() ? 1 : 0)
              << " halt=" << o->getHaltType()
              << " in0=" << input0Token(o, base) << '\n';
    opIndex += 1;
  }
}

void observeCopyFlowEffects(Architecture &architecture, const string &name)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(name);
  if (fd == (Funcdata *)0)
    throw runtime_error("copy target not found: " + name);
  AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
  const Address base(codeSpace, fd->getAddress().getOffset());

  PcodeOp *op = fd->newOp(1, base);
  fd->opSetOpcode(op, CPUI_CALLIND);
  fd->opSetInput(op, fd->newConstant(8, 0), 0);

  FuncCallSpecs fc(op);
  fc.setNoReturn(true);
  fc.setInline(true);
  std::cout << "case=copy_flow_effects_oneway\n";
  std::cout << "stage=set_both"
            << " noret=" << (fc.isNoReturn() ? 1 : 0)
            << " inline=" << (fc.isInline() ? 1 : 0) << '\n';
  FuncProto clean;
  fc.copyFlowEffects(clean);
  std::cout << "stage=copy_clean"
            << " noret=" << (fc.isNoReturn() ? 1 : 0)
            << " inline=" << (fc.isInline() ? 1 : 0) << '\n';
  FuncProto both;
  both.setInline(true);
  both.setNoReturn(true);
  fc.copyFlowEffects(both);
  std::cout << "stage=copy_both"
            << " noret=" << (fc.isNoReturn() ? 1 : 0)
            << " inline=" << (fc.isInline() ? 1 : 0) << '\n';
  FuncProto inline_only;
  inline_only.setInline(true);
  fc.copyFlowEffects(inline_only);
  std::cout << "stage=copy_inline_only"
            << " noret=" << (fc.isNoReturn() ? 1 : 0)
            << " inline=" << (fc.isInline() ? 1 : 0) << '\n';
}

void observeBinary(const string &binary)
{
  // BfdArchitecture initialization diagnostics (loader symbol overlap
  // notices, etc.) are captured privately and excluded from the target API
  // observation; only the commentdb projections are observable.
  std::ostringstream diagnostics;
  BfdArchitecture architecture(binary, "default", &diagnostics);
  DocumentStorage store;
  architecture.init(store);
  architecture.readLoaderSymbols("::");

  // The C++ analogue of Rugra's driver-seeded callee_func_protos table: the
  // resolved Funcdata's own FuncProto carries the flow-effect bits that
  // queryCall's copyFlowEffects (flow.cc:664) reads.
  Funcdata *noret = architecture.symboltab->getGlobalScope()->queryFunction("wireb_callee_noret");
  if (noret == (Funcdata *)0)
    throw runtime_error("wireb_callee_noret not found");
  noret->getFuncProto().setNoReturn(true);
  Funcdata *selfinline = architecture.symboltab->getGlobalScope()->queryFunction("wireb_inline_user");
  if (selfinline == (Funcdata *)0)
    throw runtime_error("wireb_inline_user not found");
  selfinline->getFuncProto().setInline(true);

  observeFunction(architecture, "wireb_noret_user");
  observeFunction(architecture, "wireb_inline_user");
  observeFunction(architecture, "wireb_plain_user");
  observeTruncate(architecture, "wireb_trunc_target");
  observeCopyFlowEffects(architecture, "wireb_trunc_target");
}

} // anonymous namespace

int main(int argc, char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: noreturn_wire_b_1204 SPEC_ROOT FIXTURE_BINARY\n";
    return 2;
  }
  try {
    startDecompilerLibrary(vector<string>(1, argv[1]));
    observeBinary(argv[2]);
    shutdownDecompilerLibrary();
    return 0;
  }
  catch (const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch (const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
