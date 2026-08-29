/*
 * Locked Ghidra 12.0.4 oracle for FLOW-339E-OVERLAP-HLT-0001: the basic-block
 * graph consequence of falling through a DIRECT call site into an
 * overlapping entry region whose tail is `hlt` (x86 SLEIGH p-code for `hlt`
 * is a BRANCH-to-self, so the byte at the fall-through target forms its own
 * self-loop basic block).
 *
 * This is the seam w-rc4 measured on curl main (oracle 150 blocks vs Rugra
 * 149, missing @339e = the `hlt` after `_start`'s `call *__libc_start_main`):
 * the oracle graph contains blk @3366 out=339e and blk @339e in=[3366,self]
 * out=[self] only because the fixture-oracle data environment leaves the
 * `__stack_chk_fail@plt` callee unmarked. The two cases below isolate that
 * data variable on a minimal reproduction of the curl main tail layout
 * (direct call; 5/4-byte nopl padding; entry-like endbr64 prologue; indirect
 * call through a data slot; hlt; nop):
 *
 *   - ohlt_user_plain: callee FuncProto carries NO analyzer attributes
 *       (the golden_dump_1204 per-function fixture environment:
 *       BfdArchitecture + readLoaderSymbols, no Java-side analyzers).
 *       Expect: 3 blocks; the call block has a fall-through out-edge to the
 *       hlt block; the hlt block is a self-loop (in=[call,self] out=[self]);
 *       no artificial halt op; no warning; callspec noret=0.
 *   - ohlt_user_marked: same machine code, but the callee's FuncProto is
 *       marked setNoReturn(true) first — the "Non-Returning Functions -
 *       Known" analyzer DB attribute of the full-analysis environment
 *       (Ghidra GUI analyzeHeadless; the checked-in ghidra_curl_1204.c
 *       golden). Expect: 2 blocks; flow stops at the call instruction
 *       (checkForFlowModification flow.cc:641-648 inserts the
 *       PcodeOp::noreturn artificial halt right after the CALL); the tail
 *       (nopl..hlt) is never lifted; the "Subroutine does not return"
 *       warning is present; callspec noret=1.
 *
 * Projection, per case: block count, per-block first-op address delta with
 * in/out edge address deltas (BlockGraph::getBlock order), call specs
 * (op/entry deltas, isNoReturn/isInline), warning comments (type, address
 * delta, text), and every op in SeqNum order (address delta, opcode,
 * startbasic, halt-type flags, input(0) token). Address deltas are relative
 * to each function's base so the two sides' Address spelling difference
 * (Rugra's legacy spaceless Address) drops out. Unique-space varnode offsets
 * (SLEIGH per-instruction temporaries) are projected as the bare space name:
 * the offsets are allocator-relative temporaries with no addressable
 * meaning (same normalization class as SeqNum temporaries).
 */

#include "bfd_arch.hh"
#include "flow.hh"
#include "libdecomp.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace ghidra;

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
    if (op->code() == CPUI_LOAD || op->code() == CPUI_STORE)
      return "spc:" + vn->getSpaceFromConst()->getName();
    std::ostringstream s;
    s << "const:" << vn->getOffset();
    return s.str();
  }
  if (spc->getName() == "ram")
    return "ram:" + deltaString(vn->getOffset(), base);
  if (spc->getType() == IPTR_INTERNAL)
    return "unique"; // allocator-relative temporary; offset not observable
  std::ostringstream s;
  s << spc->getName() << ':' << vn->getOffset();
  return s.str();
}

// The first PcodeOp of a block in the raw BlockGraph (after followFlow every
// component is a PcodeBlockBasic), by address delta.
string blockAddrDelta(FlowBlock *bl, const Address &base)
{
  PcodeOp *op = bl->firstOp();
  if (op == (PcodeOp *)0)
    return "none";
  return deltaString(op->getAddr().getOffset(), base);
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

  const BlockGraph &bgraph = fd->getBasicBlocks();
  std::cout << "case=" << name << '\n';
  std::cout << "blocks=" << bgraph.getSize() << '\n';
  for (int4 i = 0; i < bgraph.getSize(); ++i) {
    FlowBlock *bl = bgraph.getBlock(i);
    std::cout << "blk=" << i << " addr=" << blockAddrDelta(bl, base) << " in=[";
    for (int4 j = 0; j < bl->sizeIn(); ++j)
      std::cout << (j ? " " : "") << blockAddrDelta(bl->getIn(j), base);
    std::cout << "] out=[";
    for (int4 j = 0; j < bl->sizeOut(); ++j)
      std::cout << (j ? " " : "") << blockAddrDelta(bl->getOut(j), base);
    std::cout << "]\n";
  }

  std::cout << "calls=" << fd->numCalls() << '\n';
  for (int4 i = 0; i < fd->numCalls(); ++i) {
    const FuncCallSpecs *fc = fd->getCallSpecs(i);
    std::cout << "spec=" << i << " op_delta=";
    writeAddressDelta(fc->getOp()->getAddr(), base);
    std::cout << " entry=";
    writeAddressDelta(fc->getEntryAddress(), base);
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
    const PcodeOp *op = (*oiter).second;
    std::cout << "op=" << opIndex << " addr=";
    writeAddressDelta(op->getAddr(), base);
    std::cout << " opcode=" << static_cast<int4>(op->code())
              << " sb=" << (op->isBlockStart() ? 1 : 0)
              << " halt=" << op->getHaltType()
              << " in0=" << input0Token(op, base) << '\n';
    opIndex += 1;
  }
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

  // The analyzer-side producer, exactly as the wireb fixture drives it: the
  // marked callee's FuncProto bit is set before any caller flow runs.
  Funcdata *marked = architecture.symboltab->getGlobalScope()->queryFunction("ohlt_callee_marked");
  if (marked == (Funcdata *)0)
    throw runtime_error("ohlt_callee_marked not found");
  marked->getFuncProto().setNoReturn(true);

  observeFunction(architecture, "ohlt_user_plain");
  observeFunction(architecture, "ohlt_user_marked");
}

} // anonymous namespace

/*
 * ohlt_user_plain:  cmp/jne over a one-byte nop; call ohlt_callee_plain;
 *                   nopl padding; endbr64; xor ebp; mov r9; call *slot(%rip);
 *                   hlt; nop
 * ohlt_user_marked: byte-identical body against ohlt_callee_marked.
 *
 * The call slots share one .data qword; the CALLIND target is never
 * evaluated by flow, matching curl's `call *__libc_start_main@GOTPCREL`.
 */
extern "C" __attribute__((naked, noinline, used)) void ohlt_user_plain(void)
{
  __asm__ volatile("cmpq $0, %rax\n\t"
                   "jne 2f\n\t"
                   "nop\n\t"
                   "2:\n\t"
                   "call ohlt_callee_plain\n\t"
                   "nopl 0x0(%rax,%rax,1)\n\t"
                   "endbr64\n\t"
                   "xorl %ebp, %ebp\n\t"
                   "movq %rdx, %r9\n\t"
                   "call *ohlt_sink(%rip)\n\t"
                   "hlt\n\t"
                   "nop\n\t");
}

extern "C" __attribute__((naked, noinline, used)) void ohlt_user_marked(void)
{
  __asm__ volatile("cmpq $0, %rax\n\t"
                   "jne 2f\n\t"
                   "nop\n\t"
                   "2:\n\t"
                   "call ohlt_callee_marked\n\t"
                   "nopl 0x0(%rax,%rax,1)\n\t"
                   "endbr64\n\t"
                   "xorl %ebp, %ebp\n\t"
                   "movq %rdx, %r9\n\t"
                   "call *ohlt_sink(%rip)\n\t"
                   "hlt\n\t"
                   "nop\n\t");
}

extern "C" __attribute__((naked, noinline, used)) void ohlt_callee_plain(void)
{
  __asm__ volatile("ret");
}

extern "C" __attribute__((naked, noinline, used)) void ohlt_callee_marked(void)
{
  __asm__ volatile("ret");
}

__asm__(".data\n\t"
        ".align 8\n\t"
        "ohlt_sink: .quad ohlt_callee_plain\n\t"
        ".text\n\t");

int main(int argc, char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: flow_overlap_hlt_1204 SPEC_ROOT FIXTURE_BINARY\n";
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
