/*
 * Locked Ghidra 12.0.4 oracle for FlowInfo::checkContainedCall (flow.cc:1361).
 *
 * Probe functions exercise every branch of the call-containment check.
 * NOTE: the shared x86 SLEIGH spec has a "call with zero displacement is a
 * goto" rule (ia.sinc:2953 `:CALL rel32 is ... simm32=0 & rel32 { ...
 * goto rel32; }`), so probes that want to reach checkContainedCall must use
 * internal call targets with NON-zero displacement. The getpc/mid probes
 * deliberately hit the spec's goto rule instead (no spec is ever created),
 * locking that no spurious warnings appear on that path.
 *
 *   - getpc    : call to the next instruction -> SLEIGH goto (BRANCH at
 *                emission, zero specs, no warnings);
 *   - mid      : same, with further ops in the target block;
 *   - fwd      : forward internal call (non-zero displacement) -> converted
 *                by checkContainedCall, following-op block split;
 *   - offcut   : call target inside a visited instruction -> warning only;
 *   - beyond   : call target past the end of the last visited instruction
 *                below it -> silent skip (flow.cc:1377-1378);
 *   - multi    : two internal calls; the erased spec's successor is skipped
 *                by the for-header ++iter quirk, so the second call survives
 *                as CPUI_CALL with its callspec;
 *   - back     : converted call targeting an earlier decoded instruction;
 *   - afterc   : converted call followed by a conditional branch in what
 *                becomes a new (unreachable) block;
 *   - before   : call target below every visited address (upper_bound ==
 *                visited.begin() skip, flow.cc:1375);
 *   - callind  : register-indirect call (opcode != CPUI_CALL skip);
 *   - extern   : call to a real symbol (callee Funcdata resolved -> the
 *                flow.cc:1367-1368 skip).
 *
 * The observation projects, per case: remaining call specs (op/entry
 * deltas), warning comments (type, attach address delta, text projection),
 * the block graph (ordinals, ops, ranges, edges) and every op in SeqNum
 * order (opcode, startbasic flag, block ordinal, input(0) space class).
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" __attribute__((naked, noinline, used)) void containedcall_getpc(void)
{
  __asm__ volatile(
      "call 1f\n"
      "1:\n\t"
      "pop %rax\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_mid(void)
{
  __asm__ volatile(
      "nop\n\t"
      "call 1f\n"
      "1:\n\t"
      "nop\n\t"
      "nop\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_fwd(void)
{
  __asm__ volatile(
      "test %edi,%edi\n\t"
      "je 1f\n\t"
      "call 1f\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n\t"
      "nop\n"
      "1:\n\t"
      "nop\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_offcut(void)
{
  __asm__ volatile(
      "test %edi,%edi\n\t"
      "je 1f\n\t"
      "call 2f\n\t"
      "ret\n"
      "1:\n\t"
      ".byte 0x8b\n"
      "2:\n\t"
      ".byte 0x40, 0x00\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_beyond(void)
{
  __asm__ volatile(
      "test %edi,%edi\n\t"
      "je 1f\n\t"
      "call 2f\n\t"
      "ret\n"
      "1:\n\t"
      "ret $16\n"
      "2:\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_multi(void)
{
  __asm__ volatile(
      "call 3f\n\t"
      "call 3f\n\t"
      "nop\n"
      "3:\n\t"
      "nop\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_back(void)
{
  __asm__ volatile(
      "test %edi,%edi\n\t"
      "je 1f\n\t"
      "jmp 2f\n"
      "1:\n\t"
      "pop %rbx\n\t"
      "ret\n"
      "2:\n\t"
      "call 1b\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_afterc(void)
{
  __asm__ volatile(
      "test %edi,%edi\n\t"
      "je 1f\n\t"
      "jmp 2f\n"
      "1:\n\t"
      "pop %rcx\n\t"
      "ret\n"
      "2:\n\t"
      "call 1b\n\t"
      "test %esi,%esi\n\t"
      "je 1b\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_pad(void)
{
  __asm__ volatile(
      ".byte 0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc\n\t"
      ".byte 0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc\n\t"
      ".byte 0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc\n\t"
      ".byte 0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc");
}

/* e8 eb ff ff ff : call rel32(-0x15) -> target = entry-0x10, inside the pad
 * above (never a symbol start, never decoded). */
extern "C" __attribute__((naked, noinline, used)) void containedcall_before(void)
{
  __asm__ volatile(
      ".byte 0xe8, 0xeb, 0xff, 0xff, 0xff\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_callind(void)
{
  __asm__ volatile(
      "call *%rax\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_helper(void)
{
  __asm__ volatile("ret");
}

extern "C" __attribute__((naked, noinline, used)) void containedcall_extern(void)
{
  __asm__ volatile(
      "call containedcall_helper\n\t"
      "ret");
}

namespace {

using namespace ghidra;
using std::runtime_error;
using std::string;
using std::vector;

int4 ordinalOf(const vector<FlowBlock *> &blocks,const FlowBlock *needle)

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

string deltaString(uintb offset,const Address &base)

{
  int8 delta = (int8)(offset - base.getOffset());
  std::ostringstream s;
  s << delta;
  return s.str();
}

void writeAddressDelta(const Address &address,const Address &base)

{
  if (address.isInvalid()) {
    std::cout << "invalid";
    return;
  }
  std::cout << static_cast<int8>(address.getOffset() - base.getOffset());
}

void writeEdges(const vector<FlowBlock *> &blocks,const FlowBlock *block,bool outgoing)

{
  const int4 count = outgoing ? block->sizeOut() : block->sizeIn();
  std::cout << '[';
  for(int4 slot=0;slot<count;++slot) {
    if (slot != 0) std::cout << ',';
    const FlowBlock *peer = outgoing ? block->getOut(slot) : block->getIn(slot);
    const int4 reverse = outgoing ? block->getOutRevIndex(slot) : block->getInRevIndex(slot);
    std::cout << ordinalOf(blocks,peer) << ':' << reverse;
  }
  std::cout << ']';
}

/* Project a warning comment's text deterministically: the PIC header text
 * embeds the call address via Address::printRaw (space-prefixed), whose
 * spelling is a known Rugra infra gap (spaceless legacy Address). Both
 * sides therefore project the embedded address to a base-relative delta. */
string projectText(const string &text,const Address &base)

{
  static const char *picPrefix = "WARNING: Possible PIC construction at ";
  static const char *picSuffix = ": Changing call to branch";
  if (text.compare(0,strlen(picPrefix),picPrefix) == 0 &&
      text.size() > strlen(picPrefix) + strlen(picSuffix) &&
      text.compare(text.size() - strlen(picSuffix),strlen(picSuffix),picSuffix) == 0) {
    string token = text.substr(strlen(picPrefix),
                                text.size() - strlen(picPrefix) - strlen(picSuffix));
    string digits = token;
    const char *names[] = { "ram:", "register:", "unique:", "const:", "stack:" };
    for(int4 i=0;i<5;++i) {
      string prefix = names[i];
      if (digits.compare(0,prefix.size(),prefix) == 0) {
        digits = digits.substr(prefix.size());
        break;
      }
    }
    uintb offset = strtoull(digits.c_str(),(char **)0,16);
    return "pic:" + deltaString(offset,base);
  }
  if (text == "WARNING: Call to offcut address within same function")
    return "offcut";
  return text;
}

string input0Token(const PcodeOp *op,const Address &base)

{
  if (op->numInput() == 0) return "none";
  const Varnode *vn = op->getIn(0);
  AddrSpace *spc = vn->getSpace();
  if (spc->getType() == IPTR_FSPEC)
    return "callspec";
  if (spc->getType() == IPTR_CONSTANT) {
    if (op->code() == CPUI_LOAD || op->code() == CPUI_STORE) {
      // The space reference encoded as a constant is a heap pointer whose
      // value varies per run; project the referenced space name instead.
      return "spc:" + vn->getSpaceFromConst()->getName();
    }
    std::ostringstream s;
    s << "const:" << vn->getOffset();
    return s.str();
  }
  if (spc->getName() == "ram")
    return "ram:" + deltaString(vn->getOffset(),base);
  std::ostringstream s;
  s << spc->getName() << ':' << vn->getOffset();
  return s.str();
}

void observe(Architecture &architecture,const string &name)

{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(name);
  if (fd == (Funcdata *)0)
    throw runtime_error("probe function not found: " + name);
  if (fd->hasNoCode())
    throw runtime_error("probe function has no code: " + name);

  AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
  fd->followFlow(Address(codeSpace,0),Address(codeSpace,codeSpace->getHighest()));
  const Address &base = fd->getAddress();

  std::cout << "case=" << name << '\n';
  std::cout << "calls=" << fd->numCalls() << '\n';
  for(int4 i=0;i<fd->numCalls();++i) {
    const FuncCallSpecs *fc = fd->getCallSpecs(i);
    std::cout << "spec=" << i << " op_delta=";
    writeAddressDelta(fc->getOp()->getAddr(),base);
    std::cout << " entry=";
    writeAddressDelta(fc->getEntryAddress(),base);
    std::cout << '\n';
  }

  CommentSet::const_iterator citer, cend;
  citer = architecture.commentdb->beginComment(base);
  cend = architecture.commentdb->endComment(base);
  int4 warnIndex = 0;
  for(;citer!=cend;++citer) {
    const Comment *comment = *citer;
    uint4 type = comment->getType();
    string typeToken = "other";
    if ((type & Comment::warningheader) != 0)
      typeToken = "warningheader";
    else if ((type & Comment::warning) != 0)
      typeToken = "warning";
    std::cout << "warn=" << warnIndex << " type=" << typeToken << " addr_delta=";
    writeAddressDelta(comment->getAddr(),base);
    std::cout << " text=" << projectText(comment->getText(),base) << '\n';
    warnIndex += 1;
  }

  const BlockGraph &graph = fd->getBasicBlocks();
  const vector<FlowBlock *> &blocks = graph.getList();
  FlowBlock *entry = graph.getStartBlock();
  int4 entryCount = 0;
  for(int4 i=0;i<blocks.size();++i)
    if (blocks[i]->isEntryPoint()) entryCount += 1;

  std::cout << "blocks=" << blocks.size()
            << " entry_ordinal=" << ordinalOf(blocks,entry)
            << " entry_count=" << entryCount << '\n';
  for(int4 i=0;i<blocks.size();++i) {
    const FlowBlock *block = blocks[i];
    std::cout << "block=" << i
              << " ops=" << opCount(block)
              << " start=";
    writeAddressDelta(block->getStart(),base);
    std::cout << " stop=";
    writeAddressDelta(block->getStop(),base);
    std::cout << " in=";
    writeEdges(blocks,block,false);
    std::cout << " out=";
    writeEdges(blocks,block,true);
    std::cout << '\n';
  }

  int4 opIndex = 0;
  for(PcodeOpTree::const_iterator oiter = fd->beginOpAll();oiter != fd->endOpAll();++oiter) {
    const PcodeOp *op = (*oiter).second;
    std::cout << "op=" << opIndex
              << " blk=" << ordinalOf(blocks,op->getParent())
              << " opcode=" << static_cast<int4>(op->code())
              << " sb=" << (op->isBlockStart() ? 1 : 0)
              << " in0=" << input0Token(op,base)
              << '\n';
    opIndex += 1;
  }
}

void observeBinary(const string &binary,const string &functionName)

{
  // BfdArchitecture initialization diagnostics (loader symbol overlap
  // notices, etc.) are captured privately and excluded from the target API
  // observation; only the commentdb projections are observable.
  std::ostringstream diagnostics;
  BfdArchitecture architecture(binary,"default",&diagnostics);
  DocumentStorage store;
  architecture.init(store);
  architecture.readLoaderSymbols("::");
  observe(architecture,functionName);
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: flow_containedcall_1204 SPEC_ROOT FIXTURE_BINARY\n";
    return 2;
  }
  try {
    startDecompilerLibrary(vector<string>(1,argv[1]));
    static const char *cases[] = {
      "containedcall_getpc", "containedcall_mid", "containedcall_fwd",
      "containedcall_offcut", "containedcall_beyond", "containedcall_multi",
      "containedcall_back", "containedcall_afterc", "containedcall_before",
      "containedcall_callind", "containedcall_extern",
    };
    for(int4 i=0;i<11;++i)
      observeBinary(argv[2],cases[i]);
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
