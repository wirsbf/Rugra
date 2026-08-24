/*
 * Locked Ghidra 12.0.4 oracle for the tail-call over-trace scenario behind
 * FLOW-TAILCALL-OVERTRACE-0001: flow follows a tail jump into another
 * function body (visited gains the callee's entry and body), and the
 * functions then contain direct calls whose entry addresses ARE visited
 * instruction starts. FlowInfo::queryCall (flow.cc:656-672) resolves those
 * callees through the loader symbol table, so FlowInfo::checkContainedCall
 * (flow.cc:1361-1405) must skip them via the `fd != (Funcdata *)0` guard at
 * flow.cc:1367-1368 — no "Possible PIC construction" warning may fire even
 * though the call targets are visited instruction starts.
 *
 *   - tailjmp_sym: A conditionally tail-jumps into B's entry (flow follows
 *       the branch, visited gains B), then calls B directly, and B calls A
 *       back (A's entry is trivially visited). Every spec resolves via
 *       readLoaderSymbols: three surviving specs, zero warnings, both call
 *       ops keep CPUI_CALL.
 *   - tailjmp_offcut control: same shape but the direct call targets an
 *       interior (non-symbol) address that is a visited instruction start —
 *       no queryFunction hit, so checkContainedCall converts CALL->BRANCH
 *       and emits the PIC warning (locks that the fix did not merely
 *       silence the whole check).
 *
 * The observation projects, per case: remaining call specs (op/entry
 * deltas), warning comments (type, attach address delta, projected text),
 * the block graph (ordinals, ops, ranges, edges) and every op in SeqNum
 * order (opcode, address delta, startbasic flag, block ordinal, input(0)
 * space class). The op address deltas and block ranges make the visited
 * pollution (callee body traced from the caller) observable without access
 * to FlowInfo's private visited map.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * A (tailover_sym_user):
 *   test %edi,%edi
 *   je   1f                  ; skip the tail jump
 *   jmp  tailover_sym_callee ; tail jump into B: flow follows it, visited
 *                            ; gains B's entry and body
 * 1:call tailover_sym_callee ; direct call, entry IS a visited start (the
 *                            ; same address traced via the jmp above)
 *   ret
 * B (tailover_sym_callee):
 *   call tailover_sym_user   ; recursion: A's entry is trivially visited
 *   ret
 */
extern "C" __attribute__((naked, noinline, used)) void tailover_sym_user(void)
{
  __asm__ volatile(
      "test %edi,%edi\n\t"
      "je 1f\n\t"
      "jmp tailover_sym_callee\n"
      "1:\n\t"
      "call tailover_sym_callee\n\t"
      "ret");
}

extern "C" __attribute__((naked, noinline, used)) void tailover_sym_callee(void)
{
  __asm__ volatile(
      "call tailover_sym_user\n\t"
      "ret");
}

/*
 * Control: same tail jump, but the direct call targets an interior label
 * (not a symbol start, never resolvable by queryFunction) that is a visited
 * instruction start because flow traced it through the fall-through body.
 * checkContainedCall must convert this one to BRANCH with the PIC warning.
 *
 * offcut_user:
 *   test %edi,%edi
 *   je   1f
 *   jmp  2f                ; tail jump to the shared interior block
 * 1:call 2f                ; direct call to a visited non-symbol start
 *   ret
 * 2:nop                    ; visited interior target (start of an
 *   ret                    ; instruction, never a symbol)
 */
extern "C" __attribute__((naked, noinline, used)) void tailover_offcut_user(void)
{
  __asm__ volatile(
      "test %edi,%edi\n\t"
      "je 1f\n\t"
      "jmp 2f\n"
      "1:\n\t"
      "call 2f\n\t"
      "ret\n"
      "2:\n\t"
      "nop\n\t"
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
    // setFuncdata (fspec.cc:4957-4958) copies the resolved callee's display
    // name onto the spec, which is the observable of queryCall's hit on both
    // sides (Rugra: query_call -> FuncCallSpecs::set_funcdata).
    std::cout << " name=" << fc->getName();
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
              << " addr=";
    writeAddressDelta(op->getAddr(),base);
    std::cout << " blk=" << ordinalOf(blocks,op->getParent())
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
    std::cerr << "usage: flow_tailcall_overtrace_1204 SPEC_ROOT FIXTURE_BINARY\n";
    return 2;
  }
  try {
    startDecompilerLibrary(vector<string>(1,argv[1]));
    static const char *cases[] = {
      "tailover_sym_user", "tailover_offcut_user",
    };
    for(int4 i=0;i<2;++i)
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
