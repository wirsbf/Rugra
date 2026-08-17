/*
 * Locked Ghidra 12.0.4 RuleLoadVarnode::correctSpacebase /
 * RuleStoreVarnode::applyOp spacebase-registry oracle.
 *
 * PRINTC-INPUTREG-DEADSTORE-0001: the prologue STORE form
 * `STORE(ram, INT_ADD(RSP_input, const), v)` must resolve through
 * Architecture::getSpaceBySpacebase (architecture.cc:264-282) and the
 * contain check `assoc->getContain() != spc` (ruleaction.cc:4181) and be
 * rewritten into a stack-space COPY with setStackStore (ruleaction.cc:4333).
 *
 * Every case records the real rule call's return value and the
 * target-relevant structural state of the STORE/LOAD op immediately after:
 * opcode, input count, stable observations of slot-0/slot-1 varnodes, the
 * output varnode (space/offset/size/stack-store flag), and — one level deep —
 * the defining opcode of a unique-space address operand. Unique-space offsets
 * and raw space-id constants are deliberately NOT observed (allocation-only
 * temporaries / side-specific encodings). The registry itself is observed via
 * the stack space's contain link and spacebase record.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

/// Stable observation of one varnode (or '-' for null).
string vnState(const Varnode *vn)
{
  if (vn == (const Varnode *)0)
    return string("-");
  ostringstream out;
  if (vn->isConstant()) {
    out << "const:" << vn->getSize();
    return out.str();
  }
  AddrSpace *spc = vn->getSpace();
  if (spc->getType() == IPTR_INTERNAL) {
    out << "unique:def=";
    const PcodeOp *def = vn->getDef();
    if (def == (const PcodeOp *)0)
      out << "nodef";
    else
      out << def->getOpcode()->getName();
    return out.str();
  }
  out << spc->getName() << ':' << std::hex << vn->getOffset() << std::dec
      << ':' << vn->getSize();
  return out.str();
}

/// Stable observation of one op: opcode, input count, slot observations,
/// output observation and the stack-store flag.
string opState(const PcodeOp *op)
{
  ostringstream out;
  out << op->getOpcode()->getName()
      << ",ins=" << op->numInput()
      << ",a0=" << vnState(op->getIn(0))
      << ",a1=" << (op->numInput() > 1 ? vnState(op->getIn(1)) : string("-"));
  const Varnode *res = op->getOut();
  if (res == (const Varnode *)0) {
    out << ",out=-,ss=0";
  }
  else {
    out << ",out=" << vnState(res)
        << ",ss=" << (res->isStackStore() ? 1 : 0);
  }
  return out.str();
}

/// Per-case builder shared by the STORE and LOAD case families.
class Fixture {
  Funcdata &fd;
  BlockBasic *block;

public:
  explicit Fixture(Funcdata &func)
    : fd(func), block((BlockBasic *)0)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    block = graph.newBlockBasic(&fd);
  }

  Varnode *makeInput(int4 size,AddrSpace *spc,uintb offset)
  {
    return fd.setInputVarnode(fd.newVarnode(size,spc,offset));
  }

  PcodeOp *makeOp(OpCode opcode,int4 inputs,int4 outputSize)
  {
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(inputs,Address(codeSpace,0x1000));
    fd.opSetOpcode(op,opcode);
    if (outputSize > 0)
      fd.newUniqueOut(outputSize,op);
    fd.opInsertEnd(op,block);
    return op;
  }

  void setInput(PcodeOp *op,Varnode *vn,int4 slot)
  {
    fd.opSetInput(op,vn,slot);
  }
};

/// Build `INT_ADD(a, b)` (or a COPY of a) with a unique output, and mark the
/// spacebase flags the way the real pipeline does (Funcdata::spacebase,
/// funcdata.cc:230-269, ActionSpacebase runs before oppool2 in the mainloop).
/// \param fd is the (cleared) function
/// \param rsp is the freshly created stack-pointer input varnode
/// \param markBase triggers the fd.spacebase() flagging pass
void markSpacebase(Funcdata &fd,Varnode *rsp)
{
  fd.spacebase();
  if (!rsp->isSpacebase())
    throw std::runtime_error("fixture stack pointer did not get the spacebase flag");
}

void dump(const string &caseName,int4 result,const PcodeOp *op)
{
  std::cout << "case=" << caseName
            << "|result=" << result
            << "|op=" << opState(op) << '\n';
}

/// Case 2/3/4 family: STORE(loadspc, addrchain, v) with the named address
/// chain form; case 5 reuses it with loadspace=stack (contain mismatch).
void runStoreAddCase(Funcdata &fd,const string &name,AddrSpace *loadspace,
                     int4 chainKind,uintb chainConst)
{
  fd.clear();
  Fixture fixture(fd);
  AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
  Varnode *v = fixture.makeInput(8,registerSpace,0x100);
  Varnode *rsp = fixture.makeInput(8,registerSpace,0x20);
  Varnode *addr;
  if (chainKind == 0) {
    addr = rsp;                     // spacebase alone (val == 0)
  }
  else if (chainKind == 1) {        // INT_ADD(RSP, const)
    PcodeOp *add = fixture.makeOp(CPUI_INT_ADD,2,8);
    fixture.setInput(add,rsp,0);
    fixture.setInput(add,fd.newConstant(8,chainConst),1);
    addr = add->getOut();
  }
  else if (chainKind == 2) {        // INT_ADD(const, RSP)
    PcodeOp *add = fixture.makeOp(CPUI_INT_ADD,2,8);
    fixture.setInput(add,fd.newConstant(8,chainConst),0);
    fixture.setInput(add,rsp,1);
    addr = add->getOut();
  }
  else if (chainKind == 3) {        // INT_ADD(INT_ADD(RSP,c1),c2): written base
    PcodeOp *inner = fixture.makeOp(CPUI_INT_ADD,2,8);
    fixture.setInput(inner,rsp,0);
    fixture.setInput(inner,fd.newConstant(8,chainConst),1);
    PcodeOp *outer = fixture.makeOp(CPUI_INT_ADD,2,8);
    fixture.setInput(outer,inner->getOut(),0);
    fixture.setInput(outer,fd.newConstant(8,8),1);
    addr = outer->getOut();
  }
  else {                            // chainKind == 4: COPY(RSP) wrap
    PcodeOp *cp = fixture.makeOp(CPUI_COPY,1,8);
    fixture.setInput(cp,rsp,0);
    addr = cp->getOut();
  }
  markSpacebase(fd,rsp);

  PcodeOp *store = fixture.makeOp(CPUI_STORE,3,0);
  fixture.setInput(store,(fd.newConstant(8,(uintb)(uintp)loadspace)),0);
  fixture.setInput(store,addr,1);
  fixture.setInput(store,v,2);

  RuleStoreVarnode rule("stackvars");
  int4 result = rule.applyOp(store,fd);
  dump(name,result,store);
}

/// Case 8: LOAD(ram, INT_ADD(RSP, const)) collapses to a stack COPY.
void runLoadAddCase(Funcdata &fd,const string &name,AddrSpace *loadspace,uintb chainConst)
{
  fd.clear();
  Fixture fixture(fd);
  AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
  Varnode *rsp = fixture.makeInput(8,registerSpace,0x20);
  PcodeOp *add = fixture.makeOp(CPUI_INT_ADD,2,8);
  fixture.setInput(add,rsp,0);
  fixture.setInput(add,fd.newConstant(8,chainConst),1);
  markSpacebase(fd,rsp);

  PcodeOp *load = fixture.makeOp(CPUI_LOAD,2,8);
  fixture.setInput(load,(fd.newConstant(8,(uintb)(uintp)loadspace)),0);
  fixture.setInput(load,add->getOut(),1);

  RuleLoadVarnode rule("stackvars");
  int4 result = rule.applyOp(load,fd);
  dump(name,result,load);
}

/// Case 9: a non-spacebase register chain must miss the isSpacebase guard
/// (ruleaction.cc:4176).
void runStoreNonSpacebaseCase(Funcdata &fd,const string &name,AddrSpace *loadspace)
{
  fd.clear();
  Fixture fixture(fd);
  AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
  Varnode *v = fixture.makeInput(8,registerSpace,0x100);
  Varnode *rax = fixture.makeInput(8,registerSpace,0x0);
  PcodeOp *add = fixture.makeOp(CPUI_INT_ADD,2,8);
  fixture.setInput(add,rax,0);
  fixture.setInput(add,fd.newConstant(8,8),1);

  PcodeOp *store = fixture.makeOp(CPUI_STORE,3,0);
  fixture.setInput(store,(fd.newConstant(8,(uintb)(uintp)loadspace)),0);
  fixture.setInput(store,add->getOut(),1);
  fixture.setInput(store,v,2);

  RuleStoreVarnode rule("stackvars");
  int4 result = rule.applyOp(store,fd);
  dump(name,result,store);
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
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw std::runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->getName() != "GetStr" ||
        fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
      throw std::runtime_error("GetStr input identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " +
                               architecture.archid);

    // Registry observation: the stack space's contain link and its
    // spacebase record (addSpacebase, architecture.cc:559-570).
    AddrSpace *stackspace = architecture.getStackSpace();
    AddrSpace *contain = stackspace->getContain();
    const VarnodeData &point(stackspace->getSpacebase(0));
    std::cout << "stack_contain=" << (contain == (AddrSpace *)0 ? string("-") : contain->getName())
              << "|sb_record=" << point.space->getName() << ':'
              << std::hex << point.offset << std::dec << ':' << point.size << '\n';

    AddrSpace *ram = architecture.getDefaultDataSpace();
    AddrSpace *stack = architecture.getStackSpace();

    // spacebase + no offset: val == 0, out at stack:0 (ruleaction.cc:4201-4205).
    runStoreAddCase(*fd,"store_sbinput_off0",ram,0,0);
    // Prologue push form: INT_ADD(RSP, -8) → stack:fffffffffffffff8.
    runStoreAddCase(*fd,"store_sbinput_add",ram,1,0xfffffffffffffff8);
    // Swapped operand order (const, RSP) — the vn2 branch (cc:4219-4225).
    runStoreAddCase(*fd,"store_sbinput_swap",ram,2,0x18);
    // contain(stack)=ram != stack → miss (cc:4181-4182).
    runStoreAddCase(*fd,"store_contain_mismatch",stack,1,8);
    // Written (non-input) spacebase base → miss (cc:4179).
    runStoreAddCase(*fd,"store_written_base",ram,3,0xfffffffffffffff8);
    // COPY-wrapped spacebase chain: def != INT_ADD → miss (cc:4208).
    runStoreAddCase(*fd,"store_copy_wrapped",ram,4,0);
    // LOAD twin of the push form.
    runLoadAddCase(*fd,"load_sbinput_add",ram,0x40);
    // Non-spacebase register chain → miss (cc:4176).
    runStoreNonSpacebaseCase(*fd,"store_non_spacebase",ram);
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: rule_store_varnode_spacebase_1204 <sleigh-spec-dir> <binary>\n";
    return 2;
  }
  try {
    run(argv[1],argv[2]);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture failed: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
