/*
 * Locked Ghidra 12.0.4 RulePropagateCopy::applyOp oracle
 * (ruleaction.cc:3926-3957).
 *
 * Every case records the target-relevant structural IR immediately before and
 * after the real rule call: block and op-bank alive/dead order, op
 * lifecycle/parent/order, every input and output, and the def-use state of
 * both still-reachable and detached Varnodes. Unique-space offsets are
 * deliberately represented by stable fixture identities because they are
 * allocation-only temporaries. The narrow fixture does not claim to observe
 * unrelated type/symbol/high state.
 *
 * Case coverage maps 1:1 onto the guarded scan in applyOp:
 *   reader_propagate_slot0    - first-slot hit: isWritten, def==COPY,
 *                               heritage-known input propagates (cc:3953-3954)
 *   slot_scan_unwritten_const - cc:3936 !isWritten skip (constant), slot-1 hit
 *   slot_scan_noncopy_def     - cc:3939-3940 non-COPY def skip, slot-1 hit
 *   free_input_guard          - cc:3943 !isHeritageKnown free input rejected
 *   return_copy_guard         - cc:3933 isReturnCopy short-circuit
 *   marker_constant_guard     - cc:3946-3947 marker + constant input skipped
 *   multi_reader_bookkeeping  - opSetInput erase-old/add-new descend records
 *                               across two sequential reader applications
 *   constant_dedup_bookkeeping- opSetInput cc:108-115 constant-dedup creates a
 *                               fresh constant Varnode during propagation
 *   self_defined_throw        - cc:3944-3945 LowlevelError assertion path
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

class Fixture {
  Funcdata &fd;
  BlockBasic *block;
  vector<PcodeOp *> ops;
  map<PcodeOp *,string> opNames;
  vector<Varnode *> varnodes;
  map<Varnode *,string> varnodeNames;
  int4 nextOp;
  int4 nextVarnode;

  void rememberOp(PcodeOp *op,const string &name)
  {
    if (opNames.insert(std::make_pair(op,name)).second)
      ops.push_back(op);
  }

  void rememberVarnode(Varnode *vn,const string &name)
  {
    if (varnodeNames.insert(std::make_pair(vn,name)).second)
      varnodes.push_back(vn);
  }

  string opName(PcodeOp *op) const
  {
    map<PcodeOp *,string>::const_iterator iter = opNames.find(op);
    if (iter == opNames.end())
      throw std::runtime_error("unregistered fixture op");
    return (*iter).second;
  }

  string varnodeName(Varnode *vn) const
  {
    map<Varnode *,string>::const_iterator iter = varnodeNames.find(vn);
    if (iter == varnodeNames.end())
      throw std::runtime_error("unregistered fixture varnode");
    return (*iter).second;
  }

  void discover(void)
  {
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();
        iter!=block->endOp();++iter) {
      if (opNames.find(*iter) == opNames.end()) {
        ostringstream name;
        name << 'n' << nextOp++;
        rememberOp(*iter,name.str());
      }
    }
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();
        iter!=block->endOp();++iter) {
      PcodeOp *op = *iter;
      if (op->getOut() != (Varnode *)0 &&
          varnodeNames.find(op->getOut()) == varnodeNames.end())
        rememberVarnode(op->getOut(),opName(op) + "_out");
      for(int4 slot=0;slot<op->numInput();++slot) {
        Varnode *vn = op->getIn(slot);
        if (varnodeNames.find(vn) == varnodeNames.end()) {
          ostringstream name;
          name << 'g' << nextVarnode++;
          rememberVarnode(vn,name.str());
        }
      }
    }
  }

  string opList(list<PcodeOp *>::const_iterator iter,
                list<PcodeOp *>::const_iterator enditer) const
  {
    ostringstream out;
    bool first = true;
    for(;iter!=enditer;++iter) {
      if (!first) out << ',';
      first = false;
      out << opName(*iter);
    }
    return out.str();
  }

  string blockOrder(void) const
  {
    return opList(block->beginOp(),block->endOp());
  }

  string opState(PcodeOp *op) const
  {
    ostringstream out;
    out << opName(op)
        << "{opc=" << static_cast<int4>(op->code())
        << ",dead=" << op->isDead()
        << ",parent=" << (op->getParent() == block ? block->getIndex() : -1)
        << ",order=" << op->getSeqNum().getOrder()
        << ",inputs=[";
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (slot != 0) out << ',';
      out << varnodeName(op->getIn(slot));
    }
    out << "],output=";
    if (op->getOut() == (Varnode *)0)
      out << '-';
    else
      out << varnodeName(op->getOut());
    out << '}';
    return out.str();
  }

  string varnodeState(Varnode *vn) const
  {
    ostringstream out;
    out << varnodeName(vn)
        << "{space=" << vn->getSpace()->getName()
        << ",size=" << vn->getSize()
        << ",offset=";
    if (vn->getSpace()->getType() == IPTR_INTERNAL)
      out << "tmp";
    else
      out << std::hex << vn->getOffset() << std::dec;
    out << ",constant=" << vn->isConstant()
        << ",input=" << vn->isInput()
        << ",written=" << vn->isWritten()
        << ",free=" << vn->isFree()
        << ",def=";
    if (vn->getDef() == (PcodeOp *)0)
      out << '-';
    else
      out << opName(vn->getDef());
    out << ",desc=[";
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();
        iter!=vn->endDescend();++iter) {
      if (!first) out << ',';
      first = false;
      out << opName(*iter) << '.' << (*iter)->getSlot(vn);
    }
    out << "]}";
    return out.str();
  }

public:
  explicit Fixture(Funcdata &func)
    : fd(func), block((BlockBasic *)0), nextOp(0), nextVarnode(0)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    block = graph.newBlockBasic(&fd);
  }

  Varnode *makeInput(const string &name,int4 size,uintb offset)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    if (registerSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires the register space");
    Varnode *vn = fd.setInputVarnode(fd.newVarnode(size,registerSpace,offset));
    rememberVarnode(vn,name);
    return vn;
  }

  Varnode *makeConstant(const string &name,int4 size,uintb value)
  {
    Varnode *vn = fd.newConstant(size,value);
    rememberVarnode(vn,name);
    return vn;
  }

  Varnode *makeFreeUnique(const string &name,int4 size)
  {
    // Funcdata::newUnique (funcdata_varnode.cc:83-95) never crosses
    // VarnodeBank::xref, so the result carries no insert/constant/annotation
    // flag and isHeritageKnown() is false (varnode.hh:298).
    Varnode *vn = fd.newUnique(size);
    rememberVarnode(vn,name);
    return vn;
  }

  PcodeOp *makeOp(const string &name,OpCode opcode,int4 inputs,int4 outputSize)
  {
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(inputs,Address(codeSpace,0x1000));
    fd.opSetOpcode(op,opcode);
    rememberOp(op,name);
    Varnode *outvn = fd.newUniqueOut(outputSize,op);
    rememberVarnode(outvn,name + "_out");
    return op;
  }

  void setInput(PcodeOp *op,Varnode *vn,int4 slot)
  {
    fd.opSetInput(op,vn,slot);
  }

  void insertEnd(PcodeOp *op)
  {
    fd.opInsertEnd(op,block);
  }

  void dump(const string &caseName,const string &stage,const string &result)
  {
    discover();
    ostringstream opStates;
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();
        iter!=block->endOp();++iter) {
      if (!first) opStates << ';';
      first = false;
      opStates << opState(*iter);
    }

    ostringstream varnodeStates;
    first = true;
    for(vector<Varnode *>::const_iterator iter=varnodes.begin();
        iter!=varnodes.end();++iter) {
      if (!first) varnodeStates << ';';
      first = false;
      varnodeStates << varnodeState(*iter);
    }

    std::cout << "case=" << caseName
              << "|stage=" << stage
              << "|result=" << result
              << "|block=[" << blockOrder() << ']'
              << "|alive=[" << opList(fd.beginOpAlive(),fd.endOpAlive()) << ']'
              << "|dead=[" << opList(fd.beginOpDead(),fd.endOpDead()) << ']'
              << "|ops=[" << opStates.str() << ']'
              << "|varnodes=[" << varnodeStates.str() << "]\n";
  }
};

// reader_propagate_slot0: the dispatched op is the READER (INT_ADD), whose
// slot-0 input is written by a COPY of a heritage-known input. Expect the
// COPY's input to replace slot 0 via opSetInput and applyOp to return 1.
void runReaderPropagateSlot0(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",8,0x40);
  Varnode *x2 = fixture.makeInput("x2",8,0x48);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);
  PcodeOp *reader = fixture.makeOp("reader",CPUI_INT_ADD,2,8);

  fixture.setInput(copyop,x,0);
  fixture.setInput(reader,copyop->getOut(),0);
  fixture.setInput(reader,x2,1);
  fixture.insertEnd(copyop);
  fixture.insertEnd(reader);

  fixture.dump("reader_propagate_slot0","before","na");
  RulePropagateCopy rule("analysis");
  int4 result = rule.applyOp(reader,fd);
  fixture.dump("reader_propagate_slot0","after",std::to_string(result));
}

// slot_scan_unwritten_const: slot 0 is a constant (not written, cc:3936 skip),
// slot 1 is the COPY output and propagates. Ascending first-eligible-wins.
void runSlotScanUnwrittenConst(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",8,0x40);
  Varnode *c = fixture.makeConstant("c",8,0x9d);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);
  PcodeOp *reader = fixture.makeOp("reader",CPUI_INT_ADD,2,8);

  fixture.setInput(copyop,x,0);
  fixture.setInput(reader,c,0);
  fixture.setInput(reader,copyop->getOut(),1);
  fixture.insertEnd(copyop);
  fixture.insertEnd(reader);

  fixture.dump("slot_scan_unwritten_const","before","na");
  RulePropagateCopy rule("analysis");
  int4 result = rule.applyOp(reader,fd);
  fixture.dump("slot_scan_unwritten_const","after",std::to_string(result));
}

// slot_scan_noncopy_def: slot 0 is written by an INT_SUB (cc:3939-3940 skip),
// slot 1 is the COPY output and propagates.
void runSlotScanNoncopyDef(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",8,0x40);
  Varnode *x2 = fixture.makeInput("x2",8,0x48);
  PcodeOp *sub = fixture.makeOp("sub",CPUI_INT_SUB,2,8);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);
  PcodeOp *reader = fixture.makeOp("reader",CPUI_INT_ADD,2,8);

  fixture.setInput(sub,x,0);
  fixture.setInput(sub,x2,1);
  fixture.setInput(copyop,x,0);
  fixture.setInput(reader,sub->getOut(),0);
  fixture.setInput(reader,copyop->getOut(),1);
  fixture.insertEnd(sub);
  fixture.insertEnd(copyop);
  fixture.insertEnd(reader);

  fixture.dump("slot_scan_noncopy_def","before","na");
  RulePropagateCopy rule("analysis");
  int4 result = rule.applyOp(reader,fd);
  fixture.dump("slot_scan_noncopy_def","after",std::to_string(result));
}

// free_input_guard: the COPY's input is a free unique varnode
// (isHeritageKnown false), so cc:3943 refuses to propagate it away from its
// first use. Expect result 0 and byte-identical before/after state.
void runFreeInputGuard(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",8,0x40);
  Varnode *f = fixture.makeFreeUnique("f",8);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);
  PcodeOp *reader = fixture.makeOp("reader",CPUI_INT_ADD,2,8);

  fixture.setInput(copyop,f,0);
  fixture.setInput(reader,copyop->getOut(),0);
  fixture.setInput(reader,x,1);
  fixture.insertEnd(copyop);
  fixture.insertEnd(reader);

  fixture.dump("free_input_guard","before","na");
  RulePropagateCopy rule("analysis");
  int4 result = rule.applyOp(reader,fd);
  fixture.dump("free_input_guard","after",std::to_string(result));
}

// return_copy_guard: CPUI_RETURN carries the return_copy flag
// (TypeOpReturn, typeop.cc:878-882), so cc:3933 short-circuits before any
// slot scan even though the read COPY input would otherwise propagate.
void runReturnCopyGuard(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",8,0x40);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);
  PcodeOp *ret = fixture.makeOp("ret",CPUI_RETURN,1,8);

  fixture.setInput(copyop,x,0);
  fixture.setInput(ret,copyop->getOut(),0);
  fixture.insertEnd(copyop);
  fixture.insertEnd(ret);

  fixture.dump("return_copy_guard","before","na");
  RulePropagateCopy rule("analysis");
  int4 result = rule.applyOp(ret,fd);
  fixture.dump("return_copy_guard","after",std::to_string(result));
}

// marker_constant_guard: a MULTIEQUAL reader is a marker op; its COPY-written
// slot is eligible, the COPY input is heritage-known (constant flag), but
// cc:3946-3947 refuses to propagate constants into markers. Result 0.
void runMarkerConstantGuard(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",8,0x40);
  Varnode *c = fixture.makeConstant("c",8,0x7b);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);
  PcodeOp *phi = fixture.makeOp("phi",CPUI_MULTIEQUAL,2,8);

  fixture.setInput(copyop,c,0);
  fixture.setInput(phi,copyop->getOut(),0);
  fixture.setInput(phi,x,1);
  fixture.insertEnd(copyop);
  fixture.insertEnd(phi);

  fixture.dump("marker_constant_guard","before","na");
  RulePropagateCopy rule("analysis");
  int4 result = rule.applyOp(phi,fd);
  fixture.dump("marker_constant_guard","after",std::to_string(result));
}

// multi_reader_bookkeeping: one COPY output feeding two readers. Each applyOp
// redirects exactly one reader through opSetInput, whose bookkeeping erases
// the reader from the COPY output's descend list and appends it to the
// propagated input's descend list. r2's slot 0 is a non-COPY def and is
// skipped first (cc:3939-3940).
void runMultiReaderBookkeeping(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",8,0x40);
  Varnode *x2 = fixture.makeInput("x2",8,0x48);
  PcodeOp *sub = fixture.makeOp("sub",CPUI_INT_SUB,2,8);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);
  PcodeOp *r1 = fixture.makeOp("r1",CPUI_INT_SUB,2,8);
  PcodeOp *r2 = fixture.makeOp("r2",CPUI_INT_OR,2,8);

  fixture.setInput(sub,x,0);
  fixture.setInput(sub,x2,1);
  fixture.setInput(copyop,x,0);
  fixture.setInput(r1,copyop->getOut(),0);
  fixture.setInput(r1,x2,1);
  fixture.setInput(r2,sub->getOut(),0);
  fixture.setInput(r2,copyop->getOut(),1);
  fixture.insertEnd(sub);
  fixture.insertEnd(copyop);
  fixture.insertEnd(r1);
  fixture.insertEnd(r2);

  fixture.dump("multi_reader_bookkeeping","before","na");
  RulePropagateCopy rule("analysis");
  int4 result1 = rule.applyOp(r1,fd);
  fixture.dump("multi_reader_bookkeeping","after_r1",std::to_string(result1));
  int4 result2 = rule.applyOp(r2,fd);
  fixture.dump("multi_reader_bookkeeping","after_r2",std::to_string(result2));
}

// constant_dedup_bookkeeping: the COPY input is a constant that already has
// the COPY as its single descendant, so the propagation opSetInput takes the
// cc:108-115 constant-dedup path and installs a fresh constant Varnode on the
// reader. The fresh constant is discovered by the projection as g0.
void runConstantDedupBookkeeping(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",8,0x40);
  Varnode *c = fixture.makeConstant("c",8,0x1234);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);
  PcodeOp *reader = fixture.makeOp("reader",CPUI_INT_ADD,2,8);

  fixture.setInput(copyop,c,0);
  fixture.setInput(reader,copyop->getOut(),0);
  fixture.setInput(reader,x,1);
  fixture.insertEnd(copyop);
  fixture.insertEnd(reader);

  fixture.dump("constant_dedup_bookkeeping","before","na");
  RulePropagateCopy rule("analysis");
  int4 result = rule.applyOp(reader,fd);
  fixture.dump("constant_dedup_bookkeeping","after",std::to_string(result));
}

// self_defined_throw: a COPY reading its own output hits the cc:3944-3945
// assertion and throws LowlevelError("Self-defined varnode"). The fixture
// records the throw text as the result so both sides must reproduce the
// exact assertion message.
void runSelfDefinedThrow(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  PcodeOp *copyop = fixture.makeOp("copy",CPUI_COPY,1,8);

  fixture.setInput(copyop,copyop->getOut(),0);
  fixture.insertEnd(copyop);

  fixture.dump("self_defined_throw","before","na");
  RulePropagateCopy rule("analysis");
  string result = "no_throw";
  try {
    rule.applyOp(copyop,fd);
  }
  catch(const LowlevelError &error) {
    result = string("throw:") + error.explain;
  }
  fixture.dump("self_defined_throw","after",result);
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

    runReaderPropagateSlot0(*fd);
    runSlotScanUnwrittenConst(*fd);
    runSlotScanNoncopyDef(*fd);
    runFreeInputGuard(*fd);
    runReturnCopyGuard(*fd);
    runMarkerConstantGuard(*fd);
    runMultiReaderBookkeeping(*fd);
    runConstantDedupBookkeeping(*fd);
    runSelfDefinedThrow(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: rule_propcopy_1204 SPEC_ROOT CURL_BINARY\n";
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
