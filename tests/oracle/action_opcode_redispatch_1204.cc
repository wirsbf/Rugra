/*
 * Locked Ghidra 12.0.4 ActionPool opcode-change redispatch oracle.
 *
 * This fixture exercises the enabled/live/single-op/no-breakpoint projection
 * of ActionPool::processOp.  A SUBPIECE rule removes input 1 and rewrites the
 * opcode to INT_ZEXT.  The old opcode tail must be abandoned immediately and
 * the new opcode list restarted at index zero, even when the mutating rule
 * incorrectly returns zero.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::string;
using std::vector;

class ScriptRule final : public Rule {
  vector<string> &trace;
  OpCode trigger;
  OpCode replacement;
  bool mutate;
  int4 result;

public:
  ScriptRule(const string &name,vector<string> &events,OpCode from,OpCode to,
             bool changesOpcode,int4 returnValue)
    : Rule("analysis",0,name),trace(events),trigger(from),replacement(to),
      mutate(changesOpcode),result(returnValue) {}

  Rule *clone(const ActionGroupList &) const override { return (Rule *)0; }

  void getOpList(vector<uint4> &oplist) const override
  {
    oplist.push_back(static_cast<uint4>(trigger));
  }

  int4 applyOp(PcodeOp *op,Funcdata &data) override
  {
    trace.push_back(getName());
    if (mutate) {
      data.opRemoveInput(op,1);
      data.opSetOpcode(op,replacement);
    }
    return result;
  }
};

class ProbePool final : public ActionPool {
public:
  ProbePool(void) : ActionPool(0,"fixture_pool")
  {
    // Direct apply() bypasses Action::perform(), which normally initializes
    // these inherited accumulators before ActionPool::processOp updates count.
    count = 0;
    lcount = 0;
  }

  int4 actionCount(void) const { return count; }
  uint4 actionStatus(void) const { return status; }
};

template<typename Iterator>
long countOps(Iterator begin,Iterator end)
{
  return static_cast<long>(std::distance(begin,end));
}

string join(const vector<string> &values)
{
  std::ostringstream stream;
  for(size_t i=0;i<values.size();++i) {
    if (i != 0) stream << '>';
    stream << values[i];
  }
  return stream.str();
}

void runCase(Funcdata &fd,const string &caseName,int4 changeResult)
{
  fd.clear();
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);
  AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
  AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
  if (codeSpace == (AddrSpace *)0 || registerSpace == (AddrSpace *)0)
    throw std::runtime_error("fixture requires code and register spaces");
  fd.setBasicBlockRange(block,Address(codeSpace,0x1000),Address(codeSpace,0x1000));

  Varnode *source = fd.setInputVarnode(fd.newVarnode(2,registerSpace,0x20));
  Varnode *offset = fd.newConstant(4,0);
  PcodeOp *op = fd.newOp(2,Address(codeSpace,0x1000));
  fd.opSetOpcode(op,CPUI_SUBPIECE);
  fd.opSetInput(op,source,0);
  fd.opSetInput(op,offset,1);
  fd.newUniqueOut(4,op);
  fd.opInsertEnd(op,block);

  vector<string> trace;
  ProbePool pool;
  ScriptRule *change = new ScriptRule("change",trace,CPUI_SUBPIECE,
                                      CPUI_INT_ZEXT,true,changeResult);
  ScriptRule *oldTail = new ScriptRule("old_tail",trace,CPUI_SUBPIECE,
                                       CPUI_SUBPIECE,false,0);
  ScriptRule *newHead = new ScriptRule("new_head",trace,CPUI_INT_ZEXT,
                                       CPUI_INT_ZEXT,false,0);
  ScriptRule *newTail = new ScriptRule("new_tail",trace,CPUI_INT_ZEXT,
                                       CPUI_INT_ZEXT,false,0);
  pool.addRule(change);
  pool.addRule(oldTail);
  pool.addRule(newHead);
  pool.addRule(newTail);

  const int4 applyResult = pool.apply(fd);
  std::cout << "case=" << caseName
            << "|trace=" << join(trace)
            << "|apply_return=" << applyResult
            << "|action_count=" << pool.actionCount()
            << "|action_status=" << pool.actionStatus()
            << "|rule_stats="
            << "change:" << change->getNumTests() << '/' << change->getNumApply()
            << ",old_tail:" << oldTail->getNumTests() << '/' << oldTail->getNumApply()
            << ",new_head:" << newHead->getNumTests() << '/' << newHead->getNumApply()
            << ",new_tail:" << newTail->getNumTests() << '/' << newTail->getNumApply()
            << "|op="
            << "opcode:" << static_cast<int4>(op->code())
            << ",eval_flags:" << op->getEvalType()
            << ",inputs:" << op->numInput()
            << ",output_size:" << op->getOut()->getSize()
            << ",input0_size:" << op->getIn(0)->getSize()
            << ",input0_space:" << op->getIn(0)->getSpace()->getName()
            << ",input0_offset:" << op->getIn(0)->getOffset()
            << ",dead:" << op->isDead()
            << ",parent:" << (op->getParent() == block)
            << ",address:" << op->getAddr().getOffset()
            << ",time:" << op->getTime()
            << ",order:" << op->getSeqNum().getOrder()
            << ",alive_bank:" << countOps(fd.beginOpAlive(),fd.endOpAlive())
            << ",dead_bank:" << countOps(fd.beginOpDead(),fd.endOpDead())
            << ",removed_input_desc_empty:"
            << (offset->beginDescend() == offset->endDescend())
            << '\n';
}

void run(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    std::ostringstream diagnostics;
    BfdArchitecture architecture(binary,"default",&diagnostics);
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

    diagnostics.str("");
    diagnostics.clear();
    runCase(*fd,"positive_change",1);
    std::cerr << diagnostics.str();
    diagnostics.str("");
    diagnostics.clear();
    runCase(*fd,"zero_change",0);
    std::cerr << diagnostics.str();
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: action_opcode_redispatch_1204 SPEC_ROOT CURL_BINARY\n";
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
