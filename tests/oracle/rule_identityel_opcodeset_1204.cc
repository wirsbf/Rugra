/*
 * RULE-IDENTITYEL-OPCODESET-0001
 *
 * Locked Ghidra 12.0.4 oracle for RuleIdentityEl's public Rule/ActionPool
 * contract (ruleaction.hh:673-682, ruleaction.cc:3668-3702,
 * action.cc:740-750/822-887).  A production ActionPool containing only the
 * production RuleIdentityEl is driven to a fixed point over one ordered bank
 * of synthetic P-code operations.  No expected result is encoded here: the
 * runner records and compares the complete observations from both engines.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

struct CaseRecord {
  string name;
  PcodeOp *op;
  Varnode *lhs;
  Varnode *rhs;
  Varnode *output;
};

AddrSpace *codeSpace;
AddrSpace *regSpace;
uintb nextAddress = 0x6100;
uintb nextRegister = 0x400;

Varnode *newInput(Funcdata &fd,int4 size)
{
  Varnode *vn = fd.newVarnode(size,regSpace,nextRegister);
  nextRegister += 0x10;
  return fd.setInputVarnode(vn);
}

CaseRecord makeCase(Funcdata &fd,BlockBasic *block,const string &name,
                    OpCode opcode,Varnode *lhs,Varnode *rhs,int4 outputSize)
{
  PcodeOp *op = fd.newOp(2,Address(codeSpace,nextAddress++));
  fd.opSetOpcode(op,opcode);
  fd.opSetInput(op,lhs,0);
  fd.opSetInput(op,rhs,1);
  Varnode *output = fd.newUniqueOut(outputSize,op);
  fd.opInsertEnd(op,block);
  CaseRecord result = { name,op,lhs,rhs,output };
  return result;
}

string caseName(const PcodeOp *op,const vector<CaseRecord> &cases)
{
  for(size_t i=0;i<cases.size();++i)
    if (cases[i].op == op) return cases[i].name;
  return "?";
}

string descendOrder(const Varnode *vn,const vector<CaseRecord> &cases)
{
  ostringstream out;
  bool first = true;
  for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();
      iter!=vn->endDescend();++iter) {
    if (!first) out << ',';
    first = false;
    out << caseName(*iter,cases);
  }
  return out.str();
}

string blockOrder(const BlockBasic *block,const vector<CaseRecord> &cases)
{
  ostringstream out;
  bool first = true;
  for(list<PcodeOp *>::const_iterator iter=block->beginOp();
      iter!=block->endOp();++iter) {
    if (!first) out << ',';
    first = false;
    out << caseName(*iter,cases);
  }
  return out.str();
}

string slotIdentity(const PcodeOp *op,int4 slot,const CaseRecord &record)
{
  if (slot >= op->numInput()) return "-";
  const Varnode *vn = op->getIn(slot);
  if (vn == record.lhs) return "lhs";
  if (vn == record.rhs) return "rhs";
  return "other";
}

void emitCase(const CaseRecord &record,const BlockBasic *block)
{
  PcodeOp *op = record.op;
  std::cout << "case=" << record.name
            << "|opcode=" << static_cast<int4>(op->code())
            << "|inputs=" << op->numInput()
            << "|slot0=" << slotIdentity(op,0,record)
            << "|slot1=" << slotIdentity(op,1,record)
            << "|output_same=" << (op->getOut()==record.output ? 1 : 0)
            << "|output_def=" << (record.output->getDef()==op ? 1 : 0)
            << "|rhs_desc="
            << std::distance(record.rhs->beginDescend(),record.rhs->endDescend())
            << "|parent_same=" << (op->getParent()==block ? 1 : 0)
            << "|dead=" << (op->isDead() ? 1 : 0)
            << '\n';
}

void emitOpList(Rule &rule)
{
  vector<uint4> oplist;
  rule.getOpList(oplist);
  std::cout << "oplist=";
  for(size_t i=0;i<oplist.size();++i) {
    if (i != 0) std::cout << ',';
    std::cout << oplist[i];
  }
  std::cout << "|count=" << oplist.size() << '\n';
}

void run(Funcdata &fd)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);
  Varnode *x4 = newInput(fd,4);
  Varnode *b1 = newInput(fd,1);
  vector<CaseRecord> cases;

  cases.push_back(makeCase(fd,block,"int_add_zero",CPUI_INT_ADD,x4,
                           fd.newConstant(4,0),4));
  cases.push_back(makeCase(fd,block,"int_xor_zero",CPUI_INT_XOR,x4,
                           fd.newConstant(4,0),4));
  cases.push_back(makeCase(fd,block,"int_or_zero",CPUI_INT_OR,x4,
                           fd.newConstant(4,0),4));
  cases.push_back(makeCase(fd,block,"bool_xor_zero",CPUI_BOOL_XOR,b1,
                           fd.newConstant(1,0),1));
  cases.push_back(makeCase(fd,block,"bool_or_zero",CPUI_BOOL_OR,b1,
                           fd.newConstant(1,0),1));
  cases.push_back(makeCase(fd,block,"mult_zero",CPUI_INT_MULT,x4,
                           fd.newConstant(4,0),4));
  cases.push_back(makeCase(fd,block,"mult_one",CPUI_INT_MULT,x4,
                           fd.newConstant(4,1),4));
  cases.push_back(makeCase(fd,block,"mult_two_guard",CPUI_INT_MULT,x4,
                           fd.newConstant(4,2),4));
  cases.push_back(makeCase(fd,block,"int_sub_zero_dispatch_neg",CPUI_INT_SUB,x4,
                           fd.newConstant(4,0),4));
  cases.push_back(makeCase(fd,block,"int_and_zero_dispatch_neg",CPUI_INT_AND,x4,
                           fd.newConstant(4,0),4));
  cases.push_back(makeCase(fd,block,"int_add_nonconst_guard",CPUI_INT_ADD,x4,
                           newInput(fd,4),4));

  RuleIdentityEl *rule = new RuleIdentityEl("analysis");
  ActionPool pool(Action::rule_repeatapply,"identity_pool");
  pool.addRule(rule);

  emitOpList(*rule);
  std::cout << "lookup=production"
            << "|new=" << (pool.getSubRule("identityel")==rule ? 1 : 0)
            << "|old=" << (pool.getSubRule("identity_el")==0 ? 0 : 1)
            << '\n';
  std::cout << "rule_name=" << rule->getName() << '\n';
  std::cout << "desc=x4|stage=before|ops=" << descendOrder(x4,cases) << '\n';
  std::cout << "desc=b1|stage=before|ops=" << descendOrder(b1,cases) << '\n';
  std::cout << "block|stage=before|ops=" << blockOrder(block,cases) << '\n';

  int4 result = pool.perform(fd);
  std::cout << "pool|perform=" << result
            << "|status=" << pool.getStatus()
            << "|tests=" << pool.getNumTests()
            << "|apply=" << pool.getNumApply()
            << "|rule_tests=" << rule->getNumTests()
            << "|rule_apply=" << rule->getNumApply()
            << '\n';
  for(size_t i=0;i<cases.size();++i)
    emitCase(cases[i],block);
  std::cout << "desc=x4|stage=after|ops=" << descendOrder(x4,cases) << '\n';
  std::cout << "desc=b1|stage=after|ops=" << descendOrder(b1,cases) << '\n';
  std::cout << "block|stage=after|ops=" << blockOrder(block,cases) << '\n';
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: rule_identityel_opcodeset_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    vector<string> specPaths;
    specPaths.push_back(argv[1]);
    startDecompilerLibrary(specPaths);
    {
      std::ostringstream diagnostics;
      BfdArchitecture architecture(argv[2],"default",&diagnostics);
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
      codeSpace = architecture.getDefaultCodeSpace();
      regSpace = architecture.getSpaceByName("register");
      if (regSpace == (AddrSpace *)0)
        throw std::runtime_error("fixture requires register space");
      run(*fd);
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
