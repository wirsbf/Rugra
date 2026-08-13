/*
 * Locked Ghidra 12.0.4 RuleCollectTerms::applyOp oracle.
 *
 * Every case records the target-relevant structural IR immediately before and
 * after the real rule call: block and op-bank alive/dead order,
 * op lifecycle/parent/order, every
 * input and output, and the def-use state of both still-reachable and detached
 * Varnodes. Unique-space offsets are deliberately represented by stable
 * fixture identities because they are allocation-only temporaries. The narrow
 * fixture does not claim to observe unrelated type/symbol/high state.
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

void runLikeCase(Funcdata &fd,const string &name,int4 size,uintb coef0,uintb coef1)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",size,0x40);
  PcodeOp *mult0 = fixture.makeOp("mult0",CPUI_INT_MULT,2,size);
  PcodeOp *mult1 = fixture.makeOp("mult1",CPUI_INT_MULT,2,size);
  PcodeOp *root = fixture.makeOp("root",CPUI_INT_ADD,2,size);
  Varnode *constant0 = fixture.makeConstant("coef0",size,coef0);
  Varnode *constant1 = fixture.makeConstant("coef1",size,coef1);

  fixture.setInput(mult0,x,0);
  fixture.setInput(mult0,constant0,1);
  fixture.setInput(mult1,x,0);
  fixture.setInput(mult1,constant1,1);
  fixture.setInput(root,mult0->getOut(),0);
  fixture.setInput(root,mult1->getOut(),1);
  fixture.insertEnd(mult0);
  fixture.insertEnd(mult1);
  fixture.insertEnd(root);

  fixture.dump(name,"before","na");
  RuleCollectTerms rule("analysis");
  int4 result = rule.applyOp(root,fd);
  fixture.dump(name,"after",std::to_string(result));
}

void runConstantCase(Funcdata &fd,const string &name,int4 size,uintb innerValue,
                     uintb rootValue)
{
  fd.clear();
  Fixture fixture(fd);
  Varnode *x = fixture.makeInput("x",size,0x40);
  // Keep creation and fixture-identity registration order identical on both
  // sides. Ghidra's termOrder deliberately compares any two constants equal.
  Varnode *rootConstant = fixture.makeConstant("root_const",size,rootValue);
  Varnode *innerConstant = fixture.makeConstant("inner_const",size,innerValue);
  PcodeOp *inner = fixture.makeOp("inner",CPUI_INT_ADD,2,size);
  PcodeOp *root = fixture.makeOp("root",CPUI_INT_ADD,2,size);

  fixture.setInput(inner,x,0);
  fixture.setInput(inner,innerConstant,1);
  fixture.setInput(root,inner->getOut(),0);
  fixture.setInput(root,rootConstant,1);
  fixture.insertEnd(inner);
  fixture.insertEnd(root);

  fixture.dump(name,"before","na");
  RuleCollectTerms rule("analysis");
  int4 result = rule.applyOp(root,fd);
  fixture.dump(name,"after",std::to_string(result));
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

    runLikeCase(*fd,"like_nonoverflow",8,2,3);
    runLikeCase(*fd,"like_storage_wrap",1,0xff,2);
    runLikeCase(*fd,"like_uintb_wrap",8,~((uintb)0),2);
    runLikeCase(*fd,"like_zero",1,0xff,1);
    runConstantCase(*fd,"constant_nonoverflow",8,3,5);
    runConstantCase(*fd,"constant_storage_wrap",1,0xff,2);
    runConstantCase(*fd,"constant_uintb_wrap",8,~((uintb)0),2);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: rule_collect_terms_1204 SPEC_ROOT CURL_BINARY\n";
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
