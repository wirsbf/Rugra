/* TRANSFORM-MULTIEQUAL-INSERT-0001: locked Ghidra 12.0.4 fixture. */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "transform.hh"

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

string snapshot(const Funcdata *fd,BlockBasic *block)
{
  vector<PcodeOp *> ops;
  map<PcodeOp *,int4> opIndex;
  for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
    opIndex[*iter] = ops.size();
    ops.push_back(*iter);
  }
  vector<Varnode *> vars;
  map<Varnode *,int4> varIndex;
  for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
    PcodeOp *op = *iter;
    Varnode *outvn = op->getOut();
    if (outvn != (Varnode *)0 && varIndex.find(outvn) == varIndex.end()) {
      varIndex[outvn] = vars.size();
      vars.push_back(outvn);
    }
    for(int4 slot=0;slot<op->numInput();++slot) {
      Varnode *invn = op->getIn(slot);
      if (varIndex.find(invn) == varIndex.end()) {
        varIndex[invn] = vars.size();
        vars.push_back(invn);
      }
    }
  }
  ostringstream out;
  out << "ops[";
  for(int4 index=0;index<ops.size();++index) {
    if (index != 0) out << ';';
    PcodeOp *op = ops[index];
    out << 'o' << index << ':' << (int4)op->code()
        << "/t" << op->getSeqNum().getTime()
        << "/r" << op->getSeqNum().getOrder()
        << "/p" << (op->getParent() == block ? block->getIndex() : -1)
        << "/o";
    if (op->getOut() == (Varnode *)0)
      out << '_';
    else
      out << 'v' << varIndex[op->getOut()];
    out << "/i";
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (slot != 0) out << ',';
      out << 'v' << varIndex[op->getIn(slot)];
    }
  }
  out << "]vars[";
  for(int4 index=0;index<vars.size();++index) {
    if (index != 0) out << ';';
    Varnode *vn = vars[index];
    out << 'v' << index << ":c" << vn->getCreateIndex()
        << "/s" << vn->getSize()
        << "/sp" << vn->getSpace()->getIndex()
        << "/k" << (vn->isConstant() ? 1 : 0);
    if (vn->isConstant()) out << ':' << vn->getOffset();
    out << "/d";
    map<PcodeOp *,int4>::const_iterator defiter = opIndex.find(vn->getDef());
    if (defiter == opIndex.end()) out << '_'; else out << 'o' << (*defiter).second;
    out << "/u";
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      if (!first) out << ',';
      first = false;
      map<PcodeOp *,int4>::const_iterator useiter = opIndex.find(*iter);
      if (useiter == opIndex.end()) out << 'x'; else out << 'o' << (*useiter).second;
    }
  }
  out << "]count=" << ops.size()
      << ',' << vars.size()
      << ',' << std::distance(fd->beginOpAlive(),fd->endOpAlive())
      << ',' << std::distance(fd->beginOpDead(),fd->endOpDead())
      << ',' << std::distance(fd->beginOpAll(),fd->endOpAll())
      << ',' << fd->numVarnodes();
  return out.str();
}

BlockBasic *newBlock(Funcdata *fd)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
  return graph.newBlockBasic(fd);
}

PcodeOp *newAnchor(Funcdata *fd,BlockBasic *block,uintb address)
{
  PcodeOp *op = fd->newOp(0,Address(fd->getArch()->getDefaultCodeSpace(),address));
  fd->opSetOpcode(op,CPUI_COPY);
  fd->opInsertEnd(op,block);
  return op;
}

void wire(TransformManager &manager,TransformOp *op,int4 inputs,int4 outputSize,uintb valueBase)
{
  TransformVar *output = manager.newUnique(outputSize);
  manager.opSetOutput(op,output);
  for(int4 slot=0;slot<inputs;++slot) {
    TransformVar *input = manager.newConstant(outputSize,0,valueBase + slot);
    manager.opSetInput(op,input,slot);
  }
}

void runReplace(BfdArchitecture &architecture,const string &functionName,const string &label,OpCode opcode,int4 inputs)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x8000);
  TransformManager manager(fd);
  TransformOp *first = manager.newOpReplace(inputs,opcode,anchor);
  wire(manager,first,inputs,2,0x10);
  TransformOp *second = manager.newOpReplace(inputs,opcode,anchor);
  wire(manager,second,inputs,2,0x20);
  manager.apply();
  std::cout << label << "|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

void runFollow(BfdArchitecture &architecture,const string &functionName,const string &label,OpCode opcode,int4 inputs)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x9000);
  TransformManager manager(fd);
  TransformOp *follow = manager.newOpReplace(1,CPUI_COPY,anchor);
  wire(manager,follow,1,2,0x30);
  TransformOp *first = manager.newOp(inputs,opcode,follow);
  wire(manager,first,inputs,2,0x40);
  TransformOp *second = manager.newOp(inputs,opcode,follow);
  wire(manager,second,inputs,2,0x50);
  manager.apply();
  std::cout << label << "|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

void run(const string &specDirectory,const string &binary)
{
  vector<string> specPaths(1,specDirectory);
  startDecompilerLibrary(specPaths);
  {
    ostringstream messages;
    BfdArchitecture architecture(binary,"default",&messages);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    runReplace(architecture,"GetStr","replace_phi",CPUI_MULTIEQUAL,2);
    runFollow(architecture,"main_free","follow_phi",CPUI_MULTIEQUAL,2);
    runReplace(architecture,"hugehelp","replace_copy",CPUI_COPY,1);
    runFollow(architecture,"main_init","follow_copy",CPUI_COPY,1);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: transform_multiequal_insert_1204 SPEC_ROOT CURL_BINARY\n";
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
