/* LANEDIVIDE-INFRA-0001: locked Ghidra 12.0.4 oracle fixture. */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "subflow.hh"

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

struct GraphProjection {
  vector<PcodeOp *> ops;
  map<PcodeOp *,int4> opIndex;
  vector<Varnode *> vars;
  map<Varnode *,int4> varIndex;

  explicit GraphProjection(BlockBasic *block)
  {
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
      opIndex[*iter] = ops.size();
      ops.push_back(*iter);
    }
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      PcodeOp *op = *iter;
      touch(op->getOut());
      for(int4 slot=0;slot<op->numInput();++slot)
        touch(op->getIn(slot));
    }
  }

  void touch(Varnode *vn)
  {
    if (vn == (Varnode *)0 || varIndex.find(vn) != varIndex.end()) return;
    varIndex[vn] = vars.size();
    vars.push_back(vn);
  }

  string varName(Varnode *vn) const
  {
    if (vn == (Varnode *)0) return "_";
    map<Varnode *,int4>::const_iterator iter = varIndex.find(vn);
    if (iter == varIndex.end()) return "x";
    ostringstream out;
    out << 'v' << (*iter).second;
    return out.str();
  }

  string opName(PcodeOp *op) const
  {
    if (op == (PcodeOp *)0) return "_";
    map<PcodeOp *,int4>::const_iterator iter = opIndex.find(op);
    if (iter == opIndex.end()) return "x";
    ostringstream out;
    out << 'o' << (*iter).second;
    return out.str();
  }

  string render(const Funcdata *fd,BlockBasic *block) const
  {
    ostringstream out;
    out << "ops[";
    for(int4 i=0;i<ops.size();++i) {
      if (i != 0) out << ';';
      PcodeOp *op = ops[i];
      out << 'o' << i << ':' << (int4)op->code()
          << "@" << op->getAddr().getOffset()
          << "/t" << op->getSeqNum().getTime()
          << "/r" << op->getSeqNum().getOrder()
          << "/d" << (op->isDead() ? 1 : 0)
          << "/p" << (op->getParent() == block ? block->getIndex() : -1)
          << "/o" << varName(op->getOut()) << "/i";
      for(int4 slot=0;slot<op->numInput();++slot) {
        if (slot != 0) out << ',';
        out << varName(op->getIn(slot));
      }
    }
    out << "]vars[";
    for(int4 i=0;i<vars.size();++i) {
      if (i != 0) out << ';';
      Varnode *vn = vars[i];
      out << 'v' << i << ":c" << vn->getCreateIndex()
          << "/s" << vn->getSize()
          << "/sp" << vn->getSpace()->getIndex()
          << "/k" << (vn->isConstant() ? 1 : 0);
      if (vn->isConstant()) out << ':' << vn->getOffset();
      out << "/f" << (vn->isFree() ? 1 : 0)
          << "/n" << (vn->isInput() ? 1 : 0)
          << "/w" << (vn->isWritten() ? 1 : 0)
          << "/d" << opName(vn->getDef()) << "/u";
      bool first = true;
      for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
        if (!first) out << ',';
        first = false;
        out << opName(*iter);
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
};

string snapshot(const Funcdata *fd,BlockBasic *block)
{
  GraphProjection projection(block);
  return projection.render(fd,block);
}

BlockBasic *newBlock(Funcdata *fd)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
  return graph.newBlockBasic(fd);
}

PcodeOp *newOutputOp(Funcdata *fd,BlockBasic *block,OpCode opcode,uintb pc,int4 inputs,int4 outputSize,bool atBegin=false)
{
  Address address(fd->getArch()->getDefaultCodeSpace(),pc);
  PcodeOp *op = fd->newOp(inputs,address);
  fd->opSetOpcode(op,opcode);
  fd->newUniqueOut(outputSize,op);
  if (atBegin)
    fd->opInsertBegin(op,block);
  else
    fd->opInsertEnd(op,block);
  return op;
}

void setInput(Funcdata *fd,PcodeOp *op,Varnode *vn,int4 slot)
{
  fd->opSetInput(op,vn,slot);
}

string laneMap(const Funcdata *fd,const Architecture &architecture)
{
  ostringstream out;
  bool first = true;
  for(map<VarnodeData,const LanedRegister *>::const_iterator iter=fd->beginLaneAccess();
      iter!=fd->endLaneAccess();++iter) {
    if (!first) out << ';';
    first = false;
    const VarnodeData &storage = (*iter).first;
    const LanedRegister *record = (*iter).second;
    int4 identity = -1;
    for(int4 i=0;i<architecture.lanerecords.size();++i) {
      if (record == &architecture.lanerecords[i]) {
        identity = i;
        break;
      }
    }
    out << storage.space->getIndex() << ':' << storage.offset << ':' << storage.size
        << "=r" << identity << ':' << record->getWholeSize()
        << ':' << record->getSizeBitMask();
  }
  return out.str();
}

void runLaneMap(BfdArchitecture &architecture)
{
  AddrSpace *registerSpace = architecture.getSpaceByName("register");
  if (registerSpace == (AddrSpace *)0)
    throw std::runtime_error("register space not found");
  const LanedRegister *lookupA = architecture.getLanedRegister(
    Address(registerSpace,0x10),16);
  const LanedRegister *lookupB = architecture.getLanedRegister(
    Address(architecture.getUniqueSpace(),0xdead),16);
  std::cout << "arch|min=" << architecture.getMinimumLanedRegisterSize()
            << "|sizes=" << architecture.lanerecords[0].getWholeSize()
            << ',' << architecture.lanerecords[1].getWholeSize()
            << "|lookup16=" << lookupA->getWholeSize() << ':' << lookupA->getSizeBitMask()
            << "|same=" << (lookupA == lookupB ? 1 : 0)
            << "|missing12=" << (architecture.getLanedRegister(
                 Address(registerSpace,0),12) == (const LanedRegister *)0 ? 1 : 0)
            << '\n';

  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
  if (fd == (Funcdata *)0) throw std::runtime_error("GetStr not found");
  size_t initial = std::distance(fd->beginLaneAccess(),fd->endLaneAccess());
  fd->checkForLanedRegister(12,Address(registerSpace,0x20));
  size_t afterMiss = std::distance(fd->beginLaneAccess(),fd->endLaneAccess());
  fd->checkForLanedRegister(8,Address(registerSpace,0x20));
  fd->checkForLanedRegister(16,Address(registerSpace,0x20));
  fd->checkForLanedRegister(8,Address(architecture.getUniqueSpace(),5));
  string before = laneMap(fd,architecture);
  size_t beforeGenerated = std::distance(fd->beginLaneAccess(),fd->endLaneAccess());
  fd->setLanedRegGenerated();
  PcodeOp *suppressed = fd->newOp(0,Address(architecture.getDefaultCodeSpace(),0x4100));
  fd->newVarnodeOut(16,Address(registerSpace,0x40),suppressed);
  size_t afterGenerated = std::distance(fd->beginLaneAccess(),fd->endLaneAccess());
  fd->clear();
  size_t afterClear = std::distance(fd->beginLaneAccess(),fd->endLaneAccess());
  PcodeOp *recorded = fd->newOp(0,Address(architecture.getDefaultCodeSpace(),0x4101));
  fd->newVarnodeOut(16,Address(registerSpace,0x40),recorded);
  string afterReset = laneMap(fd,architecture);
  fd->clearLanedAccessMap();
  size_t afterExplicit = std::distance(fd->beginLaneAccess(),fd->endLaneAccess());
  std::cout << "map|miss_delta=" << (afterMiss-initial)
            << "|before=" << before
            << "|generated_delta=" << (afterGenerated-beforeGenerated)
            << "|clear_preserved=" << afterClear
            << "|reset=" << afterReset
            << "|explicit_clear=" << afterExplicit << '\n';
}

void runPiece(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("main_free");
  if (fd == (Funcdata *)0) throw std::runtime_error("main_free not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *piece = newOutputOp(fd,block,CPUI_PIECE,0x5000,2,4);
  Varnode *root = piece->getOut();
  setInput(fd,piece,fd->newConstant(2,0x1122),0);
  setInput(fd,piece,fd->newConstant(2,0x3344),1);
  PcodeOp *low = newOutputOp(fd,block,CPUI_SUBPIECE,0x5001,2,2);
  setInput(fd,low,root,0);
  setInput(fd,low,fd->newConstant(4,0),1);
  PcodeOp *high = newOutputOp(fd,block,CPUI_SUBPIECE,0x5002,2,2);
  setInput(fd,high,root,0);
  setInput(fd,high,fd->newConstant(4,2),1);
  string before = snapshot(fd,block);
  LaneDescription description(4,2);
  LaneDivide divide(fd,root,description,false);
  bool traced = divide.doTrace();
  bool markAfterTrace = root->isMark();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  std::cout << "piece|trace=" << (traced ? 1 : 0)
            << "|mark=" << (markAfterTrace ? 1 : 0)
            << "|before=" << before << "|after=" << after
            << "|old=" << (piece->isDead() ? 1 : 0)
            << ',' << (piece->getOut() == (Varnode *)0 ? 1 : 0)
            << ',' << (int4)low->code() << ',' << low->numInput()
            << ',' << (int4)high->code() << ',' << high->numInput() << '\n';
}

void runMultiequal(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("hugehelp");
  if (fd == (Funcdata *)0) throw std::runtime_error("hugehelp not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *phi = newOutputOp(fd,block,CPUI_MULTIEQUAL,0x6000,2,4,true);
  Varnode *root = phi->getOut();
  setInput(fd,phi,fd->newConstant(4,0x11223344),0);
  setInput(fd,phi,fd->newConstant(4,0x55667788),1);
  PcodeOp *low = newOutputOp(fd,block,CPUI_SUBPIECE,0x6001,2,2);
  setInput(fd,low,root,0);
  setInput(fd,low,fd->newConstant(4,0),1);
  PcodeOp *high = newOutputOp(fd,block,CPUI_SUBPIECE,0x6002,2,2);
  setInput(fd,high,root,0);
  setInput(fd,high,fd->newConstant(4,2),1);
  string before = snapshot(fd,block);
  LaneDescription description(4,2);
  LaneDivide divide(fd,root,description,false);
  bool traced = divide.doTrace();
  bool markAfterTrace = root->isMark();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  std::cout << "multiequal|trace=" << (traced ? 1 : 0)
            << "|mark=" << (markAfterTrace ? 1 : 0)
            << "|before=" << before << "|after=" << after
            << "|old=" << (phi->isDead() ? 1 : 0)
            << ',' << (phi->getOut() == (Varnode *)0 ? 1 : 0)
            << ',' << (int4)low->code() << ',' << low->numInput()
            << ',' << (int4)high->code() << ',' << high->numInput() << '\n';
}

void runFailure(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("main_init");
  if (fd == (Funcdata *)0) throw std::runtime_error("main_init not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *multiply = newOutputOp(fd,block,CPUI_INT_MULT,0x7000,2,4);
  Varnode *root = multiply->getOut();
  setInput(fd,multiply,fd->newConstant(4,3),0);
  setInput(fd,multiply,fd->newConstant(4,7),1);
  PcodeOp *low = newOutputOp(fd,block,CPUI_SUBPIECE,0x7001,2,2);
  setInput(fd,low,root,0);
  setInput(fd,low,fd->newConstant(4,0),1);
  string before = snapshot(fd,block);
  LaneDescription description(4,2);
  LaneDivide divide(fd,root,description,false);
  bool traced = divide.doTrace();
  string after = snapshot(fd,block);
  std::cout << "failure|trace=" << (traced ? 1 : 0)
            << "|same=" << (before == after ? 1 : 0)
            << "|mark=" << (root->isMark() ? 1 : 0)
            << "|before=" << before << "|after=" << after << '\n';
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
    architecture.lanerecords.clear();
    architecture.lanerecords.push_back(LanedRegister(8,1u << 2));
    architecture.lanerecords.push_back(LanedRegister(16,(1u << 4) | (1u << 8)));
    architecture.readLoaderSymbols("::");
    runLaneMap(architecture);
    runPiece(architecture);
    runMultiequal(architecture);
    runFailure(architecture);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: lanedivide_infra_1204 SPEC_ROOT CURL_BINARY\n";
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
