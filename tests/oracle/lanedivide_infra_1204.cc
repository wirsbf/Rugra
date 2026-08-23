/* LANEDIVIDE-INFRA-0001: locked Ghidra 12.0.4 oracle fixture. */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "subflow.hh"

#include <iostream>
#include <iterator>
#include <map>
#include <set>
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
  set<Varnode *> spaceidConstants;	///< Constants naming a space for a LOAD/STORE (pointer encoded in the oracle)
  set<Varnode *> iopAnnotations;	///< Annotation varnodes at slot 1 of INDIRECTs (classification normalized, see metadata)

  explicit GraphProjection(BlockBasic *block)
  {
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
      opIndex[*iter] = ops.size();
      ops.push_back(*iter);
    }
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      PcodeOp *op = *iter;
      if ((op->code() == CPUI_STORE || op->code() == CPUI_LOAD) && op->numInput() > 0)
        spaceidConstants.insert(op->getIn(0));
      if (op->code() == CPUI_INDIRECT && op->numInput() > 1)
        iopAnnotations.insert(op->getIn(1));
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
          << "/c" << (op->isIndirectCreation() ? 1 : 0)
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
          << "/";
      if (vn->getSpace()->getType() == IPTR_IOP || iopAnnotations.find(vn) != iopAnnotations.end())
        out << "si/k0";
      else
        out << "sp" << vn->getSpace()->getIndex()
            << "/k" << (vn->isConstant() ? 1 : 0);
      if (vn->isConstant()) {
        if (spaceidConstants.find(vn) != spaceidConstants.end())
          out << ":s" << vn->getSpaceFromConst()->getIndex();
        else if (vn->getSpace()->getType() != IPTR_IOP)
          out << ':' << vn->getOffset();
      }
      out << "/f" << (vn->isFree() ? 1 : 0)
          << "/t" << (vn->isTypeLock() ? 1 : 0)
          << "/q" << ((vn->getFlags() & Varnode::indirect_creation) != 0 ? 1 : 0)
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

PcodeOp *newStoreOp(Funcdata *fd,BlockBasic *block,uintb pc)
{
  Address address(fd->getArch()->getDefaultCodeSpace(),pc);
  PcodeOp *op = fd->newOp(3,address);
  fd->opSetOpcode(op,CPUI_STORE);
  fd->opInsertEnd(op,block);
  return op;
}

// SUBPIECE reader that slices one byte out of the middle of a lane:
// restriction fails (bytePos+size does not land on a lane boundary) while
// bytePos itself is a lane boundary and the lane is bigger than the piece,
// so the allowSubpieceTerminator branch (subflow.cc:3934-3944) converts the
// reader into a preexisting SUBPIECE over a single lane placeholder.
void runSubpieceTerminator(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("glob_range");
  if (fd == (Funcdata *)0) throw std::runtime_error("glob_range not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *copy = newOutputOp(fd,block,CPUI_COPY,0x8000,1,8);
  Varnode *root = copy->getOut();
  setInput(fd,copy,fd->newConstant(8,0x0102030405060708),0);
  PcodeOp *mid = newOutputOp(fd,block,CPUI_SUBPIECE,0x8001,2,1);
  setInput(fd,mid,root,0);
  setInput(fd,mid,fd->newConstant(4,4),1);
  string before = snapshot(fd,block);
  LaneDescription description(8,2);
  LaneDivide divide(fd,root,description,true);
  bool traced = divide.doTrace();
  bool markAfterTrace = root->isMark();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  std::cout << "subpiece|trace=" << (traced ? 1 : 0)
            << "|mark=" << (markAfterTrace ? 1 : 0)
            << "|before=" << before << "|after=" << after
            << "|old=" << (copy->isDead() ? 1 : 0)
            << "|mid=" << (mid->isDead() ? 1 : 0)
            << ',' << (int4)mid->code() << ',' << mid->numInput()
            << ',' << (mid->getIn(1)->isConstant() ? 1 : 0)
            << ',' << (int4)mid->getIn(1)->getOffset()
            << ',' << mid->getIn(0)->getSize() << '\n';
}

// Two STOREs reading the same root: the first through a written pointer
// (non-free path, subflow.cc:3713-3715 first guard passes), the second
// through a free constant pointer (free-but-constant path).  Lane 1 needs
// pointer advancement: newUnique + newOp(INT_ADD, follow=store) +
// newConstant(ptrSize,0,bytePos) with bytePos accumulating
// description.getSize(skipLanes+i).
void runStore(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("glob_set");
  if (fd == (Funcdata *)0) throw std::runtime_error("glob_set not found");
  AddrSpace *ramSpace = architecture.getSpaceByName("ram");
  if (ramSpace == (AddrSpace *)0) throw std::runtime_error("ram space not found");
  int4 ramIndex = ramSpace->getIndex();
  BlockBasic *block = newBlock(fd);
  PcodeOp *copy = newOutputOp(fd,block,CPUI_COPY,0x8100,1,4);
  Varnode *root = copy->getOut();
  setInput(fd,copy,fd->newConstant(4,0x11223344),0);
  PcodeOp *pointerCopy = newOutputOp(fd,block,CPUI_COPY,0x8101,1,8);
  setInput(fd,pointerCopy,fd->newConstant(8,0x1000),0);
  Varnode *pointer = pointerCopy->getOut();
  PcodeOp *storeA = newStoreOp(fd,block,0x8102);
  setInput(fd,storeA,fd->newVarnodeSpace(ramSpace),0);
  setInput(fd,storeA,pointer,1);
  setInput(fd,storeA,root,2);
  PcodeOp *storeB = newStoreOp(fd,block,0x8103);
  setInput(fd,storeB,fd->newVarnodeSpace(ramSpace),0);
  setInput(fd,storeB,fd->newConstant(8,0x2000),1);
  setInput(fd,storeB,root,2);
  string before = snapshot(fd,block);
  LaneDescription description(4,2);
  LaneDivide divide(fd,root,description,false);
  bool traced = divide.doTrace();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  int4 storeCount = 0;
  int4 addCount = 0;
  for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
    if ((*iter)->isDead()) continue;
    if ((*iter)->code() == CPUI_STORE) storeCount += 1;
    else if ((*iter)->code() == CPUI_INT_ADD) addCount += 1;
  }
  std::cout << "store|trace=" << (traced ? 1 : 0)
            << "|sp=" << ramIndex
            << "|before=" << before << "|after=" << after
            << "|old=" << (copy->isDead() ? 1 : 0)
            << ',' << (storeA->isDead() ? 1 : 0)
            << ',' << (storeB->isDead() ? 1 : 0)
            << "|split=" << storeCount << ',' << addCount << '\n';
}

// LOAD root: buildLoad splits into per-lane LOADs; lane 1 gets the advanced
// pointer (INT_ADD + byte offset 2), lane 0 reuses the base pointer at
// bytePos==0.
void runLoad(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("glob_url");
  if (fd == (Funcdata *)0) throw std::runtime_error("glob_url not found");
  AddrSpace *ramSpace = architecture.getSpaceByName("ram");
  if (ramSpace == (AddrSpace *)0) throw std::runtime_error("ram space not found");
  int4 ramIndex = ramSpace->getIndex();
  BlockBasic *block = newBlock(fd);
  PcodeOp *load = newOutputOp(fd,block,CPUI_LOAD,0x8200,2,4);
  Varnode *root = load->getOut();
  setInput(fd,load,fd->newVarnodeSpace(ramSpace),0);
  setInput(fd,load,fd->newConstant(8,0x3000),1);
  string before = snapshot(fd,block);
  LaneDescription description(4,2);
  LaneDivide divide(fd,root,description,false);
  bool traced = divide.doTrace();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  int4 loadCount = 0;
  for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
    if (!(*iter)->isDead() && (*iter)->code() == CPUI_LOAD) loadCount += 1;
  }
  std::cout << "load|trace=" << (traced ? 1 : 0)
            << "|sp=" << ramIndex
            << "|before=" << before << "|after=" << after
            << "|old=" << (load->isDead() ? 1 : 0)
            << "|split=" << loadCount << '\n';
}

// INT_RIGHT by a whole lane (16 bits = 2 bytes): the low lanes of the output
// copy from shifted source lanes, the most significant lane receives a zero
// constant COPY (subflow.cc:3819-3824).
void runRightShift(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("glob_word");
  if (fd == (Funcdata *)0) throw std::runtime_error("glob_word not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *copy = newOutputOp(fd,block,CPUI_COPY,0x8300,1,8);
  setInput(fd,copy,fd->newConstant(8,0x0102030405060708),0);
  Varnode *source = copy->getOut();
  PcodeOp *shift = newOutputOp(fd,block,CPUI_INT_RIGHT,0x8301,2,8);
  Varnode *root = shift->getOut();
  setInput(fd,shift,source,0);
  setInput(fd,shift,fd->newConstant(4,16),1);
  string before = snapshot(fd,block);
  LaneDescription description(8,2);
  LaneDivide divide(fd,root,description,false);
  bool traced = divide.doTrace();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  std::cout << "rightshift|trace=" << (traced ? 1 : 0)
            << "|before=" << before << "|after=" << after
            << "|old=" << (copy->isDead() ? 1 : 0)
            << ',' << (shift->isDead() ? 1 : 0) << '\n';
}

// INT_LEFT by a whole lane: the least significant lane receives the zero
// constant COPY, remaining lanes copy from the source lanes
// (subflow.cc:3856-3861).
void runLeftShift(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("match_url");
  if (fd == (Funcdata *)0) throw std::runtime_error("match_url not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *copy = newOutputOp(fd,block,CPUI_COPY,0x8400,1,8);
  setInput(fd,copy,fd->newConstant(8,0x1122334455667788),0);
  Varnode *source = copy->getOut();
  PcodeOp *shift = newOutputOp(fd,block,CPUI_INT_LEFT,0x8401,2,8);
  Varnode *root = shift->getOut();
  setInput(fd,shift,source,0);
  setInput(fd,shift,fd->newConstant(4,16),1);
  string before = snapshot(fd,block);
  LaneDescription description(8,2);
  LaneDivide divide(fd,root,description,false);
  bool traced = divide.doTrace();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  std::cout << "leftshift|trace=" << (traced ? 1 : 0)
            << "|before=" << before << "|after=" << after
            << "|old=" << (copy->isDead() ? 1 : 0)
            << ',' << (shift->isDead() ? 1 : 0) << '\n';
}

// INT_ZEXT from half the register: input lanes copy to the low output lanes
// and the remaining high lanes receive zero constants
// (subflow.cc:3899-3903).
void runZext(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("my_fwrite");
  if (fd == (Funcdata *)0) throw std::runtime_error("my_fwrite not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *copy = newOutputOp(fd,block,CPUI_COPY,0x8500,1,4);
  setInput(fd,copy,fd->newConstant(4,0xaabbccdd),0);
  Varnode *source = copy->getOut();
  PcodeOp *zext = newOutputOp(fd,block,CPUI_INT_ZEXT,0x8501,1,8);
  Varnode *root = zext->getOut();
  setInput(fd,zext,source,0);
  string before = snapshot(fd,block);
  LaneDescription description(8,2);
  LaneDivide divide(fd,root,description,false);
  bool traced = divide.doTrace();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  std::cout << "zext|trace=" << (traced ? 1 : 0)
            << "|before=" << before << "|after=" << after
            << "|old=" << (copy->isDead() ? 1 : 0)
            << ',' << (zext->isDead() ? 1 : 0) << '\n';
}

// Two INDIRECT roots: the first marked as a pure indirect creation (input is
// an indirect zero -> inheritIndirect propagates indirect_creation), the
// second marked possible-out (constant input without the zero flag ->
// inheritIndirect propagates indirect_creation_possible_out).  Every lane
// INDIRECT shares the iop annotation via newIop (subflow.cc:3681-3694).
void runIndirect(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("myprogress");
  if (fd == (Funcdata *)0) throw std::runtime_error("myprogress not found");
  AddrSpace *ramSpace = architecture.getSpaceByName("ram");
  if (ramSpace == (AddrSpace *)0) throw std::runtime_error("ram space not found");
  BlockBasic *block = newBlock(fd);

  PcodeOp *clobberA = newStoreOp(fd,block,0x8600);
  setInput(fd,clobberA,fd->newVarnodeSpace(ramSpace),0);
  setInput(fd,clobberA,fd->newConstant(8,0x4000),1);
  setInput(fd,clobberA,fd->newConstant(4,0x99),2);
  PcodeOp *indirectA = newOutputOp(fd,block,CPUI_INDIRECT,0x8601,2,4);
  Varnode *rootA = indirectA->getOut();
  setInput(fd,indirectA,fd->newConstant(4,0x11223344),0);
  setInput(fd,indirectA,fd->newVarnodeIop(clobberA),1);
  fd->markIndirectCreation(indirectA,false);

  PcodeOp *clobberB = newStoreOp(fd,block,0x8602);
  setInput(fd,clobberB,fd->newVarnodeSpace(ramSpace),0);
  setInput(fd,clobberB,fd->newConstant(8,0x4100),1);
  setInput(fd,clobberB,fd->newConstant(4,0x88),2);
  PcodeOp *indirectB = newOutputOp(fd,block,CPUI_INDIRECT,0x8603,2,4);
  Varnode *rootB = indirectB->getOut();
  setInput(fd,indirectB,fd->newConstant(4,0x55667788),0);
  setInput(fd,indirectB,fd->newVarnodeIop(clobberB),1);
  fd->markIndirectCreation(indirectB,true);

  string beforeA = snapshot(fd,block);
  int4 flagA = (rootA->getFlags() & Varnode::indirect_creation) != 0 ? 1 : 0;
  int4 flagB = (rootB->getFlags() & Varnode::indirect_creation) != 0 ? 1 : 0;
  LaneDescription description(4,2);
  LaneDivide divideA(fd,rootA,description,false);
  bool tracedA = divideA.doTrace();
  if (tracedA) divideA.apply();
  string middleA = snapshot(fd,block);
  LaneDivide divideB(fd,rootB,description,false);
  bool tracedB = divideB.doTrace();
  if (tracedB) divideB.apply();
  string after = snapshot(fd,block);
  int4 indirectCount = 0;
  int4 flaggedCount = 0;
  for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
    if ((*iter)->isDead()) continue;
    if ((*iter)->code() == CPUI_INDIRECT) {
      indirectCount += 1;
      if ((*iter)->isIndirectCreation()) flaggedCount += 1;
    }
  }
  std::cout << "indirect|trace=" << (tracedA ? 1 : 0) << ',' << (tracedB ? 1 : 0)
            << "|before=" << beforeA
            << "|middle=" << middleA
            << "|after=" << after
            << "|old=" << (indirectA->isDead() ? 1 : 0)
            << ',' << (indirectB->isDead() ? 1 : 0)
            << "|flagA=" << flagA
            << "|flagB=" << flagB
            << "|split=" << indirectCount << ',' << flaggedCount << '\n';
}

// Restricted window trace: a multi-lane SUBPIECE reader opens a skipLanes>0
// window (restriction of lanes 1-2), whose traceBackward runs the SUBPIECE
// extension (subflow.cc:4046-4057) reusing the root split, and whose
// traceForward sees both a mid-lane SUBPIECE terminator (laneIndex ==
// skipLanes) and a single-lane preexisting COPY.
void runRestrictedWindow(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("next_url");
  if (fd == (Funcdata *)0) throw std::runtime_error("next_url not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *copy = newOutputOp(fd,block,CPUI_COPY,0x8700,1,8);
  Varnode *root = copy->getOut();
  setInput(fd,copy,fd->newConstant(8,0x0102030405060708),0);
  PcodeOp *mid = newOutputOp(fd,block,CPUI_SUBPIECE,0x8701,2,4);
  Varnode *middle = mid->getOut();
  setInput(fd,mid,root,0);
  setInput(fd,mid,fd->newConstant(4,2),1);
  PcodeOp *tail = newOutputOp(fd,block,CPUI_SUBPIECE,0x8702,2,1);
  setInput(fd,tail,middle,0);
  setInput(fd,tail,fd->newConstant(4,2),1);
  PcodeOp *low = newOutputOp(fd,block,CPUI_SUBPIECE,0x8703,2,2);
  setInput(fd,low,middle,0);
  setInput(fd,low,fd->newConstant(4,0),1);
  string before = snapshot(fd,block);
  LaneDescription description(8,2);
  LaneDivide divide(fd,root,description,true);
  bool traced = divide.doTrace();
  if (traced) divide.apply();
  string after = snapshot(fd,block);
  std::cout << "window|trace=" << (traced ? 1 : 0)
            << "|before=" << before << "|after=" << after
            << "|old=" << (copy->isDead() ? 1 : 0)
            << ',' << (mid->isDead() ? 1 : 0)
            << "|tail=" << (tail->isDead() ? 1 : 0)
            << ',' << (int4)tail->code() << ',' << tail->numInput()
            << "|low=" << (low->isDead() ? 1 : 0)
            << ',' << (int4)low->code() << ',' << low->numInput() << '\n';
}

// Typelock gate (subflow.cc:3532-3538): a type-locked INT input and a
// type-locked STRUCT input are both rejected mid-trace (doTrace fails with
// zero mutation), while a type-locked ARRAY input stays inside the allow set
// and splits normally.
void runTypelock(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("progressbarinit");
  if (fd == (Funcdata *)0) throw std::runtime_error("progressbarinit not found");
  BlockBasic *block = newBlock(fd);
  TypeFactory *types = architecture.types;
  Datatype *intType = types->getBase(4,TYPE_INT);
  TypeStruct *structType = types->getTypeStruct("lanepair");
  Datatype *uintType = types->getBase(1,TYPE_UINT);
  Datatype *arrayType = types->getTypeArray(4,uintType);
  if (intType == (Datatype *)0 || structType == (TypeStruct *)0 ||
      uintType == (Datatype *)0 || arrayType == (Datatype *)0)
    throw std::runtime_error("typelock data-types not found");

  Varnode *intInput = fd->newUnique(4);
  intInput->updateType(intType,true,false);
  PcodeOp *intCopy = newOutputOp(fd,block,CPUI_COPY,0x8800,1,4);
  Varnode *intRoot = intCopy->getOut();
  setInput(fd,intCopy,intInput,0);
  PcodeOp *intReader = newOutputOp(fd,block,CPUI_SUBPIECE,0x8801,2,2);
  setInput(fd,intReader,intRoot,0);
  setInput(fd,intReader,fd->newConstant(4,0),1);

  Varnode *structInput = fd->newUnique(4);
  structInput->updateType(structType,true,false);
  PcodeOp *structCopy = newOutputOp(fd,block,CPUI_COPY,0x8802,1,4);
  Varnode *structRoot = structCopy->getOut();
  setInput(fd,structCopy,structInput,0);
  PcodeOp *structReader = newOutputOp(fd,block,CPUI_SUBPIECE,0x8803,2,2);
  setInput(fd,structReader,structRoot,0);
  setInput(fd,structReader,fd->newConstant(4,0),1);

  Varnode *arrayInput = fd->newUnique(4);
  arrayInput->updateType(arrayType,true,false);
  PcodeOp *arrayCopy = newOutputOp(fd,block,CPUI_COPY,0x8804,1,4);
  Varnode *arrayRoot = arrayCopy->getOut();
  setInput(fd,arrayCopy,arrayInput,0);
  PcodeOp *arrayReader = newOutputOp(fd,block,CPUI_SUBPIECE,0x8805,2,2);
  setInput(fd,arrayReader,arrayRoot,0);
  setInput(fd,arrayReader,fd->newConstant(4,0),1);

  string beforeInt = snapshot(fd,block);
  LaneDescription description(4,2);
  LaneDivide intDivide(fd,intRoot,description,false);
  bool tracedInt = intDivide.doTrace();
  string afterInt = snapshot(fd,block);
  LaneDivide structDivide(fd,structRoot,description,false);
  bool tracedStruct = structDivide.doTrace();
  string afterStruct = snapshot(fd,block);
  LaneDivide arrayDivide(fd,arrayRoot,description,false);
  bool tracedArray = arrayDivide.doTrace();
  if (tracedArray) arrayDivide.apply();
  string after = snapshot(fd,block);
  std::cout << "typelock|trace=" << (tracedInt ? 1 : 0) << ',' << (tracedStruct ? 1 : 0)
            << ',' << (tracedArray ? 1 : 0)
            << "|same=" << (beforeInt == afterInt ? 1 : 0)
            << ',' << (afterInt == afterStruct ? 1 : 0)
            << "|mark=" << (intRoot->isMark() ? 1 : 0)
            << ',' << (structRoot->isMark() ? 1 : 0)
            << "|lock=" << (intInput->isTypeLock() ? 1 : 0)
            << ',' << (structInput->isTypeLock() ? 1 : 0)
            << ',' << (arrayInput->isTypeLock() ? 1 : 0)
            << "|before=" << beforeInt << "|afterInt=" << afterInt
            << "|afterStruct=" << afterStruct << "|after=" << after << '\n';
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
    runSubpieceTerminator(architecture);
    runStore(architecture);
    runLoad(architecture);
    runRightShift(architecture);
    runLeftShift(architecture);
    runZext(architecture);
    runIndirect(architecture);
    runRestrictedWindow(architecture);
    runTypelock(architecture);
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
