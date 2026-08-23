/* ACTION-LANEDIVIDE-0001: locked Ghidra 12.0.4 oracle fixture.
 *
 * Exercises the real ActionLaneDivide::apply (coreaction.cc:585-622) —
 * collectLaneSizes candidate filtering, processVarnode success (mode 0
 * collected lanes) and failure (mode 2 default pointer-size lane with a
 * non-splittable INT_MULT definition), the post-apply IR and change
 * counter, the rule_onceperfunc second-pass skip, and the
 * clearLanedAccessMap timing.
 */
#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

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

/* Exposes the protected Action bookkeeping (count/status) for projection. */
class ProbeLaneDivide : public ActionLaneDivide {
public:
  ProbeLaneDivide(const string &g) : ActionLaneDivide(g) {}
  int4 exposedCount() const { return count; }
  uint4 exposedStatus() const { return status; }
  virtual Action *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Action *)0;
    return new ProbeLaneDivide(getGroup());
  }
};

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

PcodeOp *newOutputOp(Funcdata *fd,BlockBasic *block,OpCode opcode,uintb pc,int4 inputs,int4 outputSize)
{
  Address address(fd->getArch()->getDefaultCodeSpace(),pc);
  PcodeOp *op = fd->newOp(inputs,address);
  fd->opSetOpcode(op,opcode);
  fd->newUniqueOut(outputSize,op);
  fd->opInsertEnd(op,block);
  return op;
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

/* Success path: 4-byte PIECE root with two 2-byte SUBPIECE descendants.
 * collectLaneSizes accepts lane size 2 from the descendants and from the
 * PIECE definition; processVarnode mode 0 splits; the second perform must
 * skip apply entirely (rule_onceperfunc), leaving a re-queued laned-map
 * entry intact. */
void runPiece(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("main_free");
  if (fd == (Funcdata *)0) throw std::runtime_error("main_free not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *piece = newOutputOp(fd,block,CPUI_PIECE,0x5000,2,4);
  Varnode *root = piece->getOut();
  fd->opSetInput(piece,fd->newConstant(2,0x1122),0);
  fd->opSetInput(piece,fd->newConstant(2,0x3344),1);
  PcodeOp *low = newOutputOp(fd,block,CPUI_SUBPIECE,0x5001,2,2);
  fd->opSetInput(low,root,0);
  fd->opSetInput(low,fd->newConstant(4,0),1);
  PcodeOp *high = newOutputOp(fd,block,CPUI_SUBPIECE,0x5002,2,2);
  fd->opSetInput(high,root,0);
  fd->opSetInput(high,fd->newConstant(4,2),1);
  string mapBefore = laneMap(fd,architecture);
  string irBefore = snapshot(fd,block);
  ProbeLaneDivide action("probe");
  int4 ret1 = action.perform(*fd);
  string mapAfter = laneMap(fd,architecture);
  string irAfter = snapshot(fd,block);
  AddrSpace *registerSpace = architecture.getSpaceByName("register");
  fd->checkForLanedRegister(16,Address(registerSpace,0x77));
  string mapRequeued = laneMap(fd,architecture);
  int4 ret2 = action.perform(*fd);
  string mapAfterSecond = laneMap(fd,architecture);
  string irAfterSecond = snapshot(fd,block);
  std::cout << "piece|ret1=" << ret1
            << "|count=" << action.exposedCount()
            << "|status=" << action.exposedStatus()
            << "|map=" << mapBefore << '>' << mapAfter
            << "|requeued=" << mapRequeued
            << "|ret2=" << ret2
            << "|map2=" << mapAfterSecond
            << "|status2=" << action.exposedStatus()
            << "|count2=" << action.exposedCount()
            << "|irStable=" << (irAfter == irAfterSecond ? 1 : 0)
            << "|before=" << irBefore
            << "|after=" << irAfter << '\n';
}

/* Failure path: 16-byte INT_MULT root (INT_MULT is not lane-splittable
 * backward), one 2-byte SUBPIECE descendant. collectLaneSizes rejects
 * lane size 2 against the whole-size-16 record (bit 8 only); modes 0/1
 * collect nothing; mode 2 falls back to the default pointer-size lane 8
 * and the backward trace rejects INT_MULT. Zero mutation; the laned map
 * is still cleared at the end of apply. */
void runFailure(BfdArchitecture &architecture)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("main_init");
  if (fd == (Funcdata *)0) throw std::runtime_error("main_init not found");
  BlockBasic *block = newBlock(fd);
  PcodeOp *multiply = newOutputOp(fd,block,CPUI_INT_MULT,0x7000,2,16);
  Varnode *root = multiply->getOut();
  fd->opSetInput(multiply,fd->newConstant(16,0x1122334455667788),0);
  fd->opSetInput(multiply,fd->newConstant(16,0x99aabbccddeeff00),1);
  PcodeOp *low = newOutputOp(fd,block,CPUI_SUBPIECE,0x7001,2,2);
  fd->opSetInput(low,root,0);
  fd->opSetInput(low,fd->newConstant(4,0),1);
  string mapBefore = laneMap(fd,architecture);
  string irBefore = snapshot(fd,block);
  ProbeLaneDivide action("probe");
  int4 ret1 = action.perform(*fd);
  string mapAfter = laneMap(fd,architecture);
  string irAfter = snapshot(fd,block);
  std::cout << "failure|ret1=" << ret1
            << "|count=" << action.exposedCount()
            << "|status=" << action.exposedStatus()
            << "|map=" << mapBefore << '>' << mapAfter
            << "|irSame=" << (irBefore == irAfter ? 1 : 0)
            << "|before=" << irBefore
            << "|after=" << irAfter << '\n';
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
    architecture.lanerecords.push_back(LanedRegister(4,1u << 2));
    architecture.lanerecords.push_back(LanedRegister(16,1u << 8));
    architecture.readLoaderSymbols("::");
    // Project the normalized mode-2 default lane size (what
    // processVarnode actually consumes), not the raw pointer size: the
    // C++ oracle reads a spec-configured TypeFactory while the Rust
    // comparand drives a bare Architecture whose TypeFactory is
    // unconfigured; coreaction.cc:566-569 normalizes both to the same
    // default lane.
    int4 defaultSize = architecture.types->getSizeOfPointer();
    if (defaultSize != 4) defaultSize = 8;
    std::cout << "arch|default=" << defaultSize
              << "|min=" << architecture.getMinimumLanedRegisterSize()
              << "|sizes=" << architecture.lanerecords[0].getWholeSize()
              << ',' << architecture.lanerecords[1].getWholeSize() << '\n';
    runPiece(architecture);
    runFailure(architecture);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: action_lanedivide_1204 SPEC_ROOT CURL_BINARY\n";
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
