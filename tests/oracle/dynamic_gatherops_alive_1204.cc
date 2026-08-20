/*
 * DYNAMIC-GATHEROPS-ALIVE-0001: locked Ghidra 12.0.4 oracle fixture.
 *
 * The target address has two alive ops and one dead op.  Alive integration
 * order deliberately differs from SeqNum order.  Adjacent-address alive ops
 * exercise both address-range boundaries, and seeded output vectors prove
 * gatherOpsAtAddress appends instead of clearing.
 */
#include "bfd_arch.hh"
#include "dynamic.hh"
#include "libdecomp.hh"

#include <iostream>
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

struct Fixture {
  Funcdata *fd;
  BlockBasic *block;
  map<PcodeOp *,string> names;

  explicit Fixture(Funcdata *func) : fd(func),block((BlockBasic *)0)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    block = graph.newBlockBasic(fd);
  }

  PcodeOp *make(const string &name,uintb offset,uintm time)
  {
    AddrSpace *codeSpace = fd->getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd->newOp(0,SeqNum(Address(codeSpace,offset),time));
    fd->opSetOpcode(op,CPUI_COPY);
    names[op] = name;
    return op;
  }

  string name(PcodeOp *op) const
  {
    map<PcodeOp *,string>::const_iterator iter = names.find(op);
    if (iter == names.end()) throw std::runtime_error("unknown fixture op");
    return (*iter).second;
  }

  string pointerOrder(const vector<PcodeOp *> &ops) const
  {
    ostringstream out;
    for(size_t i=0;i<ops.size();++i) {
      if (i != 0) out << ',';
      out << name(ops[i]);
    }
    return out.str();
  }

  string aliveOrder(void) const
  {
    vector<PcodeOp *> result;
    for(list<PcodeOp *>::const_iterator iter=fd->beginOpAlive();
        iter!=fd->endOpAlive();++iter) {
      if (names.find(*iter) != names.end()) result.push_back(*iter);
    }
    return pointerOrder(result);
  }

  string deadOrder(void) const
  {
    vector<PcodeOp *> result;
    for(list<PcodeOp *>::const_iterator iter=fd->beginOpDead();
        iter!=fd->endOpDead();++iter) {
      if (names.find(*iter) != names.end()) result.push_back(*iter);
    }
    return pointerOrder(result);
  }

  string treeOrder(void) const
  {
    vector<PcodeOp *> result;
    for(PcodeOpTree::const_iterator iter=fd->beginOpAll();
        iter!=fd->endOpAll();++iter) {
      if (names.find((*iter).second) != names.end())
        result.push_back((*iter).second);
    }
    return pointerOrder(result);
  }

  string blockOrder(void) const
  {
    vector<PcodeOp *> result;
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();
        iter!=block->endOp();++iter) {
      result.push_back(*iter);
    }
    return pointerOrder(result);
  }

  string parentState(void) const
  {
    ostringstream out;
    bool first = true;
    for(PcodeOpTree::const_iterator iter=fd->beginOpAll();
        iter!=fd->endOpAll();++iter) {
      PcodeOp *op = (*iter).second;
      if (names.find(op) == names.end()) continue;
      if (!first) out << ',';
      first = false;
      out << name(op) << ':' << (op->getParent() == block ? block->getIndex() : -1);
    }
    return out.str();
  }
};

void run(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    ostringstream architectureMessages;
    BfdArchitecture architecture(binary,"default",&architectureMessages);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw std::runtime_error("GetStr was not found in the BFD symbol table");

    Fixture fixture(fd);
    PcodeOp *before = fixture.make("before",0x0fff,40);
    PcodeOp *late = fixture.make("late",0x1000,30);
    PcodeOp *dead = fixture.make("dead",0x1000,20);
    PcodeOp *early = fixture.make("early",0x1000,10);
    PcodeOp *after = fixture.make("after",0x1001,0);

    // Deliberately not SeqNum order.  The target result must still be early,late.
    fd->opInsertEnd(late,fixture.block);
    fd->opInsertEnd(before,fixture.block);
    fd->opInsertEnd(after,fixture.block);
    fd->opInsertEnd(early,fixture.block);

    std::cout << "bank|alive=" << fixture.aliveOrder()
              << "|dead=" << fixture.deadOrder()
              << "|tree=" << fixture.treeOrder()
              << "|block=" << fixture.blockOrder() << '\n';

    vector<PcodeOp *> targetResult;
    targetResult.push_back(before);
    DynamicHash::gatherOpsAtAddress(
      targetResult,fd,Address(fd->getArch()->getDefaultCodeSpace(),0x1000));
    std::cout << "target|result=" << fixture.pointerOrder(targetResult)
              << "|early_time=" << early->getSeqNum().getTime()
              << "|late_time=" << late->getSeqNum().getTime()
              << "|dead_filtered=" << (dead->isDead() ? 1 : 0) << '\n';

    vector<PcodeOp *> emptyResult;
    emptyResult.push_back(after);
    DynamicHash::gatherOpsAtAddress(
      emptyResult,fd,Address(fd->getArch()->getDefaultCodeSpace(),0x2000));
    std::cout << "empty|result=" << fixture.pointerOrder(emptyResult) << '\n';

    std::cout << "post|alive=" << fixture.aliveOrder()
              << "|dead=" << fixture.deadOrder()
              << "|tree=" << fixture.treeOrder()
              << "|block=" << fixture.blockOrder()
              << "|parents=" << fixture.parentState()
              << "|before_dead=" << (before->isDead() ? 1 : 0)
              << "|early_dead=" << (early->isDead() ? 1 : 0)
              << "|late_dead=" << (late->isDead() ? 1 : 0)
              << "|after_dead=" << (after->isDead() ? 1 : 0) << '\n';
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: dynamic_gatherops_alive_1204 SPEC_ROOT CURL_BINARY\n";
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
