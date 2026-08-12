#include "bfd_arch.hh"
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

struct Fixture {
  Funcdata *fd;
  BlockBasic *block;
  vector<PcodeOp *> ops;
  map<PcodeOp *,string> names;
  PcodeOp *tracked;
  Varnode *trackedInput;
  Varnode *trackedOutput;

  explicit Fixture(Funcdata *func)
    : fd(func), block((BlockBasic *)0), tracked((PcodeOp *)0),
      trackedInput((Varnode *)0), trackedOutput((Varnode *)0)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    block = graph.newBlockBasic(fd);
  }

  PcodeOp *make(const string &name,OpCode opcode,int4 inputs=0)
  {
    AddrSpace *codeSpace = fd->getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd->newOp(inputs,Address(codeSpace,0x1000));
    fd->opSetOpcode(op,opcode);
    ops.push_back(op);
    names[op] = name;
    return op;
  }

  string name(PcodeOp *op) const
  {
    map<PcodeOp *,string>::const_iterator iter = names.find(op);
    if (iter == names.end()) throw std::runtime_error("unknown fixture op");
    return (*iter).second;
  }

  string blockOrder(void) const
  {
    ostringstream out;
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
      if (!first) out << ',';
      first = false;
      out << name(*iter);
    }
    return out.str();
  }

  string bankOrder(bool alive) const
  {
    ostringstream out;
    bool first = true;
    list<PcodeOp *>::const_iterator iter = alive ? fd->beginOpAlive() : fd->beginOpDead();
    list<PcodeOp *>::const_iterator enditer = alive ? fd->endOpAlive() : fd->endOpDead();
    for(;iter!=enditer;++iter) {
      if (names.find(*iter) == names.end()) continue;
      if (!first) out << ',';
      first = false;
      out << name(*iter);
    }
    return out.str();
  }

  string parentOrder(void) const
  {
    ostringstream out;
    bool first = true;
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      if (!first) out << ',';
      first = false;
      out << name(*iter) << ':';
      if ((*iter)->getParent() == block)
        out << block->getIndex();
      else
        out << -1;
    }
    return out.str();
  }

  string opState(void) const
  {
    ostringstream out;
    bool first = true;
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      PcodeOp *op = *iter;
      if (!first) out << ',';
      first = false;
      out << name(op) << ':' << op->getEvalType()
          << '/' << op->isBranch()
          << '/' << op->isCall()
          << '/' << op->isMarker()
          << '/' << op->isBoolOutput()
          << '/' << op->isFlowBreak()
          << '/' << op->isCodeRef()
          << '/' << op->notPrinted();
    }
    return out.str();
  }

  void dump(const string &stage,bool includeOrder) const
  {
    int4 parent = tracked->getParent() == block ? block->getIndex() : -1;
    int4 descendCount = std::distance(trackedInput->beginDescend(),trackedInput->endDescend());
    std::cout << stage
              << "|block=" << blockOrder()
              << "|alive=" << bankOrder(true)
              << "|dead=" << bankOrder(false)
              << "|parents=" << parentOrder()
              << "|opstate=" << opState()
              << "|flags=" << block->getFlags()
              << "|tracked_dead=" << tracked->isDead()
              << "|tracked_parent=" << parent
              << "|tracked_input_desc=" << descendCount
              << "|tracked_output_def=" << (trackedOutput->getDef() == tracked);
    if (includeOrder)
      std::cout << "|tracked_order=" << tracked->getSeqNum().getOrder();
    std::cout << '\n';
  }
};

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

    Fixture fixture(fd);
    PcodeOp *terminal = fixture.make("terminal",CPUI_BRANCHIND);
    PcodeOp *target = fixture.make("target",CPUI_STORE);
    PcodeOp *head = fixture.make("head",CPUI_COPY);
    PcodeOp *phiA = fixture.make("phi_a",CPUI_MULTIEQUAL);
    PcodeOp *phiB = fixture.make("phi_b",CPUI_MULTIEQUAL);
    PcodeOp *afterPhi = fixture.make("after_phi",CPUI_COPY);
    PcodeOp *indirect = fixture.make("indirect",CPUI_INDIRECT,2);
    PcodeOp *beforeTarget = fixture.make("before_target",CPUI_COPY,1);
    PcodeOp *afterIndirect = fixture.make("after_indirect",CPUI_COPY);
    PcodeOp *endNormal = fixture.make("end_normal",CPUI_COPY);

    fixture.tracked = beforeTarget;
    fixture.trackedInput = fd->newConstant(8,0x1234);
    fd->opSetInput(beforeTarget,fixture.trackedInput,0);
    fixture.trackedOutput = fd->newUniqueOut(8,beforeTarget);
    fd->opSetInput(indirect,fd->newConstant(8,0),0);
    fd->opSetInput(indirect,fd->newVarnodeIop(target),1);
    fixture.dump("created",false);

    fd->opInsertEnd(terminal,fixture.block);
    fd->opInsertEnd(target,fixture.block);
    fd->opInsertBegin(head,fixture.block);
    fd->opInsertBegin(phiA,fixture.block);
    fd->opInsertBegin(phiB,fixture.block);
    fd->opInsertAfter(afterPhi,phiB);
    fd->opInsertBefore(indirect,target);
    fd->opInsertBefore(beforeTarget,target);
    fd->opInsertAfter(afterIndirect,indirect);
    fd->opInsertEnd(endNormal,fixture.block);
    fixture.dump("inserted",true);

    fd->opUninsert(beforeTarget);
    fixture.dump("uninserted",true);

    fd->opInsertAfter(beforeTarget,head);
    fixture.dump("reinserted",true);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: op_insert_1204 SPEC_ROOT CURL_BINARY\n";
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
