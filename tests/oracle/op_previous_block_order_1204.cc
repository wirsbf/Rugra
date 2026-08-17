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

// Fixture for PcodeOp::previousOp (op.cc:344) and PcodeOp::nextOp (op.cc:323)
// block-order semantics. The discriminative property: ops prepended late via
// opInsertBefore (the INDIRECT-guard insertion pattern used by heritage and
// merge) sit mid-block in the block op list but at the TAIL of the alivelist
// (PcodeOpBank::markAlive appends, op.cc:1022). previousOp/nextOp walk the
// block list (basiciter), never the alivelist.
struct Fixture {
  Funcdata *fd;
  BlockBasic *b1;			// guarded chain block
  BlockBasic *b2;			// fall-thru successor (b1 out edge 0)
  BlockBasic *b3;			// alternate successor (b1 out edge 1)
  BlockBasic *b4;			// three-way switch block
  BlockBasic *b5;
  BlockBasic *b6;
  BlockBasic *b7;
  vector<PcodeOp *> probeOrder;		// stable creation order
  map<PcodeOp *,string> names;

  explicit Fixture(Funcdata *func)
    : fd(func), b1((BlockBasic *)0), b2((BlockBasic *)0), b3((BlockBasic *)0),
      b4((BlockBasic *)0), b5((BlockBasic *)0), b6((BlockBasic *)0),
      b7((BlockBasic *)0)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    b1 = graph.newBlockBasic(fd);
    b2 = graph.newBlockBasic(fd);
    b3 = graph.newBlockBasic(fd);
    b4 = graph.newBlockBasic(fd);
    b5 = graph.newBlockBasic(fd);
    b6 = graph.newBlockBasic(fd);
    b7 = graph.newBlockBasic(fd);
  }

  PcodeOp *make(const string &name,OpCode opcode,int4 inputs=0)
  {
    AddrSpace *codeSpace = fd->getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd->newOp(inputs,Address(codeSpace,0x1000));
    fd->opSetOpcode(op,opcode);
    probeOrder.push_back(op);
    names[op] = name;
    return op;
  }

  string name(PcodeOp *op) const
  {
    map<PcodeOp *,string>::const_iterator iter = names.find(op);
    if (iter == names.end()) throw std::runtime_error("unknown fixture op");
    return (*iter).second;
  }

  string blockOrder(BlockBasic *bl) const
  {
    ostringstream out;
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=bl->beginOp();iter!=bl->endOp();++iter) {
      if (!first) out << ',';
      first = false;
      out << name(*iter);
    }
    return out.str();
  }

  string aliveOrder(void) const
  {
    ostringstream out;
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=fd->beginOpAlive();iter!=fd->endOpAlive();++iter) {
      if (names.find(*iter) == names.end()) continue;
      if (!first) out << ',';
      first = false;
      out << name(*iter);
    }
    return out.str();
  }

  string probePrevious(void) const
  {
    ostringstream out;
    bool first = true;
    for(vector<PcodeOp *>::const_iterator iter=probeOrder.begin();iter!=probeOrder.end();++iter) {
      PcodeOp *op = *iter;
      if (op->getParent() == (BlockBasic *)0) continue; // dead/unattached is undefined for previousOp
      if (!first) out << ',';
      first = false;
      PcodeOp *prev = op->previousOp();
      out << name(op) << ':' << (prev == (PcodeOp *)0 ? string("null") : name(prev));
    }
    return out.str();
  }

  string probeNext(void) const
  {
    ostringstream out;
    bool first = true;
    for(vector<PcodeOp *>::const_iterator iter=probeOrder.begin();iter!=probeOrder.end();++iter) {
      PcodeOp *op = *iter;
      if (op->getParent() == (BlockBasic *)0) continue;
      if (!first) out << ',';
      first = false;
      PcodeOp *next = op->nextOp();
      out << name(op) << ':' << (next == (PcodeOp *)0 ? string("null") : name(next));
    }
    return out.str();
  }

  void dump(const string &stage) const
  {
    std::cout << stage
              << "|b1=" << blockOrder(b1)
              << "|alive=" << aliveOrder()
              << "|prev=" << probePrevious()
              << "|next=" << probeNext()
              << "|b1_out=" << b1->sizeOut()
              << "|b4_out=" << b4->sizeOut()
              << '\n';
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
    // Ops of b1: head -> [guards...] -> mid (STORE) -> tail. The INDIRECT
    // guards carry the classic (const, iop-of-effect-op) input pair.
    PcodeOp *head = fixture.make("head",CPUI_COPY);
    PcodeOp *mid = fixture.make("mid",CPUI_STORE,3);
    PcodeOp *ind1 = fixture.make("ind1",CPUI_INDIRECT,2);
    PcodeOp *tail = fixture.make("tail",CPUI_COPY);
    PcodeOp *ind2 = fixture.make("ind2",CPUI_INDIRECT,2);
    PcodeOp *succHead = fixture.make("succ_head",CPUI_COPY);
    PcodeOp *altHead = fixture.make("alt_head",CPUI_COPY);
    PcodeOp *multiOut = fixture.make("multi_out",CPUI_COPY);
    fd->opSetInput(ind1,fd->newConstant(8,0),0);
    fd->opSetInput(ind1,fd->newVarnodeIop(mid),1);
    fd->opSetInput(ind2,fd->newConstant(8,0),0);
    fd->opSetInput(ind2,fd->newVarnodeIop(mid),1);

    // Stage base: straight append order (block order == alivelist order).
    fd->opInsertEnd(head,fixture.b1);
    fd->opInsertEnd(mid,fixture.b1);
    fixture.dump("base");

    // Stage guard1: INDIRECT prepended before the STORE late in life.
    fd->opInsertBefore(ind1,mid);
    fixture.dump("guard1");

    // Stage guard2: tail appended, then a second guard prepended before the
    // first guard. Block [head,ind2,ind1,mid,tail] vs alive
    // [head,mid,ind1,tail,ind2] — orders diverge everywhere.
    fd->opInsertEnd(tail,fixture.b1);
    fd->opInsertBefore(ind2,ind1);
    fixture.dump("guard2");

    // Stage edges: successors and the three-way switch block. nextOp(tail)
    // must now follow b1 out edge 0 into b2; sizeOut==3 keeps nextOp(multi_out)
    // null (op.cc:334).
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    fd->opInsertEnd(succHead,fixture.b2);
    fd->opInsertEnd(altHead,fixture.b3);
    fd->opInsertEnd(multiOut,fixture.b4);
    graph.addEdge(fixture.b1,fixture.b2);
    graph.addEdge(fixture.b1,fixture.b3);
    graph.addEdge(fixture.b4,fixture.b5);
    graph.addEdge(fixture.b4,fixture.b6);
    graph.addEdge(fixture.b4,fixture.b7);
    fixture.dump("edges");

    // Stage uninsert: pulling ind1 out of the block must re-link the chain to
    // prev(mid)=ind2 directly, and remove ind1 from the alive list.
    fd->opUninsert(ind1);
    fixture.dump("uninsert");
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: op_previous_block_order_1204 SPEC_ROOT CURL_BINARY\n";
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
