/*
 * Locked Ghidra 12.0.4 oracle for FlowInfo entry-block registration.
 *
 * The executable is also the input binary.  Two naked x86-64 symbols give
 * FlowInfo a one-block RETURN graph and a one-block self-loop graph.  The
 * latter forces generateBlocks() to create the synthetic empty entry block.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" __attribute__((naked, noinline, used)) void block_entry_ret_probe(void)
{
  __asm__ volatile("ret");
}

extern "C" __attribute__((naked, noinline, used)) void block_entry_loop_probe(void)
{
  __asm__ volatile("jmp block_entry_loop_probe");
}

namespace {

using namespace ghidra;
using std::runtime_error;
using std::string;
using std::vector;

int4 ordinalOf(const vector<FlowBlock *> &blocks,const FlowBlock *needle)

{
  for(int4 i=0;i<blocks.size();++i)
    if (blocks[i] == needle) return i;
  return -1;
}

int4 opCount(const FlowBlock *block)

{
  const BlockBasic *basic = dynamic_cast<const BlockBasic *>(block);
  if (basic == (const BlockBasic *)0) return -1;
  int4 count = 0;
  for(list<PcodeOp *>::const_iterator iter=basic->beginOp();iter!=basic->endOp();++iter)
    count += 1;
  return count;
}

void writeAddressDelta(const Address &address,const Address &base)

{
  if (address.isInvalid()) {
    std::cout << "invalid";
    return;
  }
  std::cout << static_cast<int8>(address.getOffset() - base.getOffset());
}

void writeEdges(const vector<FlowBlock *> &blocks,const FlowBlock *block,bool outgoing)

{
  const int4 count = outgoing ? block->sizeOut() : block->sizeIn();
  std::cout << '[';
  for(int4 slot=0;slot<count;++slot) {
    if (slot != 0) std::cout << ',';
    const FlowBlock *peer = outgoing ? block->getOut(slot) : block->getIn(slot);
    const int4 reverse = outgoing ? block->getOutRevIndex(slot) : block->getInRevIndex(slot);
    std::cout << ordinalOf(blocks,peer) << ':' << reverse;
  }
  std::cout << ']';
}

void observe(Architecture &architecture,const string &name)

{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(name);
  if (fd == (Funcdata *)0)
    throw runtime_error("probe function not found: " + name);
  if (fd->hasNoCode())
    throw runtime_error("probe function has no code: " + name);

  AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
  fd->followFlow(Address(codeSpace,0),Address(codeSpace,codeSpace->getHighest()));

  const BlockGraph &graph = fd->getBasicBlocks();
  const vector<FlowBlock *> &blocks = graph.getList();
  FlowBlock *entry = graph.getStartBlock();
  int4 entryCount = 0;
  for(int4 i=0;i<blocks.size();++i)
    if (blocks[i]->isEntryPoint()) entryCount += 1;

  std::cout << "case=" << name << '\n';
  std::cout << "blocks=" << blocks.size()
            << " entry_ordinal=" << ordinalOf(blocks,entry)
            << " entry_count=" << entryCount << '\n';
  for(int4 i=0;i<blocks.size();++i) {
    const FlowBlock *block = blocks[i];
    std::cout << "block=" << i
              << " index=" << block->getIndex()
              << " flags=" << block->getFlags()
              << " ops=" << opCount(block)
              << " start=";
    writeAddressDelta(block->getStart(),fd->getAddress());
    std::cout << " stop=";
    writeAddressDelta(block->getStop(),fd->getAddress());
    std::cout << " in=";
    writeEdges(blocks,block,false);
    std::cout << " out=";
    writeEdges(blocks,block,true);
    std::cout << '\n';
  }
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    observe(architecture,"block_entry_ret_probe");
    observe(architecture,"block_entry_loop_probe");
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 2) {
    std::cerr << "usage: block_entry_1204 SPEC_ROOT\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[0]);
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
