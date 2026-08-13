#include "bfd_arch.hh"
#include "graph.hh"
#include "libdecomp.hh"
#include "unionresolve.hh"
#include "variable.hh"

#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::string;
using std::vector;

string opTimes(Funcdata *fd)
{
  string result;
  for(PcodeOpTree::const_iterator iter=fd->beginOpAll();iter!=fd->endOpAll();++iter) {
    if (!result.empty()) result += ',';
    result += std::to_string((*iter).second->getTime());
  }
  return result;
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
      throw std::runtime_error("GetStr was not found");

    AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
    AddrSpace *registerSpace = architecture.getSpaceByName("register");
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(fd);

    PcodeOp *first = fd->newOp(0,Address(codeSpace,0x1000));
    PcodeOp *middle = fd->newOp(0,Address(codeSpace,0x1000));
    PcodeOp *last = fd->newOp(0,Address(codeSpace,0x1000));
    fd->opSetOpcode(first,CPUI_COPY);
    fd->opSetOpcode(middle,CPUI_COPY);
    fd->opSetOpcode(last,CPUI_COPY);
    Varnode *firstOut = fd->newVarnodeOut(4,Address(registerSpace,0x20),first);
    Varnode *middleOut = fd->newVarnodeOut(4,Address(registerSpace,0x20),middle);

    const uintm firstTime = first->getTime();
    const uintm middleTime = middle->getTime();
    const SeqNum firstIdentity = first->getSeqNum();
    const SeqNum middleIdentity = middle->getSeqNum();
    const SeqNum sameTimeOtherAddress(Address(codeSpace,0x2000),firstTime);
    fd->opInsertEnd(first,block);
    fd->opInsertEnd(middle,block);
    fd->opInsertEnd(last,block);

    // Repeated insertions into the same shrinking gap force BlockBasic::setOrder
    // more than once. SeqNum time/identity and both bank keys must remain stable.
    for(int4 i=0;i<70;++i) {
      PcodeOp *padding = fd->newOp(0,Address(codeSpace,0x1000));
      fd->opSetOpcode(padding,CPUI_COPY);
      fd->opInsertBefore(padding,middle);
    }
    fd->opUninsert(first);
    fd->opInsertEnd(first,block); // time(first)<time(middle), order(first)>order(middle)

    PcodeOp *firstLookup = fd->findOp(firstIdentity);
    PcodeOp *middleLookup = fd->findOp(middleIdentity);
    VarnodeLocSet::const_iterator firstVn = fd->beginLoc(4,firstOut->getAddr(),first->getAddr(),firstTime);
    VarnodeLocSet::const_iterator middleVn = fd->beginLoc(4,middleOut->getAddr(),middle->getAddr(),middleTime);

    std::cout << "time_order=" << first->getTime() << ':' << first->getSeqNum().getOrder()
              << ',' << middle->getTime() << ':' << middle->getSeqNum().getOrder() << '\n';
    std::cout << "identity=" << (firstIdentity == first->getSeqNum())
              << ',' << (middleIdentity == middle->getSeqNum()) << '\n';
    std::cout << "cross_address=" << (firstIdentity == sameTimeOtherAddress)
              << ',' << (firstIdentity < sameTimeOtherAddress) << '\n';
    std::cout << "lookup=" << (firstLookup == first) << ',' << (middleLookup == middle) << '\n';
    std::cout << "varnode_lookup=" << (firstVn != fd->endLoc() && *firstVn == firstOut)
              << ',' << (middleVn != fd->endLoc() && *middleVn == middleOut) << '\n';
    std::cout << "optree_prefix=" << opTimes(fd).substr(0,5) << '\n';
    std::cout << "order_relation="
              << (first->getSeqNum().getOrder() < middle->getSeqNum().getOrder()) << '\n';

    std::ostringstream graphDump;
    dump_dataflow_graph(*fd,graphDump);
    const string graphText = graphDump.str();
    const string opSection = graphText.substr(
      graphText.find("//START:opnodes"),
      graphText.find("*END_COLUMNS",graphText.find("//START:opnodes"))
        - graphText.find("//START:opnodes"));
    std::cout << "graph_time="
              << (opSection.find("\no" + std::to_string(firstTime) + " ") != string::npos)
              << ',' << (graphText.find("\no" + std::to_string(firstTime) + " v") != string::npos)
              << '\n';

    Datatype *parentType = architecture.types->getBase(4,TYPE_UNKNOWN);
    ResolveEdge firstSlotOne(parentType,first,1);
    ResolveEdge middleSlotZero(parentType,middle,0);
    ResolveEdge firstSlotZero(parentType,first,0);
    std::cout << "resolve_order=" << (firstSlotOne < middleSlotZero)
              << ',' << (firstSlotZero < middleSlotZero) << '\n';
    std::cout << "compare_name=" << HighVariable::compareName(firstOut,middleOut)
              << ',' << HighVariable::compareName(middleOut,firstOut) << '\n';
    fd->opDestroy(first);
    VarnodeLocSet::const_iterator deleted = fd->beginLoc(4,Address(registerSpace,0x20),
                                                         Address(codeSpace,0x1000),firstTime);
    VarnodeLocSet::const_iterator retained = fd->beginLoc(4,Address(registerSpace,0x20),
                                                          Address(codeSpace,0x1000),middleTime);
    std::cout << "destroy_identity="
              << (deleted == fd->endLoc() || *deleted != firstOut)
              << ',' << (retained != fd->endLoc() && *retained == middleOut) << '\n';
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc,char **argv)
{
  if (argc != 3) return 2;
  try {
    run(argv[1],argv[2]);
    return 0;
  }
  catch(const std::exception &err) {
    std::cerr << err.what() << '\n';
    return 1;
  }
}
