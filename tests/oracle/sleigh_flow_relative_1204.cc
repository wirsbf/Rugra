/*
 * Locked Ghidra 12.0.4 oracle for SLEIGH intra-instruction relative flow.
 *
 * Input is the exact raw x86-64 byte sequence 0f a2 c3 (CPUID; RET) loaded at
 * address zero.  CPUID expands into a dense p-code decision tree whose branch
 * operands remain in the constant space.  This fixture observes the complete
 * post-PcodeEmitFd operation/Varnode graph, FlowInfo visited map, relative
 * target resolution, raw edge pairs, and final basic-block graph.
 */

#include <bits/stdc++.h>

// Test-only observation of FlowInfo's state and the raw PcodeOp/Varnode flags.
// The production oracle sources are compiled without modifications.
#define private public
#define protected public
#include "flow.hh"
#include "libdecomp.hh"
#include "raw_arch.hh"
#undef protected
#undef private

namespace {

using namespace ghidra;
using std::map;
using std::runtime_error;
using std::string;
using std::vector;

const char *const TARGET = "x86:LE:64:default:gcc";
const char *const FUNCTION_NAME = "sleigh_flow_relative_probe";
const uint1 EXPECTED_IMAGE[]
  __attribute__((section(".rugra_input"),used,aligned(1))) = {0x0f, 0xa2, 0xc3};

// Funcdata::obank has default-private access (rather than an explicit
// `private:` label), so the preprocessor observation above cannot expose it.
// This standard test-only friend-injection idiom obtains only that one member.
template <typename Tag, typename Tag::type Member>
struct PrivateMemberAccess {
  friend typename Tag::type accessPrivate(Tag) { return Member; }
};

struct FuncdataOpBankTag {
  typedef PcodeOpBank Funcdata::*type;
  friend type accessPrivate(FuncdataOpBankTag);
};

template struct PrivateMemberAccess<FuncdataOpBankTag, &Funcdata::obank>;

string jsonEscape(const string &value)

{
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for(string::const_iterator iter=value.begin();iter!=value.end();++iter) {
    const unsigned char character = static_cast<unsigned char>(*iter);
    switch(character) {
    case '"': stream << "\\\""; break;
    case '\\': stream << "\\\\"; break;
    case '\b': stream << "\\b"; break;
    case '\f': stream << "\\f"; break;
    case '\n': stream << "\\n"; break;
    case '\r': stream << "\\r"; break;
    case '\t': stream << "\\t"; break;
    default:
      if (character < 0x20 || character >= 0x7f)
        stream << "\\u" << std::setw(4) << static_cast<uint4>(character);
      else
        stream << static_cast<char>(character);
      break;
    }
  }
  return stream.str();
}

string hexValue(uintb value,int4 width=16)

{
  std::ostringstream stream;
  stream << "0x" << std::hex << std::setfill('0') << std::setw(width) << value;
  return stream.str();
}

void writeSpace(const AddrSpace *space)

{
  if (space == (const AddrSpace *)0) {
    std::cout << "null";
    return;
  }
  std::cout << "{\"addr_size\":" << space->getAddrSize()
            << ",\"index\":" << space->getIndex()
            << ",\"name\":\"" << jsonEscape(space->getName())
            << "\",\"type\":" << static_cast<int4>(space->getType())
            << ",\"word_size\":" << space->getWordSize() << '}';
}

void writeAddress(const Address &address)

{
  if (address.isInvalid()) {
    std::cout << "null";
    return;
  }
  std::cout << "{\"offset\":\"" << hexValue(address.getOffset())
            << "\",\"space\":";
  writeSpace(address.getSpace());
  std::cout << '}';
}

void writeSeqNum(const SeqNum &seqnum,bool includeOrder)

{
  std::cout << "{\"address\":";
  writeAddress(seqnum.getAddr());
  if (includeOrder)
    std::cout << ",\"order\":" << seqnum.getOrder();
  std::cout << ",\"time\":" << seqnum.getTime() << '}';
}

int4 blockOrdinal(const vector<FlowBlock *> &blocks,const FlowBlock *needle)

{
  for(int4 i=0;i<blocks.size();++i)
    if (blocks[i] == needle) return i;
  return -1;
}

struct RelativeResolution {
  PcodeOp *source;
  PcodeOp *target;
  Address fallthru;
  bool isFallthru;
};

class Observation {
  Funcdata &data;
  FlowInfo &flow;
  PcodeOpBank &obank;
  const vector<FlowBlock *> &blocks;
  vector<PcodeOp *> ops;
  vector<Varnode *> varnodes;
  map<const PcodeOp *,uint8> opIds;
  map<const Varnode *,uint8> varnodeIds;
  map<const Varnode *,const AddrSpace *> spaceIds;
  vector<RelativeResolution> relatives;

  uint8 assignVarnode(Varnode *varnode)
  {
    map<const Varnode *,uint8>::const_iterator existing = varnodeIds.find(varnode);
    if (existing != varnodeIds.end()) return existing->second;
    const uint8 identity = varnodes.size();
    varnodeIds[varnode] = identity;
    varnodes.push_back(varnode);
    return identity;
  }

  void collectIdentities(void)
  {
    for(PcodeOpTree::const_iterator iter=data.beginOpAll();iter!=data.endOpAll();++iter) {
      PcodeOp *op = (*iter).second;
      opIds[op] = ops.size();
      ops.push_back(op);
      if (op->getOut() != (Varnode *)0)
        assignVarnode(op->getOut());
      for(int4 slot=0;slot<op->numInput();++slot) {
        assignVarnode(op->getIn(slot));
        if (slot == 0 && (op->code() == CPUI_LOAD || op->code() == CPUI_STORE))
          spaceIds[op->getIn(slot)] = op->getIn(slot)->getSpaceFromConst();
      }
    }
    for(VarnodeLocSet::const_iterator iter=data.beginLoc();iter!=data.endLoc();++iter)
      assignVarnode(*iter);
  }

  void collectRelatives(void)
  {
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      PcodeOp *op = *iter;
      if (op->code() != CPUI_BRANCH && op->code() != CPUI_CBRANCH)
        continue;
      if (op->numInput() == 0 || !op->getIn(0)->isConstant())
        continue;
      Address fallthru;
      PcodeOp *target = flow.findRelTarget(op,fallthru);
      RelativeResolution record;
      record.source = op;
      record.target = target;
      record.fallthru = fallthru;
      record.isFallthru = target == (PcodeOp *)0;
      relatives.push_back(record);
    }
  }

  void writeVarnodeRef(Varnode *varnode) const
  {
    map<const Varnode *,uint8>::const_iterator iter = varnodeIds.find(varnode);
    if (iter == varnodeIds.end()) throw runtime_error("unregistered Varnode identity");
    std::cout << (*iter).second;
  }

  void writeOpRef(PcodeOp *op) const
  {
    map<const PcodeOp *,uint8>::const_iterator iter = opIds.find(op);
    if (iter == opIds.end()) throw runtime_error("unregistered PcodeOp identity");
    std::cout << (*iter).second;
  }

  void writeDatatype(const Datatype *type) const
  {
    if (type == (const Datatype *)0) {
      std::cout << "null";
      return;
    }
    std::cout << "{\"metatype\":" << static_cast<int4>(type->getMetatype())
              << ",\"name\":\"" << jsonEscape(type->getName())
              << "\",\"size\":" << type->getSize() << '}';
  }

public:
  Observation(Funcdata &fd,FlowInfo &flowInfo,PcodeOpBank &opBank,
              const vector<FlowBlock *> &blockList)
    : data(fd), flow(flowInfo), obank(opBank), blocks(blockList)
  {
    collectIdentities();
    collectRelatives();
  }

  void writeHeader(const Architecture &architecture) const
  {
    std::cout << "{\"architecture\":\"x86:LE:64:default\""
              << ",\"compiler_spec\":\"gcc\""
              << ",\"input_hex\":\"0fa2c3\""
              << ",\"loaded_archid\":\"" << jsonEscape(architecture.archid)
              << "\",\"record\":\"header\"}\n";
  }

  void writeFlowState(const char *phase) const
  {
    std::cout << "{\"addrlist_count\":" << flow.addrlist.size()
              << ",\"baddr\":";
    writeAddress(flow.baddr);
    std::cout << ",\"eaddr\":";
    writeAddress(flow.eaddr);
    std::cout << ",\"flags\":" << flow.flags
              << ",\"function_size\":" << data.getSize()
              << ",\"inject_count\":" << flow.injectlist.size()
              << ",\"instruction_count\":" << flow.insn_count
              << ",\"instruction_max\":" << flow.insn_max
              << ",\"maxaddr\":";
    writeAddress(flow.maxaddr);
    std::cout << ",\"minaddr\":";
    writeAddress(flow.minaddr);
    std::cout << ",\"phase\":\"" << phase
              << "\",\"record\":\"flow_state\""
              << ",\"table_count\":" << flow.tablelist.size()
              << ",\"unprocessed_count\":" << flow.unprocessed.size()
              << ",\"visited_count\":" << flow.visited.size() << "}\n";
  }

  void writeVisited(void) const
  {
    for(map<Address,FlowInfo::VisitStat>::const_iterator iter=flow.visited.begin();
        iter!=flow.visited.end();++iter) {
      std::cout << "{\"address\":";
      writeAddress((*iter).first);
      std::cout << ",\"first_seq\":";
      writeSeqNum((*iter).second.seqnum,false);
      std::cout << ",\"record\":\"visited\",\"size\":"
                << (*iter).second.size << "}\n";
    }
  }

  void writeOperations(void) const
  {
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      PcodeOp *op = *iter;
      std::cout << "{\"addl_flags\":" << op->addlflags
                << ",\"flags\":" << op->flags
                << ",\"id\":";
      writeOpRef(op);
      std::cout << ",\"inputs\":[";
      for(int4 slot=0;slot<op->numInput();++slot) {
        if (slot != 0) std::cout << ',';
        writeVarnodeRef(op->getIn(slot));
      }
      std::cout << "],\"opcode\":" << static_cast<int4>(op->code())
                << ",\"opcode_name\":\"" << get_opname(op->code())
                << "\",\"output\":";
      if (op->getOut() == (Varnode *)0)
        std::cout << "null";
      else
        writeVarnodeRef(op->getOut());
      std::cout << ",\"parent_block\":" << blockOrdinal(blocks,op->getParent())
                << ",\"record\":\"op\",\"seq\":";
      writeSeqNum(op->getSeqNum(),true);
      std::cout << "}\n";
    }
  }

  void writeVarnodes(void) const
  {
    for(vector<Varnode *>::const_iterator iter=varnodes.begin();iter!=varnodes.end();++iter) {
      Varnode *varnode = *iter;
      map<const Varnode *,const AddrSpace *>::const_iterator spaceId = spaceIds.find(varnode);
      const bool isSpaceId = spaceId != spaceIds.end();
      std::cout << "{\"addl_flags\":" << varnode->addlflags
                << ",\"consume\":\"" << hexValue(varnode->consumed)
                << "\",\"cover_present\":" << (varnode->cover != (Cover *)0 ? "true" : "false")
                << ",\"create_index\":" << varnode->getCreateIndex()
                << ",\"def\":";
      if (varnode->getDef() == (PcodeOp *)0)
        std::cout << "null";
      else
        writeOpRef(varnode->getDef());
      std::cout << ",\"descendants\":[";
      bool first = true;
      for(list<PcodeOp *>::const_iterator diter=varnode->beginDescend();
          diter!=varnode->endDescend();++diter) {
        if (!first) std::cout << ',';
        first = false;
        writeOpRef(*diter);
      }
      std::cout << "],\"flags\":" << varnode->getFlags()
                << ",\"high_present\":" << (varnode->high != (HighVariable *)0 ? "true" : "false")
                << ",\"id\":";
      writeVarnodeRef(varnode);
      std::cout << ",\"kind\":\"" << (isSpaceId ? "spaceid" : "varnode")
                << "\",\"mapentry_present\":" << (varnode->mapentry != (SymbolEntry *)0 ? "true" : "false")
                << ",\"merge_group\":" << varnode->getMergeGroup()
                << ",\"nzmask\":";
      if (isSpaceId)
        std::cout << "null,\"offset\":null";
      else
        std::cout << "\"" << hexValue(varnode->getNZMask())
                  << "\",\"offset\":\"" << hexValue(varnode->getOffset()) << '"';
      std::cout << ",\"record\":\"varnode\",\"size\":" << varnode->getSize()
                << ",\"space\":";
      writeSpace(varnode->getSpace());
      std::cout << ",\"target_space\":";
      if (isSpaceId)
        writeSpace((*spaceId).second);
      else
        std::cout << "null";
      std::cout << ",\"type\":";
      writeDatatype(varnode->getType());
      std::cout << "}\n";
    }
  }

  void writeRelatives(void) const
  {
    for(vector<RelativeResolution>::const_iterator iter=relatives.begin();
        iter!=relatives.end();++iter) {
      const uintb offset = (*iter).source->getIn(0)->getOffset();
      const uintm computed = (*iter).source->getTime() + offset;
      std::cout << "{\"computed_target_time\":" << computed
                << ",\"kind\":\"" << ((*iter).isFallthru ? "fallthru" : "internal")
                << "\",\"offset\":\"" << hexValue(offset)
                << "\",\"record\":\"relative\",\"source\":";
      writeOpRef((*iter).source);
      std::cout << ",\"target\":";
      if ((*iter).isFallthru) {
        std::cout << "null,\"target_address\":";
        writeAddress((*iter).fallthru);
      }
      else {
        writeOpRef((*iter).target);
        std::cout << ",\"target_address\":null";
      }
      std::cout << "}\n";
    }
  }

  void writeRawEdges(void) const
  {
    list<PcodeOp *>::const_iterator source = flow.block_edge1.begin();
    list<PcodeOp *>::const_iterator target = flow.block_edge2.begin();
    uint8 ordinal = 0;
    while(source != flow.block_edge1.end()) {
      if (target == flow.block_edge2.end())
        throw runtime_error("raw edge lists have different lengths");
      std::cout << "{\"ordinal\":" << ordinal
                << ",\"record\":\"raw_edge\",\"source\":";
      writeOpRef(*source);
      std::cout << ",\"target\":";
      writeOpRef(*target);
      std::cout << "}\n";
      ++source;
      ++target;
      ordinal += 1;
    }
    if (target != flow.block_edge2.end())
      throw runtime_error("raw edge lists have different lengths");
  }

  void writeBlocks(void) const
  {
    for(int4 i=0;i<blocks.size();++i) {
      const FlowBlock *block = blocks[i];
      const BlockBasic *basic = dynamic_cast<const BlockBasic *>(block);
      if (basic == (const BlockBasic *)0)
        throw runtime_error("non-basic block in initial FlowInfo graph");
      std::cout << "{\"entry\":" << (block->isEntryPoint() ? "true" : "false")
                << ",\"flags\":" << block->getFlags()
                << ",\"id\":" << i << ",\"incoming\":[";
      for(int4 slot=0;slot<block->sizeIn();++slot) {
        if (slot != 0) std::cout << ',';
        std::cout << "{\"block\":" << blockOrdinal(blocks,block->getIn(slot))
                  << ",\"flags\":" << block->intothis[slot].label
                  << ",\"reverse\":" << block->getInRevIndex(slot) << '}';
      }
      std::cout << "],\"ops\":[";
      bool first = true;
      for(list<PcodeOp *>::const_iterator oiter=basic->beginOp();oiter!=basic->endOp();++oiter) {
        if (!first) std::cout << ',';
        first = false;
        writeOpRef(*oiter);
      }
      std::cout << "],\"outgoing\":[";
      for(int4 slot=0;slot<block->sizeOut();++slot) {
        if (slot != 0) std::cout << ',';
        std::cout << "{\"block\":" << blockOrdinal(blocks,block->getOut(slot))
                  << ",\"flags\":" << block->outofthis[slot].label
                  << ",\"reverse\":" << block->getOutRevIndex(slot) << '}';
      }
      std::cout << "],\"record\":\"block\",\"start\":";
      writeAddress(block->getStart());
      std::cout << ",\"stop\":";
      writeAddress(block->getStop());
      std::cout << "}\n";
    }
  }

  void writeSummary(void) const
  {
    uint8 graphEdges = 0;
    for(vector<FlowBlock *>::const_iterator iter=blocks.begin();iter!=blocks.end();++iter)
      graphEdges += (*iter)->sizeOut();
    uint8 internal = 0;
    uint8 fallthru = 0;
    for(vector<RelativeResolution>::const_iterator iter=relatives.begin();iter!=relatives.end();++iter) {
      if ((*iter).isFallthru) fallthru += 1;
      else internal += 1;
    }
    std::cout << "{\"alive_ops\":"
              << std::distance(data.beginOpAlive(),data.endOpAlive())
              << ",\"blocks\":" << blocks.size()
              << ",\"dead_ops\":"
              << std::distance(data.beginOpDead(),data.endOpDead())
              << ",\"graph_edges\":" << graphEdges
              << ",\"ops\":" << ops.size()
              << ",\"raw_edges\":" << flow.block_edge1.size()
              << ",\"record\":\"summary\""
              << ",\"relative_fallthru\":" << fallthru
              << ",\"relative_internal\":" << internal
              << ",\"relative_total\":" << relatives.size()
              << ",\"start_block\":" << blockOrdinal(blocks,flow.bblocks.getStartBlock())
              << ",\"varnodes\":" << varnodes.size()
              << ",\"visited\":" << flow.visited.size() << "}\n";
  }
};

void verifyImage(Architecture &architecture)

{
  uint1 loaded[sizeof(EXPECTED_IMAGE)] = {0};
  Address start(architecture.getDefaultCodeSpace(),0);
  architecture.loader->loadFill(loaded,sizeof(loaded),start);
  if (!std::equal(loaded,loaded+sizeof(loaded),EXPECTED_IMAGE))
    throw runtime_error("raw image is not exact x86 bytes 0f a2 c3");
}

void runFixture(const string &specDirectory,const string &rawImage)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    RawBinaryArchitecture architecture(rawImage,TARGET,&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    verifyImage(architecture);

    AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
    Address entry(codeSpace,0);
    Scope *globalScope = architecture.symboltab->getGlobalScope();
    Funcdata *data = globalScope->addFunction(entry,FUNCTION_NAME)->getFunction();
    if (data == (Funcdata *)0)
      throw runtime_error("failed to construct oracle Funcdata");

    PcodeOpBank &obank = data->*accessPrivate(FuncdataOpBankTag());
    BlockGraph &blocks = const_cast<BlockGraph &>(data->getBasicBlocks());
    vector<FuncCallSpecs *> calls;
    FlowInfo flow(*data,obank,blocks,calls);
    // fallthru() treats eaddr as the stopping bound, so use the byte immediately
    // after the three-byte image to allow the RET at offset 2 to be processed.
    flow.setRange(entry,entry+3);
    flow.setFlags(architecture.flowoptions);
    flow.setMaximumInstructions(architecture.max_instructions);
    flow.generateOps();

    // Capture the post-generation state before block movement only through
    // fields whose value is unchanged by generateBlocks().
    const uint8 generatedVisited = flow.visited.size();
    const uint8 generatedInstructions = flow.insn_count;
    flow.generateBlocks();
    if (flow.visited.size() != generatedVisited || flow.insn_count != generatedInstructions)
      throw runtime_error("generateBlocks unexpectedly changed visited state");
    if (!calls.empty())
      throw runtime_error("CPUID/RET fixture unexpectedly generated call specs");

    const vector<FlowBlock *> &blockList = blocks.getList();
    Observation observation(*data,flow,obank,blockList);
    observation.writeHeader(architecture);
    observation.writeFlowState("post_generate_blocks");
    observation.writeVisited();
    observation.writeOperations();
    observation.writeVarnodes();
    observation.writeRelatives();
    observation.writeRawEdges();
    observation.writeBlocks();
    observation.writeSummary();
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: sleigh_flow_relative_1204 SPEC_ROOT RAW_0FA2C3\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const ghidra::UnimplError &error) {
    std::cerr << "Ghidra UnimplError: " << error.explain << '\n';
  }
  catch(const ghidra::BadDataError &error) {
    std::cerr << "Ghidra BadDataError: " << error.explain << '\n';
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
