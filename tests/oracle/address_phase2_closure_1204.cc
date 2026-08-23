/*
 * ADDRESS-PHASE2-CLOSURE-0001: locked Ghidra 12.0.4 behavior probe.
 *
 * The probe deliberately gives RAM, an overlay, and the stack the same
 * numeric offsets.  It records the full Address/SeqNum identities consumed
 * by PcodeOpBank and FlowInfo, then records the object/list/block mutations
 * made by splitBasic.  Private access is observation-only: production
 * algorithms are compiled from the unmodified locked sources.
 */

#include <bits/stdc++.h>

#define class struct
#define private public
#define protected public
#include "flow.hh"
#include "libdecomp.hh"
#include "raw_arch.hh"
#undef protected
#undef private
#undef class

namespace {

using namespace ghidra;
using std::list;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

const char *const TARGET = "x86:LE:64:default:gcc";
const uint1 IMAGE[] __attribute__((section(".rugra_input"),used,aligned(1))) = {
  0x75, 0x01, 0x90, 0xc3                 // jne +1; nop; ret
};

// Funcdata::obank has implicit private access, so private->public cannot
// expose it.  This test-only friend injection reads that one member.
template <typename Tag, typename Tag::type Member>
struct PrivateMemberAccess {
  friend typename Tag::type accessPrivate(Tag) { return Member; }
};

struct FuncdataOpBankTag {
  typedef PcodeOpBank Funcdata::*type;
  friend type accessPrivate(FuncdataOpBankTag);
};
template struct PrivateMemberAccess<FuncdataOpBankTag, &Funcdata::obank>;

struct FixtureOverlaySpace final : public OverlaySpace {
  FixtureOverlaySpace(AddrSpaceManager *manager,const Translate *translate,
                      const string &name,int4 index,AddrSpace *base)
    : OverlaySpace(manager,translate)
  {
    this->name = name;
    this->index = index;
    baseSpace = base;
    addressSize = base->getAddrSize();
    wordsize = base->getWordSize();
    delay = base->getDelay();
    deadcodedelay = base->getDeadcodeDelay();
    calcScaleMask();
    if (base->isBigEndian()) setFlags(AddrSpace::big_endian);
    if (base->hasPhysical()) setFlags(AddrSpace::hasphysical);
  }
};

struct FixtureRawArchitecture final : public RawBinaryArchitecture {
  FixtureRawArchitecture(const string &path,const string &target,ostream *errors)
    : RawBinaryArchitecture(path,target,errors) {}

  AddrSpace *installOverlay(AddrSpace *base)
  {
    AddrSpace *overlay = new FixtureOverlaySpace(
      this,translate,"code_overlay",numSpaces(),base);
    insertSpace(overlay);
    return overlay;
  }
};

string hexValue(uintb value)
{
  ostringstream stream;
  stream << "0x" << std::hex << value;
  return stream.str();
}

string addressToken(const Address &address)
{
  if (address.isInvalid()) return "invalid";
  ostringstream stream;
  stream << address.getSpace()->getName() << '@' << address.getSpace()->getIndex()
         << ':' << hexValue(address.getOffset()) << ":invalid=0";
  return stream.str();
}

string opLabel(const map<const PcodeOp *,string> &labels,const PcodeOp *op)
{
  if (op == (const PcodeOp *)0) return "null";
  map<const PcodeOp *,string>::const_iterator iter = labels.find(op);
  if (iter != labels.end()) return iter->second;
  ostringstream stream;
  stream << 'T' << op->getTime();
  return stream.str();
}

template <typename Iterator>
string opListToken(Iterator begin,Iterator end,const map<const PcodeOp *,string> &labels)
{
  ostringstream stream;
  stream << '[';
  bool first = true;
  for(Iterator iter=begin;iter!=end;++iter) {
    if (!first) stream << ',';
    first = false;
    stream << opLabel(labels,*iter);
  }
  stream << ']';
  return stream.str();
}

string allOpsToken(const PcodeOpBank &bank,const map<const PcodeOp *,string> &labels)
{
  ostringstream stream;
  stream << '[';
  bool first = true;
  for(PcodeOpTree::const_iterator iter=bank.beginAll();iter!=bank.endAll();++iter) {
    if (!first) stream << ',';
    first = false;
    stream << opLabel(labels,(*iter).second);
  }
  stream << ']';
  return stream.str();
}

void printMembership(const char *caseName,const char *phase,const PcodeOpBank &bank,
                     const map<const PcodeOp *,string> &labels)
{
  std::cout << "case=" << caseName << " record=membership phase=" << phase
            << " uniq=" << bank.getUniqId()
            << " optree=" << allOpsToken(bank,labels)
            << " alive=" << opListToken(bank.beginAlive(),bank.endAlive(),labels)
            << " dead=" << opListToken(bank.beginDead(),bank.endDead(),labels)
            << '\n';
}

void printOp(const char *caseName,const char *phase,const string &label,
             const PcodeOp *op,const map<const PcodeOp *,string> &labels,
             bool orderInitialized,const vector<FlowBlock *> *blocks=(const vector<FlowBlock *> *)0)
{
  std::cout << "case=" << caseName << " record=op phase=" << phase
            << " id=" << label
            << " addr=" << addressToken(op->getAddr())
            << " time=" << op->getTime()
            << " order=";
  if (orderInitialized) std::cout << op->getSeqNum().getOrder();
  else std::cout << "UNINITIALIZED";
  std::cout << " dead=" << (op->isDead() ? 1 : 0)
            << " startmark=" << (op->isInstructionStart() ? 1 : 0)
            << " startbasic=" << (op->isBlockStart() ? 1 : 0)
            << " parent=";
  if (op->getParent() == (BlockBasic *)0) std::cout << "null";
  else if (blocks == (const vector<FlowBlock *> *)0) std::cout << "present";
  else {
    int4 ordinal = -1;
    for(int4 i=0;i<blocks->size();++i)
      if ((*blocks)[i] == op->getParent()) ordinal = i;
    std::cout << ordinal;
  }
  std::cout << " target=" << opLabel(labels,op->target()) << '\n';
}

void printBankTarget(const PcodeOpBank &bank,const Address &query,
                     const map<const PcodeOp *,string> &labels)
{
  PcodeOpTree::const_iterator iter = bank.begin(query);
  PcodeOp *lower = iter == bank.endAll() ? (PcodeOp *)0 : (*iter).second;
  PcodeOp *target = bank.target(query);
  std::cout << "case=bank_spaces record=bank_target query=" << addressToken(query)
            << " lower_bound=" << opLabel(labels,lower)
            << " final=" << opLabel(labels,target) << '\n';
}

void runBank(AddrSpace *ram,AddrSpace *overlay,AddrSpace *stack)
{
  PcodeOpBank bank;
  map<const PcodeOp *,string> labels;
  PcodeOp *s0 = bank.create(0,Address(stack,0x1000)); labels[s0] = "S0";
  PcodeOp *r0 = bank.create(0,Address(ram,0x1000)); labels[r0] = "R0";
  PcodeOp *r1 = bank.create(0,Address(ram,0x1000)); labels[r1] = "R1";
  PcodeOp *o0 = bank.create(0,Address(overlay,0x1000)); labels[o0] = "O0";
  s0->setFlag(PcodeOp::startmark);
  r0->setFlag(PcodeOp::startmark);
  o0->setFlag(PcodeOp::startmark);

  printMembership("bank_spaces","create",bank,labels);
  printOp("bank_spaces","create","S0",s0,labels,false);
  printOp("bank_spaces","create","R0",r0,labels,false);
  printOp("bank_spaces","create","R1",r1,labels,false);
  printOp("bank_spaces","create","O0",o0,labels,false);
  printBankTarget(bank,Address(ram,0x1000),labels);
  printBankTarget(bank,Address(ram,0x1001),labels);
  printBankTarget(bank,Address(overlay,0x1000),labels);
  printBankTarget(bank,Address(overlay,0x1001),labels);
  printBankTarget(bank,Address(stack,0x1000),labels);
  printBankTarget(bank,Address(stack,0x1001),labels);

  bank.markAlive(s0);
  bank.markAlive(r0);
  bank.markAlive(r1);
  bank.markAlive(o0);
  printMembership("bank_spaces","mark_alive",bank,labels);
  string outcome = "ok";
  try { bank.destroy(s0); }
  catch(const LowlevelError &error) { outcome = string("LowlevelError:") + error.explain; }
  std::cout << "case=bank_spaces record=destroy_alive id=S0 outcome=" << outcome << '\n';
  printMembership("bank_spaces","destroy_alive",bank,labels);
}

struct SplitFixture {
  Funcdata data;
  PcodeOpBank &bank;
  BlockGraph &blocks;
  vector<FuncCallSpecs *> calls;
  FlowInfo flow;
  map<const PcodeOp *,string> labels;

  SplitFixture(Scope *scope,const Address &entry,const string &name)
    : data(name,name,scope,entry,(FunctionSymbol *)0,4),
      bank(data.*accessPrivate(FuncdataOpBankTag())),
      blocks(const_cast<BlockGraph &>(data.getBasicBlocks())),
      flow(data,bank,blocks,calls) {}

  PcodeOp *add(const string &label,const Address &address,uint4 flags)
  {
    PcodeOp *op = data.newOp(0,address);
    data.opSetOpcode(op,CPUI_COPY);
    op->setFlag(flags);
    labels[op] = label;
    return op;
  }
};

int4 blockOrdinal(const vector<FlowBlock *> &blocks,const FlowBlock *needle)
{
  for(int4 i=0;i<blocks.size();++i) if (blocks[i] == needle) return i;
  return -1;
}

string blockOps(const BlockBasic *block,const map<const PcodeOp *,string> &labels)
{
  return opListToken(block->beginOp(),block->endOp(),labels);
}

void printBlock(const char *caseName,int4 ordinal,const BlockBasic *block,
                const map<const PcodeOp *,string> &labels)
{
  std::cout << "case=" << caseName << " record=block ordinal=" << ordinal
            << " entry=" << addressToken(block->getEntryAddr())
            << " start=" << addressToken(block->getStart())
            << " stop=" << addressToken(block->getStop())
            << " cover_count=" << block->cover.numRanges()
            << " cover=[";
  bool first = true;
  for(std::set<Range>::const_iterator iter=block->cover.begin();iter!=block->cover.end();++iter) {
    if (!first) std::cout << ',';
    first = false;
    std::cout << addressToken((*iter).getFirstAddr()) << ".."
              << addressToken((*iter).getLastAddr());
  }
  std::cout << "] ops=" << blockOps(block,labels) << '\n';
}

void runSplit(Scope *scope,AddrSpace *ram,AddrSpace *overlay,AddrSpace *stack)
{
  SplitFixture fixture(scope,Address(ram,0x1000),"split_spaces");
  PcodeOp *r0 = fixture.add("R0",Address(ram,0x1000),PcodeOp::startbasic|PcodeOp::startmark);
  PcodeOp *o0 = fixture.add("O0",Address(overlay,0x1000),PcodeOp::startmark);
  PcodeOp *s0 = fixture.add("S0",Address(stack,0x1000),PcodeOp::startbasic|PcodeOp::startmark);
  PcodeOp *s1 = fixture.add("S1",Address(stack,0x1001),PcodeOp::startmark);

  printMembership("split_spaces","before",fixture.bank,fixture.labels);
  fixture.flow.splitBasic();
  printMembership("split_spaces","after",fixture.bank,fixture.labels);
  const vector<FlowBlock *> &blocks = fixture.blocks.getList();
  std::cout << "case=split_spaces record=summary blocks=" << blocks.size()
            << " entry_ordinal=" << blockOrdinal(blocks,fixture.blocks.getStartBlock()) << '\n';
  for(int4 i=0;i<blocks.size();++i)
    printBlock("split_spaces",i,dynamic_cast<const BlockBasic *>(blocks[i]),fixture.labels);
  printOp("split_spaces","after","R0",r0,fixture.labels,true,&blocks);
  printOp("split_spaces","after","O0",o0,fixture.labels,true,&blocks);
  printOp("split_spaces","after","S0",s0,fixture.labels,true,&blocks);
  printOp("split_spaces","after","S1",s1,fixture.labels,true,&blocks);
}

void runMalformedSplit(Scope *scope,AddrSpace *ram)
{
  SplitFixture fixture(scope,Address(ram,0x2000),"split_missing_start");
  fixture.add("M0",Address(ram,0x2000),PcodeOp::startmark);
  string outcome = "ok";
  try { fixture.flow.splitBasic(); }
  catch(const LowlevelError &error) { outcome = string("LowlevelError:") + error.explain; }
  std::cout << "case=split_missing_start record=exception outcome=" << outcome
            << " blocks=" << fixture.blocks.getSize() << '\n';
  printMembership("split_missing_start","after",fixture.bank,fixture.labels);
}

void printFlowBlock(int4 ordinal,const BlockBasic *block)
{
  std::cout << " block=" << ordinal
            << " entry=" << addressToken(block->getEntryAddr())
            << " start=" << addressToken(block->getStart())
            << " stop=" << addressToken(block->getStop())
            << " cover_count=" << block->cover.numRanges()
            << " cover=[";
  bool firstRange = true;
  for(std::set<Range>::const_iterator iter=block->cover.begin();iter!=block->cover.end();++iter) {
    if (!firstRange) std::cout << ',';
    firstRange = false;
    std::cout << addressToken((*iter).getFirstAddr()) << ".."
              << addressToken((*iter).getLastAddr());
  }
  std::cout << "]"
            << " ops=[";
  bool first = true;
  for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
    if (!first) std::cout << ',';
    first = false;
    std::cout << 'T' << (*iter)->getTime() << ':' << addressToken((*iter)->getAddr())
              << ":order=" << (*iter)->getSeqNum().getOrder()
              << ":parent=" << ordinal;
  }
  std::cout << ']';
}

void runFlow(Scope *scope,Architecture &architecture,const string &spaceName,AddrSpace *space)
{
  const string caseName = string("flow_") + spaceName;
  std::cout << "case=" << caseName << " record=run mode=independent entry="
            << addressToken(Address(space,0)) << '\n';
  try {
    Funcdata data(caseName,caseName,scope,Address(space,0),(FunctionSymbol *)0,4);
    PcodeOpBank &bank = data.*accessPrivate(FuncdataOpBankTag());
    BlockGraph &blocks = const_cast<BlockGraph &>(data.getBasicBlocks());
    vector<FuncCallSpecs *> calls;
    FlowInfo flow(data,bank,blocks,calls);
    const Address entry(space,0);
    flow.setRange(entry,entry+4);
    flow.setFlags(architecture.flowoptions);
    flow.setMaximumInstructions(architecture.max_instructions);
    flow.generateOps();

    PcodeOp *target1 = flow.target(entry);
    PcodeOp *target2 = flow.target(entry);
    std::cout << "case=" << caseName << " record=generated visited=" << flow.visited.size()
              << " instructions=" << flow.insn_count
              << " flags=" << flow.flags
              << " alive=" << std::distance(bank.beginAlive(),bank.endAlive())
              << " dead=" << std::distance(bank.beginDead(),bank.endDead())
              << " target_repeat_same=" << (target1 == target2 ? 1 : 0)
              << " first=";
    if (target1 == (PcodeOp *)0) std::cout << "null";
    else std::cout << 'T' << target1->getTime() << ':' << addressToken(target1->getAddr());
    std::cout << '\n';
    for(auto iter=flow.visited.begin();iter!=flow.visited.end();++iter) {
      std::cout << "case=" << caseName << " record=visited addr=" << addressToken((*iter).first)
                << " size=" << (*iter).second.size << " first_seq=";
      if ((*iter).second.seqnum.getAddr().isInvalid()) std::cout << "invalid";
      else std::cout << addressToken((*iter).second.seqnum.getAddr()) << ":T"
                     << (*iter).second.seqnum.getTime();
      std::cout << '\n';
    }

    flow.generateBlocks();
    const vector<FlowBlock *> &blockList = blocks.getList();
    std::cout << "case=" << caseName << " record=blocks count=" << blockList.size()
              << " entry_ordinal=" << blockOrdinal(blockList,blocks.getStartBlock()) << '\n';
    for(int4 i=0;i<blockList.size();++i) {
      std::cout << "case=" << caseName << " record=flow_block";
      printFlowBlock(i,dynamic_cast<const BlockBasic *>(blockList[i]));
      std::cout << '\n';
    }
    std::cout << "case=" << caseName << " record=exception outcome=none\n";
  }
  catch(const BadDataError &error) {
    std::cout << "case=" << caseName << " record=exception outcome=BadDataError:"
              << error.explain << '\n';
  }
  catch(const LowlevelError &error) {
    std::cout << "case=" << caseName << " record=exception outcome=LowlevelError:"
              << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cout << "case=" << caseName << " record=exception outcome=std:"
              << error.what() << '\n';
  }
}

void runFixture(const string &specDirectory,const string &rawImage)
{
  vector<string> specPaths(1,specDirectory);
  startDecompilerLibrary(specPaths);
  {
    FixtureRawArchitecture architecture(rawImage,TARGET,&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    AddrSpace *ram = architecture.getDefaultCodeSpace();
    AddrSpace *stack = architecture.getStackSpace();
    if (ram == (AddrSpace *)0 || stack == (AddrSpace *)0)
      throw LowlevelError("RAM or stack space unavailable");
    AddrSpace *overlay = architecture.installOverlay(ram);
    Scope *scope = architecture.symboltab->getGlobalScope();

    std::cout << "record=header fixture=ADDRESS-PHASE2-CLOSURE-0001"
              << " architecture=x86:LE:64:default compiler_spec=gcc"
              << " input=750190c3 ram=" << ram->getIndex()
              << " overlay=" << overlay->getIndex()
              << " stack=" << stack->getIndex()
              << " flow_options=" << architecture.flowoptions
              << " max_instructions=" << architecture.max_instructions << '\n';
    runBank(ram,overlay,stack);
    runSplit(scope,ram,overlay,stack);
    runMalformedSplit(scope,ram);
    runFlow(scope,architecture,"ram",ram);
    runFlow(scope,architecture,"code_overlay",overlay);
    runFlow(scope,architecture,"stack",stack);
    std::cout << "record=coverage combined_cross_space_visited=UNTESTED"
              << " reason=FlowInfo_state_is_per_run_and_private_newAddress_is_not_shadowed\n";
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: address_phase2_closure_1204 SPEC_ROOT RAW_750190C3\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
