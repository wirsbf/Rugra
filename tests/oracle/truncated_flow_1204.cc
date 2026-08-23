/*
 * Locked Ghidra 12.0.4 oracle for Funcdata::truncatedFlow
 * (funcdata_op.cc:792-839), FlowInfo's partial-clone constructor
 * (flow.cc:52-76), Funcdata::cloneOp/cloneVarnode, and the JumpTable partial
 * copy constructor.
 *
 * The fixture builds raw p-code directly so every decisive identity and list
 * order is controlled.  In particular, SeqNum times are 0/1/2 while the dead
 * list is deliberately reordered to 1/0/2.  The clone must preserve both
 * views: the all-op tree remains SeqNum-sorted and splitBasic consumes the
 * dead list in 1/0/2 order.  A CALL owns an FSPEC annotation, a linked jump
 * table is partially copied, an unlinked override is truncated, and two
 * exception probes lock precondition and partial-mutation behavior.
 */

#include "bfd_arch.hh"
#include "flow.hh"
#include "libdecomp.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace ghidra;

namespace fixture_access {

template <typename Tag>
struct Result {
  static typename Tag::type ptr;
};
template <typename Tag>
typename Tag::type Result<Tag>::ptr;

template <typename Tag, typename Tag::type member>
struct Init {
  static const int value;
};
template <typename Tag, typename Tag::type member>
const int Init<Tag, member>::value = (Result<Tag>::ptr = member, 0);

struct ObankTag { typedef PcodeOpBank Funcdata::* type; };
struct VbankTag { typedef VarnodeBank Funcdata::* type; };
struct BblocksTag { typedef BlockGraph Funcdata::* type; };
struct QlstTag { typedef vector<FuncCallSpecs *> Funcdata::* type; };
struct JumpvecTag { typedef vector<JumpTable *> Funcdata::* type; };
struct FlagsTag { typedef uint4 Funcdata::* type; };
struct StackoffsetTag { typedef uintb FuncCallSpecs::* type; };
struct JmodelTag { typedef JumpModel *JumpTable::* type; };
struct OrigmodelTag { typedef JumpModel *JumpTable::* type; };
struct AddresstableTag { typedef vector<Address> JumpTable::* type; };
struct LabelTag { typedef vector<uintb> JumpTable::* type; };
struct SwitchConsumeTag { typedef uintb JumpTable::* type; };
struct DefaultBlockTag { typedef int4 JumpTable::* type; };
struct LastBlockTag { typedef int4 JumpTable::* type; };
struct MaxAddSubTag { typedef uint4 JumpTable::* type; };
struct MaxLeftRightTag { typedef uint4 JumpTable::* type; };
struct MaxExtTag { typedef uint4 JumpTable::* type; };
struct PartialTag { typedef bool JumpTable::* type; };
struct CollectTag { typedef bool JumpTable::* type; };
struct FoldedTag { typedef bool JumpTable::* type; };

} // namespace fixture_access

template struct fixture_access::Init<fixture_access::ObankTag, &Funcdata::obank>;
template struct fixture_access::Init<fixture_access::VbankTag, &Funcdata::vbank>;
template struct fixture_access::Init<fixture_access::BblocksTag, &Funcdata::bblocks>;
template struct fixture_access::Init<fixture_access::QlstTag, &Funcdata::qlst>;
template struct fixture_access::Init<fixture_access::JumpvecTag, &Funcdata::jumpvec>;
template struct fixture_access::Init<fixture_access::FlagsTag, &Funcdata::flags>;
template struct fixture_access::Init<fixture_access::StackoffsetTag, &FuncCallSpecs::stackoffset>;
template struct fixture_access::Init<fixture_access::JmodelTag, &JumpTable::jmodel>;
template struct fixture_access::Init<fixture_access::OrigmodelTag, &JumpTable::origmodel>;
template struct fixture_access::Init<fixture_access::AddresstableTag, &JumpTable::addresstable>;
template struct fixture_access::Init<fixture_access::LabelTag, &JumpTable::label>;
template struct fixture_access::Init<fixture_access::SwitchConsumeTag, &JumpTable::switchVarConsume>;
template struct fixture_access::Init<fixture_access::DefaultBlockTag, &JumpTable::defaultBlock>;
template struct fixture_access::Init<fixture_access::LastBlockTag, &JumpTable::lastBlock>;
template struct fixture_access::Init<fixture_access::MaxAddSubTag, &JumpTable::maxaddsub>;
template struct fixture_access::Init<fixture_access::MaxLeftRightTag, &JumpTable::maxleftright>;
template struct fixture_access::Init<fixture_access::MaxExtTag, &JumpTable::maxext>;
template struct fixture_access::Init<fixture_access::PartialTag, &JumpTable::partialTable>;
template struct fixture_access::Init<fixture_access::CollectTag, &JumpTable::collectloads>;
template struct fixture_access::Init<fixture_access::FoldedTag, &JumpTable::defaultIsFolded>;

extern "C" __attribute__((naked, noinline, used)) void truncated_flow_callee(void)
{
  __asm__ volatile("ret");
}
extern "C" __attribute__((naked, noinline, used)) void truncated_flow_source(void)
{
  __asm__ volatile("ret");
}
extern "C" __attribute__((naked, noinline, used)) void truncated_flow_target(void)
{
  __asm__ volatile("ret");
}
extern "C" __attribute__((naked, noinline, used)) void truncated_flow_nonempty(void)
{
  __asm__ volatile("ret");
}
extern "C" __attribute__((naked, noinline, used)) void truncated_flow_error_source(void)
{
  __asm__ volatile("ret");
}
extern "C" __attribute__((naked, noinline, used)) void truncated_flow_error_target(void)
{
  __asm__ volatile("ret");
}
extern "C" __attribute__((naked, noinline, used)) void truncated_flow_entry_source(void)
{
  __asm__ volatile("ret");
}
extern "C" __attribute__((naked, noinline, used)) void truncated_flow_entry_target(void)
{
  __asm__ volatile("ret");
}

namespace {

PcodeOpBank &obank(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::ObankTag>::ptr;
}

VarnodeBank &vbank(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::VbankTag>::ptr;
}

BlockGraph &bblocks(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::BblocksTag>::ptr;
}

vector<FuncCallSpecs *> &qlst(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::QlstTag>::ptr;
}

vector<JumpTable *> &jumpvec(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::JumpvecTag>::ptr;
}

uint4 funcFlags(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::FlagsTag>::ptr;
}

template <typename Tag, typename Value>
Value &jtField(JumpTable *jt)
{
  return jt->*fixture_access::Result<Tag>::ptr;
}

std::string times(const list<PcodeOp *>::const_iterator &begin,
                  const list<PcodeOp *>::const_iterator &end)
{
  std::ostringstream out;
  out << '[';
  bool first = true;
  for(list<PcodeOp *>::const_iterator it=begin;it!=end;++it) {
    if (!first) out << ',';
    first = false;
    out << (*it)->getTime();
  }
  out << ']';
  return out.str();
}

int4 listCount(const list<PcodeOp *>::const_iterator &begin,
               const list<PcodeOp *>::const_iterator &end)
{
  int4 count = 0;
  for(list<PcodeOp *>::const_iterator it=begin;it!=end;++it) count += 1;
  return count;
}

int4 treeCount(const PcodeOpTree::const_iterator &begin,
               const PcodeOpTree::const_iterator &end)
{
  int4 count = 0;
  for(PcodeOpTree::const_iterator it=begin;it!=end;++it) count += 1;
  return count;
}

std::string varnodeToken(const Varnode *vn)
{
  if (vn == (const Varnode *)0) return "none";
  if (vn->getSpace()->getType() == IPTR_FSPEC) return "fspec";
  std::ostringstream out;
  out << vn->getSpace()->getName() << ":0x" << std::hex << vn->getOffset();
  return out.str();
}

void configureTable(JumpTable *jt, PcodeOp *indirect, const Address &base)
{
  vector<Address> &addresses = jtField<fixture_access::AddresstableTag,
                                       vector<Address> >(jt);
  addresses.push_back(base + 0x10);
  addresses.push_back(base + 0x20);
  vector<uintb> &labels = jtField<fixture_access::LabelTag,vector<uintb> >(jt);
  labels.push_back(7);
  labels.push_back(9);
  jtField<fixture_access::SwitchConsumeTag,uintb>(jt) = 0x55;
  jtField<fixture_access::DefaultBlockTag,int4>(jt) = 3;
  jtField<fixture_access::LastBlockTag,int4>(jt) = 7;
  jtField<fixture_access::MaxAddSubTag,uint4>(jt) = 4;
  jtField<fixture_access::MaxLeftRightTag,uint4>(jt) = 5;
  jtField<fixture_access::MaxExtTag,uint4>(jt) = 6;
  jtField<fixture_access::PartialTag,bool>(jt) = true;
  jtField<fixture_access::CollectTag,bool>(jt) = true;
  jtField<fixture_access::FoldedTag,bool>(jt) = true;
  jtField<fixture_access::JmodelTag,JumpModel *>(jt) = new JumpModelTrivial(jt);
  jtField<fixture_access::OrigmodelTag,JumpModel *>(jt) = new JumpModelTrivial(jt);
  if (indirect != (PcodeOp *)0) jt->setIndirectOp(indirect);
}

void printTable(const JumpTable *table, const Address &base)
{
  JumpTable *jt = const_cast<JumpTable *>(table);
  vector<Address> &addresses = jtField<fixture_access::AddresstableTag,
                                       vector<Address> >(jt);
  JumpModel *model = jtField<fixture_access::JmodelTag,JumpModel *>(jt);
  JumpModel *orig = jtField<fixture_access::OrigmodelTag,JumpModel *>(jt);
  std::cout << "jumptable entries=" << addresses.size() << " addrs=[";
  for(int4 i=0;i<addresses.size();++i) {
    if (i != 0) std::cout << ',';
    std::cout << static_cast<int8>(addresses[i].getOffset() - base.getOffset());
  }
  std::cout << "] labels=" << (jt->isLabelled() ? 1 : 0)
            << " model=" << (model != (JumpModel *)0 ? 1 : 0)
            << " override=" << (model != (JumpModel *)0 && model->isOverride() ? 1 : 0)
            << " orig=" << (orig != (JumpModel *)0 ? 1 : 0)
            << " consume=" << jt->getSwitchVarConsume()
            << " default=" << jt->getDefaultBlock()
            << " last=" << jtField<fixture_access::LastBlockTag,int4>(jt)
            << " norm=" << jtField<fixture_access::MaxAddSubTag,uint4>(jt)
            << '/' << jtField<fixture_access::MaxLeftRightTag,uint4>(jt)
            << '/' << jtField<fixture_access::MaxExtTag,uint4>(jt)
            << " partial=" << (jt->isPartial() ? 1 : 0)
            << " collect=" << (jtField<fixture_access::CollectTag,bool>(jt) ? 1 : 0)
            << " folded=" << (jt->hasFoldedDefault() ? 1 : 0)
            << " indirect_time="
            << (jt->getIndirectOp() == (PcodeOp *)0 ? -1 : (int4)jt->getIndirectOp()->getTime())
            << '\n';
}

void printSuccess(Funcdata *source, Funcdata *target, FuncCallSpecs *oldspec,
                  JumpTable *sourceLinked)
{
  PcodeOpBank &sourceBank = obank(source);
  PcodeOpBank &targetBank = obank(target);
  std::cout << "case=success\n";
  std::cout << "source dead_times="
            << times(sourceBank.beginDead(),sourceBank.endDead())
            << " uniq=" << sourceBank.getUniqId() << '\n';
  std::cout << "target alive_times="
            << times(targetBank.beginAlive(),targetBank.endAlive())
            << " dead_times=" << times(targetBank.beginDead(),targetBank.endDead())
            << " uniq=" << targetBank.getUniqId() << '\n';

  int4 index = 0;
  for(PcodeOpTree::const_iterator it=targetBank.beginAll();it!=targetBank.endAll();++it) {
    PcodeOp *op = (*it).second;
    std::cout << "op=" << index++
              << " time=" << op->getTime()
              << " order=" << op->getSeqNum().getOrder()
              << " opcode=" << get_opname(op->code())
              << " startbasic=" << (op->isBlockStart() ? 1 : 0)
              << " startmark=" << (op->isInstructionStart() ? 1 : 0)
              << " in0=" << varnodeToken(op->numInput() == 0 ? (Varnode *)0 : op->getIn(0))
              << " out=" << varnodeToken(op->getOut()) << '\n';
  }

  FuncCallSpecs *newspec = target->getCallSpecs(0);
  PcodeOp *callop = newspec->getOp();
  bool fspecSelf = callop->getIn(0)->getSpace()->getType() == IPTR_FSPEC
      && FuncCallSpecs::getFspecFromConst(callop->getIn(0)->getAddr()) == newspec;
  int4 fspecCount = 0;
  for(VarnodeLocSet::const_iterator it=vbank(target).beginLoc();
      it!=vbank(target).endLoc();++it)
    if ((*it)->getSpace()->getType() == IPTR_FSPEC) fspecCount += 1;
  std::cout << "callspecs=" << target->numCalls()
            << " new=" << (newspec != oldspec ? 1 : 0)
            << " op_time=" << callop->getTime()
            << " fspec_self=" << (fspecSelf ? 1 : 0)
            << " varnodes=" << target->numVarnodes()
            << " fspec_varnodes=" << fspecCount
            << " entry_delta="
            << static_cast<int8>(newspec->getEntryAddress().getOffset()
                                 - source->getAddress().getOffset())
            << " stackoffset=" << newspec->getSpacebaseOffset()
            << " extrapop=" << newspec->getExtraPop() << '\n';

  std::cout << "jumptables=" << jumpvec(target).size() << '\n';
  printTable(jumpvec(target)[0],source->getAddress());
  JumpTable *targetTable = jumpvec(target)[0];
  std::cout << "jumptable_identity table_new=" << (targetTable != sourceLinked ? 1 : 0)
            << " indirect_new="
            << (targetTable->getIndirectOp() != sourceLinked->getIndirectOp() ? 1 : 0)
            << " model_new="
            << (jtField<fixture_access::JmodelTag,JumpModel *>(targetTable)
                != jtField<fixture_access::JmodelTag,JumpModel *>(sourceLinked) ? 1 : 0)
            << '\n';

  const vector<FlowBlock *> &blocks = target->getBasicBlocks().getList();
  std::cout << "blocks=" << blocks.size() << '\n';
  for(int4 i=0;i<blocks.size();++i) {
    const BlockBasic *basic = dynamic_cast<const BlockBasic *>(blocks[i]);
    std::cout << "block=" << i << " times=[";
    bool first = true;
    if (basic != (const BlockBasic *)0) {
      for(list<PcodeOp *>::const_iterator it=basic->beginOp();it!=basic->endOp();++it) {
        if (!first) std::cout << ',';
        first = false;
        std::cout << (*it)->getTime() << ':' << (*it)->getSeqNum().getOrder();
      }
    }
    std::cout << "]\n";
  }
}

Funcdata *requireFunction(BfdArchitecture &architecture, const string &name)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(name);
  if (fd == (Funcdata *)0) throw std::runtime_error("missing function: " + name);
  return fd;
}

void runFixture(const string &specRoot, const string &binary)
{
  vector<string> specPaths(1,specRoot);
  startDecompilerLibrary(specPaths);
  {
    std::ostringstream loaderMessages;
    BfdArchitecture architecture(binary,"default",&loaderMessages);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");

    Funcdata *source = requireFunction(architecture,"truncated_flow_source");
    Funcdata *target = requireFunction(architecture,"truncated_flow_target");
    Funcdata *callee = requireFunction(architecture,"truncated_flow_callee");
    const Address base = source->getAddress();
    AddrSpace *registerSpace = architecture.getSpaceByName("register");
    AddrSpace *stackSpace = architecture.getSpaceByName("stack");
    if (registerSpace == (AddrSpace *)0 || stackSpace == (AddrSpace *)0)
      throw std::runtime_error("required address space missing");

    PcodeOp *callop = source->newOp(1,base);
    source->opSetOpcode(callop,CPUI_CALL);
    source->opSetInput(callop,source->newCodeRef(callee->getAddress()),0);
    source->opMarkStartInstruction(callop);
    FuncCallSpecs *callspec = new FuncCallSpecs(callop);
    callspec->setExtraPop(ProtoModel::extrapop_unknown);
    callspec->setEffectiveExtraPop(ProtoModel::extrapop_unknown);
    callspec->*fixture_access::Result<fixture_access::StackoffsetTag>::ptr = 0x1234;
    source->opSetInput(callop,source->newVarnodeCallSpecs(callspec),0);
    qlst(source).push_back(callspec);

    PcodeOp *copyop = source->newOp(1,base);
    source->opSetOpcode(copyop,CPUI_COPY);
    source->opSetInput(copyop,source->newVarnode(8,Address(stackSpace,0x28)),0);
    source->newVarnodeOut(8,Address(registerSpace,0x40),copyop);
    source->opMarkStartBasic(copyop);
    source->opMarkStartInstruction(copyop);

    PcodeOp *returnop = source->newOp(0,base);
    source->opSetOpcode(returnop,CPUI_RETURN);
    source->opMarkStartInstruction(returnop);
    source->opDeadInsertAfter(callop,copyop); // dead order: time 1,0,2

    PcodeOp *spare = source->newOp(0,base);
    source->opSetOpcode(spare,CPUI_COPY);
    source->opDeadAndGone(spare);             // uniqId stays advanced to 4

    JumpTable *unlinked = new JumpTable(&architecture,base + 0x30);
    configureTable(unlinked,(PcodeOp *)0,base);
    jumpvec(source).push_back(unlinked);
    JumpTable *linked = new JumpTable(&architecture,base);
    configureTable(linked,copyop,base);
    jumpvec(source).push_back(linked);

    FlowInfo sourceFlow(*source,obank(source),bblocks(source),qlst(source));
    sourceFlow.setRange(Address(architecture.getDefaultCodeSpace(),0),
                        Address(architecture.getDefaultCodeSpace(),
                                architecture.getDefaultCodeSpace()->getHighest()));
    sourceFlow.setMaximumInstructions(77);
    sourceFlow.setFlags(FlowInfo::possible_unreachable | FlowInfo::error_unimplemented);
    target->truncatedFlow(source,&sourceFlow);
    printSuccess(source,target,callspec,linked);

    Funcdata *nonempty = requireFunction(architecture,"truncated_flow_nonempty");
    nonempty->newOp(0,nonempty->getAddress());
    string nonemptyError = "none";
    try {
      nonempty->truncatedFlow(source,&sourceFlow);
    }
    catch(const LowlevelError &error) {
      nonemptyError = error.explain;
    }
    std::cout << "case=nonempty error=" << nonemptyError
              << " ops=" << obank(nonempty).getUniqId()
              << " dead=" << listCount(obank(nonempty).beginDead(),obank(nonempty).endDead())
              << " blocks=" << nonempty->getBasicBlocks().getSize() << '\n';

    Funcdata *errorSource = requireFunction(architecture,"truncated_flow_error_source");
    Funcdata *errorTarget = requireFunction(architecture,"truncated_flow_error_target");
    PcodeOp *kept = errorSource->newOp(0,errorSource->getAddress());
    errorSource->opSetOpcode(kept,CPUI_RETURN);
    errorSource->opMarkStartBasic(kept);
    errorSource->opMarkStartInstruction(kept);
    PcodeOp *missing = errorSource->newOp(0,errorSource->getAddress());
    errorSource->opSetOpcode(missing,CPUI_COPY);
    obank(errorSource).markAlive(missing); // valid op, deliberately not cloned
    JumpTable *firstTable = new JumpTable(&architecture,errorSource->getAddress());
    firstTable->setIndirectOp(kept);
    jumpvec(errorSource).push_back(firstTable);
    JumpTable *missingTable = new JumpTable(&architecture,errorSource->getAddress());
    missingTable->setIndirectOp(missing);
    jumpvec(errorSource).push_back(missingTable);
    FlowInfo errorFlow(*errorSource,obank(errorSource),bblocks(errorSource),qlst(errorSource));
    string jumpError = "none";
    try {
      errorTarget->truncatedFlow(errorSource,&errorFlow);
    }
    catch(const LowlevelError &error) {
      jumpError = error.explain;
    }
    std::cout << "case=missing_jumptable error=" << jumpError
              << " all=" << treeCount(obank(errorTarget).beginAll(),obank(errorTarget).endAll())
              << " dead=" << listCount(obank(errorTarget).beginDead(),obank(errorTarget).endDead())
              << " alive=" << listCount(obank(errorTarget).beginAlive(),obank(errorTarget).endAlive())
              << " uniq=" << obank(errorTarget).getUniqId()
              << " jumptables=" << jumpvec(errorTarget).size()
              << " blocks=" << errorTarget->getBasicBlocks().getSize() << '\n';

    Funcdata *entrySource = requireFunction(architecture,"truncated_flow_entry_source");
    Funcdata *entryTarget = requireFunction(architecture,"truncated_flow_entry_target");
    PcodeOp *entryOp = entrySource->newOp(0,entrySource->getAddress());
    entrySource->opSetOpcode(entryOp,CPUI_RETURN);
    entrySource->opMarkStartInstruction(entryOp);
    FlowInfo entryFlow(*entrySource,obank(entrySource),bblocks(entrySource),qlst(entrySource));
    std::cout << "case=missing_entry before_all="
              << treeCount(obank(entryTarget).beginAll(),obank(entryTarget).endAll())
              << " before_dead="
              << listCount(obank(entryTarget).beginDead(),obank(entryTarget).endDead())
              << " before_alive="
              << listCount(obank(entryTarget).beginAlive(),obank(entryTarget).endAlive())
              << " before_uniq=" << obank(entryTarget).getUniqId()
              << " before_varnodes=" << entryTarget->numVarnodes()
              << " before_callspecs=" << entryTarget->numCalls()
              << " before_jumptables=" << jumpvec(entryTarget).size()
              << " before_blocks=" << entryTarget->getBasicBlocks().getSize()
              << " before_generated=" << ((funcFlags(entryTarget) & 2) != 0 ? 1 : 0)
              << '\n';
    string entryError = "none";
    try {
      entryTarget->truncatedFlow(entrySource,&entryFlow);
    }
    catch(const LowlevelError &error) {
      entryError = error.explain;
    }
    PcodeOp *entryClone = obank(entryTarget).beginDead() == obank(entryTarget).endDead()
        ? (PcodeOp *)0 : *obank(entryTarget).beginDead();
    std::cout << "case=missing_entry error=" << entryError
              << " all=" << treeCount(obank(entryTarget).beginAll(),obank(entryTarget).endAll())
              << " dead=" << listCount(obank(entryTarget).beginDead(),obank(entryTarget).endDead())
              << " alive=" << listCount(obank(entryTarget).beginAlive(),obank(entryTarget).endAlive())
              << " uniq=" << obank(entryTarget).getUniqId()
              << " varnodes=" << entryTarget->numVarnodes()
              << " callspecs=" << entryTarget->numCalls()
              << " jumptables=" << jumpvec(entryTarget).size()
              << " blocks=" << entryTarget->getBasicBlocks().getSize()
              << " generated=" << ((funcFlags(entryTarget) & 2) != 0 ? 1 : 0)
              << " first_time=" << (entryClone == (PcodeOp *)0 ? -1 : (int4)entryClone->getTime())
              << " first_order=" << (entryClone == (PcodeOp *)0 ? -1 : (int4)entryClone->getSeqNum().getOrder())
              << " first_opcode=" << (entryClone == (PcodeOp *)0 ? "none" : get_opname(entryClone->code()))
              << " first_dead=" << (entryClone != (PcodeOp *)0 && entryClone->isDead() ? 1 : 0)
              << " first_parent=" << (entryClone != (PcodeOp *)0 && entryClone->getParent() != (BlockBasic *)0 ? 1 : 0)
              << " first_startbasic=" << (entryClone != (PcodeOp *)0 && entryClone->isBlockStart() ? 1 : 0)
              << " first_startmark=" << (entryClone != (PcodeOp *)0 && entryClone->isInstructionStart() ? 1 : 0)
              << '\n';
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 2) {
    std::cerr << "usage: truncated_flow_1204 SPEC_ROOT\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[0]);
    return 0;
  }
  catch(const LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
