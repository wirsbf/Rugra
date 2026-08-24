/*
 * Locked Ghidra 12.0.4 oracle for FuncCallSpecs identity and lifecycle.
 *
 * The fixture constructs p-code directly so that three CALL ops have the
 * same machine address while retaining distinct PcodeOp/FuncCallSpecs
 * identities.  It then exercises Funcdata::getCallSpecs,
 * compareCallspecs/sortCallSpecs, deleteCallSpecs, and the callspec leg of
 * Funcdata::truncatedFlow.  Pointer values are never printed.  After delete,
 * the stale FSPEC address is compared only with the live qlst owners and is
 * never dereferenced.
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
const int Init<Tag,member>::value = (Result<Tag>::ptr = member,0);

struct ObankTag { typedef PcodeOpBank Funcdata::* type; };
struct BblocksTag { typedef BlockGraph Funcdata::* type; };
struct QlstTag { typedef vector<FuncCallSpecs *> Funcdata::* type; };
struct StackoffsetTag { typedef uintb FuncCallSpecs::* type; };
struct InputActiveTag { typedef bool FuncCallSpecs::* type; };
struct OutputActiveTag { typedef bool FuncCallSpecs::* type; };
struct BlockIndexTag { typedef int4 FlowBlock::* type; };
struct SortCallSpecsTag { typedef void (Funcdata::*type)(void); };
struct DeleteCallSpecsTag { typedef void (Funcdata::*type)(PcodeOp *); };

} // namespace fixture_access

template struct fixture_access::Init<fixture_access::ObankTag,&Funcdata::obank>;
template struct fixture_access::Init<fixture_access::BblocksTag,&Funcdata::bblocks>;
template struct fixture_access::Init<fixture_access::QlstTag,&Funcdata::qlst>;
template struct fixture_access::Init<fixture_access::StackoffsetTag,&FuncCallSpecs::stackoffset>;
template struct fixture_access::Init<fixture_access::InputActiveTag,&FuncCallSpecs::isinputactive>;
template struct fixture_access::Init<fixture_access::OutputActiveTag,&FuncCallSpecs::isoutputactive>;
template struct fixture_access::Init<fixture_access::BlockIndexTag,&FlowBlock::index>;
template struct fixture_access::Init<fixture_access::SortCallSpecsTag,&Funcdata::sortCallSpecs>;
template struct fixture_access::Init<fixture_access::DeleteCallSpecsTag,&Funcdata::deleteCallSpecs>;

extern "C" __attribute__((naked,noinline,used)) void callspec_identity_owner(void)
{
  __asm__ volatile("ret");
}

extern "C" __attribute__((naked,noinline,used)) void callspec_identity_clone_source(void)
{
  __asm__ volatile("ret");
}

extern "C" __attribute__((naked,noinline,used)) void callspec_identity_clone_target(void)
{
  __asm__ volatile("ret");
}

extern "C" __attribute__((naked,noinline,used)) void callspec_identity_callee(void)
{
  __asm__ volatile("ret");
}

namespace {

PcodeOpBank &obank(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::ObankTag>::ptr;
}

BlockGraph &bblocks(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::BblocksTag>::ptr;
}

vector<FuncCallSpecs *> &qlst(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::QlstTag>::ptr;
}

void setBlockIndex(FlowBlock *block,int4 index)
{
  block->*fixture_access::Result<fixture_access::BlockIndexTag>::ptr = index;
}

void sortCallSpecs(Funcdata *fd)
{
  (fd->*fixture_access::Result<fixture_access::SortCallSpecsTag>::ptr)();
}

void deleteCallSpecs(Funcdata *fd,PcodeOp *op)
{
  (fd->*fixture_access::Result<fixture_access::DeleteCallSpecsTag>::ptr)(op);
}

struct CallSite {
  PcodeOp *op;
  FuncCallSpecs *spec;
};

CallSite makeCall(Funcdata *fd,const Address &site,const Address &entry,
                  BlockBasic *block)
{
  PcodeOp *op = fd->newOp(1,site);
  fd->opSetOpcode(op,CPUI_CALL);
  fd->opSetInput(op,fd->newCodeRef(entry),0);
  FuncCallSpecs *spec = new FuncCallSpecs(op);
  fd->opSetInput(op,fd->newVarnodeCallSpecs(spec),0);
  if (block != (BlockBasic *)0)
    fd->opInsert(op,block,block->endOp());
  return CallSite{op,spec};
}

FuncCallSpecs *annotationTarget(const PcodeOp *op)
{
  if (op->numInput() == 0) return (FuncCallSpecs *)0;
  const Varnode *vn = op->getIn(0);
  if (vn == (const Varnode *)0 || vn->getSpace()->getType() != IPTR_FSPEC)
    return (FuncCallSpecs *)0;
  return FuncCallSpecs::getFspecFromConst(vn->getAddr());
}

bool isOwned(const Funcdata *fd,const FuncCallSpecs *needle)
{
  for(int4 i=0;i<fd->numCalls();++i)
    if (fd->getCallSpecs(i) == needle) return true;
  return false;
}

int4 labelOf(FuncCallSpecs *value,FuncCallSpecs *spec0,
             FuncCallSpecs *spec1,FuncCallSpecs *spec2)
{
  if (value == spec0) return 0;
  if (value == spec1) return 1;
  if (value == spec2) return 2;
  return -1;
}

string qlstLabels(Funcdata *fd,FuncCallSpecs *spec0,
                  FuncCallSpecs *spec1,FuncCallSpecs *spec2)
{
  std::ostringstream out;
  out << '[';
  for(int4 i=0;i<fd->numCalls();++i) {
    if (i != 0) out << ',';
    out << labelOf(fd->getCallSpecs(i),spec0,spec1,spec2);
  }
  out << ']';
  return out.str();
}

Funcdata *requireFunction(BfdArchitecture &architecture,const string &name)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(name);
  if (fd == (Funcdata *)0)
    throw std::runtime_error("missing fixture function: " + name);
  return fd;
}

void runIdentityCase(BfdArchitecture &architecture)
{
  Funcdata *fd = requireFunction(architecture,"callspec_identity_owner");
  Funcdata *callee = requireFunction(architecture,"callspec_identity_callee");
  const Address site = fd->getAddress();
  const Address entry = callee->getAddress();

  BlockBasic *block0 = bblocks(fd).newBlockBasic(fd);
  BlockBasic *block1 = bblocks(fd).newBlockBasic(fd);
  setBlockIndex(block0,0);
  setBlockIndex(block1,1);

  CallSite call0 = makeCall(fd,site,entry,block0);
  CallSite call1 = makeCall(fd,site,entry,block0);
  CallSite call2 = makeCall(fd,site,entry,block1);

  // Deliberately reverse the owner list. sortCallSpecs must move only these
  // pointers and use (parent index, SeqNum.order) as its complete key.
  qlst(fd).push_back(call2.spec);
  qlst(fd).push_back(call1.spec);
  qlst(fd).push_back(call0.spec);

  const bool exact0 = fd->getCallSpecs(call0.op) == call0.spec;
  const bool exact1 = fd->getCallSpecs(call1.op) == call1.spec;
  const bool exact2 = fd->getCallSpecs(call2.op) == call2.spec;
  std::cout << "case=identity same_addr="
            << (call0.op->getAddr() == call1.op->getAddr() ? 1 : 0)
            << " distinct_ops=" << (call0.op != call1.op ? 1 : 0)
            << " distinct_specs=" << (call0.spec != call1.spec ? 1 : 0)
            << " exact=[" << (exact0 ? 1 : 0) << ',' << (exact1 ? 1 : 0)
            << ',' << (exact2 ? 1 : 0) << "] initial_order="
            << qlstLabels(fd,call0.spec,call1.spec,call2.spec) << '\n';

  FuncCallSpecs *saved0 = call0.spec;
  FuncCallSpecs *saved1 = call1.spec;
  FuncCallSpecs *saved2 = call2.spec;
  sortCallSpecs(fd);
  const bool ownerStable = fd->getCallSpecs(0) == saved0
      && fd->getCallSpecs(1) == saved1 && fd->getCallSpecs(2) == saved2;
  const bool annotationStable = annotationTarget(call0.op) == saved0
      && annotationTarget(call1.op) == saved1
      && annotationTarget(call2.op) == saved2;
  std::cout << "case=sort order="
            << qlstLabels(fd,saved0,saved1,saved2)
            << " owner_stable=" << (ownerStable ? 1 : 0)
            << " annotation_stable=" << (annotationStable ? 1 : 0)
            << " keys=[" << call0.op->getParent()->getIndex() << ':'
            << call0.op->getSeqNum().getOrder() << ','
            << call1.op->getParent()->getIndex() << ':'
            << call1.op->getSeqNum().getOrder() << ','
            << call2.op->getParent()->getIndex() << ':'
            << call2.op->getSeqNum().getOrder() << "]\n";

  // A plain constant with the same integer bits as a live spec pointer is
  // not an IPTR_FSPEC value and must not hit the fast path or exact-op scan.
  PcodeOp *fake = fd->newOp(1,site);
  fd->opSetOpcode(fake,CPUI_CALL);
  fd->opSetInput(fake,fd->newConstant(sizeof(void *),(uintb)(uintp)saved0),0);
  fd->opInsert(fake,block1,block1->endOp());
  std::cout << "case=raw_const same_offset=1 resolved="
            << (fd->getCallSpecs(fake) == (FuncCallSpecs *)0 ? 0 : 1)
            << " space=const\n";

  // IPTR_FSPEC and IPTR_IOP are distinct oracle spaces. A typed callspec
  // annotation must never enter PcodeOp::getOpFromConst's IOP decoder.
  Varnode *typedAnnotation = call0.op->getIn(0);
  Varnode *realIopAnnotation = fd->newVarnodeIop(fake);
  const bool realIopExact =
      PcodeOp::getOpFromConst(realIopAnnotation->getAddr()) == fake;
  bool typedAsIop = false;
  if (typedAnnotation->getSpace()->getType() == IPTR_IOP)
    typedAsIop = PcodeOp::getOpFromConst(typedAnnotation->getAddr()) != (PcodeOp *)0;
  std::cout << "case=iop_guard real_iop_exact=" << (realIopExact ? 1 : 0)
            << " typed_fspec_as_iop=" << (typedAsIop ? 1 : 0)
            << '\n';

  Varnode *deletedTypedAnnotation = call1.op->getIn(0);

  // deleteCallSpecs deletes the exact owner and erases only that qlst slot.
  // annotationTarget(call1.op) is now a dangling value; compare it only to
  // live qlst owners and never dereference it.
  deleteCallSpecs(fd,call1.op);
  FuncCallSpecs *stale = annotationTarget(call1.op);
  bool expiredTypedAsIop = false;
  if (deletedTypedAnnotation->getSpace()->getType() == IPTR_IOP)
    expiredTypedAsIop =
        PcodeOp::getOpFromConst(deletedTypedAnnotation->getAddr()) != (PcodeOp *)0;
  std::cout << "case=iop_guard_expired binding_present="
            << (deletedTypedAnnotation->getSpace()->getType() == IPTR_FSPEC ? 1 : 0)
            << " owner_live=" << (isOwned(fd,stale) ? 1 : 0)
            << " typed_fspec_as_iop="
            << (expiredTypedAsIop ? 1 : 0) << '\n';
  const bool survivorExact = fd->getCallSpecs(call2.op) == saved2;
  const bool shiftedStable = fd->numCalls() == 2 && fd->getCallSpecs(1) == saved2;
  std::cout << "case=delete count=" << fd->numCalls()
            << " order=" << qlstLabels(fd,saved0,saved1,saved2)
            << " deleted_annotation_owned=" << (isOwned(fd,stale) ? 1 : 0)
            << " survivor_exact=" << (survivorExact ? 1 : 0)
            << " shifted_owner_stable=" << (shiftedStable ? 1 : 0)
            << '\n';
}

void runCloneCase(BfdArchitecture &architecture)
{
  Funcdata *source = requireFunction(architecture,"callspec_identity_clone_source");
  Funcdata *target = requireFunction(architecture,"callspec_identity_clone_target");
  Funcdata *callee = requireFunction(architecture,"callspec_identity_callee");
  const Address site = source->getAddress();

  PcodeOp *entryop = source->newOp(0,site);
  source->opSetOpcode(entryop,CPUI_COPY);
  source->opMarkStartBasic(entryop);
  source->opMarkStartInstruction(entryop);
  CallSite old = makeCall(source,site,callee->getAddress(),(BlockBasic *)0);
  source->opMarkStartInstruction(old.op);
  PcodeOp *returnop = source->newOp(0,site);
  source->opSetOpcode(returnop,CPUI_RETURN);
  source->opMarkStartInstruction(returnop);
  old.spec->*fixture_access::Result<fixture_access::StackoffsetTag>::ptr = 0x3456;
  old.spec->*fixture_access::Result<fixture_access::InputActiveTag>::ptr = true;
  old.spec->*fixture_access::Result<fixture_access::OutputActiveTag>::ptr = true;
  old.spec->getActiveInput()->registerTrial(source->getAddress(),1);
  old.spec->getActiveOutput()->registerTrial(source->getAddress(),1);
  qlst(source).push_back(old.spec);

  FlowInfo sourceFlow(*source,obank(source),bblocks(source),qlst(source));
  target->truncatedFlow(source,&sourceFlow);

  FuncCallSpecs *newspec = target->getCallSpecs(0);
  PcodeOp *newop = newspec->getOp();
  const bool seqEqual = old.op->getSeqNum() == newop->getSeqNum();
  const bool oldAnnotationOld = annotationTarget(old.op) == old.spec;
  const bool newAnnotationNew = annotationTarget(newop) == newspec;
  const bool isolated = annotationTarget(old.op) != annotationTarget(newop);
  std::cout << "case=clone source_count=" << source->numCalls()
            << " target_count=" << target->numCalls()
            << " new_owner=" << (newspec != old.spec ? 1 : 0)
            << " new_op=" << (newop != old.op ? 1 : 0)
            << " seq_equal=" << (seqEqual ? 1 : 0)
            << " old_annotation_old=" << (oldAnnotationOld ? 1 : 0)
            << " new_annotation_new=" << (newAnnotationNew ? 1 : 0)
            << " old_new_isolated=" << (isolated ? 1 : 0)
            << " active_source=" << (old.spec->isInputActive() ? 1 : 0)
            << '/' << (old.spec->isOutputActive() ? 1 : 0)
            << " active_target=" << (newspec->isInputActive() ? 1 : 0)
            << '/' << (newspec->isOutputActive() ? 1 : 0)
            << " trials_source=" << old.spec->getActiveInput()->getNumTrials()
            << '/' << old.spec->getActiveOutput()->getNumTrials()
            << " trials_target=" << newspec->getActiveInput()->getNumTrials()
            << '/' << newspec->getActiveOutput()->getNumTrials()
            << " entry_same="
            << (old.spec->getEntryAddress() == newspec->getEntryAddress() ? 1 : 0)
            << " stack_same="
            << (old.spec->getSpacebaseOffset() == newspec->getSpacebaseOffset() ? 1 : 0)
            << '\n';
}

void runFixture(const string &specRoot,const string &binary)
{
  startDecompilerLibrary(vector<string>(1,specRoot));
  {
    std::ostringstream diagnostics;
    BfdArchitecture architecture(binary,"default",&diagnostics);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    runIdentityCase(architecture);
    runCloneCase(architecture);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 2) {
    std::cerr << "usage: callspec_identity_lifecycle_1204 SPEC_ROOT\n";
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
