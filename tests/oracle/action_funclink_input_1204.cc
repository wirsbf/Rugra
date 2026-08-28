/*
 * GETSTR-FUNCLINK-SPACE-0001 bilateral oracle projection.
 *
 * This fixture loads the production x86-64 GCC compiler specification through
 * BfdArchitecture, asks that real ProtoModel to assign a seven-int8 locked
 * signature (six register formals plus the first stack formal), and then runs
 * ActionFuncLink::apply.  It observes the complete state written by
 * ActionFuncLink::funcLinkInput, including the intentionally different first
 * stack behavior for non-varargs and varargs calls.
 *
 * Pointer values and allocation identities are never printed.  Pointer
 * identity is observed only as same-space/same-object booleans.  Unique-space
 * offsets are printed because both implementations allocate them from the
 * locked ANALYSIS unique base in the same operation order.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "funcdata.hh"
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

struct CallListTag { typedef std::vector<FuncCallSpecs *> Funcdata::* type; };
struct FixedPositionTag { typedef int4 ParamTrial::* type; };
struct ActivePlaceholderTag { typedef int4 ParamActive::* type; };

} // namespace fixture_access

template struct fixture_access::Init<fixture_access::CallListTag,&Funcdata::qlst>;
template struct fixture_access::Init<fixture_access::FixedPositionTag,&ParamTrial::fixedPosition>;
template struct fixture_access::Init<fixture_access::ActivePlaceholderTag,&ParamActive::stackplaceholder>;

namespace {

std::vector<FuncCallSpecs *> &callList(Funcdata *fd)
{
  return fd->*fixture_access::Result<fixture_access::CallListTag>::ptr;
}

int4 fixedPosition(const ParamTrial &trial)
{
  return trial.*fixture_access::Result<fixture_access::FixedPositionTag>::ptr;
}

int4 activePlaceholder(const ParamActive &active)
{
  return active.*fixture_access::Result<fixture_access::ActivePlaceholderTag>::ptr;
}

const char *spaceTypeName(spacetype type)
{
  switch(type) {
  case IPTR_CONSTANT: return "constant";
  case IPTR_PROCESSOR: return "processor";
  case IPTR_SPACEBASE: return "spacebase";
  case IPTR_INTERNAL: return "internal";
  case IPTR_FSPEC: return "fspec";
  case IPTR_IOP: return "iop";
  case IPTR_JOIN: return "join";
  default: return "other";
  }
}

std::string addressDescriptor(const Address &addr)
{
  std::ostringstream out;
  AddrSpace *space = addr.getSpace();
  out << space->getName() << '@' << space->getIndex() << ':'
      << spaceTypeName(space->getType()) << ":0x" << std::hex
      << addr.getOffset() << std::dec;
  return out.str();
}

uint4 trialFlags(const ParamTrial &trial)
{
  uint4 flags = 0;
  if (trial.isChecked()) flags |= ParamTrial::checked;
  if (trial.isUsed()) flags |= ParamTrial::used;
  if (trial.isDefinitelyNotUsed()) flags |= ParamTrial::defnouse;
  if (trial.isActive()) flags |= ParamTrial::active;
  if (trial.isUnref()) flags |= ParamTrial::unref;
  if (trial.isKilledByCall()) flags |= ParamTrial::killedbycall;
  if (trial.isRemFormed()) flags |= ParamTrial::rem_formed;
  if (trial.isIndCreateFormed()) flags |= ParamTrial::indcreate_formed;
  if (trial.hasCondExeEffect()) flags |= ParamTrial::condexe_effect;
  if (trial.hasAncestorRealistic()) flags |= ParamTrial::ancestor_realistic;
  if (trial.hasAncestorSolid()) flags |= ParamTrial::ancestor_solid;
  return flags;
}

std::string opName(const Varnode *vn)
{
  if (!vn->isWritten()) return "-";
  return get_opname(vn->getDef()->code());
}

void dumpInput(const char *label,int4 slot,const Varnode *vn)
{
  std::cout << "input|" << label << '|' << slot
            << "|addr=" << addressDescriptor(vn->getAddr())
            << "|size=" << vn->getSize()
            << "|annotation=" << (vn->isAnnotation() ? 1 : 0)
            << "|input=" << (vn->isInput() ? 1 : 0)
            << "|written=" << (vn->isWritten() ? 1 : 0)
            << "|placeholder=" << (vn->isSpacebasePlaceholder() ? 1 : 0)
            << "|def=" << opName(vn) << '\n';
}

struct CaseState {
  Funcdata *fd;
  PcodeOp *op;
  FuncCallSpecs *spec;
  Varnode *preexisting;
};

CaseState makeCase(BfdArchitecture &architecture,const std::string &label,
                   uintb functionOffset,uintb callOffset,bool locked,
                   bool varargs,int4 paramCount)
{
  Scope *global = architecture.symboltab->getGlobalScope();
  Address functionAddress(architecture.getDefaultCodeSpace(),functionOffset);
  FunctionSymbol *symbol = global->addFunction(functionAddress,label);
  Funcdata *fd = symbol->getFunction();

  Address callAddress(architecture.getDefaultCodeSpace(),callOffset);
  PcodeOp *op = fd->newOp(1,callAddress);
  fd->opSetOpcode(op,CPUI_CALL);
  Address target(architecture.getDefaultCodeSpace(),0x710000);
  fd->opSetInput(op,fd->newCodeRef(target),0);
  BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(fd);
  fd->opInsert(op,block,block->endOp());

  FuncCallSpecs *spec = new FuncCallSpecs(op);
  // Production ActionDefaultParams establishes the internal store/model
  // before an external locked signature overlays the call site.
  spec->setInternal(architecture.defaultfp,architecture.types->getTypeVoid());
  if (locked) {
    PrototypePieces pieces;
    pieces.model = architecture.defaultfp;
    pieces.name = label;
    pieces.outtype = architecture.types->getTypeVoid();
    Datatype *int8Type = architecture.types->getBase(8,TYPE_INT);
    for(int4 i=0;i<paramCount;++i) {
      pieces.intypes.push_back(int8Type);
      std::ostringstream name;
      name << 'p' << i;
      pieces.innames.push_back(name.str());
    }
    pieces.firstVarArgSlot = varargs ? 2 : -1;
    spec->setPieces(pieces);
  }
  Varnode *preexisting = (Varnode *)0;
  if (locked) {
    ProtoParameter *first = spec->getParam(0);
    preexisting = fd->newVarnode(first->getSize(),first->getAddress());
  }
  callList(fd).push_back(spec);
  return CaseState{fd,op,spec,preexisting};
}

int4 trialIndex(ParamActive &active,const ParamTrial *needle)
{
  for(int4 i=0;i<active.getNumTrials();++i)
    if (&active.getTrial(i) == needle) return i;
  return -1;
}

void dumpCase(const char *label,const CaseState &state)
{
  FuncCallSpecs *spec = state.spec;
  ParamActive &active = *spec->getActiveInput();
  std::cout << "case|" << label
            << "|model=" << spec->getModelName()
            << "|locked=" << (spec->isInputLocked() ? 1 : 0)
            << "|varargs=" << (spec->isDotdotdot() ? 1 : 0)
            << "|input_active=" << (spec->isInputActive() ? 1 : 0)
            << "|output_active=" << (spec->isOutputActive() ? 1 : 0)
            << "|trials=" << active.getNumTrials()
            << "|passes=" << active.getNumPasses()
            << "|maxpass=" << active.getMaxPass()
            << "|fully_checked=" << (active.isFullyChecked() ? 1 : 0)
            << "|needs_final=" << (active.needsFinalCheck() ? 1 : 0)
            << "|recover_subcall=" << (active.isRecoverSubcall() ? 1 : 0)
            << "|join_reverse=" << (active.isJoinReverse() ? 1 : 0)
            << "|callspec_placeholder=" << spec->getStackPlaceholderSlot()
            << "|active_placeholder=" << activePlaceholder(active)
            << "|inputs=" << state.op->numInput() << '\n';

  for(int4 i=0;i<active.getNumTrials();++i) {
    const ParamTrial &trial = active.getTrial(i);
    std::cout << "trial|" << label << '|' << i
              << "|addr=" << addressDescriptor(trial.getAddress())
              << "|size=" << trial.getSize()
              << "|slot=" << trial.getSlot()
              << "|flags=0x" << std::hex << trialFlags(trial) << std::dec
              << "|fixed=" << fixedPosition(trial) << '\n';
  }
  for(int4 slot=0;slot<state.op->numInput();++slot)
    dumpInput(label,slot,state.op->getIn(slot));

  for(int4 i=0;i<spec->numParams();++i) {
    const Address formal = spec->getParam(i)->getAddress();
    const Address trial = active.getTrial(i).getAddress();
    const Address call = state.op->getIn(i+1)->getAddr();
    std::cout << "formal|" << label << '|' << i
              << "|addr=" << addressDescriptor(formal)
              << "|size=" << spec->getParam(i)->getSize() << '\n';
    std::cout << "alias|" << label << '|' << i
              << "|formal_trial_space="
              << (formal.getSpace() == trial.getSpace() ? 1 : 0)
              << "|formal_trial_addr=" << (formal == trial ? 1 : 0)
              << "|formal_call_space="
              << (formal.getSpace() == call.getSpace() ? 1 : 0)
              << "|formal_call_addr=" << (formal == call ? 1 : 0)
              << '\n';
  }

  if (state.preexisting != (Varnode *)0) {
    Varnode *callInput = state.op->getIn(1);
    const Address addr = state.preexisting->getAddr();
    const int4 size = state.preexisting->getSize();
    VarnodeLocSet::const_iterator iter = state.fd->beginLoc(size,addr);
    VarnodeLocSet::const_iterator end = state.fd->endLoc(size,addr);
    int4 count = 0;
    bool firstIsPre = false;
    bool lastIsCall = false;
    for(;iter!=end;++iter) {
      if (count == 0) firstIsPre = (*iter == state.preexisting);
      lastIsCall = (*iter == callInput);
      count += 1;
    }
    std::cout << "bank|" << label
              << "|addr=" << addressDescriptor(addr)
              << "|size=" << size
              << "|pre_call_object=" << (state.preexisting == callInput ? 1 : 0)
              << "|pre_call_space="
              << (state.preexisting->getSpace() == callInput->getSpace() ? 1 : 0)
              << "|pre_call_addr="
              << (state.preexisting->getAddr() == callInput->getAddr() ? 1 : 0)
              << "|exact_count=" << count
              << "|first_pre=" << (firstIsPre ? 1 : 0)
              << "|latest_call=" << (lastIsCall ? 1 : 0) << '\n';
  }

  std::cout << "mapping|" << label << '|';
  for(int4 slot=1;slot<=active.getNumTrials();++slot) {
    if (slot != 1) std::cout << ',';
    const ParamTrial &mapped = active.getTrialForInputVarnode(slot);
    std::cout << slot << "->" << trialIndex(active,&mapped);
  }
  std::cout << '\n';
}

void dumpAfterPlaceholderMapping(const FuncCallSpecs &locked)
{
  ParamActive active(true);
  active.registerTrial(locked.getParam(0)->getAddress(),
                       locked.getParam(0)->getSize());
  active.setPlaceholderSlot();
  active.registerTrial(locked.getParam(1)->getAddress(),
                       locked.getParam(1)->getSize());
  const int4 before = trialIndex(active,&active.getTrialForInputVarnode(1));
  const int4 after = trialIndex(active,&active.getTrialForInputVarnode(3));
  std::cout << "mapping_after_placeholder|placeholder="
            << activePlaceholder(active)
            << "|slot1=" << before << "|slot3=" << after
            << "|trial_slots=" << active.getTrial(0).getSlot()
            << ',' << active.getTrial(1).getSlot() << '\n';
}

void runFixture(const std::string &specRoot,const std::string &binary)
{
  startDecompilerLibrary(std::vector<std::string>(1,specRoot));
  {
    std::ostringstream diagnostics;
    BfdArchitecture architecture(binary,"default",&diagnostics);
    DocumentStorage store;
    architecture.init(store);

    std::cout << "schema=1|fixture=ACTION-FUNCLINK-INPUT-1204|oracle="
              << "e40ed13014025f82488b1f8f7bca566894ac376b\n";

    CaseState locked = makeCase(architecture,"locked",0x700000,0x700100,
                                true,false,7);
    CaseState registerOnly = makeCase(architecture,"register_only",0x700600,
                                      0x700700,true,false,6);
    CaseState varargs = makeCase(architecture,"varargs",0x700200,0x700300,
                                 true,true,7);
    CaseState unlocked = makeCase(architecture,"unlocked",0x700400,0x700500,
                                  false,false,0);

    ActionFuncLink action("fixture");
    action.apply(*locked.fd);
    action.apply(*registerOnly.fd);
    action.apply(*varargs.fd);
    action.apply(*unlocked.fd);

    dumpCase("locked",locked);
    dumpCase("register_only",registerOnly);
    dumpCase("varargs",varargs);
    dumpCase("unlocked",unlocked);
    dumpAfterPlaceholderMapping(*locked.spec);
    std::cout << "done\n";
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 2) {
    std::cerr << "usage: action_funclink_input_1204 SPEC_ROOT\n";
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
