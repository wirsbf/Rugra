/*
 * PIPE-ACTION-COUNT-0001A: locked Ghidra 12.0.4 leaf Action oracle.
 *
 * The fixture instantiates the real coreaction leaf classes.  Probe wrappers
 * expose Action's protected executor state and count virtual calls.  They also
 * set the base constructor's otherwise indeterminate count/lcount fields to a
 * shared deterministic zero precondition; the first perform overwrites them,
 * so this is not claimed as production constructor behavior.  Apart from this
 * precondition, ActionGroup::perform and every leaf apply/reset implementation
 * are the locked oracle implementations without synthesized changes.
 */
#include "action.hh"
#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

#include <cstdlib>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace ghidra;

struct Snapshot {
  uint4 status;
  int4 count;
  int4 lcount;
  uint4 countTests;
  uint4 countApply;
};

struct DataSnapshot {
  bool typeRecoveryOn;
  bool typeRecoveryStarted;
  int4 calls;
  int4 aliveOps;
  int4 blocks;
  int4 varnodes;
  bool modelLocked;
  bool inputLocked;
  bool outputLocked;
  string model;
  bool activeOutput;
};

template<typename Base>
class ProbeLeaf : public Base {
  uint4 applyCalls;
  uint4 resetCalls;
public:
  template<typename... Args>
  explicit ProbeLeaf(Args&&... args)
    : Base(std::forward<Args>(args)...), applyCalls(0), resetCalls(0) {
    // Action::Action leaves these indeterminate.  Give both probes a shared
    // precondition; perform() overwrites them before their behavioral use.
    this->count = 0;
    this->lcount = 0;
  }

  virtual void reset(Funcdata &data) {
    resetCalls += 1;
    Base::reset(data);
  }

  virtual int4 apply(Funcdata &data) {
    applyCalls += 1;
    return Base::apply(data);
  }

  Snapshot snapshot(void) const {
    Snapshot result = {
      this->status, this->count, this->lcount,
      this->count_tests, this->count_apply
    };
    return result;
  }

  uint4 rawFlags(void) const { return this->flags; }
  uint4 getApplyCalls(void) const { return applyCalls; }
  uint4 getResetCalls(void) const { return resetCalls; }
};

class TypeObserver : public Action {
  vector<bool> *phases;
public:
  TypeObserver(const string &group,vector<bool> *observed)
    : Action(0,"typeobserver",group), phases(observed) {}

  virtual Action *clone(const ActionGroupList &grouplist) const {
    (void)grouplist;
    return (Action *)0;
  }

  virtual int4 apply(Funcdata &data) {
    phases->push_back(data.hasTypeRecoveryStarted());
    return 0;
  }
};

class ProbeGroup : public ActionGroup {
public:
  ProbeGroup(uint4 actionFlags,const string &name)
    : ActionGroup(actionFlags,name) {
    count = 0;
    lcount = 0;
  }

  Snapshot snapshot(void) const {
    Snapshot result = { status, count, lcount, count_tests, count_apply };
    return result;
  }
};

void writeString(ostream &out,const string &value)
{
  out << '"';
  for(size_t i=0;i<value.size();++i) {
    unsigned char ch = static_cast<unsigned char>(value[i]);
    switch(ch) {
    case '"': out << "\\\""; break;
    case '\\': out << "\\\\"; break;
    case '\b': out << "\\b"; break;
    case '\f': out << "\\f"; break;
    case '\n': out << "\\n"; break;
    case '\r': out << "\\r"; break;
    case '\t': out << "\\t"; break;
    default:
      if (ch < 0x20) {
        const char *digits = "0123456789abcdef";
        out << "\\u00" << digits[(ch >> 4) & 0xf] << digits[ch & 0xf];
      }
      else
        out << static_cast<char>(ch);
      break;
    }
  }
  out << '"';
}

void writeBoolArray(ostream &out,const vector<bool> &values,size_t begin)
{
  out << '[';
  for(size_t i=begin;i<values.size();++i) {
    if (i != begin) out << ',';
    out << (values[i] ? "true" : "false");
  }
  out << ']';
}

void writeSnapshot(ostream &out,const Snapshot &snapshot)
{
  out << "{\"status\":" << snapshot.status
      << ",\"count\":" << snapshot.count
      << ",\"lcount\":" << snapshot.lcount
      << ",\"count_tests\":" << snapshot.countTests
      << ",\"count_apply\":" << snapshot.countApply << '}';
}

DataSnapshot captureData(const Funcdata &fd)
{
  int4 aliveOps = static_cast<int4>(
    std::distance(fd.beginOpAlive(),fd.endOpAlive()));
  const FuncProto &proto = fd.getFuncProto();
  DataSnapshot result = {
    fd.isTypeRecoveryOn(), fd.hasTypeRecoveryStarted(), fd.numCalls(),
    aliveOps, fd.getBasicBlocks().getSize(), fd.numVarnodes(),
    proto.isModelLocked(), proto.isInputLocked(), proto.isOutputLocked(),
    proto.getModelName(), fd.getActiveOutput() != (ParamActive *)0
  };
  return result;
}

void writeData(ostream &out,const DataSnapshot &data)
{
  out << "{\"type_recovery_on\":" << (data.typeRecoveryOn ? "true" : "false")
      << ",\"type_recovery_started\":" << (data.typeRecoveryStarted ? "true" : "false")
      << ",\"calls\":" << data.calls
      << ",\"alive_ops\":" << data.aliveOps
      << ",\"blocks\":" << data.blocks
      << ",\"varnodes\":" << data.varnodes
      << ",\"model_locked\":" << (data.modelLocked ? "true" : "false")
      << ",\"input_locked\":" << (data.inputLocked ? "true" : "false")
      << ",\"output_locked\":" << (data.outputLocked ? "true" : "false")
      << ",\"model\":";
  writeString(out,data.model);
  out << ",\"active_output\":" << (data.activeOutput ? "true" : "false") << '}';
}

template<typename Base>
void writeLeafState(ostream &out,const ProbeLeaf<Base> &action)
{
  out << "{\"raw_flags\":" << action.rawFlags()
      << ",\"effective_flags\":" << action.rawFlags()
      << ",\"executor\":";
  writeSnapshot(out,action.snapshot());
  out << ",\"apply_calls\":" << action.getApplyCalls()
      << ",\"reset_calls\":" << action.getResetCalls() << '}';
}

template<typename Observer,typename Starter>
void writeStartEvent(ostream &out,const string &label,bool hasReturn,int4 result,
                     const vector<bool> &phases,size_t phaseBegin,
                     const ProbeGroup &group,const Observer &observer,
                     const Starter &start,Funcdata &fd)
{
  out << "{\"label\":";
  writeString(out,label);
  out << ",\"return\":";
  if (hasReturn) out << result;
  else out << "null";
  out << ",\"observed_started\":";
  writeBoolArray(out,phases,phaseBegin);
  out << ",\"group\":";
  writeSnapshot(out,group.snapshot());
  out << ",\"observer\":";
  writeLeafState(out,observer);
  out << ",\"starttypes\":";
  writeLeafState(out,start);
  out << ",\"data\":";
  writeData(out,captureData(fd));
  out << '}';
}

void writeStartTypesCase(ostream &out,Funcdata &fd)
{
  vector<bool> phases;
  ProbeGroup group(Action::rule_repeatapply,"fullloop_starttypes");
  ProbeLeaf<TypeObserver> *observer =
    new ProbeLeaf<TypeObserver>("fixture",&phases);
  ProbeLeaf<ActionStartTypes> *start =
    new ProbeLeaf<ActionStartTypes>("fixture");
  group.addAction(observer);
  group.addAction(start);

  out << "{\"id\":\"fullloop_starttypes\",\"child_order\":[\"typeobserver\",\"starttypes\"],\"events\":[";
  group.reset(fd);
  writeStartEvent(out,"reset_1",false,0,phases,phases.size(),group,*observer,*start,fd);
  out << ',';

  size_t phaseBegin = phases.size();
  int4 result = group.perform(fd);
  writeStartEvent(out,"perform_1",true,result,phases,phaseBegin,group,*observer,*start,fd);
  out << ',';

  group.reset(fd);
  writeStartEvent(out,"reset_2",false,0,phases,phases.size(),group,*observer,*start,fd);
  out << ',';

  phaseBegin = phases.size();
  result = group.perform(fd);
  writeStartEvent(out,"perform_2",true,result,phases,phaseBegin,group,*observer,*start,fd);
  out << "]}";
}

template<typename Base>
void writeOnceEvent(ostream &out,const string &label,bool hasReturn,int4 result,
                    const ProbeLeaf<Base> &action,Funcdata &fd)
{
  out << "{\"label\":";
  writeString(out,label);
  out << ",\"return\":";
  if (hasReturn) out << result;
  else out << "null";
  out << ",\"action\":";
  writeLeafState(out,action);
  out << ",\"data\":";
  writeData(out,captureData(fd));
  out << '}';
}

template<typename Base>
void writeOnceAction(ostream &out,const string &id,
                     ProbeLeaf<Base> &action,Funcdata &fd)
{
  out << "{\"id\":";
  writeString(out,id);
  out << ",\"events\":[";

  action.reset(fd);
  writeOnceEvent(out,"reset_1",false,0,action,fd);
  out << ',';
  int4 result = action.perform(fd);
  writeOnceEvent(out,"perform_1",true,result,action,fd);
  out << ',';
  result = action.perform(fd);
  writeOnceEvent(out,"perform_2",true,result,action,fd);
  out << ',';
  action.reset(fd);
  writeOnceEvent(out,"reset_2",false,0,action,fd);
  out << ',';
  result = action.perform(fd);
  writeOnceEvent(out,"perform_3",true,result,action,fd);
  out << "]}";
}

void writeOnceCase(ostream &out,Funcdata &fd)
{
  ProbeLeaf<ActionPrototypeTypes> prototypeTypes("fixture");
  ProbeLeaf<ActionDefaultParams> defaultParams("fixture");
  ProbeLeaf<ActionExtraPopSetup> extraPop("fixture",(AddrSpace *)0);
  ProbeLeaf<ActionFuncLink> funcLink("fixture");
  ProbeLeaf<ActionFuncLinkOutOnly> funcLinkOutOnly("fixture");
  ProbeLeaf<ActionInternalStorage> internalStorage("fixture");

  out << "{\"id\":\"once_zero_work\",\"action_order\":["
      << "\"prototypetypes\",\"defaultparams\",\"extrapopsetup\","
      << "\"funclink\",\"funclink_outonly\",\"internalstorage\"],\"actions\":[";
  writeOnceAction(out,"prototypetypes",prototypeTypes,fd);
  out << ',';
  writeOnceAction(out,"defaultparams",defaultParams,fd);
  out << ',';
  writeOnceAction(out,"extrapopsetup",extraPop,fd);
  out << ',';
  writeOnceAction(out,"funclink",funcLink,fd);
  out << ',';
  writeOnceAction(out,"funclink_outonly",funcLinkOutOnly,fd);
  out << ',';
  writeOnceAction(out,"internalstorage",internalStorage,fd);
  out << "]}";
}

void runFixture(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary,"default",&std::cerr);
  DocumentStorage store;
  architecture.init(store);
  architecture.readLoaderSymbols("::");
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
  if (fd == (Funcdata *)0)
    throw std::runtime_error("GetStr was not found in the BFD symbol table");
  if (fd->hasNoCode())
    throw std::runtime_error("GetStr has no code");

  // Force a deterministic zero-work prototype.  This prevents
  // ActionPrototypeTypes from initiating output recovery while leaving the
  // actual action implementation and executor untouched.
  FuncProto &proto = fd->getFuncProto();
  proto.setInternal(architecture.defaultfp,architecture.types->getTypeVoid());
  proto.setModelLock(true);
  proto.setInputLock(true);
  proto.setOutputLock(true);

  std::cout << "{\"schema\":1,\"fixture\":\"PIPE-ACTION-COUNT-0001A\",\"function\":{\"name\":";
  writeString(std::cout,fd->getName());
  std::cout << ",\"entry\":" << fd->getAddress().getOffset()
            << ",\"size\":" << fd->getSize() << "},\"cases\":[";
  writeStartTypesCase(std::cout,*fd);
  std::cout << ',';
  writeOnceCase(std::cout,*fd);
  std::cout << "]}\n";
}

} // namespace

int main(int argc,char **argv)
{
  try {
    if (argc != 3)
      throw std::invalid_argument("usage: action_leaf_count_1204 SPEC_DIRECTORY BINARY");
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const ghidra::LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
  }
  catch(const std::exception &err) {
    std::cerr << "std::exception: " << err.what() << '\n';
  }
  catch(...) {
    std::cerr << "unknown exception\n";
  }
  return 1;
}
