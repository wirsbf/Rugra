/*
 * PIPE-0000: locked Ghidra 12.0.4 Action executor oracle.
 *
 * The scripted leaf controls only its own apply() result and the protected
 * change counter.  Action::reset(), Action::perform(), and
 * ActionGroup::apply() are the real locked Ghidra implementations.
 */
#include "action.hh"
#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;

struct ScriptStep {
  int4 changes;
  int4 result;

  ScriptStep(int4 changeCount,int4 returnValue)
    : changes(changeCount), result(returnValue) {}
};

struct Snapshot {
  uint4 status;
  int4 count;
  int4 lcount;
  uint4 countTests;
  uint4 countApply;
};

class ScriptedAction : public Action {
  vector<ScriptStep> script;
  size_t cursor;
  uint4 applyCalls;
  uint4 resetCalls;
  vector<int4> observedChanges;
  vector<string> *sharedTrace;
public:
  ScriptedAction(uint4 actionFlags,const string &actionName,
                 const vector<ScriptStep> &steps,vector<string> *trace = (vector<string> *)0)
    : Action(actionFlags,actionName,"fixture"), script(steps), cursor(0),
      applyCalls(0), resetCalls(0), sharedTrace(trace) {
    // Action::perform initializes these before reading them.  Initializing the
    // probe fields as well makes pre-perform/reset snapshots deterministic.
    count = 0;
    lcount = 0;
  }

  virtual Action *clone(const ActionGroupList &grouplist) const {
    return (Action *)0;
  }

  virtual void reset(Funcdata &data) {
    resetCalls += 1;
    Action::reset(data);
  }

  virtual int4 apply(Funcdata &data) {
    (void)data;
    applyCalls += 1;
    if (sharedTrace != (vector<string> *)0)
      sharedTrace->push_back(getName());
    ScriptStep step(0,0);
    if (cursor < script.size()) {
      step = script[cursor];
      cursor += 1;
    }
    observedChanges.push_back(step.changes);
    count += step.changes;
    return step.result;
  }

  Snapshot snapshot(void) const {
    Snapshot result = { status, count, lcount, count_tests, count_apply };
    return result;
  }

  uint4 getApplyCalls(void) const { return applyCalls; }
  uint4 getResetCalls(void) const { return resetCalls; }
  size_t getCursor(void) const { return cursor; }
  const vector<int4> &getObservedChanges(void) const { return observedChanges; }
};

class ProbeGroup : public ActionGroup {
public:
  ProbeGroup(uint4 actionFlags,const string &actionName)
    : ActionGroup(actionFlags,actionName) {
    count = 0;
    lcount = 0;
  }

  Snapshot snapshot(void) const {
    Snapshot result = { status, count, lcount, count_tests, count_apply };
    return result;
  }

  size_t stateIndex(void) const {
    return static_cast<size_t>(state - list.begin());
  }

  vector<string> childNames(void) const {
    vector<string> result;
    for(vector<Action *>::const_iterator iter=list.begin();iter!=list.end();++iter)
      result.push_back((*iter)->getName());
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

template<typename T>
void writeNumberArray(ostream &out,const vector<T> &values,size_t begin)
{
  out << '[';
  for(size_t i=begin;i<values.size();++i) {
    if (i != begin) out << ',';
    out << values[i];
  }
  out << ']';
}

void writeStringArray(ostream &out,const vector<string> &values,size_t begin)
{
  out << '[';
  for(size_t i=begin;i<values.size();++i) {
    if (i != begin) out << ',';
    writeString(out,values[i]);
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

void writeLeafState(ostream &out,const ScriptedAction &action)
{
  out << "{\"name\":";
  writeString(out,action.getName());
  out << ",\"executor\":";
  writeSnapshot(out,action.snapshot());
  out << ",\"apply_calls\":" << action.getApplyCalls()
      << ",\"reset_calls\":" << action.getResetCalls()
      << ",\"script_cursor\":" << action.getCursor() << '}';
}

void writeLeafEvent(ostream &out,const string &label,int4 result,
                    const ScriptedAction &action,size_t changeBegin)
{
  out << "{\"label\":";
  writeString(out,label);
  out << ",\"return\":" << result << ",\"changes\":";
  writeNumberArray(out,action.getObservedChanges(),changeBegin);
  out << ",\"action\":";
  writeLeafState(out,action);
  out << '}';
}

void writeResetEvent(ostream &out,const string &label,const ScriptedAction &action)
{
  out << "{\"label\":";
  writeString(out,label);
  out << ",\"return\":null,\"changes\":[],\"action\":";
  writeLeafState(out,action);
  out << '}';
}

void writeRepeatCase(ostream &out,Funcdata &fd)
{
  ScriptedAction action(Action::rule_repeatapply,"repeat_leaf",
    vector<ScriptStep>{ScriptStep(2,0),ScriptStep(1,0),ScriptStep(0,0)});
  action.reset(fd);
  out << "{\"id\":\"repeatapply\",\"flags\":4,\"events\":[";
  size_t begin = action.getObservedChanges().size();
  int4 result = action.perform(fd);
  writeLeafEvent(out,"perform_1",result,action,begin);
  out << ',';
  begin = action.getObservedChanges().size();
  result = action.perform(fd);
  writeLeafEvent(out,"perform_2",result,action,begin);
  out << "]}";
}

void writeOnceCase(ostream &out,Funcdata &fd)
{
  ScriptedAction action(Action::rule_onceperfunc,"once_leaf",
    vector<ScriptStep>{ScriptStep(0,0),ScriptStep(5,0)});
  action.reset(fd);
  out << "{\"id\":\"once_per_func\",\"flags\":8,\"events\":[";
  size_t begin = action.getObservedChanges().size();
  int4 result = action.perform(fd);
  writeLeafEvent(out,"perform_1",result,action,begin);
  out << ',';
  begin = action.getObservedChanges().size();
  result = action.perform(fd);
  writeLeafEvent(out,"perform_2",result,action,begin);
  out << ',';
  action.reset(fd);
  writeResetEvent(out,"reset",action);
  out << ',';
  begin = action.getObservedChanges().size();
  result = action.perform(fd);
  writeLeafEvent(out,"perform_3",result,action,begin);
  out << "]}";
}

void writeOneActCase(ostream &out,Funcdata &fd)
{
  ScriptedAction action(Action::rule_oneactperfunc,"oneact_leaf",
    vector<ScriptStep>{ScriptStep(0,0),ScriptStep(4,0),ScriptStep(9,0)});
  action.reset(fd);
  out << "{\"id\":\"one_act_per_func\",\"flags\":16,\"events\":[";
  size_t begin = action.getObservedChanges().size();
  int4 result = action.perform(fd);
  writeLeafEvent(out,"perform_1",result,action,begin);
  out << ',';
  begin = action.getObservedChanges().size();
  result = action.perform(fd);
  writeLeafEvent(out,"perform_2",result,action,begin);
  out << ',';
  begin = action.getObservedChanges().size();
  result = action.perform(fd);
  writeLeafEvent(out,"perform_3",result,action,begin);
  out << ',';
  action.reset(fd);
  writeResetEvent(out,"reset",action);
  out << ',';
  begin = action.getObservedChanges().size();
  result = action.perform(fd);
  writeLeafEvent(out,"perform_4",result,action,begin);
  out << "]}";
}

void writePartialLeafCase(ostream &out,Funcdata &fd)
{
  ScriptedAction action(0,"partial_leaf",
    vector<ScriptStep>{ScriptStep(0,-7),ScriptStep(2,0)});
  action.reset(fd);
  out << "{\"id\":\"partial_leaf_resume\",\"flags\":0,\"events\":[";
  size_t begin = action.getObservedChanges().size();
  int4 result = action.perform(fd);
  writeLeafEvent(out,"perform_1",result,action,begin);
  out << ',';
  begin = action.getObservedChanges().size();
  result = action.perform(fd);
  writeLeafEvent(out,"perform_2",result,action,begin);
  out << "]}";
}

void writeChildStates(ostream &out,const vector<ScriptedAction *> &children)
{
  out << '[';
  for(size_t i=0;i<children.size();++i) {
    if (i != 0) out << ',';
    writeLeafState(out,*children[i]);
  }
  out << ']';
}

void writeGroupEvent(ostream &out,const string &label,int4 result,
                     const ProbeGroup &group,
                     const vector<ScriptedAction *> &children,
                     const vector<string> &trace,size_t traceBegin,
                     size_t change0,size_t change1,size_t change2)
{
  out << "{\"label\":";
  writeString(out,label);
  out << ",\"return\":" << result << ",\"trace\":";
  writeStringArray(out,trace,traceBegin);
  out << ",\"changes\":[";
  writeNumberArray(out,children[0]->getObservedChanges(),change0);
  out << ',';
  writeNumberArray(out,children[1]->getObservedChanges(),change1);
  out << ',';
  writeNumberArray(out,children[2]->getObservedChanges(),change2);
  out << "],\"group_state_index\":" << group.stateIndex()
      << ",\"group\":";
  writeSnapshot(out,group.snapshot());
  out << ",\"children\":";
  writeChildStates(out,children);
  out << '}';
}

void writeGroupResetEvent(ostream &out,const string &label,
                          const ProbeGroup &group,
                          const vector<ScriptedAction *> &children,
                          const vector<string> &trace,size_t traceBegin,
                          size_t change0,size_t change1,size_t change2)
{
  out << "{\"label\":";
  writeString(out,label);
  out << ",\"return\":null,\"trace\":";
  writeStringArray(out,trace,traceBegin);
  out << ",\"changes\":[";
  writeNumberArray(out,children[0]->getObservedChanges(),change0);
  out << ',';
  writeNumberArray(out,children[1]->getObservedChanges(),change1);
  out << ',';
  writeNumberArray(out,children[2]->getObservedChanges(),change2);
  out << "],\"group_state_index\":" << group.stateIndex()
      << ",\"group\":";
  writeSnapshot(out,group.snapshot());
  out << ",\"children\":";
  writeChildStates(out,children);
  out << '}';
}

void writeGroupCase(ostream &out,Funcdata &fd)
{
  vector<string> trace;
  ProbeGroup group(0,"partial_group");
  ScriptedAction *first = new ScriptedAction(0,"group_first",
    vector<ScriptStep>{ScriptStep(1,0)},&trace);
  ScriptedAction *partial = new ScriptedAction(0,"group_partial",
    vector<ScriptStep>{ScriptStep(0,-7),ScriptStep(2,0)},&trace);
  ScriptedAction *last = new ScriptedAction(0,"group_last",
    vector<ScriptStep>{ScriptStep(4,0)},&trace);
  group.addAction(first);
  group.addAction(partial);
  group.addAction(last);
  vector<ScriptedAction *> children{first,partial,last};
  group.reset(fd);

  out << "{\"id\":\"group_partial_resume\",\"flags\":0,\"child_order\":";
  writeStringArray(out,group.childNames(),0);
  out << ",\"events\":[";

  size_t traceBegin = trace.size();
  size_t change0 = first->getObservedChanges().size();
  size_t change1 = partial->getObservedChanges().size();
  size_t change2 = last->getObservedChanges().size();
  int4 result = group.perform(fd);
  writeGroupEvent(out,"perform_1",result,group,children,trace,traceBegin,
                  change0,change1,change2);
  out << ',';

  traceBegin = trace.size();
  change0 = first->getObservedChanges().size();
  change1 = partial->getObservedChanges().size();
  change2 = last->getObservedChanges().size();
  result = group.perform(fd);
  writeGroupEvent(out,"perform_2",result,group,children,trace,traceBegin,
                  change0,change1,change2);

  out << ',';
  traceBegin = trace.size();
  change0 = first->getObservedChanges().size();
  change1 = partial->getObservedChanges().size();
  change2 = last->getObservedChanges().size();
  group.reset(fd);
  writeGroupResetEvent(out,"reset_after_complete",group,children,trace,traceBegin,
                       change0,change1,change2);

  out << ',';
  traceBegin = trace.size();
  change0 = first->getObservedChanges().size();
  change1 = partial->getObservedChanges().size();
  change2 = last->getObservedChanges().size();
  result = group.perform(fd);
  writeGroupEvent(out,"perform_3",result,group,children,trace,traceBegin,
                  change0,change1,change2);
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

  std::cout << "{\"schema\":1,\"fixture\":\"PIPE-0000\",\"function\":{\"name\":";
  writeString(std::cout,fd->getName());
  std::cout << ",\"entry\":" << fd->getAddress().getOffset()
            << ",\"size\":" << fd->getSize() << "},\"cases\":[";
  writeRepeatCase(std::cout,*fd);
  std::cout << ',';
  writeOnceCase(std::cout,*fd);
  std::cout << ',';
  writeOneActCase(std::cout,*fd);
  std::cout << ',';
  writePartialLeafCase(std::cout,*fd);
  std::cout << ',';
  writeGroupCase(std::cout,*fd);
  std::cout << "]}\n";
}

} // namespace

int main(int argc,char **argv)
{
  try {
    if (argc != 3)
      throw std::invalid_argument("usage: action_perform_1204 SPEC_DIRECTORY BINARY");
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
