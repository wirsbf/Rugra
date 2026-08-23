/*
 * ACTION-BREAKPOINT-RESUME-0001: locked Ghidra 12.0.4 Action breakpoint and
 * resume oracle (action.cc:52/117/171/257/275/285/298/382/456/481/506/789/
 * 822/877).
 *
 * The fixture drives the REAL derived default tree (ActionDatabase::
 * universalAction -> resetDefaults -> getCurrent, exactly the pipeline_tree
 * fixture's production derivation) for the name-path addressing and the
 * break_start stop/continue observations, and scripted probe trees for the
 * deterministic change-driven breakpoint matrix (break_action/tmpbreak on
 * leaves, groups, and pool rules).  Every observation is emitted through the
 * public API surface the console itself uses (setBreakPoint/getSubAction/
 * getSubRule/perform/printState/clearBreakPoints, ifacedecomp.cc:1196/1222)
 * plus test-only reads of the protected status/count/breakpoint members
 * (mirrored on the Rust side by the externalized ActionState slots).
 */

#include <bits/stdc++.h>

// Test-only access is required to read the protected Action member fields
// (status/count/breakpoint/op_state/rule_index), matching what production
// reaches through the console API and Rugra reaches through the externalized
// ActionState slots.
#define private public
#define protected public
#include "architecture.hh"
#include "comment.hh"
#include "coreaction.hh"
#include "cover.hh"
#include "database.hh"
#include "flow.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef private
#undef protected

using namespace ghidra;

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false,
                              8, 1, 6, 0, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummy_register.space = getSpace(4);
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override {
    return (PcodeInjectLibrary *)0;
  }
  void buildTypegrp(DocumentStorage &) override {}
  void buildCoreTypes(DocumentStorage &) override {}
  void buildCommentDB(DocumentStorage &) override {}
  void buildStringManager(DocumentStorage &) override {}
  void buildConstantPool(DocumentStorage &) override {}
  void buildContext(DocumentStorage &) override {}
  void buildSymbols(DocumentStorage &) override {}
  void buildSpecFile(DocumentStorage &) override {}
  void modifySpaces(Translate *) override {}
  void resolveArchitecture(void) override {}

public:
  FixtureArchitecture() {
    FixtureTranslate *fixture_translate = new FixtureTranslate();
    translate = fixture_translate;
    copySpaces(fixture_translate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    commentdb = new CommentDatabaseInternal();
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const std::string &) const override {}
};

// ----------------------------------------------------------------------------
// Scripted probe classes (case C/D).  Mirrors the PIPE-0000 ScriptedAction:
// the script controls only the apply() return and the protected count
// increment; Action::reset/perform/setBreakPoint and the group/pool plumbing
// are the real locked implementations.
// ----------------------------------------------------------------------------

struct ScriptStep {
  int4 changes;
  int4 result;
  ScriptStep(int4 changeCount, int4 returnValue)
    : changes(changeCount), result(returnValue) {}
};

class ScriptedAction final : public Action {
  std::vector<ScriptStep> script;
  size_t cursor;
  uint4 applyCalls;
  std::vector<std::string> *sharedTrace;

public:
  ScriptedAction(uint4 actionFlags, const std::string &actionName,
                 const std::vector<ScriptStep> &steps,
                 std::vector<std::string> *trace = (std::vector<std::string> *)0)
    : Action(actionFlags, actionName, "fixture"), script(steps), cursor(0),
      applyCalls(0), sharedTrace(trace) {
    count = 0;
    lcount = 0;
  }

  virtual Action *clone(const ActionGroupList &) const { return (Action *)0; }

  virtual int4 apply(Funcdata &data) {
    (void)data;
    applyCalls += 1;
    if (sharedTrace != (std::vector<std::string> *)0)
      sharedTrace->push_back(getName());
    ScriptStep step(0, 0);
    if (cursor < script.size()) {
      step = script[cursor];
      cursor += 1;
    }
    count += step.changes;
    return step.result;
  }

  uint4 getApplyCalls(void) const { return applyCalls; }
};

class ProbeGroup final : public ActionGroup {
public:
  ProbeGroup(uint4 actionFlags, const std::string &actionName)
    : ActionGroup(actionFlags, actionName) {
    count = 0;
    lcount = 0;
  }
  size_t stateIndex(void) const { return static_cast<size_t>(state - list.begin()); }
};

// The rule records every applyOp attempt (test) and every application with
// the op's address, exposing the pool's dispatch/resume position
// behaviorally: ActionPool::op_state/rule_index are default-private in the
// oracle header, so the fixture observes the same facts through the rule.
class CountingRule final : public Rule {
  int4 budget;
  uint4 tests;
  uint4 applies;
  std::vector<uintb> appliedAt;

public:
  CountingRule(const std::string &name)
    : Rule("analysis", 0, name), budget(2), tests(0), applies(0) {}

  Rule *clone(const ActionGroupList &) const override { return (Rule *)0; }

  void getOpList(std::vector<uint4> &oplist) const override {
    oplist.push_back(static_cast<uint4>(CPUI_COPY));
  }

  int4 applyOp(PcodeOp *op, Funcdata &) override {
    tests += 1;
    if (budget > 0) {
      budget -= 1;
      applies += 1;
      appliedAt.push_back(op->getAddr().getOffset());
      return 1;
    }
    return 0;
  }

  uint4 numTests(void) const { return tests; }
  uint4 numApplies(void) const { return applies; }
  const std::vector<uintb> &appliedAddresses(void) const { return appliedAt; }
};

static string normalizeName(const string &nm)
{
  string out;
  for (size_t i = 0; i < nm.size(); ++i)
    if (nm[i] != '_')
      out.push_back(nm[i]);
  return out;
}

static string poolNameOf(const Action *node)
{
  return node->getName();
}

// ----------------------------------------------------------------------------
// Case A: name-path addressing on the real derived default tree.
// ----------------------------------------------------------------------------

static void reportSubAction(Action *root, const string &spec)
{
  Action *res = root->getSubAction(spec);
  if (res == (Action *)0)
    std::cout << "addr|spec=" << spec << "|kind=action|match=NONE\n";
  else
    std::cout << "addr|spec=" << spec << "|kind=action|name=" << res->getName() << '\n';
}

// Rule-name observation: the resolved Rule* name is printed normalized
// (Rugra names rules in snake_case, the oracle without underscores).  The
// pool containing the rule is identified by the second-to-last path term,
// which names the pool node itself (getSubRule's descent semantics,
// action.cc:794-811).
static void reportSubRule(Action *root, const std::string &spec)
{
  Rule *res = root->getSubRule(spec);
  if (res == (Rule *)0) {
    std::cout << "addr|spec=" << normalizeName(spec) << "|kind=rule|match=NONE\n";
    return;
  }
  std::string::size_type pos = spec.rfind(':');
  std::string poolName = (pos == std::string::npos) ? std::string() : spec.substr(0, pos);
  pos = poolName.rfind(':');
  if (pos != std::string::npos)
    poolName = poolName.substr(pos + 1);
  std::cout << "addr|spec=" << normalizeName(spec) << "|kind=rule|name="
            << normalizeName(res->getName())
            << "|pool=" << poolName << '\n';
}

// ----------------------------------------------------------------------------
// Case C: scripted breakpoint matrix.  Each observation line pins one
// perform() call's return plus the observable member state.
// ----------------------------------------------------------------------------

static void emitLeafCall(const char *tag, int4 ret, const Action &action)
{
  std::cout << tag << "|ret=" << ret
            << "|status=" << action.status
            << "|count=" << action.count
            << "|lcount=" << action.lcount
            << "|tests=" << action.count_tests
            << "|applies=" << action.count_apply
            << "|breakpoint=" << action.breakpoint
            << "|apply_calls=" << ((ScriptedAction &)action).getApplyCalls()
            << '\n';
}

static void emitGroupCall(const char *tag, int4 ret, const ProbeGroup &group,
                          const std::vector<std::string> &trace)
{
  std::cout << tag << "|ret=" << ret
            << "|status=" << group.status
            << "|count=" << group.count
            << "|state_index=" << group.stateIndex()
            << "|trace=";
  for (size_t i = 0; i < trace.size(); ++i)
    std::cout << (i ? ">" : "") << trace[i];
  std::cout << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::cout << "schema=1|fixture=ACTION-BREAKPOINT-RESUME-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  try {
    FixtureArchitecture arch;
    arch.allacts.universalAction(&arch);
    arch.allacts.resetDefaults();
    Action *root = arch.allacts.getCurrent();

    // --- Case A: addressing on the real tree -------------------------------
    reportSubAction(root, "universal");
    reportSubAction(root, "universal:fullloop");
    reportSubAction(root, "universal:fullloop:mainloop");
    reportSubAction(root, "universal:fullloop:mainloop:stackstall");
    reportSubAction(root, "universal:fullloop:mainloop:deadcode");
    reportSubAction(root, "universal:fullloop:mainloop:unreachable");
    reportSubAction(root, "universal:fullloop:deadcode");
    reportSubAction(root, "universal:dynamicsymbols");
    reportSubAction(root, "universal:nonexistent");
    reportSubAction(root, "universal:cleanup");
    reportSubRule(root, "universal:cleanup:multnegone");
    reportSubRule(root, "universal:fullloop:mainloop:stackstall:oppool1:earlyremoval");
    reportSubRule(root, "universal:fullloop:mainloop");
    reportSubAction(root, "universal:cleanup:multnegone");

    // setBreakPoint return values (action.cc:171-185).
    std::cout << "setbp|spec=universal:fullloop:mainloop|tp=1|ok="
              << (root->setBreakPoint(Action::break_start, "universal:fullloop:mainloop") ? 1 : 0) << '\n';
    std::cout << "setbp|spec=universal:fullloop:mainloop:unreachable|tp=1|ok="
              << (root->setBreakPoint(Action::break_start, "universal:fullloop:mainloop:unreachable") ? 1 : 0) << '\n';
    std::cout << "setbp|spec=universal:cleanup:multnegone|tp=4|ok="
              << (root->setBreakPoint(Action::break_action, "universal:cleanup:multnegone") ? 1 : 0) << '\n';
    std::cout << "setbp|spec=universal:cleanup:multnegone typo|tp=4|ok="
              << (root->setBreakPoint(Action::break_action, "universal:cleanup:multnegone typo") ? 1 : 0) << '\n';

    // Breakpoint bits land on the addressed nodes (action.hh:83 / Rule::breakpoint).
    {
      Action *mainloop = root->getSubAction("universal:fullloop:mainloop");
      std::cout << "bpbits|node=universal:fullloop:mainloop|bits=" << mainloop->breakpoint << '\n';
      Rule *rule = root->getSubRule("universal:cleanup:multnegone");
      std::cout << "bpbits|rule=universal:cleanup:multnegone|bits=" << rule->getBreakPoint() << '\n';
      root->clearBreakPoints();
      std::cout << "bpbits_clear|node=universal:fullloop:mainloop|bits=" << mainloop->breakpoint << '\n';
      std::cout << "bpbits_clear|rule=universal:cleanup:multnegone|bits=" << rule->getBreakPoint() << '\n';
    }

    // --- Case B: real-tree break_start stop/continue ------------------------
    AddrSpace *code = arch.getDefaultCodeSpace();
    Scope *globalscope = arch.symboltab->getGlobalScope();
    Funcdata *fd = globalscope->addFunction(Address(code, 0x1000), "fixture")->getFunction();

    Action *fullloop = root->getSubAction("universal:fullloop");
    std::cout << "real|set_mainloop="
              << (root->setBreakPoint(Action::break_start, "universal:fullloop:mainloop") ? 1 : 0) << '\n';
    fullloop->reset(*fd);
    {
      int4 r1 = fullloop->perform(*fd);
      std::ostringstream s;
      fullloop->printState(s);
      Action *mainloop = root->getSubAction("universal:fullloop:mainloop");
      std::cout << "real|fullloop_perform1=" << r1
                << "|state=" << s.str()
                << "|mainloop_status=" << mainloop->getStatus() << '\n';
    }
    root->clearBreakPoints();

    Action *stackstall = root->getSubAction("universal:fullloop:mainloop:stackstall");
    std::cout << "real|set_stackstall="
              << (root->setBreakPoint(Action::break_start, "universal:fullloop:mainloop:stackstall") ? 1 : 0) << '\n';
    stackstall->reset(*fd);
    {
      int4 r1 = stackstall->perform(*fd);
      std::ostringstream s1;
      stackstall->printState(s1);
      std::cout << "real|ss_perform1=" << r1 << "|state1=" << s1.str() << '\n';
      int4 r2 = stackstall->perform(*fd);
      std::ostringstream s2;
      stackstall->printState(s2);
      std::cout << "real|ss_perform2=" << r2 << "|state2=" << s2.str() << '\n';
    }
    root->clearBreakPoints();
    stackstall->reset(*fd);
    {
      int4 r3 = stackstall->perform(*fd);
      std::ostringstream s3;
      stackstall->printState(s3);
      std::cout << "real|ss_single=" << r3 << "|state3=" << s3.str() << '\n';
    }

    // --- Case C: scripted breakpoint matrix ---------------------------------
    {
      // c1: persistent break_start on a leaf (count_tests not incremented on
      // the broken start; resume from breakstarthit applies without
      // re-checking; the persistent bit re-fires on the next status_start).
      ScriptedAction a(0, "leaf1",
        vector<ScriptStep>{ScriptStep(3, 0), ScriptStep(5, 0)});
      Funcdata *f2 = globalscope->addFunction(Address(code, 0x4000), "c1")->getFunction();
      a.reset(*f2);
      a.setBreakPoint(Action::break_start, "leaf1");
      emitLeafCall("c1_call1", a.perform(*f2), a);
      emitLeafCall("c1_call2", a.perform(*f2), a);
      emitLeafCall("c1_call3", a.perform(*f2), a);
      a.clearBreakPoints();
      emitLeafCall("c1_call4", a.perform(*f2), a);
      emitLeafCall("c1_call5", a.perform(*f2), a);
    }
    {
      // c2: tmpbreak_start fires exactly once (bit cleared when hit).
      ScriptedAction a(Action::rule_repeatapply, "leaf2",
        vector<ScriptStep>{ScriptStep(2, 0), ScriptStep(2, 0)});
      Funcdata *f2 = globalscope->addFunction(Address(code, 0x5000), "c2")->getFunction();
      a.reset(*f2);
      a.setBreakPoint(Action::tmpbreak_start, "leaf2");
      emitLeafCall("c2_call1", a.perform(*f2), a);
      emitLeafCall("c2_call2", a.perform(*f2), a);
      emitLeafCall("c2_call3", a.perform(*f2), a);
    }
    {
      // c3: break_action fires after the change is counted; resume from
      // status_actionbreak does not reapply and returns the count.
      ScriptedAction a(0, "leaf3", vector<ScriptStep>{ScriptStep(5, 0)});
      Funcdata *f2 = globalscope->addFunction(Address(code, 0x6000), "c3")->getFunction();
      a.reset(*f2);
      a.setBreakPoint(Action::break_action, "leaf3");
      emitLeafCall("c3_call1", a.perform(*f2), a);
      emitLeafCall("c3_call2", a.perform(*f2), a);
      emitLeafCall("c3_call3", a.perform(*f2), a);
    }
    {
      // c4: group-level break_action steps after every changing child and
      // resumes at the next child (++state, action.cc:517-520).
      std::vector<std::string> trace;
      ProbeGroup g(0, "stepper");
      g.addAction(new ScriptedAction(0, "c4_first", vector<ScriptStep>{ScriptStep(1, 0)}, &trace));
      g.addAction(new ScriptedAction(0, "c4_mid", vector<ScriptStep>{ScriptStep(2, 0)}, &trace));
      g.addAction(new ScriptedAction(0, "c4_last", vector<ScriptStep>{ScriptStep(4, 0)}, &trace));
      Funcdata *f2 = globalscope->addFunction(Address(code, 0x7000), "c4")->getFunction();
      g.reset(*f2);
      g.setBreakPoint(Action::break_action, "stepper");
      size_t begin;
      begin = trace.size();
      int4 r = g.perform(*f2);
      std::vector<std::string> t1(trace.begin() + begin, trace.end());
      emitGroupCall("c4_call1", r, g, t1);
      begin = trace.size();
      r = g.perform(*f2);
      std::vector<std::string> t2(trace.begin() + begin, trace.end());
      emitGroupCall("c4_call2", r, g, t2);
      begin = trace.size();
      r = g.perform(*f2);
      std::vector<std::string> t3(trace.begin() + begin, trace.end());
      emitGroupCall("c4_call3", r, g, t3);
      begin = trace.size();
      r = g.perform(*f2);
      std::vector<std::string> t4(trace.begin() + begin, trace.end());
      emitGroupCall("c4_call4", r, g, t4);
      begin = trace.size();
      r = g.perform(*f2);
      std::vector<std::string> t5(trace.begin() + begin, trace.end());
      emitGroupCall("c4_call5", r, g, t5);
    }
    {
      // c5: tmpbreak_action on a group fires once; the resume is not stopped
      // again (tmp bit cleared in place).
      std::vector<std::string> trace;
      ProbeGroup g(0, "tmpgroup");
      g.addAction(new ScriptedAction(0, "c5_first", vector<ScriptStep>{ScriptStep(1, 0)}, &trace));
      g.addAction(new ScriptedAction(0, "c5_last", vector<ScriptStep>{ScriptStep(2, 0)}, &trace));
      Funcdata *f2 = globalscope->addFunction(Address(code, 0x8000), "c5")->getFunction();
      g.reset(*f2);
      g.setBreakPoint(Action::tmpbreak_action, "tmpgroup");
      size_t begin = trace.size();
      int4 r = g.perform(*f2);
      std::vector<std::string> t1(trace.begin() + begin, trace.end());
      emitGroupCall("c5_call1", r, g, t1);
      begin = trace.size();
      r = g.perform(*f2);
      std::vector<std::string> t2(trace.begin() + begin, trace.end());
      emitGroupCall("c5_call2", r, g, t2);
    }
    {
      // c6: interrupted+resumed run equals an uninterrupted single run
      // (count/applies/trace).
      std::vector<std::string> traceSingle;
      ProbeGroup single(0, "single");
      single.addAction(new ScriptedAction(0, "s_first", vector<ScriptStep>{ScriptStep(1, 0)}, &traceSingle));
      single.addAction(new ScriptedAction(0, "s_mid", vector<ScriptStep>{ScriptStep(2, 0)}, &traceSingle));
      single.addAction(new ScriptedAction(0, "s_last", vector<ScriptStep>{ScriptStep(4, 0)}, &traceSingle));
      Funcdata *fs = globalscope->addFunction(Address(code, 0x9000), "c6s")->getFunction();
      single.reset(*fs);
      size_t begin = traceSingle.size();
      int4 rs = single.perform(*fs);
      std::vector<std::string> ts(traceSingle.begin() + begin, traceSingle.end());

      std::vector<std::string> traceResume;
      ProbeGroup resumed(0, "resumed");
      resumed.addAction(new ScriptedAction(0, "s_first", vector<ScriptStep>{ScriptStep(1, 0)}, &traceResume));
      resumed.addAction(new ScriptedAction(0, "s_mid", vector<ScriptStep>{ScriptStep(2, 0)}, &traceResume));
      resumed.addAction(new ScriptedAction(0, "s_last", vector<ScriptStep>{ScriptStep(4, 0)}, &traceResume));
      Funcdata *fr = globalscope->addFunction(Address(code, 0x9100), "c6r")->getFunction();
      resumed.reset(*fr);
      resumed.setBreakPoint(Action::tmpbreak_action, "resumed");
      int4 rr1 = resumed.perform(*fr);
      (void)rr1;
      // Compare the FULL interrupted+resumed trace (from the beginning of
      // the run) against the uninterrupted trace.
      int4 rr = resumed.perform(*fr);
      std::vector<std::string> tr(traceResume.begin(), traceResume.end());

      bool equal = (rs == rr) && (single.count == resumed.count)
        && (single.count_apply == resumed.count_apply) && (ts == tr);
      std::cout << "c6|single=" << rs << "|resumed=" << rr
                << "|single_count=" << single.count
                << "|resumed_count=" << resumed.count
                << "|single_applies=" << single.count_apply
                << "|resumed_applies=" << resumed.count_apply
                << "|trace=" << (ts == tr ? "same" : "diff")
                << "|equal=" << (equal ? 1 : 0) << '\n';
    }

    // --- Case D: rule-level breakpoint inside a real ActionPool ------------
    {
      // Single uninterrupted run.
      Funcdata *fs = globalscope->addFunction(Address(code, 0xa000), "ds")->getFunction();
      BlockGraph &graph = const_cast<BlockGraph &>(fs->getBasicBlocks());
      BlockBasic *block = graph.newBlockBasic(fs);
      for (int4 slot = 0; slot < 2; ++slot) {
        PcodeOp *op = fs->newOp(1, Address(code, 0xa000 + slot * 2));
        fs->opSetOpcode(op, CPUI_COPY);
        fs->opInsertEnd(op, block);
      }
      ProbeGroup single(0, "proberoot");
      ActionPool *pool = new ActionPool(Action::rule_repeatapply, "countpool");
      CountingRule *rule = new CountingRule("counter");
      pool->addRule(rule);
      single.addAction(pool);
      single.reset(*fs);
      int4 rs = single.perform(*fs);
      std::cout << "d_single|ret=" << rs
                << "|group_count=" << single.count
                << "|pool_count=" << pool->count
                << "|rule_tests=" << rule->numTests()
                << "|rule_applies=" << rule->numApplies()
                << "|applied_at=";
      for (size_t i = 0; i < rule->appliedAddresses().size(); ++i)
        std::cout << (i ? ">" : "") << "0x" << std::hex << rule->appliedAddresses()[i] << std::dec;
      std::cout << '\n';

      // Interrupted run: break_action on the rule stops after each
      // application; the resume continues from the same op without
      // re-applying the fired rule to it (action.cc:851-852 + 884-885).
      Funcdata *fr = globalscope->addFunction(Address(code, 0xb000), "dr")->getFunction();
      BlockGraph &graph2 = const_cast<BlockGraph &>(fr->getBasicBlocks());
      BlockBasic *block2 = graph2.newBlockBasic(fr);
      for (int4 slot = 0; slot < 2; ++slot) {
        PcodeOp *op = fr->newOp(1, Address(code, 0xb000 + slot * 2));
        fr->opSetOpcode(op, CPUI_COPY);
        fr->opInsertEnd(op, block2);
      }
      ProbeGroup resumed(0, "proberoot");
      ActionPool *pool2 = new ActionPool(Action::rule_repeatapply, "countpool");
      CountingRule *rule2 = new CountingRule("counter");
      pool2->addRule(rule2);
      resumed.addAction(pool2);
      resumed.reset(*fr);
      resumed.setBreakPoint(Action::break_action, "proberoot:countpool:counter");
      int4 r1 = resumed.perform(*fr);
      std::cout << "d_break1|ret=" << r1
                << "|rule_tests=" << rule2->numTests()
                << "|rule_applies=" << rule2->numApplies()
                << "|applied_at=";
      for (size_t i = 0; i < rule2->appliedAddresses().size(); ++i)
        std::cout << (i ? ">" : "") << "0x" << std::hex << rule2->appliedAddresses()[i] << std::dec;
      std::cout << '\n';
      int4 r2 = resumed.perform(*fr);
      std::cout << "d_break2|ret=" << r2
                << "|rule_tests=" << rule2->numTests()
                << "|rule_applies=" << rule2->numApplies()
                << "|applied_at=";
      for (size_t i = 0; i < rule2->appliedAddresses().size(); ++i)
        std::cout << (i ? ">" : "") << "0x" << std::hex << rule2->appliedAddresses()[i] << std::dec;
      std::cout << '\n';
      int4 r3 = resumed.perform(*fr);
      std::cout << "d_final|ret=" << r3
                << "|group_count=" << resumed.count
                << "|pool_count=" << pool2->count
                << "|rule_tests=" << rule2->numTests()
                << "|rule_applies=" << rule2->numApplies()
                << "|applied_at=";
      for (size_t i = 0; i < rule2->appliedAddresses().size(); ++i)
        std::cout << (i ? ">" : "") << "0x" << std::hex << rule2->appliedAddresses()[i] << std::dec;
      std::cout << "|resume_equals_single="
                << ((resumed.count == single.count
                     && rule2->numTests() == rule->numTests()
                     && rule2->numApplies() == rule->numApplies()) ? 1 : 0) << '\n';
    }
  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
    return 1;
  }
  return 0;
}
