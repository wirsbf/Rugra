/*
 * ACTION-EXECUTOR-BREAKPOOL-0001 locked Ghidra 12.0.4 fixture.
 *
 * The scripted leaves/rules only inject deterministic change counts and IR
 * mutations.  Breakpoint state machines, group/pool cursors, warnings,
 * counters, lookup, reset dispatch, PcodeOpTree traversal, and dead cleanup
 * are the real locked-oracle implementations from action.cc.
 */

#include <bits/stdc++.h>

#define private public
#define protected public
#include "action.hh"
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#undef protected
#undef private

using namespace ghidra;
using std::string;
using std::vector;

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;
public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this,this));
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"other",false,8,1,1,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new UniqueSpace(this,this,2,0));
    AddrSpace *ram = new AddrSpace(this,this,IPTR_PROCESSOR,"ram",false,8,1,3,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this,this,IPTR_PROCESSOR,"register",false,8,1,4,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this,this,"stack",5,8,ram,1,true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack,stack_pointer,8,true);
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"join",false,8,1,6,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new IopSpace(this,this,7));
    setDefaultCodeSpace(3);
    dummy_register.space = reg;
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummy_register; }
  string getRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData,string> &) const override {}
  void getUserOpNames(vector<string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &,const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &,const Address &) const override { return 0; }
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
    types->setCoreType("xunknown1",1,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown2",2,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown4",4,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown8",8,TYPE_UNKNOWN,false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst,types,translate);
    symboltab = new Database(this,false);
    symboltab->attachScope(new ScopeInternal(0x101,"",this),(Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }
  void printMessage(const string &message) const override {
    std::cerr << message << '\n';
  }
};

struct Step {
  int4 changes;
  int4 result;
  Step(int4 c,int4 r) : changes(c),result(r) {}
};

class ScriptAction final : public Action {
  vector<Step> script;
  size_t cursor;
public:
  uint4 calls;
  uint4 resets;
  vector<string> *trace;
  ScriptAction(uint4 f,const string &nm,const vector<Step> &steps,
               vector<string> *events = (vector<string> *)0)
    : Action(f,nm,"fixture"),script(steps),cursor(0),calls(0),resets(0),trace(events) {
    count = 0;
    lcount = 0;
  }
  Action *clone(const ActionGroupList &) const override { return (Action *)0; }
  void reset(Funcdata &fd) override {
    resets += 1;
    Action::reset(fd);
  }
  int4 apply(Funcdata &) override {
    calls += 1;
    if (trace != (vector<string> *)0) trace->push_back(name);
    Step step(0,0);
    if (cursor < script.size()) step = script[cursor++];
    count += step.changes;
    return step.result;
  }
};

class ProbeGroup final : public ActionGroup {
public:
  ProbeGroup(uint4 f,const string &nm) : ActionGroup(f,nm) {
    count = 0;
    lcount = 0;
  }
  size_t cursor(void) const { return static_cast<size_t>(state-list.begin()); }
};

class LookupRule final : public Rule {
  OpCode opcode;
public:
  LookupRule(const string &nm) : Rule("fixture",0,nm),opcode(CPUI_COPY) {}
  Rule *clone(const ActionGroupList &) const override { return (Rule *)0; }
  void getOpList(vector<uint4> &out) const override { out.push_back(opcode); }
};

static string join(const vector<string> &items)
{
  std::ostringstream out;
  for(size_t i=0;i<items.size();++i) {
    if (i != 0) out << '>';
    out << items[i];
  }
  return out.str();
}

static void printActionState(const char *kind,const char *event,int4 result,
                             const Action &action,uint4 calls)
{
  std::cout << kind << "|event=" << event << "|return=" << result
            << "|status=" << action.status << "|count=" << action.count
            << "|lcount=" << action.lcount << "|tests=" << action.count_tests
            << "|applies=" << action.count_apply << "|bp=" << action.breakpoint
            << "|flags=" << action.flags << "|calls=" << calls << '\n';
}

static void runLeaf(Funcdata &fd)
{
  ScriptAction leaf(Action::rule_repeatapply,"leaf",
                    vector<Step>{Step(2,0),Step(0,0)});
  leaf.reset(fd);
  leaf.setWarning(true,"leaf");
  leaf.setBreakPoint(Action::break_start | Action::tmpbreak_start |
                     Action::break_action | Action::tmpbreak_action,"leaf");
  int4 result = leaf.perform(fd);
  printActionState("leaf","start_break",result,leaf,leaf.calls);
  result = leaf.perform(fd);
  printActionState("leaf","action_break",result,leaf,leaf.calls);
  result = leaf.perform(fd);
  printActionState("leaf","resume_complete",result,leaf,leaf.calls);
  result = leaf.perform(fd);
  printActionState("leaf","persistent_start",result,leaf,leaf.calls);
  leaf.reset(fd);
  printActionState("leaf","reset",999,leaf,leaf.calls);
  leaf.clearBreakPoints();
  result = leaf.perform(fd);
  printActionState("leaf","after_clear",result,leaf,leaf.calls);
}

static void runGroup(Funcdata &fd)
{
  vector<string> trace;
  ProbeGroup group(0,"group");
  ScriptAction *first = new ScriptAction(0,"first",vector<Step>{Step(1,0)},&trace);
  ScriptAction *second = new ScriptAction(0,"second",vector<Step>{Step(1,0)},&trace);
  group.addAction(first);
  group.addAction(second);
  group.reset(fd);
  group.setWarning(true,"group");
  group.setBreakPoint(Action::break_action,"group");
  for(int4 call=1;call<=4;++call) {
    size_t begin = trace.size();
    int4 result = group.perform(fd);
    vector<string> delta(trace.begin()+begin,trace.end());
    std::cout << "group|call=" << call << "|return=" << result
              << "|cursor=" << group.cursor() << "|trace=" << join(delta)
              << "|status=" << group.status << "|count=" << group.count
              << "|lcount=" << group.lcount << "|tests=" << group.count_tests
              << "|applies=" << group.count_apply << "|bp=" << group.breakpoint
              << "|child_calls=" << first->calls << ',' << second->calls << '\n';
  }

  ProbeGroup partial(0,"partial_group");
  ScriptAction *child = new ScriptAction(0,"partial",
                                         vector<Step>{Step(0,-7),Step(2,0)},&trace);
  partial.addAction(child);
  partial.reset(fd);
  size_t begin = trace.size();
  int4 first_result = partial.perform(fd);
  vector<string> first_delta(trace.begin()+begin,trace.end());
  std::cout << "group_partial|call=1|return=" << first_result
            << "|cursor=" << partial.cursor() << "|trace=" << join(first_delta)
            << "|child_calls=" << child->calls << '\n';
  begin = trace.size();
  int4 second_result = partial.perform(fd);
  vector<string> second_delta(trace.begin()+begin,trace.end());
  std::cout << "group_partial|call=2|return=" << second_result
            << "|cursor=" << partial.cursor() << "|trace=" << join(second_delta)
            << "|child_calls=" << child->calls << '\n';
}

static void runLookup(Funcdata &fd)
{
  (void)fd;
  ProbeGroup actions(0,"root");
  ProbeGroup *ambiguous = new ProbeGroup(0,"ambiguous");
  ambiguous->addAction(new ScriptAction(0,"dup",vector<Step>()));
  ambiguous->addAction(new ScriptAction(0,"dup",vector<Step>()));
  ProbeGroup *unique = new ProbeGroup(0,"unique");
  unique->addAction(new ScriptAction(0,"dup",vector<Step>()));
  actions.addAction(ambiguous);
  actions.addAction(unique);
  bool action_local = actions.setBreakPoint(Action::break_start,"dup");
  bool action_qualified = actions.setBreakPoint(Action::break_action,
                                                 "root:ambiguous:dup");
  ScriptAction *a0 = static_cast<ScriptAction *>(ambiguous->list[0]);
  ScriptAction *a1 = static_cast<ScriptAction *>(ambiguous->list[1]);
  ScriptAction *u0 = static_cast<ScriptAction *>(unique->list[0]);

  ProbeGroup rules(0,"rule_root");
  ActionPool *amb_pool = new ActionPool(0,"amb_pool");
  LookupRule *r0 = new LookupRule("same_rule");
  LookupRule *r1 = new LookupRule("same_rule");
  amb_pool->addRule(r0);
  amb_pool->addRule(r1);
  ActionPool *unique_pool = new ActionPool(0,"unique_pool");
  LookupRule *ru = new LookupRule("same_rule");
  unique_pool->addRule(ru);
  rules.addAction(amb_pool);
  rules.addAction(unique_pool);
  bool rule_local = rules.disableRule("same_rule");
  bool rule_qualified = rules.setBreakPoint(Action::break_action,
                                             "rule_root:amb_pool:same_rule");
  std::cout << "lookup|action_local=" << action_local
            << "|action_qualified=" << action_qualified
            << "|action_bp=" << a0->breakpoint << ',' << a1->breakpoint << ','
            << u0->breakpoint << "|rule_local=" << rule_local
            << "|rule_qualified=" << rule_qualified
            << "|rule_disabled=" << r0->isDisabled() << ',' << r1->isDisabled()
            << ',' << ru->isDisabled() << "|rule_bp=" << r0->getBreakPoint()
            << ',' << r1->getBreakPoint() << ',' << ru->getBreakPoint() << '\n';
}

struct LiveProbe {
  vector<string> trace;
  bool mutated;
  uint4 resets;
  LiveProbe() : mutated(false),resets(0) {}
};

class LiveRule final : public Rule {
public:
  enum Kind { MUTATE,AUDIT,DISABLED };
private:
  Kind kind;
  LiveProbe &probe;
public:
  LiveRule(const string &nm,Kind k,LiveProbe &p) : Rule("fixture",0,nm),kind(k),probe(p) {}
  Rule *clone(const ActionGroupList &) const override { return (Rule *)0; }
  void getOpList(vector<uint4> &out) const override { out.push_back(CPUI_COPY); }
  void reset(Funcdata &fd) override {
    probe.resets += 1;
    Rule::reset(fd);
  }
  int4 applyOp(PcodeOp *op,Funcdata &fd) override {
    std::ostringstream event;
    event << getName() << '@' << op->getAddr().getOffset();
    probe.trace.push_back(event.str());
    if (kind != MUTATE || probe.mutated || op->getAddr().getOffset() != 0x1000)
      return 0;
    probe.mutated = true;
    BlockBasic *block = op->getParent();
    AddrSpace *space = op->getAddr().getSpace();
    PcodeOp *low = fd.newOp(0,Address(space,0x900));
    fd.opSetOpcode(low,CPUI_COPY);
    fd.opInsertEnd(low,block);
    PcodeOp *high = fd.newOp(0,Address(space,0x2000));
    fd.opSetOpcode(high,CPUI_COPY);
    fd.opInsertEnd(high,block);
    fd.opDestroy(op);
    return 3;
  }
};

class ProbePool final : public ActionPool {
public:
  ProbePool(uint4 f,const string &nm) : ActionPool(f,nm) {
    count = 0;
    lcount = 0;
  }
  string cursor(Funcdata &fd) const {
    const PcodeOpTree::const_iterator &iter = fixtureGetOpState();
    if (iter == fd.endOpAll()) return "end";
    std::ostringstream out;
    out << (*iter).second->getAddr().getOffset() << '@' << (*iter).second->getTime();
    return out.str();
  }
  int4 ruleCursor(void) const { return fixtureGetRuleIndex(); }
};

static string treeState(Funcdata &fd)
{
  std::ostringstream out;
  bool first = true;
  for(PcodeOpTree::const_iterator iter=fd.beginOpAll();iter!=fd.endOpAll();++iter) {
    if (!first) out << ',';
    first = false;
    PcodeOp *op = (*iter).second;
    out << op->getAddr().getOffset() << '@' << op->getTime() << ':' << op->isDead();
  }
  return out.str();
}

static void printPoolEvent(const char *event,int4 result,ProbePool &pool,
                           Funcdata &fd,LiveProbe &probe,LiveRule *disabled,
                           LiveRule *mutate,LiveRule *audit,size_t trace_begin)
{
  vector<string> delta(probe.trace.begin()+trace_begin,probe.trace.end());
  std::cout << "pool|event=" << event << "|return=" << result
            << "|cursor=" << pool.cursor(fd) << "|rule_index=" << pool.ruleCursor()
            << "|trace=" << join(delta) << "|tree=" << treeState(fd)
            << "|status=" << pool.status << "|count=" << pool.count
            << "|lcount=" << pool.lcount << "|tests=" << pool.count_tests
            << "|applies=" << pool.count_apply << "|bp=" << pool.breakpoint
            << "|flags=" << pool.flags << "|rule_stats="
            << disabled->getNumTests() << '/' << disabled->getNumApply() << ','
            << mutate->getNumTests() << '/' << mutate->getNumApply() << ','
            << audit->getNumTests() << '/' << audit->getNumApply()
            << "|rule_bp=" << disabled->breakpoint << ',' << mutate->breakpoint
            << ',' << audit->breakpoint << "|rule_flags=" << disabled->flags
            << ',' << mutate->flags << ',' << audit->flags << '\n';
}

static void runPool(FixtureArchitecture &arch,Funcdata &fd)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);
  AddrSpace *ram = arch.getSpace(3);
  fd.setBasicBlockRange(block,Address(ram,0x800),Address(ram,0x4000));
  PcodeOp *initial_dead = fd.newOp(0,Address(ram,0x800));
  fd.opSetOpcode(initial_dead,CPUI_COPY);
  PcodeOp *root = fd.newOp(0,Address(ram,0x1000));
  fd.opSetOpcode(root,CPUI_COPY);
  fd.opInsertEnd(root,block);
  PcodeOp *tail = fd.newOp(0,Address(ram,0x3000));
  fd.opSetOpcode(tail,CPUI_COPY);
  fd.opInsertEnd(tail,block);

  LiveProbe probe;
  ProbePool pool(0,"live_pool");
  LiveRule *disabled = new LiveRule("disabled",LiveRule::DISABLED,probe);
  LiveRule *mutate = new LiveRule("mutate",LiveRule::MUTATE,probe);
  LiveRule *audit = new LiveRule("audit",LiveRule::AUDIT,probe);
  pool.addRule(disabled);
  pool.addRule(mutate);
  pool.addRule(audit);
  pool.disableRule("live_pool:disabled");
  pool.setWarning(true,"live_pool:mutate");
  pool.setBreakPoint(Action::break_start | Action::tmpbreak_start |
                     Action::break_action | Action::tmpbreak_action,
                     "live_pool:mutate");
  pool.setWarning(true,"live_pool");
  pool.setBreakPoint(Action::tmpbreak_action,"live_pool");
  pool.reset(fd);

  size_t begin = probe.trace.size();
  int4 result = pool.perform(fd);
  printPoolEvent("rule_break",result,pool,fd,probe,disabled,mutate,audit,begin);
  begin = probe.trace.size();
  result = pool.perform(fd);
  printPoolEvent("pool_break",result,pool,fd,probe,disabled,mutate,audit,begin);
  begin = probe.trace.size();
  result = pool.perform(fd);
  printPoolEvent("pool_resume",result,pool,fd,probe,disabled,mutate,audit,begin);
  begin = probe.trace.size();
  result = pool.perform(fd);
  printPoolEvent("fresh_pass",result,pool,fd,probe,disabled,mutate,audit,begin);
  pool.reset(fd);
  printPoolEvent("reset",999,pool,fd,probe,disabled,mutate,audit,probe.trace.size());
  pool.resetStats();
  printPoolEvent("reset_stats",999,pool,fd,probe,disabled,mutate,audit,
                 probe.trace.size());
}

struct ResetProbe {
  uint4 calls;
  uint4 resets;
  ResetProbe() : calls(0),resets(0) {}
};

class ResetRule final : public Rule {
  ResetProbe &probe;
  bool call_base;
public:
  ResetRule(const string &nm,ResetProbe &p,bool base)
    : Rule("fixture",0,nm),probe(p),call_base(base) {}
  Rule *clone(const ActionGroupList &) const override { return (Rule *)0; }
  void getOpList(vector<uint4> &out) const override { out.push_back(CPUI_COPY); }
  int4 applyOp(PcodeOp *,Funcdata &) override {
    probe.calls += 1;
    return 1;
  }
  void reset(Funcdata &fd) override {
    probe.resets += 1;
    if (call_base) Rule::reset(fd);
  }
};

static void runVirtualReset(FixtureArchitecture &arch)
{
  AddrSpace *ram = arch.getSpace(3);
  Funcdata fd("virtual_reset","virtual_reset",arch.symboltab->getGlobalScope(),
              Address(ram,0x5000),(FunctionSymbol *)0,0x20);
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);
  fd.setBasicBlockRange(block,Address(ram,0x5000),Address(ram,0x5000));
  PcodeOp *op = fd.newOp(0,Address(ram,0x5000));
  fd.opSetOpcode(op,CPUI_COPY);
  fd.opInsertEnd(op,block);

  ResetProbe base_probe;
  ResetProbe no_base_probe;
  ProbePool pool(0,"reset_pool");
  ResetRule *base = new ResetRule("base_reset",base_probe,true);
  ResetRule *no_base = new ResetRule("no_base_reset",no_base_probe,false);
  pool.addRule(base);
  pool.addRule(no_base);
  pool.setWarning(true,"base_reset");
  pool.setWarning(true,"no_base_reset");
  pool.perform(fd);
  std::cout << "virtual_reset|event=before|flags=" << base->flags << ','
            << no_base->flags << "|stats=" << base->getNumTests() << '/'
            << base->getNumApply() << ',' << no_base->getNumTests() << '/'
            << no_base->getNumApply() << "|calls=" << base_probe.calls << ','
            << no_base_probe.calls << "|resets=" << base_probe.resets << ','
            << no_base_probe.resets << '\n';
  pool.reset(fd);
  std::cout << "virtual_reset|event=after|flags=" << base->flags << ','
            << no_base->flags << "|stats=" << base->getNumTests() << '/'
            << base->getNumApply() << ',' << no_base->getNumTests() << '/'
            << no_base->getNumApply() << "|calls=" << base_probe.calls << ','
            << no_base_probe.calls << "|resets=" << base_probe.resets << ','
            << no_base_probe.resets << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  vector<string> spec_paths;
  startDecompilerLibrary(spec_paths);
  try {
    FixtureArchitecture arch;
    AddrSpace *ram = arch.getSpace(3);
    Funcdata fd("break_pool","break_pool",arch.symboltab->getGlobalScope(),
                Address(ram,0x800),(FunctionSymbol *)0,0x4000);
    std::cout << "schema=1|fixture=ACTION-EXECUTOR-BREAKPOOL-0001|oracle="
              << "e40ed13014025f82488b1f8f7bca566894ac376b\n";
    runLeaf(fd);
    runGroup(fd);
    runLookup(fd);
    runPool(arch,fd);
    runVirtualReset(arch);
  }
  catch(const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
