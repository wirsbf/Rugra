/*
 * ACTIONPOOL-CLONE-FILTER-0001: locked Ghidra 12.0.4 behavioral oracle.
 *
 * A synthetic registered "universal" ActionPool is derived through the real
 * ActionDatabase::setCurrent -> deriveAction -> ActionPool::clone path.  The
 * observation preserves allrules and perop order and exposes the inherited
 * Action/Rule runtime fields so fresh-clone versus copied-state behavior is
 * explicit.  Test-only access changes visibility only; production bodies are
 * linked unchanged from the locked libdecomp archive.
 */

#include <bits/stdc++.h>
#define class struct
#define private public
#define protected public
#include "action.hh"
#undef class
#undef private
#undef protected

using namespace ghidra;
using std::cout;
using std::runtime_error;

class ScriptRule final : public Rule {
  uint4 constructor_flags;
  string constructor_name;
  vector<uint4> opcodes;

public:
  ScriptRule(const string &group, uint4 flags, const string &name,
             const vector<uint4> &ops)
      : Rule(group, flags, name), constructor_flags(flags),
        constructor_name(name), opcodes(ops) {}

  Rule *clone(const ActionGroupList &grouplist) const override {
    if (!grouplist.contains(getGroup()))
      return (Rule *)0;
    return new ScriptRule(getGroup(), constructor_flags, constructor_name,
                          opcodes);
  }

  void getOpList(vector<uint4> &result) const override {
    result.insert(result.end(), opcodes.begin(), opcodes.end());
  }
};

static string opcode_name(uint4 opcode) {
  if (opcode == CPUI_COPY) return "copy";
  if (opcode == CPUI_INT_ADD) return "int_add";
  if (opcode == CPUI_INT_SUB) return "int_sub";
  return "unknown";
}

static ActionPool *build_source(void) {
  ActionPool *pool = new ActionPool(
      Action::rule_repeatapply | Action::rule_onceperfunc |
          Action::rule_warnings_given,
      "universal");
  pool->addRule(new ScriptRule("alpha", Rule::rule_debug, "a",
                               {CPUI_COPY, CPUI_INT_ADD}));
  pool->addRule(new ScriptRule("beta", 0, "b", {CPUI_INT_ADD}));
  pool->addRule(new ScriptRule("alpha", Rule::warnings_on, "c",
                               {CPUI_COPY}));
  pool->addRule(new ScriptRule("gamma", 0, "d",
                               {CPUI_INT_SUB, CPUI_COPY}));

  pool->status = Action::status_mid;
  pool->breakpoint = Action::break_start | Action::break_action;
  pool->count_tests = 17;
  pool->count_apply = 11;
  for (size_t i = 0; i < pool->allrules.size(); ++i) {
    Rule *rule = pool->allrules[i];
    rule->flags |= Rule::type_disable | Rule::warnings_on |
                   Rule::warnings_given;
    rule->breakpoint = (uint4)(9 + i);
    rule->count_tests = (uint4)(30 + i);
    rule->count_apply = (uint4)(20 + i);
  }
  return pool;
}

static void emit_pool(const string &case_name, Action *action) {
  if (action == (Action *)0) {
    cout << "case=" << case_name << " null=1\n";
    return;
  }
  ActionPool *pool = dynamic_cast<ActionPool *>(action);
  if (pool == (ActionPool *)0)
    throw runtime_error("derived action is not ActionPool");

  cout << "case=" << case_name << " null=0 name=" << pool->getName()
       << " flags=" << pool->flags << " status=" << pool->status
       << " breakpoint=" << pool->breakpoint
       << " tests=" << pool->count_tests << " apply=" << pool->count_apply
       << " rules=" << pool->allrules.size() << '\n';
  for (size_t i = 0; i < pool->allrules.size(); ++i) {
    Rule *rule = pool->allrules[i];
    vector<uint4> ops;
    rule->getOpList(ops);
    cout << "rule=" << case_name << ':' << i << " name=" << rule->getName()
         << " group=" << rule->getGroup() << " flags=" << rule->flags
         << " breakpoint=" << rule->breakpoint
         << " tests=" << rule->count_tests << " apply=" << rule->count_apply
         << " opcodes=";
    for (size_t j = 0; j < ops.size(); ++j) {
      if (j != 0) cout << ',';
      cout << opcode_name(ops[j]);
    }
    cout << '\n';
  }
  const uint4 observed[] = {CPUI_COPY, CPUI_INT_ADD, CPUI_INT_SUB};
  for (uint4 opcode : observed) {
    cout << "perop=" << case_name << ':' << opcode_name(opcode) << " rules=";
    const vector<Rule *> &rules = pool->perop[opcode];
    for (size_t i = 0; i < rules.size(); ++i) {
      if (i != 0) cout << ',';
      cout << rules[i]->getName();
    }
    cout << '\n';
  }
}

static void derive_and_emit(ActionDatabase &database, const string &name) {
  size_t before = database.actionmap.size();
  Action *first = database.setCurrent(name);
  size_t after_first = database.actionmap.size();
  Action *second = database.setCurrent(name);
  size_t after_second = database.actionmap.size();
  bool entry = database.actionmap.find(name) != database.actionmap.end();
  bool cached = first == second && after_first == after_second &&
                after_first == before + 1;
  cout << "derive=" << name << " entry=" << (entry ? 1 : 0)
       << " cached=" << (cached ? 1 : 0)
       << " current=" << database.getCurrentName() << '\n';
  emit_pool(name, first);
}

int main(void) {
  ActionDatabase database;
  ActionPool *source = build_source();
  emit_pool("source", source);
  database.registerAction("universal", source);

  const char *all[] = {"alpha", "beta", "gamma", (const char *)0};
  const char *custom[] = {"alpha", "gamma", (const char *)0};
  const char *empty[] = {(const char *)0};
  database.setGroup("all", all);
  database.setGroup("custom", custom);
  database.setGroup("empty", empty);

  derive_and_emit(database, "all");
  derive_and_emit(database, "custom");
  derive_and_emit(database, "empty");
  return 0;
}
