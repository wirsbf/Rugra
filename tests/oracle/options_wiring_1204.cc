/*
 * OPTIONS-SPLITDATATYPE-WIRING-0002: locked Ghidra 12.0.4 behavioral oracle
 * for ActionDatabase::toggleAction (action.cc:1036-1053) driven through the
 * real OptionSplitDatatypes::apply forwarding (options.cc:1007-1016).
 *
 * The fixture builds a synthetic universal root (head leaves in "base", a
 * nested "body" group holding the "splitcopy"/"splitpointer"/"merge" leaves),
 * registers it through the production ActionDatabase, derives the "decompile"
 * root via setCurrent, then runs the production OptionSplitDatatypes option
 * over parameter triples covering: full-off, struct-only (splitpointer
 * removed), struct+pointer, re-assertion of an identical configuration
 * (toggleAction still replaces the root object), a p1 LowlevelError (no
 * mutation at all), a p2 LowlevelError (partial configuration assignment,
 * toggle block never reached), and an array-only re-enable.  Production
 * bodies are linked unchanged from the locked libdecomp archive; the
 * private/protected visibility macros only enable state observation, and a
 * minimal Architecture subclass stubs the pure virtuals that the option
 * path never calls.
 */

#include <bits/stdc++.h>
#define class struct
#define private public
#define protected public
#include "architecture.hh"
#include "options.hh"
#undef class
#undef private
#undef protected

using namespace ghidra;
using std::cout;
using std::runtime_error;

// The inherited flags word carries this leaf's construction ordinal (a
// monotonically increasing counter) solely as an allocator-independent
// identity channel: every clone is freshly constructed, so the ordinal
// changes exactly when the owning root was re-derived/replaced.
static int next_script_ordinal = 100;

class ScriptAction final : public Action {
public:
  ScriptAction(const string &g, const string &nm)
      : Action((uint4)next_script_ordinal++, nm, g) {}

  Action *clone(const ActionGroupList &grouplist) const override {
    if (!grouplist.contains(getGroup()))
      return (Action *)0;
    return new ScriptAction(getGroup(), getName());
  }

  int4 apply(Funcdata &) override { return 0; }
};

class TestArch : public Architecture {
public:
  TestArch(void) : Architecture() {}
  virtual ~TestArch(void) {}

  void printMessage(const string &message) const override {
    (void)message;
  }
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
};

static string render_group_children(const ActionGroup *grp) {
  string out;
  for (size_t i = 0; i < grp->list.size(); ++i) {
    if (i != 0)
      out += ',';
    const ActionGroup *sub = dynamic_cast<const ActionGroup *>(grp->list[i]);
    if (sub != (const ActionGroup *)0) {
      out += sub->getName();
      out += '[';
      out += render_group_children(sub);
      out += ']';
    } else {
      out += grp->list[i]->getName();
      out += '@';
      out += grp->list[i]->getGroup();
    }
  }
  return out;
}

static void emit_state(TestArch &arch, const string &tag) {
  const ActionDatabase &db = arch.allacts;
  const ActionGroupList &grp = db.getGroup("decompile");
  string members;
  for (set<string>::const_iterator it = grp.list.begin();
       it != grp.list.end(); ++it) {
    if (it != grp.list.begin())
      members += ',';
    members += *it;
  }
  const ActionGroup *root =
      dynamic_cast<const ActionGroup *>(db.getCurrent());
  if (root == (const ActionGroup *)0)
    throw runtime_error("current root is not an ActionGroup");
  cout << "state=" << tag << " config=" << arch.split_datatype_config
       << " current=" << db.getCurrentName() << " mapsize="
       << db.actionmap.size() << " members=" << members
       << " tree=" << render_group_children(root) << '\n';
}

static int first_leaf_ordinal(const Action *root) {
  const ActionGroup *grp = dynamic_cast<const ActionGroup *>(root);
  if (grp == (const ActionGroup *)0 || grp->list.empty())
    throw runtime_error("root is not a non-empty ActionGroup");
  return (int)grp->list[0]->flags;
}

int main(void) {
  // ghidra_process.cc:523 registers the linked capabilities (the C print
  // language) before any Architecture construction.
  CapabilityPoint::initializeAll();

  TestArch arch;

  // Synthetic universal root: head leaves + nested body group holding the
  // split-relevant leaves at their registration slots.
  ActionRestartGroup *universal =
      new ActionRestartGroup(Action::rule_onceperfunc, "universal", 1);
  universal->addAction(new ScriptAction("base", "start"));
  universal->addAction(new ScriptAction("base", "stop"));
  {
    ActionGroup *body = new ActionGroup(0, "body");
    body->addAction(new ScriptAction("splitcopy", "splitcopy"));
    body->addAction(new ScriptAction("splitpointer", "splitpointer"));
    body->addAction(new ScriptAction("merge", "merge"));
    universal->addAction(body);
  }
  arch.allacts.registerAction("universal", universal);

  const char *decompile_members[] = {"base", "splitcopy", "splitpointer",
                                     "merge", (const char *)0};
  arch.allacts.setGroup("decompile", decompile_members);
  arch.allacts.setCurrent("decompile");
  emit_state(arch, "init");

  struct Case {
    const char *p1;
    const char *p2;
    const char *p3;
  };
  const Case cases[] = {
      {"", "", ""},
      {"struct", "", ""},
      {"struct", "", "pointer"},
      {"array", "struct", "pointer"},
      {"array", "struct", "pointer"},
      {"bogus", "", ""},
      {"struct", "bogus", ""},
      {"", "array", ""},
  };

  OptionSplitDatatypes option;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    const int universal_before =
        first_leaf_ordinal(arch.allacts.getAction("universal"));
    const int root_before = first_leaf_ordinal(arch.allacts.getCurrent());

    bool threw = false;
    string result;
    try {
      result = option.apply(&arch, cases[i].p1, cases[i].p2, cases[i].p3);
    } catch (const LowlevelError &e) {
      threw = true;
      result = e.explain;
    }

    cout << "apply=" << i << " args=" << cases[i].p1 << '|' << cases[i].p2
         << '|' << cases[i].p3 << " threw=" << (threw ? 1 : 0)
         << " result=" << result << " config=" << arch.split_datatype_config
         << '\n';
    emit_state(arch, to_string(i));

    const int universal_after =
        first_leaf_ordinal(arch.allacts.getAction("universal"));
    const int root_after = first_leaf_ordinal(arch.allacts.getCurrent());
    cout << "identity=" << i << " universal_changed="
         << (universal_before != universal_after ? 1 : 0) << " root_changed="
         << (root_before != root_after ? 1 : 0)
         << " universal_firstid=" << universal_after
         << " root_firstid=" << root_after << '\n';
  }
  return 0;
}
