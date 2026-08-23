/*
 * PIPE-POOL-LOCAL-RULES-0001: locked Ghidra 12.0.4 pool registration purity
 * oracle (coreaction.cc:5511-5649 oppool1 / :5662-5670 oppool2 /
 * :5694-5710 actcleanup).
 *
 * The fixture drives the production registration exactly, through PUBLIC
 * API only (no test-only access manipulation is needed beyond the
 * ActionGroup child list, which lives behind an explicit `protected:`):
 *   1. ActionDatabase::universalAction (coreaction.cc:5462) builds and
 *      registers the raw universal tree; resetDefaults (action.cc:986)
 *      rebuilds the default grouplists and derives the "decompile" root
 *      (getCurrent, action.hh:313) — the production pipeline.
 *   2. setGroup("all", ...) with the union of every group string used by
 *      buildDefaultGroups' six root definitions (coreaction.cc:5424-5456,
 *      verbatim) followed by setCurrent("all") derives a second root whose
 *      clone keeps EVERY registered child (each Action::clone/Rule::clone
 *      survives iff its group is in the grouplist; the union contains all
 *      of them).  ActionPool::clone appends surviving rules in
 *      allrules order (action.cc:899-914), so this root exposes the full
 *      registration sequence of each pool — the registration site this
 *      fixture pins.
 *
 * Each root is walked depth-first (pre-order) over the ActionGroup child
 * lists; every ActionPool node prints one "pool" line with its ':'-joined
 * tree path, name and rule count, followed by one "rule" line per rule in
 * REGISTRATION ORDER with pool name, registration index and the rule's
 * diagnostic name.  The per-pool rule names are read through the PUBLIC
 * virtual ActionPool::print (action.cc:753-775), the same listing the
 * console's printActionList surfaces: print iterates allrules in order
 * (action.cc:763) and emits one line per rule whose final whitespace-
 * delimited token is the rule name.  Names are normalized by deleting '_'
 * (Rugra rule names use snake_case while the oracle mostly does not, e.g.
 * "trivialarith" vs "trivial_arith"; the underscore-free projection is
 * injective on both sides' name sets, verified when this fixture was
 * authored).  No sorting, no deduplication: the sequence itself is the
 * observable.
 *
 * The observation pins pool membership purity: oppool1 is exactly the
 * coreaction.cc:5512-5646 registrations (the extra_pool_rules loop at
 * :5647-5649 absorbs zero CPU-specific rules for this fixture
 * Architecture), oppool2 the 5 registrations at :5664-5669, and cleanup
 * the 15 registrations at :5696-5710 — with no "sexteliminate" (class
 * does not exist anywhere in the locked tree), no "equality" (class
 * ruleaction.hh:243 is never instantiated) and no "trivialarith" outside
 * oppool1.
 */

#include <bits/stdc++.h>

// Test-only access is required to read the protected ActionGroup::list
// child vector (explicit `protected:` label, action.hh:144-145) — the same
// access the pipeline_tree_1204 fixture uses for its DFS.
#define private public
#define protected public
#include "architecture.hh"
#include "coreaction.hh"
#include "cover.hh"
#include "database.hh"
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
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1, 6,
                              AddrSpace::hasphysical, 0, 0));
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

// Underscore-free normalization of a rule's diagnostic name.  Injective on
// both sides' full name sets (verified at fixture authoring time); used
// because Rugra names rules in snake_case while the oracle mostly does not.
static std::string normalize_name(const std::string &nm)
{
  std::string out;
  for (char c : nm)
    if (c != '_')
      out.push_back(c);
  return out;
}

// Extract a pool's full rule registration sequence through the PUBLIC
// virtual ActionPool::print (action.cc:753-775).  The first emitted line is
// the pool's own Action::print header (action.cc:132-144); every following
// line is one rule, whose final whitespace-delimited token is the rule's
// diagnostic name.  Fresh rules print no 'D'/'A' flag characters.
static std::vector<std::string> pool_rule_names(const ActionPool *pool)
{
  std::stringstream capture;
  pool->print(capture, 0, 0);
  std::vector<std::string> names;
  std::string line;
  bool first = true;
  while (std::getline(capture, line)) {
    if (first) { // pool header line from Action::print
      first = false;
      continue;
    }
    std::string token;
    std::istringstream tokens(line);
    std::string last;
    while (tokens >> token)
      last = token;
    if (!last.empty())
      names.push_back(last);
  }
  return names;
}

// Pre-order DFS over the tree; every ActionPool prints its full rule
// registration sequence.  `path` is the ':'-joined ancestor chain (the same
// addressing Action::getSubAction splits, action.cc:265-282).
static void dfs(Action *node, const std::string &path)
{
  const std::string &nm = node->getName();
  std::string nodepath = path.empty() ? nm : path + ":" + nm;
  if (dynamic_cast<ActionPool *>(node) != (ActionPool *)0) {
    ActionPool *pool = (ActionPool *)node;
    std::vector<std::string> names = pool_rule_names(pool);
    std::cout << "pool|path=" << nodepath
              << "|name=" << nm
              << "|count=" << names.size() << '\n';
    for (int4 i = 0; i < (int4)names.size(); ++i)
      std::cout << "rule|pool=" << nm
                << "|index=" << i
                << "|name=" << normalize_name(names[i]) << '\n';
    return;
  }
  ActionGroup *group = dynamic_cast<ActionGroup *>(node);
  if (group != (ActionGroup *)0) {
    for (std::vector<Action *>::const_iterator iter = group->list.begin();
         iter != group->list.end(); ++iter)
      dfs(*iter, nodepath);
  }
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=PIPE-POOL-LOCAL-RULES-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;

    // Production registration path (Architecture::buildAction,
    // architecture.cc:582-591): raw universal tree, then the default
    // derive (rebuilds default grouplists, setCurrent("decompile") ->
    // clone-filtered root).
    arch.allacts.universalAction(&arch);  // coreaction.cc:5462
    arch.allacts.resetDefaults();         // action.cc:986
    Action *decompile_root = arch.allacts.getCurrent();

    // Full-union derive: setGroup("all") with every group string of the
    // six buildDefaultGroups member arrays (coreaction.cc:5424-5456,
    // verbatim union, "" terminator per setGroup contract action.cc:1059),
    // then setCurrent("all") clones the raw universal tree keeping every
    // child (ActionPool::clone preserves allrules order, action.cc:899-914).
    const char *all_groups[] = {
      "base", "protorecovery", "protorecovery_a", "protorecovery_b",
      "deindirect", "localrecovery", "deadcode", "typerecovery",
      "stackptrflow", "blockrecovery", "stackvars", "deadcontrolflow",
      "switchnorm", "cleanup", "splitcopy", "splitpointer", "merge",
      "dynamic", "casts", "analysis", "fixateglobals", "fixateproto",
      "constsequence", "segment", "returnsplit", "nodejoin", "doubleload",
      "doubleprecis", "unreachable", "subvar", "floatprecision",
      "conditionalexe", "noproto", "normalizebranches", "normalanalysis",
      "siganalysis", "" };
    arch.allacts.setGroup("all", all_groups);
    arch.allacts.setCurrent("all");

    // Root 1: the union derive of the raw universal tree — the
    // registration site (clone keeps every child, order preserved).
    std::cout << "root=all\n";
    dfs(arch.allacts.getCurrent(), "");

    // Root 2: the derived decompile root — the production pipeline that
    // actually runs; its clone keeps every rule of these pools because the
    // decompile grouplist contains all their groups.
    std::cout << "root=decompile\n";
    dfs(decompile_root, "");
  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
    return 1;
  }
  return 0;
}
