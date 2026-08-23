/*
 * PIPE-DERIVED-TREE-0001: locked Ghidra 12.0.4 derived default pipeline
 * tree oracle (action.cc:986 resetDefaults / action.hh:313 getCurrent).
 *
 * The fixture drives the production derivation exactly: it builds the raw
 * universal Action tree through ActionDatabase::universalAction
 * (coreaction.cc:5462, invoked by Architecture::buildAction at
 * architecture.cc:589), then calls ActionDatabase::resetDefaults
 * (action.cc:986) which rebuilds the default grouplists
 * (coreaction.cc:5419 buildDefaultGroups) and derives the "decompile"
 * root via setCurrent -> deriveAction -> Action::clone with the decompile
 * grouplist (coreaction.cc:5424-5432).  The derived root returned by
 * getCurrent() is then walked depth-first (pre-order) and every node is
 * printed with its ':'-joined tree path, global DFS ordinal, kind
 * (group for ActionGroup/ActionRestartGroup, pool for ActionPool, leaf
 * otherwise), exact getName(), getGroup() basegroup and rule flags.
 * Duplicate names at distinct slots (unreachable/directwrite/deadcode/
 * dynamicsymbols) are kept verbatim; no sorting or deduplication.
 *
 * The observation pins the derive filtering itself: the raw head's
 * normalanalysis NormalizeSetup (:5479) and noproto FuncLinkOutOnly
 * (:5485), both protorecovery_b DirectWrite instances (:5498/:5681) and
 * the normalizebranches NormalizeBranches (:5716) must be absent from the
 * derived decompile tree, whose root key is "decompile" while the root
 * node keeps its cloned name "universal" (ActionRestartGroup::clone
 * preserves getName(), action.cc:529-544).
 */

#include <bits/stdc++.h>

// Test-only access is required to read the Action rule flags member
// (protected) matching what production reaches through the console API.
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

// Pre-order DFS over the derived tree.  `path` is the ':'-joined ancestor
// chain (the same addressing Action::getSubAction splits, action.cc:265-282),
// `ordinal` is the global pre-order counter started at 0 for the root.
static void dfs(Action *node, const std::string &path, int4 &ordinal)
{
  const std::string &nm = node->getName();
  std::string nodepath = path.empty() ? nm : path + ":" + nm;
  const char *kind = "leaf";
  ActionGroup *group = (ActionGroup *)0;
  if ((dynamic_cast<ActionRestartGroup *>(node) != (ActionRestartGroup *)0) ||
      (dynamic_cast<ActionGroup *>(node) != (ActionGroup *)0)) {
    kind = "group";
    group = (ActionGroup *)node;
  }
  else if (dynamic_cast<ActionPool *>(node) != (ActionPool *)0) {
    kind = "pool";
  }
  std::cout << "node|ordinal=" << ordinal
            << "|path=" << nodepath
            << "|kind=" << kind
            << "|name=" << nm
            << "|basegroup=" << node->getGroup()
            << "|flags=" << node->flags << '\n';
  ordinal += 1;
  if (group != (ActionGroup *)0) {
    for (std::vector<Action *>::const_iterator iter = group->list.begin();
         iter != group->list.end(); ++iter)
      dfs(*iter, nodepath, ordinal);
  }
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=PIPE-DERIVED-TREE-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;

    // Production derivation path (Architecture::buildAction,
    // architecture.cc:582-591): raw universal tree, then the default
    // derive (keeps the registered universal root, rebuilds the default
    // grouplists, setCurrent("decompile") -> clone-filtered root).
    arch.allacts.universalAction(&arch);  // coreaction.cc:5462
    arch.allacts.resetDefaults();         // action.cc:986
    Action *root = arch.allacts.getCurrent();  // action.hh:313

    // Root key vs root node name: the database registers the derived root
    // under "decompile", while the cloned ActionRestartGroup keeps the
    // universal node name (action.cc:529-544).
    std::cout << "root_key=" << arch.allacts.getCurrentName() << '\n';
    std::cout << "root_name=" << root->getName() << '\n';
    std::cout << "root_flags=" << root->flags << '\n';

    int4 ordinal = 0;
    dfs(root, "", ordinal);
    std::cout << "count=" << ordinal << '\n';
  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
    return 1;
  }
  return 0;
}
