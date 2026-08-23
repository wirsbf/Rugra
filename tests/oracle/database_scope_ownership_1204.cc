/*
 * Locked Ghidra 12.0.4 oracle for DATABASE-SCOPE-OWNERSHIP-FIXTURE-0001.
 *
 * The fixture exercises the real ownership graph built by
 * Architecture::buildDatabase (architecture.cc:597-604), then follows the
 * production namespace -> FunctionSymbol -> Funcdata -> ScopeLocal chain:
 *
 *   Database::attachScope             database.cc:2946-2971
 *   Database::findCreateScope         database.cc:3078-3087
 *   Scope::addFunction                database.cc:1615-1631
 *   FunctionSymbol::getFunction       database.cc:557-564
 *   Funcdata::Funcdata                funcdata.cc:34-82
 *   ScopeLocal::ScopeLocal            varmap.cc:341-351
 *
 * Pointer values are never printed.  Each pointer relationship is projected
 * as an alias class (same/different/null).  Expected failures record both the
 * exact exception category/text and the state left behind.  The final probe
 * observes destructor order without modifying Ghidra: ScopeInternal deletes
 * its FunctionSymbol set before Scope deletes the remaining child scopes, so
 * a sentinel child's destructor must see the function ScopeLocal already
 * detached (database.cc:1962-1975, 1182-1190; FunctionSymbol::~FunctionSymbol
 * at 552-555; Funcdata::~Funcdata at funcdata.cc:190-201).
 */

#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::string;
using std::vector;

int4 childCount(const Scope *scope)
{
  int4 count = 0;
  ScopeMap::const_iterator iter = scope->childrenBegin();
  ScopeMap::const_iterator enditer = scope->childrenEnd();
  for (; iter != enditer; ++iter)
    ++count;
  return count;
}

string joinEvents(const vector<string> &events)
{
  if (events.empty())
    return "none";
  std::ostringstream out;
  for (size_t i = 0; i < events.size(); ++i) {
    if (i != 0)
      out << '>';
    out << events[i];
  }
  return out.str();
}

/// Scope whose destructor writes only semantic state to an external recorder.
/// The optional lookup is evaluated while its parent Scope is still alive.
class ProbeScope : public ScopeInternal {
  vector<string> *events;
  string label;
  string localName;
public:
  ProbeScope(uint8 id,const string &nm,Architecture *arch,
             vector<string> *eventLog,const string &eventLabel,
             const string &observedLocalName=string())
    : ScopeInternal(id,nm,arch), events(eventLog), label(eventLabel),
      localName(observedLocalName) {}

  virtual ~ProbeScope(void)
  {
    string event = "dtor:" + label;
    if (!localName.empty()) {
      Scope *parent = getParent();
      bool present = parent != (Scope *)0 &&
          parent->resolveScope(localName,false) != (Scope *)0;
      event += present ? ":local_present=1" : ":local_present=0";
    }
    events->push_back(event);
  }
};

/// Exposes the protected virtual factory only by overriding it and calling the
/// locked production body.  init() invokes this override exactly where the
/// normal BfdArchitecture invokes Architecture::buildDatabase.
class FixtureArchitecture : public BfdArchitecture {
public:
  int4 buildCalls;
  Scope *buildResult;
  bool resultIsRegisteredGlobal;
  bool databaseBackref;
  bool globalBackref;

  FixtureArchitecture(const string &filename,const string &target,
                      std::ostream *estream)
    : BfdArchitecture(filename,target,estream), buildCalls(0),
      buildResult((Scope *)0), resultIsRegisteredGlobal(false),
      databaseBackref(false), globalBackref(false) {}

protected:
  virtual Scope *buildDatabase(DocumentStorage &store)
  {
    ++buildCalls;
    buildResult = Architecture::buildDatabase(store);
    resultIsRegisteredGlobal =
        symboltab != (Database *)0 &&
        buildResult == symboltab->getGlobalScope();
    databaseBackref = symboltab != (Database *)0 &&
        symboltab->getArch() == (Architecture *)this;
    globalBackref = buildResult != (Scope *)0 &&
        buildResult->getArch() == (Architecture *)this;
    return buildResult;
  }
};

void emitBuildDatabase(const FixtureArchitecture &arch)
{
  Scope *global = arch.buildResult;
  std::cout
      << "case=build_database"
      << "|calls=" << arch.buildCalls
      << "|result_global_alias=" << arch.resultIsRegisteredGlobal
      << "|database_arch_alias=" << arch.databaseBackref
      << "|global_arch_alias=" << arch.globalBackref
      << "|global_id=" << global->getId()
      << "|global_name_empty=" << global->getName().empty()
      << "|global_parent_null=" << (global->getParent() == (Scope *)0)
      << "|global_is_global=" << global->isGlobal()
      << '\n';
}

void runGraphAndFailures(FixtureArchitecture &arch,vector<string> &events)
{
  Database *db = arch.symboltab;
  Scope *global = db->getGlobalScope();
  AddrSpace *ram = arch.getDefaultCodeSpace();

  const uint8 factoryId = 0x12040002;
  Scope *factoryScope = db->findCreateScope(
      factoryId,"factory_ns",global);
  Scope *factoryAgain = db->findCreateScope(
      factoryId,"ignored_name",global);
  std::cout
      << "case=find_create_scope"
      << "|id_matches=" << (factoryScope->getId() == factoryId)
      << "|resolver_key_present=" <<
          (db->resolveScope(factoryId) != (Scope *)0)
      << "|repeat_key_same=" << (factoryAgain->getId() == factoryId)
      << "|name_preserved=" <<
          (factoryAgain->getName() == "factory_ns")
      << "|parent_id=" << factoryAgain->getParent()->getId()
      << "|parent_child_key_resolves=" <<
          (global->resolveScope("factory_ns",false) != (Scope *)0)
      << "|parent_child_count=" << childCount(global)
      << "|return_class=scope_pointer"
      << "|resolver_return_alias=" <<
          (db->resolveScope(factoryId) == factoryScope)
      << "|repeat_return_alias=" << (factoryAgain == factoryScope)
      << "|parent_child_return_alias=" <<
          (global->resolveScope("factory_ns",false) == factoryScope)
      << "|resolved_slot_stable=UNNEEDED"
      << "|parent_child_resolved_slot_alias=UNNEEDED"
      << "|scope_storage_class=owned_pointer"
      << "|parent_child_storage_class=scope_pointer"
      << "|next_scope_id_before=UNAVAILABLE"
      << "|next_scope_id_after_create=UNAVAILABLE"
      << "|next_scope_id_after_repeat=UNAVAILABLE"
      << '\n';

  const uint8 namespaceId = 0x12040001;
  ProbeScope *nameSpace = new ProbeScope(
      namespaceId,"fixture_ns",&arch,&events,"fixture_ns");
  db->attachScope(nameSpace,global);
  std::cout
      << "case=namespace_attach"
      << "|resolver_alias=" << (db->resolveScope(namespaceId) == nameSpace)
      << "|parent_alias=" << (nameSpace->getParent() == global)
      << "|arch_alias=" << (nameSpace->getArch() == (Architecture *)&arch)
      << "|is_global=" << nameSpace->isGlobal()
      << "|global_children=" << childCount(global)
      << '\n';

  const Address functionAddress(ram,0x7e120400);
  FunctionSymbol *functionSymbol =
      nameSpace->addFunction(functionAddress,"fixture_function");
  Funcdata *fd = functionSymbol->getFunction();
  Funcdata *fdAgain = functionSymbol->getFunction();
  ScopeLocal *local = fd->getScopeLocal();
  const uint8 localId = local->getId();
  std::cout
      << "case=function_graph"
      << "|symbol_scope_alias=" <<
          (functionSymbol->getScope() == nameSpace)
      << "|function_cached_alias=" << (fd == fdAgain)
      << "|function_symbol_backref=" <<
          (fd->getSymbol() == functionSymbol)
      << "|function_arch_alias=" <<
          (fd->getArch() == (Architecture *)&arch)
      << "|local_resolver_alias=" <<
          (db->resolveScope(localId) == local)
      << "|local_parent_alias=" << (local->getParent() == nameSpace)
      << "|local_arch_alias=" <<
          (local->getArch() == (Architecture *)&arch)
      << "|local_backref_class=" << (local->isGlobal() ? "global" : "function")
      << "|local_name_matches=" << (local->getName() == fd->getName())
      << "|namespace_children=" << childCount(nameSpace)
      << '\n';

  events.clear();
  string duplicateCategory = "none";
  string duplicateMessage = "none";
  ProbeScope *duplicate = new ProbeScope(
      namespaceId,"duplicate_scope",&arch,&events,"duplicate_scope");
  try {
    db->attachScope(duplicate,global);
  }
  catch (const RecovError &error) {
    duplicateCategory = "RecovError";
    duplicateMessage = error.explain;
  }
  std::cout
      << "case=duplicate_id"
      << "|exception=" << duplicateCategory
      << "|message=" << duplicateMessage
      << "|incoming_events=" << joinEvents(events)
      << "|original_resolver_alias=" <<
          (db->resolveScope(namespaceId) == nameSpace)
      << "|original_parent_alias=" << (nameSpace->getParent() == global)
      << "|global_children=" << childCount(global)
      << '\n';

  events.clear();
  {
    Database isolated(&arch,true);
    ProbeScope *badGlobal = new ProbeScope(
        0,"invalid_global",&arch,&events,"invalid_global");
    string category = "none";
    string message = "none";
    try {
      isolated.attachScope(badGlobal,(Scope *)0);
    }
    catch (const LowlevelError &error) {
      category = "LowlevelError";
      message = error.explain;
    }
    std::cout
        << "case=invalid_global_name"
        << "|exception=" << category
        << "|message=" << message
        << "|global_still_null=" <<
            (isolated.getGlobalScope() == (Scope *)0)
        << "|events_before_caller_delete=" << joinEvents(events);
    delete badGlobal;
    std::cout << "|events_after_caller_delete=" << joinEvents(events) << '\n';
  }

  events.clear();
  const int4 childrenBeforeRemove = childCount(nameSpace);
  nameSpace->removeSymbol(functionSymbol);
  std::cout
      << "case=function_destroy"
      << "|children_before=" << childrenBeforeRemove
      << "|local_resolver_gone=" <<
          (db->resolveScope(localId) == (Scope *)0)
      << "|local_child_gone=" << (childCount(nameSpace) == 0)
      << "|function_mapping_gone=" <<
          (nameSpace->findFunction(functionAddress) == (Funcdata *)0)
      << "|probe_events=" << joinEvents(events)
      << '\n';

  db->deleteScope(nameSpace);
  std::cout
      << "case=namespace_destroy"
      << "|resolver_gone=" <<
          (db->resolveScope(namespaceId) == (Scope *)0)
      << "|events=" << joinEvents(events)
      << "|global_children=" << childCount(global)
      << '\n';
}

void installExitOrderGraph(FixtureArchitecture &arch,vector<string> &events)
{
  Database *db = arch.symboltab;
  Scope *global = db->getGlobalScope();
  AddrSpace *ram = arch.getDefaultCodeSpace();
  ProbeScope *nameSpace = new ProbeScope(
      0x12040010,"exit_ns",&arch,&events,"exit_ns");
  db->attachScope(nameSpace,global);
  FunctionSymbol *functionSymbol = nameSpace->addFunction(
      Address(ram,0x7e120500),"exit_function");
  Funcdata *fd = functionSymbol->getFunction();
  ScopeLocal *local = fd->getScopeLocal();
  ProbeScope *sentinel = new ProbeScope(
      0x12040011,"sentinel",&arch,&events,"sentinel",
      local->getName());
  db->attachScope(sentinel,nameSpace);
  std::cout
      << "case=exit_prestate"
      << "|local_resolver_alias=" <<
          (db->resolveScope(local->getId()) == local)
      << "|local_parent_alias=" << (local->getParent() == nameSpace)
      << "|sentinel_parent_alias=" << (sentinel->getParent() == nameSpace)
      << "|namespace_children=" << childCount(nameSpace)
      << '\n';
}

void run(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  vector<string> exitEvents;
  {
    std::ostringstream diagnostics;
    FixtureArchitecture architecture(binary,"default",&diagnostics);
    DocumentStorage store;
    architecture.init(store);
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " +
                               architecture.archid);
    emitBuildDatabase(architecture);
    runGraphAndFailures(architecture,exitEvents);
    exitEvents.clear();
    installExitOrderGraph(architecture,exitEvents);
  }
  std::cout << "case=architecture_destroy|events="
            << joinEvents(exitEvents) << '\n';
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: database_scope_ownership_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1],argv[2]);
    return 0;
  }
  catch (const RecovError &error) {
    std::cerr << "database_scope_ownership_1204: RecovError: "
              << error.explain << '\n';
    return 1;
  }
  catch (const LowlevelError &error) {
    std::cerr << "database_scope_ownership_1204: LowlevelError: "
              << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "database_scope_ownership_1204: " << error.what() << '\n';
    return 1;
  }
}
