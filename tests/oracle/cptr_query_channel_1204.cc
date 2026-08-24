/*
 * B3-COREACTION-CONSTANTPTR-0001 (a1): locked Ghidra 12.0.4 oracle
 * projection for the Funcdata symbol query channel — the container /
 * property / name queries ActionConstantPtr and linkSymbolReference issue
 * through the local scope's parent (the global scope).
 *
 * Observed call-site forms:
 *   qc_*    data.getScopeLocal()->getParent()->queryContainer(rampoint,1,
 *           Address())  — the exact ActionConstantPtr::isPointer form
 *           (coreaction.cc:1151) and the linkSymbolReference form
 *           (funcdata_varnode.cc:1207, scope = the ram spacebase's map).
 *   ro_*    Scope::isReadOnly(addr,1,Address()) over queryProperties
 *           (database.cc:1796/:1263) — the RulePtrsubCharConstant
 *           (ruleaction.cc:7372) and PrintC::pushPtrCharConstant
 *           (printc.cc:1709) consumer form; the readonly bit flows from
 *           Symbol flags AND the Database property ranges
 *           (setPropertyRange, database.cc:3220 — the loader/cspec
 *           registration channel architecture.cc:1371/:864).
 *   name_*  Scope::queryByName (database.cc:1198).
 *   trav_*  the mapScope + stackContainer traversal: a namespace sub-scope
 *           answered before the parent (mapScope resolvemap,
 *           database.cc:3185; stackContainer discovery stops the walk,
 *           database.cc:957-958).
 *
 * Discriminating semantics pinned by the case table:
 *   qc_exact / qc_mid_needexact   entry->getAddr() == rampoint is the
 *                                 needexacthit test (coreaction.cc:1160).
 *   qc_chararray_mid              TYPE_ARRAY + base isCharPrint is the
 *                                 char-array middle exception
 *                                 (coreaction.cc:1153-1159).
 *   qc_intarray_mid               non-char array: no exception.
 *   ro_symbol_before_range        a symbol mapped BEFORE its property
 *                                 range never folds the readonly bit
 *                                 (addMap fold is install-time only,
 *                                 database.cc:1153).
 *   qc_after_range_fold /         a symbol mapped AFTER the range folds
 *   ro_symbol_after_range         the bit into the Symbol flags.
 *   ro_scope_only / ro_prop_only  the two non-entry queryProperties
 *                                 branches (database.cc:1271-1280); the
 *                                 prop-only window is carved out of the
 *                                 global scope's ram ownership with
 *                                 removeRange so both branches are
 *                                 observable.
 *   trav_child_wins               the namespace scope owns the address
 *                                 (mapScope) and its entry answers first.
 *   trav_discovery_shadow         the child's inScope discovery returns
 *                                 NULL before the parent's shadowing
 *                                 entry is ever consulted.
 *
 * Symbols/ranges are installed through public production paths
 * (Scope::addSymbol / Database::addRange / removeRange /
 * Database::setPropertyRange / Database::findCreateScope) on the real
 * BfdArchitecture global scope of function GetStr; every observable is the
 * query return identity (symbol name, entry first/last/offset, flags,
 * answering scope).
 */

#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

const Scope *g_globals = (const Scope *)0;

string scopeToken(const Scope *sc)

{
  if (sc == (const Scope *)0) return "none";
  if (sc == g_globals) return "global";
  return sc->getName();
}

// One parent-channel container query, observed exactly as
// ActionConstantPtr::isPointer would read the result.
void dumpContainerQuery(const string &caseName, Funcdata &fd, AddrSpace *spc,
                        uintb offset)
{
  SymbolEntry *entry = fd.getScopeLocal()->getParent()->queryContainer(
      Address(spc, offset), 1, Address());
  ostringstream out;
  out << "case=" << caseName << "|kind=qc|query=0x" << std::hex << offset
      << ":1|up=inv";
  if (entry == (SymbolEntry *)0) {
    out << "|result=null";
  }
  else {
    const Datatype *ptrType = entry->getSymbol()->getType();
    int4 meta = static_cast<int4>(ptrType->getMetatype());
    bool charbase = false;
    if (meta == static_cast<int4>(TYPE_ARRAY)) {
      const Datatype *base = ((const TypeArray *)ptrType)->getBase();
      charbase = base->isCharPrint();
    }
    bool exact = (entry->getAddr() == Address(spc, offset));
    out << "|result=" << entry->getSymbol()->getName()
        << "|first=0x" << std::hex << entry->getFirst()
        << "|last=0x" << std::hex << entry->getLast()
        << "|off=" << std::dec << entry->getOffset()
        << "|sz=" << std::dec << entry->getSize()
        << "|exact=" << (exact ? 1 : 0)
        << "|meta=" << std::dec << meta
        << "|charbase=" << (charbase ? 1 : 0)
        << "|flags=0x" << std::hex << entry->getAllFlags()
        << "|scope=" << scopeToken(entry->getSymbol()->getScope());
  }
  std::cout << out.str() << '\n';
  std::cout.flush();
}

// One isReadOnly observation (queryProperties under the hood).
void dumpReadOnly(const string &caseName, const Scope *sc, AddrSpace *spc,
                  uintb offset)
{
  uint4 flags = 0;
  SymbolEntry *entry = sc->queryProperties(Address(spc, offset), 1,
                                           Address(), flags);
  bool ro = ((flags & Varnode::readonly) != 0);
  ostringstream out;
  out << "case=" << caseName << "|kind=ro|query=0x" << std::hex << offset
      << ":1|ro=" << (ro ? 1 : 0)
      << "|entry=" << (entry == (SymbolEntry *)0
                           ? string("null")
                           : entry->getSymbol()->getName())
      << "|flags=0x" << std::hex << flags;
  std::cout << out.str() << '\n';
  std::cout.flush();
}

// One queryByName observation against the parent (global) scope.
void dumpNameQuery(const string &caseName, const Scope *sc, const string &nm)
{
  vector<Symbol *> res;
  sc->queryByName(nm, res);
  ostringstream out;
  out << "case=" << caseName << "|kind=name|query=" << nm
      << "|records=" << std::dec << res.size()
      << "|first=" << (res.empty() ? string("null") : res[0]->getName());
  std::cout << out.str() << '\n';
  std::cout.flush();
}

void runCases(Funcdata &fd)
{
  Architecture *glb = fd.getArch();
  AddrSpace *ram = glb->getDefaultCodeSpace();
  TypeFactory *types = glb->types;
  Scope *globals = glb->symboltab->getGlobalScope();
  g_globals = globals;

  {
    ostringstream out;
    out << "case=setup|arch=" << glb->archid
        << "|ram=" << ram->getName()
        << "|scope=global"
        << "|parent_is_global="
        << (fd.getScopeLocal()->getParent() == globals ? 1 : 0);
    std::cout << out.str() << '\n';
    std::cout.flush();
  }

  // Scope ownership window for the deterministic scope-only branch.
  glb->symboltab->addRange(globals, ram, 0x7f200000, 0x7f200fff);

  // Symbols mapped BEFORE the property range: no readonly fold.
  globals->addSymbol("DAT_exact", types->getBase(16, TYPE_UNKNOWN),
                     Address(ram, 0x7f200000), Address());
  globals->addSymbol("s_lit", types->getTypeArray(16, types->getTypeChar(1)),
                     Address(ram, 0x7f200100), Address());
  globals->addSymbol("arr_i", types->getTypeArray(4, types->getBase(4, TYPE_INT)),
                     Address(ram, 0x7f200200), Address());

  // Property ranges (the loader/cspec readonly registration channel).
  {
    Range ro1(ram, 0x7f200000, 0x7f2000ff);
    glb->symboltab->setPropertyRange(Varnode::readonly, ro1);
    Range ro2(ram, 0x7f300000, 0x7f3000ff);
    glb->symboltab->setPropertyRange(Varnode::readonly, ro2);
  }
  // Symbol mapped AFTER the range: the addMap fold bakes readonly in.
  globals->addSymbol("DAT_after", types->getBase(8, TYPE_UNKNOWN),
                     Address(ram, 0x7f200050), Address());

  // Namespace sub-scope owning [0x7f200300,0x7f20030f], its symbol, and a
  // parent symbol shadowed by the child's ownership window.
  Scope *ns_child = glb->symboltab->findCreateScope(0x1234, "ns_child", globals);
  glb->symboltab->addRange(ns_child, ram, 0x7f200300, 0x7f20030f);
  ns_child->addSymbol("DAT_nested", types->getBase(4, TYPE_UNKNOWN),
                      Address(ram, 0x7f200300), Address());
  globals->addSymbol("DAT_gshadow", types->getBase(8, TYPE_UNKNOWN),
                     Address(ram, 0x7f200300), Address());
  globals->addSymbol("DAT_plain", types->getBase(4, TYPE_UNKNOWN),
                     Address(ram, 0x7f200500), Address());

  // Carve the property-only window out of the global ram ownership so the
  // property-only queryProperties branch is observable (the cspec <global>
  // range otherwise owns all of ram).
  glb->symboltab->removeRange(globals, ram, 0x7f300000, 0x7f3000ff);
  glb->symboltab->removeRange(globals, ram, 0x7f400000, 0x7f4000ff);

  dumpContainerQuery("qc_exact", fd, ram, 0x7f200000);
  dumpContainerQuery("qc_mid_needexact", fd, ram, 0x7f200008);
  dumpContainerQuery("qc_miss", fd, ram, 0x7f210000);
  dumpContainerQuery("qc_chararray_mid", fd, ram, 0x7f200108);
  dumpContainerQuery("qc_intarray_mid", fd, ram, 0x7f200202);
  dumpContainerQuery("qc_after_range_fold", fd, ram, 0x7f200050);
  dumpReadOnly("ro_symbol_before_range", globals, ram, 0x7f200008);
  dumpReadOnly("ro_symbol_after_range", globals, ram, 0x7f200050);
  dumpReadOnly("ro_scope_only", globals, ram, 0x7f2000c0);
  dumpReadOnly("ro_prop_only", globals, ram, 0x7f300010);
  dumpReadOnly("ro_none", globals, ram, 0x7f400010);
  dumpNameQuery("name_hit", globals, "DAT_exact");
  dumpNameQuery("name_miss", globals, "DAT_nosuch");
  dumpNameQuery("name_child_shadowed", globals, "DAT_nested");
  dumpContainerQuery("trav_child_wins", fd, ram, 0x7f200302);
  dumpContainerQuery("trav_discovery_shadow", fd, ram, 0x7f200306);
  dumpContainerQuery("trav_plain_global", fd, ram, 0x7f200500);
}

void run(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary, "default", &std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw std::runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->getName() != "GetStr" ||
        fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
      throw std::runtime_error("GetStr input identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " +
                               architecture.archid);
    runCases(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: cptr_query_channel_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "cptr_query_channel_1204: LowlevelError: "
              << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "cptr_query_channel_1204: " << error.what() << '\n';
    return 1;
  }
}
