/*
 * DATABASE-EQUATE-VALUE-REGISTRY-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives Scope::addEquateSymbol (database.cc:1712-1724) and the
 * EquateSymbol constructor state (database.cc:624-631) through the
 * addSymbolInternal category registration (database.cc:1810-1841,
 * category block cc:1827-1836) on real oracle objects:
 *
 *  - er_single: one addEquateSymbol on the global scope. Observable state:
 *    category == equate (cc:628), catindex == 0 (first category[equate]
 *    slot, cc:1831-1832), getCategorySize(equate) == 1, the returned
 *    object dynamic_casts to EquateSymbol (the subtype identity
 *    varnode.cc:516 reads) and carries the exact uintb value (cc:627),
 *    a nonzero symbolId (cc:1813-1816), and one new dynamic SymbolEntry
 *    (cc:1722, 1-byte whole map).
 *  - er_dup: a second addEquateSymbol with the SAME name and value — a
 *    distinct EquateSymbol object (distinct id), appended to
 *    category[equate] at catindex == 1 (cc:1832 catindex = list.size()),
 *    category size grows to 2, value preserved on the new identity.
 *  - er_scope_local: an equate added to a different scope (the function's
 *    local ScopeLocal). The local category table holds exactly its own
 *    equate (size 1, catindex 0) while the global table still holds its
 *    two — scopes are independent containers (no cross-scope leakage).
 *  - er_pipe_close / er_pipe_not_close: the pipeline-created equate (the
 *    cc:1301 buildDynamicSymbol route stores it in the LOCAL scope)
 *    attached to a constant Varnode through the public
 *    Funcdata::remapDynamicVarnode (funcdata_varnode.cc:1120-1126), then
 *    Varnode::copySymbolIfValid (varnode.cc:510-522): the markup
 *    propagates to a value-close destination constant and is rejected for
 *    a not-close one (database.cc:640-659 isValueClose).
 *
 * Observations per case (single line, pipe-separated, decimal integers):
 *   er_single/er_dup: case|cat|catindex|cat_size|is_equate|value|
 *                    id_nonzero|dyn_delta
 *   er_scope_local:  case|cat|catindex|local_cat_size|global_cat_size|
 *                    is_equate|value
 *   er_pipe_*:       case|src_symbol|dst_symbol
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

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

// Count of dynamic SymbolEntries in a scope (ScopeInternal::beginDynamic /
// endDynamic, database.cc:1921/1927).
int4 dynamicEntryCount(Scope *scope)
{
  int4 count = 0;
  for (list<SymbolEntry>::const_iterator iter = scope->beginDynamic();
       iter != scope->endDynamic(); ++iter)
    ++count;
  return count;
}

// Print the observable category/value state of one addEquateSymbol result
// plus the scope's category[equate] size and dynamic-entry delta.
void observeAdded(Scope *scope, Symbol *sym, int4 catSize, int4 dynBefore,
                  const char *name)
{
  EquateSymbol *equ = dynamic_cast<EquateSymbol *>(sym);
  std::cout << "case=" << name
            << "|cat=" << sym->getCategory()
            << "|catindex=" << sym->getCategoryIndex()
            << "|cat_size=" << catSize
            << "|is_equate=" << (equ != (EquateSymbol *)0 ? 1 : 0)
            << "|value=" << (equ != (EquateSymbol *)0 ? equ->getValue() : 0)
            << "|id_nonzero=" << (sym->getId() != 0 ? 1 : 0)
            << "|dyn_delta=" << (dynamicEntryCount(scope) - dynBefore)
            << '\n';
}

// Section 1 + 2: single add and same-value duplicate on the global scope.
void runGlobalScope(Scope *global)
{
  const int4 before1 = dynamicEntryCount(global);
  // database.cc:1712-1724: new EquateSymbol(owner,nm,format,value) +
  // addSymbolInternal + addDynamicMapInternal(...,0,1,rnglist).
  Symbol *sym1 = global->addEquateSymbol("REG_EQ", Symbol::force_hex, 66,
                                         Address(), 0x1111);
  observeAdded(global, sym1, global->getCategorySize(Symbol::equate),
               before1, "er_single");

  const int4 before2 = dynamicEntryCount(global);
  Symbol *sym2 = global->addEquateSymbol("REG_EQ", Symbol::force_hex, 66,
                                         Address(), 0x2222);
  observeAdded(global, sym2, global->getCategorySize(Symbol::equate),
               before2, "er_dup");
  std::cout << "case=er_dup_ids"
            << "|ids_differ=" << (sym1->getId() != sym2->getId() ? 1 : 0)
            << '\n';
}

// Section 3: an equate in the function's local scope — the local category
// table sees exactly its own symbol, the global table is unaffected.
void runLocalScope(Scope *global, Scope *local)
{
  const int4 globalBefore = global->getCategorySize(Symbol::equate);
  Symbol *sym = local->addEquateSymbol("REG_EQ", Symbol::force_hex, 66,
                                       Address(), 0x3333);
  EquateSymbol *equ = dynamic_cast<EquateSymbol *>(sym);
  std::cout << "case=er_scope_local"
            << "|cat=" << sym->getCategory()
            << "|catindex=" << sym->getCategoryIndex()
            << "|local_cat_size=" << local->getCategorySize(Symbol::equate)
            << "|global_cat_size=" << global->getCategorySize(Symbol::equate)
            << "|is_equate=" << (equ != (EquateSymbol *)0 ? 1 : 0)
            << "|value=" << (equ != (EquateSymbol *)0 ? equ->getValue() : 0)
            << "|global_unchanged="
            << (global->getCategorySize(Symbol::equate) == globalBefore ? 1 : 0)
            << '\n';
  // The category table round-trips the same object: getCategorySymbol
  // (database.hh:733) returns an EquateSymbol with the same value.
  Symbol *fromTable = local->getCategorySymbol(Symbol::equate, 0);
  EquateSymbol *equTable = dynamic_cast<EquateSymbol *>(fromTable);
  std::cout << "case=er_scope_local_table"
            << "|same_object=" << (fromTable == sym ? 1 : 0)
            << "|value=" << (equTable != (EquateSymbol *)0 ? equTable->getValue() : 0)
            << '\n';
}

// Section 4: a pipeline-created equate reaching copySymbolIfValid.  The
// cc:1301 buildDynamicSymbol route stores the equate in the LOCAL scope and
// attaches it via the dynamic whole map; remapDynamicVarnode
// (funcdata_varnode.cc:1120-1126) is the public storage route for
// Varnode::setSymbolEntry.
void attachLocalEquate(Funcdata &fd, Scope *local, Varnode *vn, uintb value)
{
  Symbol *sym = local->addEquateSymbol("", Symbol::force_hex, value,
                                       Address(), 0x4444);
  fd.remapDynamicVarnode(vn, sym, Address(), 1);
}

void runPipe(Funcdata &fd, Scope *local)
{
  // cc:519-521: value-close destination constant receives the markup.
  Varnode *src = fd.newConstant(4, 0x33333333ULL);
  Varnode *dst = fd.newConstant(4, 0x33333333ULL);
  attachLocalEquate(fd, local, src, 0x33333333ULL);
  dst->copySymbolIfValid(src);
  std::cout << "case=er_pipe_close"
            << "|src_symbol=" << (src->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
            << "|dst_symbol=" << (dst->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
            << '\n';
  // cc:519: not-close destination constant is rejected.
  Varnode *src2 = fd.newConstant(4, 0x12345678ULL);
  Varnode *dst2 = fd.newConstant(4, 0x33333333ULL);
  attachLocalEquate(fd, local, src2, 0x12345678ULL);
  dst2->copySymbolIfValid(src2);
  std::cout << "case=er_pipe_not_close"
            << "|src_symbol=" << (src2->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
            << "|dst_symbol=" << (dst2->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
            << '\n';
}

void run(Funcdata &fd, Scope *global)
{
  runGlobalScope(global);
  Scope *local = fd.getScopeLocal();
  runLocalScope(global, local);
  // remapDynamicVarnode's clearSymbolLinks (varnode.cc:378-390)
  // dereferences Varnode::high; turn HighVariables on so constant inputs
  // created via newConstant get one.
  fd.setHighLevel();
  runPipe(fd, local);
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: database_equatereg_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    vector<string> specPaths;
    specPaths.push_back(argv[1]);
    startDecompilerLibrary(specPaths);
    {
      std::ostringstream diagnostics;
      BfdArchitecture architecture(argv[2], "default", &diagnostics);
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
      run(*fd, architecture.symboltab->getGlobalScope());
    }
    shutdownDecompilerLibrary();
    return 0;
  }
  catch(const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
