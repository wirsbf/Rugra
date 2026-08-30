/*
 * blockstruct_collapse_residual_1204.cc — locked Ghidra 12.0.4 oracle
 * structure-tree dumper for BLOCKSTRUCT-COLLAPSE-RESIDUAL-0001.
 *
 * Mirrors tools/regen_ghidra_golden.py's golden_dump_1204.cc loading path
 * (BfdArchitecture over the locked sleigh_specs assets, full universal
 * action), then calls Funcdata::printBlockTree (funcdata_block.cc:27) —
 * the oracle-side counterpart of Rugra's block.rs print_tree_dbg — and
 * additionally dumps the C text via PrintC docFunction.
 *
 * Modes:
 *   blockstruct_collapse_residual_1204 tree SPEC_ROOT BINARY NAME_OR_OFFSET OUT
 *
 * OUT receives:
 *   name / offset / size header lines
 *   "---- block tree ----" : Funcdata::printBlockTree output
 *   "---- C text ----"     : PrintC docFunction output
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostream;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

void registerFunctionSymbol(Architecture &arch, AddrSpace *code,
                             const char *name, uintb value)
{
  if (name == (const char *)0) return;
  Address address(code, value);
  if (arch.symboltab->getGlobalScope()->queryFunction(address) != (Funcdata *)0)
    return; // already registered from another symbol source
  string basename;
  Scope *scope = arch.symboltab->findCreateScopeFromSymbolName(
      name, "::", basename, (Scope *)0);
  scope->addFunction(address, basename);
}

void registerBfdFunctionSymbols(Architecture &arch,const string &binary,bool dynamicTable)
{
  bfd *abfd = bfd_openr(binary.c_str(),"default");
  if (abfd == (bfd *)0)
    throw runtime_error("bfd_openr failed: " + binary);
  if (!bfd_check_format(abfd, bfd_object)) {
    bfd_close(abfd);
    return;
  }
  long storage;
  if (dynamicTable)
    storage = bfd_get_dynamic_symtab_upper_bound(abfd);
  else
    storage = bfd_get_symtab_upper_bound(abfd);
  if (storage <= 0) {
    bfd_close(abfd);
    return;
  }
  asymbol **symbols = (asymbol **)malloc(storage);
  if (symbols == (asymbol **)0) {
    bfd_close(abfd);
    throw runtime_error("symbol table malloc failed");
  }
  long count = dynamicTable ? bfd_canonicalize_dynamic_symtab(abfd, symbols)
                            : bfd_canonicalize_symtab(abfd, symbols);
  AddrSpace *code = arch.getDefaultCodeSpace();
  for (long index = 0; index < count; ++index) {
    asymbol *symbol = symbols[index];
    if (symbol == (asymbol *)0 || symbol->name == (const char *)0) continue;
    if ((symbol->flags & BSF_FUNCTION) == 0) continue;
    if (symbol->section == (asection *)0 || bfd_is_und_section(symbol->section))
      continue;
    registerFunctionSymbol(arch, code, symbol->name, bfd_asymbol_value(symbol));
  }
  free(symbols);
  bfd_close(abfd);
}

void registerPltStubs(Architecture &arch,const string &binary)
{
  bfd *abfd = bfd_openr(binary.c_str(),"default");
  if (abfd == (bfd *)0)
    throw runtime_error("bfd_openr failed: " + binary);
  if (!bfd_check_format(abfd, bfd_object)) {
    bfd_close(abfd);
    return;
  }
  asection *relaplt = bfd_get_section_by_name(abfd, ".rela.plt");
  asection *dsymsec = bfd_get_section_by_name(abfd, ".dynsym");
  asection *dstrsec = bfd_get_section_by_name(abfd, ".dynstr");
  asection *pltsec = bfd_get_section_by_name(abfd, ".plt.sec");
  asection *plt = bfd_get_section_by_name(abfd, ".plt");
  bool plausible = relaplt != (asection *)0 && dsymsec != (asection *)0
      && dstrsec != (asection *)0 && (pltsec != (asection *)0 || plt != (asection *)0)
      && (relaplt->size % 24) == 0 && (dsymsec->size % 24) == 0;
  if (plausible) {
    vector<unsigned char> rela(relaplt->size);
    vector<unsigned char> dsym(dsymsec->size);
    vector<unsigned char> dstr(dstrsec->size);
    if (bfd_get_section_contents(abfd, relaplt, &rela[0], 0, relaplt->size)
        && bfd_get_section_contents(abfd, dsymsec, &dsym[0], 0, dsymsec->size)
        && bfd_get_section_contents(abfd, dstrsec, &dstr[0], 0, dstrsec->size)) {
      AddrSpace *code = arch.getDefaultCodeSpace();
      size_t count = rela.size() / 24;
      size_t symbolCount = dsym.size() / 24;
      for (size_t index = 0; index < count; ++index) {
        const unsigned char *record = &rela[index * 24];
        uintb info;
        std::memcpy(&info, record + 8, 8); // Elf64_Rela.r_info
        uint4 type = static_cast<uint4>(info & 0xffffffffU);
        uint4 symindex = static_cast<uint4>(info >> 32);
        if (type != 7 /* R_X86_64_JUMP_SLOT */) continue;
        if (symindex >= symbolCount) continue;
        uint4 nameOffset;
        std::memcpy(&nameOffset, &dsym[symindex * 24], 4); // Elf64_Sym.st_name
        if (nameOffset >= dstr.size()) continue;
        const char *name = reinterpret_cast<const char *>(&dstr[0]) + nameOffset;
        uintb stub = 0;
        if (pltsec != (asection *)0 && pltsec->size >= (index + 1) * 16)
          stub = pltsec->vma + index * 16;
        else if (plt != (asection *)0 && plt->size >= (index + 2) * 16)
          stub = plt->vma + (index + 1) * 16;
        else
          continue;
        registerFunctionSymbol(arch, code, name, stub);
      }
    }
  }
  bfd_close(abfd);
}

struct FunctionEntry {
  Funcdata *fd;
  string name;
  uintb offset;
};

void collectFunctionsRecursive(Scope *scope, std::set<Funcdata *> &seen,
                                vector<FunctionEntry> &entries)
{
  if (!scope->isGlobal()) return;
  MapIterator miter = scope->begin();
  MapIterator menditer = scope->end();
  while (miter != menditer) {
    Symbol *sym = (*miter)->getSymbol();
    FunctionSymbol *fsym = dynamic_cast<FunctionSymbol *>(sym);
    ++miter;
    if (fsym == (FunctionSymbol *)0) continue;
    Funcdata *fd = fsym->getFunction();
    if (fd == (Funcdata *)0) continue;
    if (!seen.insert(fd).second) continue;
    FunctionEntry entry;
    entry.fd = fd;
    entry.name = fd->getName();
    entry.offset = fd->getAddress().getOffset();
    entries.push_back(entry);
  }
  ScopeMap::const_iterator iter = scope->childrenBegin();
  ScopeMap::const_iterator enditer = scope->childrenEnd();
  for (; iter != enditer; ++iter)
    collectFunctionsRecursive((*iter).second, seen, entries);
}

vector<FunctionEntry> collectFunctions(Architecture &arch)
{
  vector<FunctionEntry> entries;
  std::set<Funcdata *> seen;
  collectFunctionsRecursive(arch.symboltab->getGlobalScope(), seen, entries);
  std::sort(entries.begin(), entries.end(),
            [](const FunctionEntry &left, const FunctionEntry &right) {
              if (left.offset != right.offset) return left.offset < right.offset;
              return left.name < right.name;
            });
  return entries;
}

string decompileFunction(Architecture &arch, Funcdata *fd, uintb &sizeOut)
{
  AddrSpace *codeSpace = arch.getDefaultCodeSpace();
  fd->followFlow(Address(codeSpace, 0), Address(codeSpace, codeSpace->getHighest()));
  Action *root = arch.allacts.getCurrent();
  if (root == (Action *)0)
    throw runtime_error("no current decompile action");
  root->reset(*fd);
  int4 result;
  do {
    result = root->perform(*fd);
  } while (result < 0);
  ostringstream cOutput;
  arch.print->setOutputStream(&cOutput);
  arch.print->docFunction(fd);
  sizeOut = fd->getSize();
  return cOutput.str();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 6 || std::string(argv[1]) != "tree") {
    std::cerr << "usage: blockstruct_collapse_residual_1204 tree SPEC_ROOT BINARY NAME_OR_OFFSET OUT\n";
    return 2;
  }
  const string specRoot = argv[2];
  const string binary = argv[3];
  const string selector = argv[4];
  const string outPath = argv[5];
  try {
    vector<string> specPaths;
    specPaths.push_back(specRoot);
    startDecompilerLibrary(specPaths);
    BfdArchitecture architecture(binary, "default", &std::cerr);
    DocumentStorage store;
    architecture.init(store);
    registerBfdFunctionSymbols(architecture, binary, false);
    registerBfdFunctionSymbols(architecture, binary, true);
    registerPltStubs(architecture, binary);
    vector<FunctionEntry> entries = collectFunctions(architecture);

    uintb selectorValue = 0;
    bool byOffset = false;
    if (!selector.empty()
        && selector.find_first_not_of("0123456789abcdefABCDEFx") == string::npos) {
      string digits = selector.substr(0, 2) == "0x" ? selector.substr(2) : selector;
      std::istringstream parse(digits);
      parse >> std::hex >> selectorValue;
      if (!parse.fail() && parse.eof() && selectorValue != 0)
        byOffset = true;
    }

    const FunctionEntry *found = (const FunctionEntry *)0;
    for (size_t index = 0; index < entries.size(); ++index) {
      if (byOffset ? entries[index].offset == selectorValue
                   : entries[index].name == selector) {
        found = &entries[index];
        break;
      }
    }
    if (found == (const FunctionEntry *)0) {
      std::cerr << "function not found: " << selector << "\n";
      return 1;
    }

    uintb size = 0;
    string text = decompileFunction(architecture, found->fd, size);
    ostringstream treeOutput;
    found->fd->printBlockTree(treeOutput);

    std::ofstream out(outPath.c_str(), std::ios::binary);
    if (!out) throw runtime_error("unable to create output: " + outPath);
    out << "name " << found->name << "\n";
    out << "offset 0x" << std::hex << found->offset << std::dec << "\n";
    out << "size " << size << "\n";
    out << "---- block tree ----\n";
    out << treeOutput.str();
    out << "---- C text ----\n";
    out << text;
    return 0;
  }
  catch (const ghidra::LowlevelError &error) {
    std::cerr << "LowlevelError: " << error.explain << "\n";
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "error: " << error.what() << "\n";
    return 1;
  }
}
