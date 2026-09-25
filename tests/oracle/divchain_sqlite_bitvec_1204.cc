/*
 * golden_dump_1204.cc — locked Ghidra 12.0.4 direct-runner golden generator
 * (ORACLE-0002 fallback A).  Mirrors tests/oracle/getstr_pipeline_1204.cc:
 * BfdArchitecture over the locked sleigh_specs assets, full universal action,
 * PrintC docFunction.
 *
 * Modes:
 *   golden_dump_1204 list SPEC_ROOT BINARY OUT_JSON
 *   golden_dump_1204 all  SPEC_ROOT BINARY OUT_DIR
 *   golden_dump_1204 one  SPEC_ROOT BINARY INDEX OUT_JSON
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

string jsonEscape(const string &value)
{
  ostringstream out;
  for (string::const_iterator iter = value.begin(); iter != value.end(); ++iter) {
    unsigned char ch = static_cast<unsigned char>(*iter);
    switch (ch) {
    case '"': out << "\\\""; break;
    case '\\': out << "\\\\"; break;
    case '\b': out << "\\b"; break;
    case '\f': out << "\\f"; break;
    case '\n': out << "\\n"; break;
    case '\r': out << "\\r"; break;
    case '\t': out << "\\t"; break;
    default:
      if (ch < 0x20) {
        out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<unsigned int>(ch) << std::dec;
      }
      else
        out << static_cast<char>(ch);
      break;
    }
  }
  return out.str();
}

void writeString(ostream &out,const string &value)
{
  out << '"' << jsonEscape(value) << '"';
}

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

// Mirror Architecture::readLoaderSymbols (architecture.cc) together with
// LoadImageBfd::advanceToNextSymbol's BSF_FUNCTION/name filter, pulling from
// either the static or the dynamic BFD symbol table.  One declared deviation:
// undefined import symbols are skipped — console mode would register them
// as functions at offset 0 with no code behind them.
void registerBfdFunctionSymbols(Architecture &arch,const string &binary,bool dynamicTable)
{
  bfd *abfd = bfd_openr(binary.c_str(),"default");
  if (abfd == (bfd *)0)
    throw runtime_error("bfd_openr failed: " + binary);
  if (!bfd_check_format(abfd, bfd_object)) {
    bfd_close(abfd);
    return;
  }
  long upper = dynamicTable ? bfd_get_dynamic_symtab_upper_bound(abfd)
                            : bfd_get_symtab_upper_bound(abfd);
  if (upper <= 0) {
    bfd_close(abfd);
    return;
  }
  asymbol **symbols = (asymbol **)malloc(upper);
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

// Register PLT stubs so that calls into imported functions carry the import
// name, mirroring what the headless ELF loader + PLT analysis produces.
// The mapping plt.sec[i] <-> .rela.plt[i] (16-byte entries, JUMP_SLOT only,
// .plt+16*(i+1) when .plt.sec is absent) is the x86-64 psABI contract the
// dynamic loader itself relies on, not a heuristic.  The .dynsym/.dynstr and
// .rela.plt sections are parsed raw (Elf64_Sym / Elf64_Rela) because BFD's
// canonicalized dynamic symbol array drops the null symbol at index 0 and
// therefore does not preserve ELF relocation symbol indices.  .plt.got
// thunks are not registered (known gap: usually only __cxa_finalize).
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
        std::memcpy(&nameOffset, &dsym[symindex * 24], 4); // Elf64_Sym.st_name (4 bytes)
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

// Mirror IfaceDecompCommand::iterateFunctionsAddrOrder /
// iterateScopesRecursive (ifacedecomp.cc): every function in the global scope
// and its sub-scopes, in address order.
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

// Same per-function drive as tests/oracle/getstr_pipeline_1204.cc: full flow
// range, universal action to completion (resuming past any breakpoint), then
// PrintC docFunction.
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

void writeFunctionRecord(const string &path,long index,const FunctionEntry &entry,
                         const string &status,const string &text,uintb size)
{
  ostringstream out;
  out << "{\"schema\":1,\"index\":" << index << ",\"name\":";
  writeString(out, entry.name);
  out << ",\"offset\":" << entry.offset << ",\"size\":" << size << ",\"status\":";
  writeString(out, status);
  out << ",\"text\":";
  writeString(out, text);
  out << "}\n";
  std::ofstream file(path.c_str(), std::ios::binary);
  if (!file) throw runtime_error("unable to create record: " + path);
  file << out.str();
}

void decompileAtIndex(Architecture &arch, vector<FunctionEntry> &entries,
                      long index, const string &outPath)
{
  const FunctionEntry &entry = entries[static_cast<size_t>(index)];
  if (entry.fd->hasNoCode()) {
    writeFunctionRecord(outPath, index, entry, "no_code", "", 0);
    return;
  }
  try {
    uintb size = 0;
    string text = decompileFunction(arch, entry.fd, size);
    writeFunctionRecord(outPath, index, entry, "OK", text, size);
  }
  catch (const ghidra::LowlevelError &error) {
    writeFunctionRecord(outPath, index, entry,
                        string("error: ") + error.explain, "", 0);
  }
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 5 && !(argc == 6 && std::string(argv[1]) == "one")) {
    std::cerr << "usage: golden_dump_1204 list|all SPEC_ROOT BINARY OUT\n"
              << "       golden_dump_1204 one SPEC_ROOT BINARY INDEX OUT_JSON\n";
    return 2;
  }
  const string mode = argv[1];
  const string specRoot = argv[2];
  const string binary = argv[3];
  const string outPath = (mode == "one") ? argv[5] : argv[4];
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

    if (mode == "list") {
      ostringstream out;
      out << "{\"schema\":1,\"count\":" << entries.size() << ",\"functions\":[";
      for (size_t index = 0; index < entries.size(); ++index) {
        if (index != 0) out << ',';
        out << "{\"index\":" << index << ",\"name\":";
        writeString(out, entries[index].name);
        out << ",\"offset\":" << entries[index].offset << '}';
      }
      out << "]}\n";
      std::ofstream file(outPath.c_str(), std::ios::binary);
      if (!file) throw runtime_error("unable to create list output");
      file << out.str();
    }
    else if (mode == "one") {
      decompileAtIndex(architecture, entries, std::atol(argv[4]), outPath);
    }
    else if (mode == "all") {
      // outPath is a directory; every function gets <index>.json
      for (size_t index = 0; index < entries.size(); ++index) {
        ostringstream name;
        name << outPath << '/' << index << ".json";
        decompileAtIndex(architecture, entries, static_cast<long>(index), name.str());
        std::cerr << "[golden_dump_1204] " << (index + 1) << '/' << entries.size()
                  << ' ' << entries[index].name << '\n';
      }
    }
    else {
      throw runtime_error("unknown mode: " + mode);
    }
    shutdownDecompilerLibrary();
    return 0;
  }
  catch (const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch (const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
