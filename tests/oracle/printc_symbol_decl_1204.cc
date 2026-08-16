/*
 * Locked Ghidra 12.0.4 PrintC::emitLocalVarDecls / emitScopeVarDecls /
 * emitVarDecl oracle for PRINTC-SYMBOL-DECL-0001.
 *
 * Each case builds the same minimal SSA-shaped function body as
 * linksymbol_typed_1204.cc (register-space temporaries written by p-code ops
 * at explicit code addresses, plus one input), runs ActionNameVars over the
 * Funcdata, and then drives the production PrintC declaration walk —
 * emitLocalVarDecls -> emitScopeVarDecls(no_category) -> emitVarDeclStatement
 * -> emitVarDecl (printc.cc:2260/2518/2510/2497) — through a FixturePrintC
 * subclass whose protected entry is exposed and whose emitter is the plain
 * text EmitNoMarkup stream.  The captured declaration text is the record.
 *
 * Cases:
 *   - typed_temporaries : bool/char/int4/char * register temps.  Proves the
 *     MapIterator address order (register space, ascending offset) and the
 *     sym->getType()/getDisplayName() spelling of emitVarDecl.
 *   - irregular_input   : an 8-byte register input (RCX) named in_RCX by
 *     buildDefaultName's irregular-input branch.
 *   - dynamic_symbol    : one typed static temp plus an explicit
 *     addDynamicSymbol entry — proves the dynamic list is walked AFTER the
 *     address map (printc.cc:2554) and its decls use the same spelling.
 *   - undef_and_category: a no-category symbol still carrying a $$undef name
 *     is EMITTED verbatim by the map branch (printc.cc:2535-2553 has NO
 *     isNameUndefined filter — only the category branch at cc:2529 does),
 *     while a symbol moved to function_parameter category (cc:2541) is
 *     skipped.
 *
 * Pointer/hash values are identity keys only.  Symbol ids are internal
 * identities; the $$undef name is pinned by renameSymbol to a fixed string so
 * the record never depends on the id counter.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"
#include "printc.hh"
#include "prettyprint.hh"

#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

// Subclass only to (a) expose the protected emitLocalVarDecls entry and
// (b) swap the default EmitMarkup emitter for the plain-text EmitNoMarkup
// stream (PrintLanguage::emit is protected; PrintC's constructor installs an
// EmitMarkup by default).
class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *g) : PrintC(g, "printc-symbol-decl-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  // printc.cc:2260 — drive exactly the local-declaration walk docFunction
  // performs at printc.cc:2656.  docFunction entered the function's scope at
  // printc.cc:2597 (pushScope(fd->getScopeLocal())) before emitting the
  // declaration block; without it pushSymbolScope would qualify every symbol
  // with its scope path ("GetStr::").  Indent level 0 reproduces the
  // oracle's outer indent (openBraceIndent has already happened at cc:2655).
  void renderLocalVarDecls(const Funcdata *fd, std::ostream &out) {
    setOutputStream(&out);
    pushScope(fd->getScopeLocal());
    emitLocalVarDecls(fd);
    popScope();
  }
};

class Fixture {
  Funcdata &fd;
  vector<Varnode *> varnodes;
  map<Varnode *, string> varnodeNames;
  vector<HighVariable *> highs;
  map<HighVariable *, string> highNames;

public:
  explicit Fixture(Funcdata &func)
    : fd(func)
  {
  }

  void rememberVarnode(Varnode *vn, const string &name)
  {
    if (varnodeNames.insert(std::make_pair(vn, name)).second)
      varnodes.push_back(vn);
  }

  string varnodeName(Varnode *vn) const
  {
    map<Varnode *, string>::const_iterator iter = varnodeNames.find(vn);
    if (iter == varnodeNames.end())
      throw std::runtime_error("unregistered fixture varnode");
    return (*iter).second;
  }

  Varnode *makeWrittenOp(const string &name, int4 size, uintb offset, uintb pc,
                         OpCode opc, int4 inputSize, uintb value, uintb usePc)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(1, Address(codeSpace, pc));
    fd.opSetOpcode(op, opc);
    Varnode *input = fd.newConstant(inputSize, value);
    fd.opSetInput(op, input, 0);
    Varnode *vn = fd.newVarnode(size, registerSpace, offset);
    fd.opSetOutput(op, vn);
    // Give the temporary a reader so it has SSA use edges for the hash.
    PcodeOp *use = fd.newOp(1, Address(codeSpace, usePc));
    fd.opSetOpcode(use, CPUI_COPY);
    fd.opSetInput(use, vn, 0);
    fd.newUniqueOut(size, use);
    rememberVarnode(vn, name);
    return vn;
  }

  Varnode *makeWritten(const string &name, int4 size, uintb offset, uintb pc,
                       uintb value)
  {
    return makeWrittenOp(name, size, offset, pc, CPUI_COPY, size, value, pc + 0x10);
  }

  Varnode *makeInput(const string &name, int4 size, uintb offset)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    if (registerSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires the register space");
    Varnode *vn = fd.setInputVarnode(fd.newVarnode(size, registerSpace, offset));
    rememberVarnode(vn, name);
    return vn;
  }

  void setType(Varnode *vn, Datatype *ct)
  {
    vn->updateType(ct);
  }

  void assignHighs(void)
  {
    for(vector<Varnode *>::const_iterator iter = varnodes.begin();
        iter != varnodes.end(); ++iter) {
      Varnode *vn = *iter;
      HighVariable *high = vn->getHigh();
      if (high == (HighVariable *)0)
        throw std::runtime_error("varnode has no high");
      if (highNames.insert(std::make_pair(high, varnodeName(vn))).second)
        highs.push_back(high);
    }
  }

  // First whole-symbol for a remembered high (the symbols ActionNameVars
  // attached); used by the category/undef cases.
  Symbol *symbolForHigh(const string &name) const
  {
    for(vector<HighVariable *>::const_iterator iter = highs.begin();
        iter != highs.end(); ++iter) {
      if (highNames.find(*iter)->second == name)
        return (*iter)->getSymbol();
    }
    throw std::runtime_error("no high remembered under name " + name);
  }

  // Captured decl text, transport-normalized identically on both sides:
  // outer whitespace stripped, inner line breaks replaced with '~'.
  void renderDecls(Architecture *glb, const string &caseName)
  {
    FixturePrintC printer(glb);
    ostringstream out;
    printer.renderLocalVarDecls(&fd, out);
    string text = out.str();
    // strip leading/trailing whitespace, then join lines with '~'
    string trimmed = text;
    while (!trimmed.empty() &&
           (trimmed[0] == '\n' || trimmed[0] == ' ' || trimmed[0] == '\r'))
      trimmed.erase(0, 1);
    while (!trimmed.empty() &&
           (trimmed[trimmed.size()-1] == '\n' || trimmed[trimmed.size()-1] == ' ' ||
            trimmed[trimmed.size()-1] == '\r'))
      trimmed.erase(trimmed.size()-1, 1);
    for(size_t i = 0; i < trimmed.size(); ++i)
      if (trimmed[i] == '\n')
        trimmed[i] = '~';
    std::cout << "case=" << caseName << "|stage=decls|text=" << trimmed << "\n";
    std::cout.flush();
  }

  void run(Architecture *glb, const string &caseName)
  {
    fd.setHighLevel();
    assignHighs();
    ActionNameVars action("analysis");
    action.perform(fd);
    renderDecls(glb, caseName);
  }
};

// Register temporaries with distinct data-types: emitVarDecl must spell each
// Symbol's data-type and finished display name (bVar/cVar/iVar/pcVar family
// from assignDefaultNames' shared counter), in register-offset order.
void runTypedTemporaries(Funcdata &fd, Architecture *glb)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *b = fixture.makeWritten("b", 1, 0x48, 0x1000, 0x2a);
  fixture.setType(b, types->getBase(1, TYPE_BOOL));
  Varnode *c = fixture.makeWritten("c", 1, 0x50, 0x1010, 0x2a);
  fixture.setType(c, types->getTypeChar(1));
  Varnode *i = fixture.makeWritten("i", 4, 0x58, 0x1020, 0x2a);
  fixture.setType(i, types->getBase(4, TYPE_INT));
  Varnode *pc = fixture.makeWritten("pc", 8, 0x60, 0x1030, 0x2a);
  Datatype *charType = types->getTypeChar(1);
  fixture.setType(pc, types->getTypePointer(8, charType, 1));
  fixture.run(glb, "typed_temporaries");
}

// An irregular register input: buildDefaultName's vn path drives the
// irregular-input branch (in_RCX), and the symbol is declared like any other.
void runIrregularInput(Funcdata &fd, Architecture *glb)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *x = fixture.makeInput("x", 8, 0x08); // RCX
  fixture.setType(x, types->getBase(8, TYPE_INT));
  fixture.run(glb, "irregular_input");
}

// One typed static temp plus an explicit dynamic Symbol (the
// buildDynamicSymbol entry shape, database.cc:1690): the dynamic list is
// walked strictly AFTER the address map (printc.cc:2554-2572).
void runDynamicSymbol(Funcdata &fd, Architecture *glb)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *i = fixture.makeWritten("i", 4, 0x58, 0x1020, 0x2a);
  fixture.setType(i, types->getBase(4, TYPE_INT));
  fd.setHighLevel();
  fixture.assignHighs();
  ActionNameVars action("analysis");
  action.perform(fd);
  ScopeLocal *localmap = fd.getScopeLocal();
  AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
  localmap->addDynamicSymbol("uVar9", types->getBase(4, TYPE_UINT),
                             Address(codeSpace, 0x36d0), 0x1234);
  fixture.renderDecls(glb, "dynamic_symbol");
}

// A $$undef-named no-category symbol plus a function_parameter-category
// symbol: the map branch (printc.cc:2535-2553) has NO isNameUndefined filter
// (only the category branch at cc:2528-2529 does), so the $$undef symbol is
// emitted verbatim; the category-0 symbol is skipped by cc:2541.  The
// $$undef name is pinned by renameSymbol so no symbol-id counter leaks into
// the record.
void runUndefAndCategory(Funcdata &fd, Architecture *glb)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *i = fixture.makeWritten("i", 4, 0x48, 0x1020, 0x2a);
  fixture.setType(i, types->getBase(4, TYPE_INT));
  Varnode *x = fixture.makeInput("x", 8, 0x08); // RCX
  fixture.setType(x, types->getBase(8, TYPE_INT));
  fd.setHighLevel();
  fixture.assignHighs();
  ActionNameVars action("analysis");
  action.perform(fd);
  ScopeLocal *localmap = fd.getScopeLocal();
  AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
  AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
  // Move the irregular input's symbol into the parameter category.
  Symbol *inputsym = fixture.symbolForHigh("x");
  localmap->setCategory(inputsym, Symbol::function_parameter, -1);
  // Add an unnamed symbol and pin its $$undef name.
  SymbolEntry *entry = localmap->addSymbol(
      "", types->getBase(8, TYPE_INT),
      Address(registerSpace, 0x90), Address(codeSpace, 0x36d0));
  localmap->renameSymbol(entry->getSymbol(), "$$undef0000000a");
  fixture.renderDecls(glb, "undef_and_category");
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

    runTypedTemporaries(*fd, &architecture);
    runIrregularInput(*fd, &architecture);
    runDynamicSymbol(*fd, &architecture);
    runUndefAndCategory(*fd, &architecture);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: printc_symbol_decl_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
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
