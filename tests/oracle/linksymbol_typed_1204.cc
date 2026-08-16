/*
 * Locked Ghidra 12.0.4 Funcdata::linkSymbol / ActionNameVars typed-symbol
 * oracle for FUNCDATA-LINKSYMBOL-TYPED-0001.
 *
 * Each case builds a minimal SSA-shaped function body (register-space
 * temporaries written by p-code ops at explicit addresses, plus one input),
 * runs ActionNameVars::perform over the Funcdata, and dumps the resulting
 * ScopeLocal symbol table and HighVariable attachments.  The typed-symbol
 * projection (bVar/cVar/iVar/pcVar naming via printNameBase) and the
 * handleSymbolConflict/buildDynamicSymbol conflict path are the observables.
 *
 * Pointer values are identity keys only.  Dynamic-symbol hashes are internal
 * identities (like pointers) and are not part of the record; the observable
 * is the dynamic storage flag plus the finished name.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

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

class Fixture {
  Funcdata &fd;
  vector<Varnode *> varnodes;
  map<Varnode *, string> varnodeNames;
  vector<HighVariable *> highs;
  map<HighVariable *, string> highNames;
  int4 nextVarnode;
  int4 nextHigh;

public:
  explicit Fixture(Funcdata &func)
    : fd(func), nextVarnode(0), nextHigh(0)
  {
  }

  void rememberVarnode(Varnode *vn, const string &name)
  {
    if (varnodeNames.insert(std::make_pair(vn, name)).second)
      varnodes.push_back(vn);
  }

  void rememberHigh(Varnode *vn, const string &name)
  {
    HighVariable *high = vn->getHigh();
    if (high == (HighVariable *)0)
      throw std::runtime_error("varnode has no high");
    if (highNames.insert(std::make_pair(high, name)).second)
      highs.push_back(high);
  }

  string varnodeName(Varnode *vn) const
  {
    if (vn == (Varnode *)0)
      return "-";
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

  string typeName(Datatype *ct) const
  {
    if (ct == (Datatype *)0)
      return "null";
    ostringstream out;
    out << "mt=" << static_cast<int4>(ct->getMetatype())
        << ",sz=" << ct->getSize() << ",pnb=";
    ct->printNameBase(out);
    return out.str();
  }

  string entryDump(Symbol *sym) const
  {
    if (sym == (Symbol *)0)
      return "none";
    const SymbolEntry *entry = sym->getFirstWholeMap();
    ostringstream out;
    out << "name=" << sym->getName()
        << ",typ=" << typeName(sym->getType())
        << ",cat=" << sym->getCategory()
        << ",spc=" << (entry->isDynamic() ? string("none") : entry->getAddr().getSpace()->getName())
        << ",off=" << std::hex
        << (entry->isDynamic() ? 0 : entry->getAddr().getOffset()) << std::dec
        << ",esz=" << entry->getSize()
        << ",dyn=" << (entry->isDynamic() ? 1 : 0)
        << ",usept=";
    Address usepoint = entry->getFirstUseAddress();
    if (usepoint.isInvalid())
      out << "invalid";
    else
      out << std::hex << usepoint.getOffset() << std::dec;
    return out.str();
  }

  string highDump(void) const
  {
    ostringstream out;
    bool first = true;
    out << "list=[";
    for(vector<HighVariable *>::const_iterator iter = highs.begin();
        iter != highs.end(); ++iter) {
      HighVariable *high = *iter;
      if (!first)
        out << ';';
      first = false;
      out << '{' << highNames.find(high)->second
          << ",sym={" << entryDump(high->getSymbol()) << '}'
          << ",soff=" << high->getSymbolOffset()
          << '}';
    }
    out << ']';
    return out.str();
  }

  string varnodeDump(void) const
  {
    ostringstream out;
    bool first = true;
    out << "list=[";
    for(vector<Varnode *>::const_iterator iter = varnodes.begin();
        iter != varnodes.end(); ++iter) {
      Varnode *vn = *iter;
      if (!first)
        out << ';';
      first = false;
      out << '{' << varnodeName(vn)
          << ",mapped=" << ((vn->getFlags() & Varnode::mapped) != 0 ? 1 : 0)
          << ",input=" << (vn->isInput() ? 1 : 0)
          << ",persist=" << (vn->isPersist() ? 1 : 0)
          << '}';
    }
    out << ']';
    return out.str();
  }

  void assignHighs(void)
  {
    for(vector<Varnode *>::const_iterator iter = varnodes.begin();
        iter != varnodes.end(); ++iter)
      rememberHigh(*iter, varnodeName(*iter));
  }

  void dump(const string &caseName, const string &stage)
  {
    std::cout << "case=" << caseName
              << "|stage=" << stage
              << "|highs=[" << highDump() << ']'
              << "|varnodes=[" << varnodeDump() << "]\n";
    std::cout.flush();
  }

  void run(const string &caseName)
  {
    fd.setHighLevel();
    assignHighs();
    dump(caseName, "before");
    ActionNameVars action("analysis");
    action.perform(fd);
    dump(caseName, "after");
  }
};

// Register temporaries with distinct data-types: the created Symbols must
// carry the HighVariable type and the assignDefaultNames projection must be
// printNameBase + "Var" + shared counter (bVar/cVar/iVar/pcVar family).
void runTypedTemporaries(Funcdata &fd)
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
  fixture.run("typed_temporaries");
}

// A 4-byte register temporary at 0x70 (defined at the function base - 1)
// followed by a 1-byte register INPUT at 0x71: the input's linkSymbol finds
// the 4-byte Symbol through queryProperties (usepoints match at base-1),
// handleSymbolConflict's isInput leg attaches the partial entry, and
// HighVariable::setSymbol's offset computation (variable.cc:258-270) yields
// symboloffset=1 — so the input high is EXCLUDED from namerec by
// coreaction.cc:2965's getSymbolOffset() < 0 gate and named by
// assignDefaultNames' entry path instead.
void runPartialCoverage(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *whole = fixture.makeWritten("whole", 4, 0x70, 0x36cf, 0x2a);
  fixture.setType(whole, types->getBase(4, TYPE_INT));
  Varnode *piece = fixture.makeInput("piece", 1, 0x71);
  fixture.setType(piece, types->getTypeChar(1));
  fixture.run("partial_coverage");
}

// An irregular register input: linkSymbol still creates the local Symbol,
// and buildDefaultName's vn path drives the irregular-input branch
// (in_<register>).
void runIrregularInput(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *x = fixture.makeInput("x", 8, 0x08); // RCX
  fixture.setType(x, types->getBase(8, TYPE_INT));
  fixture.run("irregular_input");
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

    runTypedTemporaries(*fd);
    runIrregularInput(*fd);
    runPartialCoverage(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: linksymbol_typed_1204 SPEC_ROOT CURL_BINARY\n";
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
