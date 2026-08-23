/*
 * VARMAP-DYNAMICSYM-0001: locked Ghidra 12.0.4 dynamic-symbolization
 * oracle — the explicit-Varnode conflict path that turns an unlinked
 * statement holder into a hashed ScopeLocal symbol:
 *
 *   ActionNameVars::linkSymbols      (coreaction.cc:2930-2976)
 *   Funcdata::linkSymbol             (funcdata_varnode.cc:1156-1189)
 *   Scope::queryProperties           (database.cc:1263-1281)
 *   Funcdata::handleSymbolConflict   (funcdata_varnode.cc:997-1029)
 *   Funcdata::buildDynamicSymbol     (funcdata_varnode.cc:1283-1306)
 *   DynamicHash::uniqueHash          (dynamic.cc:424-482)
 *   Scope::addDynamicSymbol          (database.cc:1690-1703)
 *   Scope::buildDefaultName          (database.cc:1756-1786)
 *   ScopeInternal::buildVariableName (database.cc:2434-2510)
 * plus the ActionNameVars::apply naming loop (coreaction.cc:2988-2997).
 *
 * Every case builds a minimal SSA-shaped body over a production
 * BfdArchitecture Funcdata (register-space temporaries written by p-code
 * ops at explicit addresses, each with a unique-space reader so the
 * dynamic hash has data-flow edges), then runs the production
 * ActionNameVars and dumps the per-HighVariable symbol projection
 * (name, data-type, storage, dynamic flag, usepoint) plus the per-case
 * scope census.
 *
 * Case census:
 *
 *   explicit_conflict_dynamic — two explicit HighVariables at the SAME
 *       register storage whose def ops share one instruction address, so
 *       the second linkSymbol's queryProperties hits the first symbol's
 *       single-point uselimit; handleSymbolConflict finds the foreign
 *       HighVariable in the loc-set walk and buildDynamicSymbol hashes
 *       the varnode into a dynamic Symbol, named by the buildDefaultName
 *       local ring (the printc uVar_<offset> GLUE residual shape).
 *   separate_usepoints_two_statics — same storage but def ops at
 *       different addresses: the second queryProperties misses the
 *       single-point uselimit, TWO static symbols are created, no dynamic
 *       path (the uselimit gate that keeps conflicts rare).
 *   implied_conflict_rejected — the implied twin of the first case: the
 *       implied flag fails HighVariable::hasName (variable.cc:729-733)
 *       before linkSymbol ever runs, so the conflicting storage creates
 *       no symbol for the implied Varnode (implied stays rejected).
 *   illegal_input_attach — an irregular register INPUT over a storage
 *       that already holds an unlimited-use Symbol: handleSymbolConflict
 *       isInput leg attaches the existing entry (funcdata_varnode.cc:
 *       1000-1003), no dynamic Symbol is created.
 *   spacebase_input_rejected — the unaffected spacebase input fails
 *       hasName (variable.cc:737-745): no link, no symbol.
 *   addrtied_attach_conflict — an address-tied Varnode over a ranged
 *       stack Symbol created for another HighVariable: the isAddrTied leg
 *       attaches (funcdata_varnode.cc:1000-1003), the stack entry keeps
 *       its unlimited use, no dynamic Symbol.
 *
 * Pointer values are identity keys only.  Dynamic hashes are internal
 * identities and are not part of the record; the observables are the
 * dynamic storage flag, the finished name, and the type/usepoint
 * projection.
 */

#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Test-only access is required to hand-set Varnode boolean flags the way
// the production ActionMarkExplicit/ActionMarkImplied pair leaves them
// (Varnode::setFlags is private), matching the varmap_unlinked_locals
// fixture's access shim.  The C++ standard headers above must come first.
#define private public
#define protected public
#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"
#undef private
#undef protected

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

  /// One fresh basic block per case body: the block keeps the fixture ops
  /// alive in the bank's address-keyed trees (gatherFirstLevelVars,
  /// linkSymbols' loc walk).
  BlockBasic *makeBlock(void)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    return graph.newBlockBasic(&fd);
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

  /// A written register temporary: defined by opc(const) at pc, read by a
  /// COPY at usePc whose output is a fresh unique temp (the unique-space
  /// reader keeps the candidate explicit-shaped and gives the dynamic
  /// hash a data-flow edge).  Both ops are inserted into a live basic
  /// block so they are registered in the address-keyed PcodeOpTree that
  /// DynamicHash::gatherFirstLevelVars walks.
  Varnode *makeWrittenOp(const string &name, int4 size, uintb offset, uintb pc,
                         OpCode opc, int4 inputSize, uintb value, uintb usePc)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    BlockBasic *block = makeBlock();
    PcodeOp *op = fd.newOp(1, Address(codeSpace, pc));
    fd.opSetOpcode(op, opc);
    Varnode *input = fd.newConstant(inputSize, value);
    fd.opSetInput(op, input, 0);
    Varnode *vn = fd.newVarnode(size, registerSpace, offset);
    fd.opSetOutput(op, vn);
    fd.opInsertEnd(op, block);
    PcodeOp *use = fd.newOp(1, Address(codeSpace, usePc));
    fd.opSetOpcode(use, CPUI_COPY);
    fd.opSetInput(use, vn, 0);
    fd.newUniqueOut(size, use);
    fd.opInsertEnd(use, block);
    rememberVarnode(vn, name);
    return vn;
  }

  Varnode *makeWritten(const string &name, int4 size, uintb offset, uintb pc,
                       uintb value)
  {
    return makeWrittenOp(name, size, offset, pc, CPUI_COPY, size, value, pc + 0x10);
  }

  /// Written and implied (the ActionMarkImplied output shape).
  Varnode *makeImplied(const string &name, int4 size, uintb offset, uintb pc,
                       uintb value)
  {
    Varnode *vn = makeWritten(name, size, offset, pc, value);
    vn->setImplied();
    return vn;
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

  Varnode *makeSpacebaseInput(const string &name, int4 size, uintb offset)
  {
    Varnode *vn = makeInput(name, size, offset);
    vn->setFlags(Varnode::spacebase | Varnode::unaffected | Varnode::directwrite);
    return vn;
  }

  /// An address-tied stack varnode inside the local window.
  Varnode *makeAddrtied(const string &name, int4 size, uintb stackOffset)
  {
    AddrSpace *stackSpace = fd.getArch()->getSpaceByName("stack");
    if (stackSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires the stack space");
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    BlockBasic *block = makeBlock();
    PcodeOp *op = fd.newOp(1, Address(codeSpace, 0x1400));
    fd.opSetOpcode(op, CPUI_COPY);
    Varnode *input = fd.newConstant(size, 0x2a);
    fd.opSetInput(op, input, 0);
    Varnode *vn = fd.newVarnode(size, stackSpace, stackOffset);
    vn->setFlags(Varnode::addrtied);
    fd.opSetOutput(op, vn);
    fd.opInsertEnd(op, block);
    PcodeOp *use = fd.newOp(1, Address(codeSpace, 0x1410));
    fd.opSetOpcode(use, CPUI_COPY);
    fd.opSetInput(use, vn, 0);
    fd.newUniqueOut(size, use);
    fd.opInsertEnd(use, block);
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

  string scopeDump(void) const
  {
    ostringstream out;
    out << "static=" << std::dec;
    int4 staticCount = 0;
    int4 dynamicCount = 0;
    ScopeLocal *localmap = fd.getScopeLocal();
    MapIterator miter, mend;
    for (miter = localmap->begin(), mend = localmap->end(); miter != mend; ++miter)
      staticCount += 1;
    std::list<SymbolEntry>::const_iterator diter, dend;
    for (diter = localmap->beginDynamic(), dend = localmap->endDynamic();
         diter != dend; ++diter)
      dynamicCount += 1;
    out << staticCount << ",dynamic=" << dynamicCount;
    return out.str();
  }

  void assignHighs(void)
  {
    for(vector<Varnode *>::const_iterator iter = varnodes.begin();
        iter != varnodes.end(); ++iter)
      rememberHigh(*iter, varnodeName(*iter));
  }

  // The BEFORE stage omits the varnode flag section: the mapped-at-creation
  // bit comes from Funcdata::newVarnode's setVarnodeProperties scope-
  // ownership query (funcdata_varnode.cc:26-42), which is outside this
  // fixture's ActionNameVars/varmap projection.
  void dump(const string &caseName, const string &stage)
  {
    if (stage == "before") {
      std::cout << "case=" << caseName
                << "|stage=" << stage
                << "|highs=[" << highDump() << ']'
                << "|scope(" << scopeDump() << ")\n";
      std::cout.flush();
      return;
    }
    std::cout << "case=" << caseName
              << "|stage=" << stage
              << "|highs=[" << highDump() << ']'
              << "|varnodes=[" << varnodeDump() << ']'
              << "|scope(" << scopeDump() << ")\n";
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

// The printc residual shape: two explicit temporaries at the same
// register storage, both written by ops at instruction 0x1000.  The
// first linkSymbol creates a static Symbol whose single-point uselimit
// covers the shared usepoint; the second queryProperties finds it, the
// loc-set walk exposes the foreign HighVariable, and buildDynamicSymbol
// creates the dynamic Symbol, named through the buildDefaultName ring.
void runExplicitConflictDynamic(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *a = fixture.makeWrittenOp("a", 8, 0x80, 0x1000, CPUI_COPY, 8, 0x2a, 0x1010);
  fixture.setType(a, types->getBase(8, TYPE_INT));
  Varnode *b = fixture.makeWrittenOp("b", 8, 0x80, 0x1000, CPUI_COPY, 8, 0x1f, 0x1010);
  fixture.setType(b, types->getBase(8, TYPE_UINT));
  fixture.run("explicit_conflict_dynamic");
}

// Same storage, def ops at different instructions: the second
// queryProperties misses the first symbol's single-point uselimit and a
// second static Symbol is created — the uselimit gate that keeps the
// dynamic path rare.
void runSeparateUsepointsTwoStatics(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *a = fixture.makeWritten("a", 8, 0x90, 0x1000, 0x2a);
  fixture.setType(a, types->getBase(8, TYPE_INT));
  Varnode *b = fixture.makeWritten("b", 8, 0x90, 0x2000, 0x1f);
  fixture.setType(b, types->getBase(8, TYPE_UINT));
  fixture.run("separate_usepoints_two_statics");
}

// The implied twin of the conflict case: the implied flag fails hasName
// at variable.cc:729-733 before linkSymbol runs, so the second high
// stays symbolless (the correct implied rejection).
void runImpliedConflictRejected(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *a = fixture.makeWrittenOp("a", 8, 0xa0, 0x1000, CPUI_COPY, 8, 0x2a, 0x1010);
  fixture.setType(a, types->getBase(8, TYPE_INT));
  Varnode *c = fixture.makeImplied("c", 8, 0xa0, 0x1000, 0x1f);
  fixture.setType(c, types->getBase(8, TYPE_UINT));
  fixture.run("implied_conflict_rejected");
}

// An irregular register INPUT at a storage holding an unlimited-use
// Symbol: handleSymbolConflict's isInput leg attaches the existing entry
// — no dynamic Symbol.  (The Symbol is added after the input is created:
// setInputVarnode's setVarnodeProperties pass would otherwise pre-set the
// mapped bit through the same query, which is outside this case's
// projection.)
void runIllegalInputAttach(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *x = fixture.makeInput("x", 8, 0xb0);
  fixture.setType(x, types->getBase(8, TYPE_INT));
  SymbolEntry *entry = fd.getScopeLocal()->addSymbol(
      "base", types->getBase(8, TYPE_INT), Address(fd.getArch()->getSpaceByName("register"), 0xb0),
      Address());
  if (entry == (SymbolEntry *)0)
    throw std::runtime_error("addSymbol failed for the attach base");
  fixture.run("illegal_input_attach");
}

// The unaffected spacebase input: hasName refuses it at variable.cc:743.
void runSpacebaseInputRejected(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *sp = fixture.makeSpacebaseInput("sp", 8, 0x20);
  fixture.setType(sp, types->getBase(8, TYPE_INT));
  fixture.run("spacebase_input_rejected");
}

// An address-tied stack Varnode over a stack Symbol created for another
// HighVariable: the isAddrTied leg attaches; no dynamic Symbol.
void runAddrtiedAttachConflict(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  AddrSpace *stackSpace = fd.getArch()->getSpaceByName("stack");
  // A first addrtied local creates the ranged stack symbol.
  Varnode *s1 = fixture.makeAddrtied("s1", 8, 0xffffffffffffff40UL);
  fixture.setType(s1, types->getBase(8, TYPE_INT));
  // A second addrtied high at the same slot (def at another instruction).
  AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
  BlockBasic *block2 = fixture.makeBlock();
  Varnode *s2 = fd.newVarnode(8, stackSpace, 0xffffffffffffff40UL);
  s2->setFlags(Varnode::addrtied);
  PcodeOp *op2 = fd.newOp(1, Address(codeSpace, 0x1800));
  fd.opSetOpcode(op2, CPUI_COPY);
  fd.opSetInput(op2, fd.newConstant(8, 0x33), 0);
  fd.opSetOutput(op2, s2);
  fd.opInsertEnd(op2, block2);
  PcodeOp *use2 = fd.newOp(1, Address(codeSpace, 0x1810));
  fd.opSetOpcode(use2, CPUI_COPY);
  fd.opSetInput(use2, s2, 0);
  fd.newUniqueOut(8, use2);
  fd.opInsertEnd(use2, block2);
  fixture.rememberVarnode(s2, "s2");
  fixture.setType(s2, types->getBase(8, TYPE_UINT));
  fixture.run("addrtied_attach_conflict");
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
    runExplicitConflictDynamic(*fd);
    runSeparateUsepointsTwoStatics(*fd);
    runImpliedConflictRejected(*fd);
    runIllegalInputAttach(*fd);
    runSpacebaseInputRejected(*fd);
    runAddrtiedAttachConflict(*fd);
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: varmap_dynamicsym_1204 SPEC_ROOT CURL_BINARY\n";
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
