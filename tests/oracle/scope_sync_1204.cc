/*
 * Locked Ghidra 12.0.4 Funcdata::syncVarnodesWithSymbols oracle for
 * FUNCDATA-SCOPE-SYNC-0001 (typed-decl chain step 3).
 *
 * Each case builds stack-space Varnodes, installs the ScopeLocal
 * Symbols/ranges, runs one Funcdata::syncVarnodesWithSymbols call with
 * explicit parameter values, and dumps every Varnode's boolean property set
 * plus its data-type.
 *
 * Pre-states are built through public production paths only: a temporarily
 * widened scope range makes newVarnodeOut's setVarnodeProperties probe
 * return the in-scope mapped|addrtied pair (database.cc:1273), setAddrForce
 * adds addrforce, updateType(,true,) locks a type, and linkSymbol attaches
 * a SymbolEntry. The temporary range is removed before the sync call, so
 * every case's before-record is a stable start state and the after-record
 * observes syncVarnodesWithSymbols alone.
 *
 * Observables per case:
 *   type_projection   updateDatatypes=true whole-size Symbol types
 *                     projected onto Varnodes (int4 / char*) and the
 *                     partial-offset getSizedType null path.
 *   unmapped_alias    in-scope unmapped Varnode (mapped|addrtied), the
 *                     isUnmappedUnaliased set and clear paths, and the
 *                     fl=0 clear of mapped/addrforce (addrtied surviving
 *                     because the mask never clears it).
 *   mask_asymmetry    addrtied clearable-but-not-settable, nolocalalias
 *                     settable-but-not-clearable, addrforce clear, the
 *                     same-(addr,size) set walk, and the isFree skip.
 *   typelock_mapentry varnode typelock blocking updateType, symbol
 *                     typelock/namelock never entering the mask, and the
 *                     attached-SymbolEntry branch keeping 'mapped' fixed.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "funcdata.hh"
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
  AddrSpace *stack;
  AddrSpace *code;
  vector<Varnode *> varnodes;
  map<Varnode *, string> varnodeNames;

public:
  explicit Fixture(Funcdata &func)
    : fd(func), stack(fd.getArch()->getStackSpace()),
      code(fd.getArch()->getDefaultCodeSpace())
  {
  }

  void remember(Varnode *vn, const string &name)
  {
    varnodeNames.insert(std::make_pair(vn, name));
    varnodes.push_back(vn);
  }

  // A written stack Varnode defined by COPY(const) at pc. With the scope
  // range temporarily covering the offset, the opSetOutput-time
  // setVarnodeProperties probe yields the in-scope mapped|addrtied pair;
  // without it the probe yields nothing (offsets sit outside the
  // x86-64-gcc default local window).
  Varnode *makeWritten(const string &name, int4 size, uintb offset, uintb pc)
  {
    PcodeOp *op = fd.newOp(1, Address(code, pc));
    fd.opSetOpcode(op, CPUI_COPY);
    fd.opSetInput(op, fd.newConstant(size, 0x2a), 0);
    Varnode *vn = fd.newVarnode(size, stack, offset);
    fd.opSetOutput(op, vn);
    remember(vn, name);
    return vn;
  }

  // A free stack Varnode (neither input nor written): skipped by
  // syncVarnodesWithSymbol's isFree guard.
  Varnode *makeFree(const string &name, int4 size, uintb offset)
  {
    Varnode *vn = fd.newVarnode(size, stack, offset);
    remember(vn, name);
    return vn;
  }

  // Scope::addSymbol with an invalid usepoint -> empty uselimit ->
  // Symbol flag addrtied set (database.cc:1149-1150).
  SymbolEntry *addSymbolNoUsepoint(const string &nm, Datatype *ct, uintb offset)
  {
    return fd.getScopeLocal()->addSymbol(nm, ct, Address(stack, offset), Address());
  }

  // Scope::addSymbol with a real usepoint -> no addrtied symbol flag.
  SymbolEntry *addSymbolUsepoint(const string &nm, Datatype *ct, uintb offset, uintb pc)
  {
    return fd.getScopeLocal()->addSymbol(nm, ct, Address(stack, offset), Address(code, pc));
  }

  void setNolocalAlias(SymbolEntry *entry)
  {
    fd.getScopeLocal()->setAttribute(entry->getSymbol(), Varnode::nolocalalias);
  }

  void setLocks(SymbolEntry *entry)
  {
    fd.getScopeLocal()->setAttribute(entry->getSymbol(), Varnode::typelock);
    fd.getScopeLocal()->setAttribute(entry->getSymbol(), Varnode::namelock);
  }

  // Database::addRange/removeRange drive Scope::rangetree, the structure
  // Scope::inScope (database.hh:597) consults.
  void addScopeRange(uintb first, uintb last)
  {
    fd.getArch()->symboltab->addRange(fd.getScopeLocal(), stack, first, last);
  }

  void removeScopeRange(uintb first, uintb last)
  {
    fd.getArch()->symboltab->removeRange(fd.getScopeLocal(), stack, first, last);
  }

  void setParamWindow(uintb first, int4 size)
  {
    fd.getScopeLocal()->markNotMapped(stack, first, size, true);
  }

  string typeName(Datatype *ct) const
  {
    if (ct == (Datatype *)0)
      return "mt=-1,sz=0,pnb=";
    ostringstream out;
    out << "mt=" << static_cast<int4>(ct->getMetatype())
        << ",sz=" << ct->getSize() << ",pnb=";
    ct->printNameBase(out);
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
      uint4 fl = vn->getFlags();
      if (!first)
        out << ';';
      first = false;
      out << '{' << varnodeNames.find(vn)->second
          << ",mapped=" << (((fl & Varnode::mapped) != 0) ? 1 : 0)
          << ",addrtied=" << (((fl & Varnode::addrtied) != 0) ? 1 : 0)
          << ",addrforce=" << (((fl & Varnode::addrforce) != 0) ? 1 : 0)
          << ",nolocalalias=" << (((fl & Varnode::nolocalalias) != 0) ? 1 : 0)
          << ",typelock=" << (((fl & Varnode::typelock) != 0) ? 1 : 0)
          << ",namelock=" << (((fl & Varnode::namelock) != 0) ? 1 : 0)
          << ",free=" << (vn->isFree() ? 1 : 0)
          << ",typ=" << typeName(vn->getType())
          << '}';
    }
    out << ']';
    return out.str();
  }

  void dump(const string &caseName, const string &stage, int4 res)
  {
    std::cout << "case=" << caseName
              << "|stage=" << stage
              << "|res=" << res
              << "|varnodes=[" << varnodeDump() << "]\n";
    std::cout.flush();
  }

  void run(const string &caseName, bool updateDatatypes, bool unmappedAliasCheck)
  {
    dump(caseName, "before", -1);
    bool res = fd.syncVarnodesWithSymbols(fd.getScopeLocal(), updateDatatypes, unmappedAliasCheck);
    dump(caseName, "after", res ? 1 : 0);
  }
};

// Whole-size Symbol types projected onto Varnodes (updateDatatypes=true):
// int4 at 0x300 and char* at 0x308 land on same-size Varnodes; the 4-byte
// read at +4 of the int8 Symbol at 0x318 takes the getSizedType null path
// (no exact piece) and keeps its unknown type. Offsets sit above the
// default local window ([0,0x1fe] plus the negative stack window), so
// creation leaves the Varnodes clean.
void runTypeProjection(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  fixture.makeWritten("ti", 4, 0x300, 0x1000);
  fixture.makeWritten("tp", 8, 0x308, 0x1010);
  fixture.makeWritten("tsub", 4, 0x31c, 0x1020);
  fixture.addSymbolNoUsepoint("lvi", types->getBase(4, TYPE_INT), 0x300);
  fixture.addSymbolNoUsepoint("lvp",
    types->getTypePointer(8, types->getTypeChar(1), 1), 0x308);
  fixture.addSymbolNoUsepoint("lv8", types->getBase(8, TYPE_INT), 0x318);
  fixture.run("type_projection", true, true);
}

// Unmapped Varnodes. The scope range holds 0x200-0x2ff at creation time so
// vin starts mapped|addrtied and vout/vparam (created under a temporary
// 0x300-0x5ff extension, plus setAddrForce) start with the full
// mapped|addrtied|addrforce triple. After the extension is removed:
// 0x400 sits below the parameter window (isUnmappedUnaliased ->
// nolocalalias, clearing mapped and addrforce while addrtied survives the
// mask); 0x502 sits inside the [0x500,0x507] parameter window (fl=0,
// clearing all three mask bits).
void runUnmappedAlias(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  fixture.addScopeRange(0x200, 0x2ff);
  fixture.addScopeRange(0x300, 0x5ff);
  fixture.makeWritten("vin", 4, 0x220, 0x1000);
  Varnode *vout = fixture.makeWritten("vout", 4, 0x400, 0x1010);
  Varnode *vparam = fixture.makeWritten("vparam", 4, 0x502, 0x1020);
  vout->setAddrForce();
  vparam->setAddrForce();
  fixture.removeScopeRange(0x300, 0x5ff);
  fixture.setParamWindow(0x500, 8);
  fixture.run("unmapped_alias", true, true);
}

// The mask asymmetry (updateDatatypes=false, the ActionRestructureVarnode
// second-pass shape). v_adt/v_nadt/v_nla are created under a temporary
// 0x300-0x338 range plus setAddrForce (mapped|addrtied|addrforce), the
// later siblings are created clean. The addrtied symbol at 0x310 leaves
// v_adt's addrtied|addrforce alone while its clean twin v_adt2 only gains
// mapped and the free twin is skipped; the no-addrtied symbol at 0x320 lets
// the sync CLEAR v_nadt's addrtied|addrforce; the nolocalalias symbol at
// 0x330 sets nolocalalias and clears addrforce on v_nla; the small locked
// int2 at 0x34e wins findOverlap over the int8 at 0x350 for v_small and
// takes the overlapping-but-not-containing branch.
void runMaskAsymmetry(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  fixture.addScopeRange(0x300, 0x338);
  Varnode *v_adt = fixture.makeWritten("v_adt", 4, 0x310, 0x1000);
  Varnode *v_nadt = fixture.makeWritten("v_nadt", 4, 0x320, 0x1020);
  Varnode *v_nla = fixture.makeWritten("v_nla", 4, 0x330, 0x1030);
  v_adt->setAddrForce();
  v_nadt->setAddrForce();
  v_nla->setAddrForce();
  fixture.removeScopeRange(0x300, 0x338);
  fixture.makeWritten("v_adt2", 4, 0x310, 0x1010);
  fixture.makeFree("v_free", 4, 0x310);
  fixture.makeWritten("v_small", 4, 0x34f, 0x1040);
  fixture.addSymbolNoUsepoint("adt", types->getBase(4, TYPE_INT), 0x310);
  fixture.addSymbolUsepoint("nadt", types->getBase(4, TYPE_INT), 0x320, 0x1000);
  SymbolEntry *nla = fixture.addSymbolNoUsepoint("nla", types->getBase(4, TYPE_INT), 0x330);
  fixture.setNolocalAlias(nla);
  SymbolEntry *sml = fixture.addSymbolNoUsepoint("sml", types->getBase(2, TYPE_INT), 0x34e);
  fixture.setLocks(sml);
  fixture.addSymbolNoUsepoint("big", types->getBase(8, TYPE_INT), 0x350);
  fixture.run("mask_asymmetry", false, true);
}

// Varnode typelock blocks updateType (v_tl keeps uint4); symbol
// typelock/namelock never enter the mask; the attached-SymbolEntry branch
// (linkSymbol through the usepoint-matched "att" entry) keeps the mapped
// bit unchanged while applying nolocalalias and the data-type on v_dyn.
void runTypelockMapentry(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Varnode *v_tl = fixture.makeWritten("v_tl", 4, 0x310, 0x1000);
  Varnode *v_dyn = fixture.makeWritten("v_dyn", 4, 0x320, 0x1010);
  v_tl->updateType(types->getBase(4, TYPE_UINT), true, false);
  SymbolEntry *tl = fixture.addSymbolNoUsepoint("tl", types->getBase(4, TYPE_INT), 0x310);
  fixture.setLocks(tl);
  // "att" carries v_dyn's def address as its usepoint so linkSymbol's
  // queryProperties finds it and handleSymbolConflict attaches the entry.
  // Its nolocalalias symbol flag drives the mapentry-branch localMask write.
  SymbolEntry *att = fixture.addSymbolUsepoint("att", types->getBase(4, TYPE_INT), 0x320, 0x1010);
  fixture.setNolocalAlias(att);
  fd.setHighLevel();
  fd.linkSymbol(v_dyn);
  fixture.run("typelock_mapentry", true, true);
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

    runTypeProjection(*fd);
    runUnmappedAlias(*fd);
    runMaskAsymmetry(*fd);
    runTypelockMapentry(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: scope_sync_1204 SPEC_ROOT CURL_BINARY\n";
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
