/*
 * Locked Ghidra 12.0.4 oracle fixture for KUNABUGS-COPYTRIM-REMAT-0001
 * (CASTFUSE-A root-cause candidate ③): does Merge::allocateCopyTrim
 * re-materialize an explicit COPY at the firstuse of a dynamic-hash temp?
 *
 * Primary-source reading of the locked oracle (merge.cc:411-434,
 * dynamic.cc:561-592, funcdata_varnode.cc:1314-1399, coreaction.cc:4852-4876)
 * says the literal candidate-③ mechanism does not exist:
 *   - Merge::allocateCopyTrim is a pure cover-trim COPY allocator with no
 *     dynamic-hash input (verified: merge.cc/merge.hh contain zero
 *     DynamicHash references),
 *   - the dynamic-mapping chain (ActionDynamicMapping /
 *     ActionDynamicSymbols -> Funcdata::attemptDynamicMapping /
 *     attemptDynamicMappingLate) only LOCATES a varnode by hash and
 *     attaches symbol properties — it never allocates ops,
 *   - DynamicHash::findVarnode requires the candidate's recomputed
 *     position hash to be exactly equal, so a COPY folded by
 *     RulePropagateCopy breaks the anchor and the symbol silently
 *     detaches — no re-materialization happens anywhere.
 *
 * This fixture locks those behaviors bilaterally:
 *
 *   fold_relocate_fn  (C1)  mint a use-anchored dynamic entry on t, fold
 *                           the defining COPY away (RulePropagateCopy
 *                           shape: the use op re-reads c), then call
 *                           Funcdata::attemptDynamicMapping directly.
 *                           Expected: res=false, nothing mapped, ZERO new
 *                           ops — the oracle never re-inserts a COPY for
 *                           the dynamic temp (kuna LOSS-229-CORRECTION's
 *                           claimed mechanism falsified on the oracle).
 *   refind_attach_fn  (C1b) mint a def-anchored entry (uniqueHash) and
 *                           call attemptDynamicMapping with the IR
 *                           unchanged: the baseline success path — the
 *                           entry re-finds t, attaches properties
 *                           (mapped=1), the second call is rejected by
 *                           the already-labelled guard.  Still zero new
 *                           ops.
 *   late_cast_retarget(C2)  attemptDynamicMappingLate on an implied
 *                           CAST-adjacent temp: the oracle re-targets the
 *                           symbol to the explicit varnode on the other
 *                           side of the CAST (funcdata_varnode.cc:1373-
 *                           1386).  (Rugra's port omits this retarget —
 *                           the case pins the oracle side of that gap.)
 *   trim_dynamic_high (C3)  the merge_trim_lane T1 CMOV diamond with a
 *                           dynamic entry minted on X: mergeAddrTied +
 *                           mergeMarker insert cover-driven trim COPYs,
 *                           the dynamic entry count is untouched by
 *                           merge, and the late dynamic-symbols action
 *                           creates no ops (the broken hash simply
 *                           detaches).  Trims are cover-driven only —
 *                           candidate ③'s merge-side claim falsified.
 *   action_walk_level (C4)  ActionDynamicMapping::perform on the C1b
 *                           shape: the oracle walks beginDynamic()/
 *                           endDynamic() and performs the attach from
 *                           the action level; pins the action-level
 *                           behaviour (Rugra's registered stub is inert —
 *                           pinned on the Rust side of the fixture).
 *
 * Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
 * Projections use stable fixture identities (varnode names, hex addresses,
 * opcode names) — never pointers or SeqNums.
 */

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Test-only access is required to hand-set Varnode boolean flags the way
// production ActionMarkExplicit/ActionMarkImplied leave them
// (Varnode::setFlags is private), matching the varmap_dynamicsym fixture's
// access shim.  The C++ standard headers above must come first.
#define private public
#define protected public
#include "bfd_arch.hh"
#include "coreaction.hh"
#include "dynamic.hh"
#include "libdecomp.hh"
#include "merge.hh"
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

public:
  explicit Fixture(Funcdata &func)
    : fd(func)
  {
  }

  /// One fresh basic block per case body: the block keeps the fixture ops
  /// alive in the bank's address-keyed trees (gatherFirstLevelVars walks
  /// the PcodeOpTree by address).
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

  string varnodeName(Varnode *vn) const
  {
    map<Varnode *, string>::const_iterator iter = varnodeNames.find(vn);
    if (iter == varnodeNames.end())
      throw std::runtime_error("unregistered fixture varnode");
    return (*iter).second;
  }

  PcodeOp *makeOp(int4 ninput, uintb pc)
  {
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(ninput, Address(codeSpace, pc));
    return op;
  }

  Varnode *regOut(const string &name, int4 size, uintb offset, PcodeOp *op)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    if (registerSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires the register space");
    Varnode *vn = fd.newVarnodeOut(size, Address(registerSpace, offset), op);
    rememberVarnode(vn, name);
    return vn;
  }

  Varnode *uniqOut(int4 size, uintb offset, PcodeOp *op)
  {
    AddrSpace *uniqueSpace = fd.getArch()->getSpaceByName("unique");
    if (uniqueSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires the unique space");
    return fd.newVarnodeOut(size, Address(uniqueSpace, offset), op);
  }

  /// Mint a production-shaped dynamic entry: compute the unique hash for
  /// `vn` exactly the way Funcdata::buildDynamicSymbol does
  /// (funcdata_varnode.cc:1300-1306), then add the dynamic symbol with a
  /// name so the late attach can be observed.
  std::pair<SymbolEntry *, string> mintDynamic(const string &caseId,
                                               const string &symName,
                                               Varnode *vn, Datatype *ct)
  {
    DynamicHash dhash;
    dhash.uniqueHash(vn, &fd);
    if (dhash.getHash() == 0)
      throw std::runtime_error("uniqueHash failed");
    const string &mintCase = caseId;
    ostringstream hexOut;
    hexOut << std::hex << dhash.getHash();
    string hashText = hexOut.str();
    Symbol *sym = fd.getScopeLocal()->addDynamicSymbol(
        symName, ct, dhash.getAddress(), dhash.getHash());
    if (sym == (Symbol *)0)
      throw std::runtime_error("addDynamicSymbol failed");
    SymbolEntry *entry = sym->getFirstWholeMap();
    if (entry == (SymbolEntry *)0)
      throw std::runtime_error("dynamic symbol has no whole map");
    std::cout << "mint|case=" << mintCase
              << "|vn=" << varnodeName(vn)
              << "|H=0x" << hashText
              << "|U=0x" << std::hex << dhash.getAddress().getOffset() << std::dec
              << '\n';
    std::cout.flush();
    return std::make_pair(entry, hashText);
  }

  void vncensus(const string &caseId, const string &stage) const
  {
    for(vector<Varnode *>::const_iterator iter = varnodes.begin();
        iter != varnodes.end(); ++iter) {
      Varnode *vn = *iter;
      int4 desc = 0;
      list<PcodeOp *>::const_iterator oiter;
      for(oiter = vn->beginDescend(); oiter != vn->endDescend(); ++oiter)
        desc += 1;
      std::cout << "vnc|case=" << caseId << "|stage=" << stage
                << "|vn=" << varnodeName(vn)
                << "|mapped=" << ((vn->getFlags() & Varnode::mapped) != 0 ? 1 : 0)
                << "|implied=" << (vn->isImplied() ? 1 : 0)
                << "|explicit=" << (vn->isExplicit() ? 1 : 0)
                << "|desc=" << desc << '\n';
    }
    std::cout.flush();
  }

  /// Alive-op census sorted by (name, address): any op creation or removal
  /// by a mapping call is visible here (the "no re-materialization"
  /// observable).
  void opcensus(const string &caseId, const string &stage) const
  {
    std::set<string> items;
    list<PcodeOp *>::const_iterator iter, enditer;
    for(iter = fd.beginOpAlive(); iter != fd.endOpAlive(); ++iter) {
      PcodeOp *op = *iter;
      if (op->isDead())
        continue;
      ostringstream item;
      item << get_opname(op->code()) << "@0x" << std::hex
           << op->getAddr().getOffset() << std::dec;
      items.insert(item.str());
    }
    std::cout << "ops|case=" << caseId << "|stage=" << stage
              << "|count=" << items.size() << "|list=";
    bool first = true;
    for(std::set<string>::const_iterator siter = items.begin();
        siter != items.end(); ++siter) {
      if (!first)
        std::cout << ';';
      first = false;
      std::cout << (*siter);
    }
    std::cout << '\n';
    std::cout.flush();
  }

  /// Opcode-only alive-op census (sorted, with counts): used where op
  /// addresses are not fixture-controlled (merge trims take the incoming
  /// block's stop address, which the fixture never initializes).
  void opcensusNames(const string &caseId, const string &stage) const
  {
    std::multiset<string> items;
    list<PcodeOp *>::const_iterator iter, enditer;
    for(iter = fd.beginOpAlive(); iter != fd.endOpAlive(); ++iter) {
      PcodeOp *op = *iter;
      if (op->isDead())
        continue;
      items.insert(get_opname(op->code()));
    }
    std::cout << "opsn|case=" << caseId << "|stage=" << stage
              << "|count=" << items.size() << "|list=";
    bool first = true;
    for(std::multiset<string>::const_iterator siter = items.begin();
        siter != items.end(); ++siter) {
      if (!first)
        std::cout << ';';
      first = false;
      std::cout << (*siter);
    }
    std::cout << '\n';
    std::cout.flush();
  }

  void dyncensus(const string &caseId, const string &stage) const
  {
    int4 dynamicCount = 0;
    ScopeLocal *localmap = fd.getScopeLocal();
    std::list<SymbolEntry>::const_iterator diter, dend;
    for(diter = localmap->beginDynamic(), dend = localmap->endDynamic();
        diter != dend; ++diter)
      dynamicCount += 1;
    std::cout << "dync|case=" << caseId << "|stage=" << stage
              << "|count=" << dynamicCount << '\n';
    std::cout.flush();
  }

  void call(const string &caseId, const string &fn, int4 res) const
  {
    std::cout << "call|case=" << caseId << "|fn=" << fn
              << "|res=" << res << '\n';
    std::cout.flush();
  }
};

// ---------------------------------------------------------------------------
// C1 fold_relocate_fn: use-anchored dynamic entry + RulePropagateCopy fold.
//
//   op1@0x1000: c  = COPY 0x2a          (c: register 0x80)
//   op2@0x1010: t  = COPY c            (t: register 0x90, the temp the
//                                       dynamic entry is minted on)
//   op3@0x1020: r  = INT_ADD t, 1      (r: unique)
//
// The entry is minted USE-anchored (calcHash(op3, 0, 0) — t as input of
// op3), so the anchor address is the use point 0x1020.  The fold then
// rewires op3 to read c directly.  findVarnode gathers c at 0x1020 but the
// recomputed position hash (attached at op1, translated opcode 0) never
// equals the minted hash (attached at op3, INT_ADD) — the entry silently
// detaches and NO op is created anywhere: the oracle does not re-insert a
// COPY for the dynamic temp (kuna LOSS-229-CORRECTION candidate ③).
void runFoldRelocate(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x1000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x2a), 0);
  Varnode *c = fixture.regOut("c", 8, 0x80, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x1010);
  fd.opSetOpcode(op2, CPUI_COPY);
  fd.opSetInput(op2, c, 0);
  Varnode *t = fixture.regOut("t", 8, 0x90, op2);
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(2, 0x1020);
  fd.opSetOpcode(op3, CPUI_INT_ADD);
  fd.opSetInput(op3, t, 0);
  fd.opSetInput(op3, fd.newConstant(8, 1), 1);
  fixture.uniqOut(8, 0x500, op3);
  fd.opInsertEnd(op3, block);

  fd.setHighLevel();

  // Mint USE-anchored (the production calcHash(op, slot, method) entry a
  // use-point rename would produce).
  DynamicHash dhash;
  dhash.calcHash(op3, 0, 0);
  if (dhash.getHash() == 0)
    throw std::runtime_error("calcHash failed for the use anchor");
  Symbol *sym = fd.getScopeLocal()->addDynamicSymbol(
      "dsym_c1", types->getBase(8, TYPE_INT), dhash.getAddress(), dhash.getHash());
  std::cout << "mint|case=fold_relocate_fn|vn=t|H=0x" << std::hex << dhash.getHash()
            << "|U=0x" << dhash.getAddress().getOffset() << std::dec << '\n';
  std::cout.flush();

  fixture.vncensus("fold_relocate_fn", "pre");
  fixture.opcensus("fold_relocate_fn", "pre");
  fixture.dyncensus("fold_relocate_fn", "pre");

  // The fold: op3 re-reads c (RulePropagateCopy's IR effect).  op2 is left
  // alive-but-dead so the census varnodes stay valid (no DCE in the
  // fixture).
  fd.opSetInput(op3, c, 0);

  fixture.vncensus("fold_relocate_fn", "folded");
  fixture.opcensus("fold_relocate_fn", "folded");

  DynamicHash dhash2;
  int4 res = fd.attemptDynamicMapping(sym->getFirstWholeMap(), dhash2) ? 1 : 0;
  fixture.call("fold_relocate_fn", "attemptDynamicMapping", res);
  fixture.vncensus("fold_relocate_fn", "after");
  fixture.opcensus("fold_relocate_fn", "after");
  fixture.dyncensus("fold_relocate_fn", "after");
}

// ---------------------------------------------------------------------------
// C1b refind_attach_fn: the baseline success path.  The IR is unchanged
// between mint and locate, so the def-anchored uniqueHash re-finds t,
// attaches symbol properties (mapped=1) and the second call is rejected by
// the already-labelled guard.  Zero new ops in every stage.
void runRefindAttach(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x1100);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x33), 0);
  Varnode *c = fixture.regOut("c", 8, 0x81, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x1110);
  fd.opSetOpcode(op2, CPUI_COPY);
  fd.opSetInput(op2, c, 0);
  Varnode *t = fixture.regOut("t", 8, 0x91, op2);
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(2, 0x1120);
  fd.opSetOpcode(op3, CPUI_INT_ADD);
  fd.opSetInput(op3, t, 0);
  fd.opSetInput(op3, fd.newConstant(8, 2), 1);
  fixture.uniqOut(8, 0x510, op3);
  fd.opInsertEnd(op3, block);

  fd.setHighLevel();
  std::pair<SymbolEntry *, string> minted =
      fixture.mintDynamic("refind_attach_fn", "dsym_c1b", t, types->getBase(8, TYPE_INT));

  fixture.vncensus("refind_attach_fn", "pre");
  fixture.opcensus("refind_attach_fn", "pre");

  DynamicHash dhash;
  int4 res = fd.attemptDynamicMapping(minted.first, dhash) ? 1 : 0;
  fixture.call("refind_attach_fn", "attemptDynamicMapping", res);
  fixture.vncensus("refind_attach_fn", "after1");
  fixture.opcensus("refind_attach_fn", "after1");

  DynamicHash dhash2;
  int4 res2 = fd.attemptDynamicMapping(minted.first, dhash2) ? 1 : 0;
  fixture.call("refind_attach_fn", "attemptDynamicMapping_second", res2);
  fixture.vncensus("refind_attach_fn", "after2");
  fixture.dyncensus("refind_attach_fn", "after2");
}

// ---------------------------------------------------------------------------
// C2 late_cast_retarget: attemptDynamicMappingLate on an implied
// CAST-adjacent temp.  The oracle re-targets the symbol to the explicit
// varnode on the other side of the CAST (funcdata_varnode.cc:1373-1386),
// so c0 — not tmp — ends up mapped.
void runLateCastRetarget(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x2000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x5a), 0);
  Varnode *c0 = fixture.regOut("c0", 8, 0xa0, op1);
  c0->setExplicit();  // the ActionMarkExplicit shape
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x2010);
  fd.opSetOpcode(op2, CPUI_CAST);
  fd.opSetInput(op2, c0, 0);
  Varnode *tmp = fixture.regOut("tmp", 8, 0xa8, op2);
  tmp->setImplied();  // the ActionMarkImplied shape
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(2, 0x2020);
  fd.opSetOpcode(op3, CPUI_INT_ADD);
  fd.opSetInput(op3, tmp, 0);
  fd.opSetInput(op3, fd.newConstant(8, 2), 1);
  fixture.uniqOut(8, 0x520, op3);
  fd.opInsertEnd(op3, block);

  fd.setHighLevel();
  std::pair<SymbolEntry *, string> minted =
      fixture.mintDynamic("late_cast_retarget", "late_sym", tmp, types->getBase(8, TYPE_UINT));

  fixture.vncensus("late_cast_retarget", "pre");
  fixture.opcensus("late_cast_retarget", "pre");

  DynamicHash dhash;
  int4 res = fd.attemptDynamicMappingLate(minted.first, dhash) ? 1 : 0;
  fixture.call("late_cast_retarget", "attemptDynamicMappingLate", res);
  fixture.vncensus("late_cast_retarget", "after");
  fixture.opcensus("late_cast_retarget", "after");
  fixture.dyncensus("late_cast_retarget", "after");
}

// ---------------------------------------------------------------------------
// C3 trim_dynamic_high: the merge_trim_lane T1 CMOV diamond with a dynamic
// entry minted on X.  mergeAddrTied + mergeMarker insert the cover-driven
// trim COPYs; merge never consults the dynamic entry (count unchanged, no
// attach), and the follow-up ActionDynamicSymbols creates no ops — the
// trim-broken hash simply detaches.  This is the merge-side falsification
// of candidate ③: trims are cover-driven only.
void runTrimDynamicHigh(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();

  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  vector<BlockBasic *> blocks;
  for(int4 i = 0; i < 5; ++i)
    blocks.push_back(graph.newBlockBasic(&fd));
  BlockBasic *b0 = blocks[0];
  BlockBasic *b1 = blocks[1];
  BlockBasic *b2 = blocks[2];
  BlockBasic *b3 = blocks[3];
  BlockBasic *b4 = blocks[4];
  graph.addEdge(b0, b1);
  graph.addEdge(b1, b2);
  graph.addEdge(b1, b3);
  graph.addEdge(b2, b3);
  graph.addEdge(b3, b4);

  PcodeOp *defX = fd.newOp(1, Address(codeSpace, 0x3000));
  fd.opSetOpcode(defX, CPUI_COPY);
  Varnode *X = fixture.regOut("X", 4, 0x20, defX);
  fd.opSetInput(defX, fd.newConstant(4, 0x1234), 0);
  fd.opInsertEnd(defX, b0);

  AddrSpace *uniqueSpace = fd.getArch()->getSpaceByName("unique");
  Varnode *boolvn = fd.newVarnode(1, Address(uniqueSpace, 0x900));
  PcodeOp *fxOp = fd.newOp(2, Address(codeSpace, 0x3010));
  fd.opSetOpcode(fxOp, CPUI_INT_RIGHT);
  Varnode *fX = fd.newVarnodeOut(4, Address(uniqueSpace, 0x910), fxOp);
  fd.opSetInput(fxOp, X, 0);
  fd.opSetInput(fxOp, fd.newConstant(4, 16), 1);
  fd.opInsertEnd(fxOp, b1);

  PcodeOp *cbranch = fd.newOp(2, Address(codeSpace, 0x3018));
  fd.opSetOpcode(cbranch, CPUI_CBRANCH);
  fd.opSetInput(cbranch, fd.newConstant(8, 0x4000), 0);
  fd.opSetInput(cbranch, boolvn, 1);
  fd.opInsertEnd(cbranch, b1);

  PcodeOp *phi = fd.newOp(2, Address(codeSpace, 0x3030));
  fd.opSetOpcode(phi, CPUI_MULTIEQUAL);
  Varnode *phiout = fd.newVarnodeOut(4, Address(fd.getArch()->getSpaceByName("register"), 0x20), phi);
  fd.opSetInput(phi, X, 0);
  fd.opSetInput(phi, fX, 1);
  fd.opInsertBegin(phi, b3);
  fixture.rememberVarnode(phiout, "phiout");

  PcodeOp *reader = fd.newOp(2, Address(codeSpace, 0x3040));
  fd.opSetOpcode(reader, CPUI_INT_AND);
  fd.opSetInput(reader, phiout, 0);
  fd.opSetInput(reader, fd.newConstant(4, 0xff), 1);
  fd.newVarnodeOut(4, Address(uniqueSpace, 0x920), reader);
  fd.opInsertEnd(reader, b4);

  fd.setHighLevel();
  std::pair<SymbolEntry *, string> minted =
      fixture.mintDynamic("trim_dynamic_high", "x_dyn", X, types->getBase(4, TYPE_INT));

  fixture.vncensus("trim_dynamic_high", "pre");
  fixture.opcensusNames("trim_dynamic_high", "pre");
  fixture.dyncensus("trim_dynamic_high", "pre");

  fd.getMerge().mergeAddrTied();
  try {
    fd.getMerge().mergeMarker();
  }
  catch(const LowlevelError &) {}

  fixture.vncensus("trim_dynamic_high", "postmerge");
  fixture.opcensusNames("trim_dynamic_high", "postmerge");
  fixture.dyncensus("trim_dynamic_high", "postmerge");

  // Which varnode each phi lane reads now (identity via the registered
  // fixture varnodes X/fX; blocks are named by creation position b0..b4).
  for(int4 slot = 0; slot < 2; ++slot) {
    Varnode *lane = phi->getIn(slot);
    string desc;
    if (lane == X)
      desc = "X";
    else if (lane == fX)
      desc = "fX";
    else if (lane->isWritten() && lane->getDef()->code() == CPUI_COPY) {
      PcodeOp *trimOp = lane->getDef();
      FlowBlock *pbl = trimOp->getParent();
      Varnode *reads = trimOp->getIn(0);
      string readsName = (reads == X) ? "X" : ((reads == fX) ? "fX" : "?");
      string blkName = "?";
      for(size_t i = 0; i < 5; ++i) {
        if (blocks[i] == pbl) {
          blkName = "b" + std::to_string(i);
          break;
        }
      }
      desc = "copy@" + blkName + "(" + readsName + ")";
    }
    else
      desc = "?";
    std::cout << "phi|case=trim_dynamic_high|lane" << slot << "=" << desc << '\n';
  }
  std::cout.flush();

  // NOTE: ActionDynamicSymbols is deliberately NOT run on this post-merge
  // state: mergeMarker's LowlevelError aborts the whole decompile in
  // production, so the late action never observes it (the fixture's catch
  // exists only to inspect the trims).  The late action's walk behaviour is
  // pinned instead by action_late_walk on a clean state.
}

// ---------------------------------------------------------------------------
// C4 action_walk_level: ActionDynamicMapping::perform walks
// beginDynamic()/endDynamic() and performs the attach from the action
// level on the unchanged C1b shape — the attach the Rust-side registered
// stub does not perform (pinned on the Rust side of this fixture).
void runActionWalkLevel(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x4000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x77), 0);
  Varnode *c = fixture.regOut("c", 8, 0x82, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x4010);
  fd.opSetOpcode(op2, CPUI_COPY);
  fd.opSetInput(op2, c, 0);
  Varnode *t = fixture.regOut("t", 8, 0x92, op2);
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(2, 0x4020);
  fd.opSetOpcode(op3, CPUI_INT_ADD);
  fd.opSetInput(op3, t, 0);
  fd.opSetInput(op3, fd.newConstant(8, 3), 1);
  fixture.uniqOut(8, 0x530, op3);
  fd.opInsertEnd(op3, block);

  fd.setHighLevel();
  std::pair<SymbolEntry *, string> minted =
      fixture.mintDynamic("action_walk_level", "dsym_c4", t, types->getBase(8, TYPE_INT));

  fixture.vncensus("action_walk_level", "pre");
  fixture.opcensus("action_walk_level", "pre");

  ActionDynamicMapping action("dynamic");
  int4 status = action.perform(fd);
  std::cout << "act|case=action_walk_level|fn=ActionDynamicMapping|count="
            << action.count << "|status=" << status << '\n';
  std::cout.flush();
  fixture.vncensus("action_walk_level", "after");
  fixture.opcensus("action_walk_level", "after");
  fixture.dyncensus("action_walk_level", "after");
}

// ---------------------------------------------------------------------------
// C5 action_late_walk: ActionDynamicSymbols::perform on the clean C1b shape
// (the production state the late action actually observes — no merge threw,
// no ops died).  The oracle walks beginDynamic()/endDynamic() and performs
// the late attach from the action level; pins the action-level behaviour
// (Rugra's registered stub is inert — pinned on the Rust side).
void runActionLateWalk(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x5000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x88), 0);
  Varnode *c = fixture.regOut("c", 8, 0x83, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x5010);
  fd.opSetOpcode(op2, CPUI_COPY);
  fd.opSetInput(op2, c, 0);
  Varnode *t = fixture.regOut("t", 8, 0x93, op2);
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(2, 0x5020);
  fd.opSetOpcode(op3, CPUI_INT_ADD);
  fd.opSetInput(op3, t, 0);
  fd.opSetInput(op3, fd.newConstant(8, 4), 1);
  fixture.uniqOut(8, 0x540, op3);
  fd.opInsertEnd(op3, block);

  fd.setHighLevel();
  std::pair<SymbolEntry *, string> minted =
      fixture.mintDynamic("action_late_walk", "dsym_c5", t, types->getBase(8, TYPE_INT));

  fixture.vncensus("action_late_walk", "pre");
  fixture.opcensus("action_late_walk", "pre");

  ActionDynamicSymbols action("dynamic");
  int4 status = action.perform(fd);
  std::cout << "act|case=action_late_walk|fn=ActionDynamicSymbols|count="
            << action.count << "|status=" << status << '\n';
  std::cout.flush();
  fixture.vncensus("action_late_walk", "after");
  fixture.opcensus("action_late_walk", "after");
  fixture.dyncensus("action_late_walk", "after");
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
    runFoldRelocate(*fd);
    runRefindAttach(*fd);
    runLateCastRetarget(*fd);
    runTrimDynamicHigh(*fd);
    runActionWalkLevel(*fd);
    runActionLateWalk(*fd);
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: copytrim_remat_1204 SPEC_ROOT CURL_BINARY\n";
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
