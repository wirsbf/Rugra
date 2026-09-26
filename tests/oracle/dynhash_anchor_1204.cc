/*
 * Locked Ghidra 12.0.4 oracle fixture for DYNHASH-UNIQUE-ANCHOR-0001
 * (CASTFUSE-A correction root-cause triplet, piece 1): the
 * calcHash(Varnode*, method) sub-graph walk and uniqueHash(Varnode*)
 * champion selection must produce byte-identical hashes to the Rust port.
 *
 * Primary-source reading of the locked oracle (dynamic.cc:268-316
 * calcHash(Varnode*), dynamic.cc:323-381 pieceTogetherHash,
 * dynamic.cc:424-477 uniqueHash(Varnode*), dynamic.cc:561-580 findVarnode,
 * dynamic.cc:645-685 gatherFirstLevelVars):
 *   - the base level of EVERY calcHash(Varnode*, method) walk builds the
 *     root's UP edge (defining op, walking up through skip ops:
 *     dynamic.cc:277-278 uses a local index so vnproc is NOT consumed)
 *     AND the root's DOWN edges (every reader, walking down through skip
 *     ops: dynamic.cc:279-280 re-runs from vnproc=0).  A walk that skips
 *     the down pass loses the reader edges from the neighborhood CRC and
 *     mis-picks the attached anchor (the CAST-adjacent temp anchors at
 *     the defining COPY with the not-attached fallback bit instead of the
 *     attached reading op).
 *   - pieceTogetherHash picks the FIRST opedge entry whose slot varnode
 *     IS the root (attached); if every edge skips over the root it falls
 *     back to opedge[0] with the not-attached bit set (dynamic.cc:357-
 *     367) and gatherFirstLevelVars follows that bit through the skip op
 *     when re-finding (dynamic.cc:662-670 / 676-679).
 *   - uniqueHash escalates methods 0..3 keeping the FIRST smallest
 *     collision list as champion (dynamic.cc:453-458), but the emitted
 *     hash is the LAST method's tmphash (the loop variable escapes at
 *     dynamic.cc:474) with position/total bits from the champion list —
 *     pinned here by a deliberate all-method collision.
 *   - findVarnode requires the recomputed collision total to match
 *     exactly (dynamic.cc:578) and returns the varnode at the encoded
 *     position.
 *
 * Ten cases pin those semantics bilaterally (all MATCH; zero pinned
 * divergence — this fixture is minted after the Rust fix):
 *
 *   def_single_reader   base up+down edges, def anchor, champion=1@m0
 *   multi_reader_sort   3 readers created out of address order — the
 *                       newly added down edges are sorted
 *                       (ToOpEdge::operator<, dynamic.cc:147-148)
 *   cast_above          root = CAST output: up walk crosses the skip op,
 *                       anchor = attached reading op (not the def)
 *   cast_below          root read via a CAST feeding a real op: the down
 *                       walk crosses the skip op
 *   double_cast_chain   CAST(CHAIN(x)): multi-hop skip loop both ways;
 *                       the mid-chain temp pins the all-skip fallback
 *   skip_no_reader      CAST output with no reader: single not-attached
 *                       fallback edge + gatherFirstLevelVars redirection
 *   input_root          unwritten input varnode: no up edge, anchor =
 *                       first sorted reader edge
 *   const_root          constant root: offset bytes folded into the CRC
 *   champion_collision  two identical-shape temps (defs share an address,
 *                       readers share an address): every method collides;
 *                       champion = method-0 list, hash = method-3 bits,
 *                       position distinguishes t1/t2 through findVarnode
 *   fold_detach         def+use anchored mint, then the reader is folded
 *                       away: findVarnode fails (the silent detach)
 *
 * Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
 * Projections use stable fixture identities (varnode names, hex addresses,
 * decoded hash fields) — never pointers or SeqNums.
 */

#include <iomanip>
#include <iostream>
#include <map>
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
#include "dynamic.hh"
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

  /// Unwritten register-space input varnode (the Funcdata::newVarnode +
  /// setInputVarnode shape an unmapped register input takes: the input
  /// flag is what makes multiple descendants legal, varnode.cc:332-336).
  Varnode *regIn(const string &name, int4 size, uintb offset)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    if (registerSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires the register space");
    Varnode *vn = fd.newVarnode(size, Address(registerSpace, offset));
    fd.setInputVarnode(vn);
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

  /// Register a constant varnode as a fixture identity (const_root's
  /// mint target).
  Varnode *constRoot(const string &name, int4 size, uintb val)
  {
    Varnode *vn = fd.newConstant(size, val);
    rememberVarnode(vn, name);
    return vn;
  }

  /// calcHash(Varnode*, method) projection: the H and anchor address for
  /// each walk level 0..3.
  void dhLines(const string &caseId, const string &name, Varnode *vn)
  {
    for(uint4 method = 0; method < 4; ++method) {
      DynamicHash dhash;
      dhash.calcHash(vn, method);
      std::cout << "dh|case=" << caseId << "|vn=" << name
                << "|method=" << method
                << "|H=0x" << std::hex << dhash.getHash()
                << "|U=0x" << dhash.getAddress().getOffset() << std::dec
                << '\n';
    }
    std::cout.flush();
  }

  /// uniqueHash(Varnode*) projection: the minted hash plus every decoded
  /// field (method, opcode, slot, not-attached, position, total).
  uint8 uhLine(const string &caseId, const string &name, Varnode *vn)
  {
    DynamicHash dhash;
    dhash.uniqueHash(vn, &fd);
    if (dhash.getHash() == 0)
      throw std::runtime_error("uniqueHash failed");
    uint8 h = dhash.getHash();
    std::cout << "uh|case=" << caseId << "|vn=" << name
              << "|H=0x" << std::hex << h
              << "|U=0x" << dhash.getAddress().getOffset() << std::dec
              << "|meth=" << DynamicHash::getMethodFromHash(h)
              << "|opc=" << DynamicHash::getOpCodeFromHash(h)
              << "|slot=" << DynamicHash::getSlotFromHash(h)
              << "|nat=" << (DynamicHash::getIsNotAttached(h) ? 1 : 0)
              << "|pos=" << DynamicHash::getPositionFromHash(h)
              << "|tot=" << DynamicHash::getTotalFromHash(h)
              << '\n';
    std::cout.flush();
    return h;
  }

  Address uhAddress(const string &caseId, Varnode *vn)
  {
    DynamicHash dhash;
    dhash.uniqueHash(vn, &fd);
    if (dhash.getHash() == 0)
      throw std::runtime_error("uniqueHash failed");
    return dhash.getAddress();
  }

  /// findVarnode round-trip on the minted hash (name projection).
  void findLine(const string &caseId, const string &name,
                const Address &addr, uint8 h)
  {
    DynamicHash dhash;
    Varnode *got = dhash.findVarnode(&fd, addr, h);
    std::cout << "find|case=" << caseId << "|vn=" << name
              << "|got=" << (got == (Varnode *)0 ? string("none") : varnodeName(got))
              << "|ok=" << (got == (Varnode *)0 ? 0 : 1)
              << '\n';
    std::cout.flush();
  }

  void findLineStage(const string &caseId, const string &name,
                     const string &stage, const Address &addr, uint8 h)
  {
    DynamicHash dhash;
    Varnode *got = dhash.findVarnode(&fd, addr, h);
    std::cout << "find|case=" << caseId << "|vn=" << name
              << "|stage=" << stage
              << "|got=" << (got == (Varnode *)0 ? string("none") : varnodeName(got))
              << "|ok=" << (got == (Varnode *)0 ? 0 : 1)
              << '\n';
    std::cout.flush();
  }
};

// ---------------------------------------------------------------------------
// def_single_reader: COPY c := 0x11 @0x1000; COPY t := c @0x1010
// (t: register 0x90); INT_ADD r := t,1 @0x1020.
//
// Method 0 edges: up (COPY@0x1010,-1, attached) + down (ADD@0x1020,0) —
// the anchor is the DEF because the up edge comes first in opedge order
// and is attached.  Methods 1/2/3 add the level-1 neighborhoods.
void runDefSingleReader(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x1000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x11), 0);
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

  fixture.dhLines("def_single_reader", "t", t);
  uint8 h = fixture.uhLine("def_single_reader", "t", t);
  Address u = fixture.uhAddress("def_single_reader", t);
  fixture.findLine("def_single_reader", "t", u, h);
}

// ---------------------------------------------------------------------------
// multi_reader_sort: COPY t := 0x22 @0x2000 (t: register 0x90); readers
// created deliberately out of address order (0x2030 first, then 0x2010,
// then 0x2020).  buildVnDown must sort the newly added down edges by
// (SeqNum address, order, slot) before they are folded into the CRC
// (dynamic.cc:147-148).
void runMultiReaderSort(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *defT = fixture.makeOp(1, 0x2000);
  fd.opSetOpcode(defT, CPUI_COPY);
  fd.opSetInput(defT, fd.newConstant(8, 0x22), 0);
  Varnode *t = fixture.regOut("t", 8, 0x90, defT);
  fd.opInsertEnd(defT, block);

  PcodeOp *r3 = fixture.makeOp(2, 0x2030);
  fd.opSetOpcode(r3, CPUI_INT_OR);
  fd.opSetInput(r3, t, 0);
  fd.opSetInput(r3, fd.newConstant(8, 3), 1);
  fixture.uniqOut(8, 0x510, r3);
  fd.opInsertEnd(r3, block);

  PcodeOp *r1 = fixture.makeOp(2, 0x2010);
  fd.opSetOpcode(r1, CPUI_INT_AND);
  fd.opSetInput(r1, t, 0);
  fd.opSetInput(r1, fd.newConstant(8, 1), 1);
  fixture.uniqOut(8, 0x511, r1);
  fd.opInsertEnd(r1, block);

  PcodeOp *r2 = fixture.makeOp(2, 0x2020);
  fd.opSetOpcode(r2, CPUI_INT_XOR);
  fd.opSetInput(r2, fd.newConstant(8, 2), 0);
  fd.opSetInput(r2, t, 1);
  fixture.uniqOut(8, 0x512, r2);
  fd.opInsertEnd(r2, block);

  fd.setHighLevel();

  fixture.dhLines("multi_reader_sort", "t", t);
  uint8 h = fixture.uhLine("multi_reader_sort", "t", t);
  Address u = fixture.uhAddress("multi_reader_sort", t);
  fixture.findLine("multi_reader_sort", "t", u, h);
}

// ---------------------------------------------------------------------------
// cast_above: COPY c0 := 0x5a @0x3000 (c0: register 0xa0, explicit);
// CAST tmp := c0 @0x3010 (tmp: register 0xa8, implied; CAST is a skipped
// hash op); INT_ADD r := tmp,2 @0x3020.
//
// The up walk crosses the skip CAST, so the up edge (COPY@0x3000,-1) is
// NOT attached to tmp; the down edge (ADD@0x3020,0) IS — the anchor is
// the attached reading op, not the defining COPY of the pre-skip
// varnode.  (This is the exact shape the pre-fix Rust walk mis-anchored
// at 0x3000 with the fallback bit.)
void runCastAbove(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x3000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x5a), 0);
  Varnode *c0 = fixture.regOut("c0", 8, 0xa0, op1);
  c0->setExplicit();
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x3010);
  fd.opSetOpcode(op2, CPUI_CAST);
  fd.opSetInput(op2, c0, 0);
  Varnode *tmp = fixture.regOut("tmp", 8, 0xa8, op2);
  tmp->setImplied();
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(2, 0x3020);
  fd.opSetOpcode(op3, CPUI_INT_ADD);
  fd.opSetInput(op3, tmp, 0);
  fd.opSetInput(op3, fd.newConstant(8, 2), 1);
  fixture.uniqOut(8, 0x520, op3);
  fd.opInsertEnd(op3, block);

  fd.setHighLevel();

  fixture.dhLines("cast_above", "tmp", tmp);
  uint8 h = fixture.uhLine("cast_above", "tmp", tmp);
  Address u = fixture.uhAddress("cast_above", tmp);
  fixture.findLine("cast_above", "tmp", u, h);
}

// ---------------------------------------------------------------------------
// cast_below: COPY c0 := 0x66 @0x4000 (c0: register 0xa0, explicit);
// CAST tmp := c0 @0x4010 (tmp: register 0xa8, implied); INT_ADD r :=
// tmp,4 @0x4020.  Root = c0.
//
// The down walk from c0 crosses the skip CAST: the descendant edge is
// (ADD@0x4020, slot-of-tmp), folded into the CRC even though tmp — not
// c0 — is the slot varnode.  The up edge (COPY@0x4000,-1) is attached,
// so the anchor stays the def.
void runCastBelow(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x4000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x66), 0);
  Varnode *c0 = fixture.regOut("c0", 8, 0xa0, op1);
  c0->setExplicit();
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x4010);
  fd.opSetOpcode(op2, CPUI_CAST);
  fd.opSetInput(op2, c0, 0);
  Varnode *tmp = fixture.regOut("tmp", 8, 0xa8, op2);
  tmp->setImplied();
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(2, 0x4020);
  fd.opSetOpcode(op3, CPUI_INT_ADD);
  fd.opSetInput(op3, tmp, 0);
  fd.opSetInput(op3, fd.newConstant(8, 4), 1);
  fixture.uniqOut(8, 0x530, op3);
  fd.opInsertEnd(op3, block);

  fd.setHighLevel();

  fixture.dhLines("cast_below", "c0", c0);
  uint8 h = fixture.uhLine("cast_below", "c0", c0);
  Address u = fixture.uhAddress("cast_below", c0);
  fixture.findLine("cast_below", "c0", u, h);
}

// ---------------------------------------------------------------------------
// double_cast_chain: COPY c := 0x55 @0x5000; CAST t1 := c @0x5010;
// CAST t2 := t1 @0x5020; INT_ADD r := t2,7 @0x5030.
//
// t2 pins the multi-hop skip loop in buildVnUp (two CASTs crossed) with
// the anchor at the attached reading op.  t1 (mid-chain) has NO edge
// attached to it on either side: the up edge lands on c's COPY and the
// down edge carries t2's slot — the opedge[0] fallback with the
// not-attached bit fires (dynamic.cc:363-367).
void runDoubleCastChain(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x5000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x55), 0);
  Varnode *c = fixture.regOut("c", 8, 0x80, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x5010);
  fd.opSetOpcode(op2, CPUI_CAST);
  fd.opSetInput(op2, c, 0);
  Varnode *t1 = fixture.regOut("t1", 8, 0x88, op2);
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(1, 0x5020);
  fd.opSetOpcode(op3, CPUI_CAST);
  fd.opSetInput(op3, t1, 0);
  Varnode *t2 = fixture.regOut("t2", 8, 0x90, op3);
  fd.opInsertEnd(op3, block);

  PcodeOp *op4 = fixture.makeOp(2, 0x5030);
  fd.opSetOpcode(op4, CPUI_INT_ADD);
  fd.opSetInput(op4, t2, 0);
  fd.opSetInput(op4, fd.newConstant(8, 7), 1);
  fixture.uniqOut(8, 0x540, op4);
  fd.opInsertEnd(op4, block);

  fd.setHighLevel();

  fixture.dhLines("double_cast_chain", "t1", t1);
  uint8 h1 = fixture.uhLine("double_cast_chain", "t1", t1);
  Address u1 = fixture.uhAddress("double_cast_chain", t1);
  fixture.findLine("double_cast_chain", "t1", u1, h1);

  fixture.dhLines("double_cast_chain", "t2", t2);
  uint8 h2 = fixture.uhLine("double_cast_chain", "t2", t2);
  Address u2 = fixture.uhAddress("double_cast_chain", t2);
  fixture.findLine("double_cast_chain", "t2", u2, h2);
}

// ---------------------------------------------------------------------------
// skip_no_reader: COPY c := 0x77 @0x6000; CAST tmp := c @0x6010 with NO
// reader of tmp.
//
// Only one edge exists (the up edge through the skip CAST, not attached
// to tmp) — the opedge[0] fallback fires with the not-attached bit, and
// gatherFirstLevelVars must follow that bit through the skip op when
// re-finding (dynamic.cc:662-670): the gather starts from the COPY's
// output c, takes c's lone descendant (the CAST) and, because it is a
// skip op, returns the CAST's own output tmp.
void runSkipNoReader(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0x6000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x77), 0);
  Varnode *c = fixture.regOut("c", 8, 0x80, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0x6010);
  fd.opSetOpcode(op2, CPUI_CAST);
  fd.opSetInput(op2, c, 0);
  Varnode *tmp = fixture.regOut("tmp", 8, 0x88, op2);
  fd.opInsertEnd(op2, block);

  fd.setHighLevel();

  fixture.dhLines("skip_no_reader", "tmp", tmp);
  uint8 h = fixture.uhLine("skip_no_reader", "tmp", tmp);
  Address u = fixture.uhAddress("skip_no_reader", tmp);
  fixture.findLine("skip_no_reader", "tmp", u, h);
}

// ---------------------------------------------------------------------------
// input_root: i: register 0xb0 (unwritten input); INT_ADD a := i,1
// @0x7010; INT_SUB b := i,2 @0x7020.
//
// No up edge exists (i is not written); the anchor is the first sorted
// down edge, attached at slot 0 of the lower-address reader.
void runInputRoot(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  Varnode *i = fixture.regIn("i", 8, 0xb0);

  PcodeOp *op1 = fixture.makeOp(2, 0x7010);
  fd.opSetOpcode(op1, CPUI_INT_ADD);
  fd.opSetInput(op1, i, 0);
  fd.opSetInput(op1, fd.newConstant(8, 1), 1);
  fixture.uniqOut(8, 0x550, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(2, 0x7020);
  fd.opSetOpcode(op2, CPUI_INT_SUB);
  fd.opSetInput(op2, i, 0);
  fd.opSetInput(op2, fd.newConstant(8, 2), 1);
  fixture.uniqOut(8, 0x551, op2);
  fd.opInsertEnd(op2, block);

  fd.setHighLevel();

  fixture.dhLines("input_root", "i", i);
  uint8 h = fixture.uhLine("input_root", "i", i);
  Address u = fixture.uhAddress("input_root", i);
  fixture.findLine("input_root", "i", u, h);
}

// ---------------------------------------------------------------------------
// const_root: k = constant 4-byte 0x1337, read by INT_ADD a := k,1
// @0x8010 (slot 0) and INT_MULT m := 2,k @0x8020 (slot 1).
//
// pieceTogetherHash folds the root's size and offset bytes into the CRC
// (dynamic.cc:341-347); the anchor is the first sorted reader edge.
void runConstRoot(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  Varnode *k = fixture.constRoot("k", 4, 0x1337);

  PcodeOp *op1 = fixture.makeOp(2, 0x8010);
  fd.opSetOpcode(op1, CPUI_INT_ADD);
  fd.opSetInput(op1, k, 0);
  fd.opSetInput(op1, fd.newConstant(4, 1), 1);
  fixture.uniqOut(4, 0x560, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(2, 0x8020);
  fd.opSetOpcode(op2, CPUI_INT_MULT);
  fd.opSetInput(op2, fd.newConstant(4, 2), 0);
  fd.opSetInput(op2, k, 1);
  fixture.uniqOut(4, 0x561, op2);
  fd.opInsertEnd(op2, block);

  fd.setHighLevel();

  fixture.dhLines("const_root", "k", k);
  uint8 h = fixture.uhLine("const_root", "k", k);
  Address u = fixture.uhAddress("const_root", k);
  fixture.findLine("const_root", "k", u, h);
}

// ---------------------------------------------------------------------------
// champion_collision: two identical-shape temps whose defs share an
// address and whose readers share an address.
//
//   COPY t1 := 0x91 @0x9000 (order n);   COPY t2 := 0x92 @0x9000 (n+1)
//   INT_ADD r1 := t1,1 @0x9010 (n+2);   INT_ADD r2 := t2,2 @0x9010 (n+3)
//
// ToOpEdge::hash folds slot + translated opcode + the op ADDRESS only —
// never the SeqNum order or the (constant) input offsets — so t1 and t2
// produce IDENTICAL hashes at every method 0..3.  uniqueHash therefore:
//   - builds the champion from METHOD 0's collision list (first smallest
//     list wins, dynamic.cc:454-456),
//   - emits the METHOD 3 hash bits (tmphash escapes the loop,
//     dynamic.cc:474),
//   - encodes position 0/1 within the gather-ordered collision list.
// findVarnode recomputes with method 3, sees total=2 matches and returns
// the varnode at the encoded position — the two temps stay
// distinguishable through their hashes.
void runChampionCollision(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *d1 = fixture.makeOp(1, 0x9000);
  fd.opSetOpcode(d1, CPUI_COPY);
  fd.opSetInput(d1, fd.newConstant(8, 0x91), 0);
  Varnode *t1 = fixture.regOut("t1", 8, 0x90, d1);
  fd.opInsertEnd(d1, block);

  PcodeOp *d2 = fixture.makeOp(1, 0x9000);
  fd.opSetOpcode(d2, CPUI_COPY);
  fd.opSetInput(d2, fd.newConstant(8, 0x92), 0);
  Varnode *t2 = fixture.regOut("t2", 8, 0x91, d2);
  fd.opInsertEnd(d2, block);

  PcodeOp *r1 = fixture.makeOp(2, 0x9010);
  fd.opSetOpcode(r1, CPUI_INT_ADD);
  fd.opSetInput(r1, t1, 0);
  fd.opSetInput(r1, fd.newConstant(8, 1), 1);
  fixture.uniqOut(8, 0x570, r1);
  fd.opInsertEnd(r1, block);

  PcodeOp *r2 = fixture.makeOp(2, 0x9010);
  fd.opSetOpcode(r2, CPUI_INT_ADD);
  fd.opSetInput(r2, t2, 0);
  fd.opSetInput(r2, fd.newConstant(8, 2), 1);
  fixture.uniqOut(8, 0x571, r2);
  fd.opInsertEnd(r2, block);

  fd.setHighLevel();

  fixture.dhLines("champion_collision", "t1", t1);
  uint8 h1 = fixture.uhLine("champion_collision", "t1", t1);
  Address u1 = fixture.uhAddress("champion_collision", t1);
  fixture.findLine("champion_collision", "t1", u1, h1);

  fixture.dhLines("champion_collision", "t2", t2);
  uint8 h2 = fixture.uhLine("champion_collision", "t2", t2);
  Address u2 = fixture.uhAddress("champion_collision", t2);
  fixture.findLine("champion_collision", "t2", u2, h2);
}

// ---------------------------------------------------------------------------
// fold_detach: COPY c := 0x2a @0xa000; COPY t := c @0xa010 (t: register
// 0x90); INT_ADD r := t,1 @0xa020.  Mint the def-anchored uniqueHash on
// t, verify the round-trip, then fold the reader away (RulePropagateCopy's
// IR effect: the reader re-reads c).  The recomputed neighborhood hash of
// t no longer matches — findVarnode returns null and the entry silently
// detaches (no op is created anywhere).
void runFoldDetach(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);

  BlockBasic *block = fixture.makeBlock();

  PcodeOp *op1 = fixture.makeOp(1, 0xa000);
  fd.opSetOpcode(op1, CPUI_COPY);
  fd.opSetInput(op1, fd.newConstant(8, 0x2a), 0);
  Varnode *c = fixture.regOut("c", 8, 0x80, op1);
  fd.opInsertEnd(op1, block);

  PcodeOp *op2 = fixture.makeOp(1, 0xa010);
  fd.opSetOpcode(op2, CPUI_COPY);
  fd.opSetInput(op2, c, 0);
  Varnode *t = fixture.regOut("t", 8, 0x90, op2);
  fd.opInsertEnd(op2, block);

  PcodeOp *op3 = fixture.makeOp(2, 0xa020);
  fd.opSetOpcode(op3, CPUI_INT_ADD);
  fd.opSetInput(op3, t, 0);
  fd.opSetInput(op3, fd.newConstant(8, 1), 1);
  fixture.uniqOut(8, 0x580, op3);
  fd.opInsertEnd(op3, block);

  fd.setHighLevel();

  fixture.dhLines("fold_detach", "t", t);
  uint8 h = fixture.uhLine("fold_detach", "t", t);
  Address u = fixture.uhAddress("fold_detach", t);
  fixture.findLineStage("fold_detach", "t", "pre", u, h);

  // The fold: op3 re-reads c.  op2 is left alive-but-dead so the census
  // varnodes stay valid (no DCE in the fixture).
  fd.opSetInput(op3, c, 0);

  fixture.findLineStage("fold_detach", "t", "postfold", u, h);
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
    runDefSingleReader(*fd);
    runMultiReaderSort(*fd);
    runCastAbove(*fd);
    runCastBelow(*fd);
    runDoubleCastChain(*fd);
    runSkipNoReader(*fd);
    runInputRoot(*fd);
    runConstRoot(*fd);
    runChampionCollision(*fd);
    runFoldDetach(*fd);
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: dynhash_anchor_1204 SPEC_ROOT CURL_BINARY\n";
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
