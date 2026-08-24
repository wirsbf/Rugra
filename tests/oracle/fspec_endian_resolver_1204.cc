/*
 * FSPEC-ENDIAN-RESOLVER-1204: locked Ghidra 12.0.4 oracle for the
 * FSPEC-JUSTIFIED-ENDIAN-0002 and FSPEC-CHARACTERIZE-RESOLVER-GATE-0003
 * fixes.
 *
 *  - case=le_forceleft_routing: Address::justifiedContain
 *    (address.cc:131-141) over the full LE/BE x forceleft matrix. The
 *    decisive semantics of ENDIAN-0002: the branch key is
 *    `base->isBigEndian() && !forceleft` (cc:138) — the endianness comes
 *    from the address's SPACE, not from forceleft — so a little-endian
 *    space returns the start distance `op2.offset - offset` even with
 *    forceleft=false. Only (BE,false) rows print the end distance
 *    `off1 - off2`.
 *  - case=param_entry_le_unflagged: ParamEntry::justifiedContain
 *    (fspec.cc:248-283) alignment==0 wrapper over an UNFLAGGED
 *    little-endian exclusion entry (8B@0x100). This is the `==0`
 *    determination route affected by ENDIAN-0002: LE unflagged pins the
 *    start distance (a sub-range at the low end is justified, a flush
 *    high sub-range is NOT 0).
 *  - case=truncate_subpiece: the exact heritage.cc:1221 call shape
 *    `addr.justifiedContain(size, truncAddr, vData.size, false)` for the
 *    Heritage::guardCallOverlappingInput SUBPIECE constant, on both the
 *    LE and the BE processor space: heritage range (addr,size) with the
 *    contained parameter (truncAddr,vData.size). LE rows must print the
 *    start distance truncAddr-addr (ENDIAN-0002), BE rows the end
 *    distance (addr+size-1)-(truncAddr+vData.size-1).
 *  - case=characterize_resolver_gate: ParamListStandard::
 *    characterizeAsParam (fspec.cc:682-719) over two unflagged LE
 *    exclusion entries (4B@0x100, 8B@0x200) with populateResolver.
 *    Extent-out queries pin the RESOLVER-GATE-0003 structure: phase 1
 *    only visits entries whose registered extent contains the query
 *    start; the second containedBy scan runs only when some registered
 *    extent starts above the query start (cc:708
 *    iterpair.first != resolver->end()); a query start above every
 *    extent skips the containedBy scan entirely and returns
 *    no_containment.
 *
 * ParamEntry/ParamListStandard construction uses the same class->struct
 * access hack as the justified_contain_1204 fixture; every observation
 * goes through public members only.
 */

#include <bits/stdc++.h>

#define class struct
#define private public
#define protected public
#include "fspec.hh"
#include "opcodes.hh"
#include "space.hh"
#include "translate.hh"
#undef protected
#undef private
#undef class

using namespace ghidra;

class FixtureTranslate final : public Translate {
public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
  }

  std::string tryInsertSpace(AddrSpace *spc) {
    try {
      insertSpace(spc);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    static VarnodeData dummy;
    return dummy;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

// canonical synthetic spaces: constant=0, other=1, unique=2, ram=3 (LE),
// ram_be=4 (BE) — the LE/BE pair is the decisive endianness control.
static void buildSpaces(FixtureTranslate *tr, AddrSpace *&ram, AddrSpace *&ram_be) {
  tr->tryInsertSpace(new ConstantSpace(tr, tr));
  tr->tryInsertSpace(new OtherSpace(tr, tr, OtherSpace::INDEX));
  tr->tryInsertSpace(new UniqueSpace(tr, tr, 2, 0));
  ram = new AddrSpace(tr, tr, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                      AddrSpace::hasphysical, 0, 0);
  ram_be = new AddrSpace(tr, tr, IPTR_PROCESSOR, "ram_be", true, 8, 1, 4,
                         AddrSpace::hasphysical, 0, 0);
  tr->tryInsertSpace(ram);
  tr->tryInsertSpace(ram_be);
}

// Fill ParamEntry fields directly (Ghidra fills them in decode(); the
// fixture replicates a staged cspec loader, mirroring Rugra's builder
// setters) — same pattern as the justified_contain_1204 fixture.
static ParamEntry makeEntry(int4 grp, AddrSpace *spc, uintb base, int4 size,
                            int4 minsize, int4 alignment, uint4 flags) {
  ParamEntry e(grp);
  e.flags = flags;
  e.type = TYPECLASS_GENERAL;
  e.groupSet.clear();
  e.groupSet.push_back(grp);
  e.spaceid = spc;
  e.addressbase = base;
  e.size = size;
  e.minsize = minsize;
  e.alignment = alignment;
  e.numslots = (alignment != 0) ? (size / alignment) : 1;
  e.joinrec = (JoinRecord *)0;
  return e;
}

struct JcGeom { uintb base; int4 esz; uintb qoff; int4 qsz; };

// Geometries where the start and end distances differ (plus one exact
// and one equal-start-bigger violation), pinned against the
// LE/BE x forceleft branch matrix of address.cc:138-141.
static const JcGeom GEOMS[] = {
  {0x1000, 8, 0x1000, 8},   // exact: every branch 0
  {0x1000, 8, 0x1000, 4},   // low sub-range: start 0, end 4
  {0x1000, 8, 0x1003, 1},   // size-1 high byte: start 3, end 0
  {0x1000, 8, 0x1002, 4},   // mid sub-range: start 2, end 2
  {0x2000, 4, 0x2000, 1},   // size-1 low byte of a 4B entry: start 0, end 3
  {0x2000, 4, 0x2003, 1},   // size-1 high byte of a 4B entry: start 3, end 0
  {0x1000, 8, 0x1000, 12},  // equal start, pokes out high -> -1 everywhere
};

struct TrGeom { uintb addr; int4 size; uintb toff; int4 tsz; };

// heritage.cc:1221 shapes: heritage range (addr,size) properly
// containing the callee parameter (truncAddr, vData.size), plus one
// poke-out violation.
static const TrGeom TRGEOMS[] = {
  {0x1000, 16, 0x1004, 4},  // LE 4, BE 8
  {0x1000, 16, 0x1000, 8},  // LE 0, BE 8
  {0x2000, 8, 0x2006, 2},   // LE 6, BE 0
  {0x2000, 8, 0x2002, 4},   // LE 2, BE 2
  {0x2000, 4, 0x2000, 8},   // param pokes out high -> -1 both spaces
};

int main(void) {
  std::cout << "schema=1|fixture=FSPEC-ENDIAN-RESOLVER-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  FixtureTranslate tr;
  AddrSpace *ram, *ram_be;
  buildSpaces(&tr, ram, ram_be);

  // ---- case 1: LE/BE x forceleft branch matrix -----------------------
  std::cout << "case=le_forceleft_routing" << std::endl;
  for (const JcGeom &g : GEOMS) {
    Address le_entry(ram, g.base);
    Address le_query(ram, g.qoff);
    Address be_entry(ram_be, g.base);
    Address be_query(ram_be, g.qoff);
    int4 off[2][2];
    off[0][0] = le_entry.justifiedContain(g.esz, le_query, g.qsz, false);
    off[0][1] = le_entry.justifiedContain(g.esz, le_query, g.qsz, true);
    off[1][0] = be_entry.justifiedContain(g.esz, be_query, g.qsz, false);
    off[1][1] = be_entry.justifiedContain(g.esz, be_query, g.qsz, true);
    // ENDIAN-0002 invariant: an LE space ignores forceleft (both rows
    // equal); a BE space with forceleft=true falls back to the start
    // distance (== LE rows).
    if (off[0][0] != off[0][1] || off[0][1] != off[1][1]) {
      std::cerr << "LE(false)/LE(true)/BE(true) divergence at base=0x"
                << std::hex << g.base << std::endl;
      return 1;
    }
    for (int be = 0; be < 2; ++be) {
      for (int fl = 0; fl < 2; ++fl) {
        std::cout << "  jc base=0x" << std::hex << g.base << " esz="
                  << std::dec << g.esz << " qoff=0x" << std::hex << g.qoff
                  << " qsz=" << std::dec << g.qsz << " fl=" << fl
                  << " be=" << be << " off=" << off[be][fl] << std::endl;
      }
    }
  }

  // ---- case 2: unflagged LE exclusion entry through the wrapper ------
  std::cout << "case=param_entry_le_unflagged" << std::endl;
  {
    ParamEntry le = makeEntry(0, ram, 0x100, 8, 1, 0, 0);
    struct PeCase { uintb qoff; int4 qsz; };
    const PeCase lec[] = {
      {0x100, 8},   // exact -> 0
      {0x100, 4},   // low sub-range -> start distance 0 (==0 justified!)
      {0x102, 4},   // unjustified sub-range -> 2
      {0x106, 2},   // flush with the high end -> 6 (NOT 0 on LE)
      {0x103, 1},   // size-1 sub-range -> 3
      {0x100, 12},  // equal start, pokes out high -> -1
      {0xFE, 4},    // low overlap ending inside -> -1
      {0x104, 8},   // high poke -> -1
    };
    for (const PeCase &c : lec) {
      int4 off = le.justifiedContain(Address(ram, c.qoff), c.qsz);
      std::cout << "  pe qoff=0x" << std::hex << c.qoff << " qsz="
                << std::dec << c.qsz << " off=" << off << std::endl;
    }
  }

  // ---- case 3: heritage truncate_amount SUBPIECE constant ------------
  std::cout << "case=truncate_subpiece" << std::endl;
  for (const TrGeom &g : TRGEOMS) {
    int4 amt_le = Address(ram, g.addr).justifiedContain(
        g.size, Address(ram, g.toff), g.tsz, false);
    int4 amt_be = Address(ram_be, g.addr).justifiedContain(
        g.size, Address(ram_be, g.toff), g.tsz, false);
    std::cout << "  tr spc=le addr=0x" << std::hex << g.addr << " size="
              << std::dec << g.size << " toff=0x" << std::hex << g.toff
              << " tsz=" << std::dec << g.tsz << " amt=" << amt_le
              << std::endl;
    std::cout << "  tr spc=be addr=0x" << std::hex << g.addr << " size="
              << std::dec << g.size << " toff=0x" << std::hex << g.toff
              << " tsz=" << std::dec << g.tsz << " amt=" << amt_be
              << std::endl;
  }

  // ---- case 4: characterizeAsParam resolver gating -------------------
  std::cout << "case=characterize_resolver_gate" << std::endl;
  {
    ParamListStandard stds;
    stds.entry.push_back(makeEntry(0, ram, 0x100, 4, 1, 0, 0));
    stds.entry.push_back(makeEntry(1, ram, 0x200, 8, 1, 0, 0));
    stds.numgroup = 2;
    stds.populateResolver();
    struct ChCase { uintb qoff; int4 qsz; };
    const ChCase chc[] = {
      {0x150, 0x20},  // start between extents, range overlaps nothing -> 0
      {0x150, 0x100}, // start between, range covers E2 -> 3 (phase-2 scan)
      {0x300, 8},     // start above every extent -> gate closed -> 0
      {0x80, 0x90},   // start below E1, range covers E1 -> 3
      {0x200, 8},     // exact E2 -> 2
      {0x202, 4},     // unjustified inside E2 -> 1
      {0x200, 16},    // equal-start pokes out of E2 -> 3
      {0x1F0, 0x18},  // start below E2, range covers it exactly -> 3
      {0x104, 8},     // start between extents (above E1, below E2) -> 0
      {0xF0, 4},      // start below every extent, covers nothing -> 0
      {0x80, 0x200},  // start below, range covers both -> 3
      {0x204, 8},     // start inside E2, pokes high -> 0
    };
    for (const ChCase &c : chc) {
      int4 cls = stds.characterizeAsParam(Address(ram, c.qoff), c.qsz);
      std::cout << "  ch qoff=0x" << std::hex << c.qoff << " qsz="
                << std::dec << c.qsz << " cls=" << cls << std::endl;
    }
  }

  return 0;
}
