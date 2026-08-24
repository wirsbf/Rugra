/*
 * JUSTIFIED-CONTAIN-1204: locked Ghidra 12.0.4 oracle for the
 * FSPEC-JUSTIFIED-CONTAIN-0001 polarity fix.
 *
 *  - Address::justifiedContain (address.cc:131-141) excludes containment
 *    when EITHER side pokes out independently: `if (op2.offset < offset)
 *    return -1;` then `if (off2 > off1) return -1;`. Equal-start-bigger
 *    queries, low-side overlaps ending flush at the entry end, and
 *    supersets must all return -1 on every endianness/forceleft branch.
 *    The fixture probes a little-endian and a big-endian processor space;
 *    `view=start` rows serialize the `op2.offset - offset` branch (LE
 *    space, forceleft=false) and `view=end` rows the `off1 - off2` branch
 *    (BE space, forceleft=false). The harness additionally verifies
 *    internally that LE(false) == LE(true) == BE(true) for every geometry
 *    (all start-distance), exiting non-zero on violation.
 *  - ParamEntry::justifiedContain (fspec.cc:248-283) alignment==0 path:
 *    an LE exclusion entry with force_left_justify (start-distance) and a
 *    BE entry without the flag (end-distance), including the -1 polarity
 *    geometries through the real entry wrapper.
 *  - ParamListStandard::characterizeAsParam (fspec.cc:682-719): the
 *    contains_justified / contains_unjustified / contained_by /
 *    no_containment decision chain over a single 4-byte LE exclusion
 *    force-left entry. Queries keep their start offset inside the entry
 *    extent (resolver find(loc) gating; foreign-start geometries are out
 *    of this fixture's covered projection).
 *
 * ParamEntry/ParamListStandard construction uses the same class->struct
 * access hack as the fspec_phase0 fixture; every observation goes through
 * public members only.
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
// setters) — same pattern as the fspec_phase0 fixture.
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

// 17 geometries: exact/sub-range size boundaries (1, 4, 8, cross-4), the
// one-sided-violation polarity set (equal-start-bigger, low overlap flush
// at entry end, superset, high poke, low overlap ending inside, size-1
// entry pokes), pinned against address.cc:131-141.
static const JcGeom GEOMS[] = {
  {0x1000, 8, 0x1000, 8},   // exact
  {0x1000, 8, 0x1000, 4},   // low sub-range
  {0x1000, 8, 0x1002, 4},   // mid sub-range
  {0x1000, 8, 0x1004, 4},   // high sub-range flush at entry end
  {0x1000, 8, 0x1003, 1},   // size-1 sub-range
  {0x1000, 8, 0x1000, 1},   // size-1 justified sub-range
  {0x1000, 8, 0x1000, 12},  // equal start, query pokes out high
  {0x1000, 8, 0xFFE, 10},   // low overlap ending flush at entry end
  {0x1000, 8, 0xFFC, 16},   // strict superset
  {0x1000, 8, 0x1004, 8},   // high-side partial overlap from inside
  {0x1000, 8, 0xFFE, 6},    // low overlap ending inside
  {0x2000, 4, 0x1FFE, 8},   // cross-4 superset of the 4-byte entry
  {0x2000, 4, 0x2002, 4},   // cross-4 high poke
  {0x2000, 4, 0x2000, 4},   // exact 4-byte entry
  {0x3000, 1, 0x3000, 1},   // exact 1-byte entry
  {0x3000, 1, 0x3000, 2},   // size-1 entry, equal-start-bigger
  {0x3000, 1, 0x2FFF, 3},   // size-1 entry, strict superset
};

int main(void) {
  std::cout << "schema=1|fixture=JUSTIFIED-CONTAIN-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  FixtureTranslate tr;
  AddrSpace *ram, *ram_be;
  buildSpaces(&tr, ram, ram_be);

  // ---- case 1: Address::justifiedContain polarity + branch arithmetic --
  std::cout << "case=address_justified_contain" << std::endl;
  for (const JcGeom &g : GEOMS) {
    Address le_entry(ram, g.base);
    Address le_query(ram, g.qoff);
    Address be_entry(ram_be, g.base);
    Address be_query(ram_be, g.qoff);
    int4 le_false = le_entry.justifiedContain(g.esz, le_query, g.qsz, false);
    int4 le_true = le_entry.justifiedContain(g.esz, le_query, g.qsz, true);
    int4 be_false = be_entry.justifiedContain(g.esz, be_query, g.qsz, false);
    int4 be_true = be_entry.justifiedContain(g.esz, be_query, g.qsz, true);
    // All forceleft/LE combinations except (BE,false) produce the
    // start-distance branch (address.cc:138-140).
    if (le_false != le_true || le_true != be_true) {
      std::cerr << "branch consistency violation at base=0x" << std::hex
                << g.base << " esz=" << std::dec << g.esz << std::endl;
      return 1;
    }
    std::cout << "  jc base=0x" << std::hex << g.base << " esz=" << std::dec
              << g.esz << " qoff=0x" << std::hex << g.qoff << " qsz="
              << std::dec << g.qsz << " view=start off=" << le_false
              << std::endl;
    std::cout << "  jc base=0x" << std::hex << g.base << " esz=" << std::dec
              << g.esz << " qoff=0x" << std::hex << g.qoff << " qsz="
              << std::dec << g.qsz << " view=end off=" << be_false
              << std::endl;
  }

  // ---- case 2: ParamEntry::justifiedContain alignment==0 path ---------
  std::cout << "case=param_entry_justified_contain" << std::endl;
  {
    // LE exclusion entry with force_left_justify: start-distance branch.
    ParamEntry le = makeEntry(0, ram, 0x100, 8, 1, 0,
                              ParamEntry::force_left_justify);
    struct PeCase { uintb qoff; int4 qsz; };
    const PeCase lec[] = {
      {0x100, 8},   // exact
      {0x100, 4},   // justified sub-range (forceleft)
      {0x102, 4},   // unjustified sub-range
      {0x106, 2},   // sub-range flush with the high end
      {0x103, 1},   // size-1 sub-range
      {0x100, 12},  // equal start, pokes out high -> -1
      {0xFE, 4},    // low overlap ending inside -> -1
      {0x100, 16},  // strict superset -> -1
      {0x104, 8},   // high poke -> -1
      {0x10C, 2},   // fully above -> -1
      {0xFC, 4},    // fully below -> -1
    };
    for (const PeCase &c : lec) {
      int4 off = le.justifiedContain(Address(ram, c.qoff), c.qsz);
      std::cout << "  pe be=0 qoff=0x" << std::hex << c.qoff << " qsz="
                << std::dec << c.qsz << " off=" << off << std::endl;
    }
    // BE exclusion entry without the flag: end-distance branch.
    ParamEntry be = makeEntry(1, ram_be, 0x100, 8, 1, 0, 0);
    const PeCase bec[] = {
      {0x100, 8},   // exact
      {0x100, 4},   // sub-range at the low end -> off1 - off2 = 4
      {0x106, 2},   // sub-range flush with the high end -> 0
      {0x103, 1},   // size-1 sub-range -> 4
      {0x100, 12},  // equal start, pokes out high -> -1
      {0xFE, 8},    // low overlap ending flush at entry end -> -1
    };
    for (const PeCase &c : bec) {
      int4 off = be.justifiedContain(Address(ram_be, c.qoff), c.qsz);
      std::cout << "  pe be=1 qoff=0x" << std::hex << c.qoff << " qsz="
                << std::dec << c.qsz << " off=" << off << std::endl;
    }
  }

  // ---- case 3: characterizeAsParam three-way classification ----------
  std::cout << "case=characterize_projection" << std::endl;
  {
    ParamListStandard stds;
    stds.entry.push_back(makeEntry(0, ram, 0x100, 4, 1, 0,
                                   ParamEntry::force_left_justify));
    stds.numgroup = 1;
    stds.populateResolver();
    struct ChCase { uintb qoff; int4 qsz; };
    const ChCase chc[] = {
      {0x100, 4},  // exact -> contains_justified
      {0x100, 1},  // size-1 justified sub-range -> contains_justified
      {0x102, 2},  // unjustified sub-range -> contains_unjustified
      {0x103, 1},  // size-1 sub-range at the high end -> contains_unjustified
      {0x100, 6},  // equal start, pokes out -> contained_by
      {0x100, 8},  // size-8 over a 4-byte entry -> contained_by
      {0x102, 4},  // high poke, entry not inside query -> no_containment
      {0x101, 4},  // staggered poke -> no_containment
    };
    for (const ChCase &c : chc) {
      int4 cls = stds.characterizeAsParam(Address(ram, c.qoff), c.qsz);
      std::cout << "  ch qoff=0x" << std::hex << c.qoff << " qsz=" << std::dec
                << c.qsz << " cls=" << cls << std::endl;
    }
  }

  return 0;
}
