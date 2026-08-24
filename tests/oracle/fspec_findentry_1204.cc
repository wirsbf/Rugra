/*
 * FSPEC-FINDENTRY-1204: locked Ghidra 12.0.4 oracle for the
 * FSPEC-FINDENTRY-GATE-0005 fix (join coverage for
 * FSPEC-RESOLVER-JOIN-WINDOW-0004).
 *
 *  - case=find_window_gate: ParamListStandard::findEntry
 *    (fspec.cc:661-680) over five plain exclusion entries.
 *    findEntry resolves through the per-space resolverMap and visits
 *    ONLY the resolver->find(loc.getOffset()) window (rangemap.hh:332):
 *    entries whose registered extent numerically contains the query
 *    start in the query's space. The decisive GATE rows: with just=false
 *    an extent-out query (below/between/above every extent of the
 *    space) returns NULL — the window is empty BEFORE the minSize and
 *    justified checks run — and a minSize-failing in-window query
 *    returns NULL because earlier list entries are not in the window.
 *    The in-window overlap row pins the (last, position) iteration
 *    order: the find window is one refined subinterval, so its records
 *    share the `last` key and iterate in position order = entry list
 *    registration order.
 *  - case=join_piece_access: populateResolver (fspec.cc:1191-1216)
 *    registers a join entry PER PIECE in the piece's own space, so
 *    findEntry CAN return a join entry. The join walk
 *    (ParamEntry::justifiedContain fspec.cc:251-262, least significant
 *    piece first) decides the just=true justification; the overlapping
 *    plain entry pins the piece-vs-entry position order (pieces take
 *    positions in JoinRecord order before later entries).
 *  - case=cross_space_join: a join with pieces in DIFFERENT spaces
 *    (ram high + reg low, equal offsets 0x200). A reg query hits the
 *    low piece (justified, offset 0); the ram query hits the high piece
 *    numerically but the low piece's address.cc:133 base != op2.base
 *    -1 makes the walk return 4 != 0 -> NULL with just=true (the
 *    per-piece space guard); with just=false the join is returned from
 *    either piece's window.
 *  - case=find_vs_characterize: the same model queried through both
 *    findEntry(loc,size,true) and characterizeAsParam (fspec.cc:682):
 *    the shared phase-1 resolver window makes cls=contains_justified
 *    coincide with a justified find hit, while out-of-window starts
 *    yield NULL / no_containment.
 *
 * ParamEntry/ParamListStandard/JoinRecord construction uses the same
 * class->struct access hack as the fspec_endian_resolver_1204 fixture;
 * every observation goes through public members only.
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

// canonical synthetic spaces: constant=0, other=1, unique=2, ram=3,
// register=4, stack=5, join=6 (same index plan as the fspec_phase0
// fixture, plus the join space the join entries live in).
static void buildSpaces(FixtureTranslate *tr, AddrSpace *&constant,
                        AddrSpace *&unique, AddrSpace *&ram,
                        AddrSpace *&reg, AddrSpace *&join) {
  tr->tryInsertSpace(new ConstantSpace(tr, tr));
  tr->tryInsertSpace(new OtherSpace(tr, tr, OtherSpace::INDEX));
  tr->tryInsertSpace(new UniqueSpace(tr, tr, 2, 0));
  ram = new AddrSpace(tr, tr, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                      AddrSpace::hasphysical, 0, 0);
  reg = new AddrSpace(tr, tr, IPTR_PROCESSOR, "register", false, 8, 1, 4,
                      AddrSpace::hasphysical, 0, 0);
  tr->tryInsertSpace(ram);
  tr->tryInsertSpace(reg);
  constant = tr->getConstantSpace();
  unique = tr->getUniqueSpace();
  join = new JoinSpace(tr, tr, 6);
}

// Fill ParamEntry fields directly (Ghidra fills them in decode(); the
// fixture replicates a staged cspec loader, mirroring Rugra's builder
// setters) — same pattern as the fspec_endian_resolver_1204 fixture.
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

// Stage a join ParamEntry: spaceid is the join space and joinrec holds
// the pieces (MOST significant first, translate.hh JoinRecord), exactly
// the state resolveJoin caches after decoding a join <pentry>.
static ParamEntry makeJoinEntry(int4 grp, AddrSpace *joinspc, JoinRecord *rec,
                                int4 size, int4 minsize) {
  ParamEntry e(grp);
  e.flags = 0;
  e.type = TYPECLASS_GENERAL;
  e.groupSet.clear();
  e.groupSet.push_back(grp);
  e.spaceid = joinspc;
  e.addressbase = 0;
  e.size = size;
  e.minsize = minsize;
  e.alignment = 0;
  e.numslots = 1;
  e.joinrec = rec;
  return e;
}

// Print the entry ordinal (position in the entry list) or "null".
static int entryIndex(const ParamListStandard *stds, const ParamEntry *e) {
  if (e == (const ParamEntry *)0)
    return -1;
  int4 i = 0;
  const list<ParamEntry>::const_iterator end = stds->entry.end();
  for (list<ParamEntry>::const_iterator it = stds->entry.begin(); it != end;
       ++it, ++i) {
    if (&(*it) == e)
      return i;
  }
  return -1;
}

static void printFe(const ParamListStandard *stds, const char *spcname,
                    AddrSpace *spc, uintb off, int4 sz, bool just) {
  const ParamEntry *hit = stds->findEntry(Address(spc, off), sz, just);
  int4 idx = entryIndex(stds, hit);
  std::cout << "  fe spc=" << spcname << " off=0x" << std::hex << off
            << " sz=" << std::dec << sz << " just=" << (just ? 1 : 0)
            << " -> ";
  if (idx < 0)
    std::cout << "null" << std::endl;
  else
    std::cout << "e" << idx << std::endl;
}

int main(void) {
  std::cout << "schema=1|fixture=FSPEC-FINDENTRY-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  FixtureTranslate tr;
  AddrSpace *constant, *unique, *ram, *reg, *join;
  buildSpaces(&tr, constant, unique, ram, reg, join);

  // ---- case 1: find window gating over plain entries -----------------
  std::cout << "case=find_window_gate" << std::endl;
  {
    ParamListStandard stds;
    // e0: register [0x100,0x107] min 1
    stds.entry.push_back(makeEntry(0, reg, 0x100, 8, 1, 0,
                                   ParamEntry::force_left_justify));
    // e1: register [0x200,0x207] min 4
    stds.entry.push_back(makeEntry(1, reg, 0x200, 8, 4, 0,
                                   ParamEntry::force_left_justify));
    // e2: ram [0x2000,0x200F] min 8
    stds.entry.push_back(makeEntry(2, ram, 0x2000, 16, 8, 0,
                                   ParamEntry::force_left_justify));
    // e3: register [0x108,0x10F] min 1
    stds.entry.push_back(makeEntry(3, reg, 0x108, 8, 1, 0,
                                   ParamEntry::force_left_justify));
    // e4: register [0x104,0x10F] min 1 (overlaps e0's high half)
    stds.entry.push_back(makeEntry(4, reg, 0x104, 8, 1, 0,
                                   ParamEntry::force_left_justify));
    stds.numgroup = 5;
    stds.populateResolver();
    struct FeCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; bool just; };
    const FeCase fe[] = {
      { "reg", reg, 0x100, 8, true },   // in window, justified -> e0
      { "reg", reg, 0x100, 4, true },   // force-left sub-range -> e0
      { "reg", reg, 0x102, 4, true },   // unjustified in window -> null
      { "reg", reg, 0x102, 4, false },  // just=false in window -> e0
      { "reg", reg, 0x110, 4, false },  // above every reg extent -> null
      { "reg", reg, 0x1F0, 8, false },  // between extents -> null
      { "reg", reg, 0x300, 8, false },  // above all -> null
      { "reg", reg, 0xFF, 4, false },   // below all -> null
      { "reg", reg, 0x200, 2, false },  // in e1 window, minSize 4 > 2 -> null
      { "reg", reg, 0x104, 4, false },  // window {e0,e4}, position order -> e0
      { "reg", reg, 0x104, 4, true },   // e0 unjustified, e4 justified -> e4
      { "ram", ram, 0x2000, 16, true }, // ram entry hit -> e2
      { "ram", ram, 0x100, 8, false },  // register offset in ram -> null
      { "unique", unique, 0x100, 8, false }, // no resolver for unique -> null
    };
    for (const FeCase &c : fe)
      printFe(&stds, c.spcname, c.spc, c.off, c.sz, c.just);
  }

  // ---- case 2: join entries reached through piece windows -------------
  std::cout << "case=join_piece_access" << std::endl;
  {
    // JoinRecord pieces are MOST significant first (translate.hh): the
    // reg:0x104 piece is the high half, reg:0x100 the low half.
    JoinRecord rec;
    VarnodeData high, low;
    high.space = reg; high.offset = 0x104; high.size = 4;
    low.space = reg; low.offset = 0x100; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandard stds;
    // e0: the join entry (registered per piece at reg:0x104 and reg:0x100)
    stds.entry.push_back(makeJoinEntry(0, join, &rec, 8, 4));
    // e1: plain register [0x100,0x107] min 8 overlapping both pieces
    stds.entry.push_back(makeEntry(1, reg, 0x100, 8, 8, 0,
                                   ParamEntry::force_left_justify));
    stds.numgroup = 2;
    stds.populateResolver();
    struct FeCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; bool just; };
    const FeCase fe[] = {
      { "reg", reg, 0x100, 8, true },  // join walk -1, plain justified -> e1
      { "reg", reg, 0x100, 8, false }, // join piece window first -> e0 (join!)
      { "reg", reg, 0x100, 4, true },  // low piece justified -> e0 (join!)
      { "reg", reg, 0x104, 4, true },  // high piece gives offset 4 -> null
      { "reg", reg, 0x104, 4, false }, // high piece window, just=false -> e0
      { "reg", reg, 0x102, 4, true },  // pokes out of the low piece -> null
    };
    for (const FeCase &c : fe)
      printFe(&stds, c.spcname, c.spc, c.off, c.sz, c.just);
  }

  // ---- case 3: cross-space join pieces --------------------------------
  std::cout << "case=cross_space_join" << std::endl;
  {
    // High piece in ram, low piece in reg, both at offset 0x200: the
    // numeric coincidence that requires the per-piece space guard
    // (address.cc:133 base != op2.base) inside the join walk.
    JoinRecord rec;
    VarnodeData high, low;
    high.space = ram; high.offset = 0x200; high.size = 4;
    low.space = reg; low.offset = 0x200; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandard stds;
    stds.entry.push_back(makeJoinEntry(0, join, &rec, 8, 4));
    stds.numgroup = 1;
    stds.populateResolver();
    struct FeCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; bool just; };
    const FeCase fe[] = {
      { "reg", reg, 0x200, 4, true },  // low piece justified -> e0
      { "ram", ram, 0x200, 4, true },  // low piece foreign space: offset 4 -> null
      { "ram", ram, 0x200, 4, false }, // high piece window, just=false -> e0
      { "reg", reg, 0x204, 4, false }, // outside both piece extents -> null
    };
    for (const FeCase &c : fe)
      printFe(&stds, c.spcname, c.spc, c.off, c.sz, c.just);
  }

  // ---- case 4: findEntry vs characterizeAsParam on one model ----------
  std::cout << "case=find_vs_characterize" << std::endl;
  {
    JoinRecord rec;
    VarnodeData high, low;
    high.space = reg; high.offset = 0x104; high.size = 4;
    low.space = reg; low.offset = 0x100; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandard stds;
    stds.entry.push_back(makeJoinEntry(0, join, &rec, 8, 4));
    stds.entry.push_back(makeEntry(1, reg, 0x100, 8, 8, 0,
                                   ParamEntry::force_left_justify));
    stds.numgroup = 2;
    stds.populateResolver();
    struct FcCase { uintb off; int4 sz; };
    const FcCase fc[] = {
      { 0x100, 4 },  // find -> e0 (join, justified); characterize -> 2
      { 0x100, 8 },  // find -> e1 (plain justified); characterize -> 2
      { 0x104, 4 },  // find -> null; characterize -> 1 (unjustified)
      { 0x110, 8 },  // find -> null; characterize -> 0 (gate closed)
      { 0xFC, 8 },   // find -> null; characterize -> 0 (containedBy false)
    };
    for (const FcCase &c : fc) {
      const ParamEntry *hit = stds.findEntry(Address(reg, c.off), c.sz, true);
      int4 idx = entryIndex(&stds, hit);
      int4 cls = stds.characterizeAsParam(Address(reg, c.off), c.sz);
      std::cout << "  fc spc=reg off=0x" << std::hex << c.off << " sz="
                << std::dec << c.sz << " fe=";
      if (idx < 0)
        std::cout << "null";
      else
        std::cout << "e" << idx;
      std::cout << " ch=" << cls << std::endl;
    }
  }

  return 0;
}
