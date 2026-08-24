/*
 * FSPEC-POSSIBLEPARAM-1204: locked Ghidra 12.0.4 oracle for the
 * FSPEC-POSSIBLEPARAM-JOIN-0006 fix (A46 residual 3: the spaceless
 * justifiedContain callers assumedExtension cc:366 and
 * ParamListStandardOut::possibleParam cc:1765).
 *
 *  - case=plain_out_entries: ParamListStandardOut::possibleParam
 *    (fspec.cc:1765-1774) iterates the RAW entry list — no resolver
 *    window, no caller-level space filter, no minSize gate — and
 *    accepts ANY non-negative justifiedContain (>= 0, not the
 *    findEntry just==0 gate), so unjustified sub-ranges are possible
 *    params. Space rejection happens only INSIDE justifiedContain:
 *    fspec.cc:269 (alignment!=0) and address.cc:133 (alignment==0).
 *  - case=join_out_entries: join entries ARE reachable: the per-piece
 *    join walk (fspec.cc:251-262) returns the containing offset
 *    (0x104/4 -> 4 >= 0 -> true), unlike findEntry(just=true) which
 *    requires 0. The old Rugra caller-level space filter made every
 *    join entry unreachable — the core divergence pinned here.
 *  - case=cross_space_join: pieces in different spaces with equal
 *    offsets; the ram query walks the foreign low piece
 *    (address.cc:133 -1, +4 skip) into the containing high piece
 *    (offset 4 >= 0) -> true.
 *  - case=assumed_extension: ParamListStandard::assumedExtension
 *    (fspec.cc:1426) -> ParamEntry::assumedExtension (fspec.cc:366):
 *    the cc:377 justifiedContain is space-aware (foreign-space query
 *    at a numerically justified offset -> CPUI_COPY), joins return
 *    CPUI_COPY at cc:376 before the containment check, the sz gates
 *    (cc:370-375), the list-level minSize skip (cc:1431), and both
 *    container shapes (whole alignment cc:383-388, whole exclusion
 *    entry cc:378-382).
 *
 * ParamEntry/ParamListStandardOut/JoinRecord construction uses the
 * same class->struct access hack as the fspec_findentry_1204 fixture;
 * every observation goes through public members only. Neither
 * possibleParam nor assumedExtension touches the resolver, so
 * populateResolver is intentionally NOT called.
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
// register=4, stack=5, join=6 (same index plan as the
// fspec_findentry_1204 fixture).
static void buildSpaces(FixtureTranslate *tr, AddrSpace *&constant,
                        AddrSpace *&unique, AddrSpace *&ram,
                        AddrSpace *&reg, AddrSpace *&stack, AddrSpace *&join) {
  tr->tryInsertSpace(new ConstantSpace(tr, tr));
  tr->tryInsertSpace(new OtherSpace(tr, tr, OtherSpace::INDEX));
  tr->tryInsertSpace(new UniqueSpace(tr, tr, 2, 0));
  ram = new AddrSpace(tr, tr, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                      AddrSpace::hasphysical, 0, 0);
  reg = new AddrSpace(tr, tr, IPTR_PROCESSOR, "register", false, 8, 1, 4,
                      AddrSpace::hasphysical, 0, 0);
  stack = new AddrSpace(tr, tr, IPTR_PROCESSOR, "stack", false, 8, 1, 5,
                        AddrSpace::hasphysical, 0, 0);
  tr->tryInsertSpace(ram);
  tr->tryInsertSpace(reg);
  tr->tryInsertSpace(stack);
  constant = tr->getConstantSpace();
  unique = tr->getUniqueSpace();
  join = new JoinSpace(tr, tr, 6);
}

// Fill ParamEntry fields directly (staged cspec loader, same pattern
// as the fspec_findentry_1204 fixture).
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

// Stage a join ParamEntry (spaceid = join space, pieces MOST
// significant first), the state resolveJoin caches after decoding a
// join <pentry>.
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

static void printPp(const ParamListStandardOut *out, const char *spcname,
                    AddrSpace *spc, uintb off, int4 sz) {
  bool hit = out->possibleParam(Address(spc, off), sz);
  std::cout << "  pp spc=" << spcname << " off=0x" << std::hex << off
            << " sz=" << std::dec << sz << " -> " << (hit ? "true" : "false")
            << std::endl;
}

static void printAe(const ParamListStandard *stds, const char *spcname,
                    AddrSpace *spc, uintb off, int4 sz) {
  VarnodeData res;
  res.space = (AddrSpace *)0;
  res.offset = 0;
  res.size = 0;
  OpCode ext = stds->assumedExtension(Address(spc, off), sz, res);
  std::cout << "  ae spc=" << spcname << " off=0x" << std::hex << off
            << " sz=" << std::dec << sz << " -> " << get_opname(ext);
  if (ext != CPUI_COPY)
    std::cout << " res=" << res.space->getName() << ":0x" << std::hex
              << res.offset << "/" << std::dec << res.size;
  std::cout << std::endl;
}

int main(void) {
  std::cout << "schema=1|fixture=FSPEC-POSSIBLEPARAM-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  FixtureTranslate tr;
  AddrSpace *constant, *unique, *ram, *reg, *stack, *join;
  buildSpaces(&tr, constant, unique, ram, reg, stack, join);

  // ---- case 1: plain output entries ------------------------------
  std::cout << "case=plain_out_entries" << std::endl;
  {
    ParamListStandardOut out;
    // e0: register [0x200,0x207] min 4, exclusion, force-left
    out.entry.push_back(makeEntry(0, reg, 0x200, 8, 4, 0,
                                  ParamEntry::force_left_justify));
    // e1: register [0x1000,0x100F] min 4, alignment 8 (aligned route)
    out.entry.push_back(makeEntry(1, reg, 0x1000, 16, 4, 8, 0));
    // e2: ram [0x2000,0x200F] min 2, exclusion, force-left
    out.entry.push_back(makeEntry(2, ram, 0x2000, 16, 2, 0,
                                  ParamEntry::force_left_justify));
    out.numgroup = 3;
    struct PpCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; };
    const PpCase pp[] = {
      { "reg", reg, 0x200, 4 },    // justified hit -> true
      { "reg", reg, 0x202, 2 },    // unjustified offset 2: >= 0 -> true
      { "reg", reg, 0x208, 4 },    // above e0, below e1 -> false
      { "reg", reg, 0x1000, 8 },   // aligned justified hit -> true
      { "reg", reg, 0x1002, 4 },   // aligned unjustified (2) -> true
      { "stack", stack, 0x1000, 8 }, // cc:269 foreign-space guard -> false
      { "stack", stack, 0x200, 4 },  // address.cc:133 route -> false
      { "ram", ram, 0x2000, 1 },   // NO minSize gate (min 2 > 1) -> true
      { "reg", reg, 0x200, 1 },    // NO minSize gate (min 4 > 1) -> true
      { "unique", unique, 0x200, 4 }, // foreign space -> false
    };
    for (const PpCase &c : pp)
      printPp(&out, c.spcname, c.spc, c.off, c.sz);
  }

  // ---- case 2: join entries ARE reachable --------------------------
  std::cout << "case=join_out_entries" << std::endl;
  {
    JoinRecord rec;
    VarnodeData high, low;
    high.space = reg; high.offset = 0x104; high.size = 4;
    low.space = reg; low.offset = 0x100; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandardOut out;
    // e0: join reg:0x104 (high) + reg:0x100 (low)
    out.entry.push_back(makeJoinEntry(0, join, &rec, 8, 4));
    // e1: plain register [0x200,0x207] min 4
    out.entry.push_back(makeEntry(1, reg, 0x200, 8, 4, 0,
                                  ParamEntry::force_left_justify));
    out.numgroup = 2;
    struct PpCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; };
    const PpCase pp[] = {
      { "reg", reg, 0x100, 4 },    // low piece offset 0 -> true (join!)
      { "reg", reg, 0x104, 4 },    // walk offset 4 >= 0 -> true (join!)
      { "reg", reg, 0x100, 8 },    // join walk -1, e1 no -> false
      { "reg", reg, 0x102, 4 },    // pokes out of both pieces -> false
      { "reg", reg, 0x200, 4 },    // plain entry hit -> true
      { "stack", stack, 0x100, 4 }, // per-piece address.cc:133 -> false
    };
    for (const PpCase &c : pp)
      printPp(&out, c.spcname, c.spc, c.off, c.sz);
  }

  // ---- case 3: cross-space join pieces -----------------------------
  std::cout << "case=cross_space_join" << std::endl;
  {
    JoinRecord rec;
    VarnodeData high, low;
    high.space = ram; high.offset = 0x200; high.size = 4;
    low.space = reg; low.offset = 0x200; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandardOut out;
    out.entry.push_back(makeJoinEntry(0, join, &rec, 8, 4));
    out.numgroup = 1;
    struct PpCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; };
    const PpCase pp[] = {
      { "reg", reg, 0x200, 4 },    // low piece offset 0 -> true
      { "ram", ram, 0x200, 4 },    // foreign low -1 (+4), high cur=0 -> 4 >= 0 -> true
      { "reg", reg, 0x204, 4 },    // outside both pieces -> false
      { "reg", reg, 0x200, 8 },    // low pokes out, high foreign -> -1 -> false
      { "stack", stack, 0x200, 4 }, // both pieces foreign -> false
    };
    for (const PpCase &c : pp)
      printPp(&out, c.spcname, c.spc, c.off, c.sz);
  }

  // ---- case 4: assumedExtension gates and containers ----------------
  std::cout << "case=assumed_extension" << std::endl;
  {
    JoinRecord rec;
    VarnodeData high, low;
    high.space = reg; high.offset = 0x204; high.size = 4;
    low.space = reg; low.offset = 0x200; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandard stds;
    // e0: register [0x100,0x11F] min 2 alignment 8, smallsize zext
    stds.entry.push_back(makeEntry(0, reg, 0x100, 32, 2, 8,
                                   ParamEntry::smallsize_zext));
    // e1: join reg:0x204 + reg:0x200 min 2, smallsize sext (never
    // extends: cc:376 join guard)
    stds.entry.push_back(makeJoinEntry(1, join, &rec, 8, 2));
    stds.entry.back().flags = ParamEntry::smallsize_sext;
    // e2: ram [0x2000,0x200F] min 2, exclusion, smallsize inttype
    stds.entry.push_back(makeEntry(2, ram, 0x2000, 16, 2, 0,
                                   ParamEntry::smallsize_inttype));
    // e3: register [0x3000,0x3007] min 2, exclusion, smallsize sext
    stds.entry.push_back(makeEntry(3, reg, 0x3000, 8, 2, 0,
                                   ParamEntry::smallsize_sext));
    // e4: register [0x4000,0x4007] min 2, exclusion, zext|inttype —
    // cc:389 zext wins over cc:391 inttype
    stds.entry.push_back(makeEntry(4, reg, 0x4000, 8, 2, 0,
                                   ParamEntry::smallsize_zext |
                                   ParamEntry::smallsize_inttype));
    // e5: register [0x5000,0x5007] min 2, exclusion, inttype|sext —
    // cc:391 inttype wins over cc:393 sext
    stds.entry.push_back(makeEntry(5, reg, 0x5000, 8, 2, 0,
                                   ParamEntry::smallsize_inttype |
                                   ParamEntry::smallsize_sext));
    stds.numgroup = 6;
    struct AeCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; };
    const AeCase ae[] = {
      { "reg", reg, 0x100, 2 },    // justified -> ZEXT, container 0x100/8
      { "reg", reg, 0x108, 2 },    // second slot -> ZEXT, container 0x108/8
      { "reg", reg, 0x102, 2 },    // unjustified (2 % 8) -> COPY
      { "stack", stack, 0x100, 2 }, // foreign space at numeric hit -> COPY
      { "reg", reg, 0x100, 8 },    // sz >= alignment (and all later gates)
      { "reg", reg, 0x100, 1 },    // list minSize skip (e0/e1/e2 min 2)
      { "reg", reg, 0x200, 2 },    // join guard cc:376 (low piece justifies)
      { "ram", ram, 0x2000, 4 },   // exclusion container 0x2000/16 -> PIECE
      { "ram", ram, 0x2002, 4 },   // unjustified (offset 2) -> COPY
      { "stack", stack, 0x2000, 4 }, // address.cc:133 route -> COPY
      { "reg", reg, 0x3000, 2 },   // sext only -> INT_SEXT, container 0x3000/8
      { "reg", reg, 0x4000, 2 },   // zext|inttype -> INT_ZEXT (cc:389 first)
      { "reg", reg, 0x5000, 2 },   // inttype|sext -> PIECE (cc:391 before 393)
    };
    for (const AeCase &c : ae)
      printAe(&stds, c.spcname, c.spc, c.off, c.sz);
  }

  return 0;
}
