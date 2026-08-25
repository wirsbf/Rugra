/*
 * FSPEC-SPACELESS-REM-1204: locked Ghidra 12.0.4 oracle for the
 * FSPEC-SPACELESS-REMAINDER fix — the last two spaceless
 * justifiedContain callers:
 *
 *  - case=uc_plain_cross_space / uc_join_reachable:
 *    ParamListStandard::unjustifiedContainer (fspec.cc:1411-1424)
 *    iterates ALL entries with NO caller-level space filter; space
 *    rejection happens only INSIDE justifiedContain (fspec.cc:269 /
 *    address.cc:133 for plain entries; per-piece address.cc:133 for
 *    joins). A stack query at a numerically unjustified register/ram
 *    offset returns hit=0 (the old spaceless arithmetic would have
 *    returned the register container); join entries ARE reachable and
 *    getContainer (fspec.cc:295) passes back the containing PIECE
 *    (register:0x100/4), not the whole join.
 *  - case=fb_plain_best_cover / fb_join_reachable / fb_cross_space_join /
 *    fb_first_only_skip / fb_first_only_allowed:
 *    ParamListStandardOut::fillinMapFallback (fspec.cc:1638-1719): both
 *    trial queries (cc:1656 evaluate-in-terms-of-current-entry and
 *    cc:1702 best-entry re-evaluation) are space-aware — the trial
 *    Address carries its space, join entries match register/ram trials
 *    through the per-piece walk (the old caller-level getSpace()
 *    equality guard made every join entry unreachable -> bestentry
 *    null -> all trials markNoUse), the best loop overwrites the
 *    per-entry evaluation state, the offmatch contiguity walk, the
 *    minSize coverage gate, the type/cover preference
 *    (TYPECLASS_GENERAL < TYPECLASS_PTR), and the firstOnly skip
 *    (cc:1649-1652: !isFirstInClass && isExclusion &&
 *    getAllGroups().size() == 1).
 *
 * ParamEntry/ParamListStandard(out)/ParamActive/ParamTrial construction
 * uses the same class->struct access hack as the
 * fspec_possibleparam_1204 fixture; every observation goes through
 * public members only. fillinMapFallback never touches the resolver, so
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
// fspec_findentry_1204 / fspec_possibleparam_1204 fixtures).
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
  stack = new AddrSpace(tr, tr, IPTR_SPACEBASE, "stack", false, 8, 1, 5,
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

static void printUc(ParamListStandard *stds, const char *spcname,
                    AddrSpace *spc, uintb off, int4 sz) {
  VarnodeData res;
  res.space = (AddrSpace *)0;
  res.offset = 0;
  res.size = 0;
  bool hit = stds->unjustifiedContainer(Address(spc, off), sz, res);
  std::cout << "  uc spc=" << spcname << " off=0x" << std::hex << off
            << " sz=" << std::dec << sz << " hit=" << (hit ? 1 : 0);
  if (hit)
    std::cout << " res=" << res.space->getName() << ":0x" << std::hex
              << res.offset << "/" << std::dec << res.size;
  std::cout << std::endl;
}

// Map the trial's ParamEntry pointer back to its list index (-1 null).
static int4 entryIndex(const std::vector<const ParamEntry *> &ptrs,
                       const ParamTrial &t) {
  const ParamEntry *ent = t.getEntry();
  if (ent == (const ParamEntry *)0) return -1;
  for (int4 i = 0; i < (int4)ptrs.size(); ++i)
    if (ptrs[i] == ent) return i;
  return -2; // unreachable in this fixture
}

// Register active trials then run fillinMapFallback and dump the
// final trial order (post sortTrials) with used/entry/offset state.
static void runFb(ParamListStandardOut *out, ParamActive *active,
                  const char * /*label*/, bool firstOnly) {
  out->fillinMapFallback(active, firstOnly);
  std::vector<const ParamEntry *> ptrs;
  for (list<ParamEntry>::const_iterator it = out->entry.begin();
       it != out->entry.end(); ++it)
    ptrs.push_back(&(*it));
  for (int4 i = 0; i < active->getNumTrials(); ++i) {
    const ParamTrial &t(active->getTrial(i));
    std::cout << "  fb spc=" << t.getAddress().getSpace()->getName()
              << " off=0x" << std::hex << t.getAddress().getOffset()
              << " sz=" << std::dec << t.getSize()
              << " used=" << (t.isUsed() ? 1 : 0)
              << " entry=" << entryIndex(ptrs, t)
              << " joff=" << t.getOffset() << std::endl;
  }
}

int main(void) {
  std::cout << "schema=1|fixture=FSPEC-SPACELESS-REM-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  FixtureTranslate tr;
  AddrSpace *constant, *unique, *ram, *reg, *stack, *join;
  buildSpaces(&tr, constant, unique, ram, reg, stack, join);

  // ---- case 1: plain entries, cross-space rejection ----------------
  std::cout << "case=uc_plain_cross_space" << std::endl;
  {
    ParamListStandard stds;
    // e0: register [0x100,0x107] min 2, exclusion, force-left
    stds.entry.push_back(makeEntry(0, reg, 0x100, 8, 2, 0,
                                   ParamEntry::force_left_justify));
    // e1: ram [0x100,0x10F] min 4, alignment 8 (non-exclusion)
    stds.entry.push_back(makeEntry(1, ram, 0x100, 16, 4, 8, 0));
    // e2: register [0x200,0x207] min 4, exclusion, force-left
    stds.entry.push_back(makeEntry(2, reg, 0x200, 8, 4, 0,
                                   ParamEntry::force_left_justify));
    stds.numgroup = 3;
    struct UcCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; };
    const UcCase uc[] = {
      { "reg", reg, 0x104, 4 },   // unjustified in e0 -> container 0x100/8
      { "reg", reg, 0x100, 4 },   // just==0 -> early false
      { "stack", stack, 0x104, 4 }, // address.cc:133 -> hit=0
      { "ram", ram, 0x104, 8 },   // e1 aligned route, just=4 -> 0x100/16
      { "reg", reg, 0x100, 1 },   // minSize gate (2 > 1, 4 > 1)
      { "ram", ram, 0x108, 8 },   // aligned justified -> just==0 -> false
      { "reg", reg, 0x202, 2 },   // e2 container 0x200/8
    };
    for (const UcCase &c : uc)
      printUc(&stds, c.spcname, c.spc, c.off, c.sz);
  }

  // ---- case 2: join entries ARE reachable --------------------------
  std::cout << "case=uc_join_reachable" << std::endl;
  {
    JoinRecord rec;
    VarnodeData high, low;
    high.space = ram; high.offset = 0x204; high.size = 4;
    low.space = reg; low.offset = 0x100; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandard stds;
    // e0: join ram:0x204 (high) + reg:0x100 (low)
    stds.entry.push_back(makeJoinEntry(0, join, &rec, 8, 4));
    // e1: register [0x100,0x107] min 4, exclusion, force-left
    stds.entry.push_back(makeEntry(1, reg, 0x100, 8, 4, 0,
                                   ParamEntry::force_left_justify));
    stds.numgroup = 2;
    struct UcCase { const char *spcname; AddrSpace *spc; uintb off; int4 sz; };
    const UcCase uc[] = {
      { "reg", reg, 0x102, 2 },   // low piece just=2 -> PIECE container reg:0x100/4
      { "reg", reg, 0x104, 4 },   // join walk -1 (poke out + foreign high) -> e1 just=4
      { "reg", reg, 0x204, 4 },   // both pieces foreign -> -1 (numeric high hit rejected)
      { "ram", ram, 0x204, 4 },   // skip low (+4), high cur=0 -> 4 -> PIECE ram:0x204/4
      { "reg", reg, 0x100, 4 },   // low piece just=0 -> early false
      { "stack", stack, 0x102, 2 }, // per-piece address.cc:133 -> hit=0
    };
    for (const UcCase &c : uc)
      printUc(&stds, c.spcname, c.spc, c.off, c.sz);
  }

  // ---- case 3: fallback, plain entries, best cover ------------------
  std::cout << "case=fb_plain_best_cover" << std::endl;
  {
    ParamListStandardOut out;
    out.entry.push_back(makeEntry(0, reg, 0x100, 8, 4, 0,
                                  ParamEntry::force_left_justify |
                                  ParamEntry::first_storage));
    out.entry.push_back(makeEntry(1, ram, 0x100, 16, 4, 8,
                                  ParamEntry::first_storage));
    // e2: same range as e0 but min 8 — coverage tie rejected
    out.entry.push_back(makeEntry(2, reg, 0x100, 8, 8, 0,
                                  ParamEntry::force_left_justify |
                                  ParamEntry::first_storage));
    out.numgroup = 3;
    ParamActive active(false);
    active.registerTrial(Address(reg, 0x104), 4);
    active.registerTrial(Address(reg, 0x100), 4);
    active.registerTrial(Address(stack, 0x104), 4);
    for (int4 i = 0; i < active.getNumTrials(); ++i)
      active.getTrial(i).markActive();
    runFb(&out, &active, "plain", false);
  }

  // ---- case 4: fallback, join entry reachable (core divergence) -----
  std::cout << "case=fb_join_reachable" << std::endl;
  {
    JoinRecord rec;
    VarnodeData high, low;
    high.space = reg; high.offset = 0x104; high.size = 4;
    low.space = reg; low.offset = 0x100; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandardOut out;
    out.entry.push_back(makeJoinEntry(0, join, &rec, 8, 4));
    out.entry.back().flags |= ParamEntry::first_storage;
    out.entry.push_back(makeEntry(1, reg, 0x200, 8, 4, 0,
                                  ParamEntry::force_left_justify |
                                  ParamEntry::first_storage));
    out.numgroup = 2;
    ParamActive active(false);
    active.registerTrial(Address(reg, 0x100), 4);
    active.registerTrial(Address(reg, 0x104), 4);
    for (int4 i = 0; i < active.getNumTrials(); ++i)
      active.getTrial(i).markActive();
    runFb(&out, &active, "join", false);
  }

  // ---- case 5: fallback, cross-space join pieces ---------------------
  std::cout << "case=fb_cross_space_join" << std::endl;
  {
    JoinRecord rec;
    VarnodeData high, low;
    high.space = ram; high.offset = 0x204; high.size = 4;
    low.space = reg; low.offset = 0x100; low.size = 4;
    rec.pieces.push_back(high);
    rec.pieces.push_back(low);
    ParamListStandardOut out;
    out.entry.push_back(makeJoinEntry(0, join, &rec, 8, 4));
    out.entry.back().flags |= ParamEntry::first_storage;
    out.numgroup = 1;
    ParamActive active(false);
    active.registerTrial(Address(reg, 0x100), 4);
    active.registerTrial(Address(ram, 0x204), 4);
    active.registerTrial(Address(stack, 0x204), 4);
    for (int4 i = 0; i < active.getNumTrials(); ++i)
      active.getTrial(i).markActive();
    runFb(&out, &active, "cross", false);
  }

  // ---- case 6: firstOnly skips non-first single-group exclusions -----
  std::cout << "case=fb_first_only_skip" << std::endl;
  {
    ParamListStandardOut out;
    out.entry.push_back(makeEntry(0, reg, 0x100, 8, 4, 0,
                                  ParamEntry::force_left_justify |
                                  ParamEntry::first_storage));
    // e1: NOT first_storage, exclusion (alignment 0), one group
    out.entry.push_back(makeEntry(1, reg, 0x108, 8, 4, 0,
                                  ParamEntry::force_left_justify));
    out.numgroup = 2;
    ParamActive active(false);
    active.registerTrial(Address(reg, 0x108), 4);
    active.getTrial(0).markActive();
    runFb(&out, &active, "skip", true);
  }

  // ---- case 7: same layout, firstOnly=false reaches e1 ----------------
  std::cout << "case=fb_first_only_allowed" << std::endl;
  {
    ParamListStandardOut out;
    out.entry.push_back(makeEntry(0, reg, 0x100, 8, 4, 0,
                                  ParamEntry::force_left_justify |
                                  ParamEntry::first_storage));
    out.entry.push_back(makeEntry(1, reg, 0x108, 8, 4, 0,
                                  ParamEntry::force_left_justify));
    out.numgroup = 2;
    ParamActive active(false);
    active.registerTrial(Address(reg, 0x108), 4);
    active.getTrial(0).markActive();
    runFb(&out, &active, "allowed", false);
  }

  return 0;
}
