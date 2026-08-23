/*
 * FSPEC-PHASE0-1204: locked Ghidra 12.0.4 oracle for the fspec Phase-0
 * alignment fixes (FSPEC-SPACEFILTER-0002 + FSPEC-TRIALCMP-0003):
 *
 *  - ParamListStandard::findEntry (fspec.cc:661-680) resolves through the
 *    per-space resolverMap: only entries whose space equals the query
 *    address's space are visited. Register/stack entries hit normally;
 *    const/unique-space queries never falsely hit register/ram offsets.
 *  - ParamListStandard::unjustifiedContainer (fspec.cc:1411-1424) and
 *    assumedExtension (fspec.cc:1426-1437) iterate ALL entries with no
 *    space filter (per-entry justifiedContain rejects foreign spaces).
 *  - ParamActive::sortTrials (fspec.hh:316) orders by
 *    ParamTrial::operator< (fspec.cc:1893-1914): model group, then entry
 *    order, then (exclusion) justified offset / (non-exclusion)
 *    reverseStack-aware address, then size; entry-less trials sort last.
 *  - ParamTrial::splitHi/splitLo (fspec.cc:1845/1856): the low piece
 *    starts at addr + (size - sz), both pieces inherit flags;
 *    ParamActive::splitTrial (fspec.cc:2033) renumbers survivor slots and
 *    bumps slotbase.
 *
 * All fixture spaces are little-endian (Rugra's coarse AddressSpace enum
 * defaults to little-endian), and exclusion entries set force_left_justify
 * so the sub-range justification arithmetic is endianness-independent on
 * both sides (the legacy spaceless Address cannot carry isBigEndian —
 * ADDRESS-0001 transitional). Slot observations are deltas because Ghidra
 * slots are 1-based (fspec.cc:4062 `triallist[trial.getSlot()-1]`) while
 * Rugra's coupled consumers are 0-based; the absolute base is outside this
 * fixture's covered projection.
 *
 * ParamEntry/ParamListStandard construction and populateResolver use the
 * same class->struct access hack as the address_space_phase1 /
 * space_registry fixtures; every observation goes through public members
 * only.
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
// register=4, stack=5 (same index plan as the address_space fixtures).
static void buildSpaces(FixtureTranslate *tr,
                        AddrSpace *&constant, AddrSpace *&unique,
                        AddrSpace *&ram, AddrSpace *&reg, AddrSpace *&stack) {
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
}

// Fill ParamEntry fields directly (Ghidra fills them in decode(); the
// fixture replicates a staged cspec loader, mirroring Rugra's builder
// setters).
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

static std::string loc(AddrSpace *spc, uintb off) {
  std::ostringstream s;
  s << spc->getName() << ":0x" << std::hex << off;
  return s.str();
}

static std::string vd(const VarnodeData &v) {
  std::ostringstream s;
  s << v.space->getName() << ":0x" << std::hex << v.offset << '/' << std::dec
    << v.size;
  return s.str();
}

int main(void) {
  std::cout << "schema=1|fixture=FSPEC-PHASE0-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  FixtureTranslate tr;
  AddrSpace *constant, *unique, *ram, *reg, *stack;
  buildSpaces(&tr, constant, unique, ram, reg, stack);

  // entry order fixes both the resolver position order and the
  // operator< entry tie-break.
  ParamListStandard stds;
  // e0: register slot, group 0, exclusion, force-left sub-ranges.
  stds.entry.push_back(makeEntry(0, reg, 0x30, 8, 4, 0,
                                 ParamEntry::force_left_justify));
  // e1: register slot, group 1, exclusion, zero-extends small values.
  stds.entry.push_back(makeEntry(1, reg, 0x38, 8, 4, 0,
                                 ParamEntry::force_left_justify |
                                 ParamEntry::smallsize_zext));
  // e2: stack entry, group 2, aligned slots, reverse stack.
  stds.entry.push_back(makeEntry(2, stack, 0, 64, 4, 8,
                                 ParamEntry::reverse_stack));
  // e3: ram entry, group 3, exclusion, int-typed extension.
  stds.entry.push_back(makeEntry(3, ram, 0x2000, 16, 8, 0,
                                 ParamEntry::force_left_justify |
                                 ParamEntry::smallsize_inttype));
  stds.numgroup = 4;
  stds.populateResolver();

  // ---- case 1: findEntry per-space resolution (via public wrappers) ----
  std::cout << "case=cross_space_find_entry" << std::endl;
  struct PpCase { AddrSpace *spc; uintb off; int4 sz; };
  const PpCase pp[] = {
    { reg, 0x30, 8 },    // justified register hit (group 0)
    { reg, 0x30, 4 },    // force-left sub-justified hit
    { reg, 0x34, 4 },    // unjustified in the entry
    { reg, 0x30, 2 },    // below minsize
    { reg, 0x48, 8 },    // no register entry at this offset
    { stack, 0x8, 8 },   // stack slot 1 (reverse numbering)
    { stack, 0x10, 4 },  // stack slot 2
    { stack, 0x100, 8 }, // beyond the 64-byte stack entry
    { ram, 0x2000, 16 }, // full ram entry hit
    { ram, 0x30, 8 },    // register's offset inside ram: no cross hit
    { unique, 0x30, 8 }, // register's offset in unique: no cross hit
    { constant, 0x2000, 8 }, // ram's offset in const: no cross hit
  };
  for (const PpCase &c : pp) {
    Address a(c.spc, c.off);
    int4 slot = -1, slotsize = -1;
    bool ok = stds.possibleParamWithSlot(a, c.sz, slot, slotsize);
    std::cout << "  pp " << loc(c.spc, c.off) << '/' << c.sz << " ok=" << (ok ? 1 : 0)
              << " slot=" << slot << " slotsize=" << slotsize << std::endl;
  }

  // ---- case 2: unjustifiedContainer has no space filter ----
  std::cout << "case=unjustified_container" << std::endl;
  struct UcCase { AddrSpace *spc; uintb off; int4 sz; };
  const UcCase uc[] = {
    { reg, 0x34, 4 },  // unjustified inside register entry e0
    { reg, 0x32, 4 },  // mid-entry, still unjustified
    { reg, 0x30, 4 },  // justified: must return false
    { ram, 0x2008, 8 }, // unjustified inside ram entry e3
    { stack, 0x2, 8 }, // stack alignment arithmetic (2 % 8 != 0)
  };
  for (const UcCase &c : uc) {
    Address a(c.spc, c.off);
    VarnodeData res;
    bool hit = stds.unjustifiedContainer(a, c.sz, res);
    std::cout << "  uc " << loc(c.spc, c.off) << '/' << c.sz << " hit=" << (hit ? 1 : 0);
    if (hit)
      std::cout << " res=" << vd(res);
    std::cout << std::endl;
  }

  // ---- case 3: assumedExtension has no space filter ----
  std::cout << "case=assumed_extension" << std::endl;
  struct AeCase { AddrSpace *spc; uintb off; int4 sz; };
  const AeCase ae[] = {
    { reg, 0x38, 4 },   // zext flag on the register entry
    { ram, 0x2000, 8 }, // inttype flag on the ram entry
    { reg, 0x30, 4 },   // e0 carries no smallsize flags: COPY
    { ram, 0x2004, 8 }, // unjustified sub-range: COPY
    { reg, 0x38, 8 },   // sz >= entry size: COPY
  };
  for (const AeCase &c : ae) {
    Address a(c.spc, c.off);
    VarnodeData res;
    OpCode op = stds.assumedExtension(a, c.sz, res);
    std::cout << "  ae " << loc(c.spc, c.off) << '/' << c.sz << " op=" << get_opname(op);
    if (op != CPUI_COPY)
      std::cout << " res=" << vd(res);
    std::cout << std::endl;
  }

  // ---- case 4: sortTrials uses operator< (group/entry/offset/addr/size)
  std::cout << "case=sort_trials" << std::endl;
  {
    ParamActive active(false);
    const std::list<ParamEntry> &full = stds.getEntry();
    std::list<ParamEntry>::const_iterator it = full.begin();
    const ParamEntry *elist[4] = { &*it, &*++it, &*++it, &*++it };
    // registered in raw-address order; sorted order must follow the model
    active.registerTrial(Address(stack, 0x10), 8); // stack entry, slot 2
    active.registerTrial(Address(reg, 0x38), 4); // register group 1
    active.registerTrial(Address(stack, 0x0), 8); // stack entry, slot 0
    active.registerTrial(Address(reg, 0x30), 8); // register group 0
    active.registerTrial(Address(reg, 0x34), 4); // register group 0, offset 4
    active.registerTrial(Address(reg, 0x50), 8); // no entry
    active.getTrial(0).setEntry(elist[2], 0);
    active.getTrial(1).setEntry(elist[1], 0);
    active.getTrial(2).setEntry(elist[2], 0);
    active.getTrial(3).setEntry(elist[0], 0);
    active.getTrial(4).setEntry(elist[0], 4);
    active.sortTrials();
    for (int4 i = 0; i < active.getNumTrials(); ++i) {
      const ParamTrial &t = active.getTrial(i);
      const ParamEntry *e = t.getEntry();
      std::cout << "  sorted[" << i << "] addr="
                << loc(t.getAddress().getSpace(), t.getAddress().getOffset())
                << " size=" << t.getSize() << " grp="
                << (e != (const ParamEntry *)0 ? e->getGroup() : -1) << " off="
                << (e != (const ParamEntry *)0 ? t.getOffset() : -1) << std::endl;
    }
  }

  // ---- case 5: splitHi/splitLo address, flags, slot ------------------
  std::cout << "case=split_hi_lo" << std::endl;
  {
    ParamActive active(false);
    active.registerTrial(Address(reg, 0x100), 12);
    ParamTrial &base = active.getTrial(0);
    base.markUsed();
    base.markActive();
    int4 base_slot = base.getSlot();
    ParamTrial hi = base.splitHi(4);
    ParamTrial lo = base.splitLo(4);
    std::cout << "  hi addr=" << loc(reg, hi.getAddress().getOffset())
              << " size=" << hi.getSize()
              << " slot_delta=" << (hi.getSlot() - base_slot)
              << " used=" << (hi.isUsed() ? 1 : 0)
              << " active=" << (hi.isActive() ? 1 : 0)
              << " checked=" << (hi.isChecked() ? 1 : 0) << std::endl;
    std::cout << "  lo addr=" << loc(reg, lo.getAddress().getOffset())
              << " size=" << lo.getSize()
              << " slot_delta=" << (lo.getSlot() - base_slot)
              << " used=" << (lo.isUsed() ? 1 : 0)
              << " active=" << (lo.isActive() ? 1 : 0)
              << " checked=" << (lo.isChecked() ? 1 : 0) << std::endl;
    // the complementary 8-byte low piece
    ParamTrial lo8 = base.splitLo(8);
    std::cout << "  lo8 addr=" << loc(reg, lo8.getAddress().getOffset())
              << " size=" << lo8.getSize()
              << " slot_delta=" << (lo8.getSlot() - base_slot) << std::endl;
  }

  // ---- case 6: splitTrial rebuilds slots and keeps flags --------------
  std::cout << "case=split_trial" << std::endl;
  {
    ParamActive active(false);
    active.registerTrial(Address(reg, 0x100), 12);
    active.registerTrial(Address(reg, 0x200), 8);
    active.getTrial(0).markUsed();
    active.getTrial(0).markActive();
    int4 survivor_slot_before = active.getTrial(1).getSlot();
    int4 slotbase_before = active.slotbase;
    active.splitTrial(0, 4);
    for (int4 i = 0; i < active.getNumTrials(); ++i) {
      const ParamTrial &t = active.getTrial(i);
      std::cout << "  st[" << i << "] addr=" << loc(reg, t.getAddress().getOffset())
                << " size=" << t.getSize() << " used=" << (t.isUsed() ? 1 : 0)
                << " active=" << (t.isActive() ? 1 : 0) << std::endl;
    }
    std::cout << "  survivor_slot_delta="
              << (active.getTrial(2).getSlot() - survivor_slot_before)
              << " slotbase_delta=" << (active.slotbase - slotbase_before)
              << " numtrials=" << active.getNumTrials() << std::endl;
  }

  return 0;
}
