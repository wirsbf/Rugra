/*
 * ADDRESS-SPACE-HANDLE-1204: locked Ghidra 12.0.4 space-aware Address /
 * Range / RangeList oracle (address.hh/address.cc).
 *
 * The fixture drives a real Translate-owned AddrSpaceManager through the
 * space-carrying Address surface: the invalid-vs-ram:0 distinction
 * (address.hh:262), cross-space ordering through operator< with the
 * m_minimal/m_maximal sentinels (address.cc:91), space-aware wrapOffset
 * arithmetic through operator+/- (address.hh:423/433), big-endian justified
 * containment/overlap/contiguity (address.cc:110/131/153/173), the
 * overlapJoin dispatch (address.hh:445), Range space isolation with
 * adjacent-not-merged insertRange/removeRange splits (address.cc:383/417),
 * the RangeList query family (inRange/getRange/longestFit/getLastSignedRange/
 * getLastAddrOpen/merge) and the RangeProperties construction errors
 * (address.cc:236). Every observation is printed in the shared line format
 * so the Rust comparand must match byte for byte.
 */

#include <bits/stdc++.h>

// Test-only access is required to reach AddrSpace::refcount-style private
// state (Range fields) and to subclass Translate. This matches the
// access-hack precedent of the space_registry fixture and is confined to
// this translation unit.
#define class struct
#define private public
#include "address.hh"
#include "fspec.hh"
#include "op.hh"
#include "space.hh"
#include "translate.hh"
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

static std::string hexU64(uintb v) {
  std::ostringstream s;
  s << "0x" << std::hex << v;
  return s.str();
}

// printRaw into a string (Address::printRaw takes an ostream).
static std::string pr(const Address &a) {
  std::ostringstream s;
  a.printRaw(s);
  return s.str();
}

// Print one address for the ordering walk: the space name and the raw
// offset, with the sentinel states spelled out (an invalid address has no
// space to name; the m_maximal sentinel is never dereferenced).
static std::string walkLabel(const Address &a) {
  if (a.isInvalid())
    return std::string("invalid:") + hexU64(a.getOffset());
  if (a.getSpace() == (AddrSpace *)~((uintp)0))
    return std::string("maximal:") + hexU64(a.getOffset());
  return a.getSpace()->getName() + ":" + hexU64(a.getOffset());
}

static std::string tryRangeProps(const RangeProperties &props,
                                 const AddrSpaceManager *manage) {
  try {
    Range range(props, manage);
    std::ostringstream s;
    range.printBounds(s);
    return s.str();
  }
  catch (LowlevelError &err) {
    return std::string("err ") + err.explain;
  }
}

// Build the canonical synthetic architecture plus the extra spaces the
// wrap/justified cases need: flash4 = 4-byte space, ws2spc = 4-byte space
// with wordsize 2, beram = big-endian 8-byte space.
static void buildSpaces(FixtureTranslate *tr) {
  tr->tryInsertSpace(new ConstantSpace(tr, tr));
  tr->tryInsertSpace(new OtherSpace(tr, tr, OtherSpace::INDEX));
  tr->tryInsertSpace(new UniqueSpace(tr, tr, 2, 0));
  tr->tryInsertSpace(new AddrSpace(tr, tr, IPTR_PROCESSOR, "ram", false, 8, 1,
                                   3, AddrSpace::hasphysical, 0, 0));
  tr->tryInsertSpace(new AddrSpace(tr, tr, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0));
  AddrSpace *ram = tr->getSpaceByName("ram");
  tr->tryInsertSpace(new SpacebaseSpace(tr, tr, "stack", 5, 8, ram, 1, true));
  tr->tryInsertSpace(new JoinSpace(tr, tr, 6));
  tr->tryInsertSpace(new IopSpace(tr, tr, 7));
  tr->tryInsertSpace(new AddrSpace(tr, tr, IPTR_PROCESSOR, "flash4", false, 4,
                                   1, 8, 0, 0, 0));
  tr->tryInsertSpace(new AddrSpace(tr, tr, IPTR_PROCESSOR, "ws2spc", false, 4,
                                   2, 9, 0, 0, 0));
  tr->tryInsertSpace(new AddrSpace(tr, tr, IPTR_PROCESSOR, "beram", true, 8,
                                   1, 10, 0, 0, 0));
}

int main(void) {
  std::cout << "schema=1|fixture=ADDRESS-SPACE-HANDLE-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // ---- case 1: invalid vs ram:0, extremal sentinels ----------------------
  std::cout << "case=invalid_vs_ram0" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *constant = tr.getConstantSpace();
    AddrSpace *join = tr.getJoinSpace();
    Address invalid(Address::m_minimal);
    Address invalid2(Address::m_minimal);
    Address ram0(ram, 0);
    Address ram1000(ram, 0x1000);
    Address maximal(Address::m_maximal);
    Address const10(constant, 0x10);
    Address join30(join, 0x30);
    std::cout << "  invalidIsInvalid=" << (invalid.isInvalid() ? 1 : 0)
              << " ram0IsInvalid=" << (ram0.isInvalid() ? 1 : 0) << std::endl;
    std::cout << "  print invalid=" << pr(invalid)
              << " ram0=" << pr(ram0)
              << " ram1000=" << pr(ram1000) << std::endl;
    std::cout << "  eq_invalid_ram0=" << ((invalid == ram0) ? 1 : 0)
              << " eq_invalid_minimal=" << ((invalid == invalid2) ? 1 : 0)
              << " ne_invalid_ram0=" << ((invalid != ram0) ? 1 : 0) << std::endl;
    std::cout << "  lt_invalid_ram0=" << ((invalid < ram0) ? 1 : 0)
              << " lt_ram0_invalid=" << ((ram0 < invalid) ? 1 : 0)
              << " le_invalid_ram0=" << ((invalid <= ram0) ? 1 : 0) << std::endl;
    std::cout << "  lt_min_ram1000=" << ((invalid < ram1000) ? 1 : 0)
              << " lt_max_ram1000=" << ((maximal < ram1000) ? 1 : 0)
              << " lt_ram1000_max=" << ((ram1000 < maximal) ? 1 : 0)
              << " eq_max_max=" << ((maximal == Address(Address::m_maximal)) ? 1 : 0)
              << std::endl;
    std::cout << "  addrSize ram=" << ram0.getAddrSize() << std::endl;
    std::cout << "  const10 isConst=" << (const10.isConstant() ? 1 : 0)
              << " isJoin=" << (const10.isJoin() ? 1 : 0)
              << " join30 isJoin=" << (join30.isJoin() ? 1 : 0)
              << " constPrint=" << pr(const10) << std::endl;
    std::cout << "  shortcut ram=" << ram0.getShortcut()
              << " const=" << const10.getShortcut() << std::endl;
  }

  // ---- case 2: cross-space ordering in a sorted container ----------------
  std::cout << "case=cross_space_ordering" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *constant = tr.getConstantSpace();
    AddrSpace *other = tr.getSpaceByName("OTHER");
    AddrSpace *unique = tr.getUniqueSpace();
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *register_ = tr.getSpaceByName("register");
    AddrSpace *stack = tr.getStackSpace();
    AddrSpace *join = tr.getJoinSpace();
    AddrSpace *iop = tr.getIopSpace();
    std::set<Address> ordered;
    ordered.insert(Address(register_, 0x5000));
    ordered.insert(Address(unique, 0x99));
    ordered.insert(Address(ram, 0x1000));
    ordered.insert(Address(constant, 0x7f));
    ordered.insert(Address(other, 0x1));
    ordered.insert(Address(stack, 0x20));
    ordered.insert(Address(join, 0x30));
    ordered.insert(Address(iop, 0x40));
    ordered.insert(Address(ram, 0x2000));
    ordered.insert(Address(register_, 0x3000));
    ordered.insert(Address(unique, 0x11));
    ordered.insert(Address(ram, 0x800));
    ordered.insert(Address(Address::m_minimal));
    ordered.insert(Address(Address::m_maximal));
    std::cout << "  size=" << ordered.size() << std::endl;
    for (std::set<Address>::const_iterator it = ordered.begin();
         it != ordered.end(); ++it) {
      std::cout << "  walk " << walkLabel(*it) << std::endl;
    }
    std::cout << "  lt(const7f,other1)=" << (Address(constant, 0x7f) < Address(other, 0x1) ? 1 : 0)
              << " lt(register3000,ram2000)=" << (Address(register_, 0x3000) < Address(ram, 0x2000) ? 1 : 0)
              << " lt(ram800,ram1000)=" << (Address(ram, 0x800) < Address(ram, 0x1000) ? 1 : 0)
              << " lt(unique99,ram1)=" << (Address(unique, 0x99) < Address(ram, 0x1) ? 1 : 0)
              << std::endl;
  }

  // ---- case 3: wrap boundaries through the real space --------------------
  std::cout << "case=wrap_boundaries" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *flash4 = tr.getSpaceByName("flash4");
    AddrSpace *ws2spc = tr.getSpaceByName("ws2spc");
    AddrSpace *constant = tr.getConstantSpace();
    AddrSpace *register_ = tr.getSpaceByName("register");
    std::cout << "  flash4 highest=" << hexU64(flash4->getHighest())
              << " ws2 highest=" << hexU64(ws2spc->getHighest())
              << " addrSize flash4=" << Address(flash4, 0).getAddrSize()
              << " ws2=" << Address(ws2spc, 0).getAddrSize() << std::endl;
    std::cout << "  flash4 fffffffe+2=" << hexU64((Address(flash4, 0xfffffffe) + 2).getOffset())
              << " ffffffff+1=" << hexU64((Address(flash4, 0xffffffff) + 1).getOffset())
              << " fffffffe+3=" << hexU64((Address(flash4, 0xfffffffe) + 3).getOffset())
              << " 10-11=" << hexU64((Address(flash4, 0x10) - 0x11).getOffset()) << std::endl;
    std::cout << "  ws2 1ffffffff+1=" << hexU64((Address(ws2spc, 0x1ffffffff) + 1).getOffset())
              << " 1ffffffff+3=" << hexU64((Address(ws2spc, 0x1ffffffff) + 3).getOffset())
              << " raw wrap 200000003=" << hexU64(ws2spc->wrapOffset(0x200000003)) << std::endl;
    std::cout << "  ram maxff+1=" << hexU64((Address(ram, 0xffffffffffffffff) + 1).getOffset())
              << " ram 100+ff=" << hexU64((Address(ram, 0x100) + 0xff).getOffset()) << std::endl;
    std::cout << "  overlap wrap=" << Address(flash4, 0xfffffffe).overlap(4, Address(flash4, 0x1), 8)
              << " negskip=" << Address(flash4, 0x10).overlap(-8, Address(flash4, 0x5), 16)
              << " const=" << Address(constant, 0x10).overlap(0, Address(constant, 0x8), 16)
              << " crossspace=" << Address(ram, 0x10).overlap(0, Address(register_, 0x8), 16)
              << " far=" << Address(flash4, 0x0).overlap(0, Address(flash4, 0x8), 4) << std::endl;
  }

  // ---- case 4: big-endian justified containment ---------------------------
  std::cout << "case=justified_big_endian" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *beram = tr.getSpaceByName("beram");
    AddrSpace *leram = tr.getSpaceByName("ram");
    AddrSpace *constant = tr.getConstantSpace();
    Address beContainer(beram, 0x100);
    Address leContainer(leram, 0x100);
    std::cout << "  beram endian big=" << (beContainer.isBigEndian() ? 1 : 0)
              << " leram=" << (leContainer.isBigEndian() ? 1 : 0) << std::endl;
    std::cout << "  jc be full=" << beContainer.justifiedContain(8, Address(beram, 0x100), 8, false)
              << " be low2=" << beContainer.justifiedContain(8, Address(beram, 0x100), 2, false)
              << " be forceleft=" << beContainer.justifiedContain(8, Address(beram, 0x100), 2, true)
              << " be high2=" << beContainer.justifiedContain(8, Address(beram, 0x106), 2, false)
              << " be out=" << beContainer.justifiedContain(8, Address(beram, 0x108), 2, false)
              << std::endl;
    std::cout << "  jc le low2=" << leContainer.justifiedContain(8, Address(leram, 0x100), 2, false)
              << " cross=" << beContainer.justifiedContain(8, Address(leram, 0x100), 2, false)
              << std::endl;
    std::cout << "  containedBy 100/4in100/8=" << (Address(beram, 0x100).containedBy(4, Address(beram, 0x100), 8) ? 1 : 0)
              << " 102/4in100/4=" << (Address(beram, 0x102).containedBy(4, Address(beram, 0x100), 4) ? 1 : 0)
              << " cross=" << (Address(beram, 0x100).containedBy(4, Address(leram, 0x100), 8) ? 1 : 0)
              << std::endl;
    std::cout << "  contiguous be hit=" << (Address(beram, 0x104).isContiguous(4, Address(beram, 0x108), 4) ? 1 : 0)
              << " be miss=" << (Address(beram, 0x104).isContiguous(4, Address(beram, 0x100), 4) ? 1 : 0)
              << " le hit=" << (Address(leram, 0x104).isContiguous(4, Address(leram, 0x100), 4) ? 1 : 0)
              << " cross=" << (Address(beram, 0x104).isContiguous(4, Address(leram, 0x100), 4) ? 1 : 0)
              << std::endl;
    std::cout << "  overlapJoin same=" << Address(leram, 0x12).overlapJoin(0, Address(leram, 0x10), 8)
              << " pointcross=" << Address(constant, 0x12).overlapJoin(0, Address(leram, 0x10), 8)
              << " opconst=" << Address(leram, 0x12).overlapJoin(0, Address(constant, 0x10), 8)
              << " far=" << Address(leram, 0x1a).overlapJoin(0, Address(leram, 0x10), 8) << std::endl;
  }

  // ---- case 5: RangeList space isolation, merge, split -------------------
  std::cout << "case=range_space_isolation" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *register_ = tr.getSpaceByName("register");
    AddrSpace *unique = tr.getUniqueSpace();
    RangeList rl;
    rl.insertRange(ram, 0x1000, 0x1fff);
    rl.insertRange(register_, 0x1000, 0x1fff);
    rl.insertRange(ram, 0x2000, 0x2fff);
    std::cout << "  numRanges=" << rl.numRanges() << " (adjacent kept)" << std::endl;
    {
      std::ostringstream s;
      rl.printBounds(s);
      std::cout << s.str(); // one line per range, each newline-terminated
    }
    std::cout << "  inRange ram1ffc/4=" << (rl.inRange(Address(ram, 0x1ffc), 4) ? 1 : 0)
              << " ram1ffd/4=" << (rl.inRange(Address(ram, 0x1ffd), 4) ? 1 : 0)
              << " reg1000/4=" << (rl.inRange(Address(register_, 0x1000), 4) ? 1 : 0)
              << " uniq1000/4=" << (rl.inRange(Address(unique, 0x1000), 4) ? 1 : 0)
              << " invalid/4=" << (rl.inRange(Address(Address::m_minimal), 4) ? 1 : 0)
              << std::endl;
    const Range *got = rl.getRange(ram, 0x1500);
    std::cout << "  getRange ram1500=" << (got != (const Range *)0 ? "found" : "null");
    got = rl.getRange(unique, 0x1500);
    std::cout << " uniq1500=" << (got != (const Range *)0 ? "found" : "null");
    got = rl.getRange(ram, 0x3000);
    std::cout << " ram3000=" << (got != (const Range *)0 ? "found" : "null") << std::endl;
    const Range *ramRange = rl.getRange(ram, 0x1500);
    std::cout << "  contains ram1500=" << (ramRange->contains(Address(ram, 0x1500)) ? 1 : 0)
              << " reg1500=" << (ramRange->contains(Address(register_, 0x1500)) ? 1 : 0)
              << " invalid=" << (ramRange->contains(Address(Address::m_minimal)) ? 1 : 0)
              << std::endl;
    rl.insertRange(ram, 0x1800, 0x2200);
    std::cout << "  numRanges=" << rl.numRanges() << " (overlap merged)" << std::endl;
    rl.removeRange(ram, 0x1400, 0x17ff);
    std::cout << "  numRanges=" << rl.numRanges() << " (split)" << std::endl;
    {
      std::ostringstream s;
      rl.printBounds(s);
      std::cout << s.str();
    }
  }

  // ---- case 6: RangeList queries, signed view, open end, merge -----------
  std::cout << "case=rangelist_queries" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *register_ = tr.getSpaceByName("register");
    AddrSpace *unique = tr.getUniqueSpace();
    AddrSpace *beram = tr.getSpaceByName("beram");
    RangeList rl2;
    rl2.insertRange(ram, 0x100, 0x1ff);
    rl2.insertRange(ram, 0x200, 0x2ff);
    std::cout << "  adjacent numRanges=" << rl2.numRanges() << std::endl;
    std::cout << "  longestFit 150/1000=" << rl2.longestFit(Address(ram, 0x150), 1000)
              << " 150/100=" << rl2.longestFit(Address(ram, 0x150), 100)
              << " 50/1000=" << rl2.longestFit(Address(ram, 0x50), 1000)
              << " uniq150/1000=" << rl2.longestFit(Address(unique, 0x150), 1000)
              << " invalid/1000=" << rl2.longestFit(Address(Address::m_minimal), 1000)
              << std::endl;
    {
      std::ostringstream s;
      rl2.getFirstRange()->printBounds(s);
      std::cout << "  first=" << s.str() << std::endl;
    }
    {
      std::ostringstream s;
      rl2.getLastRange()->printBounds(s);
      std::cout << "  last=" << s.str() << std::endl;
    }
    rl2.insertRange(ram, 0xffffffff80000000, 0xffffffffffffffff);
    {
      std::ostringstream s;
      rl2.getLastSignedRange(ram)->printBounds(s);
      std::cout << "  signed ram=" << s.str() << std::endl;
    }
    RangeList rl4;
    rl4.insertRange(register_, 0xfffffff000000000, 0xfffffff0ffffffff);
    {
      std::ostringstream s;
      rl4.getLastSignedRange(register_)->printBounds(s);
      std::cout << "  signed negonly=" << s.str() << std::endl;
    }
    RangeList rl5;
    rl5.insertRange(ram, 0, 0xffffffffffffffff);
    Address open5 = rl5.getFirstRange()->getLastAddrOpen(&tr);
    std::cout << "  lastAddrOpen fullram=" << walkLabel(open5)
              << " print=" << pr(open5) << std::endl;
    RangeList rl6;
    rl6.insertRange(beram, 0, 0xffffffffffffffff);
    Address open6 = rl6.getFirstRange()->getLastAddrOpen(&tr);
    std::cout << "  lastAddrOpen fullberam isMax=" << ((open6 == Address(Address::m_maximal)) ? 1 : 0)
              << " lt_before_max=" << ((Address(ram, 0x10) < open6) ? 1 : 0) << std::endl;
    RangeList rl3;
    rl3.insertRange(unique, 0x10, 0x1f);
    rl3.insertRange(ram, 0x300, 0x3ff);
    rl2.merge(rl3);
    std::cout << "  merged numRanges=" << rl2.numRanges() << std::endl;
    {
      std::ostringstream s;
      rl2.printBounds(s);
      std::cout << s.str();
    }
  }

  // ---- case 7: Range construction from properties ------------------------
  std::cout << "case=range_properties" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    RangeProperties p1;
    p1.spaceName = "ram";
    p1.first = 0x100;
    p1.last = 0x1ff;
    p1.seenLast = true;
    std::cout << "  p1 " << tryRangeProps(p1, &tr) << std::endl;
    RangeProperties p2;
    p2.spaceName = "ram";
    p2.first = 0x100;
    std::cout << "  p2 " << tryRangeProps(p2, &tr) << std::endl;
    RangeProperties p3;
    p3.spaceName = "nosuch";
    p3.first = 0;
    p3.seenLast = true;
    std::cout << "  p3 " << tryRangeProps(p3, &tr) << std::endl;
    RangeProperties p4;
    p4.spaceName = "ram";
    p4.first = 2;
    p4.last = 1;
    p4.seenLast = true;
    std::cout << "  p4 " << tryRangeProps(p4, &tr) << std::endl;
    RangeProperties p5;
    p5.spaceName = "flash4";
    p5.first = 0x100000000;
    p5.last = 0x100000001;
    p5.seenLast = true;
    std::cout << "  p5 " << tryRangeProps(p5, &tr) << std::endl;
    RangeProperties p6;
    p6.spaceName = "flash4";
    p6.first = 0x10;
    std::cout << "  p6 " << tryRangeProps(p6, &tr) << std::endl;
  }
  return 0;
}
