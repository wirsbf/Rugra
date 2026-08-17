/*
 * ADDRESS-COMPAT-ORDER-1204: locked Ghidra 12.0.4 ordering oracle for the
 * ADDRESS-0001 phase-1 legacy-Address space bridge (address.hh/address.cc).
 *
 * The phase-1 bridge keeps a Copy legacy `Address` whose optional space tag
 * is `None` for every pre-existing construction site. The Ghidra model of
 * that `None` is the null `base` slot: the deterministic `m_minimal`
 * extremal address (address.cc:94-97, base=null offset=0). This fixture
 * drives the comparison chain around that model: null-base equality /
 * inequality against real spaces (address.hh:356), the null-base-sorts-first
 * rule (address.hh:377), cross-space index ordering in a sorted container
 * (address.hh:389), same-space offset ordering (address.hh:391),
 * wrapOffset arithmetic through real spaces (address.hh:423/433), the
 * overlap gates (address.cc:153-165) and the SeqNum ordering ladder that
 * delegates to Address ordering (address.hh:154). Every observation is
 * printed in the shared line format so the Rust comparand (which mints
 * `None` via `Address::new` and tagged spaces via `Address::with_space`)
 * must match byte for byte.
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
// offset, with the null-base state spelled out (it names no space).
static std::string walkLabel(const Address &a) {
  if (a.isInvalid())
    return std::string("invalid:") + hexU64(a.getOffset());
  return a.getSpace()->getName() + ":" + hexU64(a.getOffset());
}

// Build the canonical synthetic architecture (same layout as the
// address_space_handle_1204 fixture): constant=0, other=1, unique=2, ram=3,
// register=4, stack=5, join=6, iop=7, flash4=8 (4-byte wrap space).
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
}

int main(void) {
  std::cout << "schema=1|fixture=ADDRESS-COMPAT-ORDER-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // ---- case 1: null base (the oracle model of the None tag) vs real ------
  std::cout << "case=null_base_vs_real" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *constant = tr.getConstantSpace();
    Address nullbase(Address::m_minimal);
    Address nullbase2(Address::m_minimal);
    Address ram0(ram, 0);
    Address ram1000(ram, 0x1000);
    Address const10(constant, 0x10);
    std::cout << "  eq_null_null=" << ((nullbase == nullbase2) ? 1 : 0)
              << " eq_null_ram0=" << ((nullbase == ram0) ? 1 : 0)
              << " ne_null_ram0=" << ((nullbase != ram0) ? 1 : 0) << std::endl;
    std::cout << "  lt_null_ram0=" << ((nullbase < ram0) ? 1 : 0)
              << " lt_ram0_null=" << ((ram0 < nullbase) ? 1 : 0)
              << " le_null_ram0=" << ((nullbase <= ram0) ? 1 : 0)
              << " lt_null_const10=" << ((nullbase < const10) ? 1 : 0)
              << " lt_const10_null=" << ((const10 < nullbase) ? 1 : 0) << std::endl;
    std::cout << "  lt_null_ram1000=" << ((nullbase < ram1000) ? 1 : 0)
              << " eq_null_nulloffset=" << ((nullbase == Address(Address::m_minimal)) ? 1 : 0)
              << std::endl;
    std::cout << "  print_null=" << pr(nullbase) << std::endl;
  }

  // ---- case 2: cross-space sorted walk with the null base first ----------
  std::cout << "case=cross_space_walk" << std::endl;
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
    ordered.insert(Address(iop, 0x50));
    ordered.insert(Address(Address::m_minimal));
    std::cout << "  size=" << ordered.size() << std::endl;
    for (std::set<Address>::const_iterator it = ordered.begin();
         it != ordered.end(); ++it) {
      std::cout << "  walk " << walkLabel(*it) << std::endl;
    }
    std::cout << "  lt(const7f,other1)=" << (Address(constant, 0x7f) < Address(other, 0x1) ? 1 : 0)
              << " lt(register3000,ram2000)=" << (Address(register_, 0x3000) < Address(ram, 0x2000) ? 1 : 0)
              << " lt(iop40,join30)=" << (Address(iop, 0x40) < Address(join, 0x30) ? 1 : 0)
              << " lt(unique99,ram1)=" << (Address(unique, 0x99) < Address(ram, 0x1) ? 1 : 0)
              << " lt(null,all)=" << (Address(Address::m_minimal) < Address(constant, 0x0) ? 1 : 0)
              << std::endl;
  }

  // ---- case 3: same-space offset ordering ---------------------------------
  std::cout << "case=same_space_offset_order" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *register_ = tr.getSpaceByName("register");
    std::cout << "  lt(ram0,ram800)=" << (Address(ram, 0) < Address(ram, 0x800) ? 1 : 0)
              << " le(ram800,ram800)=" << (Address(ram, 0x800) <= Address(ram, 0x800) ? 1 : 0)
              << " lt(ram2000,ram1000)=" << (Address(ram, 0x2000) < Address(ram, 0x1000) ? 1 : 0)
              << " eq(ram1000,ram1000)=" << (Address(ram, 0x1000) == Address(ram, 0x1000) ? 1 : 0)
              << std::endl;
    std::cout << "  lt(reg0,reg8)=" << (Address(register_, 0) < Address(register_, 8) ? 1 : 0)
              << " eq(reg8,ram8)=" << (Address(register_, 8) == Address(ram, 8) ? 1 : 0)
              << " lt(reg_maxm1,reg_max)=" << (Address(register_, 0xfffffffffffffffeULL) < Address(register_, 0xffffffffffffffffULL) ? 1 : 0)
              << std::endl;
  }

  // ---- case 4: wrapOffset arithmetic through real spaces ------------------
  std::cout << "case=wrap_arithmetic" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *flash4 = tr.getSpaceByName("flash4");
    std::cout << "  flash4 fffffffe+2=" << hexU64((Address(flash4, 0xfffffffe) + 2).getOffset())
              << " ffffffff+1=" << hexU64((Address(flash4, 0xffffffff) + 1).getOffset())
              << " fffffffe+3=" << hexU64((Address(flash4, 0xfffffffe) + 3).getOffset())
              << " 10-11=" << hexU64((Address(flash4, 0x10) - 0x11).getOffset()) << std::endl;
    std::cout << "  ram maxff+1=" << hexU64((Address(ram, 0xffffffffffffffff) + 1).getOffset())
              << " ram 100+ff=" << hexU64((Address(ram, 0x100) + 0xff).getOffset())
              << " ram 0-1=" << hexU64((Address(ram, 0) - 1).getOffset()) << std::endl;
    std::cout << "  spacekept fffffffe+2=" << hexU64((Address(flash4, 0xfffffffe) + 2).getOffset())
              << " spaceis=" << (((Address(flash4, 0xfffffffe) + 2).getSpace() == flash4) ? 1 : 0)
              << std::endl;
  }

  // ---- case 5: overlap gates ----------------------------------------------
  std::cout << "case=overlap_gates" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *flash4 = tr.getSpaceByName("flash4");
    AddrSpace *constant = tr.getConstantSpace();
    AddrSpace *register_ = tr.getSpaceByName("register");
    std::cout << "  overlap wrap=" << Address(flash4, 0xfffffffe).overlap(4, Address(flash4, 0x1), 8)
              << " negskip=" << Address(flash4, 0x10).overlap(-8, Address(flash4, 0x5), 16)
              << " far=" << Address(flash4, 0x0).overlap(0, Address(flash4, 0x8), 4) << std::endl;
    std::cout << "  const=" << Address(constant, 0x10).overlap(0, Address(constant, 0x8), 16)
              << " crossspace=" << Address(ram, 0x10).overlap(0, Address(register_, 0x8), 16)
              << " plain=" << Address(ram, 0x12).overlap(0, Address(ram, 0x10), 8) << std::endl;
  }

  // ---- case 6: SeqNum ordering ladder --------------------------------------
  std::cout << "case=seqnum_order" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *constant = tr.getConstantSpace();
    SeqNum a(Address(ram, 0x1000), 5);
    SeqNum b(Address(ram, 0x1000), 6);
    SeqNum c(Address(ram, 0x80), 9);
    SeqNum d(Address(constant, 0x10), 0);
    SeqNum e(Address(ram, 0x1000), 5);
    std::cout << "  lt(a,b)=" << (a < b ? 1 : 0)
              << " lt(b,a)=" << (b < a ? 1 : 0)
              << " lt(c,a)=" << (c < a ? 1 : 0)
              << " lt(d,a)=" << (d < a ? 1 : 0)
              << " eq(a,e)=" << ((a == e) ? 1 : 0) << std::endl;
    std::cout << "  print_a=" << a << std::endl;
  }
  return 0;
}
