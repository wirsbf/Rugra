/*
 * ADDRESS-SPACE-PHASE1-1204: locked Ghidra 12.0.4 oracle for the
 * ADDRESS-0001 phase-1 legacy-Address space bridge (address.hh/address.cc).
 *
 * Phase 1 keeps the Copy legacy `Address` and adds an optional interned
 * space tag; every pre-existing construction site mints the `None` (spaceless)
 * form. The Ghidra model of that `None` is the null `base` slot. The
 * operators define null-base behavior without dereferencing it:
 *   - operator== (address.hh:356): null equals null (offset compared), never
 *     a real space;
 *   - operator< / operator<= (address.hh:375-393/398): null sorts before
 *     every real base (:377/:383), different real spaces order by index
 *     (:389), the same space orders by offset (:391);
 *   - operator+/- (address.hh:423/433) and overlap (address.cc:153-165) are
 *     only defined for real bases in Ghidra and are exercised here with
 *     tagged spaces only.
 *
 * This fixture drives the comparison chain around that model: the None
 * fallback (null-base to null-base, offset-only) including a sorted-container
 * walk, the None-to-tagged meeting rules, cross-space index ordering with
 * None mixed in, tag identity (pointer identity: repeated construction from
 * the same registry handle, including a re-fetched handle clone), and
 * wrapOffset arithmetic plus the overlap gates through real spaces. The
 * null-base-with-explicit-offset state has no public Ghidra constructor, so
 * the fixture reaches it with the same class->struct access hack the
 * space_registry/address_space_handle fixtures use; every observation then
 * goes through the public operators only. The Rust comparand (which mints
 * `None` via `Address::new` and tagged spaces via `Address::with_space`)
 * must match byte for byte.
 */

#include <bits/stdc++.h>

// Test-only access is required to construct the null-base-with-explicit-
// offset state that the phase-1 Rust `Address::new` represents (Address
// keeps its fields behind an explicit `protected:` label, so the
// class->struct swap alone is not enough) and to subclass Translate. This
// matches the access-hack precedent of the space_registry /
// address_space_handle fixtures and is confined to this translation unit.
#define class struct
#define private public
#define protected public
#include "address.hh"
#include "fspec.hh"
#include "op.hh"
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

// The phase-1 Rust `Address::new(off)` state: a null base with an explicit
// offset. Ghidra only builds offset 0 publicly (m_minimal, address.cc:94-97);
// the explicit offset needs the protected-slot write. All comparisons below
// observe it through the public operators only.
static Address nullBase(uintb off) {
  Address a;      // address.hh:263 default ctor: base = (AddrSpace *)0
  a.offset = off; // the phase-1 bridge state under test
  return a;
}

// Print one address for the ordering walk: the space name and the raw
// offset, with the null-base state spelled out (it has no space to name).
static std::string walkLabel(const Address &a) {
  if (a.isInvalid())
    return std::string("invalid:") + hexU64(a.getOffset());
  return a.getSpace()->getName() + ":" + hexU64(a.getOffset());
}

// Build the canonical synthetic architecture subset the ordering and wrap
// cases need: constant=0, OTHER=1, unique=2, ram=3, register=4 and the
// 4-byte wrap space flash4=8 (same indices as the address_space_handle
// fixture).
static void buildSpaces(FixtureTranslate *tr) {
  tr->tryInsertSpace(new ConstantSpace(tr, tr));
  tr->tryInsertSpace(new OtherSpace(tr, tr, OtherSpace::INDEX));
  tr->tryInsertSpace(new UniqueSpace(tr, tr, 2, 0));
  tr->tryInsertSpace(new AddrSpace(tr, tr, IPTR_PROCESSOR, "ram", false, 8, 1,
                                   3, AddrSpace::hasphysical, 0, 0));
  tr->tryInsertSpace(new AddrSpace(tr, tr, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0));
  tr->tryInsertSpace(new AddrSpace(tr, tr, IPTR_PROCESSOR, "flash4", false, 4,
                                   1, 8, 0, 0, 0));
}

int main(void) {
  std::cout << "schema=1|fixture=ADDRESS-SPACE-PHASE1-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // ---- case 1: the None fallback = null-base to null-base ---------------
  std::cout << "case=none_compat_fallback" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    Address n1000 = nullBase(0x1000);
    Address n800 = nullBase(0x800);
    Address n800b = nullBase(0x800);
    Address n0 = nullBase(0);
    std::cout << "  eq_n800_n800b=" << ((n800 == n800b) ? 1 : 0)
              << " eq_n800_n1000=" << ((n800 == n1000) ? 1 : 0)
              << " ne_n800_n1000=" << ((n800 != n1000) ? 1 : 0) << std::endl;
    std::cout << "  lt_n800_n1000=" << ((n800 < n1000) ? 1 : 0)
              << " lt_n1000_n800=" << ((n1000 < n800) ? 1 : 0)
              << " le_n800_n800b=" << ((n800 <= n800b) ? 1 : 0) << std::endl;
    std::cout << "  isInvalid_n1000=" << (n1000.isInvalid() ? 1 : 0)
              << " isInvalid_minimal="
              << (Address(Address::m_minimal).isInvalid() ? 1 : 0)
              << " eq_minimal_n0="
              << ((Address(Address::m_minimal) == n0) ? 1 : 0) << std::endl;
    std::set<Address> ordered;
    ordered.insert(n1000);
    ordered.insert(n800);
    ordered.insert(n0);
    ordered.insert(nullBase(0xffffffffffffffff));
    std::cout << "  size=" << ordered.size() << std::endl;
    for (std::set<Address>::const_iterator it = ordered.begin();
         it != ordered.end(); ++it) {
      std::cout << "  walk " << walkLabel(*it) << std::endl;
    }
    // The meeting rules where the two models touch (address.hh:356/377/383).
    Address ram1000(ram, 0x1000);
    Address ram800(ram, 0x800);
    Address ram0(ram, 0);
    std::cout << "  eq_n1000_ram1000=" << ((n1000 == ram1000) ? 1 : 0)
              << " lt_n1000_ram800=" << ((n1000 < ram800) ? 1 : 0)
              << " lt_ram800_n1000=" << ((ram800 < n1000) ? 1 : 0)
              << " le_n1000_ram0=" << ((n1000 <= ram0) ? 1 : 0)
              << " isInvalid_ram1000=" << (ram1000.isInvalid() ? 1 : 0)
              << std::endl;
  }

  // ---- case 2: cross-space ordering with the null base mixed in ---------
  std::cout << "case=space_ordering" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *constant = tr.getConstantSpace();
    AddrSpace *other = tr.getSpaceByName("OTHER");
    AddrSpace *unique = tr.getUniqueSpace();
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *register_ = tr.getSpaceByName("register");
    std::set<Address> ordered;
    ordered.insert(Address(register_, 0x5000));
    ordered.insert(Address(unique, 0x99));
    ordered.insert(Address(ram, 0x1000));
    ordered.insert(Address(constant, 0x7f));
    ordered.insert(Address(other, 0x1));
    ordered.insert(Address(ram, 0x2000));
    ordered.insert(Address(register_, 0x3000));
    ordered.insert(Address(unique, 0x11));
    ordered.insert(Address(ram, 0x800));
    ordered.insert(nullBase(0x1000));
    std::cout << "  size=" << ordered.size() << std::endl;
    for (std::set<Address>::const_iterator it = ordered.begin();
         it != ordered.end(); ++it) {
      std::cout << "  walk " << walkLabel(*it) << std::endl;
    }
    std::cout << "  lt(const7f,other1)="
              << (Address(constant, 0x7f) < Address(other, 0x1) ? 1 : 0)
              << " lt(register3000,ram2000)="
              << (Address(register_, 0x3000) < Address(ram, 0x2000) ? 1 : 0)
              << " lt(ram800,ram1000)="
              << (Address(ram, 0x800) < Address(ram, 0x1000) ? 1 : 0)
              << " lt(unique99,ram1)="
              << (Address(unique, 0x99) < Address(ram, 0x1) ? 1 : 0)
              << std::endl;
    std::cout << "  eq_ram1000_again="
              << (Address(ram, 0x1000) == Address(ram, 0x1000) ? 1 : 0)
              << " eq_ram1000_reg1000="
              << (Address(ram, 0x1000) == Address(register_, 0x1000) ? 1 : 0)
              << std::endl;
  }

  // ---- case 3: tag identity = AddrSpace pointer identity ---------------
  std::cout << "case=tag_identity" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *register_ = tr.getSpaceByName("register");
    Address a1(ram, 0x1000);
    Address a2(ram, 0x1000);
    Address a3(register_, 0x1000);
    std::cout << "  eq_same_space_twice=" << ((a1 == a2) ? 1 : 0)
              << " ne_distinct_space=" << ((a1 != a3) ? 1 : 0) << std::endl;
    std::cout << "  resolve_a1=" << a1.getSpace()->getName()
              << " resolve_a3=" << a3.getSpace()->getName() << std::endl;
    std::set<Address> dedup;
    dedup.insert(a1);
    dedup.insert(Address(ram, 0x1000));
    std::cout << "  set_dedup_size=" << dedup.size() << std::endl;
    std::cout << "  print_a1=" << pr(a1) << " print_a3=" << pr(a3) << std::endl;
    // A re-fetched handle from the manager is the same allocation: the Rust
    // intern table must return the same tag for the cloned handle.
    AddrSpace *ramAgain = tr.getSpaceByName("ram");
    std::cout << "  eq_handle_clone="
              << ((a1 == Address(ramAgain, 0x1000)) ? 1 : 0) << std::endl;
  }

  // ---- case 4: wrap arithmetic and overlap gates through real spaces ---
  std::cout << "case=wrap_overlap_tagged" << std::endl;
  {
    FixtureTranslate tr;
    buildSpaces(&tr);
    AddrSpace *ram = tr.getSpaceByName("ram");
    AddrSpace *flash4 = tr.getSpaceByName("flash4");
    AddrSpace *constant = tr.getConstantSpace();
    AddrSpace *register_ = tr.getSpaceByName("register");
    std::cout << "  flash4 fffffffe+2="
              << hexU64((Address(flash4, 0xfffffffe) + 2).getOffset())
              << " ffffffff+1="
              << hexU64((Address(flash4, 0xffffffff) + 1).getOffset())
              << " fffffffe+3="
              << hexU64((Address(flash4, 0xfffffffe) + 3).getOffset())
              << " 10-11="
              << hexU64((Address(flash4, 0x10) - 0x11).getOffset()) << std::endl;
    std::cout << "  ram maxff+1="
              << hexU64((Address(ram, 0xffffffffffffffff) + 1).getOffset())
              << std::endl;
    std::cout << "  overlap wrap="
              << Address(flash4, 0xfffffffe).overlap(4, Address(flash4, 0x1), 8)
              << " negskip="
              << Address(flash4, 0x10).overlap(-8, Address(flash4, 0x5), 16)
              << " const="
              << Address(constant, 0x10).overlap(0, Address(constant, 0x8), 16)
              << " crossspace="
              << Address(ram, 0x10).overlap(0, Address(register_, 0x8), 16)
              << std::endl;
  }
  return 0;
}
