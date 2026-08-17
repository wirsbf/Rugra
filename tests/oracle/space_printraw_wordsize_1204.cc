/*
 * SPACE-PRINTRAW-WORDSIZE-1204: locked Ghidra 12.0.4 oracle for
 * AddrSpace::printRaw (space.cc:206-222) and the per-space getAddrSize()
 * projection (SPACE-PRINTRAW-WORDSIZE-0001).
 *
 * The printRaw cases lock, byte for byte:
 *   - the fixed 2*addrsize hex width for addrsize <= 4 spaces,
 *   - the leading-zero shrink rule for addrsize > 4 spaces
 *     (offset>>32==0 -> 4 bytes, else offset>>48==0 -> 6 bytes; the shrink
 *     test uses the raw byte offset, not the scaled value),
 *   - the byteToAddress(offset, wordsize) scaling for wordsize 2/4 spaces
 *     (space.hh:523),
 *   - the "+cut" suffix for off-cut offsets (offset % wordsize != 0),
 *   - ostream setw minimum-width semantics: a scaled value wider than the
 *     2*sz field prints fully and un-padded,
 *   - and the ConstantSpace/OtherSpace printRaw overrides (space.cc:372/410:
 *     plain hex, no padding, no scaling).
 *
 * The addrsize_projection case locks the canonical per-space address sizes
 * over the real constructors: const/OTHER = sizeof(uintb) = 8 (space.cc:357/
 * 397), iop = sizeof(void *) = 8 (op.cc:36), unique = UniqueSpace::SIZE = 4
 * (space.cc:418/428), join = sizeof(uintm) = 4 (types.h:27, space.cc:447),
 * the x86-64-shaped ram/register/stack = 8, and an overlay space copying its
 * base (space.cc:661-680). The "legacy" lines echo the same values for the
 * nine Rugra flat-enum space kinds so the enum mapping is locked against the
 * Ghidra truth.
 */

#include <bits/stdc++.h>

// Test-only access for OverlaySpace::baseSpace (implicitly private, no label
// token) via the `class -> struct` precedent of the space_registry_1204 and
// cover_rebuild fixtures, confined to this translation unit.
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

class FixtureOverlaySpace final : public OverlaySpace {
public:
  // Overlay spaces are only fully specified through OverlaySpace::decode in
  // production (space.cc:661-680). This fixture subclass applies the same
  // decode-body field flow with the name/index/base supplied directly.
  FixtureOverlaySpace(AddrSpaceManager *m, const Translate *t,
                      const std::string &nm, int4 ind, AddrSpace *base)
      : OverlaySpace(m, t) {
    name = nm;
    index = ind;
    baseSpace = base;
    addressSize = base->getAddrSize();
    wordsize = base->getWordSize();
    delay = base->getDelay();
    deadcodedelay = base->getDeadcodeDelay();
    calcScaleMask();
    if (base->isBigEndian())
      setFlags(AddrSpace::big_endian);
    if (base->hasPhysical())
      setFlags(AddrSpace::hasphysical);
  }
};

class FixtureTranslate final : public Translate {
public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    static VarnodeData dummy;
    return dummy;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override {
    return 0;
  }
  int4 printAssembly(AssemblyEmit &, const Address &) const override {
    return 0;
  }
};

static void printRawLine(const AddrSpace *spc, uintb off) {
  std::ostringstream hold;
  spc->printRaw(hold, off);
  std::cout << "  " << spc->getName() << " off=0x" << std::hex << off
            << " -> " << hold.str() << std::endl;
}

int main(void) {
  std::cout << "schema=1|fixture=SPACE-PRINTRAW-WORDSIZE-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;
  FixtureTranslate tr;

  // ---- case 1: canonical per-space address sizes -------------------------
  std::cout << "case=addrsize_projection" << std::endl;
  {
    ConstantSpace constspc(&tr, &tr);
    OtherSpace otherspc(&tr, &tr, OtherSpace::INDEX);
    UniqueSpace uniqspc(&tr, &tr, 2, 0);
    AddrSpace ram(&tr, &tr, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                  AddrSpace::hasphysical, 0, 0);
    AddrSpace reg(&tr, &tr, IPTR_PROCESSOR, "register", false, 8, 1, 4,
                  AddrSpace::hasphysical, 0, 0);
    SpacebaseSpace stack(&tr, &tr, "stack", 5, 8, &ram, 1, true);
    JoinSpace joinspc(&tr, &tr, 6);
    IopSpace iopspc(&tr, &tr, 7);
    FixtureOverlaySpace ovram(&tr, &tr, "ovram", 9, &ram);
    const AddrSpace *all[] = {&constspc, &otherspc, &uniqspc, &ram,  &reg,
                              &stack,    &joinspc,   &iopspc,  &ovram};
    for (const AddrSpace *spc : all) {
      std::cout << "  space " << spc->getName() << " addrsize="
                << spc->getAddrSize() << " wordsize=" << spc->getWordSize()
                << std::endl;
    }
    // Legacy flat-enum mapping: echo the constructor truth for each Rugra
    // enum kind (overlay copies its base; "other" is the OTHER space).
    std::cout << "  legacy ram addrsize=" << ram.getAddrSize()
              << " wordsize=" << ram.getWordSize() << std::endl;
    std::cout << "  legacy register addrsize=" << reg.getAddrSize()
              << " wordsize=" << reg.getWordSize() << std::endl;
    std::cout << "  legacy unique addrsize=" << uniqspc.getAddrSize()
              << " wordsize=" << uniqspc.getWordSize() << std::endl;
    std::cout << "  legacy const addrsize=" << constspc.getAddrSize()
              << " wordsize=" << constspc.getWordSize() << std::endl;
    std::cout << "  legacy stack addrsize=" << stack.getAddrSize()
              << " wordsize=" << stack.getWordSize() << std::endl;
    std::cout << "  legacy join addrsize=" << joinspc.getAddrSize()
              << " wordsize=" << joinspc.getWordSize() << std::endl;
    std::cout << "  legacy iop addrsize=" << iopspc.getAddrSize()
              << " wordsize=" << iopspc.getWordSize() << std::endl;
    std::cout << "  legacy overlay addrsize=" << ovram.getAddrSize()
              << " wordsize=" << ovram.getWordSize() << std::endl;
    std::cout << "  legacy other addrsize=" << otherspc.getAddrSize()
              << " wordsize=" << otherspc.getWordSize() << std::endl;
  }

  // ---- case 2: wordsize 1 printing ---------------------------------------
  std::cout << "case=printraw_wordsize1" << std::endl;
  {
    AddrSpace ram8(&tr, &tr, IPTR_PROCESSOR, "ram8", false, 8, 1, 3, 0, 0, 0);
    AddrSpace ram4(&tr, &tr, IPTR_PROCESSOR, "ram4", false, 4, 1, 4, 0, 0, 0);
    AddrSpace ram2(&tr, &tr, IPTR_PROCESSOR, "ram2", false, 2, 1, 5, 0, 0, 0);
    // Shrink rule coverage for the 8-byte space.
    printRawLine(&ram8, 0x0);              // full zero pad, shrunk to 4 bytes
    printRawLine(&ram8, 0x1234);           // shrunk to 4 bytes
    printRawLine(&ram8, 0x123456789ab);    // shrunk to 6 bytes
    printRawLine(&ram8, 0x123456789abcdef0); // full 16 digits
    // Fixed width for <= 4 byte spaces.
    printRawLine(&ram4, 0x0);
    printRawLine(&ram4, 0x1234);
    printRawLine(&ram4, 0xffffffff);
    printRawLine(&ram2, 0x0);
    printRawLine(&ram2, 0x123);
    // setw is a minimum: a value wider than 2*sz prints un-padded.
    printRawLine(&ram2, 0x12345);
  }

  // ---- case 3: wordsize 2 printing ---------------------------------------
  std::cout << "case=printraw_wordsize2" << std::endl;
  {
    AddrSpace ws2x4(&tr, &tr, IPTR_PROCESSOR, "ws2x4", false, 4, 2, 3, 0, 0,
                    0);
    AddrSpace ws2x8(&tr, &tr, IPTR_PROCESSOR, "ws2x8", false, 8, 2, 4, 0, 0,
                    0);
    AddrSpace ws2x2(&tr, &tr, IPTR_PROCESSOR, "ws2x2", false, 2, 2, 5, 0, 0,
                    0);
    printRawLine(&ws2x4, 0x0);       // on-cut, scaled to 0
    printRawLine(&ws2x4, 0x100);     // on-cut
    printRawLine(&ws2x4, 0x101);     // off-cut +1
    printRawLine(&ws2x4, 0x102);     // on-cut, scaled to 0x81
    printRawLine(&ws2x4, 0x103);     // off-cut +1 over 0x81
    printRawLine(&ws2x4, 0xfffffffe);
    printRawLine(&ws2x4, 0xffffffff);
    printRawLine(&ws2x8, 0x10); // shrink rule + scaling
    printRawLine(&ws2x8, 0x11);
    printRawLine(&ws2x8, 0x10000000000);
    printRawLine(&ws2x8, 0xffffffffffffffff);
    printRawLine(&ws2x2, 0x100);
    printRawLine(&ws2x2, 0x1ff);
    printRawLine(&ws2x2, 0x201); // scaled value wider than the 4-digit field
  }

  // ---- case 4: wordsize 4 printing ---------------------------------------
  std::cout << "case=printraw_wordsize4" << std::endl;
  {
    AddrSpace ws4x8(&tr, &tr, IPTR_PROCESSOR, "ws4x8", false, 8, 4, 3, 0, 0,
                    0);
    AddrSpace ws4x4(&tr, &tr, IPTR_PROCESSOR, "ws4x4", false, 4, 4, 4, 0, 0,
                    0);
    printRawLine(&ws4x8, 0x10);
    printRawLine(&ws4x8, 0x13); // +3
    printRawLine(&ws4x8, 0x10000000000);
    printRawLine(&ws4x8, 0x10000000003);
    printRawLine(&ws4x8, 0xffffffffffffffff);
    printRawLine(&ws4x4, 0x1000);
    printRawLine(&ws4x4, 0x1003);
    printRawLine(&ws4x4, 0xffffffff);
  }

  // ---- case 5: ConstantSpace/OtherSpace overrides ------------------------
  std::cout << "case=printraw_overrides" << std::endl;
  {
    ConstantSpace constspc(&tr, &tr);
    OtherSpace otherspc(&tr, &tr, OtherSpace::INDEX);
    printRawLine(&constspc, 0x0);
    printRawLine(&constspc, 0xabc);
    printRawLine(&constspc, 0xdeadbeefcafe);
    printRawLine(&otherspc, 0x0);
    printRawLine(&otherspc, 0xabc);
  }
  return 0;
}
