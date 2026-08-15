/*
 * SPACE-REGISTRY-1204: locked Ghidra 12.0.4 architecture-owned AddrSpace
 * registry oracle (AddrSpaceManager core).
 *
 * The fixture drives a real Translate-owned AddrSpaceManager through the
 * production space lifecycle: canonical insert order with dynamic index
 * allocation, name/index/type rejection with partial baselist growth,
 * dead-slot hole skipping and late re-fill, shortcut assignment with
 * collisions and the >26 'z' reuse, wordsize/addrsize/endian/flag
 * projection (calcScaleMask, wrapOffset, near pointers, truncation,
 * overlay-base marking), the spacebase pointer bridge
 * (addSpacebasePointer/setBaseRegister), and copySpaces refcounting.
 * Every observation is printed in the shared line format so the Rust
 * comparand must match byte for byte.
 */

#include <bits/stdc++.h>

// Test-only access is required to read AddrSpace::refcount (private, no
// getter), to fill TruncationTag fields without the XML decoder, and to
// reach OverlaySpace::baseSpace (implicitly private, no label token). The
// explicit-label members need `private -> public`; the label-less ones need
// `class -> struct`. This matches the access-hack precedent of the
// cover_rebuild fixture and is confined to this translation unit.
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

class FixtureAddrSpace final : public AddrSpace {
public:
  // Expose the protected members the fixture needs: the flag setter (to
  // build a synthetic OTHER-typed space at a wrong index, a state production
  // only reaches through decode) and truncateSpace.
  using AddrSpace::AddrSpace;
  void exposeSetFlags(uint4 fl) { setFlags(fl); }
  void exposeTruncate(uint4 sz) { truncateSpace(sz); }
};

// Overlay spaces are only fully specified through OverlaySpace::decode in
// production (space.cc:661-680). This fixture subclass applies the same
// decode-body field flow with the name/index/base supplied directly.
class FixtureOverlaySpace final : public OverlaySpace {
public:
  FixtureOverlaySpace(AddrSpaceManager *m, const Translate *t,
                      const std::string &nm, int4 ind, AddrSpace *base)
      : OverlaySpace(m, t) {
    name = nm;
    index = ind;
    baseSpace = base; // private member, public via the fixture access hack
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

  // AddrSpaceManager protected bridge, exactly like production Translate
  // subclasses (SleighTranslate) call these during initialization.
  std::string tryInsertSpace(AddrSpace *spc) {
    try {
      insertSpace(spc);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
  }

  std::string tryAddSpacebasePointer(SpacebaseSpace *basespace,
                                     const VarnodeData &ptrdata, int4 truncSize,
                                     bool stackGrowth) {
    try {
      addSpacebasePointer(basespace, ptrdata, truncSize, stackGrowth);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
  }

  std::string trySetDefaultCodeSpace(int4 index) {
    try {
      setDefaultCodeSpace(index);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
  }

  std::string tryCopySpaces(const AddrSpaceManager *op2) {
    try {
      copySpaces(op2);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
  }

  std::string tryGetSpacebase(const AddrSpace *spc, int4 i, VarnodeData &out) {
    try {
      out = spc->getSpacebase(i);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
  }

  std::string tryTruncateSpace(const std::string &name, uint4 size) {
    TruncationTag tag;
    tag.spaceName = name;
    tag.size = size;
    try {
      truncateSpace(tag);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
  }

  void doMarkNearPointers(AddrSpace *spc, int4 size) {
    markNearPointers(spc, size);
  }

  void doSetReverseJustified(AddrSpace *spc) { setReverseJustified(spc); }

  void doSetInferPtrBounds(const Range &range) { setInferPtrBounds(range); }

  void doSetDeadcodeDelay(AddrSpace *spc, int4 delay) {
    setDeadcodeDelay(spc, delay);
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

static void printSpaceLine(const AddrSpace *spc) {
  std::cout << "  space idx=" << spc->getIndex()
            << " name=" << spc->getName()
            << " type=" << (int4)spc->getType()
            << " addrsize=" << spc->getAddrSize()
            << " wordsize=" << spc->getWordSize()
            << " endian=" << (spc->isBigEndian() ? "big" : "l")
            << " shortcut=" << spc->getShortcut()
            << " delay=" << spc->getDelay()
            << " dead=" << spc->getDeadcodeDelay()
            << " highest=" << hexU64(spc->getHighest())
            << " plb=" << hexU64(spc->getPointerLowerBound())
            << " pub=" << hexU64(spc->getPointerUpperBound())
            << " minptr=" << spc->getMinimumPtrSize()
            << " ref=" << spc->refcount
            << " be=" << (spc->isBigEndian() ? 1 : 0)
            << " h=" << (spc->isHeritaged() ? 1 : 0)
            << " dc=" << (spc->doesDeadcode() ? 1 : 0)
            << " rj=" << (spc->isReverseJustified() ? 1 : 0)
            << " fs=" << (spc->isFormalStackSpace() ? 1 : 0)
            << " ov=" << (spc->isOverlay() ? 1 : 0)
            << " ob=" << (spc->isOverlayBase() ? 1 : 0)
            << " tr=" << (spc->isTruncated() ? 1 : 0)
            << " hp=" << (spc->hasPhysical() ? 1 : 0)
            << " oo=" << (spc->isOtherSpace() ? 1 : 0)
            << " np=" << (spc->hasNearPointers() ? 1 : 0)
            << std::endl;
}

static void printWalk(const AddrSpaceManager *mgr) {
  std::cout << "  walk";
  for (AddrSpace *spc = mgr->getNextSpaceInOrder((AddrSpace *)0);
       spc != (AddrSpace *)0 && spc != (AddrSpace *)~((uintp)0);
       spc = mgr->getNextSpaceInOrder(spc)) {
    std::cout << " " << spc->getName();
  }
  std::cout << std::endl;
}

// Build the canonical synthetic architecture (same layout the production
// fixtures use): const=0, OTHER=1, unique=2, ram=3, register=4, stack=5,
// join=6, iop=7.
static void buildCanonical(FixtureTranslate *tr) {
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
  tr->trySetDefaultCodeSpace(3);
}

int main(void) {
  std::cout << "schema=1|fixture=SPACE-REGISTRY-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // ---- case 1: canonical insert order + index allocation ----------------
  std::cout << "case=canonical_insert_order" << std::endl;
  {
    FixtureTranslate tr;
    buildCanonical(&tr);
    std::cout << "  numSpaces=" << tr.numSpaces() << std::endl;
    for (int4 i = 0; i < tr.numSpaces(); ++i)
      printSpaceLine(tr.getSpace(i));
    std::cout << "  defaultSize=" << tr.getDefaultSize() << std::endl;
    std::cout << "  const=" << tr.getConstantSpace()->getName()
              << " iop=" << tr.getIopSpace()->getName()
              << " join=" << tr.getJoinSpace()->getName()
              << " stack=" << tr.getStackSpace()->getName()
              << " uniq=" << tr.getUniqueSpace()->getName()
              << " code=" << tr.getDefaultCodeSpace()->getName()
              << " data=" << tr.getDefaultDataSpace()->getName() << std::endl;
    printWalk(&tr);
  }

  // ---- case 2: rejection paths (name/id/type/index) ----------------------
  std::cout << "case=rejection_paths" << std::endl;
  {
    FixtureTranslate tr;
    tr.tryInsertSpace(new ConstantSpace(&tr, &tr));
    tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "ram", false, 8,
                                    1, 3, AddrSpace::hasphysical, 0, 0));
    tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "register", false,
                                    8, 1, 4, AddrSpace::hasphysical, 0, 0));
    std::cout << "  "
              << tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR,
                                                 "extra", false, 8, 1, 3, 0,
                                                 0, 0))
              << std::endl;
    std::cout << "  "
              << tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR,
                                                 "ram", false, 8, 1, 9, 0,
                                                 0, 0))
              << std::endl;
    std::cout << "  "
              << tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_INTERNAL,
                                                 "tmpx", false, 8, 1, 9, 0,
                                                 0, 0))
              << std::endl;
    std::cout << "  "
              << tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_CONSTANT,
                                                 "const", false, 8, 1, 5, 0,
                                                 0, 0))
              << std::endl;
    FixtureAddrSpace *fakeOther = new FixtureAddrSpace(
        &tr, &tr, IPTR_PROCESSOR, "OTHER", false, 8, 1, 5, 0, 0, 0);
    fakeOther->exposeSetFlags(AddrSpace::is_otherspace);
    std::cout << "  " << tr.tryInsertSpace(fakeOther) << std::endl;
    std::cout << "  " << tr.tryInsertSpace(new ConstantSpace(&tr, &tr))
              << std::endl;
    std::cout << "  numSpaces=" << tr.numSpaces() << std::endl;
    std::cout << "  extraLookup="
              << (tr.getSpaceByName("extra") == (AddrSpace *)0 ? "null"
                                                                : "found")
              << std::endl;
    std::cout << "  slot9="
              << (tr.getSpace(9) == (AddrSpace *)0 ? "null" : "found")
              << std::endl;
    printWalk(&tr);
  }

  // ---- case 3: dead-hole skipping and late re-fill -----------------------
  std::cout << "case=hole_fill_iteration" << std::endl;
  {
    FixtureTranslate tr;
    tr.tryInsertSpace(new ConstantSpace(&tr, &tr));
    tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "ram", false, 8,
                                    1, 3, AddrSpace::hasphysical, 0, 0));
    std::cout << "  numSpaces=" << tr.numSpaces() << std::endl;
    printWalk(&tr);
    std::cout << "  slot1="
              << (tr.getSpace(1) == (AddrSpace *)0 ? "null" : "found")
              << std::endl;
    tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "extra", false, 8,
                                    1, 2, 0, 0, 0));
    std::cout << "  numSpaces=" << tr.numSpaces() << std::endl;
    printWalk(&tr);
    tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "far", false, 8,
                                    1, 9, 0, 0, 0));
    std::cout << "  numSpaces=" << tr.numSpaces() << std::endl;
    printWalk(&tr);
    std::cout << "  slot8="
              << (tr.getSpace(8) == (AddrSpace *)0 ? "null" : "found")
              << std::endl;
  }

  // ---- case 4: shortcut assignment + collisions --------------------------
  std::cout << "case=shortcut_collision" << std::endl;
  {
    FixtureTranslate tr;
    tr.tryInsertSpace(new ConstantSpace(&tr, &tr));
    tr.tryInsertSpace(new OtherSpace(&tr, &tr, OtherSpace::INDEX));
    tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "register", false,
                                    8, 1, 4, AddrSpace::hasphysical, 0, 0));
    AddrSpace *ram = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "ram", false, 8, 1,
                                   3, AddrSpace::hasphysical, 0, 0);
    tr.tryInsertSpace(ram);
    tr.tryInsertSpace(new UniqueSpace(&tr, &tr, 2, 0));
    tr.tryInsertSpace(new SpacebaseSpace(&tr, &tr, "stack", 5, 8, ram, 1, true));
    tr.tryInsertSpace(new JoinSpace(&tr, &tr, 6));
    tr.tryInsertSpace(new IopSpace(&tr, &tr, 7));
    tr.tryInsertSpace(new FspecSpace(&tr, &tr, 8));
    AddrSpace *sram = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "sram", false, 8,
                                    1, 9, 0, 0, 0);
    tr.tryInsertSpace(sram);
    AddrSpace *trampoline = new AddrSpace(&tr, &tr, IPTR_PROCESSOR,
                                          "trampoline", false, 8, 1, 10, 0, 0,
                                          0);
    tr.tryInsertSpace(trampoline);
    AddrSpace *zulu = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "Zulu", false, 8,
                                    1, 11, 0, 0, 0);
    tr.tryInsertSpace(zulu);
    std::cout << "  sram=" << sram->getShortcut()
              << " trampoline=" << trampoline->getShortcut()
              << " zulu=" << zulu->getShortcut() << std::endl;
    const char *keys[] = {"#", "%", "s", "u", "j", "i", "f", "r", "o", "t",
                          "v", "z"};
    for (int4 i = 0; i < 12; ++i) {
      AddrSpace *spc = tr.getSpaceByShortcut(keys[i][0]);
      std::cout << "  lookup " << keys[i] << " -> "
                << (spc == (AddrSpace *)0 ? std::string("null")
                                          : spc->getName())
                << std::endl;
    }
  }

  // ---- case 5: shortcut 'z' reuse after 26 collisions --------------------
  std::cout << "case=shortcut_z_reuse" << std::endl;
  {
    FixtureTranslate tr;
    tr.tryInsertSpace(new ConstantSpace(&tr, &tr));
    for (int4 i = 0; i < 26; ++i) {
      std::string name;
      name += (char)('a' + i);
      name += (char)('a' + i);
      tr.tryInsertSpace(new AddrSpace(&tr, &tr, IPTR_PROCESSOR, name, false, 8,
                                      1, i + 1, 0, 0, 0));
    }
    AddrSpace *apple = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "apple", false,
                                     8, 1, 27, 0, 0, 0);
    tr.tryInsertSpace(apple);
    std::cout << "  appleShortcut=" << apple->getShortcut() << std::endl;
    std::cout << "  zOwner=" << tr.getSpaceByShortcut('z')->getName()
              << std::endl;
  }

  // ---- case 6: wordsize/addrsize/endian/flag projection ------------------
  std::cout << "case=projection_wordsize_endian_flags" << std::endl;
  {
    FixtureTranslate tr;
    AddrSpace *ws2 = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "ws2", false, 4, 2,
                                   3, 0, 0, 0);
    tr.tryInsertSpace(ws2);
    AddrSpace *ws3 = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "ws3", false, 2, 3,
                                   4, 0, 0, 0);
    tr.tryInsertSpace(ws3);
    FixtureAddrSpace *big = new FixtureAddrSpace(&tr, &tr, IPTR_PROCESSOR, "big", true, 8, 1,
                                   5, 0, 0, 0);
    tr.tryInsertSpace(big);
    printSpaceLine(ws2);
    printSpaceLine(ws3);
    printSpaceLine(big);
    std::cout << "  a2b(5,2)=" << AddrSpace::addressToByte(5, 2)
              << " b2a(10,2)=" << AddrSpace::byteToAddress(10, 2)
              << " a2bi(7,2)=" << AddrSpace::addressToByteInt(7, 2)
              << " b2ai(14,2)=" << AddrSpace::byteToAddressInt(14, 2)
              << std::endl;
    std::cout << "  wrap " << hexU64(ws2->wrapOffset(0x1ffffffff)) << " "
              << hexU64(ws2->wrapOffset(0x200000000)) << " "
              << hexU64(ws2->wrapOffset(0x200000001)) << " "
              << hexU64(ws2->wrapOffset(0x300000002)) << std::endl;
    tr.doMarkNearPointers(ws2, 2);
    tr.doSetReverseJustified(ws2);
    tr.doSetDeadcodeDelay(ws2, 7);
    std::cout << "  afterMarks"
              << " np=" << (ws2->hasNearPointers() ? 1 : 0)
              << " minptr=" << ws2->getMinimumPtrSize()
              << " rj=" << (ws2->isReverseJustified() ? 1 : 0)
              << " dead=" << ws2->getDeadcodeDelay() << std::endl;
    Range rng(ws2, 0x10, 0x20);
    tr.doSetInferPtrBounds(rng);
    std::cout << "  inferBounds plb=" << hexU64(ws2->getPointerLowerBound())
              << " pub=" << hexU64(ws2->getPointerUpperBound()) << std::endl;
    big->exposeTruncate(4);
    std::cout << "  truncated tr=" << (big->isTruncated() ? 1 : 0)
              << " minptr=" << big->getMinimumPtrSize()
              << " addrsize=" << big->getAddrSize()
              << " highest=" << hexU64(big->getHighest()) << std::endl;
    AddrSpace *ram = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "ram", false, 8, 1,
                                   6, AddrSpace::hasphysical, 0, 0);
    tr.tryInsertSpace(ram);
    tr.tryInsertSpace(new FixtureOverlaySpace(&tr, &tr, "ov", 7, ram));
    AddrSpace *ov = tr.getSpaceByName("ov");
    std::cout << "  overlay ram_ob=" << (ram->isOverlayBase() ? 1 : 0)
              << " ov_ov=" << (ov->isOverlay() ? 1 : 0)
              << " contain=" << ov->getContain()->getName()
              << " ov_hp=" << (ov->hasPhysical() ? 1 : 0) << std::endl;
    std::cout << "  " << tr.tryTruncateSpace("nosuch", 4) << std::endl;
    std::cout << "  " << tr.tryTruncateSpace("ov", 2) << std::endl;
    std::cout << "  ovAfter tr=" << (ov->isTruncated() ? 1 : 0)
              << " addrsize=" << ov->getAddrSize()
              << " highest=" << hexU64(ov->getHighest()) << std::endl;
  }

  // ---- case 7: spacebase pointer bridge ----------------------------------
  std::cout << "case=spacebase_pointer_bridge" << std::endl;
  {
    FixtureTranslate tr;
    tr.tryInsertSpace(new ConstantSpace(&tr, &tr));
    AddrSpace *ram = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "ram", false, 8, 1,
                                   3, AddrSpace::hasphysical, 0, 0);
    tr.tryInsertSpace(ram);
    AddrSpace *reg = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    tr.tryInsertSpace(reg);
    SpacebaseSpace *stack =
        new SpacebaseSpace(&tr, &tr, "stack", 5, 8, ram, 1, true);
    tr.tryInsertSpace(stack);
    std::cout << "  numBaseBefore=" << stack->numSpacebase() << std::endl;
    VarnodeData ptr;
    ptr.space = reg;
    ptr.offset = 0;
    ptr.size = 8;
    std::cout << "  " << tr.tryAddSpacebasePointer(stack, ptr, 8, true)
              << std::endl;
    std::cout << "  numBaseAfter=" << stack->numSpacebase() << std::endl;
    VarnodeData base;
    std::cout << "  get0 " << tr.tryGetSpacebase(stack, 0, base)
              << " space=" << base.space->getName() << " off=" << base.offset
              << " size=" << base.size << std::endl;
    VarnodeData full = stack->getSpacebaseFull(0);
    std::cout << "  full0 space=" << full.space->getName()
              << " off=" << full.offset << " size=" << full.size << std::endl;
    std::cout << "  growsNeg=" << (stack->stackGrowsNegative() ? 1 : 0)
              << " contain=" << stack->getContain()->getName() << std::endl;
    std::cout << "  readdSame "
              << tr.tryAddSpacebasePointer(stack, ptr, 8, true) << std::endl;
    VarnodeData other;
    other.space = reg;
    other.offset = 8;
    other.size = 8;
    std::cout << "  "
              << tr.tryAddSpacebasePointer(stack, other, 8, true) << std::endl;
    std::cout << "  get1 " << tr.tryGetSpacebase(stack, 1, base) << std::endl;
    SpacebaseSpace *heap =
        new SpacebaseSpace(&tr, &tr, "heapbase", 6, 8, ram, 0, false);
    tr.tryInsertSpace(heap);
    std::cout << "  heapNum=" << heap->numSpacebase() << " growsNeg="
              << (heap->stackGrowsNegative() ? 1 : 0) << " formal="
              << (heap->isFormalStackSpace() ? 1 : 0) << std::endl;
    std::cout << "  heapGet0 " << tr.tryGetSpacebase(heap, 0, base)
              << std::endl;
    // Big-endian register truncation shifts the offset up by the lost bytes.
    AddrSpace *bereg = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "beregi", true,
                                     8, 1, 7, 0, 0, 0);
    SpacebaseSpace *bestack =
        new SpacebaseSpace(&tr, &tr, "bestack", 8, 8, ram, 0, false);
    VarnodeData beptr;
    beptr.space = bereg;
    beptr.offset = 0x100;
    beptr.size = 8;
    std::cout << "  beTrunc "
              << tr.tryAddSpacebasePointer(bestack, beptr, 4, false)
              << std::endl;
    VarnodeData bebase = bestack->getSpacebase(0);
    std::cout << "  beBase off=" << hexU64(bebase.offset) << " size="
              << bebase.size << " growsNeg="
              << (bestack->stackGrowsNegative() ? 1 : 0) << std::endl;
    VarnodeData befull = bestack->getSpacebaseFull(0);
    std::cout << "  beFull off=" << hexU64(befull.offset) << " size="
              << befull.size << std::endl;
    // Little-endian truncation keeps the low offset.
    SpacebaseSpace *lestack =
        new SpacebaseSpace(&tr, &tr, "lestack", 9, 8, ram, 0, false);
    VarnodeData leptr;
    leptr.space = reg;
    leptr.offset = 0x100;
    leptr.size = 8;
    tr.tryAddSpacebasePointer(lestack, leptr, 4, true);
    VarnodeData lebase = lestack->getSpacebase(0);
    std::cout << "  leBase off=" << hexU64(lebase.offset) << " size="
              << lebase.size << std::endl;
  }

  // ---- case 8: copySpaces shared-handle refcounting ----------------------
  std::cout << "case=copy_spaces_refcount" << std::endl;
  {
    FixtureTranslate trA;
    buildCanonical(&trA);
    FixtureTranslate trB;
    std::cout << "  " << trB.tryCopySpaces(&trA) << std::endl;
    std::cout << "  numSpaces=" << trB.numSpaces() << std::endl;
    AddrSpace *ramA = trA.getSpaceByName("ram");
    AddrSpace *ramB = trB.getSpaceByName("ram");
    std::cout << "  sameHandle=" << (ramA == ramB ? 1 : 0) << std::endl;
    std::cout << "  refA=" << ramA->refcount << " refB=" << ramB->refcount
              << std::endl;
    std::cout << "  defaultSize=" << trB.getDefaultSize()
              << " code=" << trB.getDefaultCodeSpace()->getName()
              << " data=" << trB.getDefaultDataSpace()->getName() << std::endl;
    std::cout << "  slots iop=" << trB.getIopSpace()->getName()
              << " join=" << trB.getJoinSpace()->getName()
              << " stack=" << trB.getStackSpace()->getName()
              << " uniq=" << trB.getUniqueSpace()->getName()
              << " const=" << trB.getConstantSpace()->getName() << std::endl;
    printWalk(&trB);
    std::cout << "  "
              << trB.tryInsertSpace(new AddrSpace(&trB, &trB, IPTR_PROCESSOR,
                                                  "ram", false, 8, 1, 9, 0,
                                                  0, 0))
              << std::endl;
  }
  return 0;
}
