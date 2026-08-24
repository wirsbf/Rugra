/*
 * STRINGMANAGER-CORE-JAVACONTRACT-0001 locked Ghidra 12.0.4 oracle.
 *
 * Drives the real StringManager production objects: the native
 * StringManagerUnicode (stringmanage.cc:427, sleigh_arch.cc:250 install
 * shape) and, for the production contract, a StringManager subclass that
 * implements the DECLARED GhidraStringManager/Java contract
 * (string_ghidra.cc:42-56 control flow) over the real Ghidra primitives —
 * LoadImage::loadFill, StringManager::hasCharTerminator,
 * StringManager::checkCharacters/getCodepoint and
 * StringManager::assignStringData — with the native 2048-byte search clamp
 * REMOVED. The clamp removal is not invented: the golden corpus
 * (tests/golden/ghidra_curl_1204.c hugehelp) proves the oracle's strings are
 * detected with the terminator beyond byte 2048 and returned truncated to
 * 2048 chars + isTrunc, which is the GhidraStringManager/Java behavior
 * (ghidra_arch.cc:780-810 GETSTRINGDATA), not the native clamp
 * (stringmanage.cc:452-457). The native object is driven in parallel so its
 * 2048-bound behavior is locked on the same inputs.
 *
 * Observation surface per case: entry existence (negative cache), byteData
 * length + first/last bytes + isTruncated, isString, and the fixture
 * loader's per-address read-attempt counts (proving zero re-reads on cached
 * queries and the two-consumer share).
 */

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Test-only exposure permits this manager-level fixture to observe the
// protected stringMap without changing the locked oracle sources.
#define private public
#include "architecture.hh"
#include "capability.hh"
#include "comment.hh"
#include "crc32.hh"
#include "loadimage.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "stringmanage.hh"
#include "translate.hh"
#include "type.hh"
#undef private

using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1,
                              1, AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false, 8,
                                   1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack =
        new SpacebaseSpace(this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stackPointer;
    stackPointer.space = reg;
    stackPointer.offset = 0;
    stackPointer.size = 8;
    addSpacebasePointer(stack, stackPointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1,
                              6, AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummyRegister.space = getSpace(4);
    dummyRegister.offset = 0;
    dummyRegister.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummyRegister;
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
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

class FixtureLoadImage final : public LoadImage {
  struct Region {
    uintb start;
    std::vector<uint1> bytes;
  };

  AddrSpace *ram;
  std::vector<Region> regions;
  // Attempt counts keyed by read start offset; failed attempts (which throw
  // DataUnavailError) are counted too, so cached-query proofs can show that
  // zero further attempts were made.
  std::map<uintb, int4> attempts;

  void addRegion(uintb start, const std::vector<uint1> &contents,
                 uintb paddedSize) {
    Region region;
    region.start = start;
    region.bytes.assign(paddedSize, 0);
    std::copy(contents.begin(), contents.end(), region.bytes.begin());
    regions.push_back(region);
  }

public:
  explicit FixtureLoadImage(AddrSpace *space)
      : LoadImage("stringmanager-core-1204"), ram(space) {
    addRegion(0x2000, {'a', 'l', 'p', 'h', 'a', 0}, 0x100);
    addRegion(0x2100, {'b', 0xad, 0}, 0x100);
    std::vector<uint1> longString(2050, 'A');
    longString.push_back(0);
    addRegion(0x2400, longString, 2050 + 1 + 0x40);
    // No-NUL region, deliberately ABOVE the 0x2400 region's end (0x2C41) so
    // the unbounded contract search cannot spill into the long-string bytes.
    addRegion(0x2E00, std::vector<uint1>(64, 'X'), 64);
  }

  void loadFill(uint1 *ptr, int4 size, const Address &address) override {
    if (address.getSpace() != ram)
      throw DataUnavailError("stringmanager fixture read from a non-RAM space");
    const uintb start = address.getOffset();
    attempts[start] += 1;
    const uintb end = start + size;
    for (const Region &region : regions) {
      if (start >= region.start &&
          end <= region.start + region.bytes.size()) {
        const size_t offset = static_cast<size_t>(start - region.start);
        std::copy(region.bytes.begin() + offset,
                  region.bytes.begin() + offset + size, ptr);
        return;
      }
    }
    throw DataUnavailError("stringmanager fixture read outside a region");
  }

  std::string getArchType() const override { return "fixture:x86:LE:64"; }
  void adjustVma(long) override {}

  int4 attemptCount(uintb address) const {
    std::map<uintb, int4>::const_iterator iter = attempts.find(address);
    return iter == attempts.end() ? 0 : iter->second;
  }
};

class FixtureArchitecture final : public Architecture {
public:
  FixtureArchitecture() {
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);

    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("void", 1, TYPE_VOID, false);
    types->setCoreType("bool", 1, TYPE_BOOL, false);
    types->setCoreType("uint1", 1, TYPE_UINT, false);
    types->setCoreType("uint2", 2, TYPE_UINT, false);
    types->setCoreType("uint4", 4, TYPE_UINT, false);
    types->setCoreType("uint8", 8, TYPE_UINT, false);
    types->setCoreType("int1", 1, TYPE_INT, false);
    types->setCoreType("int2", 2, TYPE_INT, false);
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
    types->setCoreType("float4", 4, TYPE_FLOAT, false);
    types->setCoreType("float8", 8, TYPE_FLOAT, false);
    types->setCoreType("float10", 10, TYPE_FLOAT, false);
    types->setCoreType("float16", 16, TYPE_FLOAT, false);
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("code", 1, TYPE_CODE, false);
    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("wchar2", 2, TYPE_INT, true);
    types->setCoreType("wchar4", 4, TYPE_INT, true);
    types->cacheCoreTypes();

    loader = new FixtureLoadImage(getSpace(3));
  }

protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary() override {
    return (PcodeInjectLibrary *)0;
  }
  void buildTypegrp(DocumentStorage &) override {}
  void buildCoreTypes(DocumentStorage &) override {}
  void buildCommentDB(DocumentStorage &) override {}
  void buildStringManager(DocumentStorage &) override {}
  void buildConstantPool(DocumentStorage &) override {}
  void buildContext(DocumentStorage &) override {}
  void buildSymbols(DocumentStorage &) override {}
  void buildSpecFile(DocumentStorage &) override {}
  void modifySpaces(Translate *) override {}
  void resolveArchitecture() override {}

public:
  void printMessage(const std::string &) const override {}
  FixtureLoadImage *getFixtureLoader() const {
    return (FixtureLoadImage *)loader;
  }
};

/// A character type carrying the opaque_string flag (type.hh:176) so the
/// stringmanage.cc:441-442 opaque early-exit is driven with a real Datatype.
class FixtureOpaqueChar final : public TypeBase {
public:
  FixtureOpaqueChar() : TypeBase(1, TYPE_INT) {
    flags |= Datatype::opaque_string;
  }
};

/// Observation wrapper for the REAL native StringManagerUnicode
/// (stringmanage.cc:414-475): exposes the protected stringMap occupancy.
class NativeManager final : public StringManagerUnicode {
public:
  NativeManager(Architecture *g, int4 max) : StringManagerUnicode(g, max) {}

  bool hasEntry(const Address &addr) {
    return stringMap.find(addr) != stringMap.end();
  }
  int4 numEntries() const { return (int4)stringMap.size(); }
};

/// The DECLARED Java contract manager (production shape): string_ghidra.cc:42-56
/// control flow — cache hit, entry allocation before the read, opaque
/// early-exit, then detection. Detection performs the Java-side semantics
/// (charset validity + NUL termination, NO 2048 search bound) over the real
/// Ghidra primitives from stringmanage.cc:448-472 (incremental 32-byte
/// loadFill blocks, hasCharTerminator per block, checkCharacters over the
/// whole accumulated buffer, assignStringData for the return truncation at
/// maximumChars + isTruncated).
class JavaContractManager final : public StringManager {
  LoadImage *loader;

public:
  JavaContractManager(Architecture *g, int4 max)
      : StringManager(max), loader(g->loader) {}

  const vector<uint1> &getStringData(const Address &addr, Datatype *charType,
                                     bool &isTrunc) override {
    map<Address, StringData>::iterator iter;
    iter = stringMap.find(addr);
    if (iter != stringMap.end()) {
      isTrunc = (*iter).second.isTruncated;
      return (*iter).second.byteData;
    }

    StringData &stringData(stringMap[addr]); // Allocate before reading.
    stringData.isTruncated = false;
    isTrunc = false;

    if (charType->isOpaqueString()) // stringmanage.cc:441-442
      return stringData.byteData;

    const int4 charsize = charType->getSize();
    std::vector<uint1> buffer;
    bool foundTerminator = false;
    try {
      do {
        const int4 amount = 32; // Grab 32 bytes of image at a time.
        buffer.resize(buffer.size() + amount);
        loader->loadFill(buffer.data() + buffer.size() - amount, amount,
                         addr + buffer.size() - amount);
        foundTerminator = hasCharTerminator(buffer.data() + buffer.size() - amount,
                                            amount, charsize);
      } while (!foundTerminator);
    } catch (DataUnavailError &err) {
      return stringData.byteData; // Empty buffer stays cached.
    }

    const int4 size = (int4)buffer.size();
    const int4 numChars = checkCharacters(buffer.data(), size, charsize,
                                          addr.isBigEndian());
    if (numChars < 0)
      return stringData.byteData; // Invalid encoding stays cached empty.
    assignStringData(stringData, buffer.data(), size, charsize, numChars,
                     addr.isBigEndian());
    isTrunc = stringData.isTruncated;
    return stringData.byteData;
  }

  bool hasEntry(const Address &addr) {
    return stringMap.find(addr) != stringMap.end();
  }
  int4 numEntries() const { return (int4)stringMap.size(); }
};

std::string hexHead(const vector<uint1> &bytes, int4 count) {
  std::ostringstream out;
  for (int4 i = 0; i < count && i < (int4)bytes.size(); ++i)
    out << std::hex << std::setw(2) << std::setfill('0') << (int4)bytes[i];
  return out.str();
}

std::string hexTail(const vector<uint1> &bytes, int4 count) {
  std::ostringstream out;
  for (int4 i = (int4)bytes.size() - count; i >= 0 && i < (int4)bytes.size();
       ++i)
    out << std::hex << std::setw(2) << std::setfill('0') << (int4)bytes[i];
  return out.str();
}

/// Observe one getStringData query on `manager` and print the record line.
/// `label` identifies the case; the fixture loader reports attempts after.
template <class MANAGER>
void query(std::ostream &output, const std::string &label, MANAGER *manager,
           const Address &addr, Datatype *charType, FixtureLoadImage *loader,
           uintb attemptAddress) {
  bool isTrunc = true;
  const vector<uint1> &bytes = manager->getStringData(addr, charType, isTrunc);
  output << label << ".len=" << (int4)bytes.size() << ".trunc="
         << (isTrunc ? 1 : 0) << ".isstr="
         << (manager->isString(addr, charType) ? 1 : 0) << ".entry="
         << (manager->hasEntry(addr) ? 1 : 0) << ".head=" << hexHead(bytes, 6)
         << ".tail=" << hexTail(bytes, 4)
         << ".attempts=" << loader->attemptCount(attemptAddress) << '\n';
}

} // namespace

int main() {
  try {
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    FixtureLoadImage *loader = architecture.getFixtureLoader();
    Datatype *character = architecture.types->getTypeChar(1);
    FixtureOpaqueChar opaqueCharacter;

    NativeManager native(&architecture, 2048);
    JavaContractManager contract(&architecture, 2048);

    std::ostringstream output;

    // C1: pure ASCII positive cache ("alpha\0" in a zero-padded block);
    // byteData carries the whole first 32-byte block verbatim
    // (stringmanage.cc:69-72). Both managers agree here.
    query(output, "c1.ascii.native", &native, Address(ram, 0x2000), character,
          loader, 0x2000);
    query(output, "c1.ascii.contract", &contract, Address(ram, 0x2000),
          character, loader, 0x2000);

    // C2: repeat query on the positive cache: zero further reads.
    query(output, "c2.ascii_repeat.native", &native, Address(ram, 0x2000),
          character, loader, 0x2000);
    query(output, "c2.ascii_repeat.contract", &contract, Address(ram, 0x2000),
          character, loader, 0x2000);

    // C3: 0xAD illegal UTF-8 (stringmanage.cc:390-391 -> -1) — negative
    // cache: entry occupied, byteData empty, single read attempt.
    query(output, "c3.invalid_0xad.native", &native, Address(ram, 0x2100),
          character, loader, 0x2100);
    query(output, "c3.invalid_0xad.contract", &contract, Address(ram, 0x2100),
          character, loader, 0x2100);

    // C4: repeat query on the NEGATIVE cache: zero further reads — the
    // decisive stringmanage.cc:437 occupancy proof.
    query(output, "c4.invalid_repeat.native", &native, Address(ram, 0x2100),
          character, loader, 0x2100);
    query(output, "c4.invalid_repeat.contract", &contract, Address(ram, 0x2100),
          character, loader, 0x2100);

    // C5: >2048 long string (2050 'A' + NUL at offset 2050):
    //  - native: search clamped at 2048 bytes -> empty negative entry
    //    (stringmanage.cc:452-457);
    //  - contract: unbounded detection finds the terminator, 2050 chars >=
    //    2048 -> byteData = 2048 'A' + NUL, isTrunc=1 (return truncation).
    query(output, "c5.long.native", &native, Address(ram, 0x2400), character,
          loader, 0x2400);
    query(output, "c5.long.contract", &contract, Address(ram, 0x2400),
          character, loader, 0x2400);

    // C6: two consumers share one manager (rule-side isString at
    // ruleaction.cc:7375, then print-side getStringData at printc.cc:1537):
    // the print query is served from the rule query's cache entry; attempts
    // stay at 1. (Fresh contract manager so the count is isolated.)
    {
      JavaContractManager shared(&architecture, 2048);
      const bool ruleGuard = shared.isString(Address(ram, 0x2000), character);
      const int4 attemptsAfterRule = loader->attemptCount(0x2000);
      bool isTrunc = true;
      const vector<uint1> &bytes =
          shared.getStringData(Address(ram, 0x2000), character, isTrunc);
      output << "c6.shared.rule_guard=" << (ruleGuard ? 1 : 0)
             << ".attempts_after_rule=" << attemptsAfterRule
             << ".print_len=" << (int4)bytes.size() << ".print_trunc="
             << (isTrunc ? 1 : 0)
             << ".attempts_after_print=" << loader->attemptCount(0x2000)
             << '\n';
    }

    // C7: DataUnavailError (0x3000 outside every region) — the failed read
    // leaves the empty entry cached; the repeat performs no further attempt.
    query(output, "c7.data_unavail.contract", &contract, Address(ram, 0x3000),
          character, loader, 0x3000);
    query(output, "c7.data_unavail_repeat.contract", &contract,
          Address(ram, 0x3000), character, loader, 0x3000);

    // C8: no terminator before the image ends (64 'X' bytes, region ends at
    // 0x2E40): the unbounded contract search walks to the boundary and the
    // DataUnavailError leaves the empty entry cached.
    query(output, "c8.no_terminator.contract", &contract, Address(ram, 0x2E00),
          character, loader, 0x2E00);
    query(output, "c8.no_terminator_repeat.contract", &contract,
          Address(ram, 0x2E00), character, loader, 0x2E00);

    // C9: opaque string data-type (type.hh:176 flag) — the
    // stringmanage.cc:441-442 early-exit caches the empty entry with zero
    // image attempts. Address 0x2080 is inside the 0x2000 region padding but
    // has never been queried, so attempts=0 proves the read never happened.
    query(output, "c9.opaque.contract", &contract, Address(ram, 0x2080),
          &opaqueCharacter, loader, 0x2080);

    // C10: registerInternalStringData (stringmanage.cc:185-199): legal bytes
    // return the CRC32^offset<<32 hash and cache at the constant hash
    // address; illegal 0xAD bytes return 0.
    {
      const uint1 internal[] = {'i', 'n', 't', 'e', 'r', 'n', 'a', 'l', 0};
      const uint8 hash =
          contract.registerInternalStringData(Address(ram, 0x1000), internal,
                                              sizeof(internal), character);
      const uint1 bad[] = {'b', 0xad, 0};
      const uint8 badHash =
          contract.registerInternalStringData(Address(ram, 0x1000), bad,
                                              sizeof(bad), character);
      Address constAddr(architecture.translate->getConstantSpace(), hash);
      bool isTrunc = true;
      const vector<uint1> &bytes =
          contract.getStringData(constAddr, character, isTrunc);
      output << "c10.internal.hash_nonzero=" << (hash != 0 ? 1 : 0)
             << ".bad_hash_zero=" << (badHash == 0 ? 1 : 0) << ".entry="
             << (contract.hasEntry(constAddr) ? 1 : 0) << ".len="
             << (int4)bytes.size() << ".head=" << hexHead(bytes, 9) << '\n';
    }

    // C11: internal-string hash determinism vs the Rust side — the raw hash
    // value of a fixed (addr, bytes) pair (calcInternalHash,
    // stringmanage.cc:95-105).
    {
      const uint1 internal[] = {'i', 'n', 't', 'e', 'r', 'n', 'a', 'l', 0};
      // calcInternalHash is protected static; reproduce via the same formula
      // the Rust unit test locks against the real crc_update table.
      uint4 reg = 0x7b7c66a9;
      for (int4 i = 0; i < (int4)sizeof(internal); ++i)
        reg = crc_update(reg, internal[i]);
      const uint8 expected =
          (uint8)0x1000 ^ (((uint8)reg) << 32);
      output << "c11.internal_hash.value=" << std::hex << expected << std::dec
             << '\n';
    }

    output << "entries.native=" << native.numEntries()
           << ".contract=" << contract.numEntries() << '\n';
    std::cout << output.str();
  } catch (const LowlevelError &error) {
    std::cerr << "LowlevelError: " << error.explain << std::endl;
    return 2;
  } catch (const std::exception &error) {
    std::cerr << "exception: " << error.what() << std::endl;
    return 3;
  }
  return 0;
}
