/*
 * FSPEC-SPACE-IDENTITY-1204: locked Ghidra 12.0.4 oracle for
 * TYPEOP-FSPEC-SPACE-0001 slice 1 — the fspec space's identity foundation:
 *
 *   - FspecSpace construction/registration (fspec.cc:2107-2122) and the
 *     IPTR_FSPEC arm of AddrSpaceManager::insertSpace (translate.cc:373-379),
 *     including the duplicate/type-name rejection messages and the 'f'
 *     shortcut from assignShortcut (translate.cc:541-542), with the
 *     production insertion order of Architecture::restoreFromSpec
 *     (architecture.cc:631-634: fspec at numSpaces(), then iop, then join);
 *   - same-offset space discrimination across CONST/FSPEC/IOP (+stack/join)
 *     through Address operator==/operator< (address.hh:356-393), the
 *     std::map<Address,...> iteration order, Address::overlap
 *     (address.cc:153-165), containedBy/justifiedContain cross-space
 *     rejections (address.cc:110-142) and operator+ wraparound
 *     (address.hh:423-425);
 *   - the FspecSpace printRaw forms (fspec.cc:2153-2164) driven by the
 *     call-spec name/entry-address members (fspec.hh:1647-1648);
 *   - the FspecSpace encodeAttributes projection (fspec.cc:2124-2151):
 *     an invalid entry encodes as the literal space "fspec" with NO offset
 *     (so decoding it throws LowlevelError("Address is missing offset"),
 *     space.cc:186), a valid entry encodes the ENTRY space+offset through
 *     Address::encode (address.hh:469-474) and XmlEncode::writeSpace
 *     (marshal.cc), and the decode side resolves space names through
 *     XmlDecode::readSpace/getSpaceByName (marshal.cc:400-409) with the
 *     "Unknown address space name" rejection;
 *   - the never-decoded guards: FspecSpace::decode (fspec.cc:2166-2170)
 *     and IopSpace::decode (op.cc:61-65).
 *
 * The fspec offsets are real FuncCallSpecs-shaped storage views whose
 * `name`/`entryaddress` members are placement-constructed in static
 * buffers (the two fields printRaw/encodeAttributes read); no raw offset
 * value is ever printed, so the projection is byte-stable across runs.
 *
 * IopSpace::printRaw (op.cc:41-59) is deliberately NOT exercised: it
 * dereferences the offset as a PcodeOp* (SPACE-IOP-PRINTRAW-0001 residual,
 * blocked by ADDRESS-0001); no byte-exact Rust comparand exists yet. The
 * PackedEncode::writeSpace special-space byte (marshal.cc:1198-1203) and
 * PackedDecode::readSpace's "Cannot marshal special address space"
 * rejection (marshal.cc:1013-1028) are marshal-layer and stay with
 * MARSHAL-XML-TEXT-0001.
 */

#include <bits/stdc++.h>

// Test-only access for protected AddrSpaceManager::insertSpace and the
// FuncCallSpecs name/entryaddress members via the `class -> struct`
// precedent of the space_registry_1204 fixture, confined to this
// translation unit.
#define class struct
#define private public
#include "address.hh"
#include "error.hh"
#include "fspec.hh"
#include "libdecomp.hh"
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
  // AddrSpaceManager protected bridge, exactly like production Translate
  // subclasses (space_registry_1204 fixture precedent).
  void insert(AddrSpace *spc) { insertSpace(spc); }
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

// Static storage views shaped like FuncCallSpecs. Only the two members the
// FspecSpace methods read (fspec.hh:1647-1648) are placement-constructed;
// nothing destructs them (fixture process storage).
alignas(FuncCallSpecs) static unsigned char
    fc_storage[4][sizeof(FuncCallSpecs)];

static void print_addr_raw(const AddrSpace *spc, uintb off,
                           std::ostringstream &out, const std::string &tag) {
  std::ostringstream hold;
  spc->printRaw(hold, off);
  out << "|" << tag << "=" << hold.str();
}

int main(void) {
  std::cout << "schema=1|fixture=FSPEC-SPACE-IDENTITY-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;
  startDecompilerLibrary((const char *)0);
  FixtureTranslate mgr;

  // Fixture registry mirroring the production architecture order: spec
  // spaces first (const=0, unique=2, ram=3, register=4, stack=5; index 1 is
  // a dead hole), then Architecture::restoreFromSpec's internal spaces at
  // numSpaces() (architecture.cc:631-634): fspec=6, iop=7, join=8. All
  // spaces are heap-allocated because ~AddrSpaceManager deletes every
  // registered space (space_registry_1204 precedent).
  ConstantSpace *constspc = new ConstantSpace(&mgr, &mgr);
  mgr.insert(constspc);
  UniqueSpace *uniqspc = new UniqueSpace(&mgr, &mgr, 2, 0);
  mgr.insert(uniqspc);
  AddrSpace *ram = new AddrSpace(&mgr, &mgr, IPTR_PROCESSOR, "ram", false, 8,
                                 1, 3, AddrSpace::hasphysical, 0, 0);
  mgr.insert(ram);
  AddrSpace *reg = new AddrSpace(&mgr, &mgr, IPTR_PROCESSOR, "register",
                                 false, 8, 1, 4, AddrSpace::hasphysical, 0, 0);
  mgr.insert(reg);
  SpacebaseSpace *stack =
      new SpacebaseSpace(&mgr, &mgr, "stack", 5, 8, ram, 1, true);
  mgr.insert(stack);
  FspecSpace *fspec = new FspecSpace(&mgr, &mgr, mgr.numSpaces());
  mgr.insert(fspec);
  IopSpace *iop = new IopSpace(&mgr, &mgr, mgr.numSpaces());
  mgr.insert(iop);
  JoinSpace *join = new JoinSpace(&mgr, &mgr, mgr.numSpaces());
  mgr.insert(join);


  // ---- case=registration_lookup --------------------------------------
  {
    std::ostringstream out;
    out << std::hex;
    out << "case=registration_lookup"
        << "|byname_eq_cached="
        << (mgr.getSpaceByName("fspec") == mgr.getFspecSpace())
        << "|byname_miss=" << (mgr.getSpaceByName("fspec2") == (AddrSpace *)0)
        << "|shortcut=" << fspec->getShortcut()
        << "|shortcut_lookup_eq="
        << (mgr.getSpaceByShortcut('f') == fspec)
        << "|type=" << (int4)fspec->getType()
        << "|name=" << fspec->getName()
        << "|addrsize=" << fspec->getAddrSize()
        << "|wordsize=" << fspec->getWordSize()
        << "|delay=" << fspec->getDelay()
        << "|deadcodedelay=" << fspec->getDeadcodeDelay()
        << "|heritaged=" << (fspec->isHeritaged() ? 1 : 0)
        << "|does_deadcode=" << (fspec->doesDeadcode() ? 1 : 0)
        << "|bigendian=" << (fspec->isBigEndian() ? 1 : 0)
        << "|highest=0x" << fspec->getHighest()
        << "|plb=0x" << fspec->getPointerLowerBound()
        << "|pub=0x" << fspec->getPointerUpperBound()
        << "|index=" << fspec->getIndex();
    std::string dup_msg;
    try {
      mgr.insert(new FspecSpace(&mgr, &mgr, 20));
    } catch (LowlevelError &err) {
      dup_msg = err.explain;
    }
    // Fresh manager so only the type-name mismatch fires (on the main
    // manager the cached fspec slot would also append the duplicate-name
    // message, translate.cc:410-419).
    std::string wrongtype_msg;
    {
      FixtureTranslate mgr2;
      mgr2.insert(new ConstantSpace(&mgr2, &mgr2));
      mgr2.insert(new AddrSpace(&mgr2, &mgr2, IPTR_PROCESSOR, "ram", false, 8,
                                1, 3, AddrSpace::hasphysical, 0, 0));
      try {
        mgr2.insert(new AddrSpace(&mgr2, &mgr2, IPTR_FSPEC, "wrongfs", false,
                                  8, 1, 9, 0, 1, 1));
      } catch (LowlevelError &err) {
        wrongtype_msg = err.explain;
      }
    }
    out << "|dup_msg=" << dup_msg
        << "|wrongtype_msg=" << wrongtype_msg
        << "|iop_shortcut=" << iop->getShortcut()
        << "|iop_index=" << iop->getIndex()
        << "|walk=";
    bool first = true;
    for (AddrSpace *spc = mgr.getNextSpaceInOrder((AddrSpace *)0);
         spc != (AddrSpace *)0 && spc != (AddrSpace *)~((uintp)0);
         spc = mgr.getNextSpaceInOrder(spc)) {
      if (!first) out << ',';
      out << spc->getName();
      first = false;
    }
    std::cout << out.str() << std::endl;
  }

  // ---- fspec storage views -------------------------------------------
  // Invalid entries use the m_minimal constructor (address.cc:94-97) so the
  // offset member is deterministically 0, unlike the default constructor
  // which leaves it uninitialized.
  FuncCallSpecs *fc_invalid = reinterpret_cast<FuncCallSpecs *>(&fc_storage[0][0]);
  new (&fc_invalid->name) std::string();
  new (&fc_invalid->entryaddress) Address(Address::m_minimal);
  FuncCallSpecs *fc_valid = reinterpret_cast<FuncCallSpecs *>(&fc_storage[1][0]);
  new (&fc_valid->name) std::string();
  new (&fc_valid->entryaddress) Address(ram, 0x1234);
  FuncCallSpecs *fc_named = reinterpret_cast<FuncCallSpecs *>(&fc_storage[2][0]);
  new (&fc_named->name) std::string("target_func");
  new (&fc_named->entryaddress) Address(ram, 0x1234);
  FuncCallSpecs *fc_named2 = reinterpret_cast<FuncCallSpecs *>(&fc_storage[3][0]);
  new (&fc_named2->name) std::string("named_indirect");
  new (&fc_named2->entryaddress) Address(Address::m_minimal);

  const uintb off_invalid = (uintb)(uintp)fc_invalid;
  const uintb off_valid = (uintb)(uintp)fc_valid;
  const uintb off_named = (uintb)(uintp)fc_named;
  const uintb off_named2 = (uintb)(uintp)fc_named2;

  // ---- case=same_offset_discrimination --------------------------------
  {
    const uintb X = 0x5555aaaa;
    Address c(constspc, X), s(stack, X), f(fspec, X), i(iop, X), j(join, X);
    Address f2(fspec, X);
    std::vector<Address> vec;
    vec.push_back(i);
    vec.push_back(f);
    vec.push_back(j);
    vec.push_back(c);
    vec.push_back(s);
    std::stable_sort(vec.begin(), vec.end());
    std::map<Address, int> ordered;
    ordered[i] = 4;
    ordered[f] = 3;
    ordered[j] = 5;
    ordered[c] = 1;
    ordered[s] = 2;
    std::ostringstream out;
    out << "case=same_offset_discrimination"
        << "|eq_cross=" << ((c == f) ? 1 : 0)
        << "|eq_self=" << ((f == f2) ? 1 : 0)
        << "|lt_const_fspec=" << ((c < f) ? 1 : 0)
        << "|lt_fspec_iop=" << ((f < i) ? 1 : 0)
        << "|lt_const_iop=" << ((c < i) ? 1 : 0)
        << "|lt_fspec_join=" << ((f < j) ? 1 : 0)
        << "|lt_stack_fspec=" << ((s < f) ? 1 : 0)
        << "|order=";
    bool first = true;
    for (const Address &addr : vec) {
      if (!first) out << ',';
      out << addr.getSpace()->getName();
      first = false;
    }
    out << "|map_order=";
    first = true;
    for (const auto &kv : ordered) {
      if (!first) out << ',';
      out << kv.first.getSpace()->getName();
      first = false;
    }
    out << "|ovl_fspec_iop=" << f.overlap(0, i, 8)
        << "|ovl_self=" << f.overlap(0, f2, 8)
        << "|ovl_shift=" << Address(fspec, X + 4).overlap(0, f, 8)
        << "|ovl_const=" << c.overlap(0, c, 8)
        << "|ovl_iop_shift=" << Address(iop, X + 3).overlap(0, i, 5)
        << "|contained_cross=" << (f.containedBy(4, i, 8) ? 1 : 0)
        << "|justified_cross=" << f.justifiedContain(8, i, 4, false)
        << "|wrap_max_eq0="
        << (((Address(fspec, ~((uintb)0)) + 1).getOffset() == 0) ? 1 : 0);
    std::cout << out.str() << std::endl;
  }

  // ---- case=print_raw_forms -------------------------------------------
  {
    std::ostringstream out;
    out << "case=print_raw_forms";
    print_addr_raw(fspec, off_invalid, out, "invalid_entry");
    print_addr_raw(fspec, off_valid, out, "valid_entry");
    print_addr_raw(fspec, off_named, out, "named");
    print_addr_raw(fspec, off_named2, out, "named_indirect");
    print_addr_raw(constspc, 0x1234, out, "const_form");
    std::cout << out.str() << std::endl;
  }

  // ---- case=encode_decode_roundtrip -----------------------------------
  {
    std::ostringstream out;
    out << "case=encode_decode_roundtrip";
    // (a) invalid entry: <addr space="fspec"/> — decode throws.
    {
      std::ostringstream enc;
      XmlEncode xenc(enc, false);
      Address(fspec, off_invalid).encode(xenc);
      std::string xml = enc.str();
      std::istringstream in(xml);
      DocumentStorage store;
      Document *doc = store.parseDocument(in);
      const Element *root = doc->getRoot();
      std::string names;
      for (int4 k = 0; k < root->getNumAttributes(); ++k) {
        if (k != 0) names += ',';
        names += root->getAttributeName(k);
      }
      std::string err;
      try {
        std::istringstream in2(xml);
        XmlDecode dec(&mgr);
        dec.ingestStream(in2);
        Address::decode(dec);
      } catch (LowlevelError &e) {
        err = e.explain;
      } catch (DecoderError &e) {
        err = e.explain;
      }
      out << "|invalid_entry_attrs=" << names
          << "|invalid_entry_decode_err=" << err;
    }
    // (b) valid entry: encodes the ENTRY space+offset; decoding yields the
    // entry address, NOT the original fspec address.
    {
      std::ostringstream enc;
      XmlEncode xenc(enc, false);
      Address orig(fspec, off_valid);
      orig.encode(xenc);
      std::string xml = enc.str();
      std::istringstream in(xml);
      DocumentStorage store;
      Document *doc = store.parseDocument(in);
      const Element *root = doc->getRoot();
      std::string names;
      for (int4 k = 0; k < root->getNumAttributes(); ++k) {
        if (k != 0) names += ',';
        names += root->getAttributeName(k);
      }
      std::string err;
      std::string dec_space;
      uintb dec_off = 0;
      bool dec_ok = false;
      try {
        std::istringstream in2(xml);
        XmlDecode dec(&mgr);
        dec.ingestStream(in2);
        Address res = Address::decode(dec);
        dec_ok = true;
        dec_space = res.getSpace()->getName();
        dec_off = res.getOffset();
      } catch (LowlevelError &e) {
        err = e.explain;
      } catch (DecoderError &e) {
        err = e.explain;
      }
      (void)dec_ok;
      out << "|valid_entry_attrs=" << names
          << "|valid_entry_dec_space=" << dec_space
          << "|valid_entry_dec_off=" << std::dec << dec_off
          << "|valid_entry_dec_is_fspec="
          << (dec_space == fspec->getName() ? 1 : 0)
          << "|valid_entry_same_as_orig=0";
    }
    // (c) plain ram address round-trips through itself.
    {
      std::ostringstream enc;
      XmlEncode xenc(enc, false);
      Address orig(ram, 0x1234);
      orig.encode(xenc);
      std::string xml = enc.str();
      std::istringstream in2(xml);
      XmlDecode dec(&mgr);
      dec.ingestStream(in2);
      Address res = Address::decode(dec);
      out << "|ram_rt_eq=" << ((res == orig) ? 1 : 0);
    }
    // (d) crafted <addr space="fspec" offset="0x77"/> resolves by name.
    {
      std::istringstream in2("<addr space=\"fspec\" offset=\"0x77\"/>");
      XmlDecode dec(&mgr);
      dec.ingestStream(in2);
      Address res = Address::decode(dec);
      // Compare against the original fspec handle: the duplicate-insert
      // test above already poisoned the cached slot (insertSpace replaces
      // fspecspace before throwing and deletes the rejected space,
      // translate.cc:373-379/426-431), while name2Space still resolves the
      // original space.
      out << "|crafted_fspec_space="
          << (res.getSpace() == fspec ? 1 : 0)
          << "|crafted_off_eq=" << ((res.getOffset() == 0x77) ? 1 : 0)
          << "|crafted_wrap=" << (res + 1).getOffset();
    }
    // (e) unknown space name rejection.
    {
      std::string err;
      try {
        std::istringstream in2("<addr space=\"nosuch\" offset=\"0x1\"/>");
        XmlDecode dec(&mgr);
        dec.ingestStream(in2);
        Address::decode(dec);
      } catch (LowlevelError &e) {
        err = e.explain;
      } catch (DecoderError &e) {
        err = e.explain;
      }
      out << "|unknown_space_err=" << err;
    }
    // (f) attribute-less <addr/> decodes invalid.
    {
      std::istringstream in2("<addr/>");
      XmlDecode dec(&mgr);
      dec.ingestStream(in2);
      Address res = Address::decode(dec);
      out << "|empty_addr_invalid=" << (res.isInvalid() ? 1 : 0);
    }
    // (g) the never-decoded guards.
    {
      XmlDecode dec(&mgr);
      std::string err;
      try {
        fspec->decode(dec);
      } catch (LowlevelError &e) {
        err = e.explain;
      }
      out << "|fspec_decode_err=" << err;
    }
    std::cout << out.str() << std::endl;
  }

  // ---- case=cross_space_exceptions -------------------------------------
  {
    Range ram_range(ram, 0x1000, 0x2000);
    Address f(fspec, 0x1000);
    Address ram_point(ram, 0x1000);
    std::ostringstream out;
    out << "case=cross_space_exceptions"
        << "|range_contains_fspec="
        << (ram_range.contains(f) ? 1 : 0)
        << "|overlap_join_cross="
        << f.overlapJoin(0, ram_point, 8);
    XmlDecode dec(&mgr);
    std::string err;
    try {
      iop->decode(dec);
    } catch (LowlevelError &e) {
      err = e.explain;
    }
    out << "|iop_decode_err=" << err;
    std::cout << out.str() << std::endl;
  }

  return 0;
}
