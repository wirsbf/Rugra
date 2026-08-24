/*
 * MARSHAL-PACKED-JOIN-1204: locked Ghidra 12.0.4 oracle for
 * MARSHAL-XML-TEXT-0001 — the packed special-space codec and the JoinSpace
 * piece codec:
 *
 *   - PackedEncode::writeSpace (marshal.cc:1193-1218): the special-space
 *     type byte per space type (fspec 0x62, iop 0x63, join 0x61; formal
 *     stack 0x60 vs secondary spacebase 0x64) and the default
 *     ADDRESSSPACE-index arm;
 *   - PackedDecode::readSpace (marshal.cc:997-1031): the index resolution
 *     with the "Unknown address space index" rejection, the STACK/JOIN
 *     special codes, and the asymmetry that fspec/iop/spacebase special
 *     codes are WRITTEN by the encoder but REJECTED by the decoder with
 *     DecoderError("Cannot marshal special address space"); a non-space
 *     attribute rejects with "Expecting space attribute";
 *   - JoinSpace::encodeAttributes/decodeAttributes (space.cc:502-531/
 *     539-588) driven through BOTH encodings: writeSpace(join) + indexed
 *     ATTRIB_PIECE strings "{name}:0x{offset:x}:{size}" + ATTRIB_LOGICALSIZE
 *     for a single-piece (float extension) join; decode reinterprets
 *     "pieceN" names via XmlDecode::getIndexedAttributeId (marshal.cc:
 *     243-260) or takes the indexed ids directly in the packed form, then
 *     rebuilds through AddrSpaceManager::findAddJoin (translate.cc:671)
 *     whose dedup returns the original unified offset;
 *   - the edge rejections: unlinked offset ("Unlinked join address",
 *     translate.cc:761), single-colon piece ("join address piece attribute
 *     is malformed", space.cc:573), a piece position beyond MAX_PIECES
 *     skipped so findAddJoin sees no pieces ("Cannot create a join without
 *     pieces", translate.cc:676), and encoding a record with more than
 *     MAX_PIECES pieces ("Exceeded maximum pieces in one join address",
 *     space.cc:509).
 *
 * The register-name piece form (no ':', space.cc:566-569 via
 * getTrans()->getRegister) is deliberately NOT exercised: it needs the
 * Translate register table (SPACE-0001 residual). An unknown piece space
 * name is likewise not exercised: C++ stores a null space and only avoids
 * the null dereference because JoinRecord::operator< compares unified
 * sizes first (translate.cc:172-191) — UB-adjacent behavior Rust's
 * non-optional space handle rejects at the lookup point.
 */

#include <bits/stdc++.h>

// Test-only access for protected AddrSpaceManager::insertSpace, exactly
// like the fspec_space_identity_1204 fixture, confined to this translation
// unit.
#define class struct
#define private public
#include "address.hh"
#include "error.hh"
#include "libdecomp.hh"
#include "marshal.hh"
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
  // subclasses (fspec_space_identity_1204 fixture precedent).
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

static std::string hex_bytes(const std::string &raw) {
  std::ostringstream out;
  static const char *digits = "0123456789abcdef";
  for (unsigned char b : raw) {
    out << digits[b >> 4] << digits[b & 0xf];
  }
  return out.str();
}

// The PackedEncode byte image of <addr space="..."/> for one space.
static std::string packed_space_image(AddrSpace *spc) {
  std::ostringstream raw;
  PackedEncode enc(raw);
  enc.openElement(ELEM_ADDR);
  enc.writeSpace(ATTRIB_SPACE, spc);
  enc.closeElement(ELEM_ADDR);
  return raw.str();
}

// readSpace(ATTRIB_SPACE) over an already-encoded image: findMatching-
// Attribute + readSpace + the curPos=startPos reset (marshal.cc:1033-1040).
static std::string packed_read_space_probe(const std::string &image,
                                           AddrSpaceManager &mgr,
                                           std::string &space_name) {
  try {
    std::istringstream in(image);
    PackedDecode dec(&mgr);
    dec.ingestStream(in);
    uint4 elemId = dec.openElement();
    AddrSpace *spc = dec.readSpace(ATTRIB_SPACE);
    dec.closeElement(elemId);
    space_name = spc->getName();
    return "";
  } catch (DecoderError &e) {
    return e.explain;
  } catch (LowlevelError &e) {
    return e.explain;
  }
}

// The VarnodeData::decodeFromAttributes walk (pcoderaw.cc:33-56) over an
// open element: ATTRIB_SPACE -> readSpace -> rewind -> decodeAttributes.
static bool packed_decode_addr(const std::string &image,
                               AddrSpaceManager &mgr, uintb &off,
                               uint4 &size, std::string &err) {
  try {
    std::istringstream in(image);
    PackedDecode dec(&mgr);
    dec.ingestStream(in);
    uint4 elemId = dec.openElement();
    uint4 attribId = dec.getNextAttributeId();
    if (attribId != ATTRIB_SPACE.getId()) {
      err = "no space attribute";
      return false;
    }
    AddrSpace *spc = dec.readSpace();
    dec.rewindAttributes();
    off = spc->decodeAttributes(dec, size);
    dec.closeElement(elemId);
    return true;
  } catch (DecoderError &e) {
    err = e.explain;
    return false;
  } catch (LowlevelError &e) {
    err = e.explain;
    return false;
  }
}

static bool xml_decode_addr(const std::string &xml, AddrSpaceManager &mgr,
                            uintb &off, uint4 &size, std::string &err) {
  try {
    std::istringstream in(xml);
    XmlDecode dec(&mgr);
    dec.ingestStream(in);
    uint4 elemId = dec.openElement();
    uint4 attribId = dec.getNextAttributeId();
    if (attribId != ATTRIB_SPACE.getId()) {
      err = "no space attribute";
      return false;
    }
    AddrSpace *spc = dec.readSpace();
    dec.rewindAttributes();
    off = spc->decodeAttributes(dec, size);
    dec.closeElement(elemId);
    return true;
  } catch (DecoderError &e) {
    err = e.explain;
    return false;
  } catch (LowlevelError &e) {
    err = e.explain;
    return false;
  }
}

int main(void) {
  std::cout << "schema=1|fixture=MARSHAL-PACKED-JOIN-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;
  startDecompilerLibrary((const char *)0);
  FixtureTranslate mgr;

  // Registry identical to fspec_space_identity_1204 (const=0, unique=2,
  // ram=3, register=4, stack=5 formal spacebase, fspec=6, iop=7, join=8)
  // plus a SECONDARY (non-formal) spacebase regbase=9 for the
  // SPECIALSPACE_SPACEBASE byte. All heap-allocated because
  // ~AddrSpaceManager deletes every registered space.
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
  SpacebaseSpace *regbase =
      new SpacebaseSpace(&mgr, &mgr, "regbase", 9, 8, ram, 1, false);
  mgr.insert(regbase);

  // ---- case=packed_special_space_bytes ---------------------------------
  {
    std::ostringstream out;
    out << "case=packed_special_space_bytes"
        << "|const=" << hex_bytes(packed_space_image(constspc))
        << "|unique=" << hex_bytes(packed_space_image(uniqspc))
        << "|ram=" << hex_bytes(packed_space_image(ram))
        << "|register=" << hex_bytes(packed_space_image(reg))
        << "|stack=" << hex_bytes(packed_space_image(stack))
        << "|regbase=" << hex_bytes(packed_space_image(regbase))
        << "|fspec=" << hex_bytes(packed_space_image(fspec))
        << "|iop=" << hex_bytes(packed_space_image(iop))
        << "|join=" << hex_bytes(packed_space_image(join));
    std::cout << out.str() << std::endl;
  }

  // ---- case=packed_read_space -------------------------------------------
  {
    std::ostringstream out;
    out << "case=packed_read_space";
    std::string nm;
    std::string err;
    err = packed_read_space_probe(packed_space_image(ram), mgr, nm);
    out << "|ram_rt=" << (err.empty() && nm == "ram" ? 1 : 0)
        << "|ram_err=" << err;
    err = packed_read_space_probe(packed_space_image(join), mgr, nm);
    out << "|join_rt=" << (err.empty() && nm == "join" ? 1 : 0)
        << "|join_err=" << err;
    err = packed_read_space_probe(packed_space_image(stack), mgr, nm);
    out << "|stack_rt=" << (err.empty() && nm == "stack" ? 1 : 0)
        << "|stack_err=" << err;
    // Crafted rejections: the fspec/iop/spacebase special codes (encoder
    // writes them, decoder rejects), an out-of-range space index, and a
    // non-space attribute type.
    // <addr space=fspec-special>: 4b d4 62 8b
    err = packed_read_space_probe(std::string("\x4b\xd4\x62\x8b", 4), mgr, nm);
    out << "|fspec_rej=" << err;
    // <addr space=iop-special>: 4b d4 63 8b
    err = packed_read_space_probe(std::string("\x4b\xd4\x63\x8b", 4), mgr, nm);
    out << "|iop_rej=" << err;
    // <addr space=spacebase-special>: 4b d4 64 8b
    err = packed_read_space_probe(std::string("\x4b\xd4\x64\x8b", 4), mgr, nm);
    out << "|spacebase_rej=" << err;
    // <addr space=index 200>: d4 52 81 c8 (writeInteger ladder: lenCode 2)
    err = packed_read_space_probe(
        std::string("\x4b\xd4\x52\x81\xc8\x8b", 6), mgr, nm);
    out << "|bad_index_rej=" << err;
    // <addr space=unsigned-int-5>: d4 41 85 (not a space-typed attribute)
    err = packed_read_space_probe(
        std::string("\x4b\xd4\x41\x85\x8b", 5), mgr, nm);
    out << "|not_space_rej=" << err;
    std::cout << out.str() << std::endl;
  }

  // ---- case=packed_join_roundtrip ---------------------------------------
  {
    // Two-piece join: ram:0x1000:8 + register:0x8:8 (most significant
    // first); findAddJoin allocates 16-byte aligned unified offsets.
    std::vector<VarnodeData> pieces;
    VarnodeData p0;
    p0.space = ram;
    p0.offset = 0x1000;
    p0.size = 8;
    pieces.push_back(p0);
    VarnodeData p1;
    p1.space = reg;
    p1.offset = 0x8;
    p1.size = 8;
    pieces.push_back(p1);
    JoinRecord *rec2 = mgr.findAddJoin(pieces, 0);
    uintb off2 = rec2->getUnified().offset;

    std::ostringstream raw;
    PackedEncode enc(raw);
    enc.openElement(ELEM_ADDR);
    join->encodeAttributes(enc, off2);
    enc.closeElement(ELEM_ADDR);
    std::string image = raw.str();

    uintb dec_off = 0;
    uint4 dec_size = 0;
    std::string err;
    bool ok = packed_decode_addr(image, mgr, dec_off, dec_size, err);
    std::ostringstream out;
    out << "case=packed_join_roundtrip"
        << "|bytes=" << hex_bytes(image)
        << "|off=" << std::hex << off2
        << "|rt_ok=" << (ok ? 1 : 0)
        << "|rt_err=" << err
        << "|rt_off=" << std::hex << dec_off
        << "|rt_size=" << std::dec << dec_size;

    // Single-piece float extension: register:0x0:10 with logical size 16.
    std::vector<VarnodeData> fpiece;
    VarnodeData f0;
    f0.space = reg;
    f0.offset = 0;
    f0.size = 10;
    fpiece.push_back(f0);
    JoinRecord *recf = mgr.findAddJoin(fpiece, 16);
    uintb offf = recf->getUnified().offset;

    std::ostringstream fraw;
    PackedEncode fenc(fraw);
    fenc.openElement(ELEM_ADDR);
    join->encodeAttributes(fenc, offf);
    fenc.closeElement(ELEM_ADDR);
    std::string fimage = fraw.str();

    uintb fdec_off = 0;
    uint4 fdec_size = 0;
    bool fok = packed_decode_addr(fimage, mgr, fdec_off, fdec_size, err);
    out << "|float_bytes=" << hex_bytes(fimage)
        << "|float_off=" << std::hex << offf
        << "|float_rt_ok=" << (fok ? 1 : 0)
        << "|float_rt_err=" << err
        << "|float_rt_off=" << std::hex << fdec_off
        << "|float_rt_size=" << std::dec << fdec_size;
    std::cout << out.str() << std::endl;
  }

  // ---- case=xml_join_roundtrip ------------------------------------------
  {
    std::vector<VarnodeData> pieces;
    VarnodeData p0;
    p0.space = ram;
    p0.offset = 0x1000;
    p0.size = 8;
    pieces.push_back(p0);
    VarnodeData p1;
    p1.space = reg;
    p1.offset = 0x8;
    p1.size = 8;
    pieces.push_back(p1);
    JoinRecord *rec2 = mgr.findAddJoin(pieces, 0); // dedup hit
    uintb off2 = rec2->getUnified().offset;

    std::ostringstream enc;
    XmlEncode xenc(enc, false);
    xenc.openElement(ELEM_ADDR);
    join->encodeAttributes(xenc, off2);
    xenc.closeElement(ELEM_ADDR);
    std::string xml = enc.str();

    // Attribute-pair walk of the parsed document (name=value, source
    // order).
    std::istringstream in(xml);
    DocumentStorage store;
    Document *doc = store.parseDocument(in);
    const Element *root = doc->getRoot();
    std::string attrs;
    for (int4 k = 0; k < root->getNumAttributes(); ++k) {
      if (k != 0) attrs += ',';
      attrs += root->getAttributeName(k);
      attrs += '=';
      attrs += root->getAttributeValue(k);
    }

    uintb dec_off1 = 0, dec_off2 = 0;
    uint4 dec_size1 = 0, dec_size2 = 0;
    std::string err;
    bool ok1 = xml_decode_addr(xml, mgr, dec_off1, dec_size1, err);
    bool ok2 = xml_decode_addr(xml, mgr, dec_off2, dec_size2, err);
    std::ostringstream out;
    out << "case=xml_join_roundtrip"
        << "|attrs=" << attrs
        << "|off=" << std::hex << off2
        << "|rt1_ok=" << (ok1 ? 1 : 0)
        << "|rt1_err=" << err
        << "|rt1_off=" << std::hex << dec_off1
        << "|rt1_size=" << std::dec << dec_size1
        << "|dedup_eq=" << ((ok2 && dec_off2 == dec_off1) ? 1 : 0);
    std::cout << out.str() << std::endl;
  }

  // ---- case=join_codec_edges --------------------------------------------
  {
    std::ostringstream out;
    out << "case=join_codec_edges";
    // (a) Encoding an offset with no JoinRecord: findJoin throws.
    {
      std::ostringstream raw;
      PackedEncode enc(raw);
      enc.openElement(ELEM_ADDR);
      std::string err;
      try {
        join->encodeAttributes(enc, 0xdead);
      } catch (LowlevelError &e) {
        err = e.explain;
      }
      out << "|unlinked_err=" << err;
    }
    // (b) Single-colon piece string: malformed.
    {
      uintb off;
      uint4 sz;
      std::string err;
      xml_decode_addr(
          "<addr space=\"join\" piece1=\"ram:0x1000\"/>", mgr, off, sz, err);
      out << "|malformed_err=" << err;
    }
    // (c) piece66: pos 65 > MAX_PIECES, skipped -> no pieces ->
    // findAddJoin rejection.
    {
      uintb off;
      uint4 sz;
      std::string err;
      xml_decode_addr(
          "<addr space=\"join\" piece66=\"ram:0x0:4\"/>", mgr, off, sz, err);
      out << "|overflow_piece_err=" << err;
    }
    // (d) Encoding a record holding more than MAX_PIECES pieces.
    {
      std::vector<VarnodeData> many;
      for (int4 i = 0; i < 65; ++i) {
        VarnodeData vd;
        vd.space = ram;
        vd.offset = (uintb)i * 0x10;
        vd.size = 1;
        many.push_back(vd);
      }
      JoinRecord *rec65 = mgr.findAddJoin(many, 0);
      std::ostringstream raw;
      PackedEncode enc(raw);
      enc.openElement(ELEM_ADDR);
      std::string err;
      try {
        join->encodeAttributes(enc, rec65->getUnified().offset);
      } catch (LowlevelError &e) {
        err = e.explain;
      }
      out << "|encode_overflow_err=" << err;
    }
    std::cout << out.str() << std::endl;
  }

  return 0;
}
