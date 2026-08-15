/*
 * EXTERNAL-STUB-1204: locked Ghidra 12.0.4 construction-period space
 * registration oracle (EXTERNAL-stub support wave).
 *
 * The fixture drives the real AddrSpaceManager decode path that production
 * architectures use to register spaces from a spec —
 * AddrSpaceManager::decodeSpaces (translate.cc:281-303, including the
 * DEFAULT-space registration via the `defaultspace` attribute) and
 * AddrSpaceManager::decodeSpace (translate.cc:254-275, the element-id
 * dispatch to the partial SpacebaseSpace/UniqueSpace/OtherSpace/
 * OverlaySpace/AddrSpace constructors) — over a hand-built Element tree,
 * plus the readSpace resolution errors (marshal.cc:400-409) and the
 * EXTERNAL-named processor-space registration the Ghidra platform side
 * defines for import stubs (Java AddressSpace.java:80; the 12.0.4
 * decompiler oracle has no ExternalSpace — see the fixture's Rust twin).
 * Every observation is printed in the shared line format so the Rust
 * comparand must match byte for byte.
 */

#include <bits/stdc++.h>

// Test-only access is required to reach the protected decode entry points
// (production reaches them from Translate subclasses during initialization)
// and to read AddrSpace::refcount. This matches the access-hack precedent
// of the space_registry fixture and is confined to this translation unit.
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

  // AddrSpaceManager protected bridge, exactly like production Translate
  // subclasses call these during initialization.
  std::string tryDecodeSpaces(XmlDecode &decoder) {
    try {
      decodeSpaces(decoder, this);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
    catch (DecoderError &err) {
      return std::string("err ") + err.explain;
    }
  }

  std::string tryDecodeSpace(AddrSpace *&out, XmlDecode &decoder) {
    try {
      out = decodeSpace(decoder, this);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
    catch (DecoderError &err) {
      return std::string("err ") + err.explain;
    }
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

// Helpers building the hand-parsed Element tree: a <spaces> document with
// <space>/<space_unique>/<space_base>/<space_overlay> children, exactly the
// shapes SleighArchitecture feeds decodeSpaces in production.
static Element *makeSpaceElement(Element *parent, const std::string &tag,
                                 const std::vector<std::pair<std::string,
                                 std::string>> &attributes) {
  Element *el = new Element(parent);
  el->setName(tag);
  for (size_t i = 0; i < attributes.size(); ++i)
    el->addAttribute(attributes[i].first, attributes[i].second);
  parent->addChild(el);
  return el;
}

static Element *makeSpacesDocument(const std::string &defaultspace) {
  Element *spaces = new Element((Element *)0);
  spaces->setName("spaces");
  spaces->addAttribute("defaultspace", defaultspace);
  return spaces;
}

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
            << " ref=" << spc->refcount
            << " h=" << (spc->isHeritaged() ? 1 : 0)
            << " dc=" << (spc->doesDeadcode() ? 1 : 0)
            << " fs=" << (spc->isFormalStackSpace() ? 1 : 0)
            << " ov=" << (spc->isOverlay() ? 1 : 0)
            << " ob=" << (spc->isOverlayBase() ? 1 : 0)
            << " hp=" << (spc->hasPhysical() ? 1 : 0)
            << " oo=" << (spc->isOtherSpace() ? 1 : 0)
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

// Canonical decodeSpaces input: const is implicit (decodeSpaces inserts it
// itself), unique=2, ram=3, register=4, default=ram.
static Element *canonicalSpaces(void) {
  Element *spaces = makeSpacesDocument("ram");
  makeSpaceElement(spaces, "space_unique",
                   {{"name", "unique"}, {"index", "2"}, {"size", "4"},
                    {"delay", "0"}});
  makeSpaceElement(spaces, "space",
                   {{"name", "ram"}, {"index", "3"}, {"size", "8"},
                    {"delay", "0"}, {"physical", "true"}});
  makeSpaceElement(spaces, "space",
                   {{"name", "register"}, {"index", "4"}, {"size", "8"},
                    {"delay", "0"}, {"physical", "true"}});
  return spaces;
}

int main(void) {
  // The id lookups (AttributeId::find/ElementId::find) are filled by the
  // explicit initialize calls that every production entry point makes
  // (libdecomp.cc:23-24); the fixture must do the same before decoding.
  AttributeId::initialize();
  ElementId::initialize();
  std::cout << "schema=1|fixture=EXTERNAL-STUB-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // ---- case 1: decodeSpaces canonical registration + DEFAULT ----------
  std::cout << "case=decode_spaces_default_registration" << std::endl;
  {
    FixtureTranslate tr;
    Element *doc = canonicalSpaces();
    XmlDecode decoder(&tr, doc);
    std::cout << "  " << tr.tryDecodeSpaces(decoder) << std::endl;
    std::cout << "  numSpaces=" << tr.numSpaces() << std::endl;
    for (int4 i = 0; i < tr.numSpaces(); ++i)
      if (tr.getSpace(i) != (AddrSpace *)0)
        printSpaceLine(tr.getSpace(i));
    std::cout << "  defaultSize=" << tr.getDefaultSize()
              << " code=" << tr.getDefaultCodeSpace()->getName()
              << " data=" << tr.getDefaultDataSpace()->getName() << std::endl;
    printWalk(&tr);
    delete doc;
  }

  // ---- case 2: <space_overlay> decode marks the base -------------------
  std::cout << "case=decode_space_overlay_marks_base" << std::endl;
  {
    FixtureTranslate tr;
    Element *doc = canonicalSpaces();
    makeSpaceElement(doc, "space_overlay",
                     {{"name", "ov"}, {"index", "5"}, {"base", "ram"}});
    XmlDecode decoder(&tr, doc);
    std::cout << "  " << tr.tryDecodeSpaces(decoder) << std::endl;
    AddrSpace *ov = tr.getSpaceByName("ov");
    AddrSpace *ram = tr.getSpaceByName("ram");
    std::cout << "  ram_ob=" << (ram->isOverlayBase() ? 1 : 0)
              << " ov_ov=" << (ov->isOverlay() ? 1 : 0)
              << " contain=" << ov->getContain()->getName() << std::endl;
    printSpaceLine(ov);
    delete doc;
  }

  // ---- case 3: <space_base> decode resolves contain --------------------
  std::cout << "case=decode_space_base_stack_contain" << std::endl;
  {
    FixtureTranslate tr;
    Element *doc = canonicalSpaces();
    makeSpaceElement(doc, "space_base",
                     {{"name", "stack"}, {"index", "5"}, {"size", "8"},
                      {"delay", "1"}, {"contain", "ram"}});
    XmlDecode decoder(&tr, doc);
    std::cout << "  " << tr.tryDecodeSpaces(decoder) << std::endl;
    AddrSpace *stack = tr.getSpaceByName("stack");
    std::cout << "  stackSlot=" << tr.getStackSpace()->getName()
              << " type=" << (int4)stack->getType()
              << " contain=" << stack->getContain()->getName()
              << " numBase=" << stack->numSpacebase()
              << " growsNeg=" << (stack->stackGrowsNegative() ? 1 : 0)
              << " formal=" << (stack->isFormalStackSpace() ? 1 : 0)
              << std::endl;
    printSpaceLine(stack);
    delete doc;
  }

  // ---- case 4: readSpace resolution failure ----------------------------
  std::cout << "case=decode_space_unknown_base" << std::endl;
  {
    FixtureTranslate tr;
    Element *doc = canonicalSpaces();
    makeSpaceElement(doc, "space_overlay",
                     {{"name", "bad"}, {"index", "6"}, {"base", "nope"}});
    XmlDecode decoder(&tr, doc);
    std::cout << "  " << tr.tryDecodeSpaces(decoder) << std::endl;
    std::cout << "  ovLookup="
              << (tr.getSpaceByName("bad") == (AddrSpace *)0
                      ? std::string("null")
                      : tr.getSpaceByName("bad")->getName())
              << std::endl;
    delete doc;
  }

  // ---- case 5: bad defaultspace attribute ------------------------------
  std::cout << "case=decode_spaces_bad_default" << std::endl;
  {
    FixtureTranslate tr;
    Element *doc = makeSpacesDocument("missing");
    makeSpaceElement(doc, "space",
                     {{"name", "ram"}, {"index", "3"}, {"size", "8"},
                      {"delay", "0"}});
    XmlDecode decoder(&tr, doc);
    std::cout << "  " << tr.tryDecodeSpaces(decoder) << std::endl;
    std::cout << "  default="
              << (tr.getDefaultCodeSpace() == (AddrSpace *)0
                      ? std::string("null")
                      : tr.getDefaultCodeSpace()->getName())
              << std::endl;
    delete doc;
  }

  // ---- case 6: EXTERNAL-named processor space registration -------------
  // The Ghidra platform side defines the external space as a flat 32-bit
  // space named "EXTERNAL" (AddressSpace.java:80) and the ELF importer
  // materializes import stubs in a default-space EXTERNAL memory block.
  // The 12.0.4 decompiler registers it like any other processor space:
  // no overlay flags, no special type handling.
  std::cout << "case=external_named_space_registration" << std::endl;
  {
    FixtureTranslate tr;
    Element *doc = canonicalSpaces();
    XmlDecode setup(&tr, doc);
    std::cout << "  " << tr.tryDecodeSpaces(setup) << std::endl;
    AddrSpace *external = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "EXTERNAL",
                                        false, 4, 1, 9, 0, 0, 0);
    std::cout << "  " << tr.tryInsertSpace(external) << std::endl;
    AddrSpace *ram = tr.getSpaceByName("ram");
    std::cout << "  lookup="
              << (tr.getSpaceByName("EXTERNAL") == (AddrSpace *)0
                      ? std::string("null")
                      : tr.getSpaceByName("EXTERNAL")->getName())
              << " shortcut=" << external->getShortcut()
              << " ram_ob=" << (ram->isOverlayBase() ? 1 : 0) << std::endl;
    printSpaceLine(external);
    AddrSpace *duplicate = new AddrSpace(&tr, &tr, IPTR_PROCESSOR, "EXTERNAL",
                                         false, 4, 1, 10, 0, 0, 0);
    std::cout << "  " << tr.tryInsertSpace(duplicate) << std::endl;
    printWalk(&tr);
    delete doc;
  }

  // ---- case 7: deadcodedelay default from delay ------------------------
  std::cout << "case=deadcodedelay_default_from_delay" << std::endl;
  {
    FixtureTranslate tr;
    Element *doc = makeSpacesDocument("ws");
    makeSpaceElement(doc, "space",
                     {{"name", "ws"}, {"index", "3"}, {"size", "4"},
                      {"wordsize", "2"}, {"delay", "3"}});
    XmlDecode decoder(&tr, doc);
    std::cout << "  " << tr.tryDecodeSpaces(decoder) << std::endl;
    AddrSpace *ws = tr.getSpaceByName("ws");
    printSpaceLine(ws);
    FixtureTranslate tr2;
    Element *doc2 = makeSpacesDocument("ws2");
    makeSpaceElement(doc2, "space",
                     {{"name", "ws2"}, {"index", "3"}, {"size", "4"},
                      {"delay", "2"}, {"deadcodedelay", "5"}});
    XmlDecode decoder2(&tr2, doc2);
    std::cout << "  " << tr2.tryDecodeSpaces(decoder2) << std::endl;
    AddrSpace *ws2 = tr2.getSpaceByName("ws2");
    printSpaceLine(ws2);
    delete doc;
    delete doc2;
  }
  return 0;
}
