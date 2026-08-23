/*
 * TYPEFACTORY-LOCALTYPE-CACHE-0001: locked Ghidra 12.0.4 oracle for
 * TypeFactory::setCoreType/cacheCoreTypes/getBase/getBaseNoChar/clear.
 *
 * The fixture clears the production BfdArchitecture factory before each
 * registration wave so names and insertion order are entirely fixture-owned.
 * Observations preserve exact names, hash ids, pointer identity, ordered-tree
 * winner selection, repeated-cache state, and post-clear reconstruction.
 *
 * REWORK waves additionally cover: wide-character and 10/16-byte float cache
 * slots, the raw TypeFactory constructor state, noncore-to-core promotion of
 * an existing named registration, same-name conflict errors and their partial
 * state, decodeCoreTypes full rebuilds (enum tree participation, shared-id
 * and missing-id LowlevelErrors), and the max_basetype_size array
 * conversion.
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "type.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;

void emitIdentity(const string &key,const Datatype *left,const Datatype *right)

{
  std::cout << key << '=' << (left == right ? 1 : 0) << '\n';
}

void emitType(const string &key,const Datatype *type)

{
  std::cout << key << ".name=" << type->getName() << '\n';
  std::cout << key << ".id=" << type->getId() << '\n';
  std::cout << key << ".size=" << type->getSize() << '\n';
  std::cout << key << ".meta=" << static_cast<int4>(type->getMetatype()) << '\n';
  std::cout << key << ".core=" << (type->isCoreType() ? 1 : 0) << '\n';
  std::cout << key << ".char=" << (type->isASCII() ? 1 : 0) << '\n';
}

/// Decode a <coretypes> stream held in a string against the given factory,
/// mirroring how SleighArchitecture::buildCoreTypes feeds the production
/// factory (sleigh_arch.cc:207-212).
static void decodeCoreTypesFromString(TypeFactory *factory,Architecture *glb,const string &xml)

{
  std::istringstream stream(xml);
  DocumentStorage store;
  Document *doc = store.parseDocument(stream);
  XmlDecode decoder(glb,doc->getRoot());
  factory->decodeCoreTypes(decoder);
}

/// First line of an error message (the oracle's "Shared type id" text spans
/// multiple lines through its printRaw fragments).
static string firstLine(const string &message)

{
  size_t pos = message.find('\n');
  return (pos == string::npos) ? message : message.substr(0,pos);
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary,"default",&std::cerr);
  DocumentStorage store;
  architecture.init(store);
  if (architecture.archid != "x86:LE:64:default:gcc")
    throw std::runtime_error("runtime architecture/compiler drifted: " + architecture.archid);

  TypeFactory *factory = architecture.types;
  if (factory == (TypeFactory *)0)
    throw std::runtime_error("architecture has no TypeFactory");

  factory->clear();
  factory->setCoreType("plain_high",1,TYPE_INT,false);
  factory->setCoreType("aaaaaaaa",1,TYPE_INT,false);
  factory->setCoreType("unsigned_custom_a",1,TYPE_UINT,false);
  factory->setCoreType("unsigned_custom_b",1,TYPE_UINT,false);
  factory->setCoreType("custom_ascii_glyph",1,TYPE_INT,true);
  factory->cacheCoreTypes();

  Datatype *plainHigh = factory->findByName("plain_high");
  Datatype *plainA = factory->findByName("aaaaaaaa");
  Datatype *uintA = factory->findByName("unsigned_custom_a");
  Datatype *uintB = factory->findByName("unsigned_custom_b");
  Datatype *ascii = factory->findByName("custom_ascii_glyph");
  Datatype *preferred = factory->getBase(1,TYPE_INT);
  Datatype *nochar = factory->getBaseNoChar(1,TYPE_INT);
  Datatype *preferredUint = factory->getBase(1,TYPE_UINT);
  emitType("initial.plain_high",plainHigh);
  emitType("initial.aaaaaaaa",plainA);
  emitType("initial.ascii",ascii);
  emitType("initial.uint_a",uintA);
  emitType("initial.uint_b",uintB);
  emitType("initial.preferred",preferred);
  emitType("initial.nochar",nochar);
  emitType("initial.preferred_uint",preferredUint);
  emitIdentity("initial.preferred_is_ascii",preferred,ascii);
  emitIdentity("initial.nochar_is_tree_last",nochar,
      plainHigh->getId() > plainA->getId() ? plainHigh : plainA);
  emitIdentity("initial.uint_is_tree_first",preferredUint,
      uintA->getId() < uintB->getId() ? uintA : uintB);
  emitIdentity("initial.charcache_is_ascii",factory->getTypeChar(1),ascii);
  emitIdentity("initial.getbase_repeat",preferred,factory->getBase(1,TYPE_INT));
  emitIdentity("initial.nochar_repeat",nochar,factory->getBaseNoChar(1,TYPE_INT));

  factory->cacheCoreTypes();
  emitIdentity("repeat_cache.preferred",preferred,factory->getBase(1,TYPE_INT));
  emitIdentity("repeat_cache.nochar",nochar,factory->getBaseNoChar(1,TYPE_INT));
  emitIdentity("repeat_cache.uint",preferredUint,factory->getBase(1,TYPE_UINT));

  factory->setCoreType("zzzzzzzz",1,TYPE_INT,false);
  Datatype *latePlain = factory->findByName("zzzzzzzz");
  factory->cacheCoreTypes();
  Datatype *lateNochar = factory->getBaseNoChar(1,TYPE_INT);
  emitType("late.plain",latePlain);
  emitType("late.nochar",lateNochar);
  emitIdentity("late.old_nochar_same",nochar,lateNochar);
  emitIdentity("late.new_nochar_is_late",lateNochar,latePlain);
  emitIdentity("late.preferred_still_ascii",factory->getBase(1,TYPE_INT),ascii);

  factory->clear();
  factory->clear();
  std::cout << "clear.old_name_absent="
            << (factory->findByName("custom_ascii_glyph") == (Datatype *)0 ? 1 : 0)
            << '\n';
  Datatype *emptyBase = factory->getBase(1,TYPE_INT);
  emitType("clear.empty_base",emptyBase);
  emitIdentity("clear.empty_nochar_falls_through",emptyBase,
      factory->getBaseNoChar(1,TYPE_INT));

  factory->clear();
  factory->setCoreType("post_clear_plain",1,TYPE_INT,false);
  factory->cacheCoreTypes();
  Datatype *postPlain = factory->findByName("post_clear_plain");
  Datatype *postPreferred = factory->getBase(1,TYPE_INT);
  Datatype *postNochar = factory->getBaseNoChar(1,TYPE_INT);
  emitType("post.plain",postPlain);
  emitIdentity("post.preferred_is_plain",postPreferred,postPlain);
  emitIdentity("post.nochar_is_plain",postNochar,postPlain);
  factory->cacheCoreTypes();
  emitIdentity("post.repeat_cache_preferred",postPreferred,
      factory->getBase(1,TYPE_INT));
  emitIdentity("post.repeat_cache_nochar",postNochar,
      factory->getBaseNoChar(1,TYPE_INT));

  factory->setCoreType("post_clear_ascii",1,TYPE_INT,true);
  Datatype *postAscii = factory->findByName("post_clear_ascii");
  factory->cacheCoreTypes();
  emitType("post.ascii",postAscii);
  emitIdentity("post.preferred_is_ascii",factory->getBase(1,TYPE_INT),postAscii);
  emitIdentity("post.nochar_stays_plain",factory->getBaseNoChar(1,TYPE_INT),postPlain);
  emitIdentity("post.charcache_is_ascii",factory->getTypeChar(1),postAscii);

  // ---- REWORK waves: wide characters, float10/16, raw constructor,
  // ---- promotion, conflicts, decodeCoreTypes, and large-base conversion.

  // Wave A: wide characters and dedicated float slots.
  factory->clear();
  factory->setCoreType("wide2",2,TYPE_INT,true);
  factory->setCoreType("wide4",4,TYPE_INT,true);
  factory->setCoreType("plain2",2,TYPE_INT,false);
  factory->setCoreType("f10",10,TYPE_FLOAT,false);
  factory->setCoreType("f16",16,TYPE_FLOAT,false);
  factory->cacheCoreTypes();
  emitType("wide.w2",factory->findByName("wide2"));
  emitType("wide.f10",factory->findByName("f10"));
  emitType("wide.f16",factory->findByName("f16"));
  emitIdentity("wide.charcache2_is_wide2",factory->getTypeChar(2),factory->findByName("wide2"));
  emitIdentity("wide.preferred2_is_plain2",factory->getBase(2,TYPE_INT),factory->findByName("plain2"));
  emitIdentity("wide.f10_slot",factory->getBase(10,TYPE_FLOAT),factory->findByName("f10"));
  emitIdentity("wide.f16_slot",factory->getBase(16,TYPE_FLOAT),factory->findByName("f16"));
  try {
    factory->getTypeChar(5);
    std::cout << "wide.char5_threw=0\n";
  }
  catch(const LowlevelError &err) {
    std::cout << "wide.char5_threw=1\n";
    std::cout << "wide.char5_msg=" << err.explain << '\n';
  }

  // Wave B: the raw TypeFactory constructor state (type.cc:3106-3119).
  {
    TypeFactory rawFactory(&architecture);
    try {
      rawFactory.getBase(1,TYPE_INT);
      std::cout << "raw.align_threw=0\n";
    }
    catch(const LowlevelError &err) {
      std::cout << "raw.align_threw=1\n";
      std::cout << "raw.align_msg=" << err.explain << '\n';
    }
    emitType("raw.void",rawFactory.getTypeVoid());
    try {
      rawFactory.getTypeChar(1);
      std::cout << "raw.char_threw=0\n";
    }
    catch(const LowlevelError &err) {
      std::cout << "raw.char_threw=1\n";
      std::cout << "raw.char_msg=" << err.explain << '\n';
    }
  }

  // Wave C: promoting an existing non-core named type (type.cc:3178-3195).
  factory->clear();
  Datatype *promoPre = factory->getBase(1,TYPE_INT,"promo_plain");
  emitType("promo.pre",promoPre);
  factory->setCoreType("promo_plain",1,TYPE_INT,false);
  Datatype *promoPost = factory->findByName("promo_plain");
  emitType("promo.post",promoPost);
  factory->cacheCoreTypes();
  emitIdentity("promo.preferred_is_promo",factory->getBase(1,TYPE_INT),promoPost);
  emitIdentity("promo.nochar_is_promo",factory->getBaseNoChar(1,TYPE_INT),promoPost);
  factory->clearNoncore();
  std::cout << "promo.noncore_survives="
            << (factory->findByName("promo_plain") == (Datatype *)0 ? 0 : 1) << '\n';

  // Wave D: same-name conflicts leave the factory untouched (type.cc:3423).
  try {
    factory->setCoreType("promo_plain",2,TYPE_INT,false);
    std::cout << "conflict.size_threw=0\n";
  }
  catch(const LowlevelError &err) {
    std::cout << "conflict.size_threw=1\n";
    std::cout << "conflict.size_msg=" << err.explain << '\n';
  }
  try {
    factory->setCoreType("promo_plain",1,TYPE_INT,true);
    std::cout << "conflict.char_threw=0\n";
  }
  catch(const LowlevelError &err) {
    std::cout << "conflict.char_threw=1\n";
    std::cout << "conflict.char_msg=" << err.explain << '\n';
  }
  Datatype *conflictSurvivor = factory->findByName("promo_plain");
  emitType("conflict.survivor",conflictSurvivor);
  emitIdentity("conflict.preferred_unaffected",factory->getBase(1,TYPE_INT),conflictSurvivor);

  // Wave E1: full decodeCoreTypes rebuild (type.cc:4567-4577).
  decodeCoreTypesFromString(factory,&architecture,
      "<coretypes>"
      "<type name=\"dk_int1\" size=\"1\" metatype=\"int\" id=\"0x5500000000000001\"/>"
      "<type name=\"dk_char\" size=\"1\" metatype=\"int\" char=\"true\" id=\"0x5500000000000002\"/>"
      "<type name=\"dk_utf2\" size=\"2\" metatype=\"int\" utf=\"true\" id=\"0x5500000000000003\"/>"
      "<type metatype=\"enum_int\" name=\"dk_enum1\" size=\"1\" id=\"0x5500000000000004\">"
      "<val name=\"A\" value=\"0\"/></type>"
      "<type metatype=\"void\" id=\"0x5500000000000005\"/>"
      "<type name=\"dk_plain2\" size=\"2\" metatype=\"int\" id=\"0x5500000000000006\"/>"
      "</coretypes>");
  std::cout << "dk.old_promo_gone="
            << (factory->findByName("promo_plain") == (Datatype *)0 ? 1 : 0) << '\n';
  emitType("dk.int1",factory->findByName("dk_int1"));
  emitType("dk.char",factory->findByName("dk_char"));
  emitType("dk.enum1",factory->findByName("dk_enum1"));
  emitType("dk.void",factory->findByName("void"));
  emitIdentity("dk.nochar_is_int1",factory->getBaseNoChar(1,TYPE_INT),factory->findByName("dk_int1"));
  emitIdentity("dk.preferred_is_char",factory->getBase(1,TYPE_INT),factory->findByName("dk_char"));
  emitIdentity("dk.charcache2_is_utf2",factory->getTypeChar(2),factory->findByName("dk_utf2"));
  emitIdentity("dk.preferred2_is_plain2",factory->getBase(2,TYPE_INT),factory->findByName("dk_plain2"));
  emitIdentity("dk.void_is_decoded",factory->getTypeVoid(),factory->findByName("void"));

  // Wave E2: a size-1 signed enum with no plain INT competitor wins
  // type_nochar (type.cc:3220-3222 runs before the isEnumType break).
  decodeCoreTypesFromString(factory,&architecture,
      "<coretypes>"
      "<type metatype=\"enum_int\" name=\"dk_enum_only\" size=\"1\" id=\"0x5500000000000011\"/>"
      "</coretypes>");
  emitIdentity("dk2.nochar_is_enum",factory->getBaseNoChar(1,TYPE_INT),factory->findByName("dk_enum_only"));
  emitIdentity("dk2.preferred_not_enum",factory->getBase(1,TYPE_INT),factory->findByName("dk_enum_only"));
  emitType("dk2.preferred",factory->getBase(1,TYPE_INT));

  // Wave E3: the shared-id insert conflict (type.cc:3393-3403) with partial
  // state — the first child survives, the cache pass never runs.
  try {
    decodeCoreTypesFromString(factory,&architecture,
        "<coretypes>"
        "<type name=\"dk3_a\" size=\"1\" metatype=\"int\" id=\"0x5500000000000021\"/>"
        "<type name=\"dk3_b\" size=\"1\" metatype=\"int\" id=\"0x5500000000000021\"/>"
        "</coretypes>");
    std::cout << "dk3.shared_threw=0\n";
  }
  catch(const LowlevelError &err) {
    std::cout << "dk3.shared_threw=1\n";
    std::cout << "dk3.shared_first_line=" << firstLine(err.explain) << '\n';
  }
  std::cout << "dk3.partial_a_present="
            << (factory->findByName("dk3_a") == (Datatype *)0 ? 0 : 1) << '\n';
  std::cout << "dk3.partial_b_absent="
            << (factory->findByName("dk3_b") == (Datatype *)0 ? 1 : 0) << '\n';
  emitIdentity("dk3.preferred_not_a",factory->getBase(1,TYPE_INT),factory->findByName("dk3_a"));

  // Wave E4: a named candidate without an id (type.cc:3419).
  try {
    decodeCoreTypesFromString(factory,&architecture,
        "<coretypes>"
        "<type metatype=\"void\"/>"
        "</coretypes>");
    std::cout << "dk4.noid_threw=0\n";
  }
  catch(const LowlevelError &err) {
    std::cout << "dk4.noid_threw=1\n";
    std::cout << "dk4.noid_msg=" << err.explain << '\n';
  }
  std::cout << "dk4.void_absent="
            << (factory->findByName("void") == (Datatype *)0 ? 1 : 0) << '\n';

  // Wave F: the large-base array conversion (type.cc:3652-3657).
  factory->clear();
  factory->setCoreType("u1",1,TYPE_UNKNOWN,false);
  factory->cacheCoreTypes();
  Datatype *big = factory->getBase(20,TYPE_INT);
  emitType("big.arr20",big);
  emitIdentity("big.repeat",big,factory->getBase(20,TYPE_INT));
  std::cout << "big.element_name="
            << ((TypeArray *)big)->getBase()->getName() << '\n';
  std::cout << "big.element_core="
            << (((TypeArray *)big)->getBase()->isCoreType() ? 1 : 0) << '\n';
  Datatype *bigFloat = factory->getBase(12,TYPE_FLOAT);
  emitType("big.float12",bigFloat);
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw std::invalid_argument(
          "usage: typefactory_local_cache_1204 SPEC_DIRECTORY BINARY");
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const ghidra::LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
  }
  catch(const std::exception &err) {
    std::cerr << "std::exception: " << err.what() << '\n';
  }
  return 1;
}
