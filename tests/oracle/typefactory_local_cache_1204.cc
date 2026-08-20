/*
 * TYPEFACTORY-LOCALTYPE-CACHE-0001: locked Ghidra 12.0.4 oracle for
 * TypeFactory::setCoreType/cacheCoreTypes/getBase/getBaseNoChar/clear.
 *
 * The fixture clears the production BfdArchitecture factory before each
 * registration wave so names and insertion order are entirely fixture-owned.
 * Observations preserve exact names, hash ids, pointer identity, ordered-tree
 * winner selection, repeated-cache state, and post-clear reconstruction.
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "type.hh"

#include <iostream>
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
