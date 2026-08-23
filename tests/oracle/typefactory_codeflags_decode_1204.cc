/*
 * TYPEFACTORY-CODEFLAGS-DECODE-0001: locked Ghidra 12.0.4 oracle for
 * TypeFactory::decodeTypeWithCodeFlags (type.cc:4193-4212), the
 * decodeCode stub/compare/define chain it calls (type.cc:4401-4429,
 * 2903-2931), and the XmlDecode cursor partial state every error path
 * leaves behind.
 *
 * The locked oracle's decodeTypeWithCodeFlags never reaches decodeCode's
 * prototype handling on real streams: decodeBasic runs the outer element's
 * attribute enumeration to exhaustion, the WORDSIZE loop (type.cc:4201-4207,
 * no rewindAttributes) reads nothing, and decodeCode's decodeStub then
 * re-reads the SAME still-open element and raises "Bad size for type ".
 * The fixture records that behaviour verbatim across code-pointer flag
 * combinations (varargs/model/ctor/dtor/thiscall models), the two earlier
 * error paths, the decodeCode paths reachable through decodeType
 * (prototype-less stub creation, completion via the setPrototype wrapper
 * with a null prototype, dedup identity, redefinition and name-clash
 * errors with their surviving factory state), and the pointer->code chain.
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

/// Run one decodeTypeWithCodeFlags probe over the wrapped inner XML and
/// emit the error record plus the cursor partial state: the still-open
/// element's unread children (peek), the successful close of that element,
/// and the readable <void/> sibling behind it.
static void runCodeFlagsCase(TypeFactory *factory,Architecture *glb,
                              const string &key,const string &innerXml,
                              bool isConstructor,bool isDestructor)
{
  const string xml = "<root>" + innerXml + "<void/></root>";
  std::istringstream stream(xml);
  DocumentStorage store;
  Document *doc = store.parseDocument(stream);
  XmlDecode decoder(glb,doc->getRoot());
  uint4 rootId = decoder.openElement();
  bool thrown = false;
  string text;
  try {
    factory->decodeTypeWithCodeFlags(decoder,isConstructor,isDestructor);
  }
  catch(const LowlevelError &err) {
    thrown = true;
    text = err.explain;
  }
  std::cout << key << ".thrown=" << (thrown ? 1 : 0) << '\n';
  std::cout << key << ".text=" << text << '\n';
  std::cout << key << ".peek=" << (decoder.peekElement() != 0 ? 1 : 0) << '\n';
  decoder.closeElementSkipping(0);
  int4 resume = 0;
  try {
    uint4 vId = decoder.openElement(ELEM_VOID);
    decoder.closeElement(vId);
    resume = 1;
  }
  catch(DecoderError &err) { }
  std::cout << key << ".resume_void=" << resume << '\n';
  decoder.closeElement(rootId);
}

/// Decode one inner <type> element through TypeFactory::decodeType and
/// return the resulting Datatype, or null with errText set.
static Datatype *decodeTypeStr(TypeFactory *factory,Architecture *glb,
                               const string &innerXml,string &errText)
{
  const string xml = "<root>" + innerXml + "</root>";
  std::istringstream stream(xml);
  DocumentStorage store;
  Document *doc = store.parseDocument(stream);
  XmlDecode decoder(glb,doc->getRoot());
  uint4 rootId = decoder.openElement();
  Datatype *res = (Datatype *)0;
  errText.clear();
  try {
    res = factory->decodeType(decoder);
  }
  catch(const LowlevelError &err) {
    errText = err.explain;
  }
  decoder.closeElement(rootId);
  return res;
}

static void emitThrown(const string &key,bool thrown,const string &text)

{
  std::cout << key << ".thrown=" << (thrown ? 1 : 0) << '\n';
  std::cout << key << ".text=" << text << '\n';
}

static void emitCodeType(const string &key,const Datatype *ct)

{
  std::cout << key << ".name=" << ct->getName() << '\n';
  std::cout << key << ".id=" << ct->getId() << '\n';
  std::cout << key << ".size=" << ct->getSize() << '\n';
  std::cout << key << ".meta=" << static_cast<int4>(ct->getMetatype()) << '\n';
  std::cout << key << ".incomplete=" << (ct->isIncomplete() ? 1 : 0) << '\n';
  std::cout << key << ".varlength=" << (ct->isVariableLength() ? 1 : 0) << '\n';
  const TypeCode *tc = dynamic_cast<const TypeCode *>(ct);
  std::cout << key << ".proto=" << ((tc != (const TypeCode *)0 && tc->getPrototype() != (const FuncProto *)0) ? 1 : 0) << '\n';
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

  // ---------------- Wave 1: decodeTypeWithCodeFlags ----------------
  // a_*: the nested pointer->code form under every code-pointer flag
  // combination. The locked oracle throws "Bad size for type " (empty
  // name) from decodeCode's decodeStub re-read of the exhausted outer
  // element before ANY flag is consulted; the records prove the flag
  // indifference byte-for-byte.
  runCodeFlagsCase(factory,&architecture,"w1.a_plain",
    "<type metatype=\"ptr\" size=\"8\">"
    "<type metatype=\"code\" size=\"1\"/>"
    "</type>", true, false);
  runCodeFlagsCase(factory,&architecture,"w1.a_varargs",
    "<type metatype=\"ptr\" size=\"8\">"
    "<type metatype=\"code\" size=\"1\">"
    "<prototype model=\"__stdcall\" dotdotdot=\"true\"><returnsym/></prototype>"
    "</type>"
    "</type>", false, true);
  runCodeFlagsCase(factory,&architecture,"w1.a_model",
    "<type metatype=\"ptr\" size=\"8\">"
    "<type metatype=\"code\" size=\"1\">"
    "<prototype model=\"unknown_cc\" constructor=\"true\" destructor=\"true\"/>"
    "</type>"
    "</type>", true, true);
  runCodeFlagsCase(factory,&architecture,"w1.a_thiscall",
    "<type metatype=\"ptr\" size=\"8\" wordsize=\"1\">"
    "<type metatype=\"code\" size=\"1\">"
    "<prototype model=\"__thiscall\"><returnsym/></prototype>"
    "</type>"
    "</type>", false, false);
  // b_*: metatype check failures before any child is read.
  runCodeFlagsCase(factory,&architecture,"w1.b_code",
    "<type metatype=\"code\" size=\"1\"/>", true, false);
  runCodeFlagsCase(factory,&architecture,"w1.b_unspec",
    "<type size=\"4\"/>", true, true);
  // c_*: the first decodeBasic's own Bad size throw (named and anonymous).
  runCodeFlagsCase(factory,&architecture,"w1.c_nosize_named",
    "<type metatype=\"ptr\" name=\"vp\"/>", true, false);
  runCodeFlagsCase(factory,&architecture,"w1.c_nosize_anon",
    "<type metatype=\"ptr\"/>", false, true);

  // ---------------- Wave 2: decodeCode via decodeType ----------------
  // d_named: prototype-less code stub decoded, completed in place by the
  // setPrototype wrapper (Ghidra clears type_incomplete even for a null
  // prototype), observable through the returned handle.
  string err;
  Datatype *cfOne = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" name=\"cf_one\" size=\"1\"/>", err);
  std::cout << "w2.d_named.thrown=" << (cfOne == (Datatype *)0 ? 1 : 0) << '\n';
  emitCodeType("w2.d_named",cfOne);

  // d_dedup: identical second decode returns the same container object.
  Datatype *cfOneAgain = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" name=\"cf_one\" size=\"1\"/>", err);
  std::cout << "w2.d_dedup.identity=" << (cfOne == cfOneAgain ? 1 : 0) << '\n';
  emitCodeType("w2.d_dedup",cfOneAgain);

  // d_redefine: same name+id, different size; the completed container type
  // fails compareDependency and the previous definition survives.
  Datatype *cfRedefined = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" name=\"cf_one\" size=\"2\"/>", err);
  emitThrown("w2.d_redefine", cfRedefined == (Datatype *)0, err);
  emitCodeType("w2.d_redefine_survivor", factory->findByName("cf_one"));

  // d_clash: a named non-code occupant of the name triggers the
  // findByIdLocal metatype check; the int definition survives.
  Datatype *clashInt = decodeTypeStr(factory,&architecture,
    "<type metatype=\"int\" name=\"clash_t\" size=\"4\"/>", err);
  std::cout << "w2.d_clash_int.thrown=" << (clashInt == (Datatype *)0 ? 1 : 0) << '\n';
  std::cout << "w2.d_clash_int.meta=" << static_cast<int4>(clashInt->getMetatype()) << '\n';
  Datatype *clashCode = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" name=\"clash_t\" size=\"1\"/>", err);
  emitThrown("w2.d_clash", clashCode == (Datatype *)0, err);
  const Datatype *clashSurvivor = factory->findByName("clash_t");
  std::cout << "w2.d_clash_survivor.meta=" << static_cast<int4>(clashSurvivor->getMetatype()) << '\n';
  std::cout << "w2.d_clash_survivor.size=" << clashSurvivor->getSize() << '\n';

  // d_ctorflags: TypeFactory::decodeCode is PRIVATE in the locked oracle
  // (type.hh:791) — its only public callers are decodeTypeNoRef
  // (isConstructor/isDestructor both false) and decodeTypeWithCodeFlags
  // (which throws before reaching it, wave 1). The constructor/destructor
  // flag chain therefore has no reachable public success observation in
  // 12.0.4; the w1 flag-indifference records are its full observable set.

  // d_varlength: a varlength attribute folds the size into the id
  // (decodeBasic hashSize) and survives the completion wrapper's flag OR.
  Datatype *cfV = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" name=\"cf_v\" size=\"1\" varlength=\"true\"/>", err);
  std::cout << "w2.d_varlength.thrown=" << (cfV == (Datatype *)0 ? 1 : 0) << '\n';
  emitCodeType("w2.d_varlength",cfV);
  Datatype *cfVAgain = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" name=\"cf_v\" size=\"1\" varlength=\"true\"/>", err);
  std::cout << "w2.d_varlength_dedup.identity=" << (cfV == cfVAgain ? 1 : 0) << '\n';

  // d_unnamed: anonymous code stub (id 0) canonicalized structurally;
  // repeat decode dedups to the same object.
  Datatype *anon1 = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" size=\"1\"/>", err);
  std::cout << "w2.d_unnamed.thrown=" << (anon1 == (Datatype *)0 ? 1 : 0) << '\n';
  emitCodeType("w2.d_unnamed",anon1);
  Datatype *anon2 = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" size=\"1\"/>", err);
  std::cout << "w2.d_unnamed_dedup.identity=" << (anon1 == anon2 ? 1 : 0) << '\n';

  // ---------------- Wave 3: pointer->code chain via decodeType ----------------
  Datatype *chainCode = decodeTypeStr(factory,&architecture,
    "<type metatype=\"code\" name=\"cf_chain\" size=\"1\"/>", err);
  std::cout << "w3.chain.thrown=" << (chainCode == (Datatype *)0 ? 1 : 0) << '\n';

  Datatype *plainPtr = decodeTypeStr(factory,&architecture,
    "<type metatype=\"ptr\" size=\"8\">"
    "<type metatype=\"code\" name=\"cf_chain\" size=\"1\"/>"
    "</type>", err);
  std::cout << "w3.ptr.thrown=" << (plainPtr == (Datatype *)0 ? 1 : 0) << '\n';
  std::cout << "w3.ptr.meta=" << static_cast<int4>(plainPtr->getMetatype()) << '\n';
  std::cout << "w3.ptr.size=" << plainPtr->getSize() << '\n';
  std::cout << "w3.ptr.wordsize=" << dynamic_cast<const TypePointer *>(plainPtr)->getWordSize() << '\n';
  std::cout << "w3.ptr.ptrto_identity="
            << (dynamic_cast<const TypePointer *>(plainPtr)->getPtrTo() == chainCode ? 1 : 0) << '\n';

  Datatype *widePtr = decodeTypeStr(factory,&architecture,
    "<type metatype=\"ptr\" size=\"8\" wordsize=\"4\">"
    "<type metatype=\"code\" name=\"cf_chain\" size=\"1\"/>"
    "</type>", err);
  std::cout << "w3.ptr_ws.thrown=" << (widePtr == (Datatype *)0 ? 1 : 0) << '\n';
  std::cout << "w3.ptr_ws.wordsize=" << dynamic_cast<const TypePointer *>(widePtr)->getWordSize() << '\n';
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw std::invalid_argument(
          "usage: typefactory_codeflags_decode_1204 SPEC_DIRECTORY BINARY");
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
