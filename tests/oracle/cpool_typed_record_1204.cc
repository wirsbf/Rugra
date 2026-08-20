/*
 * CPOOL-TYPED-RECORD-0001: locked Ghidra 12.0.4 oracle for CPoolRecord,
 * ConstantPool, and ConstantPoolInternal.
 *
 * The fixture drives the production BfdArchitecture TypeFactory, decodes
 * real constant-pool XML, observes canonical Datatype pointer identity and
 * exception-time partial state, and emits the exact PackedEncode bytes.
 */
#include "bfd_arch.hh"
#include "cpool.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "type.hh"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using namespace std;

string bytesToHex(const string &bytes)

{
  ostringstream result;
  result << hex << setfill('0');
  for (string::const_iterator iter = bytes.begin(); iter != bytes.end(); ++iter)
    result << setw(2) << (static_cast<unsigned int>(static_cast<uint1>(*iter)));
  return result.str();
}

string recordBytes(const CPoolRecord *record)

{
  if (record->getByteData() == (const uint1 *)0)
    return "-";
  ostringstream result;
  result << hex << setfill('0');
  for (int4 i = 0; i < record->getByteDataLength(); ++i)
    result << setw(2) << static_cast<unsigned int>(record->getByteData()[i]);
  return result.str();
}

void emitRecord(const char *key,const CPoolRecord *record,
    const Datatype *intType,const Datatype *boolType)

{
  cout << "record|key=" << key
       << "|tag=" << record->getTag()
       << "|token=" << record->getToken()
       << "|value=" << record->getValue()
       << "|bytes=" << recordBytes(record)
       << "|type=" << (record->getType() == (Datatype *)0
                            ? string("<null>") : record->getType()->getName())
       << "|is_i4=" << (record->getType() == intType ? 1 : 0)
       << "|is_bool=" << (record->getType() == boolType ? 1 : 0)
       << "|ctor=" << (record->isConstructor() ? 1 : 0)
       << "|dtor=" << (record->isDestructor() ? 1 : 0)
       << '\n';
}

void decodePool(ConstantPoolInternal &pool,TypeFactory &factory,
    Architecture &architecture,const string &xml)

{
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  pool.decode(decoder,factory);
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary,"default",&cerr);
  DocumentStorage store;
  architecture.init(store);
  if (architecture.archid != "x86:LE:64:default:gcc")
    throw runtime_error("runtime architecture/compiler drifted: " + architecture.archid);

  TypeFactory *factory = architecture.types;
  if (factory == (TypeFactory *)0)
    throw runtime_error("architecture has no TypeFactory");
  Datatype *intType = factory->findByName("int4");
  Datatype *boolType = factory->findByName("bool");
  if (intType == (Datatype *)0 || intType->getSize() != 4 ||
      intType->getMetatype() != TYPE_INT)
    throw runtime_error("production TypeFactory has no canonical int4");
  if (boolType == (Datatype *)0 || boolType->getSize() != 1 ||
      boolType->getMetatype() != TYPE_BOOL)
    throw runtime_error("production TypeFactory has no canonical bool1");

  cout << "schema=1\n";
  cout << "oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";

  const string primaryXml =
      "<constantpool>"
      "<ref a=\"9\" b=\"4\"/><cpoolrec tag=\"primitive\">"
      "<value>287454020</value><token>primitive-token</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"2\" b=\"8\"/><cpoolrec tag=\"string\">"
      "<data length=\"17\">00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 </data>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"7\" b=\"1\"/><cpoolrec tag=\"classref\"><token>class-token</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"4\" b=\"0\"/><cpoolrec tag=\"method\"><token>method-token</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"6\" b=\"2\"/><cpoolrec tag=\"field\"><token>field-token</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"3\" b=\"9\"/><cpoolrec tag=\"arraylength\"><token>length-token</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"8\" b=\"5\"/><cpoolrec tag=\"instanceof\"><token>instance-token</token>"
      "<typeref name=\"bool\"/></cpoolrec>"
      "<ref a=\"5\" b=\"7\"/><cpoolrec tag=\"checkcast\"><token>cast-token</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"10\" b=\"0\"/><cpoolrec tag=\"unknown-tag\"><value>7</value>"
      "<token>unknown-token</token><typeref name=\"int4\"/></cpoolrec>"
      "</constantpool>";
  ConstantPoolInternal primary;
  decodePool(primary,*factory,architecture,primaryXml);

  const uintb refs[][2] = {
    {2,8}, {3,9}, {4,0}, {5,7}, {6,2}, {7,1}, {8,5}, {9,4}, {10,0},
  };
  const char *keys[] = {
    "2,8", "3,9", "4,0", "5,7", "6,2", "7,1", "8,5", "9,4", "10,0",
  };
  for (int4 i = 0; i < 9; ++i) {
    vector<uintb> key;
    key.push_back(refs[i][0]);
    key.push_back(refs[i][1]);
    emitRecord(keys[i],primary.getRecord(key),intType,boolType);
  }

  vector<uintb> methodOne(1,4);
  vector<uintb> methodTwo;
  methodTwo.push_back(4);
  methodTwo.push_back(0);
  vector<uintb> methodThree(methodTwo);
  methodThree.push_back(77);
  vector<uintb> reverse;
  reverse.push_back(0);
  reverse.push_back(4);
  vector<uintb> miss;
  miss.push_back(100);
  miss.push_back(1);
  cout << "lookup|one_equals_two="
       << (primary.getRecord(methodOne) == primary.getRecord(methodTwo) ? 1 : 0)
       << "|third_ignored="
       << (primary.getRecord(methodThree) == primary.getRecord(methodTwo) ? 1 : 0)
       << "|reverse_miss=" << (primary.getRecord(reverse) == (const CPoolRecord *)0 ? 1 : 0)
       << "|plain_miss=" << (primary.getRecord(miss) == (const CPoolRecord *)0 ? 1 : 0)
       << '\n';

  ostringstream packedStream;
  PackedEncode packedEncoder(packedStream);
  primary.encode(packedEncoder);
  cout << "packed=" << bytesToHex(packedStream.str()) << '\n';

  ConstantPoolInternal replacement;
  vector<uintb> replacementKey;
  replacementKey.push_back(42);
  replacementKey.push_back(7);
  replacement.putRecord(replacementKey,CPoolRecord::pointer_field,"original",intType);
  string duplicateError;
  try {
    replacement.putRecord(replacementKey,CPoolRecord::check_cast,"replacement",boolType);
  }
  catch(const LowlevelError &err) {
    duplicateError = err.explain;
  }
  const CPoolRecord *original = replacement.getRecord(replacementKey);
  cout << "duplicate|error=" << duplicateError
       << "|token=" << original->getToken()
       << "|type_is_i4=" << (original->getType() == intType ? 1 : 0) << '\n';
  replacement.clear();
  replacement.putRecord(replacementKey,CPoolRecord::check_cast,"replacement",boolType);
  const CPoolRecord *replaced = replacement.getRecord(replacementKey);
  cout << "replace_after_clear|empty=0|token=" << replaced->getToken()
       << "|type_is_bool=" << (replaced->getType() == boolType ? 1 : 0) << '\n';

  const string partialXml =
      "<constantpool>"
      "<ref a=\"1\" b=\"1\"/><cpoolrec tag=\"field\"><token>good</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"13\" b=\"6\"/><cpoolrec tag=\"string\"><token>not-data</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "<ref a=\"20\" b=\"1\"/><cpoolrec tag=\"field\"><token>after</token>"
      "<typeref name=\"int4\"/></cpoolrec>"
      "</constantpool>";
  ConstantPoolInternal partial;
  string partialError;
  try {
    decodePool(partial,*factory,architecture,partialXml);
  }
  catch(const LowlevelError &err) {
    partialError = err.explain;
  }
  vector<uintb> goodKey;
  goodKey.push_back(1);
  goodKey.push_back(1);
  vector<uintb> badKey;
  badKey.push_back(13);
  badKey.push_back(6);
  vector<uintb> afterKey;
  afterKey.push_back(20);
  afterKey.push_back(1);
  const CPoolRecord *bad = partial.getRecord(badKey);
  cout << "partial|error=" << partialError
       << "|good=" << (partial.getRecord(goodKey) != (const CPoolRecord *)0 ? 1 : 0)
       << "|bad=" << (bad != (const CPoolRecord *)0 ? 1 : 0)
       << "|bad_tag=" << bad->getTag()
       << "|bad_token=" << bad->getToken()
       << "|bad_type_null=" << (bad->getType() == (Datatype *)0 ? 1 : 0)
       << "|after_miss=" << (partial.getRecord(afterKey) == (const CPoolRecord *)0 ? 1 : 0)
       << '\n';

  const string typeErrorXml =
      "<constantpool><ref a=\"14\" b=\"6\"/><cpoolrec tag=\"field\">"
      "<token>typed-before-error</token><typeref name=\"missing_cpool_type\"/>"
      "</cpoolrec></constantpool>";
  ConstantPoolInternal typeErrorPool;
  string typeError;
  try {
    decodePool(typeErrorPool,*factory,architecture,typeErrorXml);
  }
  catch(const LowlevelError &err) {
    typeError = err.explain;
  }
  vector<uintb> typeErrorKey;
  typeErrorKey.push_back(14);
  typeErrorKey.push_back(6);
  const CPoolRecord *typePartial = typeErrorPool.getRecord(typeErrorKey);
  cout << "type_error|error=" << typeError
       << "|present=" << (typePartial != (const CPoolRecord *)0 ? 1 : 0)
       << "|tag=" << typePartial->getTag()
       << "|token=" << typePartial->getToken()
       << "|type_null=" << (typePartial->getType() == (Datatype *)0 ? 1 : 0)
       << '\n';

  const string flagsXml =
      "<constantpool><ref a=\"30\" b=\"1\"/>"
      "<cpoolrec tag=\"method\" constructor=\"true\" destructor=\"true\">"
      "<token>flagged</token><type metatype=\"ptr\" size=\"8\">"
      "<type metatype=\"code\" size=\"1\"><prototype/></type></type>"
      "</cpoolrec></constantpool>";
  ConstantPoolInternal flagsPool;
  string flagsError;
  try {
    decodePool(flagsPool,*factory,architecture,flagsXml);
  }
  catch(const LowlevelError &err) {
    flagsError = err.explain;
  }
  vector<uintb> flagsKey;
  flagsKey.push_back(30);
  flagsKey.push_back(1);
  const CPoolRecord *flagsRecord = flagsPool.getRecord(flagsKey);
  const FuncProto *prototype = (const FuncProto *)0;
  if (flagsRecord->getType() != (Datatype *)0) {
    const TypePointer *pointerType = (const TypePointer *)flagsRecord->getType();
    const TypeCode *codeType = (const TypeCode *)pointerType->getPtrTo();
    prototype = codeType->getPrototype();
  }
  cout << "codeflags|status=" << (flagsError.size() == 0 ? "OK" : "ERROR")
       << "|error=" << flagsError
       << "|record_ctor=" << (flagsRecord->isConstructor() ? 1 : 0)
       << "|record_dtor=" << (flagsRecord->isDestructor() ? 1 : 0)
       << "|type_null=" << (flagsRecord->getType() == (Datatype *)0 ? 1 : 0)
       << "|prototype=" << (prototype != (const FuncProto *)0 ? 1 : 0)
       << "|proto_ctor=" << (prototype != (const FuncProto *)0 && prototype->isConstructor() ? 1 : 0)
       << "|proto_dtor=" << (prototype != (const FuncProto *)0 && prototype->isDestructor() ? 1 : 0)
       << '\n';
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument("usage: cpool_typed_record_1204 SPEC_DIRECTORY BINARY");
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const LowlevelError &err) {
    cerr << "LowlevelError: " << err.explain << '\n';
  }
  catch(const exception &err) {
    cerr << "std::exception: " << err.what() << '\n';
  }
  return 1;
}
