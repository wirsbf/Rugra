/*
 * PROTO-EFFECT-MODEL-0001: locked Ghidra 12.0.4 FuncProto model/effect oracle.
 */
#include "bfd_arch.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;

struct Probe {
  const char *label;
  const char *space;
  uintb offset;
  int4 size;
};

const Probe probes[] = {
  { "unique_always", "unique", 0x777, 4 },
  { "same_offset_const", "const", 0x10, 8 },
  { "whole_ram_space", "ram", 0x777, 32 },
  { "register_exact", "register", 0x10, 8 },
  { "register_contained", "register", 0x12, 2 },
  { "register_partial_left", "register", 0x0e, 4 },
  { "register_partial_right", "register", 0x16, 4 },
  { "register_killed", "register", 0x20, 8 },
  { "return_address", "register", 0x30, 8 },
  { "same_offset_stack", "stack", 0x10, 8 },
  { "same_offset_register", "register", 0x10, 8 },
  { "before_first_register", "register", 0x08, 8 }
};

const char *effectName(uint4 effect);

void writeEffectiveRecords(ostream &out,const FuncProto &proto)
{
  out << '[';
  bool first = true;
  for(vector<EffectRecord>::const_iterator iter=proto.effectBegin();
      iter!=proto.effectEnd();++iter) {
    if (!first) out << ',';
    first = false;
    Address address = iter->getAddress();
    out << "{\"space\":\"" << address.getSpace()->getName()
        << "\",\"offset\":" << address.getOffset()
        << ",\"size\":" << iter->getSize()
        << ",\"effect\":\"" << effectName(iter->getType()) << "\"}";
  }
  out << ']';
}

const char *effectName(uint4 effect)
{
  switch(effect) {
  case EffectRecord::unaffected: return "unaffected";
  case EffectRecord::killedbycall: return "killedbycall";
  case EffectRecord::return_address: return "return_address";
  case EffectRecord::unknown_effect: return "unknown_effect";
  default: return "invalid";
  }
}

void decodeModel(Architecture &architecture,ProtoModel &model,const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  model.decode(decoder);
}

void decodeProto(Architecture &architecture,ProtoModel *model,Datatype *voidType,
                 FuncProto &proto,const string &xml)
{
  proto.setInternal(model,voidType);
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  proto.decode(decoder,&architecture);
}

void writeEffects(ostream &out,const FuncProto &proto,const Architecture &architecture)
{
  out << '[';
  for(size_t i=0;i<sizeof(probes)/sizeof(probes[0]);++i) {
    if (i != 0) out << ',';
    AddrSpace *space = architecture.getSpaceByName(probes[i].space);
    if (space == (AddrSpace *)0)
      throw std::runtime_error(string("missing address space: ") + probes[i].space);
    out << "{\"label\":\"" << probes[i].label
        << "\",\"space\":\"" << probes[i].space
        << "\",\"offset\":" << probes[i].offset
        << ",\"size\":" << probes[i].size
        << ",\"effect\":\""
        << effectName(proto.hasEffect(Address(space,probes[i].offset),probes[i].size))
        << "\"}";
  }
  out << ']';
}

void runFixture(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary,"default",&std::cerr);
  DocumentStorage documentStorage;
  architecture.init(documentStorage);

  Datatype *voidType = architecture.types->getTypeVoid();
  if (voidType == (Datatype *)0)
    throw std::runtime_error("architecture has no void type");

  const string modelXml =
    "<prototype name=\"fixture_model\" extrapop=\"16\" hasthis=\"true\" constructor=\"true\">"
    "<input/>"
    "<output killedbycall=\"true\"/>"
    "<unaffected><addr space=\"ram\" offset=\"0\" size=\"0\"/>"
    "<addr space=\"register\" offset=\"16\" size=\"8\"/></unaffected>"
    "<killedbycall><addr space=\"const\" offset=\"16\" size=\"8\"/>"
    "<addr space=\"register\" offset=\"32\" size=\"8\"/>"
    "<addr space=\"stack\" offset=\"16\" size=\"8\"/></killedbycall>"
    "<returnaddress><addr space=\"register\" offset=\"48\" size=\"8\"/></returnaddress>"
    "</prototype>";
  const string unknownModelXml =
    "<prototype name=\"fixture_unknown\" extrapop=\"unknown\">"
    "<input/><output/><returnaddress>"
    "<addr space=\"register\" offset=\"64\" size=\"8\"/>"
    "</returnaddress></prototype>";
  const string replacementModelXml =
    "<prototype name=\"fixture_replacement\" extrapop=\"24\">"
    "<input/><output/></prototype>";

  ProtoModel *model = new ProtoModel(&architecture);
  decodeModel(architecture,*model,modelXml);
  architecture.protoModels[model->getName()] = model;

  ProtoModel independentModel(&architecture);
  decodeModel(architecture,independentModel,modelXml);
  ProtoModel unknownModel(&architecture);
  decodeModel(architecture,unknownModel,unknownModelXml);
  ProtoModel replacementModel(&architecture);
  decodeModel(architecture,replacementModel,replacementModelXml);

  FuncProto modelProto;
  modelProto.setInternal(model,voidType);
  FuncProto modelCopy;
  modelCopy.copy(modelProto);
  FuncProto independentProto;
  independentProto.setInternal(&independentModel,voidType);

  const string overrideAXml =
    "<prototype model=\"fixture_model\" extrapop=\"16\">"
    "<returnsym><addr/><void/></returnsym>"
    "<killedbycall><addr space=\"register\" offset=\"16\" size=\"8\"/></killedbycall>"
    "</prototype>";
  const string overrideBXml =
    "<prototype model=\"fixture_model\" extrapop=\"16\">"
    "<returnsym><addr/><void/></returnsym>"
    "<unaffected><addr space=\"register\" offset=\"48\" size=\"8\"/></unaffected>"
    "</prototype>";
  FuncProto overrideA;
  decodeProto(architecture,model,voidType,overrideA,overrideAXml);
  FuncProto overrideACopy;
  overrideACopy.copy(overrideA);
  FuncProto overrideB;
  decodeProto(architecture,model,voidType,overrideB,overrideBXml);
  overrideA.copy(overrideB);

  AddrSpace *registerSpace = architecture.getSpaceByName("register");
  VarnodeData lookupStorage;
  lookupStorage.space = registerSpace;
  lookupStorage.offset = 0x10;
  lookupStorage.size = 8;
  vector<EffectRecord> lookupRecords;
  lookupRecords.push_back(EffectRecord(lookupStorage,EffectRecord::unaffected));
  int4 beforeFirstOverlap = ProtoModel::lookupRecord(
    lookupRecords,1,Address(registerSpace,0x08),16);
  int4 beforeFirstDisjoint = ProtoModel::lookupRecord(
    lookupRecords,1,Address(registerSpace,0x00),8);

  FuncProto sticky;
  sticky.setInternal(model,voidType);
  int4 initialExtraPop = sticky.getExtraPop();
  bool initialThis = sticky.hasThisPointer();
  bool initialConstructor = sticky.isConstructor();
  bool initialAutoKilled = sticky.isAutoKilledByCall();
  sticky.setModel(&unknownModel);
  int4 switchedExtraPop = sticky.getExtraPop();
  bool switchedThis = sticky.hasThisPointer();
  bool switchedConstructor = sticky.isConstructor();
  bool switchedAutoKilled = sticky.isAutoKilledByCall();
  sticky.setModel(&replacementModel);
  int4 replacedExtraPop = sticky.getExtraPop();
  bool replacedThis = sticky.hasThisPointer();
  bool replacedConstructor = sticky.isConstructor();
  bool replacedAutoKilled = sticky.isAutoKilledByCall();
  sticky.setModel((ProtoModel *)0);
  ostringstream nullModelPrint;
  sticky.printRaw("fixture",nullModelPrint);
  bool nullPrintHasNoModel =
    nullModelPrint.str().compare(0,11,"(no model) ") == 0;

  FuncProto outputLocked;
  outputLocked.setInternal((ProtoModel *)0,voidType);
  bool outputLockBefore = outputLocked.isAutoKilledByCall();
  outputLocked.setOutputLock(true);
  bool outputLockAfter = outputLocked.isAutoKilledByCall();

  FuncProto copyHintSource;
  copyHintSource.setInternal((ProtoModel *)0,voidType);
  copyHintSource.setReturnBytesConsumed(7);
  FuncProto copyHintDestination;
  copyHintDestination.setInternal((ProtoModel *)0,voidType);
  copyHintDestination.setReturnBytesConsumed(3);
  copyHintDestination.copy(copyHintSource);

  std::cout << "{\"schema\":1,\"fixture\":\"PROTO-EFFECT-MODEL-0001\""
            << ",\"model_effects\":";
  writeEffects(std::cout,modelProto,architecture);
  std::cout << ",\"effective_model_records\":";
  writeEffectiveRecords(std::cout,modelProto);
  std::cout << ",\"model_identity\":{\"copy\":"
            << modelCopy.hasMatchingModel(model)
            << ",\"independent_same_definition\":"
            << independentProto.hasMatchingModel(model)
            << "},\"override_a_copy\":";
  writeEffects(std::cout,overrideACopy,architecture);
  std::cout << ",\"effective_override_records\":";
  writeEffectiveRecords(std::cout,overrideACopy);
  std::cout << ",\"override_a_after_reassign\":";
  writeEffects(std::cout,overrideA,architecture);
  std::cout << ",\"lookup_record_before_first\":{\"overlap\":"
            << beforeFirstOverlap << ",\"disjoint\":" << beforeFirstDisjoint << '}';
  std::cout << ",\"set_model\":{\"initial\":{\"extrapop\":"
            << initialExtraPop << ",\"has_this\":" << initialThis
            << ",\"constructor\":" << initialConstructor
            << ",\"auto_killed\":" << initialAutoKilled
            << "},\"unknown_switch\":{\"extrapop\":" << switchedExtraPop
            << ",\"has_this\":" << switchedThis
            << ",\"constructor\":" << switchedConstructor
            << ",\"auto_killed\":" << switchedAutoKilled
            << "},\"known_switch\":{\"extrapop\":" << replacedExtraPop
            << ",\"has_this\":" << replacedThis
            << ",\"constructor\":" << replacedConstructor
            << ",\"auto_killed\":" << replacedAutoKilled
            << "},\"null_switch\":{\"has_model\":" << sticky.hasModel()
            << ",\"extrapop\":" << sticky.getExtraPop()
            << ",\"has_this\":" << sticky.hasThisPointer()
            << ",\"constructor\":" << sticky.isConstructor()
            << ",\"auto_killed\":" << sticky.isAutoKilledByCall()
            << ",\"print_has_no_model\":" << nullPrintHasNoModel
            << "}},\"output_lock_auto_killed\":{\"before\":" << outputLockBefore
            << ",\"after\":" << outputLockAfter
            << "},\"copy_preserves_destination_return_bytes\":"
            << copyHintDestination.getReturnBytesConsumed() << "}\n";
}

} // namespace

int main(int argc,char **argv)
{
  try {
    if (argc != 3)
      throw std::invalid_argument("usage: funcproto_effect_model_1204 SPEC_DIRECTORY BINARY");
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
