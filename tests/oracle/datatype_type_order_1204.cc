/*
 * DATATYPE-TYPEORDER-0001: locked Ghidra 12.0.4 Datatype ordering oracle.
 *
 * Raw pointer ordering is reduced to equality/non-equality plus antisymmetry,
 * never serialized.
 */
#include "bfd_arch.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "type.hh"
#include "xml.hh"

#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;

int4 signum(int4 value)
{
  if (value < 0) return -1;
  if (value > 0) return 1;
  return 0;
}

class ProbeBase : public TypeBase {
public:
  ProbeBase(int4 size,type_metatype meta,const string &name)
    : TypeBase(size,meta,name) {}
  void setCore(void) { flags |= coretype; }
};

class ProbePointer : public TypePointer {
public:
  ProbePointer(int4 size,Datatype *ptrTo,uint4 wordSize)
    : TypePointer(size,ptrTo,wordSize) {}
  void setId(uint8 value) { id = value; }
};

class ProbeStruct : public TypeStruct {
public:
  explicit ProbeStruct(const string &typeName)
    : TypeStruct() { name = typeName; displayName = typeName; }
  void define(const vector<TypeField> &fields,int4 fixedSize,int4 fixedAlign)
  {
    setFields(fields,fixedSize,fixedAlign);
    flags &= ~(uint4)type_incomplete;
  }
  void setId(uint8 value) { id = value; }
};

class ProbeEnum : public TypeEnum {
public:
  ProbeEnum(int4 size,type_metatype meta,const string &typeName)
    : TypeEnum(size,meta,typeName) {}
  void define(const map<uintb,string> &values) { namemap = values; }
};

class ProbeUnion : public TypeUnion {
public:
  explicit ProbeUnion(const string &typeName)
    : TypeUnion() { name = typeName; displayName = typeName; }
  void define(const vector<TypeField> &fields,int4 fixedSize,int4 fixedAlign)
  {
    setFields(fields,fixedSize,fixedAlign);
    flags &= ~(uint4)type_incomplete;
  }
};

class ProbeCode : public TypeCode {
public:
  void install(ProtoModel *model,Datatype *voidType,bool constructor,bool destructor)
  {
    proto = new FuncProto();
    proto->setInternal(model,voidType);
    proto->setConstructor(constructor);
    proto->setDestructor(destructor);
  }
};

void emitOrder(const string &key,const Datatype &left,const Datatype &right)
{
  std::cout << key << '=' << signum(left.typeOrder(right)) << '\n';
}

void emitBoolOrder(const string &key,const Datatype &left,const Datatype &right)
{
  std::cout << key << '=' << signum(left.typeOrderBool(right)) << '\n';
}

void decodeComparableModel(Architecture &architecture,ProtoModel &model,bool hasThis)
{
  string xml = "<prototype name=\"fixture_same\" extrapop=\"0\"";
  if (hasThis) xml += " hasthis=\"true\"";
  xml += "><input/><output/></prototype>";
  std::istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  model.decode(decoder);
}

void runFixture(Architecture &architecture)
{
  ProbeBase unknown4(4,TYPE_UNKNOWN,"unknown4");
  ProbeBase sint4(4,TYPE_INT,"int4");
  ProbeBase int4Alias(4,TYPE_INT,"different_name_same_shape");
  ProbeBase int8(8,TYPE_INT,"int8");
  ProbeBase uint4(4,TYPE_UINT,"uint4");
  ProbeBase bool1(1,TYPE_BOOL,"bool1");
  ProbeBase bool1Copy(1,TYPE_BOOL,"bool1_copy");

  ProbeStruct incompleteStruct("Incomplete");
  ProbeStruct oneFieldStruct("One");
  vector<TypeField> oneField;
  oneField.push_back(TypeField(0,0,"a",&sint4));
  oneFieldStruct.define(oneField,4,4);
  ProbeStruct twoFieldStruct("Two");
  vector<TypeField> twoFields;
  twoFields.push_back(TypeField(0,0,"a",&sint4));
  twoFields.push_back(TypeField(1,4,"b",&uint4));
  twoFieldStruct.define(twoFields,8,4);

  ProbePointer ptrUnknown(8,&unknown4,1);
  ProbePointer ptrInt(8,&sint4,1);
  ProbePointer ptrIncomplete(8,&incompleteStruct,1);
  ProbePointer ptrOneField(8,&oneFieldStruct,1);
  ProbePointer ptrTwoField(8,&twoFieldStruct,1);

  std::cout << "identity.same=" << signum(sint4.typeOrder(sint4)) << '\n';
  std::cout << "submeta.unknown=" << static_cast<int4>(unknown4.getSubMeta()) << '\n';
  std::cout << "submeta.int=" << static_cast<int4>(sint4.getSubMeta()) << '\n';
  std::cout << "submeta.uint=" << static_cast<int4>(uint4.getSubMeta()) << '\n';
  std::cout << "submeta.bool=" << static_cast<int4>(bool1.getSubMeta()) << '\n';
  std::cout << "submeta.ptr_unknown=" << static_cast<int4>(ptrUnknown.getSubMeta()) << '\n';
  std::cout << "submeta.ptr_incomplete_struct=" << static_cast<int4>(ptrIncomplete.getSubMeta()) << '\n';
  std::cout << "submeta.ptr_one_field_struct=" << static_cast<int4>(ptrOneField.getSubMeta()) << '\n';
  std::cout << "submeta.ptr_one_field_needs_resolution="
            << ptrOneField.needsResolution() << '\n';
  std::cout << "submeta.ptr_two_field_struct=" << static_cast<int4>(ptrTwoField.getSubMeta()) << '\n';

  emitOrder("order.ptr_unknown",ptrUnknown,unknown4);
  emitOrder("order.int_unknown",sint4,unknown4);
  emitOrder("order.uint_unknown",uint4,unknown4);
  emitOrder("order.bool_unknown",bool1,unknown4);
  emitOrder("order.int_uint",sint4,uint4);
  emitOrder("order.int4_int8",sint4,int8);
  emitOrder("order.name_ignored",sint4,int4Alias);
  emitBoolOrder("bool_order.bool_int",bool1,sint4);
  emitBoolOrder("bool_order.int_bool",sint4,bool1);
  emitBoolOrder("bool_order.distinct_bool",bool1,bool1Copy);
  emitBoolOrder("bool_order.same_bool",bool1,bool1);

  emitOrder("recursive.ptr_int_uint",ptrInt,ProbePointer(8,&uint4,1));
  ProbePointer cutoffLeft(8,&sint4,1);
  ProbePointer cutoffRight(8,&uint4,1);
  cutoffLeft.setId(7);
  cutoffRight.setId(9);
  std::cout << "recursive.level0_id="
            << signum(cutoffLeft.compare(cutoffRight,0)) << '\n';
  std::cout << "recursive.level1_target="
            << signum(cutoffLeft.compare(cutoffRight,1)) << '\n';

  ProbeStruct structOne("S1");
  structOne.define(oneField,8,4);
  ProbeStruct structTwo("S2");
  structTwo.define(twoFields,8,4);
  std::cout << "tie.struct_more_fields="
            << signum(structTwo.compare(structOne,10)) << '\n';
  vector<TypeField> nameB;
  nameB.push_back(TypeField(0,0,"b",&sint4));
  ProbeStruct structNameB("S3");
  structNameB.define(nameB,8,4);
  std::cout << "tie.struct_field_name="
            << signum(structOne.compare(structNameB,10)) << '\n';
  vector<TypeField> unknownField;
  unknownField.push_back(TypeField(0,0,"a",&unknown4));
  ProbeStruct structUnknown("S4");
  structUnknown.define(unknownField,8,4);
  std::cout << "tie.struct_field_metatype="
            << signum(structOne.compare(structUnknown,10)) << '\n';

  ProbeEnum enumA(4,TYPE_ENUM_INT,"EA");
  ProbeEnum enumB(4,TYPE_ENUM_INT,"EB");
  map<uintb,string> valuesA;
  valuesA[1] = "A";
  map<uintb,string> valuesB;
  valuesB[2] = "A";
  enumA.define(valuesA);
  enumB.define(valuesB);
  std::cout << "tie.enum_value=" << signum(enumA.compare(enumB,10)) << '\n';

  ProbePointer depSameA(8,&sint4,1);
  ProbePointer depSameB(8,&sint4,1);
  ProbeBase int4Copy(4,TYPE_INT,"int4_copy");
  ProbePointer depDistinct(8,&int4Copy,1);
  int4 depForward = depSameA.compareDependency(depDistinct);
  int4 depReverse = depDistinct.compareDependency(depSameA);
  std::cout << "dependency.same_target="
            << signum(depSameA.compareDependency(depSameB)) << '\n';
  std::cout << "dependency.distinct_target_nonzero=" << (depForward != 0) << '\n';
  std::cout << "dependency.distinct_target_antisymmetric="
            << (signum(depForward) == -signum(depReverse)) << '\n';

  Datatype &basePtrInt = ptrInt;
  ProbePointer ptrUint(8,&uint4,1);
  Datatype &basePtrUint = ptrUint;
  std::cout << "base_api.compare_pointer="
            << signum(basePtrInt.compare(basePtrUint,10)) << '\n';
  Datatype &baseDepDistinct = depDistinct;
  int4 baseDepForward = basePtrInt.compareDependency(baseDepDistinct);
  int4 baseDepReverse = baseDepDistinct.compareDependency(basePtrInt);
  std::cout << "base_api.dependency_pointer_nonzero="
            << (baseDepForward != 0) << '\n';
  std::cout << "base_api.dependency_pointer_antisymmetric="
            << (signum(baseDepForward) == -signum(baseDepReverse)) << '\n';

  TypeArray arrayOne(1,&sint4);
  TypePointer arrayPointer(8,&arrayOne,1);
  std::cout << "pointer_state.array_flag=" << arrayPointer.isPointerToArray() << '\n';
  std::cout << "pointer_state.array_needs_resolution="
            << arrayPointer.needsResolution() << '\n';
  ProbeUnion unionType("U");
  unionType.define(oneField,4,4);
  TypePointer unionPointer(8,&unionType,1);
  std::cout << "pointer_state.union_submeta="
            << static_cast<int4>(unionPointer.getSubMeta()) << '\n';
  std::cout << "pointer_state.union_needs_resolution="
            << unionPointer.needsResolution() << '\n';
  TypePointer pointerToUnionPointer(8,&unionPointer,1);
  std::cout << "pointer_state.pointer_needs_resolution="
            << pointerToUnionPointer.needsResolution() << '\n';
  ProbeBase coreInt(4,TYPE_INT,"core_int");
  coreInt.setCore();
  TypePointer corePointer(8,&coreInt,1);
  std::cout << "pointer_state.core_inherited=" << corePointer.isCoreType() << '\n';

  AddrSpace *ram = architecture.getDefaultDataSpace();
  AddrSpace *reg = architecture.getSpaceByName("register");
  if (ram == (AddrSpace *)0 || reg == (AddrSpace *)0)
    throw std::runtime_error("fixture address spaces unavailable");
  ProbePointer pointerNoSpace(ram->getAddrSize(),&sint4,ram->getWordSize());
  TypePointer pointerRam(&sint4,ram);
  TypePointer pointerRegister(&sint4,reg);
  std::cout << "pointer_space.present_before_none="
            << signum(pointerRam.compare(pointerNoSpace,10)) << '\n';
  std::cout << "pointer_space.ram_before_register="
            << signum(pointerRam.compare(pointerRegister,10)) << '\n';
  std::cout << "pointer_space.dependency_ranking="
            << signum(pointerRam.compareDependency(pointerRegister)) << '\n';

  TypePointerRel formalRel(8,&unknown4,1,&oneFieldStruct,4);
  TypePointer parentPointer(8,&oneFieldStruct,1);
  TypePointerRel *ephemeralRel = architecture.types->getTypePointerRel(
      &parentPointer,&unknown4,4);
  std::cout << "pointer_rel.formal_submeta="
            << static_cast<int4>(formalRel.getSubMeta()) << '\n';
  std::cout << "pointer_rel.ephemeral_submeta="
            << static_cast<int4>(ephemeralRel->getSubMeta()) << '\n';
  std::cout << "pointer_rel.formal_has_stripped=" << formalRel.hasStripped() << '\n';
  std::cout << "pointer_rel.ephemeral_has_stripped="
            << ephemeralRel->hasStripped() << '\n';
  std::cout << "pointer_rel.parent_identity="
            << (formalRel.getParent() == &oneFieldStruct) << '\n';
  std::cout << "pointer_rel.parent_name=" << formalRel.getParent()->getName() << '\n';
  std::cout << "pointer_rel.parent_size=" << formalRel.getParent()->getSize() << '\n';
  std::cout << "pointer_rel.parent_needs_resolution="
            << formalRel.getParent()->needsResolution() << '\n';
  std::cout << "pointer_rel.byte_offset=" << formalRel.getByteOffset() << '\n';
  std::cout << "pointer_rel.stripped_identity="
            << (ephemeralRel->getStripped() != (Datatype *)0) << '\n';
  std::cout << "pointer_rel.formal_before_ephemeral="
            << signum(formalRel.compare(*ephemeralRel,10)) << '\n';
  TypePointerRel formalIntRel(8,&sint4,1,&oneFieldStruct,4);
  TypePointerRel *ephemeralIntRel = architecture.types->getTypePointerRel(
      &parentPointer,&sint4,4);
  std::cout << "pointer_rel.stripped_tie="
            << signum(formalIntRel.compare(*ephemeralIntRel,10)) << '\n';
  TypePointerRel relOffsetEight(8,&unknown4,1,&oneFieldStruct,8);
  std::cout << "pointer_rel.dependency_offset="
            << signum(formalRel.compareDependency(relOffsetEight)) << '\n';
  ProbeStruct otherRelParent("OtherRelParent");
  otherRelParent.define(oneField,4,4);
  TypePointerRel relOtherParent(8,&unknown4,1,&otherRelParent,4);
  int4 relParentForward = formalRel.compareDependency(relOtherParent);
  int4 relParentReverse = relOtherParent.compareDependency(formalRel);
  std::cout << "pointer_rel.dependency_parent_nonzero="
            << (relParentForward != 0) << '\n';
  std::cout << "pointer_rel.dependency_parent_antisymmetric="
            << (signum(relParentForward) == -signum(relParentReverse)) << '\n';

  TypeUnicode unicode1("unicode1",1,TYPE_INT);
  TypeChar char1("char1");
  std::cout << "unicode.direct_submeta="
            << static_cast<int4>(unicode1.getSubMeta()) << '\n';
  std::cout << "unicode.char_submeta="
            << static_cast<int4>(char1.getSubMeta()) << '\n';
  std::cout << "unicode.before_char="
            << signum(unicode1.typeOrder(char1)) << '\n';

  ProtoModel samePlainModel(&architecture);
  ProtoModel sameThisModel(&architecture);
  decodeComparableModel(architecture,samePlainModel,false);
  decodeComparableModel(architecture,sameThisModel,true);
  ProbeCode codePlain;
  ProbeCode codeConstructor;
  ProbeCode codeDestructor;
  ProbeCode codeSamePlain;
  ProbeCode codeSameThis;
  ProbeCode codeNoModel;
  codePlain.install(architecture.defaultfp,architecture.types->getTypeVoid(),false,false);
  codeConstructor.install(architecture.defaultfp,architecture.types->getTypeVoid(),true,false);
  codeDestructor.install(architecture.defaultfp,architecture.types->getTypeVoid(),false,true);
  codeSamePlain.install(&samePlainModel,architecture.types->getTypeVoid(),false,false);
  codeSameThis.install(&sameThisModel,architecture.types->getTypeVoid(),false,false);
  codeNoModel.install((ProtoModel *)0,architecture.types->getTypeVoid(),false,false);
  Datatype &baseCodePlain = codePlain;
  Datatype &baseCodeConstructor = codeConstructor;
  Datatype &baseCodeDestructor = codeDestructor;
  Datatype &baseCodeSamePlain = codeSamePlain;
  Datatype &baseCodeSameThis = codeSameThis;
  Datatype &baseCodeNoModel = codeNoModel;
  std::cout << "code_model.absent_after_present="
            << signum(baseCodeNoModel.compare(baseCodePlain,10)) << '\n';
  std::cout << "code_flags.plain_constructor="
            << signum(baseCodePlain.compare(baseCodeConstructor,10)) << '\n';
  std::cout << "code_flags.constructor_destructor="
            << signum(baseCodeConstructor.compare(baseCodeDestructor,10)) << '\n';
  std::cout << "code_flags.same_model_name="
            << (codeSamePlain.getPrototype()->getModelName() ==
                codeSameThis.getPrototype()->getModelName()) << '\n';
  std::cout << "code_flags.plain_this="
            << signum(baseCodeSamePlain.compare(baseCodeSameThis,10)) << '\n';

  Address invalidFrame;
  Address validZero(architecture.getDefaultCodeSpace(),0);
  Address validOne(architecture.getDefaultCodeSpace(),1);
  TypeSpacebase spacebaseInvalid(ram,invalidFrame,&architecture);
  TypeSpacebase spacebaseValidZero(ram,validZero,&architecture);
  TypeSpacebase spacebaseRegister(reg,validZero,&architecture);
  TypeSpacebase spacebaseValidOne(ram,validOne,&architecture);
  std::cout << "spacebase.invalid_spaceless="
            << invalidFrame.isInvalid() << '\n';
  std::cout << "spacebase.valid_zero=" << (!validZero.isInvalid()) << '\n';
  int4 spaceForward = spacebaseValidZero.compareDependency(spacebaseRegister);
  int4 spaceReverse = spacebaseRegister.compareDependency(spacebaseValidZero);
  std::cout << "spacebase.space_identity_nonzero=" << (spaceForward != 0) << '\n';
  std::cout << "spacebase.space_identity_antisymmetric="
            << (signum(spaceForward) == -signum(spaceReverse)) << '\n';
  std::cout << "spacebase.localframe_order="
            << signum(spacebaseValidZero.compareDependency(spacebaseValidOne)) << '\n';
  std::cout << "spacebase.global_shortcut="
            << signum(spacebaseInvalid.compareDependency(spacebaseValidZero)) << '\n';

  Datatype *factoryInt = architecture.types->getBase(4,TYPE_INT);
  TypePointer *factoryPlainPointer = architecture.types->getTypePointer(4,factoryInt,2);
  std::cout << "factory_gap.ordinary_pointer_is_ptrrel="
            << factoryPlainPointer->isPointerRel() << '\n';
  TypePointer parentFactoryPointer(8,&oneFieldStruct,1);
  Datatype *factoryUnknown = architecture.types->getBase(4,TYPE_UNKNOWN);
  TypePointerRel *factoryRel = architecture.types->getTypePointerRel(
      &parentFactoryPointer,factoryUnknown,4);
  std::cout << "factory_gap.ephemeral_rel_has_stripped="
            << factoryRel->hasStripped() << '\n';
  std::cout << "factory_gap.ephemeral_rel_submeta="
            << static_cast<int4>(factoryRel->getSubMeta()) << '\n';
  TypeArray *factoryArray = architecture.types->getTypeArray(1,factoryInt);
  TypePointer *factoryArrayPointer = architecture.types->getTypePointer(
      8,factoryArray,1);
  std::cout << "factory_gap.array_pointer_flag="
            << factoryArrayPointer->isPointerToArray() << '\n';
  TypePointer *factoryCorePointer = architecture.types->getTypePointer(
      8,factoryInt,1);
  std::cout << "factory_gap.core_pointer_inherited="
            << factoryCorePointer->isCoreType() << '\n';
  std::cout << "factory_gap.unicode1_submeta="
            << static_cast<int4>(unicode1.getSubMeta()) << '\n';
}

} // namespace

int main(int argc,char **argv)
{
  try {
    if (argc != 3)
      throw std::invalid_argument(
          "usage: datatype_type_order_1204 SPEC_DIRECTORY BINARY");
    vector<string> specPaths;
    specPaths.push_back(argv[1]);
    startDecompilerLibrary(specPaths);
    {
      BfdArchitecture architecture(argv[2],"default",&std::cerr);
      DocumentStorage store;
      architecture.init(store);
      runFixture(architecture);
    }
    shutdownDecompilerLibrary();
    return 0;
  }
  catch(const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
  }
  catch(const std::exception &err) {
    std::cerr << "std::exception: " << err.what() << '\n';
  }
  return 1;
}
