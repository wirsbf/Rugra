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
#include <cstdio>
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
  void setId(uint8 value) { id = value; }
};

class ProbeArray : public TypeArray {
public:
  ProbeArray(int4 numElements,Datatype *element)
    : TypeArray(numElements,element) {}
  void setId(uint8 value) { id = value; }
};

class ProbePartialStruct : public TypePartialStruct {
public:
  ProbePartialStruct(Datatype *contain,int4 off,int4 sz,Datatype *strip)
    : TypePartialStruct(contain,off,sz,strip) {}
  void setId(uint8 value) { id = value; }
};

class ProbePartialEnum : public TypePartialEnum {
public:
  ProbePartialEnum(TypeEnum *par,int4 off,int4 sz,Datatype *strip)
    : TypePartialEnum(par,off,sz,strip) {}
  void setId(uint8 value) { id = value; }
};

class ProbePartialUnion : public TypePartialUnion {
public:
  ProbePartialUnion(TypeUnion *contain,int4 off,int4 sz,Datatype *strip)
    : TypePartialUnion(contain,off,sz,strip) {}
  void setId(uint8 value) { id = value; }
};

// Mirrors TypeChar::decode (type.cc:818) for the unsigned 1-byte character
// form, which has no direct public constructor.
class ProbeChar : public TypeChar {
public:
  ProbeChar(const string &name,type_metatype meta)
    : TypeChar(name)
  {
    metatype = meta;
    submeta = (metatype == TYPE_INT) ? SUB_INT_CHAR : SUB_UINT_CHAR;
  }
};

// Exposes the protected TypePointerRel::markEphemeral for the SUB_PTRREL_UNK
// construction-time state write.
class ProbeRel : public TypePointerRel {
public:
  ProbeRel(int4 sz,Datatype *pt,uint4 ws,Datatype *par,int4 off)
    : TypePointerRel(sz,pt,ws,par,off) {}
  void callMarkEphemeral(TypeFactory &typegrp) { markEphemeral(typegrp); }
};

class ProbePointerSpace : public TypePointer {
public:
  ProbePointerSpace(int4 sz,Datatype *pt,uint4 ws)
    : TypePointer(sz,pt,ws) {}
  void setSpace(AddrSpace *space) { spaceid = space; }
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
  void installPieces(ProtoModel *model,Datatype *voidType,Datatype *outType,
                     const vector<Datatype *> &inTypes,int4 firstVarArgSlot)
  {
    proto = new FuncProto();
    proto->setInternal(model,voidType);
    PrototypePieces pieces;
    pieces.model = model;
    pieces.outtype = outType;
    pieces.intypes = inTypes;
    pieces.firstVarArgSlot = firstVarArgSlot;
    proto->updateAllTypes(pieces);
  }
  void setId(uint8 value) { id = value; }
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

void decodeNamedModel(Architecture &architecture,ProtoModel &model,
                      const string &name)
{
  string xml = "<prototype name=\"" + name + "\" extrapop=\"0\"";
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

  // TypeCode varargs / model-name / parameter-count / parameter-type /
  // return-type / level-id residual matrix.
  Datatype *voidType = architecture.types->getTypeVoid();
  vector<Datatype *> noTypes;
  vector<Datatype *> oneIntType;
  oneIntType.push_back(&sint4);
  vector<Datatype *> oneUintType;
  oneUintType.push_back(&uint4);
  vector<Datatype *> oneIntCopyType;
  ProbeBase intParamCopy(4,TYPE_INT,"int_param_copy");
  oneIntCopyType.push_back(&intParamCopy);
  ProbeCode codeParamPlain;
  codeParamPlain.installPieces(architecture.defaultfp,voidType,voidType,
                               oneIntType,-1);
  ProbeCode codeParamVarargs;
  codeParamVarargs.installPieces(architecture.defaultfp,voidType,voidType,
                                 oneIntType,0);
  ProbeCode codeParamNone;
  codeParamNone.installPieces(architecture.defaultfp,voidType,voidType,
                              noTypes,-1);
  ProbeCode codeParamUint;
  codeParamUint.installPieces(architecture.defaultfp,voidType,voidType,
                              oneUintType,-1);
  ProbeCode codeReturnInt;
  codeReturnInt.installPieces(architecture.defaultfp,voidType,&int8,
                              oneIntType,-1);
  std::cout << "code2.varargs_plain_first="
            << signum(codeParamPlain.compare(codeParamVarargs,10)) << '\n';
  std::cout << "code2.param_count_zero_vs_one="
            << signum(codeParamNone.compare(codeParamPlain,10)) << '\n';
  std::cout << "code2.param_count_one_vs_zero="
            << signum(codeParamPlain.compare(codeParamNone,10)) << '\n';
  std::cout << "code2.param_type_recursion="
            << signum(codeParamPlain.compare(codeParamUint,10)) << '\n';
  std::cout << "code2.return_type_recursion="
            << signum(codeParamPlain.compare(codeReturnInt,10)) << '\n';
  ProtoModel modelFixtureA(&architecture);
  ProtoModel modelFixtureB(&architecture);
  decodeNamedModel(architecture,modelFixtureA,"fixture_a");
  decodeNamedModel(architecture,modelFixtureB,"fixture_b");
  ProbeCode codeModelA;
  ProbeCode codeModelB;
  codeModelA.install(&modelFixtureA,voidType,false,false);
  codeModelB.install(&modelFixtureB,voidType,false,false);
  std::cout << "code2.model_name_differs="
            << signum(codeModelA.compare(codeModelB,10)) << '\n';
  ProbeCode codeIdLow;
  ProbeCode codeIdHigh;
  codeIdLow.installPieces(architecture.defaultfp,voidType,voidType,
                          oneIntType,-1);
  codeIdHigh.installPieces(architecture.defaultfp,voidType,voidType,
                           oneIntType,-1);
  codeIdLow.setId(5);
  codeIdHigh.setId(9);
  std::cout << "code2.level0_id="
            << signum(codeIdLow.compare(codeIdHigh,0)) << '\n';
  ProbeCode codeDepParamA;
  ProbeCode codeDepParamB;
  codeDepParamA.installPieces(architecture.defaultfp,voidType,voidType,
                              oneIntType,-1);
  codeDepParamB.installPieces(architecture.defaultfp,voidType,voidType,
                              oneIntCopyType,-1);
  int4 codeParamDepForward = codeDepParamA.compareDependency(codeDepParamB);
  int4 codeParamDepReverse = codeDepParamB.compareDependency(codeDepParamA);
  std::cout << "code2.deep_equal_distinct_params="
            << signum(codeDepParamA.compare(codeDepParamB,10)) << '\n';
  std::cout << "code2.dependency_distinct_param_nonzero="
            << (codeParamDepForward != 0) << '\n';
  std::cout << "code2.dependency_distinct_param_antisymmetric="
            << (signum(codeParamDepForward) == -signum(codeParamDepReverse))
            << '\n';
  TypeVoid voidOutA;
  TypeVoid voidOutB;
  ProbeCode codeDepOutA;
  ProbeCode codeDepOutB;
  codeDepOutA.installPieces(architecture.defaultfp,voidType,&voidOutA,
                            oneIntType,-1);
  codeDepOutB.installPieces(architecture.defaultfp,voidType,&voidOutB,
                            oneIntType,-1);
  int4 codeOutDepForward = codeDepOutA.compareDependency(codeDepOutB);
  int4 codeOutDepReverse = codeDepOutB.compareDependency(codeDepOutA);
  std::cout << "code2.deep_equal_distinct_output="
            << signum(codeDepOutA.compare(codeDepOutB,10)) << '\n';
  std::cout << "code2.dependency_distinct_output_nonzero="
            << (codeOutDepForward != 0) << '\n';
  std::cout << "code2.dependency_distinct_output_antisymmetric="
            << (signum(codeOutDepForward) == -signum(codeOutDepReverse))
            << '\n';

  // Array / Union / Partial compare and dependency matrices.
  ProbeArray arrayIntOne(1,&sint4);
  ProbeArray arrayIntTwo(2,&sint4);
  ProbeArray arrayUintOne(1,&uint4);
  ProbeBase arrayElemCopy(4,TYPE_INT,"array_elem_copy");
  ProbeArray arrayIntCopyOne(1,&arrayElemCopy);
  std::cout << "array2.compare_elem_differs="
            << signum(arrayIntOne.compare(arrayUintOne,10)) << '\n';
  std::cout << "array2.compare_size="
            << signum(arrayIntTwo.compare(arrayIntOne,10)) << '\n';
  ProbeArray arrayIdLow(1,&sint4);
  ProbeArray arrayIdHigh(1,&sint4);
  arrayIdLow.setId(5);
  arrayIdHigh.setId(9);
  std::cout << "array2.compare_level0_id="
            << signum(arrayIdLow.compare(arrayIdHigh,0)) << '\n';
  std::cout << "array2.dependency_size="
            << signum(arrayIntOne.compareDependency(arrayIntTwo)) << '\n';
  int4 arrayDepForward = arrayIntOne.compareDependency(arrayIntCopyOne);
  int4 arrayDepReverse = arrayIntCopyOne.compareDependency(arrayIntOne);
  std::cout << "array2.dependency_distinct_elem_nonzero="
            << (arrayDepForward != 0) << '\n';
  std::cout << "array2.dependency_distinct_elem_antisymmetric="
            << (signum(arrayDepForward) == -signum(arrayDepReverse)) << '\n';

  vector<TypeField> unionFieldA;
  unionFieldA.push_back(TypeField(0,0,"a",&sint4));
  vector<TypeField> unionFieldB;
  unionFieldB.push_back(TypeField(0,0,"b",&sint4));
  vector<TypeField> unionFieldUint;
  unionFieldUint.push_back(TypeField(0,0,"a",&uint4));
  ProbeUnion unionNameA("UA");
  unionNameA.define(unionFieldA,4,4);
  ProbeUnion unionNameB("UB");
  unionNameB.define(unionFieldB,4,4);
  ProbeUnion unionUint("UU");
  unionUint.define(unionFieldUint,4,4);
  ProbeUnion unionIdLow("UI");
  unionIdLow.define(unionFieldA,4,4);
  ProbeUnion unionIdHigh("UI2");
  unionIdHigh.define(unionFieldA,4,4);
  unionIdLow.setId(5);
  unionIdHigh.setId(9);
  vector<TypeField> unionFieldIntCopy;
  unionFieldIntCopy.push_back(TypeField(0,0,"a",&intParamCopy));
  ProbeUnion unionFieldCopy("UC");
  unionFieldCopy.define(unionFieldIntCopy,4,4);
  std::cout << "union2.compare_field_name="
            << signum(unionNameA.compare(unionNameB,10)) << '\n';
  std::cout << "union2.compare_field_metatype="
            << signum(unionNameA.compare(unionUint,10)) << '\n';
  std::cout << "union2.compare_level0_id="
            << signum(unionIdLow.compare(unionIdHigh,0)) << '\n';
  int4 unionDepForward = unionNameA.compareDependency(unionFieldCopy);
  int4 unionDepReverse = unionFieldCopy.compareDependency(unionNameA);
  std::cout << "union2.dependency_distinct_field_nonzero="
            << (unionDepForward != 0) << '\n';
  std::cout << "union2.dependency_distinct_field_antisymmetric="
            << (signum(unionDepForward) == -signum(unionDepReverse)) << '\n';

  vector<TypeField> offsetFieldZero;
  offsetFieldZero.push_back(TypeField(0,0,"a",&sint4));
  vector<TypeField> offsetFieldTwo;
  offsetFieldTwo.push_back(TypeField(0,2,"a",&sint4));
  ProbeStruct structOffsetZero("SO0");
  structOffsetZero.define(offsetFieldZero,8,4);
  ProbeStruct structOffsetTwo("SO2");
  structOffsetTwo.define(offsetFieldTwo,8,4);
  std::cout << "struct2.compare_field_offset="
            << signum(structOffsetZero.compare(structOffsetTwo,10)) << '\n';
  vector<TypeField> pointerFieldInt;
  pointerFieldInt.push_back(TypeField(0,0,"p",&ptrInt));
  vector<TypeField> pointerFieldUint;
  pointerFieldUint.push_back(TypeField(0,0,"p",&ptrUint));
  ProbeStruct structPtrFieldInt("SP1");
  structPtrFieldInt.define(pointerFieldInt,8,8);
  ProbeStruct structPtrFieldUint("SP2");
  structPtrFieldUint.define(pointerFieldUint,8,8);
  std::cout << "struct2.compare_deep_pointer_field="
            << signum(structPtrFieldInt.compare(structPtrFieldUint,10))
            << '\n';
  ProbeStruct structIdLow("SI");
  structIdLow.define(offsetFieldZero,8,4);
  ProbeStruct structIdHigh("SI2");
  structIdHigh.define(offsetFieldZero,8,4);
  structIdLow.setId(5);
  structIdHigh.setId(9);
  std::cout << "struct2.compare_level0_id="
            << signum(structIdLow.compare(structIdHigh,0)) << '\n';
  vector<TypeField> dependencyOffsetFour;
  dependencyOffsetFour.push_back(TypeField(0,4,"a",&sint4));
  ProbeStruct structDepOffsetFour("SD4");
  structDepOffsetFour.define(dependencyOffsetFour,8,4);
  std::cout << "struct2.dependency_field_offset="
            << signum(structOffsetZero.compareDependency(structDepOffsetFour))
            << '\n';
  vector<TypeField> structFieldCopyVector;
  structFieldCopyVector.push_back(TypeField(0,0,"a",&intParamCopy));
  ProbeStruct structFieldCopy("SC");
  structFieldCopy.define(structFieldCopyVector,8,4);
  int4 structDepForward = structOffsetZero.compareDependency(structFieldCopy);
  int4 structDepReverse = structFieldCopy.compareDependency(structOffsetZero);
  std::cout << "struct2.dependency_distinct_field_nonzero="
            << (structDepForward != 0) << '\n';
  std::cout << "struct2.dependency_distinct_field_antisymmetric="
            << (signum(structDepForward) == -signum(structDepReverse))
            << '\n';

  ProbePartialStruct partialOffsetZero(&structOne,0,4,&unknown4);
  ProbePartialStruct partialOffsetFour(&structOne,4,4,&unknown4);
  std::cout << "partialstruct2.compare_offset="
            << signum(partialOffsetZero.compare(partialOffsetFour,10))
            << '\n';
  ProbePartialStruct partialContainerOne(&structOne,0,4,&unknown4);
  ProbePartialStruct partialContainerTwo(&structTwo,0,4,&unknown4);
  std::cout << "partialstruct2.compare_container="
            << signum(partialContainerOne.compare(partialContainerTwo,10))
            << '\n';
  ProbePartialStruct partialIdLow(&structOne,0,4,&unknown4);
  ProbePartialStruct partialIdHigh(&structOne,0,4,&unknown4);
  partialIdLow.setId(5);
  partialIdHigh.setId(9);
  std::cout << "partialstruct2.compare_level0_id="
            << signum(partialIdLow.compare(partialIdHigh,0)) << '\n';
  std::cout << "partialstruct2.dependency_same_container="
            << signum(partialOffsetZero.compareDependency(
                partialContainerOne)) << '\n';
  std::cout << "partialstruct2.dependency_offset="
            << signum(partialOffsetZero.compareDependency(partialOffsetFour))
            << '\n';
  ProbeStruct structOneCopy("S1copy");
  structOneCopy.define(oneField,4,4);
  ProbePartialStruct partialContainerCopy(&structOneCopy,0,4,&unknown4);
  int4 partialStructDepForward =
      partialOffsetZero.compareDependency(partialContainerCopy);
  int4 partialStructDepReverse =
      partialContainerCopy.compareDependency(partialOffsetZero);
  std::cout << "partialstruct2.dependency_distinct_container_nonzero="
            << (partialStructDepForward != 0) << '\n';
  std::cout << "partialstruct2.dependency_distinct_container_antisymmetric="
            << (signum(partialStructDepForward) ==
                -signum(partialStructDepReverse)) << '\n';

  ProbePartialEnum partialEnumOffsetZero(&enumA,0,1,&unknown4);
  ProbePartialEnum partialEnumOffsetOne(&enumA,1,1,&unknown4);
  std::cout << "partialenum2.compare_offset="
            << signum(partialEnumOffsetZero.compare(partialEnumOffsetOne,10))
            << '\n';
  ProbePartialEnum partialEnumParentB(&enumB,0,1,&unknown4);
  std::cout << "partialenum2.compare_parent="
            << signum(partialEnumOffsetZero.compare(partialEnumParentB,10))
            << '\n';
  ProbePartialEnum partialEnumIdLow(&enumA,0,1,&unknown4);
  ProbePartialEnum partialEnumIdHigh(&enumA,0,1,&unknown4);
  partialEnumIdLow.setId(5);
  partialEnumIdHigh.setId(9);
  std::cout << "partialenum2.compare_level0_id="
            << signum(partialEnumIdLow.compare(partialEnumIdHigh,0)) << '\n';
  std::cout << "partialenum2.dependency_same_parent="
            << signum(partialEnumOffsetZero.compareDependency(
                partialEnumIdLow)) << '\n';
  std::cout << "partialenum2.dependency_offset="
            << signum(partialEnumOffsetZero.compareDependency(
                partialEnumOffsetOne)) << '\n';
  ProbeEnum enumACopy(4,TYPE_ENUM_INT,"EAC");
  enumACopy.define(valuesA);
  ProbePartialEnum partialEnumParentCopy(&enumACopy,0,1,&unknown4);
  int4 partialEnumDepForward =
      partialEnumOffsetZero.compareDependency(partialEnumParentCopy);
  int4 partialEnumDepReverse =
      partialEnumParentCopy.compareDependency(partialEnumOffsetZero);
  std::cout << "partialenum2.dependency_distinct_parent_nonzero="
            << (partialEnumDepForward != 0) << '\n';
  std::cout << "partialenum2.dependency_distinct_parent_antisymmetric="
            << (signum(partialEnumDepForward) ==
                -signum(partialEnumDepReverse)) << '\n';

  vector<TypeField> unionTwoFieldVector;
  unionTwoFieldVector.push_back(TypeField(0,0,"a",&sint4));
  unionTwoFieldVector.push_back(TypeField(1,0,"b",&uint4));
  ProbeUnion unionTwoFields("U2F");
  unionTwoFields.define(unionTwoFieldVector,4,4);
  ProbePartialUnion partialUnionOffsetZero(&unionType,0,4,&unknown4);
  ProbePartialUnion partialUnionOffsetFour(&unionType,4,4,&unknown4);
  std::cout << "partialunion2.compare_offset="
            << signum(partialUnionOffsetZero.compare(partialUnionOffsetFour,10))
            << '\n';
  ProbePartialUnion partialUnionContainerTwo(&unionTwoFields,0,4,&unknown4);
  std::cout << "partialunion2.compare_container="
            << signum(partialUnionOffsetZero.compare(
                partialUnionContainerTwo,10)) << '\n';
  ProbePartialUnion partialUnionIdLow(&unionType,0,4,&unknown4);
  ProbePartialUnion partialUnionIdHigh(&unionType,0,4,&unknown4);
  partialUnionIdLow.setId(5);
  partialUnionIdHigh.setId(9);
  std::cout << "partialunion2.compare_level0_id="
            << signum(partialUnionIdLow.compare(partialUnionIdHigh,0))
            << '\n';
  std::cout << "partialunion2.dependency_same_container="
            << signum(partialUnionOffsetZero.compareDependency(
                partialUnionIdLow)) << '\n';
  std::cout << "partialunion2.dependency_offset="
            << signum(partialUnionOffsetZero.compareDependency(
                partialUnionOffsetFour)) << '\n';
  ProbeUnion unionTypeCopy("Ucopy");
  unionTypeCopy.define(oneField,4,4);
  ProbePartialUnion partialUnionContainerCopy(&unionTypeCopy,0,4,&unknown4);
  int4 partialUnionDepForward =
      partialUnionOffsetZero.compareDependency(partialUnionContainerCopy);
  int4 partialUnionDepReverse =
      partialUnionContainerCopy.compareDependency(partialUnionOffsetZero);
  std::cout << "partialunion2.dependency_distinct_container_nonzero="
            << (partialUnionDepForward != 0) << '\n';
  std::cout << "partialunion2.dependency_distinct_container_antisymmetric="
            << (signum(partialUnionDepForward) ==
                -signum(partialUnionDepReverse)) << '\n';

  // same-kind AddrSpace identity: two raw IPTR_PROCESSOR spaces sharing an
  // index cannot be distinguished by pointer identity in Rugra's enum model.
  AddrSpace dupSpaceA(&architecture,(const Translate *)0,IPTR_PROCESSOR,
                      "dup_a",false,8,1,5,AddrSpace::hasphysical,2,3);
  AddrSpace dupSpaceB(&architecture,(const Translate *)0,IPTR_PROCESSOR,
                      "dup_b",false,8,1,6,AddrSpace::hasphysical,2,3);
  AddrSpace dupSpaceA2(&architecture,(const Translate *)0,IPTR_PROCESSOR,
                       "dup_a2",false,8,1,5,AddrSpace::hasphysical,2,3);
  TypeSpacebase sameKindA(&dupSpaceA,Address(&dupSpaceA,0),&architecture);
  TypeSpacebase sameKindB(&dupSpaceB,Address(&dupSpaceB,0),&architecture);
  TypeSpacebase sameKindA2(&dupSpaceA2,Address(&dupSpaceA2,0),&architecture);
  int4 sameKindForward = sameKindA.compareDependency(sameKindB);
  int4 sameKindReverse = sameKindB.compareDependency(sameKindA);
  std::cout << "sksp.distinct_index_nonzero="
            << (sameKindForward != 0) << '\n';
  std::cout << "sksp.distinct_index_antisymmetric="
            << (signum(sameKindForward) == -signum(sameKindReverse)) << '\n';
  std::cout << "sksp.same_object_equal="
            << signum(sameKindA.compareDependency(sameKindA)) << '\n';
  std::cout << "sksp.same_index_distinct_object_nonzero="
            << (sameKindA.compareDependency(sameKindA2) != 0) << '\n';
  ProbePointerSpace ptrDupSpaceA(8,&sint4,1);
  ProbePointerSpace ptrDupSpaceA2(8,&sint4,1);
  ptrDupSpaceA.setSpace(&dupSpaceA);
  ptrDupSpaceA2.setSpace(&dupSpaceA2);
  std::cout << "ptr_same_kind.same_index_quirk="
            << signum(ptrDupSpaceA.compare(ptrDupSpaceA2,10)) << '\n';

  // Exhaustive 24-value sub-metatype runtime ordering matrix.
  TypeVoid voidMatrix;
  TypeSpacebase spacebaseMatrix(ram,validZero,&architecture);
  ProbeBase unknownMatrix(4,TYPE_UNKNOWN,"unknown_matrix");
  TypePartialStruct partialStructMatrix(&twoFieldStruct,0,4,&unknown4);
  TypeChar charSignedMatrix("cs1");
  ProbeChar charUnsignedMatrix("cu1",TYPE_UINT);
  ProbeBase intMatrix(4,TYPE_INT,"int_matrix");
  ProbeBase uintMatrix(4,TYPE_UINT,"uint_matrix");
  ProbeEnum enumSignedMatrix(4,TYPE_ENUM_INT,"ES");
  enumSignedMatrix.define(valuesA);
  TypePartialEnum partialEnumMatrix(&enumA,0,1,&unknown4);
  ProbeEnum enumUnsignedMatrix(4,TYPE_ENUM_UINT,"EU");
  enumUnsignedMatrix.define(valuesA);
  TypeUnicode unicodeSignedMatrix("ws2",2,TYPE_INT);
  TypeUnicode unicodeUnsignedMatrix("wu2",2,TYPE_UINT);
  ProbeBase boolMatrix(1,TYPE_BOOL,"bool_matrix");
  ProbeCode codeMatrix;
  ProbeBase floatMatrix(4,TYPE_FLOAT,"float_matrix");
  ProbeRel relUnkMatrix(8,&unknown4,1,&oneFieldStruct,4);
  relUnkMatrix.callMarkEphemeral(*architecture.types);
  ProbePointer ptrPlainMatrix(8,&sint4,1);
  TypePointerRel relFormalMatrix(8,&sint4,1,&oneFieldStruct,4);
  ProbePointer ptrStructMatrix(8,&twoFieldStruct,1);
  TypeArray arrayMatrix(1,&sint4);
  TypePartialUnion partialUnionMatrix(&unionType,0,4,&unknown4);
  Datatype *matrixTypes[24] = {
    &voidMatrix,
    &spacebaseMatrix,
    &unknownMatrix,
    &partialStructMatrix,
    &charSignedMatrix,
    &charUnsignedMatrix,
    &intMatrix,
    &uintMatrix,
    &enumSignedMatrix,
    &partialEnumMatrix,
    &enumUnsignedMatrix,
    &unicodeSignedMatrix,
    &unicodeUnsignedMatrix,
    &boolMatrix,
    &codeMatrix,
    &floatMatrix,
    &relUnkMatrix,
    &ptrPlainMatrix,
    &relFormalMatrix,
    &ptrStructMatrix,
    &arrayMatrix,
    &twoFieldStruct,
    &unionType,
    &partialUnionMatrix
  };
  for(int4 i=0;i<24;++i) {
    char key[32];
    snprintf(key,sizeof(key),"matrix.submeta_%02d",23-i);
    std::cout << key << '='
              << static_cast<int4>(matrixTypes[i]->getSubMeta()) << '\n';
  }
  for(int4 i=0;i+1<24;++i) {
    char key[32];
    snprintf(key,sizeof(key),"matrix.order_%02d_%02d",23-i,22-i);
    std::cout << key << '='
              << signum(matrixTypes[i]->compare(*matrixTypes[i+1],10))
              << '\n';
  }
  int4 matrixViolations = 0;
  for(int4 i=0;i<24;++i) {
    for(int4 j=i+1;j<24;++j) {
      if(signum(matrixTypes[i]->compare(*matrixTypes[j],10)) != 1)
        ++matrixViolations;
    }
  }
  std::cout << "matrix.total_order_violations=" << matrixViolations << '\n';
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
