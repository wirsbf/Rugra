/*
 * TYPEFACTORY-EXACTPIECE-0001
 *
 * Locked Ghidra 12.0.4 direct behavior fixture for
 * TypeFactory::getExactPiece (type.cc:4090-4117) and the inline TypeArray
 * constructor used by TypeFactory::getTypeArray (type.hh:937-944,
 * type.cc:3902-3908).
 *
 * The synthetic little-endian 64-bit Architecture exists only to provide the
 * production TypeFactory with its real alignment map and address-size state.
 * Every observed type is made by the production factory.  Pointer values are
 * never serialized; identity is projected as equality predicates.
 * TYPEFIELD-IDENT-REPRESENTATION-0001 remains explicit: locked TypeField
 * stores declaration-order ident values that Rust TypeField cannot represent;
 * the bounded target closure never reads ident, so no whole-TypeStruct
 * same-input claim is made.
 */

#include "architecture.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "translate.hh"
#include "type.hh"

#include <exception>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::map;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;

public:
  FixtureTranslate()
  {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this,this));
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"other",false,8,1,1,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new UniqueSpace(this,this,2,0));
    AddrSpace *ram = new AddrSpace(this,this,IPTR_PROCESSOR,"ram",false,8,1,3,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this,this,IPTR_PROCESSOR,"register",false,8,1,4,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this,this,"stack",5,8,ram,1,true);
    insertSpace(stack);
    VarnodeData stackPointer = { reg, 0, 8 };
    addSpacebasePointer(stack,stackPointer,8,true);
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"join",false,8,1,6,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new IopSpace(this,this,7));
    setDefaultCodeSpace(3);
    dummyRegister = { reg, 0, 8 };
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummyRegister; }
  string getRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  void getAllRegisters(map<VarnodeData,string> &) const override {}
  void getUserOpNames(vector<string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &,const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &,const Address &) const override { return 0; }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override {
    return (PcodeInjectLibrary *)0;
  }
  void buildTypegrp(DocumentStorage &) override {}
  void buildCoreTypes(DocumentStorage &) override {}
  void buildCommentDB(DocumentStorage &) override {}
  void buildStringManager(DocumentStorage &) override {}
  void buildConstantPool(DocumentStorage &) override {}
  void buildContext(DocumentStorage &) override {}
  void buildSymbols(DocumentStorage &) override {}
  void buildSpecFile(DocumentStorage &) override {}
  void modifySpaces(Translate *) override {}
  void resolveArchitecture(void) override {}

public:
  FixtureArchitecture()
  {
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
    if (max_basetype_size != 10)
      throw runtime_error("fixture max_basetype_size drifted");
    types = new TypeFactory(this);

    // Explicit size=0 prevents the locked getPrimitiveAlignSize(0) path from
    // seeing a zero alignment while incomplete composites are installed.
    std::istringstream organization(
        "<data_organization><size_alignment_map>"
        "<entry size=\"0\" alignment=\"1\"/>"
        "<entry size=\"1\" alignment=\"1\"/>"
        "<entry size=\"2\" alignment=\"2\"/>"
        "<entry size=\"3\" alignment=\"2\"/>"
        "<entry size=\"4\" alignment=\"4\"/>"
        "<entry size=\"8\" alignment=\"8\"/>"
        "<entry size=\"16\" alignment=\"8\"/>"
        "<entry size=\"32\" alignment=\"8\"/>"
        "</size_alignment_map></data_organization>");
    XmlDecode organizationDecoder(this);
    organizationDecoder.ingestStream(organization);
    types->decodeDataOrganization(organizationDecoder);
    types->setupSizes();

    // Do not depend on Architecture::getDefaultSize for this fixture's enum.
    std::istringstream enumConfig("<enum size=\"8\" signed=\"false\"/>");
    XmlDecode enumDecoder(this);
    enumDecoder.ingestStream(enumConfig);
    types->parseEnumConfig(enumDecoder);

    // Both comparands start from an otherwise empty/raw factory, then install
    // exactly one named core unknown.  This is the prerequisite exercised by
    // getBase(>10,TYPE_UNKNOWN)'s array conversion path.
    types->setCoreType("undefined1",1,TYPE_UNKNOWN,false);
    types->cacheCoreTypes();
  }

  void printMessage(const string &) const override {}
};

string plainKind(Datatype *ct)
{
  if (ct == (Datatype *)0)
    return "null";
  if (dynamic_cast<TypePartialStruct *>(ct) != (TypePartialStruct *)0)
    return "partial_struct";
  if (dynamic_cast<TypePartialUnion *>(ct) != (TypePartialUnion *)0)
    return "partial_union";
  if (dynamic_cast<TypePartialEnum *>(ct) != (TypePartialEnum *)0)
    return "partial_enum";
  if (ct->isEnumType())
    return "enum";
  switch(ct->getMetatype()) {
  case TYPE_STRUCT: return "struct";
  case TYPE_UNION: return "union";
  case TYPE_ARRAY: return "array";
  case TYPE_UINT: return "uint";
  case TYPE_INT: return "int";
  case TYPE_UNKNOWN: return "unknown";
  default: return "other";
  }
}

string shortShape(Datatype *ct)
{
  if (ct == (Datatype *)0)
    return "null";
  ostringstream out;
  out << plainKind(ct) << ':' << ct->getSize();
  return out.str();
}

string shape(Datatype *ct)
{
  if (ct == (Datatype *)0)
    return "null";
  ostringstream out;
  if (TypePartialStruct *part = dynamic_cast<TypePartialStruct *>(ct)) {
    out << "partial_struct:" << part->getSize()
        << "@" << part->getOffset()
        << "/parent=" << shortShape(part->getParent());
    return out.str();
  }
  if (TypePartialUnion *part = dynamic_cast<TypePartialUnion *>(ct)) {
    out << "partial_union:" << part->getSize()
        << "@" << part->getOffset()
        << "/parent=" << shortShape(part->getParentUnion());
    return out.str();
  }
  if (TypePartialEnum *part = dynamic_cast<TypePartialEnum *>(ct)) {
    out << "partial_enum:" << part->getSize()
        << "@" << part->getOffset()
        << "/parent=" << shortShape(part->getParent());
    return out.str();
  }
  if (TypeArray *array = dynamic_cast<TypeArray *>(ct)) {
    out << "array:" << array->getSize()
        << 'x' << array->numElements()
        << "/elem=" << shortShape(array->getBase());
    return out.str();
  }
  return shortShape(ct);
}

void emitPiece(TypeFactory *types,const string &caseName,Datatype *input,
               int4 offset,int4 size,Datatype *expected,
               Datatype *direct,bool hasDirect)
{
  Datatype *first = types->getExactPiece(input,offset,size);
  Datatype *repeat = types->getExactPiece(input,offset,size);
  cout << "piece|case=" << caseName
       << "|input=" << shape(input)
       << "|offset=" << offset
       << "|size=" << size
       << "|result=" << shape(first)
       << "|same_input=" << (first == input ? 1 : 0)
       << "|same_expected=" << (first == expected ? 1 : 0)
       << "|repeat_same=" << (first == repeat ? 1 : 0)
       << "|direct_same=";
  if (hasDirect)
    cout << (first == direct ? 1 : 0);
  else
    cout << "na";
  cout << '\n';
}

void emitPieceWithSubtype(TypeFactory *types,const string &caseName,
                          Datatype *input,int4 offset,int4 size,
                          Datatype *expected,int8 subtypeOffset)
{
  int8 subtypeNewOff = -999;
  Datatype *subtype = input->getSubType(subtypeOffset,&subtypeNewOff);
  Datatype *first = types->getExactPiece(input,offset,size);
  Datatype *repeat = types->getExactPiece(input,offset,size);
  cout << "piece_subtype|case=" << caseName
       << "|input=" << shape(input)
       << "|offset=" << offset
       << "|size=" << size
       << "|result=" << shape(first)
       << "|same_input=" << (first == input ? 1 : 0)
       << "|same_expected=" << (first == expected ? 1 : 0)
       << "|repeat_same=" << (first == repeat ? 1 : 0)
       << "|direct_same=na"
       << "|subtype_offset=" << subtypeOffset
       << "|subtype=" << shape(subtype)
       << "|subtype_newoff=" << subtypeNewOff
       << '\n';
}

void emitArrayPolicy(TypeFactory *types,const string &caseName,Datatype *input,
                     Datatype *expectedElement,Datatype *contrastElement,
                     bool hasContrast,int4 typedefTargetSame)
{
  TypeArray *array = types->getTypeArray(2,input);
  TypeArray *repeat = types->getTypeArray(2,input);
  TypeArray *expectedArray = types->getTypeArray(2,expectedElement);
  TypeArray *contrastArray = hasContrast
      ? types->getTypeArray(2,contrastElement)
      : (TypeArray *)0;
  Datatype *actualElement = array->getBase();
  cout << "array_policy|case=" << caseName
       << "|input=" << shape(input)
       << "|input_ghidra_metatype_code=" << (int4)input->getMetatype()
       << "|input_submeta=" << (int4)input->getSubMeta()
       << "|input_id=" << input->getId()
       << "|input_is_core=" << (input->isCoreType() ? 1 : 0)
       << "|input_is_enum=" << (input->isEnumType() ? 1 : 0)
       << "|input_is_variable_length=" << (input->isVariableLength() ? 1 : 0)
       << "|input_is_incomplete=" << (input->isIncomplete() ? 1 : 0)
       << "|input_is_pointer_to_array=" << (input->isPointerToArray() ? 1 : 0)
       << "|input_has_stripped=" << (input->hasStripped() ? 1 : 0)
       << "|input_needs_resolution=" << (input->needsResolution() ? 1 : 0)
       << "|input_alignment=" << input->getAlignment()
       << "|input_align_size=" << input->getAlignSize()
       << "|input_name_empty=" << (input->getName().empty() ? 1 : 0)
       << "|input_display_name_empty=" << (input->getDisplayName().empty() ? 1 : 0)
       << "|typedef_target_same=";
  if (typedefTargetSame < 0)
    cout << "na";
  else
    cout << typedefTargetSame;
  cout << "|element=" << shape(actualElement)
       << "|element_same_input=" << (actualElement == input ? 1 : 0)
       << "|element_same_expected=" << (actualElement == expectedElement ? 1 : 0)
       << "|array_same_expected=" << (array == expectedArray ? 1 : 0)
       << "|array_same_contrast=";
  if (hasContrast)
    cout << (array == contrastArray ? 1 : 0);
  else
    cout << "na";
  cout << "|array_size=" << array->getSize()
       << "|array_alignment=" << array->getAlignment()
       << "|array_align_size=" << array->getAlignSize()
       << "|array_name_empty=" << (array->getName().empty() ? 1 : 0)
       << "|array_display_name_empty=" << (array->getDisplayName().empty() ? 1 : 0)
       << "|repeat_same=" << (array == repeat ? 1 : 0)
       << '\n';
}

struct CompositeDependencies {
  Datatype *oldElement;
  int4 snapshotSize;
  int4 snapshotAlignment;
  int4 snapshotAlignSize;
  bool snapshotIncomplete;
  uint8 snapshotId;
  string snapshotDisplayName;
  TypeArray *array;
  TypePointer *pointer;
  Datatype *partial;
  Datatype *typedefType;
  bool unionParent;
};

Datatype *getPartialParent(Datatype *partial)
{
  if (TypePartialStruct *part = dynamic_cast<TypePartialStruct *>(partial))
    return part->getParent();
  if (TypePartialUnion *part = dynamic_cast<TypePartialUnion *>(partial))
    return part->getParentUnion();
  return (Datatype *)0;
}

void emitCompositeArrayLayout(TypeFactory *types,const string &caseName,
                              const CompositeDependencies &dependencies,
                              Datatype *element,int4 count)
{
  Datatype *oldElement = dependencies.oldElement;
  Datatype *factoryElement = types->findByName(element->getName());
  TypeArray *array = types->getTypeArray(count,element);
  TypeArray *repeat = types->getTypeArray(count,element);
  TypeArray *dependencyArrayOldRepeat =
      types->getTypeArray(2,oldElement);
  TypeArray *dependencyArrayPost =
      types->getTypeArray(2,element);
  TypePointer *dependencyPointerOldRepeat =
      types->getTypePointer(8,oldElement,1);
  TypePointer *dependencyPointerPost =
      types->getTypePointer(8,element,1);
  Datatype *dependencyPartialOldRepeat;
  Datatype *dependencyPartialPost;
  if (dependencies.unionParent) {
    dependencyPartialOldRepeat = types->getTypePartialUnion(
        (TypeUnion *)oldElement,0,1);
    dependencyPartialPost = types->getTypePartialUnion(
        (TypeUnion *)element,0,1);
  }
  else {
    dependencyPartialOldRepeat = types->getTypePartialStruct(
        oldElement,0,1);
    dependencyPartialPost = types->getTypePartialStruct(
        element,0,1);
  }
  Datatype *dependencyArrayElement = dependencies.array->getBase();
  Datatype *dependencyPointerTarget = dependencies.pointer->getPtrTo();
  Datatype *dependencyPartialParent = getPartialParent(dependencies.partial);
  Datatype *dependencyTypedefTarget = dependencies.typedefType->getTypedef();
  Datatype *dependencyTypedefFactory =
      types->findByName(dependencies.typedefType->getName());
  cout << "array_layout|case=" << caseName
       << "|pre_same_post=" << (oldElement == element ? 1 : 0)
       << "|post_same_factory=" << (factoryElement == element ? 1 : 0)
       << "|pre_size=" << dependencies.snapshotSize
       << "|pre_alignment=" << dependencies.snapshotAlignment
       << "|pre_align_size=" << dependencies.snapshotAlignSize
       << "|pre_incomplete=" << (dependencies.snapshotIncomplete ? 1 : 0)
       << "|pre_id=" << dependencies.snapshotId
       << "|pre_display_name=" << dependencies.snapshotDisplayName
       << "|old_after_size=" << oldElement->getSize()
       << "|old_after_alignment=" << oldElement->getAlignment()
       << "|old_after_align_size=" << oldElement->getAlignSize()
       << "|old_after_incomplete=" << (oldElement->isIncomplete() ? 1 : 0)
       << "|old_after_id=" << oldElement->getId()
       << "|old_after_display_name=" << oldElement->getDisplayName()
       << "|post_size=" << element->getSize()
       << "|post_alignment=" << element->getAlignment()
       << "|post_align_size=" << element->getAlignSize()
       << "|post_incomplete=" << (element->isIncomplete() ? 1 : 0)
       << "|post_id=" << element->getId()
       << "|post_display_name=" << element->getDisplayName()
       << "|dep_array_size=" << dependencies.array->getSize()
       << "|dep_array_element_same_old="
       << (dependencyArrayElement == oldElement ? 1 : 0)
       << "|dep_array_element_same_post="
       << (dependencyArrayElement == element ? 1 : 0)
       << "|dep_array_element_size=" << dependencyArrayElement->getSize()
       << "|dep_array_element_alignment=" << dependencyArrayElement->getAlignment()
       << "|dep_array_element_align_size=" << dependencyArrayElement->getAlignSize()
       << "|dep_array_element_incomplete="
       << (dependencyArrayElement->isIncomplete() ? 1 : 0)
       << "|dep_array_old_repeat_same="
       << (dependencies.array == dependencyArrayOldRepeat ? 1 : 0)
       << "|dep_array_post_same="
       << (dependencies.array == dependencyArrayPost ? 1 : 0)
       << "|dep_pointer_target_same_old="
       << (dependencyPointerTarget == oldElement ? 1 : 0)
       << "|dep_pointer_target_same_post="
       << (dependencyPointerTarget == element ? 1 : 0)
       << "|dep_pointer_target_size=" << dependencyPointerTarget->getSize()
       << "|dep_pointer_target_alignment=" << dependencyPointerTarget->getAlignment()
       << "|dep_pointer_target_align_size=" << dependencyPointerTarget->getAlignSize()
       << "|dep_pointer_target_incomplete="
       << (dependencyPointerTarget->isIncomplete() ? 1 : 0)
       << "|dep_pointer_submeta=" << (int4)dependencies.pointer->getSubMeta()
       << "|dep_pointer_is_core="
       << (dependencies.pointer->isCoreType() ? 1 : 0)
       << "|dep_pointer_is_enum="
       << (dependencies.pointer->isEnumType() ? 1 : 0)
       << "|dep_pointer_is_variable_length="
       << (dependencies.pointer->isVariableLength() ? 1 : 0)
       << "|dep_pointer_is_incomplete="
       << (dependencies.pointer->isIncomplete() ? 1 : 0)
       << "|dep_pointer_is_pointer_to_array="
       << (dependencies.pointer->isPointerToArray() ? 1 : 0)
       << "|dep_pointer_has_stripped="
       << (dependencies.pointer->hasStripped() ? 1 : 0)
       << "|dep_pointer_needs_resolution="
       << (dependencies.pointer->needsResolution() ? 1 : 0)
       << "|dep_pointer_old_repeat_same="
       << (dependencies.pointer == dependencyPointerOldRepeat ? 1 : 0)
       << "|dep_pointer_post_same="
       << (dependencies.pointer == dependencyPointerPost ? 1 : 0)
       << "|dep_partial_parent_same_old="
       << (dependencyPartialParent == oldElement ? 1 : 0)
       << "|dep_partial_parent_same_post="
       << (dependencyPartialParent == element ? 1 : 0)
       << "|dep_partial_parent_size=" << dependencyPartialParent->getSize()
       << "|dep_partial_parent_alignment=" << dependencyPartialParent->getAlignment()
       << "|dep_partial_parent_align_size=" << dependencyPartialParent->getAlignSize()
       << "|dep_partial_parent_incomplete="
       << (dependencyPartialParent->isIncomplete() ? 1 : 0)
       << "|dep_partial_old_repeat_same="
       << (dependencies.partial == dependencyPartialOldRepeat ? 1 : 0)
       << "|dep_partial_post_same="
       << (dependencies.partial == dependencyPartialPost ? 1 : 0)
       << "|dep_typedef_target_same_old="
       << (dependencyTypedefTarget == oldElement ? 1 : 0)
       << "|dep_typedef_target_same_post="
       << (dependencyTypedefTarget == element ? 1 : 0)
       << "|dep_typedef_target_size=" << dependencyTypedefTarget->getSize()
       << "|dep_typedef_target_alignment=" << dependencyTypedefTarget->getAlignment()
       << "|dep_typedef_target_align_size=" << dependencyTypedefTarget->getAlignSize()
       << "|dep_typedef_target_incomplete="
       << (dependencyTypedefTarget->isIncomplete() ? 1 : 0)
       << "|dep_typedef_same_factory="
       << (dependencies.typedefType == dependencyTypedefFactory ? 1 : 0)
       << "|dep_typedef_size=" << dependencies.typedefType->getSize()
       << "|dep_typedef_alignment=" << dependencies.typedefType->getAlignment()
       << "|dep_typedef_align_size=" << dependencies.typedefType->getAlignSize()
       << "|dep_typedef_incomplete="
       << (dependencies.typedefType->isIncomplete() ? 1 : 0)
       << "|dep_typedef_id=" << dependencies.typedefType->getId()
       << "|dep_typedef_display_name="
       << dependencies.typedefType->getDisplayName()
       << "|dep_typedef_factory_size=" << dependencyTypedefFactory->getSize()
       << "|dep_typedef_factory_alignment="
       << dependencyTypedefFactory->getAlignment()
       << "|dep_typedef_factory_align_size="
       << dependencyTypedefFactory->getAlignSize()
       << "|dep_typedef_factory_incomplete="
       << (dependencyTypedefFactory->isIncomplete() ? 1 : 0)
       << "|dep_typedef_factory_id=" << dependencyTypedefFactory->getId()
       << "|dep_typedef_factory_display_name="
       << dependencyTypedefFactory->getDisplayName()
       << "|element=" << shape(element)
       << "|element_ghidra_metatype_code=" << (int4)element->getMetatype()
       << "|element_submeta=" << (int4)element->getSubMeta()
       << "|element_id=" << element->getId()
       << "|element_is_core=" << (element->isCoreType() ? 1 : 0)
       << "|element_is_enum=" << (element->isEnumType() ? 1 : 0)
       << "|element_is_variable_length=" << (element->isVariableLength() ? 1 : 0)
       << "|element_is_incomplete=" << (element->isIncomplete() ? 1 : 0)
       << "|element_is_pointer_to_array=" << (element->isPointerToArray() ? 1 : 0)
       << "|element_has_stripped=" << (element->hasStripped() ? 1 : 0)
       << "|element_needs_resolution=" << (element->needsResolution() ? 1 : 0)
       << "|element_size=" << element->getSize()
       << "|element_alignment=" << element->getAlignment()
       << "|element_align_size=" << element->getAlignSize()
       << "|element_name_empty=" << (element->getName().empty() ? 1 : 0)
       << "|element_display_name_empty=" << (element->getDisplayName().empty() ? 1 : 0)
       << "|array_size=" << array->getSize()
       << "|array_alignment=" << array->getAlignment()
       << "|array_align_size=" << array->getAlignSize()
       << "|elements=" << array->numElements()
       << "|array_element_same_input=" << (array->getBase() == element ? 1 : 0)
       << "|array_name_empty=" << (array->getName().empty() ? 1 : 0)
       << "|array_display_name_empty=" << (array->getDisplayName().empty() ? 1 : 0)
       << "|factory_repeat_same=" << (array == repeat ? 1 : 0)
       << '\n';
}

struct FixtureTypes {
  Datatype *uint2Type;
  Datatype *uint4Type;
  Datatype *uint8Type;
  Datatype *odd3Type;
  TypeStruct *inner;
  TypeStruct *outer;
  TypeUnion *union8;
  TypeEnum *enum8;
  TypeArray *uint4Array3;
  TypeArray *odd3Array3;
  TypePartialStruct *innerPart6;

  explicit FixtureTypes(TypeFactory *types)
  {
    uint2Type = types->getBase(2,TYPE_UINT);
    uint4Type = types->getBase(4,TYPE_UINT);
    uint8Type = types->getBase(8,TYPE_UINT);
    odd3Type = types->getBase(3,TYPE_UINT);

    inner = types->getTypeStruct("fixture_exact_inner8");
    vector<TypeField> innerFields;
    innerFields.push_back(TypeField(0,0,"lo",uint4Type));
    innerFields.push_back(TypeField(1,4,"hi",uint4Type));
    types->setFields(innerFields,inner,8,4,0);

    // Bytes [4,8) are an intentional structure hole.  inner occupies [8,16).
    outer = types->getTypeStruct("fixture_exact_outer24");
    vector<TypeField> outerFields;
    outerFields.push_back(TypeField(0,0,"head",uint4Type));
    outerFields.push_back(TypeField(1,8,"inner",inner));
    outerFields.push_back(TypeField(2,16,"tail",uint8Type));
    types->setFields(outerFields,outer,24,8,0);

    union8 = types->getTypeUnion("fixture_exact_union8");
    vector<TypeField> unionFields;
    unionFields.push_back(TypeField(0,0,"wide",uint8Type));
    unionFields.push_back(TypeField(1,0,"narrow",uint4Type));
    types->setFields(unionFields,union8,8,8,0);

    enum8 = types->getTypeEnum("fixture_exact_enum8");
    uint4Array3 = types->getTypeArray(3,uint4Type);
    odd3Array3 = types->getTypeArray(3,odd3Type);
    innerPart6 = types->getTypePartialStruct(inner,0,6);
  }
};

void run(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  {
    FixtureArchitecture architecture;
    TypeFactory *types = architecture.types;
    FixtureTypes fixture(types);

    emitPiece(types,"whole_struct",fixture.outer,0,24,fixture.outer,
              (Datatype *)0,false);
    emitPiece(types,"nested_struct",fixture.outer,8,8,fixture.inner,
              (Datatype *)0,false);
    emitPiece(types,"nested_leaf",fixture.outer,12,4,fixture.uint4Type,
              (Datatype *)0,false);
    emitPiece(types,"contained_scalar_partial",fixture.outer,9,2,
              (Datatype *)0,(Datatype *)0,false);
    // The upper-bound guard accepts this negative start, then the exact-size
    // check returns the scalar before any subtype/offset validation.
    emitPiece(types,"scalar_negative_exact",fixture.uint4Type,-1,4,
              fixture.uint4Type,(Datatype *)0,false);

    TypePartialStruct *cross = types->getTypePartialStruct(fixture.inner,2,4);
    emitPiece(types,"cross_field",fixture.inner,2,4,cross,cross,true);
    TypePartialStruct *hole = types->getTypePartialStruct(fixture.outer,4,4);
    emitPiece(types,"struct_hole",fixture.outer,4,4,hole,hole,true);
    emitPiece(types,"beyond_end",fixture.outer,22,4,
              (Datatype *)0,(Datatype *)0,false);

    emitPiece(types,"whole_union",fixture.union8,0,8,fixture.union8,
              (Datatype *)0,false);
    TypePartialUnion *partUnion = types->getTypePartialUnion(fixture.union8,1,4);
    emitPiece(types,"partial_union",fixture.union8,1,4,partUnion,partUnion,true);

    emitPiece(types,"whole_enum",fixture.enum8,0,8,fixture.enum8,
              (Datatype *)0,false);
    TypePartialEnum *partEnum = types->getTypePartialEnum(fixture.enum8,2,4);
    emitPiece(types,"partial_enum",fixture.enum8,2,4,partEnum,partEnum,true);

    emitPiece(types,"whole_array",fixture.uint4Array3,0,12,fixture.uint4Array3,
              (Datatype *)0,false);
    emitPiece(types,"array_element",fixture.uint4Array3,4,4,fixture.uint4Type,
              (Datatype *)0,false);
    TypePartialStruct *arrayCross =
        types->getTypePartialStruct(fixture.uint4Array3,3,2);
    emitPiece(types,"array_cross_stride",fixture.uint4Array3,3,2,
              arrayCross,arrayCross,true);

    emitPiece(types,"partialstruct_whole",fixture.innerPart6,0,6,
              fixture.innerPart6,fixture.innerPart6,true);
    emitPiece(types,"partialstruct_nested",fixture.innerPart6,0,4,
              fixture.uint4Type,(Datatype *)0,false);
    emitPiece(types,"partialstruct_cross",fixture.innerPart6,2,4,
              (Datatype *)0,(Datatype *)0,false);
    // First descend inner -> uint4, then the next do/while iteration assigns
    // ct=null.  This distinguishes the locked overwrite-on-failure behavior
    // from returning the last successful subtype.
    TypePartialStruct *narrowPart =
        types->getTypePartialStruct(fixture.inner,0,2);
    emitPieceWithSubtype(types,"partialstruct_descent_null",narrowPart,0,1,
                         (Datatype *)0,0);

    TypeArray *oddArrayRepeat = types->getTypeArray(3,fixture.odd3Type);
    Datatype *oddPiece = types->getExactPiece(fixture.odd3Array3,4,3);
    Datatype *oddPieceRepeat = types->getExactPiece(fixture.odd3Array3,4,3);
    cout << "array_layout|case=odd3_array3"
         << "|element=" << shape(fixture.odd3Type)
         << "|element_ghidra_metatype_code=" << (int4)fixture.odd3Type->getMetatype()
         << "|element_submeta=" << (int4)fixture.odd3Type->getSubMeta()
         << "|element_id=" << fixture.odd3Type->getId()
         << "|element_is_core=" << (fixture.odd3Type->isCoreType() ? 1 : 0)
         << "|element_is_enum=" << (fixture.odd3Type->isEnumType() ? 1 : 0)
         << "|element_is_variable_length="
         << (fixture.odd3Type->isVariableLength() ? 1 : 0)
         << "|element_is_incomplete="
         << (fixture.odd3Type->isIncomplete() ? 1 : 0)
         << "|element_is_pointer_to_array="
         << (fixture.odd3Type->isPointerToArray() ? 1 : 0)
         << "|element_has_stripped="
         << (fixture.odd3Type->hasStripped() ? 1 : 0)
         << "|element_needs_resolution="
         << (fixture.odd3Type->needsResolution() ? 1 : 0)
         << "|element_size=" << fixture.odd3Type->getSize()
         << "|element_alignment=" << fixture.odd3Type->getAlignment()
         << "|element_align_size=" << fixture.odd3Type->getAlignSize()
         << "|element_name_empty=" << (fixture.odd3Type->getName().empty() ? 1 : 0)
         << "|element_display_name_empty="
         << (fixture.odd3Type->getDisplayName().empty() ? 1 : 0)
         << "|array_size=" << fixture.odd3Array3->getSize()
         << "|array_alignment=" << fixture.odd3Array3->getAlignment()
         << "|array_align_size=" << fixture.odd3Array3->getAlignSize()
         << "|elements=" << fixture.odd3Array3->numElements()
         << "|array_element_same_input="
         << (fixture.odd3Array3->getBase() == fixture.odd3Type ? 1 : 0)
         << "|array_name_empty=" << (fixture.odd3Array3->getName().empty() ? 1 : 0)
         << "|array_display_name_empty="
         << (fixture.odd3Array3->getDisplayName().empty() ? 1 : 0)
         << "|factory_repeat_same=" << (fixture.odd3Array3 == oddArrayRepeat ? 1 : 0)
         << "|piece=" << shape(oddPiece)
         << "|piece_expected_same=" << (oddPiece == fixture.odd3Type ? 1 : 0)
         << "|piece_repeat_same=" << (oddPiece == oddPieceRepeat ? 1 : 0)
         << '\n';

    // Ordinary typedefs carry typedefImm but NOT has_stripped.  getTypeArray
    // therefore preserves the typedef object as its exact element.
    Datatype *typedef4 = types->getTypedef(
        fixture.uint4Type,"fixture_exact_u4_alias",0,0);
    emitArrayPolicy(types,"typedef_preserve",typedef4,typedef4,
                    fixture.uint4Type,true,
                    typedef4->getTypedef() == fixture.uint4Type ? 1 : 0);

    // PartialStruct is formal-only and has_stripped.  getTypeArray must use
    // its undefined fallback, and canonicalize to the direct fallback array.
    TypePartialStruct *partialElement =
        types->getTypePartialStruct(fixture.outer,0,12);
    emitArrayPolicy(types,"partialstruct_strip",partialElement,
                    partialElement->getStripped(),(Datatype *)0,false,-1);

    // A typedef clone of a PartialStruct keeps has_stripped and the cloned
    // virtual stripped pointer.  typedefImm points at the original partial,
    // but getTypeArray must dispatch getStripped on the typedef clone rather
    // than treating typedefImm itself as the array element.
    Datatype *typedefPartial = types->getTypedef(
        partialElement,"fixture_exact_partial_alias",0,0);
    emitArrayPolicy(types,"typedef_partialstruct_strip",typedefPartial,
                    partialElement->getStripped(),partialElement,true,
                    typedefPartial->getTypedef() == partialElement ? 1 : 0);

    // The unnamed overload creates an ephemeral PointerRel and installs a
    // stripped plain pointer.  Arrays must contain the plain pointer.
    TypePointer *parentPointer =
        types->getTypePointer(8,fixture.inner,1);
    TypePointerRel *relativeElement =
        types->getTypePointerRel(parentPointer,fixture.uint4Type,4);
    emitArrayPolicy(types,"pointerrel_strip",relativeElement,
                    relativeElement->getStripped(),(Datatype *)0,false,-1);

    // Explicit alignments deliberately disagree with size-derived primitive
    // alignment.  The output reads real Datatype state; no number is assumed
    // by the fixture metadata before the locked executable runs.
    TypeStruct *alignStruct =
        types->getTypeStruct("fixture_exact_align_struct6");
    CompositeDependencies alignStructDependencies;
    alignStructDependencies.oldElement = alignStruct;
    alignStructDependencies.snapshotSize = alignStruct->getSize();
    alignStructDependencies.snapshotAlignment = alignStruct->getAlignment();
    alignStructDependencies.snapshotAlignSize = alignStruct->getAlignSize();
    alignStructDependencies.snapshotIncomplete = alignStruct->isIncomplete();
    alignStructDependencies.snapshotId = alignStruct->getId();
    alignStructDependencies.snapshotDisplayName = alignStruct->getDisplayName();
    alignStructDependencies.array = types->getTypeArray(2,alignStruct);
    alignStructDependencies.pointer = types->getTypePointer(8,alignStruct,1);
    alignStructDependencies.partial =
        types->getTypePartialStruct(alignStruct,0,1);
    alignStructDependencies.typedefType = types->getTypedef(
        alignStruct,"fixture_exact_align_struct6_alias",0,0);
    alignStructDependencies.unionParent = false;
    vector<TypeField> alignStructFields;
    alignStructFields.push_back(TypeField(0,0,"wide",fixture.uint4Type));
    alignStructFields.push_back(TypeField(1,4,"tail",fixture.uint2Type));
    types->setFields(alignStructFields,alignStruct,6,1,0);
    emitCompositeArrayLayout(types,"explicit_align_struct",
                             alignStructDependencies,alignStruct,3);

    TypeUnion *alignUnion =
        types->getTypeUnion("fixture_exact_align_union4");
    CompositeDependencies alignUnionDependencies;
    alignUnionDependencies.oldElement = alignUnion;
    alignUnionDependencies.snapshotSize = alignUnion->getSize();
    alignUnionDependencies.snapshotAlignment = alignUnion->getAlignment();
    alignUnionDependencies.snapshotAlignSize = alignUnion->getAlignSize();
    alignUnionDependencies.snapshotIncomplete = alignUnion->isIncomplete();
    alignUnionDependencies.snapshotId = alignUnion->getId();
    alignUnionDependencies.snapshotDisplayName = alignUnion->getDisplayName();
    alignUnionDependencies.array = types->getTypeArray(2,alignUnion);
    alignUnionDependencies.pointer = types->getTypePointer(8,alignUnion,1);
    alignUnionDependencies.partial =
        types->getTypePartialUnion(alignUnion,0,1);
    alignUnionDependencies.typedefType = types->getTypedef(
        alignUnion,"fixture_exact_align_union4_alias",0,0);
    alignUnionDependencies.unionParent = true;
    vector<TypeField> alignUnionFields;
    alignUnionFields.push_back(TypeField(0,0,"wide",fixture.uint4Type));
    alignUnionFields.push_back(TypeField(1,0,"narrow",fixture.uint2Type));
    types->setFields(alignUnionFields,alignUnion,4,1,0);
    emitCompositeArrayLayout(types,"explicit_align_union",
                             alignUnionDependencies,alignUnion,3);

    TypeArray *singleArray = types->getTypeArray(1,fixture.uint4Type);
    TypeArray *singleRepeat = types->getTypeArray(1,fixture.uint4Type);
    cout << "array_ctor|case=array_size1_needsres"
         << "|size=" << singleArray->getSize()
         << "|alignment=" << singleArray->getAlignment()
         << "|align_size=" << singleArray->getAlignSize()
         << "|elements=" << singleArray->numElements()
         << "|element_same=" << (singleArray->getBase() == fixture.uint4Type ? 1 : 0)
         << "|needs_resolution=" << (singleArray->needsResolution() ? 1 : 0)
         << "|name_empty=" << (singleArray->getName().empty() ? 1 : 0)
         << "|display_name_empty=" << (singleArray->getDisplayName().empty() ? 1 : 0)
         << "|repeat_same=" << (singleArray == singleRepeat ? 1 : 0)
         << '\n';

    TypeArray *sameTotalA = types->getTypeArray(4,fixture.uint2Type);
    TypeArray *sameTotalB = types->getTypeArray(2,fixture.uint4Type);
    TypeArray *sameTotalARepeat = types->getTypeArray(4,fixture.uint2Type);
    TypeArray *sameTotalBRepeat = types->getTypeArray(2,fixture.uint4Type);
    cout << "array_identity|case=same_total_distinct_elements"
         << "|a_size=" << sameTotalA->getSize()
         << "|b_size=" << sameTotalB->getSize()
         << "|same_total=" << (sameTotalA->getSize() == sameTotalB->getSize() ? 1 : 0)
         << "|a_element_same=" << (sameTotalA->getBase() == fixture.uint2Type ? 1 : 0)
         << "|b_element_same=" << (sameTotalB->getBase() == fixture.uint4Type ? 1 : 0)
         << "|arrays_same=" << (sameTotalA == sameTotalB ? 1 : 0)
         << "|a_repeat_same=" << (sameTotalA == sameTotalARepeat ? 1 : 0)
         << "|b_repeat_same=" << (sameTotalB == sameTotalBRepeat ? 1 : 0)
         << '\n';

    emitArrayPolicy(types,"partialenum_strip",partEnum,
                    partEnum->getStripped(),(Datatype *)0,false,-1);
    emitArrayPolicy(types,"partialunion_strip",partUnion,
                    partUnion->getStripped(),(Datatype *)0,false,-1);

    TypePartialStruct *negativeDirect =
        types->getTypePartialStruct(fixture.outer,-1,4);
    emitPiece(types,"negative_offset",fixture.outer,-1,4,
              negativeDirect,negativeDirect,true);
    TypePartialStruct *zeroDirect =
        types->getTypePartialStruct(fixture.outer,4,0);
    emitPiece(types,"zero_size_hole",fixture.outer,4,0,
              zeroDirect,zeroDirect,true);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(void)
{
  try {
    run();
    return 0;
  }
  catch(const LowlevelError &error) {
    cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const DecoderError &error) {
    cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const exception &error) {
    cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
