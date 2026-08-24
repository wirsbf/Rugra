/*
 * TYPEFACTORY-DOWNCHAIN-VIRTUAL-0001
 *
 * Locked Ghidra 12.0.4 direct behavior fixture for the virtual
 * TypePointer::downChain dispatch (type.hh:429 declaration,
 * TypePointerRel override type.hh:681; plain body type.cc:1084-1121,
 * relative body type.cc:2656-2672).
 *
 * The synthetic little-endian 64-bit Architecture exists only to provide the
 * production TypeFactory with its real alignment map and address-size state.
 * Every observed type is made by the production factory.  Pointer values are
 * never serialized; identity is projected as equality predicates.  Each
 * record drives one virtual `input->downChain(off,par,parOff,allowWrap,
 * typegrp)` call through the fixed 25-case manifest: field hits, hole/null
 * descents, off==0 and off==size boundaries, negative-encoded wrap, the
 * enum branch, multi-level array chains with carried accumulators, and the
 * plain/relative routing discrimination (including the deferred-call
 * `par = this` identity and the untouched-accumulator recover-parent path).
 *
 * Bounded input domain: no field/element type in this graph carries a
 * stripped state, and the alternate-pointer-size truncate path never fires,
 * so getTypePointerStripArray's hasStripped pre-strip (type.cc:3851-3852)
 * and calcTruncate are not observable here; they remain registered
 * residuals, not normalized differences.
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
    // exactly one named core unknown (identical to the exactpiece baseline).
    types->setCoreType("undefined1",1,TYPE_UNKNOWN,false);
    types->cacheCoreTypes();
  }

  void printMessage(const string &) const override {}
};

string plainKind(Datatype *ct)
{
  if (ct == (Datatype *)0)
    return "null";
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
  if (TypeArray *array = dynamic_cast<TypeArray *>(ct)) {
    out << "array:" << array->getSize()
        << 'x' << array->numElements()
        << "/elem=" << shortShape(array->getBase());
    return out.str();
  }
  return shortShape(ct);
}

string pointerShape(TypePointer *ptr)
{
  if (ptr == (TypePointer *)0)
    return "null";
  ostringstream out;
  if (TypePointerRel *rel = dynamic_cast<TypePointerRel *>(ptr)) {
    out << "ptrrel:" << rel->getSize()
        << "->" << shortShape(rel->getPtrTo())
        << '+' << rel->getByteOffset()
        << '@' << shortShape(rel->getParent());
    return out.str();
  }
  out << "ptr:" << ptr->getSize()
      << "->" << shape(ptr->getPtrTo());
  return out.str();
}

struct DownchainState {
  TypePointer *result;
  TypePointer *par;
  int8 parOff;
  int8 off;
};

// One virtual downChain call with explicit accumulator inputs; every
// observable (result shape/identity, renormalized off, par shape/identity,
// parOff) is emitted in the fixed field order.
DownchainState emitDownchainStep(TypeFactory *types,const string &caseName,
                                 TypePointer *input,int8 offIn,bool allowWrap,
                                 TypePointer *parIn,int8 parOffIn)
{
  int8 off = offIn;
  TypePointer *par = parIn;
  int8 parOff = parOffIn;
  TypePointer *result = input->downChain(off,par,parOff,allowWrap,*types);
  cout << "downchain|case=" << caseName
       << "|input=" << pointerShape(input)
       << "|off_in=" << offIn
       << "|wrap=" << (allowWrap ? 1 : 0)
       << "|result=" << pointerShape(result)
       << "|off_out=" << off
       << "|par=" << pointerShape(par)
       << "|par_off=" << parOff
       << "|result_same_input=" << (result == input ? 1 : 0)
       << "|par_same_input=" << (par == input ? 1 : 0)
       << '\n';
  DownchainState state;
  state.result = result;
  state.par = par;
  state.parOff = parOff;
  state.off = off;
  return state;
}

DownchainState emitDownchain(TypeFactory *types,const string &caseName,
                             TypePointer *input,int8 offIn,bool allowWrap)
{
  return emitDownchainStep(types,caseName,input,offIn,allowWrap,
                           (TypePointer *)0,-999);
}

struct FixtureTypes {
  Datatype *uint4Type;
  Datatype *uint8Type;
  TypeStruct *inner;
  TypeStruct *progress;
  TypeStruct *holed;
  TypeStruct *holder;
  TypeEnum *enum8;
  TypeArray *inners3;
  TypeArray *inners3x2;
  TypePointer *pdPointer;
  TypePointer *holedPointer;
  TypePointer *arrPointer;
  TypePointer *arr2Pointer;
  TypePointer *holderPointer;
  TypePointer *uint4Pointer;
  TypePointer *enumPointer;
  TypePointerRel *relTotal;
  TypePointerRel *relInner;
  TypePointerRel *relHole;
  TypePointerRel *relFirst;

  explicit FixtureTypes(TypeFactory *types)
  {
    uint4Type = types->getBase(4,TYPE_UINT);
    uint8Type = types->getBase(8,TYPE_UINT);

    inner = types->getTypeStruct("fixture_dcv_inner8");
    vector<TypeField> innerFields;
    innerFields.push_back(TypeField(0,0,"lo",uint4Type));
    innerFields.push_back(TypeField(1,4,"hi",uint4Type));
    types->setFields(innerFields,inner,8,4,0);

    // Bytes [4,8) are an intentional structure hole.  inner occupies
    // [8,16), total occupies [16,24).
    progress = types->getTypeStruct("fixture_dcv_progress24");
    vector<TypeField> progressFields;
    progressFields.push_back(TypeField(0,0,"head",uint4Type));
    progressFields.push_back(TypeField(1,8,"inner",inner));
    progressFields.push_back(TypeField(2,16,"total",uint8Type));
    types->setFields(progressFields,progress,24,8,0);

    holed = types->getTypeStruct("fixture_dcv_holed12");
    vector<TypeField> holedFields;
    holedFields.push_back(TypeField(0,0,"head",uint4Type));
    holedFields.push_back(TypeField(1,8,"tail",uint4Type));
    types->setFields(holedFields,holed,12,4,0);

    inners3 = types->getTypeArray(3,inner);
    inners3x2 = types->getTypeArray(2,inners3);

    holder = types->getTypeStruct("fixture_dcv_holder24");
    vector<TypeField> holderFields;
    holderFields.push_back(TypeField(0,0,"elems",inners3));
    types->setFields(holderFields,holder,24,4,0);

    enum8 = types->getTypeEnum("fixture_dcv_enum8");

    pdPointer = types->getTypePointer(8,progress,1);
    holedPointer = types->getTypePointer(8,holed,1);
    arrPointer = types->getTypePointer(8,inners3,1);
    arr2Pointer = types->getTypePointer(8,inners3x2,1);
    holderPointer = types->getTypePointer(8,holder,1);
    uint4Pointer = types->getTypePointer(8,uint4Type,1);
    enumPointer = types->getTypePointer(8,enum8,1);

    // Ephemeral relative pointers from the unnamed parent-pointer overload
    // (type.cc:4016): the virtual dispatch input of the B1 propagation.
    relTotal = types->getTypePointerRel(pdPointer,uint8Type,16);
    relInner = types->getTypePointerRel(pdPointer,inner,8);
    relHole = types->getTypePointerRel(holedPointer,uint4Type,4);
    relFirst = types->getTypePointerRel(pdPointer,uint4Type,0);
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

    // Plain struct descents (TypePointer::downChain, type.cc:1084).
    emitDownchain(types,"pd_field_hit",fixture.pdPointer,16,false);
    emitDownchain(types,"pd_field_inner",fixture.pdPointer,8,false);
    emitDownchain(types,"pd_field_mid",fixture.pdPointer,2,false);
    emitDownchain(types,"pd_hole_null",fixture.pdPointer,5,false);
    emitDownchain(types,"pd_off0",fixture.pdPointer,0,false);
    // off==size boundary: wrap denied returns NULL before any mutation.
    emitDownchain(types,"pd_off_size_nowrap",fixture.pdPointer,24,false);
    // off==size with wrap folds back to zero and returns this pointer.
    emitDownchain(types,"pd_off_size_wrap",fixture.pdPointer,24,true);
    // Negative-encoded offsets (PTRSUB-style deny vs INT_ADD-style wrap).
    emitDownchain(types,"pd_negative_nowrap",fixture.pdPointer,-4,false);
    emitDownchain(types,"pd_negative_wrap",fixture.pdPointer,-4,true);

    // Array descents: element identity, strip vs preserve, nesting.
    emitDownchain(types,"array_elem",fixture.arrPointer,12,false);
    emitDownchain(types,"array_strip_contrast",fixture.holderPointer,0,false);
    emitDownchain(types,"array_preserve_nested",fixture.arr2Pointer,8,false);

    // Two propagateAddIn2Out-style chain steps with carried accumulators:
    // first the array element level, then the struct field level.
    DownchainState step1 =
        emitDownchain(types,"chain_step1",fixture.arrPointer,12,false);
    emitDownchainStep(types,"chain_step2",step1.result,step1.off,false,
                      step1.par,step1.parOff);

    // Hole descent returning NULL with the container still recorded.
    emitDownchain(types,"holed_hole_null",fixture.holedPointer,6,false);

    // Scalar pointee: base getSubType is NULL; wrap folds to this pointer.
    emitDownchain(types,"uint4_plain_null",fixture.uint4Pointer,0,false);
    emitDownchain(types,"uint4_off_size_wrap",fixture.uint4Pointer,4,true);

    // Enumeration branch (type.cc:1102-1107).
    emitDownchain(types,"enum_into_uint1",fixture.enumPointer,3,false);

    // Relative-pointer dispatch (TypePointerRel::downChain, type.cc:2656).
    emitDownchain(types,"rel_total_field",fixture.relTotal,0,false);
    // relOff==0 && offset!=0 returns the parent pointer and leaves the
    // accumulators untouched (type.cc:2669-2670).
    emitDownchain(types,"rel_recover_parent",fixture.relTotal,-16,false);
    emitDownchain(types,"rel_out_of_parent",fixture.relTotal,8,false);
    // Deferred plain call on the relative pointer itself: par = this (rel).
    emitDownchain(types,"rel_defer_field",fixture.relInner,4,false);
    // relOff inside the parent hole: the recursive plain call returns NULL
    // and the rel override passes it through (type.cc:2671, no fallback).
    emitDownchain(types,"rel_tail_null",fixture.relHole,2,false);
    // off==ptrto->getSize() falls out of the deferral guard into the
    // parent-relative path (contrast with rel_defer_field).
    emitDownchain(types,"rel_defer_boundary",fixture.relInner,8,false);
    // Routing discrimination: same scalar ptrto, plain yields NULL while
    // the relative pointer reaches the parent's first field.
    emitDownchain(types,"route_rel_first",fixture.relFirst,0,false);
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
