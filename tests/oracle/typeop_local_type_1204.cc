/*
 * TYPEOP-LOCALTYPE-DISPATCH-0001: locked Ghidra 12.0.4 oracle projection for
 * TypeOpCall::getInputLocal.
 *
 * This fixture constructs one real FuncCallSpecs object, encodes it through
 * Funcdata::newVarnodeCallSpecs, and invokes PcodeOp::inputTypeLocal so the
 * unmodified Architecture-owned TypeOpCall is the code under observation.
 * It records FSPEC pointer aliasing, the same numeric offset in a non-FSPEC
 * space, slot-to-parameter indexing, per-parameter lock/this flags, size and
 * void guards, and canonical TypeFactory pointer identity.
 */
#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "typeop.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using namespace std;

string typeToken(const Datatype *ct)

{
  ostringstream stream;
  ct->printRaw(stream);
  return stream.str();
}

void emitBool(const string &key,bool value)

{
  cout << key << '=' << (value ? 1 : 0) << '\n';
}

void emitCase(const string &name,PcodeOp *op,int4 slot,Datatype *expected,
              ProtoParameter *param,TypeFactory *factory)

{
  Datatype *actual = op->inputTypeLocal(slot);
  Datatype *repeat = op->inputTypeLocal(slot);
  Datatype *fallback = factory->getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN);
  cout << "case." << name << ".slot=" << slot << '\n';
  cout << "case." << name << ".input_size=" << op->getIn(slot)->getSize() << '\n';
  cout << "case." << name << ".param_present=" << (param != (ProtoParameter *)0 ? 1 : 0) << '\n';
  cout << "case." << name << ".param_locked="
       << (param != (ProtoParameter *)0 && param->isTypeLocked() ? 1 : 0) << '\n';
  cout << "case." << name << ".param_this="
       << (param != (ProtoParameter *)0 && param->isThisPointer() ? 1 : 0) << '\n';
  cout << "case." << name << ".result_type=" << typeToken(actual) << '\n';
  cout << "case." << name << ".result_meta=" << static_cast<int4>(actual->getMetatype()) << '\n';
  cout << "case." << name << ".result_size=" << actual->getSize() << '\n';
  emitBool("case." + name + ".expected_identity",actual == expected);
  emitBool("case." + name + ".param_identity",
      param != (ProtoParameter *)0 && actual == param->getType());
  emitBool("case." + name + ".fallback_identity",actual == fallback);
  emitBool("case." + name + ".repeat_identity",actual == repeat);
}

ParameterPieces pieces(AddrSpace *space,uintb offset,Datatype *type,uint4 flags)

{
  ParameterPieces result;
  result.addr = Address(space,offset);
  result.type = type;
  result.flags = flags;
  return result;
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths(1,specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary,"default",&cerr);
  DocumentStorage store;
  architecture.init(store);
  if (architecture.archid != "x86:LE:64:default:gcc")
    throw runtime_error("runtime architecture/compiler drifted: " + architecture.archid);

  TypeFactory *factory = architecture.types;
  AddrSpace *code = architecture.getDefaultCodeSpace();
  AddrSpace *reg = architecture.getSpaceByName("register");
  if (factory == (TypeFactory *)0 || code == (AddrSpace *)0 || reg == (AddrSpace *)0)
    throw runtime_error("required architecture service missing");

  Scope *global = architecture.symboltab->getGlobalScope();
  FunctionSymbol *symbol = global->addFunction(
      Address(code,0x500000),"typeop_call_local_fixture");
  Funcdata *fd = symbol->getFunction();

  const int4 pointerSize = factory->getSizeOfPointer();
  const int4 wordSize = architecture.getDefaultDataSpace()->getWordSize();
  Datatype *voidType = factory->getTypeVoid();
  Datatype *charType = factory->getTypeChar(factory->getSizeOfChar());
  Datatype *charPointer = factory->getTypePointer(pointerSize,charType,wordSize);
  Datatype *int4Type = factory->getBase(4,TYPE_INT);
  Datatype *uint8Type = factory->getBase(8,TYPE_UINT);
  Datatype *oversizeType = factory->getTypeArray(2,uint8Type);
  TypeStruct *objectType = factory->getTypeStruct("typeop_call_fixture_object");
  Datatype *objectPointer = factory->getTypePointer(pointerSize,objectType,wordSize);
  Datatype *plainPointer = factory->getTypePointer(pointerSize,int4Type,wordSize);

  PcodeOp *callOp = fd->newOp(9,Address(code,0x500010));
  fd->opSetOpcode(callOp,CPUI_CALL);
  // FuncCallSpecs::FuncCallSpecs reads the original direct-call target from
  // input 0 before flow replaces that input with the FSPEC annotation.
  fd->opSetInput(callOp,fd->newCodeRef(Address(code,0x600000)),0);
  FuncCallSpecs callspec(callOp);
  callspec.setInternal(architecture.defaultfp,voidType);
  callspec.setParam(0,"locked_ptr",
      pieces(reg,0x00,charPointer,ParameterPieces::typelock));
  callspec.setParam(1,"locked_small",
      pieces(reg,0x08,int4Type,ParameterPieces::typelock));
  callspec.setParam(2,"unlocked_int",
      pieces(reg,0x10,int4Type,0));
  callspec.setParam(3,"locked_void",
      pieces(reg,0x18,voidType,ParameterPieces::typelock));
  callspec.setParam(4,"locked_oversize",
      pieces(reg,0x20,oversizeType,ParameterPieces::typelock));
  callspec.setParam(5,"this_struct",
      pieces(reg,0x28,objectPointer,ParameterPieces::isthis));
  callspec.setParam(6,"this_plain",
      pieces(reg,0x30,plainPointer,ParameterPieces::isthis));

  Varnode *fspecPrimary = fd->newVarnodeCallSpecs(&callspec);
  Varnode *fspecAlias = fd->newVarnodeCallSpecs(&callspec);
  const uintb callspecEncoding = (uintb)(uintp)&callspec;
  Varnode *constantMimic = fd->newConstant(sizeof(&callspec),callspecEncoding);
  fd->opSetInput(callOp,fspecPrimary,0);
  fd->opSetInput(callOp,fd->newConstant(8,0x7180),1);
  fd->opSetInput(callOp,fd->newConstant(8,0x11223344),2);
  fd->opSetInput(callOp,fd->newConstant(4,0x55667788),3);
  fd->opSetInput(callOp,fd->newConstant(8,0),4);
  fd->opSetInput(callOp,fd->newConstant(8,0x99a8),5);
  fd->opSetInput(callOp,fd->newConstant(8,0xc1d8),6);
  fd->opSetInput(callOp,fd->newConstant(8,0xea40),7);
  fd->opSetInput(callOp,fd->newConstant(1,0x7f),8);

  cout << "fixture=TYPEOP-LOCALTYPE-DISPATCH-0001.call_input" << '\n';
  cout << "architecture=" << architecture.archid << '\n';
  cout << "representation.fspec_name=" << fspecPrimary->getSpace()->getName() << '\n';
  cout << "representation.fspec_type="
       << static_cast<int4>(fspecPrimary->getSpace()->getType()) << '\n';
  cout << "representation.constant_type="
       << static_cast<int4>(constantMimic->getSpace()->getType()) << '\n';
  emitBool("representation.primary_roundtrip",
      FuncCallSpecs::getFspecFromConst(fspecPrimary->getAddr()) == &callspec);
  emitBool("representation.alias_roundtrip",
      FuncCallSpecs::getFspecFromConst(fspecAlias->getAddr()) == &callspec);
  emitBool("representation.alias_distinct_varnode",fspecPrimary != fspecAlias);
  emitBool("representation.alias_same_address",fspecPrimary->getAddr() == fspecAlias->getAddr());
  emitBool("representation.constant_same_offset",
      constantMimic->getOffset() == fspecPrimary->getOffset());
  emitBool("representation.constant_not_fspec",
      constantMimic->getSpace()->getType() != IPTR_FSPEC);

  emitCase("slot0_target",callOp,0,
      factory->getBase(fspecPrimary->getSize(),TYPE_UNKNOWN),(ProtoParameter *)0,factory);
  emitCase("locked_ptr_equal",callOp,1,charPointer,callspec.getParam(0),factory);
  emitCase("locked_small_fits",callOp,2,int4Type,callspec.getParam(1),factory);
  emitCase("unlocked_param",callOp,3,
      factory->getBase(4,TYPE_UNKNOWN),callspec.getParam(2),factory);
  emitCase("locked_void",callOp,4,
      factory->getBase(8,TYPE_UNKNOWN),callspec.getParam(3),factory);
  emitCase("locked_oversize",callOp,5,
      factory->getBase(8,TYPE_UNKNOWN),callspec.getParam(4),factory);
  emitCase("unlocked_this_struct",callOp,6,objectPointer,callspec.getParam(5),factory);
  emitCase("unlocked_this_plain",callOp,7,
      factory->getBase(8,TYPE_UNKNOWN),callspec.getParam(6),factory);
  emitCase("missing_param",callOp,8,
      factory->getBase(1,TYPE_UNKNOWN),(ProtoParameter *)0,factory);

  callspec.getParam(0)->setTypeLock(false);
  emitCase("locked_ptr_after_unlock",callOp,1,
      factory->getBase(8,TYPE_UNKNOWN),callspec.getParam(0),factory);
  callspec.getParam(0)->setTypeLock(true);
  emitCase("locked_ptr_after_relock",callOp,1,charPointer,callspec.getParam(0),factory);

  fd->opSetInput(callOp,fspecAlias,0);
  emitCase("fspec_alias",callOp,1,charPointer,callspec.getParam(0),factory);
  fd->opSetInput(callOp,constantMimic,0);
  emitCase("constant_same_offset",callOp,1,
      factory->getBase(8,TYPE_UNKNOWN),callspec.getParam(0),factory);
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument("usage: typeop_local_type_1204 SPEC_DIRECTORY BINARY");
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
