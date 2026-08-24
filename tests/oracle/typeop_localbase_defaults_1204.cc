/*
 * TYPEOP-LOCALBASE-DEFAULTS-0001: locked Ghidra 12.0.4 oracle projection for
 * the TypeOp base-class getOutputLocal/getInputLocal defaults and the
 * TypeOpCall constructor opflags.
 *
 * Every observation goes through PcodeOp::inputTypeLocal/outputTypeLocal, so
 * the Architecture-owned TypeOp table instance is the code under
 * observation. Cases cover:
 *   - opcodes with no get*Local override (BRANCH/BRANCHIND/SEGMENTOP/CAST)
 *     whose local type must be getBase(size,TYPE_UNKNOWN),
 *   - the TypeOpFunc metain/metaout derivation recorded through ZEXT (UINT)
 *     and SEXT (INT),
 *   - the CALL op without a FSPEC annotation (base defaults through
 *     TypeOpCall's explicit TypeOp::get*Local fallbacks) and with a locked
 *     parameter (D1 regression),
 *   - non-standard operand sizes (3 bytes) through TypeFactory::getBase,
 *   - the TypeOpCall constructor opflags bit for bit.
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

// One input-local observation: inputTypeLocal(slot) must be
// getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN) for base-default opcodes.
void emitInputCase(const string &name,PcodeOp *op,int4 slot,TypeFactory *factory)

{
  Datatype *actual = op->inputTypeLocal(slot);
  Datatype *repeat = op->inputTypeLocal(slot);
  Datatype *fallback = factory->getBase(op->getIn(slot)->getSize(),TYPE_UNKNOWN);
  cout << "case." << name << ".slot=" << slot << '\n';
  cout << "case." << name << ".operand_size=" << op->getIn(slot)->getSize() << '\n';
  cout << "case." << name << ".result_type=" << typeToken(actual) << '\n';
  cout << "case." << name << ".result_meta=" << static_cast<int4>(actual->getMetatype()) << '\n';
  cout << "case." << name << ".result_size=" << actual->getSize() << '\n';
  emitBool("case." + name + ".base_identity",actual == fallback);
  emitBool("case." + name + ".repeat_identity",actual == repeat);
}

// One output-local observation: outputTypeLocal() must be
// getBase(op->getOut()->getSize(),TYPE_UNKNOWN) for base-default opcodes.
void emitOutputCase(const string &name,PcodeOp *op,TypeFactory *factory)

{
  Datatype *actual = op->outputTypeLocal();
  Datatype *repeat = op->outputTypeLocal();
  Datatype *fallback = factory->getBase(op->getOut()->getSize(),TYPE_UNKNOWN);
  cout << "case." << name << ".slot=-1" << '\n';
  cout << "case." << name << ".operand_size=" << op->getOut()->getSize() << '\n';
  cout << "case." << name << ".result_type=" << typeToken(actual) << '\n';
  cout << "case." << name << ".result_meta=" << static_cast<int4>(actual->getMetatype()) << '\n';
  cout << "case." << name << ".result_size=" << actual->getSize() << '\n';
  emitBool("case." + name + ".base_identity",actual == fallback);
  emitBool("case." + name + ".repeat_identity",actual == repeat);
}

// ZEXT/SEXT record the TypeOpFunc metain/metaout derivation: the input local
// is getBase(inSize,metain) and the output local getBase(outSize,metaout),
// with metain/metaout=TYPE_UINT for ZEXT and TYPE_INT for SEXT (typeop.cc
// :1116/:1142 constructors; selectJavaOperators can retune them).
void emitMetatypeCase(const string &name,PcodeOp *op,int4 slot,type_metatype meta,
                      TypeFactory *factory)

{
  Datatype *actual = (slot < 0) ? op->outputTypeLocal() : op->inputTypeLocal(slot);
  int4 size = (slot < 0) ? op->getOut()->getSize() : op->getIn(slot)->getSize();
  Datatype *metaBase = factory->getBase(size,meta);
  Datatype *unknownBase = factory->getBase(size,TYPE_UNKNOWN);
  cout << "case." << name << ".slot=" << slot << '\n';
  cout << "case." << name << ".operand_size=" << size << '\n';
  cout << "case." << name << ".result_type=" << typeToken(actual) << '\n';
  cout << "case." << name << ".result_meta=" << static_cast<int4>(actual->getMetatype()) << '\n';
  cout << "case." << name << ".result_size=" << actual->getSize() << '\n';
  emitBool("case." + name + ".meta_identity",actual == metaBase);
  emitBool("case." + name + ".base_identity",actual == unknownBase);
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
      Address(code,0x500000),"typeop_localbase_fixture");
  Funcdata *fd = symbol->getFunction();

  cout << "fixture=TYPEOP-LOCALBASE-DEFAULTS-0001" << '\n';
  cout << "architecture=" << architecture.archid << '\n';

  // ---- TypeOpCall constructor opflags (typeop.cc:663) ----
  TypeOpCall callInst(factory);
  const uint4 callFlags = callInst.getFlags();
  {
    ostringstream stream;
    stream << hex << callFlags;
    cout << "flags.call.hex=" << stream.str() << '\n';
  }
  cout << "flags.call.decimal=" << callFlags << '\n';
  emitBool("flags.call.special",(callFlags & PcodeOp::special) != 0);
  emitBool("flags.call.call_bit",(callFlags & PcodeOp::call) != 0);
  emitBool("flags.call.has_callspec",(callFlags & PcodeOp::has_callspec) != 0);
  emitBool("flags.call.coderef",(callFlags & PcodeOp::coderef) != 0);
  emitBool("flags.call.nocollapse",(callFlags & PcodeOp::nocollapse) != 0);
  emitBool("flags.call.commutative_clear",(callFlags & PcodeOp::commutative) == 0);

  // ---- BRANCH: base defaults on the coderef input (no output) ----
  PcodeOp *branchOp = fd->newOp(1,Address(code,0x500100));
  fd->opSetOpcode(branchOp,CPUI_BRANCH);
  fd->opSetInput(branchOp,fd->newCodeRef(Address(code,0x600100)),0);
  emitInputCase("branch_input0",branchOp,0,factory);

  // ---- BRANCHIND: base defaults on a 4-byte constant input ----
  PcodeOp *branchindOp = fd->newOp(1,Address(code,0x500110));
  fd->opSetOpcode(branchindOp,CPUI_BRANCHIND);
  fd->opSetInput(branchindOp,fd->newConstant(4,0x1234),0);
  emitInputCase("branchind_input0",branchindOp,0,factory);

  // ---- SEGMENTOP: base defaults incl. a non-standard 3-byte operand ----
  PcodeOp *segOp = fd->newOp(3,Address(code,0x500120));
  fd->opSetOpcode(segOp,CPUI_SEGMENTOP);
  fd->opSetInput(segOp,fd->newConstant(4,0),0);
  fd->opSetInput(segOp,fd->newConstant(3,0x112233),1);
  fd->opSetInput(segOp,fd->newConstant(8,0),2);
  fd->opSetOutput(segOp,fd->newVarnode(3,reg,0x300));
  emitInputCase("segment_input1_size3",segOp,1,factory);
  emitOutputCase("segment_output_size3",segOp,factory);

  // ---- CAST: "we don't care what types are cast" -> base defaults ----
  PcodeOp *castOp = fd->newOp(1,Address(code,0x500130));
  fd->opSetOpcode(castOp,CPUI_CAST);
  fd->opSetInput(castOp,fd->newConstant(4,0xaabbccdd),0);
  fd->opSetOutput(castOp,fd->newVarnode(4,reg,0x400));
  emitInputCase("cast_input0",castOp,0,factory);
  emitOutputCase("cast_output",castOp,factory);

  // ---- ZEXT/SEXT: TypeOpFunc metain/metaout derivation (UINT vs INT) ----
  PcodeOp *zextOp = fd->newOp(1,Address(code,0x500140));
  fd->opSetOpcode(zextOp,CPUI_INT_ZEXT);
  fd->opSetInput(zextOp,fd->newConstant(1,0x7f),0);
  fd->opSetOutput(zextOp,fd->newVarnode(4,reg,0x500));
  emitMetatypeCase("zext_input0",zextOp,0,TYPE_UINT,factory);
  emitMetatypeCase("zext_output",zextOp,-1,TYPE_UINT,factory);

  PcodeOp *sextOp = fd->newOp(1,Address(code,0x500150));
  fd->opSetOpcode(sextOp,CPUI_INT_SEXT);
  fd->opSetInput(sextOp,fd->newConstant(1,0x80),0);
  fd->opSetOutput(sextOp,fd->newVarnode(4,reg,0x510));
  emitMetatypeCase("sext_input0",sextOp,0,TYPE_INT,factory);
  emitMetatypeCase("sext_output",sextOp,-1,TYPE_INT,factory);

  // ---- CALL without a FSPEC annotation: TypeOpCall explicit fallbacks ----
  // resolve through the TypeOp base defaults (typeop.cc:696/:729).
  const int4 pointerSize = factory->getSizeOfPointer();
  const int4 wordSize = architecture.getDefaultDataSpace()->getWordSize();
  Datatype *voidType = factory->getTypeVoid();
  Datatype *charType = factory->getTypeChar(factory->getSizeOfChar());
  Datatype *charPointer = factory->getTypePointer(pointerSize,charType,wordSize);

  PcodeOp *plainCallOp = fd->newOp(1,Address(code,0x500160));
  fd->opSetOpcode(plainCallOp,CPUI_CALL);
  // A direct-call target before flow analysis: input 0 is still the coderef.
  fd->opSetInput(plainCallOp,fd->newCodeRef(Address(code,0x600160)),0);
  fd->opSetOutput(plainCallOp,fd->newVarnode(8,reg,0x600));
  emitInputCase("call_input0_nofspec",plainCallOp,0,factory);
  emitOutputCase("call_output_nofspec",plainCallOp,factory);

  // ---- CALL with one locked parameter: D1 behavior must not regress ----
  PcodeOp *callOp = fd->newOp(2,Address(code,0x500170));
  fd->opSetOpcode(callOp,CPUI_CALL);
  fd->opSetInput(callOp,fd->newCodeRef(Address(code,0x600170)),0);
  FuncCallSpecs callspec(callOp);
  callspec.setInternal(architecture.defaultfp,voidType);
  callspec.setParam(0,"locked_ptr",
      pieces(reg,0x00,charPointer,ParameterPieces::typelock));
  fd->opSetInput(callOp,fd->newVarnodeCallSpecs(&callspec),0);
  fd->opSetInput(callOp,fd->newConstant(8,0x7180),1);
  {
    Datatype *actual = callOp->inputTypeLocal(1);
    Datatype *repeat = callOp->inputTypeLocal(1);
    Datatype *fallback = factory->getBase(8,TYPE_UNKNOWN);
    cout << "case.call_input1_locked.slot=1" << '\n';
    cout << "case.call_input1_locked.operand_size=8" << '\n';
    cout << "case.call_input1_locked.result_type=" << typeToken(actual) << '\n';
    cout << "case.call_input1_locked.result_meta="
         << static_cast<int4>(actual->getMetatype()) << '\n';
    cout << "case.call_input1_locked.result_size=" << actual->getSize() << '\n';
    emitBool("case.call_input1_locked.param_identity",actual == charPointer);
    emitBool("case.call_input1_locked.base_identity",actual == fallback);
    emitBool("case.call_input1_locked.repeat_identity",actual == repeat);
  }
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument("usage: typeop_localbase_defaults_1204 SPEC_DIRECTORY BINARY");
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
