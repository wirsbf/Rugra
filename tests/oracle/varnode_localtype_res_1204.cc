/*
 * VARNODE-LOCALTYPE-RESOLUTION-0001: locked Ghidra 12.0.4 oracle projection
 * for Varnode::getLocalType (varnode.cc:900-936), including the def-side
 * stop_type_propagation early return (cc:912-914, op flag 0x40) that sets
 * the blockup out-parameter.
 *
 * Cases:
 *   - def_only:      PTRSUB def with no readers -> getBase(4,TYPE_INT),
 *                    blockup stays false.
 *   - def_stop:      same def with setStopTypePropagation() plus an INT_LESS
 *                    reader whose uint4 would win the typeOrder merge -> the
 *                    reader is never consulted (cc:914 early return), blockup
 *                    becomes true.
 *   - def_nostop:    the same graph without the STOP flag -> descendants
 *                    compete, uint4 (SUB_UINT_PLAIN < SUB_INT_PLAIN) wins.
 *   - readers_min:   input varnode read by INT_LESS/INT_SLESS in both
 *                    insertion orders -> uint4 regardless of order.
 *   - ptr_pointee_replace: CALL(char-pointer) then CALL(int4-pointer):
 *                    TypePointer::compare descends into the pointee
 *                    (type.cc:951), int4* is strictly smaller than char* and
 *                    replaces it (cc:929).
 *   - tie_structs:   two distinct empty structures have typeOrder 0
 *                    (type.cc:1742-1780) -> first-encountered survives.
 *   - tie_def_reader_ab/ba: CALL def with a LOCKED output struct vs a
 *                    CALL reader locked to the other struct — the def's
 *                    outputTypeLocal seed (cc:911) competes under the same
 *                    typeOrder tie; cc:929 keeps the incumbent, so the def
 *                    seed survives in BOTH orders (R19 D2 review advice 1:
 *                    def-output-first tie coverage).
 *   - callind_slot0: input varnode read by a CALLIND at slot 0 -> the
 *                    code-pointer type (typeop.cc:752-756), the same branch
 *                    varnode.rs op_input_type_local now delegates to
 *                    TypeOpCallind::getInputLocal.
 *   - path_beats_int: CALL reader (locked char pointer) vs INT_SLESS (int8)
 *                    -> char pointer wins (SUB_PTR < SUB_INT_PLAIN).
 *   - typelock:      type-locked varnode with a union type -> returned
 *                    directly, def/descendants never consulted, blockup
 *                    untouched.
 *   - null_local:    free varnode (no def, no readers) -> throw
 *                    LowlevelError("NULL local type") (cc:933-934).
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

// One getLocalType observation: resolved type projection plus the blockup
// out-parameter the caller initialized to false (coreaction.cc:5020).
void emitCase(const string &name,Datatype *ct,bool blockup)

{
  if (ct != (Datatype *)0) {
    cout << "case." << name << ".result_type=" << typeToken(ct) << '\n';
    cout << "case." << name << ".result_meta=" << static_cast<int4>(ct->getMetatype()) << '\n';
    cout << "case." << name << ".result_size=" << ct->getSize() << '\n';
  }
  else {
    cout << "case." << name << ".result_type=NULL" << '\n';
    cout << "case." << name << ".result_meta=NULL" << '\n';
    cout << "case." << name << ".result_size=NULL" << '\n';
  }
  emitBool("case." + name + ".blockup",blockup);
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
      Address(code,0x500000),"varnode_localtype_res_fixture");
  Funcdata *fd = symbol->getFunction();

  cout << "fixture=VARNODE-LOCALTYPE-RESOLUTION-0001" << '\n';
  cout << "architecture=" << architecture.archid << '\n';

  const int4 wordSize = architecture.getDefaultDataSpace()->getWordSize();
  Datatype *voidType = factory->getTypeVoid();
  Datatype *charType = factory->getTypeChar(factory->getSizeOfChar());
  Datatype *charPointer = factory->getTypePointer(factory->getSizeOfPointer(),charType,wordSize);
  Datatype *int4Type = factory->getBase(4,TYPE_INT);
  Datatype *int8Base = factory->getBase(8,TYPE_INT);
  Datatype *intPointer = factory->getTypePointer(factory->getSizeOfPointer(),int4Type,wordSize);
  Datatype *structA = factory->getTypeStruct("structA");
  Datatype *structB = factory->getTypeStruct("structB");
  Datatype *unionType = factory->getTypeUnion("unionU");

  // ---- def_only: PTRSUB output, no readers (varnode.cc:910-911, 921 loop
  // empty) -> ct stays def->outputTypeLocal() = getBase(4,TYPE_INT)
  // (typeop.cc:2308-2312). ----
  {
    PcodeOp *defOp = fd->newOp(2,Address(code,0x500100));
    fd->opSetOpcode(defOp,CPUI_PTRSUB);
    fd->opSetInput(defOp,fd->newVarnode(8,reg,0x100),0);
    fd->opSetInput(defOp,fd->newConstant(4,0x10),1);
    Varnode *out = fd->newVarnode(4,reg,0x300);
    fd->opSetOutput(defOp,out);
    bool blockup = false;
    Datatype *ct = out->getLocalType(blockup);
    emitCase("def_only",ct,blockup);
    emitBool("case.def_only.int4_identity",ct == int4Type);
    Datatype *repeat = out->getLocalType(blockup);
    emitBool("case.def_only.repeat_identity",ct == repeat);
  }

  // ---- def_stop: PTRSUB def with stop_type_propagation (op.hh:216
  // setStopTypePropagation) + INT_LESS reader whose uint4 inputTypeLocal
  // would beat int4 if consulted. cc:912-914: blockup=true, return ct
  // straight from outputTypeLocal. ----
  {
    PcodeOp *defOp = fd->newOp(2,Address(code,0x500110));
    fd->opSetOpcode(defOp,CPUI_PTRSUB);
    fd->opSetInput(defOp,fd->newVarnode(8,reg,0x110),0);
    fd->opSetInput(defOp,fd->newConstant(4,0x10),1);
    Varnode *out = fd->newVarnode(4,reg,0x310);
    fd->opSetOutput(defOp,out);
    defOp->setStopTypePropagation();

    PcodeOp *reader = fd->newOp(2,Address(code,0x500118));
    fd->opSetOpcode(reader,CPUI_INT_LESS);
    fd->opSetInput(reader,out,0);
    fd->opSetInput(reader,fd->newVarnode(4,reg,0x311),1);

    bool blockup = false;
    Datatype *ct = out->getLocalType(blockup);
    emitCase("def_stop",ct,blockup);
    emitBool("case.def_stop.stops_flag",defOp->stopsTypePropagation());
    emitBool("case.def_stop.int4_identity",ct == int4Type);
    // The reader's uint4 must NOT have replaced the def's int4.
    emitBool("case.def_stop.uint_not_consulted",ct != factory->getBase(4,TYPE_UINT));
  }

  // ---- def_nostop: identical graph without STOP -> descendants compete
  // (cc:921-932): uint4 replaces int4 (0 > uint4->typeOrder(int4): submeta
  // SUB_UINT_PLAIN(16) < SUB_INT_PLAIN(17), type.cc:212-218). ----
  {
    PcodeOp *defOp = fd->newOp(2,Address(code,0x500120));
    fd->opSetOpcode(defOp,CPUI_PTRSUB);
    fd->opSetInput(defOp,fd->newVarnode(8,reg,0x120),0);
    fd->opSetInput(defOp,fd->newConstant(4,0x10),1);
    Varnode *out = fd->newVarnode(4,reg,0x320);
    fd->opSetOutput(defOp,out);

    PcodeOp *reader = fd->newOp(2,Address(code,0x500128));
    fd->opSetOpcode(reader,CPUI_INT_LESS);
    fd->opSetInput(reader,out,0);
    fd->opSetInput(reader,fd->newVarnode(4,reg,0x321),1);

    bool blockup = false;
    Datatype *ct = out->getLocalType(blockup);
    emitCase("def_nostop",ct,blockup);
    emitBool("case.def_nostop.uint_identity",ct == factory->getBase(4,TYPE_UINT));
  }

  // ---- readers_min: input varnode (no def) read by INT_LESS (metain
  // TYPE_UINT, typeop.cc:924 ctor) and INT_SLESS (metain TYPE_INT,
  // typeop.cc:975 ctor) in both insertion orders. ----
  {
    Varnode *vn = fd->setInputVarnode(fd->newVarnode(4,reg,0x330));
    PcodeOp *lessFirst = fd->newOp(2,Address(code,0x500130));
    fd->opSetOpcode(lessFirst,CPUI_INT_LESS);
    fd->opSetInput(lessFirst,vn,0);
    fd->opSetInput(lessFirst,fd->newVarnode(4,reg,0x331),1);
    PcodeOp *slessSecond = fd->newOp(2,Address(code,0x500138));
    fd->opSetOpcode(slessSecond,CPUI_INT_SLESS);
    fd->opSetInput(slessSecond,vn,0);
    fd->opSetInput(slessSecond,fd->newVarnode(4,reg,0x332),1);
    bool blockup = false;
    Datatype *ct = vn->getLocalType(blockup);
    emitCase("readers_min_uint_first",ct,blockup);
    emitBool("case.readers_min_uint_first.uint_identity",ct == factory->getBase(4,TYPE_UINT));
  }
  {
    Varnode *vn = fd->setInputVarnode(fd->newVarnode(4,reg,0x340));
    PcodeOp *slessFirst = fd->newOp(2,Address(code,0x500140));
    fd->opSetOpcode(slessFirst,CPUI_INT_SLESS);
    fd->opSetInput(slessFirst,vn,0);
    fd->opSetInput(slessFirst,fd->newVarnode(4,reg,0x341),1);
    PcodeOp *lessSecond = fd->newOp(2,Address(code,0x500148));
    fd->opSetOpcode(lessSecond,CPUI_INT_LESS);
    fd->opSetInput(lessSecond,vn,0);
    fd->opSetInput(lessSecond,fd->newVarnode(4,reg,0x342),1);
    bool blockup = false;
    Datatype *ct = vn->getLocalType(blockup);
    emitCase("readers_min_int_first",ct,blockup);
    emitBool("case.readers_min_int_first.uint_identity",ct == factory->getBase(4,TYPE_UINT));
  }

  // ---- ptr_pointee_replace: 8-byte input varnode read by CALL(char*) then
  // CALL(int4*). Both pointers are SUB_PTR size 8, but TypePointer::compare
  // descends into the pointee (type.cc:951): int4 (SUB_INT_PLAIN 17) beats
  // char (SUB_INT_CHAR 19), so int4* is STRICTLY smaller and replaces the
  // first-seen char* (cc:929 strict-less-than replacement). ----
  {
    Varnode *vn = fd->setInputVarnode(fd->newVarnode(8,reg,0x350));
    PcodeOp *callA = fd->newOp(2,Address(code,0x500150));
    fd->opSetOpcode(callA,CPUI_CALL);
    fd->opSetInput(callA,fd->newCodeRef(Address(code,0x600150)),0);
    FuncCallSpecs specA(callA);
    specA.setInternal(architecture.defaultfp,voidType);
    specA.setParam(0,"locked_charptr",
                   pieces(reg,0x00,charPointer,ParameterPieces::typelock));
    fd->opSetInput(callA,fd->newVarnodeCallSpecs(&specA),0);
    fd->opSetInput(callA,vn,1);
    PcodeOp *callB = fd->newOp(2,Address(code,0x500158));
    fd->opSetOpcode(callB,CPUI_CALL);
    fd->opSetInput(callB,fd->newCodeRef(Address(code,0x600158)),0);
    FuncCallSpecs specB(callB);
    specB.setInternal(architecture.defaultfp,voidType);
    specB.setParam(0,"locked_intptr",
                   pieces(reg,0x00,intPointer,ParameterPieces::typelock));
    fd->opSetInput(callB,fd->newVarnodeCallSpecs(&specB),0);
    fd->opSetInput(callB,vn,1);
    bool blockup = false;
    Datatype *ct = vn->getLocalType(blockup);
    emitCase("ptr_pointee_replace",ct,blockup);
    emitBool("case.ptr_pointee_replace.intptr_identity",ct == intPointer);
    emitBool("case.ptr_pointee_replace.charptr_replaced",ct != charPointer);
    // int4* is strictly smaller than char* (pointee descent, type.cc:951).
    emitBool("case.ptr_pointee_replace.pointee_descent",
             0 < charPointer->typeOrder(*intPointer));
  }

  // ---- tie_structs_ab / tie_structs_ba: two distinct EMPTY structures
  // (getTypeStruct, size 0, no fields) have TypeStruct::compare == 0 at
  // level 10 (type.cc:1742-1780: equal submeta/size/field-count, no fields
  // to descend) -> a genuine typeOrder tie; cc:929 replaces only on
  // strictly smaller, so the FIRST encountered struct survives. ----
  {
    Varnode *vn = fd->setInputVarnode(fd->newVarnode(8,reg,0x360));
    PcodeOp *callA = fd->newOp(2,Address(code,0x500160));
    fd->opSetOpcode(callA,CPUI_CALL);
    fd->opSetInput(callA,fd->newCodeRef(Address(code,0x600160)),0);
    FuncCallSpecs specA(callA);
    specA.setInternal(architecture.defaultfp,voidType);
    specA.setParam(0,"locked_structa",
                   pieces(reg,0x00,structA,ParameterPieces::typelock));
    fd->opSetInput(callA,fd->newVarnodeCallSpecs(&specA),0);
    fd->opSetInput(callA,vn,1);
    PcodeOp *callB = fd->newOp(2,Address(code,0x500168));
    fd->opSetOpcode(callB,CPUI_CALL);
    fd->opSetInput(callB,fd->newCodeRef(Address(code,0x600168)),0);
    FuncCallSpecs specB(callB);
    specB.setInternal(architecture.defaultfp,voidType);
    specB.setParam(0,"locked_structb",
                   pieces(reg,0x00,structB,ParameterPieces::typelock));
    fd->opSetInput(callB,fd->newVarnodeCallSpecs(&specB),0);
    fd->opSetInput(callB,vn,1);
    bool blockup = false;
    Datatype *ct = vn->getLocalType(blockup);
    emitCase("tie_structs_ab",ct,blockup);
    emitBool("case.tie_structs_ab.structa_identity",ct == structA);
    emitBool("case.tie_structs_ab.tie_typeorder",
             structA->typeOrder(*structB) == 0);
  }
  {
    Varnode *vn = fd->setInputVarnode(fd->newVarnode(8,reg,0x368));
    PcodeOp *callA = fd->newOp(2,Address(code,0x500190));
    fd->opSetOpcode(callA,CPUI_CALL);
    fd->opSetInput(callA,fd->newCodeRef(Address(code,0x600190)),0);
    FuncCallSpecs specA(callA);
    specA.setInternal(architecture.defaultfp,voidType);
    specA.setParam(0,"locked_structb",
                   pieces(reg,0x00,structB,ParameterPieces::typelock));
    fd->opSetInput(callA,fd->newVarnodeCallSpecs(&specA),0);
    fd->opSetInput(callA,vn,1);
    PcodeOp *callB = fd->newOp(2,Address(code,0x500198));
    fd->opSetOpcode(callB,CPUI_CALL);
    fd->opSetInput(callB,fd->newCodeRef(Address(code,0x600198)),0);
    FuncCallSpecs specB(callB);
    specB.setInternal(architecture.defaultfp,voidType);
    specB.setParam(0,"locked_structa",
                   pieces(reg,0x00,structA,ParameterPieces::typelock));
    fd->opSetInput(callB,fd->newVarnodeCallSpecs(&specB),0);
    fd->opSetInput(callB,vn,1);
    bool blockup = false;
    Datatype *ct = vn->getLocalType(blockup);
    emitCase("tie_structs_ba",ct,blockup);
    emitBool("case.tie_structs_ba.structb_identity",ct == structB);
  }

  // ---- tie_def_reader_ab / tie_def_reader_ba: the def is a CALL whose
  // callspec output is typelocked to one empty struct (FuncCallSpecs::
  // setOutput with ParameterPieces::typelock -> TypeOpCall::getOutputLocal
  // returns it, typeop.cc:732-735); the sole reader is a CALL locked to the
  // OTHER empty struct. The def seed (cc:911) and the reader candidate
  // (cc:924) have typeOrder 0; cc:926-927 seeds ct from the def FIRST and
  // cc:929-930 replaces only on strictly smaller, so the DEF seed survives
  // the tie in both orderings — the def-output-first competition structure.
  // ----
  {
    Varnode *out = fd->newVarnode(8,reg,0x3A0);
    PcodeOp *defCall = fd->newOp(1,Address(code,0x5001A0));
    fd->opSetOpcode(defCall,CPUI_CALL);
    fd->opSetInput(defCall,fd->newCodeRef(Address(code,0x6001A0)),0);
    FuncCallSpecs defSpec(defCall);
    defSpec.setInternal(architecture.defaultfp,voidType);
    defSpec.setOutput(pieces(reg,0x00,structA,ParameterPieces::typelock));
    fd->opSetInput(defCall,fd->newVarnodeCallSpecs(&defSpec),0);
    fd->opSetOutput(defCall,out);
    PcodeOp *reader = fd->newOp(2,Address(code,0x5001A8));
    fd->opSetOpcode(reader,CPUI_CALL);
    fd->opSetInput(reader,fd->newCodeRef(Address(code,0x6001A8)),0);
    FuncCallSpecs readerSpec(reader);
    readerSpec.setInternal(architecture.defaultfp,voidType);
    readerSpec.setParam(0,"locked_structb",
                        pieces(reg,0x00,structB,ParameterPieces::typelock));
    fd->opSetInput(reader,fd->newVarnodeCallSpecs(&readerSpec),0);
    fd->opSetInput(reader,out,1);
    bool blockup = false;
    Datatype *ct = out->getLocalType(blockup);
    emitCase("tie_def_reader_ab",ct,blockup);
    emitBool("case.tie_def_reader_ab.def_structa_identity",ct == structA);
    emitBool("case.tie_def_reader_ab.reader_structb_not_winner",ct != structB);
    emitBool("case.tie_def_reader_ab.def_output_locked",defSpec.isOutputLocked());
  }
  {
    Varnode *out = fd->newVarnode(8,reg,0x3B0);
    PcodeOp *defCall = fd->newOp(1,Address(code,0x5001B0));
    fd->opSetOpcode(defCall,CPUI_CALL);
    fd->opSetInput(defCall,fd->newCodeRef(Address(code,0x6001B0)),0);
    FuncCallSpecs defSpec(defCall);
    defSpec.setInternal(architecture.defaultfp,voidType);
    defSpec.setOutput(pieces(reg,0x00,structB,ParameterPieces::typelock));
    fd->opSetInput(defCall,fd->newVarnodeCallSpecs(&defSpec),0);
    fd->opSetOutput(defCall,out);
    PcodeOp *reader = fd->newOp(2,Address(code,0x5001B8));
    fd->opSetOpcode(reader,CPUI_CALL);
    fd->opSetInput(reader,fd->newCodeRef(Address(code,0x6001B8)),0);
    FuncCallSpecs readerSpec(reader);
    readerSpec.setInternal(architecture.defaultfp,voidType);
    readerSpec.setParam(0,"locked_structa",
                        pieces(reg,0x00,structA,ParameterPieces::typelock));
    fd->opSetInput(reader,fd->newVarnodeCallSpecs(&readerSpec),0);
    fd->opSetInput(reader,out,1);
    bool blockup = false;
    Datatype *ct = out->getLocalType(blockup);
    emitCase("tie_def_reader_ba",ct,blockup);
    emitBool("case.tie_def_reader_ba.def_structb_identity",ct == structB);
    emitBool("case.tie_def_reader_ba.reader_structa_not_winner",ct != structA);
    emitBool("case.tie_def_reader_ba.tie_typeorder",
             structA->typeOrder(*structB) == 0);
  }

  // ---- callind_slot0: input varnode read by a CALLIND at slot 0. The
  // indirect-target input resolves through TypeOpCallind::getInputLocal
  // (typeop.cc:752-756): a pointer to the code type, sized by the input and
  // worded by the op's own (code) space. ----
  {
    Varnode *vn = fd->setInputVarnode(fd->newVarnode(8,reg,0x3C0));
    PcodeOp *callind = fd->newOp(1,Address(code,0x5001C0));
    fd->opSetOpcode(callind,CPUI_CALLIND);
    fd->opSetInput(callind,vn,0);
    bool blockup = false;
    Datatype *ct = vn->getLocalType(blockup);
    emitCase("callind_slot0",ct,blockup);
    Datatype *codePointer = factory->getTypePointer(
        vn->getSize(),factory->getTypeCode(),code->getWordSize());
    emitBool("case.callind_slot0.codeptr_identity",ct == codePointer);
  }

  // ---- path_beats_int: CALL reader (locked char*, SUB_PTR) competes with
  // INT_SLESS (int8, SUB_INT_PLAIN) -> the pointer (path) type wins. ----
  {
    Varnode *vn = fd->setInputVarnode(fd->newVarnode(8,reg,0x370));
    PcodeOp *callOp = fd->newOp(2,Address(code,0x500170));
    fd->opSetOpcode(callOp,CPUI_CALL);
    fd->opSetInput(callOp,fd->newCodeRef(Address(code,0x600170)),0);
    FuncCallSpecs spec(callOp);
    spec.setInternal(architecture.defaultfp,voidType);
    spec.setParam(0,"locked_charptr",
                  pieces(reg,0x00,charPointer,ParameterPieces::typelock));
    fd->opSetInput(callOp,fd->newVarnodeCallSpecs(&spec),0);
    fd->opSetInput(callOp,vn,1);
    PcodeOp *sless = fd->newOp(2,Address(code,0x500178));
    fd->opSetOpcode(sless,CPUI_INT_SLESS);
    fd->opSetInput(sless,vn,0);
    fd->opSetInput(sless,fd->newVarnode(8,reg,0x371),1);
    bool blockup = false;
    Datatype *ct = vn->getLocalType(blockup);
    emitCase("path_beats_int",ct,blockup);
    emitBool("case.path_beats_int.charptr_identity",ct == charPointer);
    emitBool("case.path_beats_int.int8_not_winner",ct != int8Base);
  }

  // ---- typelock_union: updateType(union,true,false) locks the union type
  // (varnode.cc:474-489); cc:906-907 returns it directly — the PTRSUB def
  // and the INT_LESS reader below are never consulted. ----
  {
    PcodeOp *defOp = fd->newOp(2,Address(code,0x500180));
    fd->opSetOpcode(defOp,CPUI_PTRSUB);
    fd->opSetInput(defOp,fd->newVarnode(8,reg,0x180),0);
    fd->opSetInput(defOp,fd->newConstant(4,0x10),1);
    Varnode *out = fd->newVarnode(4,reg,0x380);
    fd->opSetOutput(defOp,out);
    out->updateType(unionType,true,false);
    PcodeOp *reader = fd->newOp(2,Address(code,0x500188));
    fd->opSetOpcode(reader,CPUI_INT_LESS);
    fd->opSetInput(reader,out,0);
    fd->opSetInput(reader,fd->newVarnode(4,reg,0x381),1);
    bool blockup = false;
    Datatype *ct = out->getLocalType(blockup);
    emitCase("typelock_union",ct,blockup);
    emitBool("case.typelock_union.identity",ct == unionType);
    emitBool("case.typelock_union.is_locked",out->isTypeLock());
  }

  // ---- null_local_type: free varnode with no def and no readers ->
  // cc:933-934 throw LowlevelError("NULL local type"); blockup stays false.
  // ----
  {
    Varnode *vn = fd->newVarnode(4,reg,0x390);
    bool blockup = false;
    try {
      Datatype *ct = vn->getLocalType(blockup);
      emitCase("null_local_type",ct,blockup);
    }
    catch(const LowlevelError &err) {
      cout << "case.null_local_type.error=" << err.explain << '\n';
      emitBool("case.null_local_type.blockup",blockup);
    }
  }
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument("usage: varnode_localtype_res_1204 SPEC_DIRECTORY BINARY");
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
