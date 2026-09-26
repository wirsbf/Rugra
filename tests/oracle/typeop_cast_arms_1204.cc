/*
 * WORKPKG-UNMAP-TYPEOP-0001: locked Ghidra 12.0.4 oracle projection for the
 * getInputCast/getOutputToken virtual-dispatch arms.
 *
 * The fixture drives the unmodified Architecture-owned TypeOp objects
 * through `op->getOpcode()->getInputCast/getOutputToken/getOperatorName`
 * for every arm the work package ports:
 *   - ordering comparisons (SLESS/SLESSEQUAL/LESS/LESSEQUAL, cc:1023-1107)
 *   - extensions (ZEXT/SEXT, cc:1131-1165)
 *   - shifts (INT_RIGHT/INT_SRIGHT slot 0 + base slot, cc:1543-1598)
 *   - divide/remainder (DIV/SDIV/REM/SREM, cc:1639-1709)
 *   - FLOAT_INT2FLOAT (absorbZext + care_uint_int, cc:1847-1862/1872-1883)
 *   - PTRADD slot 0 align-size arm (cc:2250-2266)
 *   - never-cast arms (PIECE/SUBPIECE/SEGMENTOP, cc:2057/2136/2420)
 *   - getOutputToken families (shifts cc:1518/1558/1608, PIECE cc:2063,
 *     SUBPIECE cc:2142, SEGMENTOP cc:2414)
 *   - getOperatorName sizes (cc:1122/1148/1340/1356/1372/2048/2127)
 *   - getInputLocal specials (CBRANCH cc:609, INDIRECT cc:1992,
 *     CALLOTHER cc:855)
 * Each case prints a stable key=value record; the Rugra twin must print the
 * identical stream.
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
  if (ct == (const Datatype *)0)
    return "NONE";
  ostringstream stream;
  ct->printRaw(stream);
  return stream.str();
}

void emitCase(const string &name,const Datatype *ct)

{
  cout << "case." << name << ".result_type=" << typeToken(ct) << '\n';
  if (ct != (const Datatype *)0) {
    cout << "case." << name << ".result_meta=" << static_cast<int4>(ct->getMetatype()) << '\n';
    cout << "case." << name << ".result_size=" << dec << ct->getSize() << '\n';
  }
  else {
    cout << "case." << name << ".result_meta=NONE" << '\n';
    cout << "case." << name << ".result_size=NONE" << '\n';
  }
}

/// Create a HighVariable whose derived type is `ct` and attach it to `vn`
/// WITHOUT making `vn` a member. Production merges produce exactly this
/// observable (the read-facing high type differs from the varnode's own
/// type); HighVariable(vn) membership would re-derive from `vn` and hide
/// the curtype!=reqtype arms.
void attachForeignHigh(Varnode *vn,const Datatype *ct)

{
  Varnode *carrier = new Varnode(1,Address(),(Datatype *)0); // detached, typed below
  carrier->updateType(const_cast<Datatype *>(ct),false,false);
  HighVariable *high = new HighVariable(carrier);
  vn->setHigh(high,0);
}

/// Create the normal production observable: the high derives from `vn`'s
/// own instance type.
void attachOwnHigh(Varnode *vn)

{
  HighVariable *high = new HighVariable(vn);
  if (high == (HighVariable *)0)
    throw runtime_error("high attach failed");
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
  AddrSpace *ram = architecture.getDefaultDataSpace();
  if (factory == (TypeFactory *)0 || code == (AddrSpace *)0 || ram == (AddrSpace *)0)
    throw runtime_error("required architecture service missing");

  Scope *global = architecture.symboltab->getGlobalScope();
  FunctionSymbol *symbol = global->addFunction(
      Address(code,0x500000),"typeop_cast_arms_fixture");
  Funcdata *fd = symbol->getFunction();

  CastStrategyC strategy;
  strategy.setTypeFactory(factory);

  const int4 pointerSize = factory->getSizeOfPointer();
  const int4 wordSize = ram->getWordSize();
  Datatype *int4Type = factory->getBase(4,TYPE_INT);
  Datatype *uint4Type = factory->getBase(4,TYPE_UINT);
  Datatype *int1Type = factory->getBase(1,TYPE_INT);
  Datatype *uint1Type = factory->getBase(1,TYPE_UINT);
  Datatype *bool1Type = factory->getBase(1,TYPE_BOOL);
  Datatype *float4Type = factory->getBase(4,TYPE_FLOAT);
  Datatype *charType = factory->getTypeChar(factory->getSizeOfChar());
  Datatype *charPointer = factory->getTypePointer(pointerSize,charType,wordSize);
  Datatype *intPointer = factory->getTypePointer(pointerSize,int4Type,wordSize);

  cout << "fixture=WORKPKG-UNMAP-TYPEOP-0001.cast_arms" << '\n';
  cout << "architecture=" << architecture.archid << '\n';

  // --- Ordering comparisons (cc:1023/1049/1075/1099) ----------------------
  // 4-byte inputs: intPromotionType = NO_PROMOTION (size>=promoteSize), so
  // the plain castStandard(req,cur,TRUE,care_ptr_uint) decision is pinned.
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x500010));
    fd->opSetOpcode(op,CPUI_INT_SLESS);
    Varnode *a = fd->newVarnode(4,Address(ram,0x1000));
    a->updateType(int4Type,false,false);
    attachOwnHigh(a);
    Varnode *b = fd->newVarnode(4,Address(ram,0x1010));
    b->updateType(uint4Type,false,false);
    attachOwnHigh(b);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,b,1);
    fd->opSetOutput(op,fd->newVarnode(1,Address(ram,0x2000)));
    emitCase("sless_slot0_int_cur",op->getOpcode()->getInputCast(op,0,&strategy));
    emitCase("sless_slot1_uint_cur",op->getOpcode()->getInputCast(op,1,&strategy));
  }
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x500020));
    fd->opSetOpcode(op,CPUI_INT_LESSEQUAL);
    Varnode *a = fd->newVarnode(4,Address(ram,0x1020));
    a->updateType(uint4Type,false,false);
    attachOwnHigh(a);
    Varnode *b = fd->newVarnode(4,Address(ram,0x1030));
    b->updateType(int4Type,false,false);
    attachOwnHigh(b);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,b,1);
    fd->opSetOutput(op,fd->newVarnode(1,Address(ram,0x2010)));
    emitCase("lessequal_slot0_uint_cur",op->getOpcode()->getInputCast(op,0,&strategy));
    emitCase("lessequal_slot1_int_cur",op->getOpcode()->getInputCast(op,1,&strategy));
  }
  // 1-byte inputs: intPromotionType = UNKNOWN (unwritten), so
  // checkIntPromotionForCompare forces the inputTypeLocal base.
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x500030));
    fd->opSetOpcode(op,CPUI_INT_SLESS);
    Varnode *a = fd->newVarnode(1,Address(ram,0x1040));
    a->updateType(int1Type,false,false);
    attachOwnHigh(a);
    Varnode *b = fd->newVarnode(1,Address(ram,0x1050));
    b->updateType(bool1Type,false,false);
    attachOwnHigh(b);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,b,1);
    fd->opSetOutput(op,fd->newVarnode(1,Address(ram,0x2020)));
    emitCase("sless_slot0_promotion_forced",op->getOpcode()->getInputCast(op,0,&strategy));
  }

  // --- Extensions (cc:1131 ZEXT / cc:1157 SEXT) ---------------------------
  {
    PcodeOp *op = fd->newOp(1,Address(code,0x500040));
    fd->opSetOpcode(op,CPUI_INT_ZEXT);
    Varnode *a = fd->newVarnode(1,Address(ram,0x1060));
    a->updateType(int1Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetOutput(op,fd->newVarnode(4,Address(ram,0x2030)));
    emitCase("zext_slot0_int1_cur",op->getOpcode()->getInputCast(op,0,&strategy));
  }
  {
    PcodeOp *op = fd->newOp(1,Address(code,0x500050));
    fd->opSetOpcode(op,CPUI_INT_ZEXT);
    Varnode *a = fd->newVarnode(4,Address(ram,0x1070));
    a->updateType(uint4Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetOutput(op,fd->newVarnode(8,Address(ram,0x2040)));
    emitCase("zext_slot0_uint4_cur",op->getOpcode()->getInputCast(op,0,&strategy));
  }
  {
    PcodeOp *op = fd->newOp(1,Address(code,0x500060));
    fd->opSetOpcode(op,CPUI_INT_SEXT);
    Varnode *a = fd->newVarnode(4,Address(ram,0x1080));
    a->updateType(uint4Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetOutput(op,fd->newVarnode(8,Address(ram,0x2050)));
    emitCase("sext_slot0_uint4_cur",op->getOpcode()->getInputCast(op,0,&strategy));
  }

  // --- Shifts (cc:1543 INT_RIGHT / cc:1585 INT_SRIGHT) --------------------
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x500070));
    fd->opSetOpcode(op,CPUI_INT_RIGHT);
    Varnode *a = fd->newVarnode(4,Address(ram,0x1090));
    a->updateType(uint4Type,false,false);
    attachOwnHigh(a);
    Varnode *shiftAmount = fd->newConstant(1,3);
    attachForeignHigh(shiftAmount,int1Type);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,shiftAmount,1);
    fd->opSetOutput(op,fd->newVarnode(4,Address(ram,0x2060)));
    emitCase("right_slot0_uint4_cur",op->getOpcode()->getInputCast(op,0,&strategy));
    emitCase("right_slot1_base_arm",op->getOpcode()->getInputCast(op,1,&strategy));
  }
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x500080));
    fd->opSetOpcode(op,CPUI_INT_SRIGHT);
    Varnode *a = fd->newVarnode(1,Address(ram,0x10a0));
    a->updateType(bool1Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,fd->newConstant(1,2),1);
    fd->opSetOutput(op,fd->newVarnode(1,Address(ram,0x2070)));
    emitCase("sright_slot0_promotion_forced",op->getOpcode()->getInputCast(op,0,&strategy));
  }

  // --- Divide/remainder (cc:1639/1659/1679/1699) --------------------------
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x500090));
    fd->opSetOpcode(op,CPUI_INT_SDIV);
    Varnode *a = fd->newVarnode(4,Address(ram,0x10b0));
    a->updateType(uint4Type,false,false);
    attachOwnHigh(a);
    Varnode *b = fd->newVarnode(4,Address(ram,0x10c0));
    b->updateType(int4Type,false,false);
    attachOwnHigh(b);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,b,1);
    fd->opSetOutput(op,fd->newVarnode(4,Address(ram,0x2080)));
    emitCase("sdiv_slot0_uint_cur",op->getOpcode()->getInputCast(op,0,&strategy));
    emitCase("sdiv_slot1_int_cur",op->getOpcode()->getInputCast(op,1,&strategy));
  }
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x5000a0));
    fd->opSetOpcode(op,CPUI_INT_REM);
    Varnode *a = fd->newVarnode(4,Address(ram,0x10d0));
    a->updateType(uint4Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,fd->newConstant(4,7),1);
    fd->opSetOutput(op,fd->newVarnode(4,Address(ram,0x2090)));
    emitCase("rem_slot0_uint_cur",op->getOpcode()->getInputCast(op,0,&strategy));
  }

  // --- FLOAT_INT2FLOAT (cc:1847 + absorbZext cc:1872) ---------------------
  {
    // Plain: 4-byte int-typed input -> int4 base under int cur is cast-free.
    PcodeOp *op = fd->newOp(1,Address(code,0x5000b0));
    fd->opSetOpcode(op,CPUI_FLOAT_INT2FLOAT);
    Varnode *a = fd->newVarnode(4,Address(ram,0x10e0));
    a->updateType(int4Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetOutput(op,fd->newVarnode(8,Address(ram,0x20a0)));
    emitCase("i2f_slot0_int_cur",op->getOpcode()->getInputCast(op,0,&strategy));
  }
  {
    // uint-typed input: care_uint_int stays TRUE when the varnode's NZMask
    // can carry the high bit -> uint under the int base takes the cast.
    PcodeOp *op = fd->newOp(1,Address(code,0x5000c0));
    fd->opSetOpcode(op,CPUI_FLOAT_INT2FLOAT);
    Varnode *a = fd->newVarnode(4,Address(ram,0x10f0));
    a->updateType(uint4Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetOutput(op,fd->newVarnode(8,Address(ram,0x20b0)));
    emitCase("i2f_slot0_uint_cur",op->getOpcode()->getInputCast(op,0,&strategy));
  }
  {
    // Constant with clear high bit: care_uint_int drops to FALSE, so the
    // uint high type under the int base is cast-free (cc:1856-1860).
    PcodeOp *op = fd->newOp(1,Address(code,0x5000d0));
    fd->opSetOpcode(op,CPUI_FLOAT_INT2FLOAT);
    Varnode *a = fd->newConstant(4,0x7f);
    Varnode *carrier = fd->newVarnode(4,Address(ram,0x1100));
    carrier->updateType(uint4Type,false,false);
    HighVariable *carrierHigh = new HighVariable(carrier);
    a->setHigh(carrierHigh,0);
    fd->opSetInput(op,a,0);
    fd->opSetOutput(op,fd->newVarnode(8,Address(ram,0x20c0)));
    emitCase("i2f_slot0_const_low_highbit",op->getOpcode()->getInputCast(op,0,&strategy));
  }
  {
    // Constant with the high bit set: care stays TRUE.
    PcodeOp *op = fd->newOp(1,Address(code,0x5000e0));
    fd->opSetOpcode(op,CPUI_FLOAT_INT2FLOAT);
    Varnode *a = fd->newConstant(4,0x80000000);
    Varnode *carrier = fd->newVarnode(4,Address(ram,0x1110));
    carrier->updateType(uint4Type,false,false);
    HighVariable *carrierHigh = new HighVariable(carrier);
    a->setHigh(carrierHigh,0);
    fd->opSetInput(op,a,0);
    fd->opSetOutput(op,fd->newVarnode(8,Address(ram,0x20d0)));
    emitCase("i2f_slot0_const_high_highbit",op->getOpcode()->getInputCast(op,0,&strategy));
  }
  {
    // absorbZext: implied INT_ZEXT output feeding the conversion -> no cast.
    PcodeOp *zextOp = fd->newOp(1,Address(code,0x5000f0));
    fd->opSetOpcode(zextOp,CPUI_INT_ZEXT);
    Varnode *zextIn = fd->newVarnode(4,Address(ram,0x1120));
    zextIn->updateType(uint4Type,false,false);
    attachOwnHigh(zextIn);
    Varnode *zextOut = fd->newVarnode(8,Address(ram,0x1130));
    fd->opSetInput(zextOp,zextIn,0);
    fd->opSetOutput(zextOp,zextOut);
    zextOut->setImplied();

    PcodeOp *op = fd->newOp(1,Address(code,0x500100));
    fd->opSetOpcode(op,CPUI_FLOAT_INT2FLOAT);
    fd->opSetInput(op,zextOut,0);
    fd->opSetOutput(op,fd->newVarnode(8,Address(ram,0x20e0)));
    emitCase("i2f_slot0_absorb_zext",op->getOpcode()->getInputCast(op,0,&strategy));
  }

  // --- PTRADD slot 0 (cc:2250-2266) ---------------------------------------
  {
    // vn type int*, high type char*: bases int(alignSize 4) vs char(1)
    // differ -> the varnode type is the cast.
    PcodeOp *op = fd->newOp(3,Address(code,0x500110));
    fd->opSetOpcode(op,CPUI_PTRADD);
    Varnode *a = fd->newVarnode(pointerSize,Address(ram,0x1140));
    a->updateType(intPointer,false,false);
    attachForeignHigh(a,charPointer);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,fd->newConstant(8,2),1);
    fd->opSetInput(op,fd->newConstant(1,4),2);
    fd->opSetOutput(op,fd->newVarnode(pointerSize,Address(ram,0x20f0)));
    emitCase("ptradd_slot0_align_diff",op->getOpcode()->getInputCast(op,0,&strategy));
    // Equal bases cancel the cast.
    Varnode *b = fd->newVarnode(pointerSize,Address(ram,0x1150));
    b->updateType(intPointer,false,false);
    attachForeignHigh(b,intPointer);
    fd->opSetInput(op,b,0);
    emitCase("ptradd_slot0_align_equal",op->getOpcode()->getInputCast(op,0,&strategy));
    // Non-pointer varnode type returns the varnode type (cc:2257).
    Varnode *c = fd->newVarnode(4,Address(ram,0x1160));
    c->updateType(int4Type,false,false);
    attachForeignHigh(c,charPointer);
    fd->opSetInput(op,c,0);
    emitCase("ptradd_slot0_nonptr_vntype",op->getOpcode()->getInputCast(op,0,&strategy));
    // Slot 1 falls to the base arm (cc:2265).
    Varnode *d = fd->newVarnode(pointerSize,Address(ram,0x1170));
    d->updateType(intPointer,false,false);
    attachOwnHigh(d);
    fd->opSetInput(op,d,0);
    Varnode *indexConst = fd->newConstant(8,2);
    attachForeignHigh(indexConst,int4Type);
    fd->opSetInput(op,indexConst,1);
    emitCase("ptradd_slot1_base_arm",op->getOpcode()->getInputCast(op,1,&strategy));
  }

  // --- Never-cast arms (PIECE cc:2057 / SUBPIECE cc:2136 / SEGMENTOP cc:2420)
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x500120));
    fd->opSetOpcode(op,CPUI_PIECE);
    Varnode *a = fd->newVarnode(4,Address(ram,0x1180));
    a->updateType(int4Type,false,false);
    attachOwnHigh(a);
    Varnode *b = fd->newVarnode(4,Address(ram,0x1190));
    b->updateType(uint4Type,false,false);
    attachOwnHigh(b);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,b,1);
    fd->opSetOutput(op,fd->newVarnode(8,Address(ram,0x2100)));
    emitCase("piece_slot0_never",op->getOpcode()->getInputCast(op,0,&strategy));
    emitCase("piece_slot1_never",op->getOpcode()->getInputCast(op,1,&strategy));
  }
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x500130));
    fd->opSetOpcode(op,CPUI_SUBPIECE);
    Varnode *a = fd->newVarnode(8,Address(ram,0x11a0));
    a->updateType(uint4Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,fd->newConstant(1,0),1);
    fd->opSetOutput(op,fd->newVarnode(4,Address(ram,0x2110)));
    emitCase("subpiece_slot0_never",op->getOpcode()->getInputCast(op,0,&strategy));
  }
  {
    PcodeOp *op = fd->newOp(3,Address(code,0x500140));
    fd->opSetOpcode(op,CPUI_SEGMENTOP);
    Varnode *a = fd->newVarnode(pointerSize,Address(ram,0x11b0));
    a->updateType(int4Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,fd->newConstant(8,0),1);
    Varnode *c = fd->newVarnode(pointerSize,Address(ram,0x11c0));
    c->updateType(intPointer,false,false);
    attachOwnHigh(c);
    fd->opSetInput(op,c,2);
    fd->opSetOutput(op,fd->newVarnode(pointerSize,Address(ram,0x2120)));
    emitCase("segment_slot0_never",op->getOpcode()->getInputCast(op,0,&strategy));
    emitCase("segment_slot2_never",op->getOpcode()->getInputCast(op,2,&strategy));
  }

  // --- getOutputToken families --------------------------------------------
  {
    // Shifts (cc:1518/1558/1608): bool demoted to the int base.
    PcodeOp *op = fd->newOp(2,Address(code,0x500150));
    fd->opSetOpcode(op,CPUI_INT_LEFT);
    Varnode *a = fd->newVarnode(1,Address(ram,0x11d0));
    a->updateType(bool1Type,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,fd->newConstant(1,3),1);
    fd->opSetOutput(op,fd->newVarnode(1,Address(ram,0x2130)));
    emitCase("left_token_bool_in",op->getOpcode()->getOutputToken(op,&strategy));
    fd->opSetOpcode(op,CPUI_INT_RIGHT);
    emitCase("right_token_bool_in",op->getOpcode()->getOutputToken(op,&strategy));
    Varnode *b = fd->newVarnode(4,Address(ram,0x11e0));
    b->updateType(int4Type,false,false);
    attachOwnHigh(b);
    fd->opSetInput(op,b,0);
    fd->opSetOutput(op,fd->newVarnode(4,Address(ram,0x2140)));
    emitCase("right_token_int_in",op->getOpcode()->getOutputToken(op,&strategy));
    fd->opSetOpcode(op,CPUI_INT_SRIGHT);
    emitCase("sright_token_int_in",op->getOpcode()->getOutputToken(op,&strategy));
  }
  {
    // PIECE (cc:2063): INT/UINT def-facing output wins; unknown falls to
    // the uint base.
    PcodeOp *op = fd->newOp(2,Address(code,0x500160));
    fd->opSetOpcode(op,CPUI_PIECE);
    Varnode *a = fd->newVarnode(4,Address(ram,0x11f0));
    Varnode *b = fd->newVarnode(4,Address(ram,0x1200));
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,b,1);
    Varnode *out = fd->newVarnode(8,Address(ram,0x2150));
    out->updateType(int4Type,false,false);
    attachForeignHigh(out,int4Type);
    fd->opSetOutput(op,out);
    emitCase("piece_token_int_out",op->getOpcode()->getOutputToken(op,&strategy));
    Varnode *out2 = fd->newVarnode(8,Address(ram,0x2160));
    out2->updateType(float4Type,false,false);
    attachForeignHigh(out2,float4Type);
    fd->opSetOutput(op,out2);
    emitCase("piece_token_float_out",op->getOpcode()->getOutputToken(op,&strategy));
  }
  {
    // SUBPIECE (cc:2142): findTruncation field / def-facing / int base.
    TypeStruct *record = factory->getTypeStruct("typeop_cast_fixture_struct");
    vector<TypeField> fields;
    fields.push_back(TypeField(0,0,"alpha",int4Type));
    fields.push_back(TypeField(1,8,"beta",float4Type));
    factory->setFields(fields,record,16,4,0);

    PcodeOp *op = fd->newOp(2,Address(code,0x500170));
    fd->opSetOpcode(op,CPUI_SUBPIECE);
    Varnode *a = fd->newVarnode(16,Address(ram,0x1210));
    a->updateType(record,false,false);
    attachOwnHigh(a);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,fd->newConstant(1,0),1);
    Varnode *out = fd->newVarnode(4,Address(ram,0x2170));
    attachForeignHigh(out,factory->getBase(4,TYPE_UNKNOWN));
    fd->opSetOutput(op,out);
    emitCase("subpiece_token_struct_field",op->getOpcode()->getOutputToken(op,&strategy));
    // No field at this offset (lsb=4): falls to the def-facing arm; the
    // output reads as the unknown base -> the int base.
    Datatype *xunknown4 = factory->getBase(4,TYPE_UNKNOWN);
    Varnode *outg = fd->newVarnode(4,Address(ram,0x2175));
    attachForeignHigh(outg,xunknown4);
    fd->opSetOutput(op,outg);
    fd->opSetInput(op,fd->newConstant(1,4),1);
    emitCase("subpiece_token_gap_intbase",op->getOpcode()->getOutputToken(op,&strategy));
    // Def-facing float output wins over the int base when no field matches.
    Varnode *outf = fd->newVarnode(4,Address(ram,0x2180));
    outf->updateType(float4Type,false,false);
    attachForeignHigh(outf,float4Type);
    fd->opSetOutput(op,outf);
    emitCase("subpiece_token_deffacing_float",op->getOpcode()->getOutputToken(op,&strategy));
  }
  {
    // SEGMENTOP (cc:2414): the token is in(2)'s read-facing type.
    PcodeOp *op = fd->newOp(3,Address(code,0x500180));
    fd->opSetOpcode(op,CPUI_SEGMENTOP);
    Varnode *a = fd->newVarnode(pointerSize,Address(ram,0x1220));
    Varnode *c = fd->newVarnode(pointerSize,Address(ram,0x1230));
    c->updateType(intPointer,false,false);
    attachOwnHigh(c);
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,fd->newConstant(8,0),1);
    fd->opSetInput(op,c,2);
    fd->opSetOutput(op,fd->newVarnode(pointerSize,Address(ram,0x2190)));
    emitCase("segment_token_in2",op->getOpcode()->getOutputToken(op,&strategy));
  }

  // --- getOperatorName (cc:1122/1148/1340/1356/1372/2048/2127) ------------
  {
    PcodeOp *op = fd->newOp(1,Address(code,0x500190));
    fd->opSetOpcode(op,CPUI_INT_ZEXT);
    Varnode *a = fd->newVarnode(1,Address(ram,0x1240));
    fd->opSetInput(op,a,0);
    Varnode *out = fd->newVarnode(4,Address(ram,0x21a0));
    fd->opSetOutput(op,out);
    cout << "case.zext_name=" << op->getOpcode()->getOperatorName(op) << '\n';
    fd->opSetOpcode(op,CPUI_INT_SEXT);
    cout << "case.sext_name=" << op->getOpcode()->getOperatorName(op) << '\n';
  }
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x5001a0));
    fd->opSetOpcode(op,CPUI_INT_CARRY);
    Varnode *a = fd->newVarnode(4,Address(ram,0x1250));
    Varnode *b = fd->newVarnode(4,Address(ram,0x1260));
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,b,1);
    cout << "case.carry_name=" << op->getOpcode()->getOperatorName(op) << '\n';
    fd->opSetOpcode(op,CPUI_INT_SCARRY);
    cout << "case.scarry_name=" << op->getOpcode()->getOperatorName(op) << '\n';
    fd->opSetOpcode(op,CPUI_INT_SBORROW);
    cout << "case.sborrow_name=" << op->getOpcode()->getOperatorName(op) << '\n';
  }
  {
    PcodeOp *op = fd->newOp(2,Address(code,0x5001b0));
    fd->opSetOpcode(op,CPUI_PIECE);
    Varnode *a = fd->newVarnode(4,Address(ram,0x1270));
    Varnode *b = fd->newVarnode(4,Address(ram,0x1280));
    Varnode *out = fd->newVarnode(8,Address(ram,0x21b0));
    fd->opSetInput(op,a,0);
    fd->opSetInput(op,b,1);
    fd->opSetOutput(op,out);
    cout << "case.piece_name=" << op->getOpcode()->getOperatorName(op) << '\n';
    fd->opSetOpcode(op,CPUI_SUBPIECE);
    fd->opSetInput(op,fd->newConstant(1,0),1);
    cout << "case.subpiece_name=" << op->getOpcode()->getOperatorName(op) << '\n';
  }

  // --- getInputLocal specials (cc:609/1992/855) ----------------------------
  {
    // CBRANCH: slot 1 bool base; slot 0 code pointer worded by the input
    // space.
    PcodeOp *op = fd->newOp(2,Address(code,0x5001c0));
    fd->opSetOpcode(op,CPUI_CBRANCH);
    Varnode *target = fd->newCodeRef(Address(code,0x600000));
    fd->opSetInput(op,target,0);
    Varnode *cond = fd->newVarnode(1,Address(ram,0x1290));
    cond->updateType(bool1Type,false,false);
    attachOwnHigh(cond);
    fd->opSetInput(op,cond,1);
    emitCase("cbranch_local_slot0",op->getOpcode()->getInputLocal(op,0));
    emitCase("cbranch_local_slot1",op->getOpcode()->getInputLocal(op,1));
  }
  {
    // INDIRECT: slot 0 base default; slot 1 code pointer sized by in(0).
    // The referenced op only needs a code-space address (its own shape is
    // irrelevant to the word-size lookup at cc:2000-2002).
    PcodeOp *iopTarget = fd->newOp(1,Address(code,0x600100));
    fd->opSetOpcode(iopTarget,CPUI_STORE);

    PcodeOp *op = fd->newOp(2,Address(code,0x5001d0));
    fd->opSetOpcode(op,CPUI_INDIRECT);
    Varnode *value = fd->newVarnode(4,Address(ram,0x12a0));
    value->updateType(int4Type,false,false);
    attachOwnHigh(value);
    fd->opSetInput(op,value,0);
    fd->opSetInput(op,fd->newVarnodeIop(iopTarget),1);
    emitCase("indirect_local_slot0",op->getOpcode()->getInputLocal(op,0));
    emitCase("indirect_local_slot1",op->getOpcode()->getInputLocal(op,1));
  }
  {
    // CALLOTHER: an unregistered index falls to the base UNKNOWN default
    // for every slot (cc:860-862).
    PcodeOp *op = fd->newOp(2,Address(code,0x5001e0));
    fd->opSetOpcode(op,CPUI_CALLOTHER);
    fd->opSetInput(op,fd->newConstant(1,120),0);
    Varnode *arg = fd->newVarnode(4,Address(ram,0x12b0));
    fd->opSetInput(op,arg,1);
    emitCase("callother_local_slot0",op->getOpcode()->getInputLocal(op,0));
    emitCase("callother_local_slot1",op->getOpcode()->getInputLocal(op,1));
  }
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument("usage: typeop_cast_arms_1204 SPEC_DIRECTORY BINARY");
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
