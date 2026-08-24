/* TYPE-PTRWIDTH-PTRSUB-0001: locked Ghidra propagateFromPointer width cases. */
#include <bits/stdc++.h>

// Test-only access lets the fixture build the same attached PcodeOp/Varnode
// alias graph that production Funcdata builds through friend-only setters.
#define private public
#include "op.hh"
#undef private

using namespace ghidra;

int main(void)
{
  TypeBase progress(32,TYPE_STRUCT,"ProgressData");
  TypePointer progressPtr(8,&progress,1);
  TypeBase int4Type(4,TYPE_INT,"int4");
  TypePointer int4Ptr(8,&int4Type,1);
  TypeBase value16Type(16,TYPE_UNKNOWN,"value16");
  TypeBase value4Type(4,TYPE_UNKNOWN,"value4");
  TypeBase value32Type(32,TYPE_UNKNOWN,"value32");
  TypeBase spaceType(8,TYPE_UNKNOWN,"space");
  Varnode progressSource(8,Address(),&progressPtr);
  Varnode int4Source(8,Address(),&int4Ptr);
  Varnode value16(16,Address(),&value16Type);
  Varnode value4(4,Address(),&value4Type);
  Varnode value32(32,Address(),&value32Type);
  Varnode spacebaseOutput(4,Address(),&int4Type);
  spacebaseOutput.setFlags(Varnode::spacebase);
  Varnode spaceConstant(8,Address(),&spaceType);
  TypeOpLoad load((TypeFactory *)0);
  TypeOpStore store((TypeFactory *)0);

  PcodeOp loadOp(2,SeqNum(Address(),0));
  loadOp.setInput(&spaceConstant,0);
  loadOp.setInput(&progressSource,1);
  loadOp.setOutput(&value16);
  Datatype *load16 = load.propagateType(progressSource.getType(),&loadOp,
                                        loadOp.getIn(1),loadOp.getOut(),1,-1);
  loadOp.setOutput(&value4);
  Datatype *load4 = load.propagateType(progressSource.getType(),&loadOp,
                                       loadOp.getIn(1),loadOp.getOut(),1,-1);
  loadOp.setOutput(&value32);
  Datatype *load32 = load.propagateType(progressSource.getType(),&loadOp,
                                        loadOp.getIn(1),loadOp.getOut(),1,-1);

  PcodeOp store16Op(3,SeqNum(Address(),1));
  store16Op.setInput(&spaceConstant,0);
  store16Op.setInput(&progressSource,1);
  store16Op.setInput(&value16,2);
  Datatype *store16 = store.propagateType(progressSource.getType(),&store16Op,
                                          store16Op.getIn(1),store16Op.getIn(2),1,2);
  PcodeOp store4Op(3,SeqNum(Address(),2));
  store4Op.setInput(&spaceConstant,0);
  store4Op.setInput(&progressSource,1);
  store4Op.setInput(&value4,2);
  Datatype *store4 = store.propagateType(progressSource.getType(),&store4Op,
                                         store4Op.getIn(1),store4Op.getIn(2),1,2);
  PcodeOp store32Op(3,SeqNum(Address(),3));
  store32Op.setInput(&spaceConstant,0);
  store32Op.setInput(&progressSource,1);
  store32Op.setInput(&value32,2);
  Datatype *store32 = store.propagateType(progressSource.getType(),&store32Op,
                                          store32Op.getIn(1),store32Op.getIn(2),1,2);

  loadOp.setInput(&int4Source,1);
  loadOp.setOutput(&value4);
  Datatype *loadInt4 = load.propagateType(int4Source.getType(),&loadOp,
                                          loadOp.getIn(1),loadOp.getOut(),1,-1);

  PcodeOp spacebaseLoadOp(2,SeqNum(Address(),4));
  spacebaseLoadOp.setInput(&spaceConstant,0);
  spacebaseLoadOp.setInput(&int4Source,1);
  spacebaseLoadOp.setOutput(&spacebaseOutput);
  Datatype *loadSpacebase = load.propagateType(spacebaseOutput.getType(),&spacebaseLoadOp,
                                               spacebaseLoadOp.getOut(),
                                               spacebaseLoadOp.getIn(1),-1,1);

  std::cout << "fixture=TYPE-PTRWIDTH-PTRSUB-0001\n"
            << "load_struct32_deref16_null=" << (load16 == (Datatype *)0) << '\n'
            << "load_struct32_deref4_null=" << (load4 == (Datatype *)0) << '\n'
            << "load_struct32_deref32_identity=" << (load32 == &progress) << '\n'
            << "store_struct32_deref16_null=" << (store16 == (Datatype *)0) << '\n'
            << "store_struct32_deref4_null=" << (store4 == (Datatype *)0) << '\n'
            << "store_struct32_deref32_identity=" << (store32 == &progress) << '\n'
            << "load_int4_deref4_identity=" << (loadInt4 == &int4Type) << '\n'
            << "source_type_alias=" << (progressSource.getType() == &progressPtr) << '\n'
            << "load_args_attached="
            << ((loadOp.getIn(1) == &int4Source) && (loadOp.getOut() == &value4)) << '\n'
            << "store_args_attached="
            << ((store16Op.getIn(1) == &progressSource) &&
                (store16Op.getIn(2) == &value16)) << '\n'
            << "load_spacebase_source_null=" << (loadSpacebase == (Datatype *)0) << '\n'
            << "target_types_unchanged="
            << ((value16.getType() == &value16Type) &&
                (value4.getType() == &value4Type) &&
                (value32.getType() == &value32Type)) << '\n'
            << "shared_space_alias="
            << ((loadOp.getIn(0) == &spaceConstant) &&
                (store16Op.getIn(0) == &spaceConstant) &&
                (store4Op.getIn(0) == &spaceConstant) &&
                (store32Op.getIn(0) == &spaceConstant)) << '\n';
  return 0;
}
