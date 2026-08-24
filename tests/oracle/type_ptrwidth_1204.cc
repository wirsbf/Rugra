/* TYPE-PTRWIDTH-PTRSUB-0001: locked Ghidra propagateFromPointer width cases. */
#include "typeop.hh"

#include <iostream>

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
  Varnode progressSource(8,Address(),&progressPtr);
  Varnode int4Source(8,Address(),&int4Ptr);
  Varnode value16(16,Address(),&value16Type);
  Varnode value4(4,Address(),&value4Type);
  Varnode value32(32,Address(),&value32Type);
  TypeOpLoad load((TypeFactory *)0);
  TypeOpStore store((TypeFactory *)0);

  Datatype *load16 = load.propagateType(progressSource.getType(),(PcodeOp *)0,
                                        &progressSource,&value16,1,-1);
  Datatype *load4 = load.propagateType(progressSource.getType(),(PcodeOp *)0,
                                       &progressSource,&value4,1,-1);
  Datatype *load32 = load.propagateType(progressSource.getType(),(PcodeOp *)0,
                                        &progressSource,&value32,1,-1);
  Datatype *store16 = store.propagateType(progressSource.getType(),(PcodeOp *)0,
                                          &progressSource,&value16,1,2);
  Datatype *store4 = store.propagateType(progressSource.getType(),(PcodeOp *)0,
                                         &progressSource,&value4,1,2);
  Datatype *store32 = store.propagateType(progressSource.getType(),(PcodeOp *)0,
                                          &progressSource,&value32,1,2);
  Datatype *loadInt4 = load.propagateType(int4Source.getType(),(PcodeOp *)0,
                                          &int4Source,&value4,1,-1);

  std::cout << "fixture=TYPE-PTRWIDTH-PTRSUB-0001\n"
            << "load_struct32_deref16_null=" << (load16 == (Datatype *)0) << '\n'
            << "load_struct32_deref4_null=" << (load4 == (Datatype *)0) << '\n'
            << "load_struct32_deref32_identity=" << (load32 == &progress) << '\n'
            << "store_struct32_deref16_null=" << (store16 == (Datatype *)0) << '\n'
            << "store_struct32_deref4_null=" << (store4 == (Datatype *)0) << '\n'
            << "store_struct32_deref32_identity=" << (store32 == &progress) << '\n'
            << "load_int4_deref4_identity=" << (loadInt4 == &int4Type) << '\n'
            << "source_type_alias=" << (progressSource.getType() == &progressPtr) << '\n';
  return 0;
}
