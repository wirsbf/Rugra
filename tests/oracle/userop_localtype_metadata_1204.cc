/*
 * USEROP-LOCALTYPE-METADATA-0001: locked Ghidra 12.0.4 oracle for
 * DatatypeUserOp metadata and UserOpManage registration/query behavior.
 *
 * The projection observes factory pointer identity, slot-minus-one lookup,
 * null-input compaction, descriptor replacement, duplicate builtin identity,
 * and the exact no-mutation state after each registration exception.
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "userop.hh"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace std;
using namespace ghidra;

// C++11 private-member fixture bridge.  UserOpManage::registerOp is private,
// but it is the production function whose ordering must be observed.  Explicit
// template instantiation is the standard compile-time access bridge; the
// fixture invokes the unmodified locked function body.
template<typename Tag,typename Tag::type member>
struct PrivateMemberAccess {
  friend typename Tag::type access(Tag) { return member; }
};

struct RegisterOpTag {
  typedef void (UserOpManage::*type)(UserPcodeOp *);
  friend type access(RegisterOpTag);
};

template struct PrivateMemberAccess<RegisterOpTag,&UserOpManage::registerOp>;

void registerOp(UserOpManage &manager,UserPcodeOp *op)

{
  (manager.*access(RegisterOpTag()))(op);
}

string registerResult(UserOpManage &manager,UserPcodeOp *op)

{
  try {
    registerOp(manager,op);
    return "NO_ERROR";
  }
  catch(const LowlevelError &err) {
    delete op;                 // registerOp did not take ownership on these paths
    return err.explain;
  }
}

string badBuiltinResult(UserOpManage &manager,uint4 id)

{
  try {
    manager.registerBuiltin(id);
    return "NO_ERROR";
  }
  catch(const LowlevelError &err) {
    return err.explain;
  }
}

void emitBool(const string &key,bool value)

{
  cout << key << '=' << (value ? 1 : 0) << '\n';
}

void emitDatatypeBuiltin(Architecture &arch,uint4 id,const string &key,
                         Datatype *expectedOut,Datatype *expectedIn0,
                         Datatype *expectedIn1,Datatype *expectedIn2)

{
  UserPcodeOp *descriptor = arch.userops.registerBuiltin(id);
  cout << key << ".type=" << descriptor->getType() << '\n';
  cout << key << ".index=" << descriptor->getIndex() << '\n';
  emitBool(key + ".manager_same",arch.userops.getOp(id) == descriptor);
  emitBool(key + ".out",descriptor->getOutputLocal((PcodeOp *)0) == expectedOut);
  emitBool(key + ".slot0_null",descriptor->getInputLocal((PcodeOp *)0,0) == (Datatype *)0);
  emitBool(key + ".slot1",descriptor->getInputLocal((PcodeOp *)0,1) == expectedIn0);
  emitBool(key + ".slot2",descriptor->getInputLocal((PcodeOp *)0,2) == expectedIn1);
  emitBool(key + ".slot3",descriptor->getInputLocal((PcodeOp *)0,3) == expectedIn2);
  emitBool(key + ".slot4_null",descriptor->getInputLocal((PcodeOp *)0,4) == (Datatype *)0);
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture arch(binary,"default",&cerr);
  DocumentStorage store;
  arch.init(store);
  if (arch.archid != "x86:LE:64:default:gcc")
    throw runtime_error("runtime architecture/compiler drifted: " + arch.archid);

  TypeFactory *factory = arch.types;
  const int4 pointerSize = factory->getSizeOfPointer();
  const int4 wordSize = arch.getDefaultDataSpace()->getWordSize();
  Datatype *voidType = factory->getTypeVoid();
  Datatype *voidPointer = factory->getTypePointer(pointerSize,voidType,wordSize);
  Datatype *intType = factory->getBase(4,TYPE_INT);
  Datatype *charType = factory->getTypeChar(factory->getSizeOfChar());
  Datatype *charPointer = factory->getTypePointer(pointerSize,charType,wordSize);
  Datatype *wcharType = factory->getTypeChar(factory->getSizeOfWChar());
  Datatype *wcharPointer = factory->getTypePointer(pointerSize,wcharType,wordSize);

  emitDatatypeBuiltin(arch,UserPcodeOp::BUILTIN_MEMCPY,"builtin.memcpy",
      voidPointer,voidPointer,voidPointer,intType);
  UserPcodeOp *memcpyDescriptor = arch.userops.getOp(UserPcodeOp::BUILTIN_MEMCPY);
  UserPcodeOp *memcpyRepeat = arch.userops.registerBuiltin(UserPcodeOp::BUILTIN_MEMCPY);
  emitBool("builtin.memcpy.repeat_same",memcpyRepeat == memcpyDescriptor);
  emitBool("builtin.memcpy.repeat_out",
      memcpyRepeat->getOutputLocal((PcodeOp *)0) == voidPointer);

  emitDatatypeBuiltin(arch,UserPcodeOp::BUILTIN_STRNCPY,"builtin.strncpy",
      charPointer,charPointer,charPointer,intType);
  emitDatatypeBuiltin(arch,UserPcodeOp::BUILTIN_WCSNCPY,"builtin.wcsncpy",
      wcharPointer,wcharPointer,wcharPointer,intType);
  emitBool("builtin.memcpy.stable_after_growth",
      arch.userops.getOp(UserPcodeOp::BUILTIN_MEMCPY) == memcpyDescriptor);

  const uint4 badId = UserPcodeOp::BUILTIN_WCSNCPY + 1;
  cout << "builtin.bad.error=" << badBuiltinResult(arch.userops,badId) << '\n';
  emitBool("builtin.bad.absent",arch.userops.getOp(badId) == (UserPcodeOp *)0);
  emitBool("builtin.memcpy.stable_after_error",
      arch.userops.getOp(UserPcodeOp::BUILTIN_MEMCPY) == memcpyDescriptor);

  UserOpManage manager;
  registerOp(manager,new UnspecializedPcodeOp("typed",&arch,2));
  emitBool("custom.gap0_null",manager.getOp(0) == (UserPcodeOp *)0);
  emitBool("custom.gap1_null",manager.getOp(1) == (UserPcodeOp *)0);
  emitBool("custom.base_out_null",
      manager.getOp(2)->getOutputLocal((PcodeOp *)0) == (Datatype *)0);
  emitBool("custom.base_in_null",
      manager.getOp(2)->getInputLocal((PcodeOp *)0,1) == (Datatype *)0);

  cout << "custom.typed.error=" << registerResult(manager,
      new DatatypeUserOp("typed",&arch,2,voidPointer,
          (Datatype *)0,charType,(Datatype *)0,intType)) << '\n';
  UserPcodeOp *typed = manager.getOp(2);
  cout << "custom.typed.type=" << typed->getType() << '\n';
  emitBool("custom.by_name_same",manager.getOp("typed") == typed);
  emitBool("custom.out",typed->getOutputLocal((PcodeOp *)0) == voidPointer);
  emitBool("custom.slot0_null",typed->getInputLocal((PcodeOp *)0,0) == (Datatype *)0);
  emitBool("custom.slot1_compacted",typed->getInputLocal((PcodeOp *)0,1) == charType);
  emitBool("custom.slot2_compacted",typed->getInputLocal((PcodeOp *)0,2) == intType);
  emitBool("custom.slot3_null",typed->getInputLocal((PcodeOp *)0,3) == (Datatype *)0);

  cout << "custom.replace.error=" << registerResult(manager,
      new DatatypeUserOp("typed",&arch,2,intType,voidType)) << '\n';
  typed = manager.getOp(2);
  emitBool("custom.replace.out",typed->getOutputLocal((PcodeOp *)0) == intType);
  emitBool("custom.replace.slot1",typed->getInputLocal((PcodeOp *)0,1) == voidType);
  emitBool("custom.replace.slot2_null",
      typed->getInputLocal((PcodeOp *)0,2) == (Datatype *)0);

  cout << "custom.same_name_new_index.error=" << registerResult(manager,
      new DatatypeUserOp("typed",&arch,3,voidType,intType)) << '\n';
  emitBool("custom.same_name_new_index.gap_preserved",
      manager.getOp(3) == (UserPcodeOp *)0);
  emitBool("custom.same_name_new_index.old_preserved",
      manager.getOp(2)->getOutputLocal((PcodeOp *)0) == intType);

  cout << "custom.same_index_new_name.error=" << registerResult(manager,
      new DatatypeUserOp("other",&arch,2,voidType,intType)) << '\n';
  emitBool("custom.same_index_new_name.absent",
      manager.getOp("other") == (UserPcodeOp *)0);
  emitBool("custom.same_index_new_name.old_preserved",
      manager.getOp("typed") == manager.getOp(2));

  cout << "custom.negative.error=" << registerResult(manager,
      new DatatypeUserOp("negative",&arch,-1,voidType,intType)) << '\n';
  emitBool("custom.negative.absent",
      manager.getOp("negative") == (UserPcodeOp *)0);

  cout << "custom.missing.error=" << registerResult(manager,
      new DatatypeUserOp("missing",&arch,4,(Datatype *)0)) << '\n';
  emitBool("custom.missing.out_null",
      manager.getOp(4)->getOutputLocal((PcodeOp *)0) == (Datatype *)0);
  emitBool("custom.missing.in_null",
      manager.getOp(4)->getInputLocal((PcodeOp *)0,1) == (Datatype *)0);
  emitBool("custom.error_gap_still_null",manager.getOp(3) == (UserPcodeOp *)0);
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument(
          "usage: userop_localtype_metadata_1204 SPEC_DIRECTORY BINARY");
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
