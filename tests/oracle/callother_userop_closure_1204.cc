/*
 * TYPEOP-CALLOTHER-USEROP-CLOSURE-0001: locked Ghidra 12.0.4 oracle for the
 * PcodeOp -> TypeOpCallother -> Architecture-owned UserOpManage caller
 * closure (typeop.cc:855-873), including the TypeOp base canonical
 * TYPE_UNKNOWN fallback when descriptor metadata is absent
 * (typeop.cc:261-275) and DatatypeUserOp's slot-minus-one input mapping
 * (userop.cc:76-83).
 *
 * Cases:
 *   - memcpy_*:        CALLOTHER op whose slot-0 constant is
 *                      BUILTIN_MEMCPY (a registerBuiltin DatatypeUserOp,
 *                      userop.cc:449-457: out=void*, in0..1=void*,
 *                      in2=int4). outputTypeLocal/inputTypeLocal(1..3)
 *                      return the registered metadata; slot 0 (the index
 *                      constant) and slot 4 (past the fixed inputs) miss
 *                      the metadata and fall back to getBase(size,
 *                      TYPE_UNKNOWN); Varnode::getLocalType observes the
 *                      same closure from both the def side (output
 *                      varnode) and the reader side (slot-1 input
 *                      varnode).
 *   - metadataless_*:  CALLOTHER op whose slot-0 constant selects an
 *                      UnspecializedPcodeOp (registered into the
 *                      Architecture-owned manager through the private
 *                      registerOp body). The virtual getOutputLocal/
 *                      getInputLocal return null -> every observation
 *                      resolves through the TypeOp base default.
 *
 * Unregistered CALLOTHER indexes are a null-descriptor dereference in
 * Ghidra (UB before typeop.cc:859) and are therefore not projected; the
 * first free manager slot is located by probing registerOp so the fixture
 * never depends on how many basicops the x86-64 SLEIGH registers.
 */
#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "typeop.hh"
#include "userop.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using namespace std;

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

// One closure observation: resolved type projection plus the blockup
// out-parameter as Varnode::getLocalType callers initialize it (false,
// coreaction.cc:5020). Direct outputTypeLocal/inputTypeLocal observations
// pass false because the TypeOp query cannot touch blockup.
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

// Locate the first free slot of the Architecture-owned manager by probing
// registerOp; collisions with SLEIGH-registered basicops throw (registerOp
// does not take ownership on the exception paths, so the probe deletes the
// candidate itself). The x86-64 SLEIGH registers 1756 userops, so the probe
// cap must reach past that table; the resolved index value itself is never
// projected (the Rust side runs its own fresh-manager index).
int4 firstFreeUseropSlot(Architecture &architecture)

{
  for(int4 ind=0;ind<4096;++ind) {
    UserPcodeOp *candidate = new UnspecializedPcodeOp("metadataless",&architecture,ind);
    try {
      registerOp(architecture.userops,candidate);
      return ind;
    }
    catch(const LowlevelError &) {
      delete candidate;
    }
  }
  throw runtime_error("no free userop slot below index 4096");
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
      Address(code,0x500000),"callother_userop_closure_fixture");
  Funcdata *fd = symbol->getFunction();

  cout << "fixture=TYPEOP-CALLOTHER-USEROP-CLOSURE-0001" << '\n';
  cout << "architecture=" << architecture.archid << '\n';

  const int4 ptrSize = factory->getSizeOfPointer();
  const int4 wordSize = architecture.getDefaultDataSpace()->getWordSize();
  Datatype *voidType = factory->getTypeVoid();
  Datatype *voidPointer = factory->getTypePointer(ptrSize,voidType,wordSize);
  Datatype *int4Type = factory->getBase(4,TYPE_INT);
  Datatype *unknown4 = factory->getBase(4,TYPE_UNKNOWN);
  Datatype *unknown2 = factory->getBase(2,TYPE_UNKNOWN);
  Datatype *unknown1 = factory->getBase(1,TYPE_UNKNOWN);

  // Production registration path: registerBuiltin(BUILTIN_MEMCPY) creates the
  // DatatypeUserOp with canonical factory types (userop.cc:449-457).
  UserPcodeOp *memcpyDescriptor =
      architecture.userops.registerBuiltin(UserPcodeOp::BUILTIN_MEMCPY);
  cout << "memcpy.type=" << memcpyDescriptor->getType() << '\n';
  emitBool("memcpy.manager_same",
           architecture.userops.getOp(UserPcodeOp::BUILTIN_MEMCPY) == memcpyDescriptor);
  emitBool("memcpy.out_identity",
           memcpyDescriptor->getOutputLocal((PcodeOp *)0) == voidPointer);

  // Production registration path into the same Architecture-owned manager:
  // an UnspecializedPcodeOp carries no local-type metadata (userop.hh:101/108
  // base virtuals return null).
  const int4 metadatalessIndex = firstFreeUseropSlot(architecture);
  UserPcodeOp *metadataless = architecture.userops.getOp(metadatalessIndex);
  if (metadataless == (UserPcodeOp *)0)
    throw runtime_error("metadataless descriptor missing after registration");
  cout << "metadataless.type=" << metadataless->getType() << '\n';
  emitBool("metadataless.manager_same",
           architecture.userops.getOp(metadatalessIndex) == metadataless);

  // ---- memcpy closure: 5-input CALLOTHER (slot 0 = BUILTIN_MEMCPY index
  // constant; slots 1/2 = 8-byte operands; slot 3 = 4-byte size; slot 4 =
  // 1-byte extra operand so the past-the-end fallback has a real varnode).
  // ----
  PcodeOp *memcpyOp = fd->newOp(5,Address(code,0x500100));
  fd->opSetOpcode(memcpyOp,CPUI_CALLOTHER);
  fd->opSetInput(memcpyOp,fd->newConstant(4,UserPcodeOp::BUILTIN_MEMCPY),0);
  Varnode *readerVn = fd->setInputVarnode(fd->newVarnode(8,reg,0x110));
  fd->opSetInput(memcpyOp,readerVn,1);
  fd->opSetInput(memcpyOp,fd->newVarnode(8,reg,0x111),2);
  fd->opSetInput(memcpyOp,fd->newVarnode(4,reg,0x112),3);
  fd->opSetInput(memcpyOp,fd->newVarnode(1,reg,0x113),4);
  Varnode *memcpyOut = fd->newVarnode(8,reg,0x300);
  fd->opSetOutput(memcpyOp,memcpyOut);

  // Def side through the production caller: Varnode::getLocalType seeds from
  // def->outputTypeLocal() (varnode.cc:910-911) -> TypeOpCallother::
  // getOutputLocal (typeop.cc:865-873) -> DatatypeUserOp::getOutputLocal
  // (userop.cc:70-74) -> the registered void*.
  {
    bool blockup = false;
    Datatype *ct = memcpyOut->getLocalType(blockup);
    emitCase("memcpy_def",ct,blockup);
    emitBool("case.memcpy_def.voidptr_identity",ct == voidPointer);
  }
  // Direct PcodeOp::outputTypeLocal (op.hh:251) on the same op.
  {
    Datatype *ct = memcpyOp->outputTypeLocal();
    emitCase("memcpy_out_direct",ct,false);
    emitBool("case.memcpy_out_direct.voidptr_identity",ct == voidPointer);
  }
  // Slot 0 (the CALLOTHER index constant): DatatypeUserOp::getInputLocal
  // maps slot-1 = -1 -> null (userop.cc:79-82) -> TypeOp base default
  // getBase(4,TYPE_UNKNOWN) (typeop.cc:271-275).
  {
    Datatype *ct = memcpyOp->inputTypeLocal(0);
    emitCase("memcpy_in0",ct,false);
    emitBool("case.memcpy_in0.unknown4_identity",ct == unknown4);
  }
  // Slots 1..3: the registered void*/void*/int4 metadata.
  {
    Datatype *ct = memcpyOp->inputTypeLocal(1);
    emitCase("memcpy_in1",ct,false);
    emitBool("case.memcpy_in1.voidptr_identity",ct == voidPointer);
  }
  {
    Datatype *ct = memcpyOp->inputTypeLocal(2);
    emitCase("memcpy_in2",ct,false);
    emitBool("case.memcpy_in2.voidptr_identity",ct == voidPointer);
  }
  {
    Datatype *ct = memcpyOp->inputTypeLocal(3);
    emitCase("memcpy_in3",ct,false);
    emitBool("case.memcpy_in3.int4_identity",ct == int4Type);
  }
  // Slot 4 is past the fixed inputs: slot-1 = 3 >= inTypes.size() = 3 ->
  // null -> base default over the 1-byte slot-4 varnode.
  {
    Datatype *ct = memcpyOp->inputTypeLocal(4);
    emitCase("memcpy_in4",ct,false);
    emitBool("case.memcpy_in4.unknown1_identity",ct == unknown1);
  }
  // Reader side through the production caller: the slot-1 operand varnode has
  // no def; getLocalType walks its single descendant (varnode.cc:918-932) ->
  // inputTypeLocal(1) -> the registered void*.
  {
    bool blockup = false;
    Datatype *ct = readerVn->getLocalType(blockup);
    emitCase("memcpy_reader",ct,blockup);
    emitBool("case.memcpy_reader.voidptr_identity",ct == voidPointer);
  }

  // ---- metadataless closure: 2-input CALLOTHER whose slot-0 constant picks
  // the UnspecializedPcodeOp. Every query takes the TypeOp base default.
  // ----
  PcodeOp *plainOp = fd->newOp(2,Address(code,0x500200));
  fd->opSetOpcode(plainOp,CPUI_CALLOTHER);
  fd->opSetInput(plainOp,fd->newConstant(4,metadatalessIndex),0);
  Varnode *plainReaderVn = fd->setInputVarnode(fd->newVarnode(4,reg,0x120));
  fd->opSetInput(plainOp,plainReaderVn,1);
  Varnode *plainOut = fd->newVarnode(2,reg,0x310);
  fd->opSetOutput(plainOp,plainOut);

  {
    bool blockup = false;
    Datatype *ct = plainOut->getLocalType(blockup);
    emitCase("metadataless_def",ct,blockup);
    emitBool("case.metadataless_def.unknown2_identity",ct == unknown2);
  }
  {
    Datatype *ct = plainOp->outputTypeLocal();
    emitCase("metadataless_out_direct",ct,false);
    emitBool("case.metadataless_out_direct.unknown2_identity",ct == unknown2);
  }
  {
    Datatype *ct = plainOp->inputTypeLocal(0);
    emitCase("metadataless_in0",ct,false);
    emitBool("case.metadataless_in0.unknown4_identity",ct == unknown4);
  }
  {
    Datatype *ct = plainOp->inputTypeLocal(1);
    emitCase("metadataless_in1",ct,false);
    emitBool("case.metadataless_in1.unknown4_identity",ct == unknown4);
  }
  {
    bool blockup = false;
    Datatype *ct = plainReaderVn->getLocalType(blockup);
    emitCase("metadataless_reader",ct,blockup);
    emitBool("case.metadataless_reader.unknown4_identity",ct == unknown4);
  }
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument(
          "usage: callother_userop_closure_1204 SPEC_DIRECTORY BINARY");
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
