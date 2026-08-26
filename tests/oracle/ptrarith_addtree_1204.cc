/*
 * Locked Ghidra 12.0.4 RulePtrArith::applyOp oracle (AddTree family).
 *
 * Every case records the target-relevant structural IR immediately before and
 * after the real rule call: block and op-bank alive/dead order, op lifecycle
 * state (opcode/dead/parent/order/inputs/output), the def-use state of every
 * fixture-tracked and transformation-created Varnode, plus the data-type
 * metatype read facing the rule. Unique-space offsets are represented by
 * stable fixture identities because they are allocation-only temporaries.
 *
 * The five cases pin the RULE-PTRARITH-ADDTREE-0001 activation chain that
 * next_url exercises end to end:
 *   - ptradd8_load          INT_ADD(char**, 0x38) feeding a LOAD pointer slot
 *                           converts to PTRADD(ptr, 7, 8) — the `ppcVar6+7`
 *                           shape of the golden output.
 *   - ptrsub_struct_load    INT_ADD(struct*, field-off) feeding a LOAD
 *                           converts to PTRSUB(ptr, off).
 *   - charpp_nonmult_no_chg a non-multiple constant on a scalar base keeps
 *                           the INT_ADD (valid=false path).
 *   - untyped_base_no_chg   an untyped base never reaches the slot search
 *                           pass (the pre-factory production failure mode).
 *   - recovery_not_started  the hasTypeRecoveryStarted() first guard.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

class Fixture {
  Funcdata &fd;
  BlockBasic *block;
  vector<PcodeOp *> ops;
  map<PcodeOp *,string> opNames;
  vector<Varnode *> varnodes;
  map<Varnode *,string> varnodeNames;
  int4 nextOp;
  int4 nextVarnode;

  void rememberOp(PcodeOp *op,const string &name)
  {
    if (opNames.insert(std::make_pair(op,name)).second)
      ops.push_back(op);
  }

  void rememberVarnode(Varnode *vn,const string &name)
  {
    if (varnodeNames.insert(std::make_pair(vn,name)).second)
      varnodes.push_back(vn);
  }

  string opName(PcodeOp *op) const
  {
    map<PcodeOp *,string>::const_iterator iter = opNames.find(op);
    if (iter == opNames.end())
      throw std::runtime_error("unregistered fixture op");
    return (*iter).second;
  }

  string varnodeName(Varnode *vn) const
  {
    map<Varnode *,string>::const_iterator iter = varnodeNames.find(vn);
    if (iter == varnodeNames.end())
      throw std::runtime_error("unregistered fixture varnode");
    return (*iter).second;
  }

  void discover(void)
  {
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();
        iter!=block->endOp();++iter) {
      if (opNames.find(*iter) == opNames.end()) {
        ostringstream name;
        name << 'n' << nextOp++;
        rememberOp(*iter,name.str());
      }
    }
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();
        iter!=block->endOp();++iter) {
      PcodeOp *op = *iter;
      if (op->getOut() != (Varnode *)0 &&
          varnodeNames.find(op->getOut()) == varnodeNames.end())
        rememberVarnode(op->getOut(),opName(op) + "_out");
      for(int4 slot=0;slot<op->numInput();++slot) {
        Varnode *vn = op->getIn(slot);
        if (varnodeNames.find(vn) == varnodeNames.end()) {
          ostringstream name;
          name << 'g' << nextVarnode++;
          rememberVarnode(vn,name.str());
        }
      }
    }
  }

  string opList(list<PcodeOp *>::const_iterator iter,
                list<PcodeOp *>::const_iterator enditer) const
  {
    ostringstream out;
    bool first = true;
    for(;iter!=enditer;++iter) {
      if (!first) out << ',';
      first = false;
      out << opName(*iter);
    }
    return out.str();
  }

  string blockOrder(void) const
  {
    return opList(block->beginOp(),block->endOp());
  }

  string opState(PcodeOp *op) const
  {
    ostringstream out;
    out << opName(op)
        << "{opc=" << static_cast<int4>(op->code())
        << ",dead=" << op->isDead()
        << ",parent=" << (op->getParent() == block ? block->getIndex() : -1)
        << ",order=" << op->getSeqNum().getOrder()
        << ",inputs=[";
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (slot != 0) out << ',';
      out << varnodeName(op->getIn(slot));
    }
    out << "],output=";
    if (op->getOut() == (Varnode *)0)
      out << '-';
    else
      out << varnodeName(op->getOut());
    out << '}';
    return out.str();
  }

  string typeTag(Varnode *vn) const
  {
    const Datatype *ct = vn->getType();
    if (ct == (const Datatype *)0 || ct->getMetatype() == TYPE_VOID)
      return "void";
    ostringstream out;
    switch(ct->getMetatype()) {
    case TYPE_PTR: out << "ptr"; break;
    case TYPE_STRUCT: out << "struct"; break;
    case TYPE_ARRAY: out << "array"; break;
    case TYPE_INT: out << "int"; break;
    case TYPE_UINT: out << "uint"; break;
    case TYPE_UNKNOWN: out << "unknown"; break;
    default: out << "other"; break;
    }
    out << ':' << ct->getSize();
    return out.str();
  }

  string varnodeState(Varnode *vn) const
  {
    ostringstream out;
    out << varnodeName(vn)
        << "{space=" << vn->getSpace()->getName()
        << ",size=" << vn->getSize()
        << ",offset=";
    if (vn->getSpace()->getType() == IPTR_INTERNAL)
      out << "tmp";
    else
      out << std::hex << vn->getOffset() << std::dec;
    out << ",constant=" << vn->isConstant()
        << ",input=" << vn->isInput()
        << ",written=" << vn->isWritten()
        << ",free=" << vn->isFree()
        << ",def=";
    if (vn->getDef() == (PcodeOp *)0)
      out << '-';
    else
      out << opName(vn->getDef());
    out << ",type=" << typeTag(vn);
    out << ",desc=[";
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();
        iter!=vn->endDescend();++iter) {
      if (!first) out << ',';
      first = false;
      out << opName(*iter) << '.' << (*iter)->getSlot(vn);
    }
    out << "]}";
    return out.str();
  }

public:
  explicit Fixture(Funcdata &func)
    : fd(func), block((BlockBasic *)0), nextOp(0), nextVarnode(0)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    block = graph.newBlockBasic(&fd);
  }

  Varnode *makeInput(const string &name,int4 size,uintb offset)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    if (registerSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires the register space");
    Varnode *vn = fd.setInputVarnode(fd.newVarnode(size,registerSpace,offset));
    rememberVarnode(vn,name);
    return vn;
  }

  Varnode *makeConstant(const string &name,int4 size,uintb value)
  {
    Varnode *vn = fd.newConstant(size,value);
    rememberVarnode(vn,name);
    return vn;
  }

  PcodeOp *makeOp(const string &name,OpCode opcode,int4 inputs,int4 outputSize)
  {
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(inputs,Address(codeSpace,0x1000));
    fd.opSetOpcode(op,opcode);
    rememberOp(op,name);
    if (outputSize > 0) {
      Varnode *outvn = fd.newUniqueOut(outputSize,op);
      rememberVarnode(outvn,name + "_out");
    }
    return op;
  }

  void setInput(PcodeOp *op,Varnode *vn,int4 slot)
  {
    fd.opSetInput(op,vn,slot);
  }

  void insertEnd(PcodeOp *op)
  {
    fd.opInsertEnd(op,block);
  }

  void startTypeRecovery(void)
  {
    fd.startTypeRecovery();
  }

  void dump(const string &caseName,const string &stage,const string &result)
  {
    discover();
    ostringstream opStates;
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=block->beginOp();
        iter!=block->endOp();++iter) {
      if (!first) opStates << ';';
      first = false;
      opStates << opState(*iter);
    }

    ostringstream varnodeStates;
    first = true;
    for(vector<Varnode *>::const_iterator iter=varnodes.begin();
        iter!=varnodes.end();++iter) {
      if (!first) varnodeStates << ';';
      first = false;
      varnodeStates << varnodeState(*iter);
    }

    std::cout << "case=" << caseName
              << "|stage=" << stage
              << "|result=" << result
              << "|block=[" << blockOrder() << ']'
              << "|alive=[" << opList(fd.beginOpAlive(),fd.endOpAlive()) << ']'
              << "|dead=[" << opList(fd.beginOpDead(),fd.endOpDead()) << ']'
              << "|ops=[" << opStates.str() << ']'
              << "|varnodes=[" << varnodeStates.str() << "]\n";
  }
};

/// Build the AddTree shape under test: a typed base pointer input, an
/// INT_ADD with a constant, and a LOAD consuming the INT_ADD output as its
/// pointer (evaluatePointerExpression's res==2 LOAD branch). The LOAD space
/// constant uses the fixed sentinel 1: its value is never consulted by
/// RulePtrArith, and encoding the AddrSpace pointer would make the dump
/// address-layout dependent.
void runAddLoadCase(Funcdata &fd,const string &name,Datatype *baseType,
                    uintb addConstant,int4 loadSize,bool startRecovery)
{
  fd.clear();
  Fixture fixture(fd);
  TypeFactory *types = fd.getArch()->types;
  Datatype *pointerType = types->getTypePointer(baseType->getSize(),baseType,1);

  Varnode *ptr = fixture.makeInput("ptr",8,0x40);
  ptr->updateType(pointerType);
  PcodeOp *add = fixture.makeOp("add",CPUI_INT_ADD,2,8);
  Varnode *constant = fixture.makeConstant("off",8,addConstant);
  PcodeOp *load = fixture.makeOp("load",CPUI_LOAD,2,loadSize);

  fixture.setInput(add,ptr,0);
  fixture.setInput(add,constant,1);
  fixture.setInput(load,fd.newConstant(8,1),0);
  fixture.setInput(load,add->getOut(),1);
  fixture.insertEnd(add);
  fixture.insertEnd(load);
  if (startRecovery)
    fixture.startTypeRecovery();

  fixture.dump(name,"before","na");
  RulePtrArith rule("typerecovery");
  int4 result = rule.applyOp(add,fd);
  fixture.dump(name,"after",std::to_string(result));
}

/// Untyped base: the applyOp pointer-slot search must reject the op before
/// any AddTree analysis (the production pre-factory failure mode).
void runUntypedCase(Funcdata &fd,const string &name)
{
  fd.clear();
  Fixture fixture(fd);
  Datatype *intType = fd.getArch()->types->getBase(8,TYPE_INT);

  Varnode *ptr = fixture.makeInput("ptr",8,0x40);
  ptr->updateType(intType);
  PcodeOp *add = fixture.makeOp("add",CPUI_INT_ADD,2,8);
  Varnode *constant = fixture.makeConstant("off",8,0x38);
  PcodeOp *load = fixture.makeOp("load",CPUI_LOAD,2,8);

  fixture.setInput(add,ptr,0);
  fixture.setInput(add,constant,1);
  fixture.setInput(load,fd.newConstant(8,1),0);
  fixture.setInput(load,add->getOut(),1);
  fixture.insertEnd(add);
  fixture.insertEnd(load);
  fixture.startTypeRecovery();

  fixture.dump(name,"before","na");
  RulePtrArith rule("typerecovery");
  int4 result = rule.applyOp(add,fd);
  fixture.dump(name,"after",std::to_string(result));
}

void run(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw std::runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->getName() != "GetStr" ||
        fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
      throw std::runtime_error("GetStr input identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " +
                               architecture.archid);

    TypeFactory *types = architecture.types;
    TypeStruct *twoField = types->getTypeStruct("PtrarithStruct");
    {
      vector<TypeField> fields;
      Datatype *uint8Type = types->getBase(8,TYPE_UINT);
      fields.push_back(TypeField(0,0,"first",uint8Type));
      fields.push_back(TypeField(1,8,"second",uint8Type));
      types->setFields(fields,twoField,16,8,0);
    }
    Datatype *uint8Base = types->getBase(8,TYPE_UINT);

    // hasTypeRecoveryStarted() first guard: identical shape to the PTRADD
    // case but recovery never starts, so the rule must return 0 untouched.
    runAddLoadCase(*fd,"recovery_not_started",uint8Base,0x38,8,false);
    // Untyped base: slot search rejection.
    runUntypedCase(*fd,"untyped_base_no_chg");
    // char** + 0x38 -> PTRADD(ptr, 7, 8): the next_url `ppcVar6+7` shape.
    runAddLoadCase(*fd,"ptradd8_load",uint8Base,0x38,8,true);
    // struct* + field offset 8 -> PTRSUB(ptr, 8).
    runAddLoadCase(*fd,"ptrsub_struct_load",twoField,8,8,true);
    // char** + 0x3a: non-multiple remainder on a scalar base -> valid=false,
    // INT_ADD must survive untouched.
    runAddLoadCase(*fd,"charpp_nonmult_no_chg",uint8Base,0x3a,8,true);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: ptrarith_addtree_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1],argv[2]);
    return 0;
  }
  catch(const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
