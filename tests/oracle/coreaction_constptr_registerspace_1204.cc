/*
 * Locked Ghidra 12.0.4 ActionConstantPtr register-space-inference oracle.
 *
 * HTTPDMAIN-F4-WEBTYPE-0001: the x86-64-gcc cspec <global> block carries a
 * REGISTER-space range (<register name="MXCSR"/>), but
 * Architecture::cacheAddrSpaceProperties (architecture.cc:680-683) filters
 * register spaces (delay 0) out of inferPtrSpaces. This fixture pins the two
 * observable consequences on the real production stack (BfdArchitecture over
 * the pinned curl binary with the repo's sleigh_specs):
 *
 *  1. inferptr_spaces — the name list of Architecture::inferPtrSpaces
 *     (architecture.hh:182): ram only, NO register member.
 *  2. constptr_sz8_container — an 8-byte constant whose address resolves
 *     into a global-scope container symbol (Scope::addSymbol,
 *     database.cc:1530) feeding a lone COPY gets converted by
 *     ActionConstantPtr (coreaction.cc:1167) into
 *     PTRSUB(spacebase, offset) via Funcdata::spacebaseConstant
 *     (funcdata.cc:360), with a pointer-typed (charPrint pointee) output.
 *  3. constptr_sz4_container — the SAME address in the httpd flag-web form
 *     (4-byte constant feeding the COPY that stores into the int web):
 *     selectInferSpace (coreaction.cc:1005) rejects every inferPtrSpaces
 *     member (ram demands size == addrSize == 8), so NO conversion happens
 *     — the constant stays a bare const:4 and the COPY survives. This is
 *     the oracle form behind `int iVar3 = 0x17a422` (httpd main); a
 *     register-space member with addrSize 4 would pass the size gate and
 *     mis-type the whole int web char*.
 *  4. constptr_sz8_nomiss — an 8-byte constant with NO container symbol:
 *     isPointer's queryContainer miss (coreaction.cc:1163) leaves the COPY
 *     alone.
 *
 * Observations: per case the COPY op state after the real
 * ActionConstantPtr::apply — opcode, input count, slot-0/slot-1 varnode
 * observations (constants print size+offset; unique offsets are NOT
 * observed — allocation-only temporaries), the output size and the
 * output's data-type metatype + charPrint-pointee flag.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "coreaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "op.hh"
#include "type.hh"
#include "varnode.hh"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

/// The global container symbol's address (bit_transitions >= 3, inside the
/// ram pointer bounds; resolveConstant(ram) is the identity for a plain
/// space).
const uintb SYMBOL_ADDR = 0x4e000;
/// An address with no container symbol (queryContainer miss arm).
const uintb MISS_ADDR = 0x4f001;

string metaName(type_metatype meta)
{
  switch (meta) {
  case TYPE_VOID: return string("void");
  case TYPE_UNKNOWN: return string("unknown");
  case TYPE_INT: return string("int");
  case TYPE_UINT: return string("uint");
  case TYPE_BOOL: return string("bool");
  case TYPE_CODE: return string("code");
  case TYPE_FLOAT: return string("float");
  case TYPE_PTR: return string("ptr");
  case TYPE_ARRAY: return string("array");
  case TYPE_STRUCT: return string("struct");
  case TYPE_SPACEBASE: return string("spacebase");
  default: break;
  }
  return string("other");
}

/// Deterministic opcode spelling shared with the Rust twin (the TypeOp
/// display table is language-dependent; the fixture pins the enum names).
string opcodeName(OpCode opc)
{
  switch (opc) {
  case CPUI_COPY: return string("COPY");
  case CPUI_PTRSUB: return string("PTRSUB");
  case CPUI_INT_EQUAL: return string("INT_EQUAL");
  default: break;
  }
  return string("OTHER");
}

/// Stable observation of one varnode (or '-' for null). Unique-space
/// offsets are deliberately NOT observed (allocation-only temporaries).
string vnState(const Varnode *vn)
{
  if (vn == (const Varnode *)0)
    return string("-");
  ostringstream out;
  if (vn->isConstant())
    out << "const:" << vn->getSize() << ":0x" << std::hex << vn->getOffset() << std::dec;
  else {
    out << vn->getSpace()->getName() << ':' << vn->getSize();
    if (vn->isSpacebase())
      out << ":sb";
  }
  return out.str();
}

/// Stable observation of the output's data-type.
string typeState(const Varnode *vn)
{
  if (vn == (const Varnode *)0)
    return string("-");
  const Datatype *ct = vn->getType();
  ostringstream out;
  out << metaName(ct->getMetatype());
  if (ct->getMetatype() == TYPE_PTR) {
    const Datatype *base = ((const TypePointer *)ct)->getPtrTo();
    out << (base->isCharPrint() ? ":charprint" : ":other");
  }
  return out.str();
}

string opState(const PcodeOp *op)
{
  ostringstream out;
  out << opcodeName(op->code()) << "|ins=" << op->numInput()
      << "|in0=" << vnState(op->getIn(0));
  if (op->numInput() > 1)
    out << "|in1=" << vnState(op->getIn(1));
  const Varnode *outvn = op->getOut();
  out << "|out=" << (outvn == (const Varnode *)0 ? string("-") : vnState(outvn))
      << "|type=" << typeState(outvn);
  return out.str();
}

class Fixture {
public:
  Funcdata &fd;
  BlockBasic *block;

  explicit Fixture(Funcdata &func)
    : fd(func), block((BlockBasic *)0)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    block = graph.newBlockBasic(&fd);
  }

  Varnode *makeInput(int4 size,AddrSpace *spc,uintb offset)
  {
    return fd.setInputVarnode(fd.newVarnode(size,spc,offset));
  }

  PcodeOp *makeOp(OpCode opcode,int4 inputs,int4 outputSize)
  {
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(inputs,Address(codeSpace,0x1000));
    fd.opSetOpcode(op,opcode);
    if (outputSize > 0)
      fd.newUniqueOut(outputSize,op);
    fd.opInsertEnd(op,block);
    return op;
  }
};

/// One constptr case: `COPY(Const(size, addr)) -> out` whose output feeds an
/// INT_EQUAL against a second register input (the httpd flag-web form: the
/// web holds the call return and the bare string-address constant). Runs the
/// REAL ActionConstantPtr::apply and dumps the COPY op state.
void runCase(Funcdata &fd,const string &name,int4 constSize,uintb addr)
{
  fd.clear();
  Fixture fixture(fd);
  AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
  Varnode *other = fixture.makeInput(constSize,registerSpace,0x100);

  PcodeOp *copy = fixture.makeOp(CPUI_COPY,1,constSize);
  fd.opSetInput(copy,fd.newConstant(constSize,addr),0);

  PcodeOp *cmp = fixture.makeOp(CPUI_INT_EQUAL,2,1);
  fd.opSetInput(cmp,copy->getOut(),0);
  fd.opSetInput(cmp,other,1);

  fd.startTypeRecovery();
  ActionConstantPtr action("constptr");
  // The real pipeline resets every Action before first use
  // (ActionDatabase::reset / ActionRestartGroup); the constructor leaves
  // localcount uninitialized, so the fixture must reset explicitly — the
  // same discipline as the action_infertypes fixture.
  action.reset(fd);
  action.apply(fd);

  std::cout << "case=" << name
            << "|result=0"
            << "|op=" << opState(copy) << '\n';
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
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " +
                               architecture.archid);

    // Observation 1: the inference list itself. cacheAddrSpaceProperties
    // (architecture.cc:665-701) keeps the <global> ram range and drops the
    // MXCSR register range (delay-0 filter at architecture.cc:680).
    ostringstream spaces;
    for(int4 i=0;i<(int4)architecture.inferPtrSpaces.size();++i) {
      if (i != 0)
        spaces << ',';
      spaces << architecture.inferPtrSpaces[i]->getName();
    }
    std::cout << "inferptr_spaces=" << spaces.str() << '\n';

    // The container symbol: char[6] "ptemp_sim" at SYMBOL_ADDR in the
    // global scope (Scope::addSymbol, database.cc:1530-1540) — the program
    // data-type path a real string symbol rides on.
    AddrSpace *ram = architecture.getDefaultDataSpace();
    Datatype *chartype = architecture.types->getTypeChar(1);
    Datatype *strtype = architecture.types->getTypeArray(6,chartype);
    Scope *global = architecture.symboltab->getGlobalScope();
    SymbolEntry *entry = global->addSymbol("ptemp_sim",strtype,
                                           Address(ram,SYMBOL_ADDR),Address());
    if (entry == (SymbolEntry *)0 || entry->getAddr().getOffset() != SYMBOL_ADDR)
      throw std::runtime_error("container symbol was not mapped");

    runCase(*fd,"constptr_sz8_container",8,SYMBOL_ADDR);
    runCase(*fd,"constptr_sz4_container",4,SYMBOL_ADDR);
    runCase(*fd,"constptr_sz8_nocontainer",8,MISS_ADDR);
  }
  shutdownDecompilerLibrary();
}

} // namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: coreaction_constptr_registerspace_1204 <sleigh-spec-dir> <binary>\n";
    return 2;
  }
  try {
    run(argv[1],argv[2]);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture failed: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
