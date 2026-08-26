/*
 * B3-COREACTION-CONSTANTPTR-0001 (b): locked Ghidra 12.0.4 oracle
 * projection for ActionConstantPtr::apply — the constant-space iteration,
 * selectInferSpace, isPointer's op/range/bit-form/container gates and the
 * spacebaseConstant PTRSUB/INT_ADD rewrite chain (coreaction.cc:957-1217,
 * funcdata.cc:360-462).
 *
 * Every case builds one consumer op over a manually created constant in the
 * Funcdata of GetStr (the a1 fixture's proven BfdArchitecture host), with
 * the symbol/entry table installed on the real global scope through public
 * Scope::addSymbol / Database::addRange / Database::setPropertyRange paths.
 * apply() runs once through the real locked ActionConstantPtr (an
 * InspectableConstantPtr subclass exposing the protected count), after
 * startTypeRecovery().
 *
 * Discriminating semantics pinned by the case table:
 *   w_7180/w_99a8/w_c1d8     the three invalid-UTF-8 hugehelp alias shapes:
 *                            undefined1 DAT entries, exact hits -> PTRSUB,
 *                            pointer-to-undefined1 output (the `&DAT_*`
 *                            chain coreaction.cc:1210 builds).
 *   w_ea40/w_11270/w_13ad0   the three string-typed hugehelp alias shapes:
 *                            char-array entries -> PTRSUB with
 *                            pointer-to-char output (ruleaction.cc:7366-
 *                            7369's charPrint input).
 *   needexact_mid            a constant landing mid-entry of a non-char
 *                            entry: needexacthit rejects it
 *                            (coreaction.cc:1161-1162); the consumer COPY
 *                            survives and the constant still gets
 *                            setPtrCheck (cc:1208 runs after the search).
 *   chararray_mid            the char-array middle exception
 *                            (coreaction.cc:1153-1159): mid-string constant
 *                            passes with needexacthit=false; extra!=0 gives
 *                            the COPY->INT_ADD(PTRSUB,extra) reuse chain
 *                            (funcdata.cc:382/421-433).
 *   bounds_low               pointerLowerBound rejection (cc:1138).
 *   bitform                  the bit_transitions>=3 rejection (cc:1143).
 *   zero_const / ptrsub_in   the cc:1188 / cc:1203-1204 skips (no PtrCheck
 *                            set — the skip happens before cc:1208).
 *   intadd_spacebase         the cc:1201 skip (other side already a
 *                            spacebase).
 *   call_locked_ptr          the cc:1093-1099 arm: a CALL arg with a locked
 *                            char* parameter type proceeds to a hit.
 *   call_locked_notptr       the rejection: a locked int parameter type is
 *                            "definitely not passing a pointer".
 *   call_no_spec             no callspec registered + infer_pointers
 *                            (cc:1100-1101) — the hugehelp puts shape
 *                            before callspec linking.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "funcdata.hh"
#include "libdecomp.hh"

#include <iomanip>
#include <iostream>
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

class InspectableConstantPtr : public ActionConstantPtr {
public:
  InspectableConstantPtr(void) : ActionConstantPtr("typerecovery") {
    // Action::Action leaves count/lcount uninitialized; perform() normally
    // initializes them. This fixture calls apply() directly.
    count = 0;
    lcount = 0;
  }
  int4 fixtureCount(void) const { return count; }
};

class Fixture {
  Funcdata &fd;
  vector<BlockBasic *> blocks;
  map<BlockBasic *, string> blockNames;
  vector<PcodeOp *> ops;
  map<PcodeOp *, string> opNames;
  vector<Varnode *> varnodes;
  map<Varnode *, string> varnodeNames;

  string opName(PcodeOp *op) const
  {
    if (op == (PcodeOp *)0) return "-";
    map<PcodeOp *,string>::const_iterator iter = opNames.find(op);
    if (iter == opNames.end()) throw std::runtime_error("unknown op");
    return (*iter).second;
  }

  string varnodeName(Varnode *vn) const
  {
    if (vn == (Varnode *)0) return "-";
    map<Varnode *,string>::const_iterator iter = varnodeNames.find(vn);
    if (iter == varnodeNames.end()) return varnode_space_token(vn);
    return (*iter).second;
  }

  static string varnode_space_token(Varnode *vn)
  {
    return vn->getSpace()->getName();
  }

public:
  explicit Fixture(Funcdata &func) : fd(func) {}

  void rememberVarnode(Varnode *vn,const string &name)
  {
    if (varnodeNames.insert(std::make_pair(vn,name)).second)
      varnodes.push_back(vn);
  }

  void rememberOp(PcodeOp *op,const string &name)
  {
    if (opNames.insert(std::make_pair(op,name)).second)
      ops.push_back(op);
  }

  BlockBasic *makeBlock(const string &name)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);
    blocks.push_back(block);
    blockNames.insert(std::make_pair(block,name));
    return block;
  }

  Varnode *makeConstant(const string &name,int4 size,uintb value)
  {
    Varnode *vn = fd.newConstant(size,value);
    rememberVarnode(vn,name);
    return vn;
  }

  Varnode *makeSpacebase(const string &name)
  {
    AddrSpace *stack = fd.getArch()->getSpaceByName("stack");
    Varnode *vn = fd.newSpacebasePtr(stack);
    // The production RSP input varnode carries the spacebase flag (set by
    // Funcdata::spacebase / heritage); pin it so the cc:1201 gate reads
    // the flag in isolation, mirroring the Rust fixture.
    vn->fixtureSetSpacebase();
    rememberVarnode(vn,name);
    return vn;
  }

  PcodeOp *makeOp(const string &name,OpCode opcode,int4 inputs,int4 outputSize,
                  BlockBasic *block)
  {
    PcodeOp *op = fd.newOp(inputs,Address(fd.getArch()->getDefaultCodeSpace(),0x4c20));
    fd.opSetOpcode(op,opcode);
    rememberOp(op,name);
    if (outputSize != 0) {
      Varnode *out = fd.newUniqueOut(outputSize,op);
      rememberVarnode(out,name + "_out");
    }
    fd.opInsertEnd(op,block);
    return op;
  }

  void setInput(PcodeOp *op,Varnode *vn,int4 slot) { fd.opSetInput(op,vn,slot); }

  // One observed op after apply: opcode, inputs (with per-varnode space /
  // offset / size / spacebase / ptrcheck / type metatype / charprint), the
  // output's pointer-target metatype, and the linkSymbolReference answer.
  void dumpOp(const string &caseName,PcodeOp *op)
  {
    ostringstream out;
    // Numeric opcode: the archive's generated opcodes.cc name table is
    // stale (get_opname is off-table), while the enum values are the
    // shared contract with the Rust side.
    out << "case=" << caseName
        << "|op=" << static_cast<int4>(op->code())
        << "|inputs=[";
    for(int4 i=0;i<op->numInput();++i) {
      if (i != 0) out << ',';
      Varnode *vn = op->getIn(i);
      out << varnodeName(vn) << "{sp=" << varnode_space_token(vn)
          << ",off=";
      if (vn->getSpace()->getType() == IPTR_INTERNAL)
        out << "u"; // unique-space offsets are allocator-order noise
      else
        out << "0x" << std::hex << vn->getOffset() << std::dec;
      out << ",sz=" << vn->getSize()
          << ",sb=" << (vn->isSpacebase() ? 1 : 0)
          << ",pc=" << (vn->isPtrCheck() ? 1 : 0);
      Datatype *dt = vn->getType();
      if (dt != (Datatype *)0) {
        out << ",meta=" << static_cast<int4>(dt->getMetatype());
        if (dt->getMetatype() == TYPE_PTR)
          out << ",ptro=" << static_cast<int4>(((TypePointer *)dt)->getPtrTo()->getMetatype())
              << ",char=" << (((TypePointer *)dt)->getPtrTo()->isCharPrint() ? 1 : 0);
      }
      out << '}';
    }
    out << "],output=";
    Varnode *outvn = op->getOut();
    if (outvn == (Varnode *)0) {
      out << "-";
    }
    else {
      Datatype *dt = outvn->getType();
      out << varnodeName(outvn) << "{sz=" << outvn->getSize();
      if (dt != (Datatype *)0) {
        out << ",meta=" << static_cast<int4>(dt->getMetatype());
        if (dt->getMetatype() == TYPE_PTR)
          out << ",ptro=" << static_cast<int4>(((TypePointer *)dt)->getPtrTo()->getMetatype())
              << ",char=" << (((TypePointer *)dt)->getPtrTo()->isCharPrint() ? 1 : 0);
      }
      out << '}';
    }
    std::cout << out.str() << '\n';
    std::cout.flush();
  }
};

void installSymbols(Architecture *glb)
{
  TypeFactory *types = glb->types;
  Scope *globals = glb->symboltab->getGlobalScope();
  AddrSpace *ram = glb->getDefaultCodeSpace();

  // The driver-shaped .rodata layer: every hugehelp alias address gets a
  // 1-byte DAT entry; the string aliases get char arrays.
  globals->addSymbol("DAT_7180", types->getBase(1, TYPE_UNKNOWN),
                     Address(ram, 0x7180), Address());
  globals->addSymbol("DAT_99a8", types->getBase(1, TYPE_UNKNOWN),
                     Address(ram, 0x99a8), Address());
  globals->addSymbol("DAT_c1d8", types->getBase(1, TYPE_UNKNOWN),
                     Address(ram, 0xc1d8), Address());
  globals->addSymbol("s_ea40", types->getTypeArray(8, types->getTypeChar(1)),
                     Address(ram, 0xea40), Address());
  globals->addSymbol("s_11270", types->getTypeArray(12, types->getTypeChar(1)),
                     Address(ram, 0x11270), Address());
  globals->addSymbol("s_13ad0", types->getTypeArray(6, types->getTypeChar(1)),
                     Address(ram, 0x13ad0), Address());

  // The a1-region discrimination entries.
  glb->symboltab->addRange(globals, ram, 0x7f200000, 0x7f200fff);
  globals->addSymbol("DAT_exact", types->getBase(16, TYPE_UNKNOWN),
                     Address(ram, 0x7f200000), Address());
  globals->addSymbol("s_lit", types->getTypeArray(16, types->getTypeChar(1)),
                     Address(ram, 0x7f200100), Address());
  globals->addSymbol("s_call", types->getTypeArray(8, types->getTypeChar(1)),
                     Address(ram, 0x7f200140), Address());
  globals->addSymbol("i_call", types->getBase(4, TYPE_INT),
                     Address(ram, 0x7f200180), Address());
  Range ro(ram, 0x7f200000, 0x7f200fff);
  glb->symboltab->setPropertyRange(Varnode::readonly, ro);
}

void runCases(Funcdata &fd)
{
  installSymbols(fd.getArch());

  Fixture fx(fd);
  BlockBasic *block = fx.makeBlock("b0");

  // --- the six hugehelp alias shapes (COPY consumers, infer_pointers) ---
  struct AliasCase { const char *name; uintb addr; };
  const AliasCase aliases[] = {
    { "w_7180", 0x7180 }, { "w_99a8", 0x99a8 }, { "w_c1d8", 0xc1d8 },
    { "w_ea40", 0xea40 }, { "w_11270", 0x11270 }, { "w_13ad0", 0x13ad0 },
  };
  vector<PcodeOp *> aliasOps;
  for(int4 i=0;i<6;++i) {
    Varnode *c = fx.makeConstant(aliases[i].name, 8, aliases[i].addr);
    PcodeOp *op = fx.makeOp(string(aliases[i].name) + "_copy", CPUI_COPY, 1, 8, block);
    fx.setInput(op, c, 0);
    aliasOps.push_back(op);
  }

  // --- needexacthit rejection: mid-entry of a non-char entry ---
  Varnode *c_mid = fx.makeConstant("needexact_mid", 8, 0x7f200008);
  PcodeOp *op_mid = fx.makeOp("needexact_mid_copy", CPUI_COPY, 1, 8, block);
  fx.setInput(op_mid, c_mid, 0);

  // --- char-array middle exception + INT_ADD reuse chain ---
  Varnode *c_charmid = fx.makeConstant("chararray_mid", 8, 0x7f200108);
  PcodeOp *op_charmid = fx.makeOp("chararray_mid_copy", CPUI_COPY, 1, 8, block);
  fx.setInput(op_charmid, c_charmid, 0);

  // --- pointer range rejection ---
  Varnode *c_low = fx.makeConstant("bounds_low", 8, 0x100);
  PcodeOp *op_low = fx.makeOp("bounds_low_copy", CPUI_COPY, 1, 8, block);
  fx.setInput(op_low, c_low, 0);

  // --- bit-form rejection (0x1000 is above the lower bound) ---
  Varnode *c_bit = fx.makeConstant("bitform", 8, 0x1000);
  PcodeOp *op_bit = fx.makeOp("bitform_copy", CPUI_COPY, 1, 8, block);
  fx.setInput(op_bit, c_bit, 0);

  // --- zero constant: skipped before the PtrCheck flag ---
  Varnode *c_zero = fx.makeConstant("zero_const", 8, 0);
  PcodeOp *op_zero = fx.makeOp("zero_const_copy", CPUI_COPY, 1, 8, block);
  fx.setInput(op_zero, c_zero, 0);

  // --- PTRSUB consumer: skipped before the PtrCheck flag ---
  Varnode *c_ptrsub = fx.makeConstant("ptrsub_in", 8, 0x7f200000);
  Varnode *sb0 = fx.makeSpacebase("ptrsub_sb");
  PcodeOp *op_ptrsub = fx.makeOp("ptrsub_consumer", CPUI_PTRSUB, 2, 8, block);
  fx.setInput(op_ptrsub, sb0, 0);
  fx.setInput(op_ptrsub, c_ptrsub, 1);

  // --- INT_ADD whose other input is a spacebase: skipped ---
  Varnode *c_add = fx.makeConstant("intadd_spacebase", 8, 0x7f200000);
  Varnode *sb1 = fx.makeSpacebase("intadd_sb");
  PcodeOp *op_add = fx.makeOp("intadd_consumer", CPUI_INT_ADD, 2, 8, block);
  fx.setInput(op_add, sb1, 0);
  fx.setInput(op_add, c_add, 1);

  // --- CALL shapes ---
  Varnode *c_callptr = fx.makeConstant("call_locked_ptr", 8, 0x7f200140);
  PcodeOp *op_callptr = fx.makeOp("call_locked_ptr_call", CPUI_CALL, 2, 0, block);
  fx.setInput(op_callptr, fd.newConstant(8, 0x1000), 0);
  fx.setInput(op_callptr, c_callptr, 1);

  Varnode *c_callint = fx.makeConstant("call_locked_notptr", 8, 0x7f200180);
  PcodeOp *op_callint = fx.makeOp("call_locked_notptr_call", CPUI_CALL, 2, 0, block);
  fx.setInput(op_callint, fd.newConstant(8, 0x1004), 0);
  fx.setInput(op_callint, c_callint, 1);

  Varnode *c_callnone = fx.makeConstant("call_no_spec", 8, 0x7f200148);
  PcodeOp *op_callnone = fx.makeOp("call_no_spec_call", CPUI_CALL, 2, 0, block);
  fx.setInput(op_callnone, fd.newConstant(8, 0x1008), 0);
  fx.setInput(op_callnone, c_callnone, 1);

  // Locked callspecs: char* param accepts (cc:1095-1098), int param
  // rejects (cc:1097).
  {
    // FuncProto::setInternal builds the model+parameter store the raw
    // FuncCallSpecs ctor leaves null (fspec.cc:3891).
    FuncCallSpecs *fc = new FuncCallSpecs(op_callptr);
    fc->setInternal(fd.getArch()->defaultfp, fd.getArch()->types->getTypeVoid());
    ParameterPieces pieces;
    pieces.addr = Address(fd.getArch()->getDefaultCodeSpace(), 0);
    pieces.type = fd.getArch()->types->getTypePointer(8, fd.getArch()->types->getTypeChar(1), 1);
    pieces.flags = ParameterPieces::typelock;
    fc->setParam(0, "s", pieces);
    fc->setInputLock(true);
    fd.fixtureAddToCallList(fc);
  }
  {
    FuncCallSpecs *fc = new FuncCallSpecs(op_callint);
    fc->setInternal(fd.getArch()->defaultfp, fd.getArch()->types->getTypeVoid());
    ParameterPieces pieces;
    pieces.addr = Address(fd.getArch()->getDefaultCodeSpace(), 0);
    pieces.type = fd.getArch()->types->getBase(4, TYPE_INT);
    pieces.flags = ParameterPieces::typelock;
    fc->setParam(0, "n", pieces);
    fc->setInputLock(true);
    fd.fixtureAddToCallList(fc);
  }

  // Type recovery must be started (coreaction.cc:1170).
  fd.startTypeRecovery();

  InspectableConstantPtr action;
  // The production executor (Action::perform) resets the action before the
  // first apply — coreaction.hh:188's ctor leaves localcount uninitialized
  // until reset() zeroes it (coreaction.hh:194).
  action.reset(fd);
  int4 result = action.apply(fd);

  {
    ostringstream out;
    out << "case=setup|arch=" << fd.getArch()->archid
        << "|count=" << action.fixtureCount()
        << "|return=" << result
        << "|infer_spaces=" << fd.getArch()->inferPtrSpaces.size();
    std::cout << out.str() << '\n';
    std::cout.flush();
  }

  for(int4 i=0;i<6;++i) fx.dumpOp(aliases[i].name, aliasOps[i]);
  fx.dumpOp("needexact_mid", op_mid);
  fx.dumpOp("chararray_mid", op_charmid);
  fx.dumpOp("bounds_low", op_low);
  fx.dumpOp("bitform", op_bit);
  fx.dumpOp("zero_const", op_zero);
  fx.dumpOp("ptrsub_in", op_ptrsub);
  fx.dumpOp("intadd_spacebase", op_add);
  fx.dumpOp("call_locked_ptr", op_callptr);
  fx.dumpOp("call_locked_notptr", op_callint);
  fx.dumpOp("call_no_spec", op_callnone);
}

// The `&name` channel (Funcdata::linkSymbolReference,
// funcdata_varnode.cc:1193-1211) reads in(0)->getHigh() — the merge-created
// HighVariable — so it is pinned by the a1 query-channel fixture plus the
// E2E `&DAT_*` rendering rather than this pre-merge action fixture.

void run(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary, "default", &std::cerr);
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
    runCases(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: cptr_b_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "cptr_b_1204: LowlevelError: " << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "cptr_b_1204: " << error.what() << '\n';
    return 1;
  }
}
