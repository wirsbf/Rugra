/*
 * RULE-COLLAPSECONSTANTS-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives RuleCollapseConstants::applyOp (ruleaction.cc:3854-3882) directly on
 * synthetic PcodeOps with all-constant inputs, covering every collapsible
 * opcode class (integer div/rem incl. signed truncation, shifts incl.
 * overlarge SRIGHT, PIECE/SUBPIECE, ZEXT/SEXT/2COMP/NEGATE/POPCOUNT/LZCOUNT,
 * BOOL_*, the integer comparison/carry family, the FLOAT_* family at 4 and 8
 * bytes), the error paths that must mark nocollapse (divide-by-zero,
 * ternary INSERT "Invalid constant collapse", missing float format for a
 * 2-byte float), the early-out guards (non-constant input, nocollapse
 * opflag, >8-byte output), and the markedInput symbol propagation through
 * PcodeOp::collapseConstantSymbol (op.cc:503-540) with a real EquateSymbol
 * (database.hh:302), including the SUBPIECE offset!=0 rejection.
 *
 * Observations per case (single line, pipe-separated):
 *   case|apply|opcode|inputs|in0_const|in0_size|in0_offset|out_size|apply2|
 *   in0_symbol
 * where apply2 re-runs applyOp and observes the nocollapse flag through the
 * only public probe (isCollapsible): for a still-all-constant assignment op
 * with <=8-byte output, a second return of 0 proves PcodeOp::nocollapse
 * (0x10) was set.  The oplist probe prints the live-opcode count of the
 * inherited base Rule::getOpList (action.cc:706-713): Ghidra pushes
 * 0..CPUI_MAX-1 blindly, but slots 0 and 45 cannot be assigned to any
 * PcodeOp (opcodes.hh:37 "CPUI_COPY = 1" first value; opcodes.hh:92 "Slot 45
 * is currently unused"), so the observable trigger set is 72 opcodes.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

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

RuleCollapseConstants collapseRule("analysis");

Varnode *constantInput(Funcdata &fd, uintb value, int4 size)
{
  return fd.newConstant(size, value);
}

PcodeOp *makeOp(Funcdata &fd, BlockBasic *block, OpCode opcode,
                const vector<uintb> &values, const vector<int4> &sizes,
                int4 outputSize)
{
  PcodeOp *op = fd.newOp(values.size(), Address(fd.getArch()->getDefaultCodeSpace(), 0x5000));
  fd.opSetOpcode(op, opcode);
  for (uint4 slot = 0; slot < values.size(); ++slot)
    fd.opSetInput(op, constantInput(fd, values[slot], sizes[slot]), slot);
  fd.newUniqueOut(outputSize, op);
  fd.opInsertEnd(op, block);
  return op;
}

void observe(const string &name, PcodeOp *op, Funcdata &fd)
{
  const int4 first = collapseRule.applyOp(op, fd);
  const int4 second = collapseRule.applyOp(op, fd);
  Varnode *in0 = op->numInput() > 0 ? op->getIn(0) : (Varnode *)0;
  ostringstream out;
  out << "case=" << name
      << "|apply=" << first
      << "|opcode=" << static_cast<int4>(op->code())
      << "|inputs=" << op->numInput();
  if (in0 != (Varnode *)0) {
    out << "|in0_const=" << (in0->isConstant() ? 1 : 0)
        << "|in0_size=" << in0->getSize()
        << "|in0_offset=" << in0->getOffset()
        << "|in0_symbol=" << (in0->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0);
  }
  else {
    out << "|in0_const=_|in0_size=_|in0_offset=_|in0_symbol=_";
  }
  out << "|out_size=" << (op->getOut() != (Varnode *)0 ? op->getOut()->getSize() : -1)
      << "|apply2=" << second
      << '\n';
  std::cout << out.str();
}

// One input lives in a register (non-constant guard, op.cc:121-122).
PcodeOp *makeNonConstOp(Funcdata &fd, BlockBasic *block)
{
  AddrSpace *code = fd.getArch()->getDefaultCodeSpace();
  AddrSpace *reg = fd.getArch()->getSpaceByName("register");
  if (reg == (AddrSpace *)0)
    throw std::runtime_error("fixture requires register space");
  PcodeOp *op = fd.newOp(2, Address(code, 0x5000));
  fd.opSetOpcode(op, CPUI_INT_ADD);
  Varnode *regvn = fd.setInputVarnode(fd.newVarnode(4, reg, 0x20));
  fd.opSetInput(op, regvn, 0);
  fd.opSetInput(op, constantInput(fd, 5, 4), 1);
  fd.newUniqueOut(4, op);
  fd.opInsertEnd(op, block);
  return op;
}

// Attach a real EquateSymbol (database.hh:302) to a constant input varnode so
// PcodeOp::collapse's markedInput path (op.cc:455-457/463-465) fires and
// collapseConstantSymbol can dynamic_cast it in copySymbolIfValid
// (varnode.cc:510-522).  The symbol is created through the public
// Scope::addEquateSymbol (database.cc:1712) and linked to the varnode through
// the public Funcdata::remapDynamicVarnode (funcdata_varnode.cc:1112-1127).
// The equate value equals the collapsed result, so EquateSymbol::isValueClose
// (database.cc:640-659) accepts on the exact-equality branch.
void attachEquate(Funcdata &fd, Varnode *vn, uintb value)
{
  Scope *scope = fd.getScopeLocal();
  Symbol *sym = scope->addEquateSymbol("FIXTURE_EQ", 0, value, Address(), 0);
  fd.remapDynamicVarnode(vn, sym, Address(), 1);
}

void run(Funcdata &fd)
{
  // The equate cases go through Funcdata::remapDynamicVarnode, whose
  // clearSymbolLinks (varnode.cc:378-390) dereferences Varnode::high; turn
  // HighVariables on so constant inputs created via newConstant get one
  // (funcdata_varnode.cc:594-604 setHighLevel).
  fd.setHighLevel();
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);

  // Base Rule::getOpList (action.cc:706-713) — the class does not override it.
  vector<uint4> oplist;
  collapseRule.getOpList(oplist);
  int4 live = 0;
  for (uint4 index = 0; index < oplist.size(); ++index) {
    uint4 entry = oplist[index];
    if (entry >= 1 && entry <= 73 && entry != 45) // slots 0/45 cannot be assigned
      live += 1;
  }
  std::cout << "case=oplist_probe|apply=_|opcode=_|inputs=_|in0_const=_|in0_size=_"
               "|in0_offset=_|in0_symbol=_|out_size=_|apply2=_|oplist_live=" << live << '\n';

  struct Case {
    const char *name;
    OpCode opcode;
    vector<uintb> values;
    vector<int4> sizes;
    int4 outputSize;
  };
  const vector<Case> cases = {
    // signed division truncates toward zero; remainder keeps dividend sign
    {"int_sdiv_neg", CPUI_INT_SDIV, {0xFFFFFF9C, 7}, {4, 4}, 4},
    {"int_srem_neg", CPUI_INT_SREM, {0xFFFFFF9C, 7}, {4, 4}, 4},
    {"int_div", CPUI_INT_DIV, {0xFFFFFF9C, 7}, {4, 4}, 4},
    {"int_rem", CPUI_INT_REM, {0xFFFFFF9C, 7}, {4, 4}, 4},
    {"err_div_zero", CPUI_INT_DIV, {5, 0}, {4, 4}, 4},
    {"err_srem_zero", CPUI_INT_SREM, {5, 0}, {4, 4}, 4},
    // shifts (opbehavior.cc:411-472) incl. overlarge amounts
    {"int_left", CPUI_INT_LEFT, {0x12345678, 5}, {4, 4}, 4},
    {"int_left_overlarge", CPUI_INT_LEFT, {0x12345678, 32}, {4, 4}, 4},
    {"int_right", CPUI_INT_RIGHT, {0xF1234567, 4}, {4, 4}, 4},
    {"int_sright_neg", CPUI_INT_SRIGHT, {0xF1234567, 4}, {4, 4}, 4},
    {"int_sright_overlarge", CPUI_INT_SRIGHT, {0x80000000, 33}, {4, 4}, 4},
    // concat/truncate + extensions (opbehavior.cc:251-288/752-766)
    {"int_piece", CPUI_PIECE, {0x1122, 0x3344}, {2, 2}, 4},
    {"int_subpiece_low", CPUI_SUBPIECE, {0x1122334455667788, 0}, {8, 1}, 4},
    {"int_subpiece_high", CPUI_SUBPIECE, {0x1122334455667788, 4}, {8, 1}, 4},
    {"int_zext", CPUI_INT_ZEXT, {0x80}, {1}, 4},
    {"int_sext", CPUI_INT_SEXT, {0x80}, {1}, 4},
    // unary integer/bit ops (opbehavior.cc:362-388/782-792)
    {"int_2comp", CPUI_INT_2COMP, {1}, {4}, 4},
    {"int_negate", CPUI_INT_NEGATE, {0x0F0F0F0F}, {4}, 4},
    {"int_popcount", CPUI_POPCOUNT, {0xFF00FF00}, {4}, 4},
    {"int_lzcount", CPUI_LZCOUNT, {0x00010000}, {4}, 4},
    // boolean algebra (opbehavior.cc:541-567)
    {"bool_negate", CPUI_BOOL_NEGATE, {1}, {1}, 1},
    {"bool_and", CPUI_BOOL_AND, {1, 0}, {1, 1}, 1},
    {"bool_or", CPUI_BOOL_OR, {1, 0}, {1, 1}, 1},
    {"bool_xor", CPUI_BOOL_XOR, {1, 1}, {1, 1}, 1},
    // comparison / carry family (opbehavior.cc:183-360)
    {"cmp_equal", CPUI_INT_EQUAL, {5, 5}, {4, 4}, 1},
    {"cmp_not_equal", CPUI_INT_NOTEQUAL, {5, 5}, {4, 4}, 1},
    {"cmp_less", CPUI_INT_LESS, {3, 9}, {4, 4}, 1},
    {"cmp_less_equal", CPUI_INT_LESSEQUAL, {9, 9}, {4, 4}, 1},
    {"cmp_sless", CPUI_INT_SLESS, {0xFFFFFF80, 1}, {4, 4}, 1},
    {"cmp_sless_equal", CPUI_INT_SLESSEQUAL, {0xFFFFFF80, 0xFFFFFF80}, {4, 4}, 1},
    {"cmp_carry", CPUI_INT_CARRY, {0xFFFFFFFF, 1}, {4, 4}, 1},
    {"cmp_scarry", CPUI_INT_SCARRY, {0x7FFFFFFF, 1}, {4, 4}, 1},
    {"cmp_sborrow", CPUI_INT_SBORROW, {0x80000000, 1}, {4, 4}, 1},
    // FLOAT_* at single precision (Translate defaults, translate.cc:966-971)
    {"float_add4", CPUI_FLOAT_ADD, {0x3F800000, 0x40000000}, {4, 4}, 4},
    {"float_sub4", CPUI_FLOAT_SUB, {0x40400000, 0x40000000}, {4, 4}, 4},
    {"float_mult4", CPUI_FLOAT_MULT, {0x3F800000, 0x40000000}, {4, 4}, 4},
    {"float_div4", CPUI_FLOAT_DIV, {0x40400000, 0x40000000}, {4, 4}, 4},
    {"float_less4", CPUI_FLOAT_LESS, {0x3F800000, 0x40000000}, {4, 4}, 1},
    {"float_less_equal4", CPUI_FLOAT_LESSEQUAL, {0x40000000, 0x40000000}, {4, 4}, 1},
    {"float_equal4", CPUI_FLOAT_EQUAL, {0x3F800000, 0x3F800000}, {4, 4}, 1},
    {"float_not_equal4", CPUI_FLOAT_NOTEQUAL, {0x3F800000, 0x40000000}, {4, 4}, 1},
    {"float_nan4", CPUI_FLOAT_NAN, {0x7FC00000}, {4}, 1},
    {"float_neg4", CPUI_FLOAT_NEG, {0x3F800000}, {4}, 4},
    {"float_abs4", CPUI_FLOAT_ABS, {0xBF800000}, {4}, 4},
    {"float_sqrt4", CPUI_FLOAT_SQRT, {0x40800000}, {4}, 4},
    {"float_ceil4", CPUI_FLOAT_CEIL, {0x40200000}, {4}, 4},
    {"float_floor4", CPUI_FLOAT_FLOOR, {0x40200000}, {4}, 4},
    {"float_round4", CPUI_FLOAT_ROUND, {0x40200000}, {4}, 4},
    {"float_int2float4", CPUI_FLOAT_INT2FLOAT, {7}, {4}, 4},
    {"float_trunc4", CPUI_FLOAT_TRUNC, {0x40300000}, {4}, 4},
    // FLOAT_* at double precision + precision change
    {"float_add8", CPUI_FLOAT_ADD, {0x3FF0000000000000, 0x4000000000000000}, {8, 8}, 8},
    {"float_neg8", CPUI_FLOAT_NEG, {0x3FF0000000000000}, {8}, 8},
    {"float2float_4to8", CPUI_FLOAT_FLOAT2FLOAT, {0x3FC00000}, {4}, 8},
    // error paths: ternary eval type and missing float format
    {"err_insert_ternary", CPUI_INSERT, {0xAB, 0xCD, 0}, {1, 1, 1}, 2},
    {"err_float_noformat", CPUI_FLOAT_TRUNC, {0x3C00}, {2}, 4},
    // guards: nocollapse opflag (typeop.cc:2303) and >8-byte output
    {"guard_ptrsub_nocollapse", CPUI_PTRSUB, {0x1000, 8}, {4, 4}, 4},
    {"guard_out_too_big", CPUI_INT_ADD, {1, 2}, {16, 16}, 16},
  };
  for (vector<Case>::const_iterator iter = cases.begin(); iter != cases.end(); ++iter)
    observe(iter->name, makeOp(fd, block, iter->opcode, iter->values, iter->sizes, iter->outputSize), fd);

  observe("guard_nonconst_input", makeNonConstOp(fd, block), fd);

  // markedInput symbol propagation: INT_ADD picks in0 (op.cc:524-533).
  {
    PcodeOp *op = makeOp(fd, block, CPUI_INT_ADD, {0x11111111, 0x22222222}, {4, 4}, 4);
    attachEquate(fd, op->getIn(0), 0x33333333);
    observe("sym_add_marked", op, fd);
  }
  // SUBPIECE with offset != 0 must NOT propagate (op.cc:508-510).
  {
    PcodeOp *op = makeOp(fd, block, CPUI_SUBPIECE, {0x1122334455667788, 4}, {8, 1}, 4);
    attachEquate(fd, op->getIn(0), 0x11223344);
    observe("sym_subpiece_high_no_propagate", op, fd);
  }
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: rule_collapse_constants_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    vector<string> specPaths;
    specPaths.push_back(argv[1]);
    startDecompilerLibrary(specPaths);
    {
      std::ostringstream diagnostics;
      BfdArchitecture architecture(argv[2], "default", &diagnostics);
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
      run(*fd);
    }
    shutdownDecompilerLibrary();
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
