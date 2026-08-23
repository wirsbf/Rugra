/*
 * VARNODE-COPYSYMBOL-EQUATE-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives Varnode::copySymbolIfValid (varnode.cc:510-522) and its decisive
 * dependency EquateSymbol::isValueClose (database.cc:640-659) directly on
 * real oracle objects, covering every branch of both functions:
 *
 *  - isValueClose branch table (database.cc:640-659): full-width exact
 *    equality; masked-off bits that are pure sign-extension accepted;
 *    masked-off '1' bits that are NOT sign-extension rejected; the five
 *    close forms within calc_mask(size) (masked equal / bitwise-not /
 *    negation / +1 / -1); nothing-matches rejection at sizes 2 and 8.
 *  - copySymbolIfValid direct (varnode.cc:510-522): no SymbolEntry early
 *    return; dynamic_cast<EquateSymbol*> failure on a plain (non-equate)
 *    dynamically mapped symbol; isValueClose acceptance propagating the
 *    markup through copySymbol (varnode.cc:493-505, including the
 *    typelock/namelock-only flag copy that leaves `mapped` clear on the
 *    destination); not-close rejection leaving the destination untouched.
 *  - op-level integration through RuleCollapseConstants::applyOp
 *    (ruleaction.cc:3854-3882) -> PcodeOp::collapseConstantSymbol
 *    (op.cc:503-540): INT_ADD markedInput propagation when the collapsed
 *    constant is value-close to the equate, the not-close rejection, and
 *    the SUBPIECE offset!=0 rejection (op.cc:508-510) where
 *    copySymbolIfValid is never reached.
 *
 * Equates are created through the public Scope::addEquateSymbol
 * (database.cc:1712) and attached through the public
 * Varnode::setSymbolEntry (varnode.cc:429) via getFirstWholeMap, the same
 * storage route the markedInput path observes.  The plain symbol uses the
 * public Scope::addDynamicSymbol (database.hh:784).
 *
 * Observations per case (single line, pipe-separated, decimal integers):
 *   vc_*: case|value|op2|size|close
 *   cs_*: case|dst_offset|dst_size|src_symbol|dst_symbol|dst_namelock|
 *         dst_typelock|dst_mapped
 *   op_*: case|apply|opcode|in0_offset|out_size|in0_symbol
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

// Attach a real EquateSymbol (database.hh:302) to a constant varnode through
// the public Scope::addEquateSymbol (database.cc:1712) +
// Funcdata::remapDynamicVarnode (funcdata_varnode.cc:1120-1127) route — the
// same route the markedInput -> collapseConstantSymbol -> copySymbolIfValid
// chain (op.cc:503-540) observes.  Varnode::setSymbolEntry itself is private
// (varnode.hh:172), so the Funcdata wrapper is the public storage path.
void attachEquate(Funcdata &fd, Scope *scope, Varnode *vn, uintb value)
{
  Symbol *sym = scope->addEquateSymbol("FIXTURE_EQ", 0, value, Address(), 0);
  fd.remapDynamicVarnode(vn, sym, Address(), 1);
}

// Attach a plain (non-equate) dynamic Symbol through the same public route.
// The symbol carries a real 1-byte base type (database.cc:1823 rejects null
// types for dynamically mapped symbols).
void attachPlainSymbol(Funcdata &fd, Scope *scope, Varnode *vn)
{
  Datatype *ct = scope->getArch()->types->getBase(1, TYPE_UNKNOWN);
  Symbol *sym = scope->addDynamicSymbol("FIXTURE_PLAIN", ct, Address(), 0);
  fd.remapDynamicVarnode(vn, sym, Address(), 1);
}

// Section A: EquateSymbol::isValueClose branch table (database.cc:640-659).
void runValueCloseTable(Scope *scope)
{
  struct VC {
    const char *name;
    uintb value;
    uintb op2;
    int4 size;
  };
  const VC cases[] = {
    // cc:642 full-width exact equality.
    {"vc_exact", 0x11223344ULL, 0x11223344ULL, 4},
    // cc:645-650 masked-off bits are pure sign-extension, then mask-equal.
    {"vc_signext_masked", 0xFFFFFFFF8899AABBULL, 0x8899AABBULL, 4},
    // cc:645-649 masked-off '1' bits are NOT sign-extension -> reject.
    {"vc_masked_non_signext", 0x1122334455667788ULL, 0x55667788ULL, 4},
    // cc:650 maskValue == (op2Value & mask) with a wider op2Value.
    {"vc_op2_wider_masked", 0x55667788ULL, 0x1122334455667788ULL, 4},
    // cc:651 maskValue == (~op2Value & mask).
    {"vc_bitnot_close", 0x0F0FULL, 0xF0F0ULL, 2},
    // cc:652 maskValue == (-op2Value & mask).
    {"vc_negate_close", 0x0F0FULL, 0xF0F1ULL, 2},
    // cc:653 maskValue == ((op2Value + 1) & mask).
    {"vc_plus1_close", 0x0F0FULL, 0x0F0EULL, 2},
    // cc:654 maskValue == ((op2Value - 1) & mask).
    {"vc_minus1_close", 0x0F0FULL, 0x0F10ULL, 2},
    // cc:655 nothing matches.
    {"vc_not_close", 0x1234ULL, 0x5678ULL, 2},
    // cc:655 nothing matches at full 8-byte precision (adjacent +/-1 miss).
    {"vc_size8_not_close", 0x10ULL, 0x20ULL, 8},
    // cc:651 bitwise-not close at full 8-byte precision.
    {"vc_size8_bitnot", 0x10ULL, 0xFFFFFFFFFFFFFFEFULL, 8},
  };
  for (const VC *iter = cases; iter != cases + sizeof(cases) / sizeof(cases[0]); ++iter) {
    EquateSymbol equ(scope, "VCEQ", 0, iter->value);
    std::cout << "case=" << iter->name
              << "|value=" << iter->value
              << "|op2=" << iter->op2
              << "|size=" << iter->size
              << "|close=" << (equ.isValueClose(iter->op2, iter->size) ? 1 : 0)
              << '\n';
  }
}

// Section B: Varnode::copySymbolIfValid directly on free constant varnodes.
void runCopyIfValidDirect(Funcdata &fd, Scope *scope)
{
  struct CS {
    const char *name;
    uintb equateValue;
    uintb srcVal;
    uintb dstVal;
    int4 size;
    bool plain;   // true: attach a non-equate dynamic symbol instead
    bool noSym;   // true: attach nothing (mapentry == null guard)
  };
  const CS cases[] = {
    // cc:519-521 equate value equal to the destination constant: copy.
    {"cs_equate_equal", 0x33333333ULL, 0x33333333ULL, 0x33333333ULL, 4, false, false},
    // cc:519 isValueClose false: reject (the strictness this fixture gates).
    {"cs_equate_not_close", 0x12345678ULL, 0x12345678ULL, 0x33333333ULL, 4, false, false},
    // cc:652 negate-close form still propagates.
    {"cs_equate_negate_close", 0x0F0FULL, 0xF0F1ULL, 0x0F0FULL, 2, false, false},
    // cc:645-650 sign-extended equate value matches the masked constant.
    {"cs_equate_signext", 0xFFFFFFFF8899AABBULL, 0x8899AABBULL, 0x8899AABBULL, 4, false, false},
    // cc:516-518 dynamic_cast<EquateSymbol*> fails on a plain symbol.
    {"cs_plain_symbol", 0, 0x33333333ULL, 0x33333333ULL, 4, true, false},
    // cc:513-515 source varnode carries no SymbolEntry.
    {"cs_no_mapentry", 0, 0x33333333ULL, 0x33333333ULL, 4, false, true},
  };
  for (const CS *iter = cases; iter != cases + sizeof(cases) / sizeof(cases[0]); ++iter) {
    Varnode *src = fd.newConstant(iter->size, iter->srcVal);
    Varnode *dst = fd.newConstant(iter->size, iter->dstVal);
    if (iter->plain)
      attachPlainSymbol(fd, scope, src);
    else if (!iter->noSym)
      attachEquate(fd, scope, src, iter->equateValue);
    dst->copySymbolIfValid(src);
    std::cout << "case=" << iter->name
              << "|dst_offset=" << dst->getOffset()
              << "|dst_size=" << dst->getSize()
              << "|src_symbol=" << (src->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
              << "|dst_symbol=" << (dst->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
              << "|dst_namelock=" << (dst->isNameLock() ? 1 : 0)
              << "|dst_typelock=" << (dst->isTypeLock() ? 1 : 0)
              << "|dst_mapped=" << (dst->isMapped() ? 1 : 0)
              << '\n';
  }
}

// Section C: the op-level integration through RuleCollapseConstants.
PcodeOp *makeOp(Funcdata &fd, BlockBasic *block, OpCode opcode,
                const vector<uintb> &values, const vector<int4> &sizes,
                int4 outputSize)
{
  PcodeOp *op = fd.newOp(values.size(), Address(fd.getArch()->getDefaultCodeSpace(), 0x5000));
  fd.opSetOpcode(op, opcode);
  for (uint4 slot = 0; slot < values.size(); ++slot)
    fd.opSetInput(op, fd.newConstant(sizes[slot], values[slot]), slot);
  fd.newUniqueOut(outputSize, op);
  fd.opInsertEnd(op, block);
  return op;
}

void runOpLevel(Funcdata &fd, Scope *scope)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);

  struct OP {
    const char *name;
    OpCode opcode;
    vector<uintb> values;
    vector<int4> sizes;
    int4 outputSize;
    uintb equateValue;
  };
  vector<OP> cases;
  // op.cc:524-533 INT_ADD picks in0 as the symbol source; the collapsed
  // constant 0x33333333 is value-close to the equate -> markup propagates.
  cases.push_back({"op_add_marked_close", CPUI_INT_ADD,
                   {0x11111111ULL, 0x22222222ULL}, {4, 4}, 4, 0x33333333ULL});
  // The collapsed constant 3 is not close to the equate 0xDEADBEEF -> the
  // markup must NOT propagate (varnode.cc:519 rejects).
  cases.push_back({"op_add_marked_not_close", CPUI_INT_ADD,
                   {1ULL, 2ULL}, {4, 4}, 4, 0xDEADBEEFULL});
  // op.cc:508-510 SUBPIECE with offset != 0 never reaches
  // copySymbolIfValid; the high-bytes truncation carries no markup.
  cases.push_back({"op_subpiece_high_no_propagate", CPUI_SUBPIECE,
                   {0x1122334455667788ULL, 4ULL}, {8, 1}, 4, 0x11223344ULL});
  for (vector<OP>::const_iterator iter = cases.begin(); iter != cases.end(); ++iter) {
    PcodeOp *op = makeOp(fd, block, iter->opcode, iter->values, iter->sizes, iter->outputSize);
    attachEquate(fd, scope, op->getIn(0), iter->equateValue);
    const int4 apply = collapseRule.applyOp(op, fd);
    // After a successful collapse the op is COPY(newConst): the propagated
    // markup lands on the new constant, which is now input 0 (ruleaction.cc:
    // 3874 opSetInput(op,vn,0)); the original unique output is untouched.
    Varnode *out = op->getOut();
    Varnode *in0 = op->numInput() > 0 ? op->getIn(0) : (Varnode *)0;
    std::cout << "case=" << iter->name
              << "|apply=" << apply
              << "|opcode=" << static_cast<int4>(op->code())
              << "|in0_offset=" << (in0 != (Varnode *)0 ? (int8)in0->getOffset() : -1)
              << "|out_size=" << (out != (Varnode *)0 ? out->getSize() : -1)
              << "|in0_symbol=" << (in0 != (Varnode *)0 && in0->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
              << '\n';
  }
}

void run(Funcdata &fd)
{
  // remapDynamicVarnode's clearSymbolLinks (varnode.cc:378-390) dereferences
  // Varnode::high; turn HighVariables on so constant inputs created via
  // newConstant get one (funcdata_varnote.cc:594-604 setHighLevel).
  fd.setHighLevel();
  Scope *scope = fd.getScopeLocal();
  runValueCloseTable(scope);
  runCopyIfValidDirect(fd, scope);
  runOpLevel(fd, scope);
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: varnode_copysymbol_1204 SPEC_ROOT CURL_BINARY\n";
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
