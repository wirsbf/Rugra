/*
 * RULE-SUBCOMMUTE-SDIV-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives RuleSubCommute::applyOp (ruleaction.cc:4514-4653) directly on
 * synthetic SUBPIECE( INT_SDIV/INT_SREM( INT_SEXT(a), INT_SEXT(b)|const ),
 * offset ) forms — the arm at ruleaction.cc:4570-4602 that KUNASDIV proved
 * missing on the Rugra side (g_div 100/-7 oracle folded to
 * 0xfffffffffffffff2 while Rugra left SUB168(SEXT816(100)/SEXT816(-7),0)).
 *
 * After the single SubCommute application, the harness runs a bounded
 * fixpoint of RulePropagateCopy + RuleCollapseConstants over every op in
 * address order, reproducing the oppool chain that folds the commuted
 * 8-byte division into a constant (opbehavior.cc:507-517 evaluateBinary).
 *
 * Modes (argv[1]):
 *   normal    — all non-trap cases, golden stdout diff vs the Rust mirror.
 *   trap_sdiv / trap_srem — single INT64_MIN / -1 case; the fold reaches
 *               OpBehaviorIntSdiv/IntSrem evaluateBinary which performs the
 *               native division: SIGFPE here (rc 136), Rust panic on the
 *               other side. Form-comparison only, no golden (KUNASDIV
 *               precedent — KUNAUB-SDIV-0001 ruling (a)).
 *
 * Observations (one block per case, ops sorted by sequence):
 *   case=<name>|sub_apply=<0/1>|passes=<n>
 *     op=<opcode#>|nin=<k>|in0=<c|w|o>|in0_size|in0_off>|out_size
 *   endcase
 * in0 class: c=constant, w=written (has def), o=other (input/free).
 * Each case owns the address window [base, base+0x100); rule-created ops
 * inherit the SUBPIECE address (data.newOp(2, op->getAddr()), cc:4637), so
 * the per-case dump captures exactly this case's ops, alive only.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

RuleSubCommute subCommuteRule("analysis");
RulePropagateCopy propagateCopyRule("analysis");
RuleSubCancel subCancelRule("analysis");
RuleCollapseConstants collapseRule("analysis");

Varnode *constantInput(Funcdata &fd, uintb value, int4 size)
{
  return fd.newConstant(size, value);
}

Varnode *registerInput(Funcdata &fd, AddrSpace *reg, uintb off, int4 size)
{
  return fd.setInputVarnode(fd.newVarnode(size, reg, off));
}

void printOpLine(PcodeOp *op)
{
  ostringstream out;
  out << "  op=" << static_cast<int4>(op->code())
      << "@0x" << std::hex << op->getAddr().getOffset() << std::dec
      << "|nin=" << op->numInput();
  Varnode *in0 = op->numInput() > 0 ? op->getIn(0) : (Varnode *)0;
  if (in0 != (Varnode *)0) {
    char cls = 'o';
    if (in0->isConstant())
      cls = 'c';
    else if (in0->isWritten())
      cls = 'w';
    out << "|in0=" << cls
        << "|" << in0->getSize()
        << "|0x" << std::hex << in0->getOffset() << std::dec;
  }
  else
    out << "|in0=_|0|0x0";
  out << "|" << (op->getOut() != (Varnode *)0 ? op->getOut()->getSize() : -1)
      << '\n';
  std::cout << out.str();
}

void dumpCaseWindow(Funcdata &fd, const Address &lo, const Address &hi)
{
  for (auto iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
    PcodeOp *op = iter->second;
    const Address &a = op->getAddr();
    if (a < lo || hi < a)
      continue;
    printOpLine(op);
  }
}

// One application of RuleSubCommute, then a bounded propagate+subcancel+
// collapse fixpoint in address order (the oppool chain that folds the
// commuted short division: RuleSubCancel turns SUB168(SEXT816(x),0) into
// COPY(x), RulePropagateCopy pushes constants through the COPYs,
// RuleCollapseConstants evaluates the 8-byte SDIV/SREM).
string g_caseName;

int4 runChain(Funcdata &fd, PcodeOp *subOp)
{
  int4 apply = subCommuteRule.applyOp(subOp, fd);
  int4 passes = 0;
  for (int4 pass = 0; pass < 8; ++pass) {
    bool changed = false;
    vector<PcodeOp *> snapshot;
    for (auto iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter)
      snapshot.push_back(iter->second);
    for (uint4 i = 0; i < snapshot.size(); ++i) {
      PcodeOp *op = snapshot[i];
      if (op->isDead())
        continue;
      if (propagateCopyRule.applyOp(op, fd) != 0)
        changed = true;
      if (op->isDead())
        continue;
      // RuleSubCancel registers CPUI_SUBPIECE only (ruleaction.cc:5116);
      // the ActionPool filters by getOpList, so the harness must too.
      if (op->code() == CPUI_SUBPIECE) {
        if (subCancelRule.applyOp(op, fd) != 0)
          changed = true;
      }
      if (op->isDead())
        continue;
      if (collapseRule.applyOp(op, fd) != 0)
        changed = true;
    }
    ++passes;
    if (!changed)
      break;
  }
  std::cout << "case=" << g_caseName << "|sub_apply=" << apply
            << "|passes=" << passes << '\n';
  return apply;
}

// ---- case builders --------------------------------------------------------

// SUB{out}( {opc}{long}( SEXT{long}(in0), SEXT{long}(in1) ), off )
PcodeOp *bothSextCase(Funcdata &fd, BlockBasic *block, AddrSpace *code,
                      AddrSpace *reg, OpCode opc, uint4 base,
                      uintb in0val, uintb in1val, int4 extInSize,
                      int4 longSize, int4 outSize, int4 offset,
                      bool constantInputs, uintb regOff)
{
  vector<Varnode *> extIns(2);
  for (int4 slot = 0; slot < 2; ++slot) {
    uintb val = slot == 0 ? in0val : in1val;
    Varnode *in = constantInputs
                      ? constantInput(fd, val, extInSize)
                      : registerInput(fd, reg, regOff + 0x8 * slot, extInSize);
    extIns[slot] = in;
  }
  vector<PcodeOp *> extOps(2);
  for (int4 slot = 0; slot < 2; ++slot) {
    PcodeOp *extOp = fd.newOp(1, Address(code, base + 0x10 * (slot + 1)));
    fd.opSetOpcode(extOp, CPUI_INT_SEXT);
    fd.newUniqueOut(longSize, extOp);
    fd.opSetInput(extOp, extIns[slot], 0);
    fd.opInsertEnd(extOp, block);
    extOps[slot] = extOp;
  }
  PcodeOp *longform = fd.newOp(2, Address(code, base + 0x10 * 3));
  fd.opSetOpcode(longform, opc);
  fd.newUniqueOut(longSize, longform);
  fd.opSetInput(longform, extOps[0]->getOut(), 0);
  fd.opSetInput(longform, extOps[1]->getOut(), 1);
  fd.opInsertEnd(longform, block);
  PcodeOp *subOp = fd.newOp(2, Address(code, base + 0x10 * 4));
  fd.opSetOpcode(subOp, CPUI_SUBPIECE);
  fd.newUniqueOut(outSize, subOp);
  fd.opSetInput(subOp, longform->getOut(), 0);
  fd.opSetInput(subOp, constantInput(fd, offset, 4), 1);
  fd.opInsertEnd(subOp, block);
  return subOp;
}

// SUB{out}( {opc}{long}( SEXT{long}(in0 @extInSize), const@constSize ), 0 )
PcodeOp *constDivisorCase(Funcdata &fd, BlockBasic *block, AddrSpace *code,
                          OpCode opc, uint4 base, uintb in0val,
                          int4 extInSize, uintb divisor, int4 constSize,
                          int4 longSize, int4 outSize)
{
  PcodeOp *extOp = fd.newOp(1, Address(code, base + 0x10));
  fd.opSetOpcode(extOp, CPUI_INT_SEXT);
  fd.newUniqueOut(longSize, extOp);
  fd.opSetInput(extOp, constantInput(fd, in0val, extInSize), 0);
  fd.opInsertEnd(extOp, block);
  PcodeOp *longform = fd.newOp(2, Address(code, base + 0x20));
  fd.opSetOpcode(longform, opc);
  fd.newUniqueOut(longSize, longform);
  fd.opSetInput(longform, extOp->getOut(), 0);
  fd.opSetInput(longform, constantInput(fd, divisor, constSize), 1);
  fd.opInsertEnd(longform, block);
  PcodeOp *subOp = fd.newOp(2, Address(code, base + 0x30));
  fd.opSetOpcode(subOp, CPUI_SUBPIECE);
  fd.newUniqueOut(outSize, subOp);
  fd.opSetInput(subOp, longform->getOut(), 0);
  fd.opSetInput(subOp, constantInput(fd, 0, 4), 1);
  fd.opInsertEnd(subOp, block);
  return subOp;
}

// SUB8( {opc}16( ZEXT816(in0), SEXT816(in1) ), 0 ) — wrong extension flavor
// on in(0) must be rejected (cc:4577).
PcodeOp *zextIn0Case(Funcdata &fd, BlockBasic *block, AddrSpace *code,
                     OpCode opc, uint4 base, uintb in0val, uintb in1val)
{
  PcodeOp *zext0 = fd.newOp(1, Address(code, base + 0x10));
  fd.opSetOpcode(zext0, CPUI_INT_ZEXT);
  fd.newUniqueOut(16, zext0);
  fd.opSetInput(zext0, constantInput(fd, in0val, 8), 0);
  fd.opInsertEnd(zext0, block);
  PcodeOp *sext1 = fd.newOp(1, Address(code, base + 0x20));
  fd.opSetOpcode(sext1, CPUI_INT_SEXT);
  fd.newUniqueOut(16, sext1);
  fd.opSetInput(sext1, constantInput(fd, in1val, 8), 0);
  fd.opInsertEnd(sext1, block);
  PcodeOp *longform = fd.newOp(2, Address(code, base + 0x30));
  fd.opSetOpcode(longform, opc);
  fd.newUniqueOut(16, longform);
  fd.opSetInput(longform, zext0->getOut(), 0);
  fd.opSetInput(longform, sext1->getOut(), 1);
  fd.opInsertEnd(longform, block);
  PcodeOp *subOp = fd.newOp(2, Address(code, base + 0x40));
  fd.opSetOpcode(subOp, CPUI_SUBPIECE);
  fd.newUniqueOut(8, subOp);
  fd.opSetInput(subOp, longform->getOut(), 0);
  fd.opSetInput(subOp, constantInput(fd, 0, 4), 1);
  fd.opInsertEnd(subOp, block);
  return subOp;
}

// SUB8( {opc}16( SEXT816(in0), COPY(const) ), 0 ) — in(1) written but not a
// SEXT must be rejected (cc:4581).
PcodeOp *copyIn1Case(Funcdata &fd, BlockBasic *block, AddrSpace *code,
                     OpCode opc, uint4 base, uintb in0val, uintb in1val)
{
  PcodeOp *sext0 = fd.newOp(1, Address(code, base + 0x10));
  fd.opSetOpcode(sext0, CPUI_INT_SEXT);
  fd.newUniqueOut(16, sext0);
  fd.opSetInput(sext0, constantInput(fd, in0val, 8), 0);
  fd.opInsertEnd(sext0, block);
  PcodeOp *copy1 = fd.newOp(1, Address(code, base + 0x20));
  fd.opSetOpcode(copy1, CPUI_COPY);
  fd.newUniqueOut(16, copy1);
  fd.opSetInput(copy1, constantInput(fd, in1val, 16), 0);
  fd.opInsertEnd(copy1, block);
  PcodeOp *longform = fd.newOp(2, Address(code, base + 0x30));
  fd.opSetOpcode(longform, opc);
  fd.newUniqueOut(16, longform);
  fd.opSetInput(longform, sext0->getOut(), 0);
  fd.opSetInput(longform, copy1->getOut(), 1);
  fd.opInsertEnd(longform, block);
  PcodeOp *subOp = fd.newOp(2, Address(code, base + 0x40));
  fd.opSetOpcode(subOp, CPUI_SUBPIECE);
  fd.newUniqueOut(8, subOp);
  fd.opSetInput(subOp, longform->getOut(), 0);
  fd.opSetInput(subOp, constantInput(fd, 0, 4), 1);
  fd.opInsertEnd(subOp, block);
  return subOp;
}

// SUB8( {opc}16( SEXT816(in0), reginput ), 0 ) — in(1) neither written nor
// constant must be rejected (cc:4599-4600 else branch).
PcodeOp *regIn1Case(Funcdata &fd, BlockBasic *block, AddrSpace *code,
                    AddrSpace *reg, OpCode opc, uint4 base, uintb in0val,
                    uintb regOff)
{
  PcodeOp *sext0 = fd.newOp(1, Address(code, base + 0x10));
  fd.opSetOpcode(sext0, CPUI_INT_SEXT);
  fd.newUniqueOut(16, sext0);
  fd.opSetInput(sext0, constantInput(fd, in0val, 8), 0);
  fd.opInsertEnd(sext0, block);
  PcodeOp *longform = fd.newOp(2, Address(code, base + 0x20));
  fd.opSetOpcode(longform, opc);
  fd.newUniqueOut(16, longform);
  fd.opSetInput(longform, sext0->getOut(), 0);
  fd.opSetInput(longform, registerInput(fd, reg, regOff, 8), 1);
  fd.opInsertEnd(longform, block);
  PcodeOp *subOp = fd.newOp(2, Address(code, base + 0x30));
  fd.opSetOpcode(subOp, CPUI_SUBPIECE);
  fd.newUniqueOut(8, subOp);
  fd.opSetInput(subOp, longform->getOut(), 0);
  fd.opSetInput(subOp, constantInput(fd, 0, 4), 1);
  fd.opInsertEnd(subOp, block);
  return subOp;
}

// SUB4( {opc}16( SEXT16(regA@4), SEXT16(regB@8) ), 0 ) — unequal ext input
// sizes exercise the shortenExtension leg of cancelExtensions (cc:4494-4505).
PcodeOp *unequalPartialCase(Funcdata &fd, BlockBasic *block, AddrSpace *code,
                            AddrSpace *reg, OpCode opc, uint4 base, uintb regOff)
{
  PcodeOp *ext0 = fd.newOp(1, Address(code, base + 0x10));
  fd.opSetOpcode(ext0, CPUI_INT_SEXT);
  fd.newUniqueOut(16, ext0);
  fd.opSetInput(ext0, registerInput(fd, reg, regOff, 4), 0);
  fd.opInsertEnd(ext0, block);
  PcodeOp *ext1 = fd.newOp(1, Address(code, base + 0x20));
  fd.opSetOpcode(ext1, CPUI_INT_SEXT);
  fd.newUniqueOut(16, ext1);
  fd.opSetInput(ext1, registerInput(fd, reg, regOff + 0x8, 8), 0);
  fd.opInsertEnd(ext1, block);
  PcodeOp *longform = fd.newOp(2, Address(code, base + 0x30));
  fd.opSetOpcode(longform, opc);
  fd.newUniqueOut(16, longform);
  fd.opSetInput(longform, ext0->getOut(), 0);
  fd.opSetInput(longform, ext1->getOut(), 1);
  fd.opInsertEnd(longform, block);
  PcodeOp *subOp = fd.newOp(2, Address(code, base + 0x40));
  fd.opSetOpcode(subOp, CPUI_SUBPIECE);
  fd.newUniqueOut(4, subOp);
  fd.opSetInput(subOp, longform->getOut(), 0);
  fd.opSetInput(subOp, constantInput(fd, 0, 4), 1);
  fd.opInsertEnd(subOp, block);
  return subOp;
}

struct CaseSpec {
  const char *name;
  uint4 base;
  int kind; // 0 bothSextConst, 1 bothSextReg, 2 constDivisor, 3 zext0,
            // 4 copyIn1, 5 regIn1, 6 unequalPartial, 7 offsetNonzero
  int opc;  // 0 SDIV, 1 SREM
  uintb in0;
  uintb in1;
  int4 extInSize;
  int4 constSize;
  int4 longSize;
  int4 outSize;
  int4 offset;
  uintb regOff;
};

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 4) {
    std::cerr << "usage: rule_subcommute_sdiv_1204 SPEC_ROOT CURL_BINARY MODE(normal|trap_sdiv|trap_srem)\n";
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

      string mode = argv[3];
      AddrSpace *code = fd->getArch()->getDefaultCodeSpace();
      AddrSpace *reg = fd->getArch()->getSpaceByName("register");
      if (reg == (AddrSpace *)0)
        throw std::runtime_error("fixture requires register space");
      BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
      BlockBasic *block = graph.newBlockBasic(fd);

      const vector<CaseSpec> cases = {
        // g_div 100/-7 KUNASDIV form: both SEXT inputs (constants), outvn 8.
        {"sdiv_written_fold", 0x500000, 0, 0, 100, 0xfffffffffffffff9ULL, 8, 0, 16, 8, 0, 0},
        {"srem_written_fold", 0x500100, 0, 1, 100, 0xfffffffffffffff9ULL, 8, 0, 16, 8, 0, 0},
        {"sdiv_pos_divisor", 0x500200, 0, 0, 100, 7, 8, 0, 16, 8, 0, 0},
        {"sdiv_w4_sext_written", 0x500300, 0, 0, 0xfffffff9, 100, 4, 0, 16, 8, 0, 0},
        {"sdiv_const_fit_w4", 0x500400, 2, 0, 100, 0xfffffffffffffff9ULL, 4, 8, 8, 4, 0, 0},
        {"srem_const_fit_w4", 0x500500, 2, 1, 100, 0xfffffffffffffff9ULL, 4, 8, 8, 4, 0, 0},
        {"sdiv_const_sign_mismatch", 0x500600, 2, 0, 100, 0x00000000ffffff80ULL, 4, 8, 8, 4, 0, 0},
        {"sdiv_const_high_bits", 0x500700, 2, 0, 100, 0x100000080ULL, 4, 8, 8, 4, 0, 0},
        {"sdiv_offset_nonzero", 0x500800, 7, 0, 100, 0xfffffffffffffff9ULL, 8, 0, 16, 8, 8, 0},
        {"sdiv_in0_zext", 0x500900, 3, 0, 100, 0xfffffffffffffff9ULL, 8, 0, 16, 8, 0, 0},
        {"sdiv_in1_copy", 0x500a00, 4, 0, 100, 0xfffffffffffffff9ULL, 8, 0, 16, 8, 0, 0},
        {"sdiv_in1_reginput", 0x500b00, 5, 0, 100, 0, 8, 0, 16, 8, 0, 0x240},
        {"sdiv_partial_equal", 0x500c00, 1, 0, 0, 0, 8, 0, 16, 4, 0, 0x200},
        {"srem_partial_equal", 0x500d00, 1, 1, 0, 0, 8, 0, 16, 4, 0, 0x230},
        {"sdiv_partial_const_ext", 0x500e00, 0, 0, 100, 0xfffffffffffffff9ULL, 8, 0, 16, 4, 0, 0},
        {"sdiv_partial_unequal", 0x500f00, 6, 0, 0, 0, 0, 0, 16, 4, 0, 0x260},
      };
      vector<CaseSpec> runCases = cases;
      if (mode == "trap_sdiv" || mode == "trap_srem") {
        int opc = mode == "trap_sdiv" ? 0 : 1;
        CaseSpec trap = {"trap", 0x600000, 0, opc,
                         0x8000000000000000ULL, 0xffffffffffffffffULL, 8, 0, 16, 8, 0, 0};
        runCases.clear();
        runCases.push_back(trap);
      }
      else if (mode != "normal") {
        throw std::runtime_error("unknown mode: " + mode);
      }

      for (uint4 ci = 0; ci < runCases.size(); ++ci) {
        const CaseSpec &spec = runCases[ci];
        uint4 base = spec.base;
        PcodeOp *subOp = (PcodeOp *)0;
        switch (spec.kind) {
        case 0:
          subOp = bothSextCase(*fd, block, code, reg,
                               spec.opc == 0 ? CPUI_INT_SDIV : CPUI_INT_SREM,
                               base, spec.in0, spec.in1, spec.extInSize,
                               spec.longSize, spec.outSize, spec.offset, true,
                               spec.regOff);
          break;
        case 1:
          subOp = bothSextCase(*fd, block, code, reg,
                               spec.opc == 0 ? CPUI_INT_SDIV : CPUI_INT_SREM,
                               base, spec.in0, spec.in1, spec.extInSize,
                               spec.longSize, spec.outSize, spec.offset, false,
                               spec.regOff);
          break;
        case 2:
          subOp = constDivisorCase(*fd, block, code,
                                   spec.opc == 0 ? CPUI_INT_SDIV : CPUI_INT_SREM,
                                   base, spec.in0, spec.extInSize, spec.in1,
                                   spec.constSize, spec.longSize, spec.outSize);
          break;
        case 3:
          subOp = zextIn0Case(*fd, block, code,
                              spec.opc == 0 ? CPUI_INT_SDIV : CPUI_INT_SREM,
                              base, spec.in0, spec.in1);
          break;
        case 4:
          subOp = copyIn1Case(*fd, block, code,
                              spec.opc == 0 ? CPUI_INT_SDIV : CPUI_INT_SREM,
                              base, spec.in0, spec.in1);
          break;
        case 5:
          subOp = regIn1Case(*fd, block, code, reg,
                             spec.opc == 0 ? CPUI_INT_SDIV : CPUI_INT_SREM,
                             base, spec.in0, spec.regOff);
          break;
        case 6:
          subOp = unequalPartialCase(*fd, block, code, reg,
                                     spec.opc == 0 ? CPUI_INT_SDIV : CPUI_INT_SREM,
                                     base, spec.regOff);
          break;
        case 7:
          subOp = bothSextCase(*fd, block, code, reg,
                               spec.opc == 0 ? CPUI_INT_SDIV : CPUI_INT_SREM,
                               base, spec.in0, spec.in1, spec.extInSize,
                               spec.longSize, spec.outSize, spec.offset, true,
                               spec.regOff);
          break;
        }
        g_caseName = spec.name;
        runChain(*fd, subOp);
        dumpCaseWindow(*fd, Address(code, base), Address(code, base + 0x80));
        std::cout << "endcase\n";
        std::cout.flush();
      }
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
