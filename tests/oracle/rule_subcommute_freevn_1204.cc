/*
 * RULE-SUBCOMMUTE-FREEVN-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives RuleSubCommute::applyOp (ruleaction.cc:4514-4653) directly on
 * synthetic SUBPIECE( {INT_ADD,INT_MULT,INT_AND,INT_OR,INT_XOR,INT_NEGATE}(
 * freeVn / const, ... ), offset ) forms — the generic tail commute loop at
 * ruleaction.cc:4631-4652 whose opSetInput ORDER carries the semantics this
 * ticket locks (BINSWEEP-SUBCOMMUTE-FREEVARNODE-0001, CR-SUBCOMMUTE finding
 * 3): cc:4640 opSetInput(longform,newVn,i) must free vn from longform's slot
 * i BEFORE cc:4641 opSetInput(newsub,vn,0) attaches it, because a free
 * varnode may hold only one descendant (varnode.cc:330-340 addDescend throws
 * "Free varnode has multiple descendants" on the second) and a constant
 * still read elsewhere takes the Funcdata::opSetInput dedup COPY
 * (funcdata_op.cc:108-115) instead of the original varnode identity.
 *
 * Free varnodes are manufactured exactly the way the real pipeline does:
 * a COPY writes a unique varnode, longform reads it, then
 * Funcdata::opUnsetOutput(writer) (funcdata_op.cc:52-66 -> VarnodeBank::
 * makeFree, varnode.cc:1316) clears WRITTEN while keeping the descend list.
 *
 * Modes (argv[1]):
 *   normal     — 13 cases, golden stdout diff vs the Rust mirror.
 *   trap_dupfree — one case where the SAME free varnode feeds both XOR
 *                slots (legal while written; freed afterwards): the oracle
 *                itself throws LowlevelError rc=1 when the tail's first
 *                slot attach finds the leftover second descend entry
 *                (varnode.cc:334-336). Form comparison only, no golden —
 *                the crash-form pair is the deliverable.
 *
 * Observations (one block per case, ops in SeqNum order):
 *   case=<name>|sub_apply=<0/1>
 *     op=<opcode#>@0x<addr>|nin=<k>|in0=<c|w|o>|<in0_size>|0x<in0_off>|out=<n>
 *     keep=<c0|c1|f0|f1|w0|w1>|readers=<n>|descends=<n>
 *   endcase
 * in0 class: c=constant, w=written (has def), o=other (free).
 * keep lines: per captured longform input (slot order), readers = alive
 * SUBPIECE ops in the case window whose in(0) IS the captured Varnode
 * (pointer identity — catches the dedup-copy deviation), descends = live
 * descendant count. Each case owns the address window [base, base+0x80);
 * rule-created ops inherit the SUBPIECE address (data.newOp(2,
 * op->getAddr()), cc:4637).
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

Varnode *constantInput(Funcdata &fd, uintb value, int4 size)
{
  return fd.newConstant(size, value);
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
  out << "|out=" << (op->getOut() != (Varnode *)0 ? op->getOut()->getSize() : -1)
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

void dumpKeepLines(Funcdata &fd, const vector<Varnode *> &keeps,
                   const vector<string> &tags, const Address &lo,
                   const Address &hi)
{
  for (uint4 k = 0; k < keeps.size(); ++k) {
    Varnode *vn = keeps[k];
    int4 readers = 0;
    for (auto iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
      PcodeOp *op = iter->second;
      const Address &a = op->getAddr();
      if (a < lo || hi < a)
        continue;
      if (op->code() != CPUI_SUBPIECE)
        continue;
      if (op->numInput() > 0 && op->getIn(0) == vn)
        ++readers;
    }
    int4 descends = 0;
    for (auto iter = vn->beginDescend(); iter != vn->endDescend(); ++iter)
      ++descends;
    std::cout << "  keep=" << tags[k] << "|readers=" << readers
              << "|descends=" << descends << '\n';
  }
}

// ---- case builder ----------------------------------------------------------

// slotKind per longform slot: 0=free (COPY writer, unset after wiring),
// 1=constant, 4=written (COPY writer kept alive), 3=same vn as slot 0
// freed afterwards (trap_dupfree only), 5=same vn as slot 0 kept written
// (dup-reuse leg). extraKind: 0=none, 1=ZEXT overlap reader on outvn
// (cc:4623-4628 reject), 2=second SUBPIECE reader on base (cc:4621 reject).
struct CaseBuilt {
  PcodeOp *subOp;
  vector<Varnode *> keeps;
  vector<string> tags;
};

CaseBuilt tailCommuteCase(Funcdata &fd, BlockBasic *block, AddrSpace *code,
                          OpCode opc, uint4 base, const int4 *slotKind,
                          const uintb *slotVal, int4 longSize, int4 outSize,
                          int4 offset, int4 extraKind)
{
  CaseBuilt r;
  r.subOp = (PcodeOp *)0;
  int4 nin = (opc == CPUI_INT_NEGATE) ? 1 : 2;
  Varnode *ins[2] = {(Varnode *)0, (Varnode *)0};
  PcodeOp *writers[2] = {(PcodeOp *)0, (PcodeOp *)0};
  for (int4 slot = 0; slot < nin; ++slot) {
    if (slotKind[slot] == 3 || slotKind[slot] == 5) {
      ins[slot] = ins[0];
      continue;
    }
    if (slotKind[slot] == 1) {
      ins[slot] = constantInput(fd, slotVal[slot], longSize);
      continue;
    }
    PcodeOp *writer = fd.newOp(1, Address(code, base + 0x10 + 0x8 * slot));
    fd.opSetOpcode(writer, CPUI_COPY);
    Varnode *fv = fd.newUniqueOut(longSize, writer);
    fd.opSetInput(writer, constantInput(fd, slotVal[slot], longSize), 0);
    fd.opInsertEnd(writer, block);
    writers[slot] = writer;
    ins[slot] = fv;
  }
  PcodeOp *longform = fd.newOp(nin, Address(code, base + 0x30));
  fd.opSetOpcode(longform, opc);
  fd.newUniqueOut(longSize, longform);
  fd.opSetInput(longform, ins[0], 0);
  if (nin > 1)
    fd.opSetInput(longform, ins[1], 1);
  fd.opInsertEnd(longform, block);
  PcodeOp *subOp = fd.newOp(2, Address(code, base + 0x40));
  fd.opSetOpcode(subOp, CPUI_SUBPIECE);
  fd.newUniqueOut(outSize, subOp);
  fd.opSetInput(subOp, longform->getOut(), 0);
  fd.opSetInput(subOp, constantInput(fd, offset, 4), 1);
  fd.opInsertEnd(subOp, block);
  // Free the COPY outputs: fv keeps descend=[longform(,longform)] but loses
  // WRITTEN — the exact free-varnode state the ip corpus hit.
  for (int4 slot = 0; slot < nin; ++slot) {
    if (slotKind[slot] == 0)
      fd.opUnsetOutput(writers[slot]);
  }
  if (extraKind == 1) {
    // outvn->loneDescend() is a ZEXT back to insize: cc:4626-4627 reject.
    PcodeOp *zx = fd.newOp(1, Address(code, base + 0x50));
    fd.opSetOpcode(zx, CPUI_INT_ZEXT);
    fd.newUniqueOut(longSize, zx);
    fd.opSetInput(zx, subOp->getOut(), 0);
    fd.opInsertEnd(zx, block);
  }
  else if (extraKind == 2) {
    // A second SUBPIECE reads base: base->loneDescend() != op reject.
    PcodeOp *sub2 = fd.newOp(2, Address(code, base + 0x50));
    fd.opSetOpcode(sub2, CPUI_SUBPIECE);
    fd.newUniqueOut(outSize, sub2);
    fd.opSetInput(sub2, longform->getOut(), 0);
    fd.opSetInput(sub2, constantInput(fd, offset, 4), 1);
    fd.opInsertEnd(sub2, block);
  }
  for (int4 slot = 0; slot < nin; ++slot) {
    r.keeps.push_back(ins[slot]);
    ostringstream tag;
    tag << ((slotKind[slot] == 1)   ? 'c'
            : ((slotKind[slot] == 4 || slotKind[slot] == 5) ? 'w' : 'f'))
        << slot;
    r.tags.push_back(tag.str());
  }
  r.subOp = subOp;
  return r;
}

struct CaseSpec {
  const char *name;
  uint4 base;
  int opc; // 0 ADD, 1 MULT, 2 AND, 3 OR, 4 XOR, 5 NEGATE
  int4 slotKind[2];
  uintb slotVal[2];
  int4 longSize;
  int4 outSize;
  int4 offset;
  int4 extraKind;
};

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 4) {
    std::cerr << "usage: rule_subcommute_freevn_1204 SPEC_ROOT CURL_BINARY MODE(normal|trap_dupfree)\n";
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
      BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
      BlockBasic *block = graph.newBlockBasic(fd);

      const vector<CaseSpec> cases = {
        // The ip-corpus panic form: both longform inputs free varnodes.
        {"add_free_free", 0x510000, 0, {0, 0}, {0x11, 0x22}, 8, 4, 0, 0},
        // Const tail inputs: identity must survive (no opSetInput dedup copy
        // once cc:4640 frees the slot first).
        {"add_free_const", 0x510100, 0, {0, 1}, {0x11, 0x64}, 8, 4, 0, 0},
        {"add_const_free", 0x510200, 0, {1, 0}, {0x64, 0x22}, 8, 4, 0, 0},
        {"add_const_const", 0x510300, 0, {1, 1}, {0x64, 0xc8}, 8, 4, 0, 0},
        // Other commuting opcodes with free tails.
        {"mult_free_free", 0x510400, 1, {0, 0}, {7, 6}, 8, 4, 0, 0},
        {"and_free_free", 0x510500, 2, {0, 0}, {0xf0, 0x0f}, 8, 2, 0, 0},
        {"or_free16", 0x510600, 3, {0, 0}, {0xa1, 0xb2}, 16, 8, 0, 0},
        // Single-input arm.
        {"negate_free", 0x510700, 5, {0, 0}, {0x33, 0}, 8, 4, 0, 0},
        // Bitwise commutes at a non-zero subpiece offset.
        {"xor_free_off4", 0x510800, 4, {0, 0}, {0x44, 0x55}, 8, 4, 4, 0},
        {"mult_free_const", 0x510900, 1, {0, 1}, {9, 3}, 8, 4, 0, 0},
        // dup-reuse leg: the SAME written vn feeds both slots — only one
        // new SUBPIECE is created (cc:4636 guard, cc:4646 reuse).
        {"xor_same_written", 0x510a00, 4, {4, 5}, {0x66, 0x66}, 8, 4, 0, 0},
        // cc:4623-4628 reject: outvn feeds a ZEXT back to insize.
        {"add_free_zext_overlap", 0x510b00, 0, {0, 0}, {0x11, 0x22}, 8, 4, 0, 1},
        // cc:4621 reject: a second SUBPIECE also reads base.
        {"add_two_readers", 0x510c00, 0, {0, 0}, {0x11, 0x22}, 8, 4, 0, 2},
      };
      vector<CaseSpec> runCases = cases;
      if (mode == "trap_dupfree") {
        CaseSpec trap = {"trap_dupfree", 0x520000, 4, {0, 3},
                         {0x77, 0x77}, 8, 4, 0, 0};
        runCases.clear();
        runCases.push_back(trap);
      }
      else if (mode != "normal") {
        throw std::runtime_error("unknown mode: " + mode);
      }

      for (uint4 ci = 0; ci < runCases.size(); ++ci) {
        const CaseSpec &spec = runCases[ci];
        OpCode opc = (spec.opc == 0)   ? CPUI_INT_ADD
                     : (spec.opc == 1)  ? CPUI_INT_MULT
                     : (spec.opc == 2)  ? CPUI_INT_AND
                     : (spec.opc == 3)  ? CPUI_INT_OR
                     : (spec.opc == 4)  ? CPUI_INT_XOR
                                        : CPUI_INT_NEGATE;
        CaseBuilt built = tailCommuteCase(*fd, block, code, opc, spec.base,
                                          spec.slotKind, spec.slotVal,
                                          spec.longSize, spec.outSize,
                                          spec.offset, spec.extraKind);
        int4 apply = subCommuteRule.applyOp(built.subOp, *fd);
        std::cout << "case=" << spec.name << "|sub_apply=" << apply << '\n';
        dumpCaseWindow(*fd, Address(code, spec.base),
                       Address(code, spec.base + 0x80));
        dumpKeepLines(*fd, built.keeps, built.tags, Address(code, spec.base),
                      Address(code, spec.base + 0x80));
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
