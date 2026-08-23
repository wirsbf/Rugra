/*
 * RULE-BEHAVIORAL-FIVE-0001: locked Ghidra 12.0.4 fixture.
 *
 * Drives the five behavioral rules whose Rugra implementations previously
 * ran different algorithms than the oracle (RULE_GAPS_2026-08-22.md §2 M1-M5):
 *
 *   RuleZextEliminate  (ruleaction.cc:2471-2526)  dispatch comparison ops
 *   RuleSignForm       (ruleaction.cc:8445-8474)  dispatch SUBPIECE
 *   RuleSignNearMult   (ruleaction.cc:8533-8592)  dispatch INT_AND
 *   RuleShiftBitops    (ruleaction.cc:476-566)    dispatch LEFT/RIGHT/SUBPIECE/MULT
 *   RuleShift2Mult     (ruleaction.cc:3704-3751)  dispatch INT_LEFT only
 *
 * Every case is dispatched exactly like ActionPool (action.cc:748-750):
 * applyOp is invoked on the op only when its opcode is in the rule's
 * getOpList; otherwise the op is untouched.  This makes the negative
 * "old-Rugra-behavior" cases decisive: the opcode sets the oracle refuses
 * (INT_ZEXT under zexteliminate, INT_SRIGHT under signform, INT_MULT under
 * signnearmult, shift-by-0/SRIGHT under shiftbitops, INT_RIGHT under
 * shift2mult) are exactly the ones the old Rugra registrations transformed.
 *
 * Each rule has >= 2 positive cases (a transform the oracle performs) and
 * >= 1 negative case rejected by an oracle guard, plus at least one
 * dispatch-refused case pinning the old Rugra-local behavior as never fired.
 *
 * Observation per case (single line, pipe-separated):
 *   case=<name>|apply=<0/1>|opcode=<int>|inputs=<n>|in0=<tok>|in1=<tok>|
 *   in0def=<int>|defin1=<tok>
 * where a varnode token is
 *   c<size>:<hexoffset>   constant
 *   w<size>               written (has a defining op; in0def prints its code)
 *   u<size>               unwritten (function input)
 * and defin1 prints the defining op's input-1 token when in0 is written
 * (this pins the INT_SDIV(x, 2^n) op RuleSignNearMult inserts).
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

RuleZextEliminate zextEliminateRule("analysis");
RuleSignForm signFormRule("analysis");
RuleSignNearMult signNearMultRule("analysis");
RuleShiftBitops shiftBitopsRule("analysis");
RuleShift2Mult shift2MultRule("analysis");

AddrSpace *codeSpace;
AddrSpace *regSpace;

Varnode *constantInput(Funcdata &fd, uintb value, int4 size)
{
  return fd.newConstant(size, value);
}

// Each input varnode gets a fresh, non-overlapping register offset (the
// oracle's setInputVarnode rejects overlapping inputs across cases).
static uintb inputOffsetCounter = 0;

Varnode *inputVarnode(Funcdata &fd, int4 size, uintb)
{
  uintb offset = 0x10 + 0x10 * (inputOffsetCounter++);
  return fd.setInputVarnode(fd.newVarnode(size, regSpace, offset));
}

PcodeOp *makeOp(Funcdata &fd, BlockBasic *block, OpCode opcode,
                const vector<Varnode *> &inputs, int4 outputSize)
{
  PcodeOp *op = fd.newOp(inputs.size(), Address(codeSpace, 0x5000));
  fd.opSetOpcode(op, opcode);
  for (uint4 slot = 0; slot < inputs.size(); ++slot)
    fd.opSetInput(op, inputs[slot], slot);
  fd.newUniqueOut(outputSize, op);
  fd.opInsertEnd(op, block);
  return op;
}

// ActionPool-equivalent dispatch (action.cc:748-750): only ops whose opcode
// is in the rule's getOpList reach applyOp.
int4 dispatchApply(Rule &rule, PcodeOp *op, Funcdata &fd)
{
  vector<uint4> oplist;
  rule.getOpList(oplist);
  uint4 code = static_cast<uint4>(op->code());
  for (uint4 i = 0; i < oplist.size(); ++i)
    if (oplist[i] == code)
      return rule.applyOp(op, fd);
  return 0;
}

string vnToken(Varnode *vn)
{
  if (vn == (Varnode *)0)
    return "-";
  ostringstream s;
  if (vn->isConstant()) {
    s << 'c' << vn->getSize() << ':' << hex << vn->getOffset() << dec;
  }
  else if (vn->isWritten())
    s << 'w' << vn->getSize();
  else
    s << 'u' << vn->getSize();
  return s.str();
}

void observe(const string &name, Rule &rule, PcodeOp *op, Funcdata &fd)
{
  const int4 apply = dispatchApply(rule, op, fd);
  Varnode *in0 = op->numInput() > 0 ? op->getIn(0) : (Varnode *)0;
  Varnode *in1 = op->numInput() > 1 ? op->getIn(1) : (Varnode *)0;
  ostringstream out;
  out << "case=" << name
      << "|apply=" << apply
      << "|opcode=" << static_cast<int4>(op->code())
      << "|inputs=" << op->numInput()
      << "|in0=" << vnToken(in0)
      << "|in1=" << vnToken(in1)
      << "|in0def=";
  if (in0 != (Varnode *)0 && in0->isWritten()) {
    PcodeOp *def = in0->getDef();
    out << static_cast<int4>(def->code());
    out << "|defin1="
        << (def->numInput() > 1 ? vnToken(def->getIn(1)) : string("_"));
  }
  else {
    out << "-1|defin1=_";
  }
  out << '\n';
  std::cout << out.str();
}

void oplistProbe(const string &tag, Rule &rule)
{
  vector<uint4> oplist;
  rule.getOpList(oplist);
  ostringstream out;
  out << "case=oplist_" << tag
      << "|apply=_|opcode=_|inputs=_|in0=_|in1=_|in0def=_|defin1=_|ops=";
  for (uint4 i = 0; i < oplist.size(); ++i) {
    if (i != 0)
      out << ',';
    out << oplist[i];
  }
  out << '\n';
  std::cout << out.str();
}

// --- RuleZextEliminate (ruleaction.cc:2471-2526) ---

PcodeOp *makeZextCmp(Funcdata &fd, BlockBasic *block, OpCode cmpOpcode,
                     int4 smallSize, uintb cmpConst, bool zextOnSlot1,
                     PcodeOp **zextOpOut)
{
  Varnode *v = inputVarnode(fd, smallSize, 0x10);
  PcodeOp *zextOp = makeOp(fd, block, CPUI_INT_ZEXT,
                           vector<Varnode *>(1, v), 4);
  Varnode *c = constantInput(fd, cmpConst, 4);
  vector<Varnode *> inputs;
  if (zextOnSlot1)
    inputs.push_back(c), inputs.push_back(zextOp->getOut());
  else
    inputs.push_back(zextOp->getOut()), inputs.push_back(c);
  PcodeOp *cmpOp = makeOp(fd, block, cmpOpcode, inputs, 1);
  *zextOpOut = zextOp;
  return cmpOp;
}

// --- RuleSignForm (ruleaction.cc:8445-8474) ---

PcodeOp *makeSignForm(Funcdata &fd, BlockBasic *block, OpCode extOpcode,
                      int4 smallSize, int4 extOutSize, int4 outSize,
                      uintb truncOffset)
{
  Varnode *v = inputVarnode(fd, smallSize, 0x10);
  PcodeOp *extOp = makeOp(fd, block, extOpcode, vector<Varnode *>(1, v), extOutSize);
  vector<Varnode *> inputs;
  inputs.push_back(extOp->getOut());
  inputs.push_back(constantInput(fd, truncOffset, 4));
  return makeOp(fd, block, CPUI_SUBPIECE, inputs, outSize);
}

// --- RuleSignNearMult (ruleaction.cc:8533-8592) ---

// Builds AND( x + ((x s>> (8*size-1)) >> k), mask ) with the shift side on
// the requested ADD slot; returns the AND op.
PcodeOp *makeNearMult(Funcdata &fd, BlockBasic *block, int4 size, uintb k,
                      uintb mask, bool shiftOnSlot0)
{
  Varnode *x = inputVarnode(fd, size, 0x10);
  PcodeOp *sshOp = makeOp(fd, block, CPUI_INT_SRIGHT,
                          {x, constantInput(fd, 8 * size - 1, 4)}, size);
  PcodeOp *rightOp = makeOp(fd, block, CPUI_INT_RIGHT,
                            {sshOp->getOut(), constantInput(fd, k, 4)}, size);
  vector<Varnode *> addInputs;
  if (shiftOnSlot0) {
    addInputs.push_back(rightOp->getOut());
    addInputs.push_back(x);
  }
  else {
    addInputs.push_back(x);
    addInputs.push_back(rightOp->getOut());
  }
  PcodeOp *addOp = makeOp(fd, block, CPUI_INT_ADD, addInputs, size);
  PcodeOp *andOp = makeOp(fd, block, CPUI_INT_AND,
                          {addOp->getOut(), constantInput(fd, mask, 4)}, size);
  return andOp;
}

// --- RuleShiftBitops (ruleaction.cc:476-566) ---

PcodeOp *makeBitopShift(Funcdata &fd, BlockBasic *block, OpCode bitOpcode,
                        uintb bitConst, OpCode shiftOpcode, uintb shiftConst,
                        int4 size, int4 outSize)
{
  Varnode *v = inputVarnode(fd, size, 0x10);
  PcodeOp *bitOp = makeOp(fd, block, bitOpcode,
                          {v, constantInput(fd, bitConst, 4)}, size);
  PcodeOp *shiftOp = makeOp(fd, block, shiftOpcode,
                            {bitOp->getOut(), constantInput(fd, shiftConst, 4)}, outSize);
  return shiftOp;
}

// --- RuleShift2Mult (ruleaction.cc:3704-3751) ---

PcodeOp *makeShiftFeed(Funcdata &fd, BlockBasic *block, OpCode shiftOpcode,
                       uintb shiftConst, OpCode consumerOpcode)
{
  Varnode *v = inputVarnode(fd, 4, 0x10);
  PcodeOp *shiftOp = makeOp(fd, block, shiftOpcode,
                            {v, constantInput(fd, shiftConst, 4)}, 4);
  Varnode *w = inputVarnode(fd, 4, 0x20);
  if (consumerOpcode != CPUI_MAX)
    makeOp(fd, block, consumerOpcode, {shiftOp->getOut(), w}, 4);
  return shiftOp;
}

void run(Funcdata &fd)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);

  // opcode-set probes: the dispatch contract of each rule.
  oplistProbe("zexteliminate", zextEliminateRule);
  oplistProbe("signform", signFormRule);
  oplistProbe("signnearmult", signNearMultRule);
  oplistProbe("shiftbitops", shiftBitopsRule);
  oplistProbe("shift2mult", shift2MultRule);

  // --- RuleZextEliminate ---
  {
    PcodeOp *zextOp;
    // positive: zext(V:1->4) == 5 => V == 5 (slot 0 carries the zext)
    observe("zextelim_eq_pos", zextEliminateRule,
            makeZextCmp(fd, block, CPUI_INT_EQUAL, 1, 5, false, &zextOp), fd);
    // positive: 5 != zext(V:1->4) => 5 != V (zext on slot 1, cc:2501-2506)
    observe("zextelim_notequal_slot1_pos", zextEliminateRule,
            makeZextCmp(fd, block, CPUI_INT_NOTEQUAL, 1, 5, true, &zextOp), fd);
    // positive: zext(V:2->4) <= 0x1234 (0x1234 >> 16 == 0)
    observe("zextelim_lessequal_pos", zextEliminateRule,
            makeZextCmp(fd, block, CPUI_INT_LESSEQUAL, 2, 0x1234, false, &zextOp), fd);
    // negative: zext(V:1->4) < 0x12c (300 >> 8 != 0) -> cc:2516 rejects
    observe("zextelim_less_val_too_big_neg", zextEliminateRule,
            makeZextCmp(fd, block, CPUI_INT_LESS, 1, 300, false, &zextOp), fd);
  }
  {
    // negative: the zext output feeds a second op -> loneDescend fails
    PcodeOp *zextOp;
    PcodeOp *cmpOp = makeZextCmp(fd, block, CPUI_INT_EQUAL, 1, 5, false, &zextOp);
    makeOp(fd, block, CPUI_COPY, vector<Varnode *>(1, zextOp->getOut()), 4);
    observe("zextelim_shared_zext_neg", zextEliminateRule, cmpOp, fd);
  }
  {
    // negative dispatch (old Rugra folded same-size zext->COPY here):
    // the INT_ZEXT op itself is not in the oplist -> untouched.
    Varnode *v = inputVarnode(fd, 4, 0x10);
    PcodeOp *zextOp = makeOp(fd, block, CPUI_INT_ZEXT, vector<Varnode *>(1, v), 4);
    observe("zextelim_zext_op_dispatch_neg", zextEliminateRule, zextOp, fd);
  }
  {
    // negative: other input not constant -> cc:2510 rejects
    PcodeOp *zextOp;
    Varnode *v = inputVarnode(fd, 1, 0x10);
    zextOp = makeOp(fd, block, CPUI_INT_ZEXT, vector<Varnode *>(1, v), 4);
    Varnode *w = inputVarnode(fd, 4, 0x30);
    PcodeOp *cmpOp = makeOp(fd, block, CPUI_INT_EQUAL, {zextOp->getOut(), w}, 1);
    observe("zextelim_nonconst_other_neg", zextEliminateRule, cmpOp, fd);
  }

  // --- RuleSignForm ---
  // positive: sub(sext(V:1->4), 2) => V s>> 7 (c=2 >= |V|=1)
  observe("signform_subpiece_sext_1b_pos", signFormRule,
          makeSignForm(fd, block, CPUI_INT_SEXT, 1, 4, 1, 2), fd);
  // positive: sub(sext(V:4->8), 4) => V s>> 31
  observe("signform_subpiece_sext_4b_pos", signFormRule,
          makeSignForm(fd, block, CPUI_INT_SEXT, 4, 8, 4, 4), fd);
  // negative: truncation offset below |V| -> cc:8466 rejects
  observe("signform_offset_below_size_neg", signFormRule,
          makeSignForm(fd, block, CPUI_INT_SEXT, 1, 4, 1, 0), fd);
  // negative: input defined by INT_ZEXT, not INT_SEXT -> cc:8462 rejects
  observe("signform_zext_input_neg", signFormRule,
          makeSignForm(fd, block, CPUI_INT_ZEXT, 1, 4, 1, 2), fd);
  {
    // negative dispatch (old Rugra dispatched INT_SRIGHT and transformed):
    // INT_SRIGHT is not in the oplist -> untouched.
    Varnode *v = inputVarnode(fd, 1, 0x10);
    PcodeOp *sextOp = makeOp(fd, block, CPUI_INT_SEXT, vector<Varnode *>(1, v), 4);
    PcodeOp *srOp = makeOp(fd, block, CPUI_INT_SRIGHT,
                           {sextOp->getOut(), constantInput(fd, 2, 4)}, 1);
    observe("signform_sright_dispatch_neg", signFormRule, srOp, fd);
  }

  // --- RuleSignNearMult ---
  // positive (n=4): (V + (V s>>31 >> 28)) & 0xfffffff0 => (V s/ 16) * 16
  observe("signnear_n4_pos", signNearMultRule,
          makeNearMult(fd, block, 4, 28, 0xfffffff0, false), fd);
  // positive (n=8, shift side on ADD slot 0): (V + ...) & 0xffffff00 => (V s/ 256) * 256
  observe("signnear_n8_swap_pos", signNearMultRule,
          makeNearMult(fd, block, 4, 24, 0xffffff00, true), fd);
  // negative: mask does not match (calc_mask<<4)&calc_mask = 0xfffffff0 != 0xffffff00
  observe("signnear_mask_mismatch_neg", signNearMultRule,
          makeNearMult(fd, block, 4, 28, 0xffffff00, false), fd);
  {
    // negative: sign shift amount 30 != 8*4-1 -> cc:8577 rejects
    Varnode *x = inputVarnode(fd, 4, 0x10);
    PcodeOp *sshOp = makeOp(fd, block, CPUI_INT_SRIGHT,
                            {x, constantInput(fd, 30, 4)}, 4);
    PcodeOp *rightOp = makeOp(fd, block, CPUI_INT_RIGHT,
                              {sshOp->getOut(), constantInput(fd, 28, 4)}, 4);
    PcodeOp *addOp = makeOp(fd, block, CPUI_INT_ADD, {x, rightOp->getOut()}, 4);
    PcodeOp *andOp = makeOp(fd, block, CPUI_INT_AND,
                            {addOp->getOut(), constantInput(fd, 0xfffffff0, 4)}, 4);
    observe("signnear_wrong_sshift_neg", signNearMultRule, andOp, fd);
  }
  {
    // negative dispatch (old Rugra dispatched INT_MULT and rewrote the
    // existing multiply): INT_MULT is not in the oplist -> untouched.
    Varnode *x = inputVarnode(fd, 4, 0x10);
    PcodeOp *sshOp = makeOp(fd, block, CPUI_INT_SRIGHT,
                            {x, constantInput(fd, 31, 4)}, 4);
    PcodeOp *rightOp = makeOp(fd, block, CPUI_INT_RIGHT,
                              {sshOp->getOut(), constantInput(fd, 28, 4)}, 4);
    PcodeOp *addOp = makeOp(fd, block, CPUI_INT_ADD, {x, rightOp->getOut()}, 4);
    PcodeOp *multOp = makeOp(fd, block, CPUI_INT_MULT,
                             {addOp->getOut(), constantInput(fd, 16, 4)}, 4);
    observe("signnear_mult_dispatch_neg", signNearMultRule, multOp, fd);
  }

  // --- RuleShiftBitops ---
  // positive: (V & 0xf000) << 20 => #0 << 20 (mask fully shifted out)
  observe("bitops_and_left_pos", shiftBitopsRule,
          makeBitopShift(fd, block, CPUI_INT_AND, 0xf000, CPUI_INT_LEFT, 20, 4, 4), fd);
  // positive: (V + 0xf000) << 20 => V << 20 (ADD constant side vanishes)
  observe("bitops_add_left_pos", shiftBitopsRule,
          makeBitopShift(fd, block, CPUI_INT_ADD, 0xf000, CPUI_INT_LEFT, 20, 4, 4), fd);
  // positive: (V | 0xff) >> 24 => V >> 24
  observe("bitops_or_right_pos", shiftBitopsRule,
          makeBitopShift(fd, block, CPUI_INT_OR, 0xff, CPUI_INT_RIGHT, 24, 4, 4), fd);
  // positive: SUBPIECE counts bytes (sa = offset*8): sub(V & 0xff, 1) => #0
  observe("bitops_subpiece_pos", shiftBitopsRule,
          makeBitopShift(fd, block, CPUI_INT_AND, 0xff, CPUI_SUBPIECE, 1, 4, 3), fd);
  // positive: INT_MULT shift amount is leastsigbit_set: (V & 0xf0000) * 0x10000 => #0
  observe("bitops_mult_lsb_pos", shiftBitopsRule,
          makeBitopShift(fd, block, CPUI_INT_AND, 0xf0000, CPUI_INT_MULT, 0x10000, 4, 4), fd);
  // negative: (V & 0xf0) << 4 keeps 0xf00 in the mask -> no swallow
  observe("bitops_no_swallow_neg", shiftBitopsRule,
          makeBitopShift(fd, block, CPUI_INT_AND, 0xf0, CPUI_INT_LEFT, 4, 4, 4), fd);
  // negative: ADD only folds under a left shift (cc:531-533)
  observe("bitops_add_right_neg", shiftBitopsRule,
          makeBitopShift(fd, block, CPUI_INT_ADD, 0xf000, CPUI_INT_RIGHT, 4, 4, 4), fd);
  {
    // negative (old Rugra folded shift-by-0 -> COPY here): sa=0 cannot
    // swallow any nzm, applyOp returns 0 and the op keeps both inputs.
    observe("bitops_shift_by_zero_neg", shiftBitopsRule,
            makeBitopShift(fd, block, CPUI_INT_AND, 0xf, CPUI_INT_LEFT, 0, 4, 4), fd);
    // negative dispatch (old Rugra registered INT_SRIGHT): INT_SRIGHT is
    // not in the oplist -> untouched.
    observe("bitops_sright_dispatch_neg", shiftBitopsRule,
            makeBitopShift(fd, block, CPUI_INT_OR, 0xff, CPUI_INT_SRIGHT, 0, 4, 4), fd);
  }

  // --- RuleShift2Mult ---
  // positive: (V << 3) feeding INT_ADD => V * 8
  observe("shift2mult_desc_add_pos", shift2MultRule,
          makeShiftFeed(fd, block, CPUI_INT_LEFT, 3, CPUI_INT_ADD), fd);
  // positive: input side defined by INT_ADD: (V + W) << 2 => (V + W) * 4
  {
    Varnode *v = inputVarnode(fd, 4, 0x10);
    Varnode *w = inputVarnode(fd, 4, 0x20);
    PcodeOp *addOp = makeOp(fd, block, CPUI_INT_ADD, {v, w}, 4);
    PcodeOp *shiftOp = makeOp(fd, block, CPUI_INT_LEFT,
                              {addOp->getOut(), constantInput(fd, 2, 4)}, 4);
    observe("shift2mult_input_add_pos", shift2MultRule, shiftOp, fd);
  }
  // positive: (V << 3) feeding INT_SUB => V * 8
  observe("shift2mult_desc_sub_pos", shift2MultRule,
          makeShiftFeed(fd, block, CPUI_INT_LEFT, 3, CPUI_INT_SUB), fd);
  // negative: only a COPY consumer -> flag stays 0 (cc:3746)
  observe("shift2mult_no_arith_neg", shift2MultRule,
          makeShiftFeed(fd, block, CPUI_INT_LEFT, 3, CPUI_COPY), fd);
  // negative: shift amount >= 32 (cc:3729-3731)
  observe("shift2mult_big_shift_neg", shift2MultRule,
          makeShiftFeed(fd, block, CPUI_INT_LEFT, 32, CPUI_INT_ADD), fd);
  // negative dispatch (old Rugra registered INT_RIGHT and rewrote V>>c into
  // V * 2^c): INT_RIGHT is not in the oplist -> untouched.
  observe("shift2mult_right_dispatch_neg", shift2MultRule,
          makeShiftFeed(fd, block, CPUI_INT_RIGHT, 3, CPUI_INT_ADD), fd);

  // --- RuleShiftBitops with PROPAGATED nzm (FUNCDATA-CALCNZM follow-up) ---
  // The main pipeline runs ActionNonzeroMask (coreaction.cc:5507) before the
  // rule pools each mainloop, so ruleaction.cc:541 reads the nzm field that
  // Funcdata::calcNZMask (funcdata_varnode.cc:856-927) propagated through
  // written outputs, not the constructor default. Build the chains first,
  // then run calcNZMask (after all prior observations are printed), then
  // observe: without propagation the AND output still reports ~0 and the
  // positive transforms below cannot fire.
  PcodeOp *propAddShift;
  {
    // (the review counterexample): (X + (W & 0x80)) << 7 on 1-byte values.
    Varnode *w = inputVarnode(fd, 1, 0x10);
    PcodeOp *andwOp = makeOp(fd, block, CPUI_INT_AND,
                             {w, constantInput(fd, 0x80, 1)}, 1);
    Varnode *x = inputVarnode(fd, 1, 0x10);
    PcodeOp *addOp = makeOp(fd, block, CPUI_INT_ADD,
                            {x, andwOp->getOut()}, 1);
    propAddShift = makeOp(fd, block, CPUI_INT_LEFT,
                          {addOp->getOut(), constantInput(fd, 7, 4)}, 1);
  }
  PcodeOp *propSubSub;
  {
    // right-shift direction: SUBPIECE(W & 0x8080, 2) on 2-byte values.
    Varnode *w = inputVarnode(fd, 2, 0x10);
    PcodeOp *andwOp = makeOp(fd, block, CPUI_INT_AND,
                             {w, constantInput(fd, 0x8080, 2)}, 2);
    propSubSub = makeOp(fd, block, CPUI_SUBPIECE,
                        {andwOp->getOut(), constantInput(fd, 2, 4)}, 1);
  }
  PcodeOp *propDenseShift;
  {
    // (X + (W & 0xff)) << 1 keeps bits after propagation.
    Varnode *w = inputVarnode(fd, 1, 0x10);
    PcodeOp *andwOp = makeOp(fd, block, CPUI_INT_AND,
                             {w, constantInput(fd, 0xff, 1)}, 1);
    Varnode *x = inputVarnode(fd, 1, 0x10);
    PcodeOp *addOp = makeOp(fd, block, CPUI_INT_ADD,
                            {x, andwOp->getOut()}, 1);
    propDenseShift = makeOp(fd, block, CPUI_INT_LEFT,
                            {addOp->getOut(), constantInput(fd, 1, 4)}, 1);
  }
  fd.calcNZMask();

  // positive: calcNZMask assigns AND-out nzm = 0x80; 0x80 << 7 loses the
  // 1-byte output mask -> break at i=1 -> ADD keeps the surviving X.
  observe("bitops_propagated_add_pos", shiftBitopsRule, propAddShift, fd);
  // positive: AND-out nzm = 0x8080; >> 16 (byte offset 2) is zero -> break
  // at i=0 on a WRITTEN input -> AND collapses to #0.
  observe("bitops_propagated_subpiece_pos", shiftBitopsRule, propSubSub, fd);
  // negative: 0xff << 1 keeps 0xfe in the 1-byte mask after propagation ->
  // no swallow -> untouched.
  observe("bitops_propagated_dense_neg", shiftBitopsRule, propDenseShift, fd);
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: rule_behavioral_1204 SPEC_ROOT CURL_BINARY\n";
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
      codeSpace = architecture.getDefaultCodeSpace();
      regSpace = architecture.getSpaceByName("register");
      if (regSpace == (AddrSpace *)0)
        throw std::runtime_error("fixture requires register space");
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
