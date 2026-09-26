/*
 * WORKPKG-UNMAP-STRFOLD-0006 / CONSTSEQ-STRINGCOPY-0001 locked Ghidra 12.0.4
 * oracle fixture: RuleStringCopy::applyOp (constseq.cc:954) driving the real
 * StringSequence analysis chain (ctor cc:188 / collectCopyOps cc:227 /
 * checkInterference cc:62 / formByteArray cc:108 / constructTypedPointer
 * cc:273 / buildStringCopy cc:347 / removeForward cc:383 / removeCopyOps
 * cc:415 / transform cc:453).
 *
 * Every case installs a real ScopeLocal Symbol (Scope::addSymbol on the
 * BfdArchitecture local scope of function GetStr), builds constant-character
 * COPY ops into stack addresses typed as the canonical factory char, and
 * calls the real rule's applyOp. The observation surface after the call:
 *  - the rule's return value,
 *  - the surviving ops of the basic block in block order: opcode, input
 *    count, per-slot varnode observations (constants with their values,
 *    stack/register storages, unique varnodes by their defining opcode),
 *    and the output varnode's factory type name,
 *  - the count of surviving COPY ops,
 *  - the string bytes read back through the architecture's real
 *    StringManagerUnicode::getStringData (stringmanage.cc:427) at the
 *    STRINGDATA hash constant, plus the truncation flag.
 *
 * Deliberate blind spots (allocation-only or side-specific encodings, the
 * rule_store_varnode_spacebase_1204 precedent): raw space-id constants, the
 * iop-space constant encoding of INDIRECT effect ops, unique-space offsets.
 */

#include "bfd_arch.hh"
#include "constseq.hh"
#include "funcdata.hh"
#include "libdecomp.hh"

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

/// Stable observation of one varnode (or '-' for null).
string vnState(const Varnode *vn)
{
  if (vn == (const Varnode *)0)
    return string("-");
  if (vn->isConstant()) {
    ostringstream h;
    h << "const:" << vn->getSize() << ':' << std::hex << vn->getOffset();
    return h.str();
  }
  AddrSpace *spc = vn->getSpace();
  if (spc->getType() == IPTR_IOP)
    return string("iop");
  if (spc->getType() == IPTR_INTERNAL) {
    const PcodeOp *def = vn->getDef();
    return string("unique:def=") + ((def == (const PcodeOp *)0) ? "nodef" : def->getOpcode()->getName());
  }
  ostringstream out;
  out << spc->getName() << ':' << std::hex << vn->getOffset() << std::dec
      << ':' << vn->getSize();
  return out.str();
}

/// Stable observation of one op: block-order index, opcode, input count,
/// per-slot inputs (up to 3), output varnode and output type name.
void dumpOp(int4 seq, const PcodeOp *op)
{
  ostringstream out;
  out << "op=" << seq << '|' << op->getOpcode()->getName()
      << "|ins=" << op->numInput();
  for (int4 i = 0; i < op->numInput() && i < 3; ++i)
    out << "|a" << i << '=' << vnState(op->getIn(i));
  const Varnode *res = op->getOut();
  if (res == (const Varnode *)0) {
    out << "|out=-|type=-";
  }
  else {
    out << "|out=" << vnState(res);
    const Datatype *ct = res->getType();
    out << "|type=" << ((ct == (const Datatype *)0) ? string("-") : ct->getName());
  }
  std::cout << out.str() << '\n';
}

/// Dump the whole surviving op list of the block plus the COPY count.
void dumpBlock(BlockBasic *block)
{
  int4 seq = 0;
  int4 copyCount = 0;
  for (list<PcodeOp *>::const_iterator iter = block->beginOp(); iter != block->endOp(); ++iter) {
    const PcodeOp *op = *iter;
    if (op->code() == CPUI_COPY)
      copyCount += 1;
    dumpOp(seq, *iter);
    seq += 1;
  }
  std::cout << "alive_ops=" << seq << "|copies=" << copyCount << '\n';
}

/// Read the internal string back through the manager at the STRINGDATA hash
/// (the CALLOTHER with a 2-input form whose input0 is BUILTIN_STRINGDATA).
void dumpStringReadback(Funcdata &fd, AddrSpace *constspc, Datatype *charT)
{
  bool found = false;
  for (list<PcodeOp *>::const_iterator iter = fd.beginOpAlive(); iter != fd.endOpAlive(); ++iter) {
    const PcodeOp *op = *iter;
    if (op->code() != CPUI_CALLOTHER || op->numInput() != 2)
      continue;
    if (op->getIn(0)->getOffset() != UserPcodeOp::BUILTIN_STRINGDATA)
      continue;
    uint8 hash = op->getIn(1)->getOffset();
    found = true;
    Address constAddr(constspc, hash);
    bool isTrunc = false;
    const vector<uint1> &data(fd.getArch()->stringManager->getStringData(constAddr, charT, isTrunc));    ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (int4 i = 0; i < data.size(); ++i)
      hex << std::setw(2) << (int4)data[i];
    std::cout << "string_hash=" << hash << "|bytes=" << hex.str()
              << "|trunc=" << (isTrunc ? 1 : 0) << "|len=" << data.size() << '\n';
  }
  if (!found)
    std::cout << "string_hash=-\n";
}

/// Per-case builder: a fresh basic block plus constant-character COPY
/// construction into typed stack varnodes.
class Fixture {
  Funcdata &fd;
public:
  BlockBasic *block;
private:
  AddrSpace *stack;
  AddrSpace *code;
  Datatype *charT;
  uintb codeAddr;

public:
  vector<PcodeOp *> copies;

  explicit Fixture(Funcdata &f, Datatype *ct, uintb baseCodeAddr)
    : fd(f), block((BlockBasic *)0), stack(f.getArch()->getStackSpace()),
      code(f.getArch()->getDefaultCodeSpace()), charT(ct), codeAddr(baseCodeAddr)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    block = graph.newBlockBasic(&fd);
  }

  ~Fixture(void)
  {
    // Leave the IR behind; the Funcdata owns it.
  }

  PcodeOp *makeCopy(uintb stackOff, uintb ch)
  {
    PcodeOp *op = fd.newOp(1, Address(code, codeAddr));
    codeAddr += 1;
    fd.opSetOpcode(op, CPUI_COPY);
    fd.opSetInput(op, fd.newConstant(1, ch), 0);
    Varnode *vn = fd.newVarnode(1, stack, stackOff);
    vn->updateType(charT);
    fd.opSetOutput(op, vn);
    fd.opInsertEnd(op, block);
    copies.push_back(op);
    return op;
  }

  PcodeOp *makeWideCopy(uintb stackOff, uintb ch)
  {
    // A 2-byte COPY output: collectCopyOps must reject it (constseq.cc:246).
    PcodeOp *op = fd.newOp(1, Address(code, codeAddr));
    codeAddr += 1;
    fd.opSetOpcode(op, CPUI_COPY);
    fd.opSetInput(op, fd.newConstant(2, ch), 0);
    Varnode *vn = fd.newVarnode(2, stack, stackOff);
    vn->updateType(charT);
    fd.opSetOutput(op, vn);
    fd.opInsertEnd(op, block);
    copies.push_back(op);
    return op;
  }

  void run(const string &name, PcodeOp *root)
  {
    RuleStringCopy rule("constsequence");
    int4 res = rule.applyOp(root, fd);
    std::cout << "case=" << name << "|ret=" << res << '\n';
    dumpBlock(block);
    dumpStringReadback(fd, fd.getArch()->getConstantSpace(), charT);
  }
};

void runCases(Funcdata &fd)
{
  AddrSpace *stack = fd.getArch()->getStackSpace();
  TypeFactory *types = fd.getArch()->types;
  Datatype *charT = types->getTypeChar(types->getSizeOfChar());
  ScopeLocal *lm = fd.getScopeLocal();

  // flat_array: char[16] symbol, "Hello\0" at the symbol start. Exercises
  // the array-layer walk with root offset 0 (PTRADD(#0) skipped, cc:304-307)
  // and the BUILTIN_STRNCPY selection.
  {
    TypeArray *arrT = types->getTypeArray(16, charT);
    lm->addSymbol("name_buf", arrT, Address(stack, 0x2000), Address());
    Fixture fx(fd, charT, 0x400000);
    const char *hello = "Hello";
    for (int4 i = 0; i < 5; ++i)
      fx.makeCopy(0x2000 + i, (uintb)hello[i]);
    fx.makeCopy(0x2005, 0);
    fx.run("flat_array", fx.copies[0]);
  }

  // nested_struct: struct { char buf[16]; int len; } with "World\0" at the
  // struct start. Exercises the struct-level PTRSUB arm (cc:316-318) before
  // the array layer.
  {
    TypeStruct *st = types->getTypeStruct("holder_t");
    vector<TypeField> fields;
    TypeArray *bufT = types->getTypeArray(16, charT);
    fields.push_back(TypeField(0, 0, "buf", bufT));
    Datatype *intT = types->getBase(4, TYPE_INT);
    fields.push_back(TypeField(1, 16, "len", intT));
    types->setFields(fields, st, 20, 4, 0);
    lm->addSymbol("holder", st, Address(stack, 0x2100), Address());
    Fixture fx(fd, charT, 0x400100);
    const char *world = "World";
    for (int4 i = 0; i < 5; ++i)
      fx.makeCopy(0x2100 + i, (uintb)world[i]);
    fx.makeCopy(0x2105, 0);
    fx.run("nested_struct", fx.copies[0]);
  }

  // array_offset_root: char[16] symbol with "Tail!\0" starting 2 bytes in.
  // Exercises the root-offset walk (lastOff=2, startAddr back 2) and the
  // PTRADD(prev, numEl=2, elSize=1) arm (cc:309-313).
  {
    TypeArray *arrT = types->getTypeArray(16, charT);
    lm->addSymbol("tail_buf", arrT, Address(stack, 0x2200), Address());
    Fixture fx(fd, charT, 0x400200);
    const char *tail = "Tail!";
    for (int4 i = 0; i < 5; ++i)
      fx.makeCopy(0x2202 + i, (uintb)tail[i]);
    fx.makeCopy(0x2207, 0);
    fx.run("array_offset_root", fx.copies[0]);
  }

  // too_short: "Hi\0" (3 ops < MINIMUM_SEQUENCE_LENGTH) — collectCopyOps
  // returns false (cc:263), the sequence stays invalid, ret=0.
  {
    TypeArray *arrT = types->getTypeArray(16, charT);
    lm->addSymbol("tiny_buf", arrT, Address(stack, 0x2300), Address());
    Fixture fx(fd, charT, 0x400300);
    fx.makeCopy(0x2300, 'H');
    fx.makeCopy(0x2301, 'i');
    fx.makeCopy(0x2302, 0);
    fx.run("too_short", fx.copies[0]);
  }

  // root_not_first: applying the rule on the second COPY of "Abcd\0" —
  // collectCopyOps sees the previous-element COPY and returns false
  // (cc:250-251), ret=0.
  {
    TypeArray *arrT = types->getTypeArray(16, charT);
    lm->addSymbol("order_buf", arrT, Address(stack, 0x2350), Address());
    Fixture fx(fd, charT, 0x400380);
    const char *abcd = "Abcd";
    for (int4 i = 0; i < 4; ++i)
      fx.makeCopy(0x2350 + i, (uintb)abcd[i]);
    fx.makeCopy(0x2354, 0);
    fx.run("root_not_first", fx.copies[1]);
  }

  // gap_in_copies: "ABCD" with a 2-byte gap before "E\0" — the loc walk
  // breaks at the gap (cc:257-258), leaving the 4 leading COPYs; the
  // unterminated 4-character run still forms a legal string (cc:135-142
  // counts to the first unused element).
  {
    TypeArray *arrT = types->getTypeArray(16, charT);
    lm->addSymbol("gap_buf", arrT, Address(stack, 0x2400), Address());
    Fixture fx(fd, charT, 0x400400);
    const char *abcd = "ABCD";
    for (int4 i = 0; i < 4; ++i)
      fx.makeCopy(0x2400 + i, (uintb)abcd[i]);
    fx.makeCopy(0x2406, 'E');
    fx.makeCopy(0x2407, 0);
    fx.run("gap_in_copies", fx.copies[0]);
  }

  // wide_copy: a 2-byte COPY output in the sequence — collectCopyOps
  // returns false at the size guard (cc:246-247), ret=0.
  {
    TypeArray *arrT = types->getTypeArray(16, charT);
    lm->addSymbol("wide_buf", arrT, Address(stack, 0x2450), Address());
    Fixture fx(fd, charT, 0x400480);
    fx.makeCopy(0x2450, 'O');
    fx.makeCopy(0x2451, 'K');
    fx.makeWideCopy(0x2452, 'X');
    fx.makeCopy(0x2454, 'Y');
    fx.makeCopy(0x2455, 0);
    fx.run("wide_copy", fx.copies[0]);
  }

  // concat_cascade: "Pair\0" whose first three COPY outputs feed two chained
  // PIECE ops (the CONCAT-stack form, cc:411-413), and a fourth COPY feeds a
  // non-PIECE INT_ADD reader. Exercises removeForward's both arms (xref
  // double-visit merge and plain point record), the dead-PIECE cascade, the
  // surviving point's INDIRECT redefinition around the CALLOTHER
  // (cc:429-441), and the destruction pass (cc:443-446).
  {
    TypeArray *arrT = types->getTypeArray(16, charT);
    lm->addSymbol("pair_buf", arrT, Address(stack, 0x2500), Address());
    Fixture fx(fd, charT, 0x400500);
    const char *pair = "Pair";
    for (int4 i = 0; i < 4; ++i)
      fx.makeCopy(0x2500 + i, (uintb)pair[i]);
    fx.makeCopy(0x2504, 0);
    Varnode *copy0 = fx.copies[0]->getOut();
    Varnode *copy1 = fx.copies[1]->getOut();
    Varnode *copy2 = fx.copies[2]->getOut();
    Varnode *copy3 = fx.copies[3]->getOut();
    // piece1 = PIECE(copy1, copy0)
    PcodeOp *piece1 = fd.newOp(2, Address(fd.getArch()->getDefaultCodeSpace(), 0x400510));
    fd.opSetOpcode(piece1, CPUI_PIECE);
    fd.opSetInput(piece1, copy1, 0);
    fd.opSetInput(piece1, copy0, 1);
    fd.newUniqueOut(2, piece1);
    fd.opInsertEnd(piece1, fx.block);
    // piece2 = PIECE(piece1_out, copy2)
    PcodeOp *piece2 = fd.newOp(2, Address(fd.getArch()->getDefaultCodeSpace(), 0x400511));
    fd.opSetOpcode(piece2, CPUI_PIECE);
    fd.opSetInput(piece2, piece1->getOut(), 0);
    fd.opSetInput(piece2, copy2, 1);
    fd.newUniqueOut(3, piece2);
    fd.opInsertEnd(piece2, fx.block);
    // int_add = INT_ADD(copy3, const) — the surviving non-PIECE point.
    PcodeOp *addOp = fd.newOp(2, Address(fd.getArch()->getDefaultCodeSpace(), 0x400512));
    fd.opSetOpcode(addOp, CPUI_INT_ADD);
    fd.opSetInput(addOp, copy3, 0);
    fd.opSetInput(addOp, fd.newConstant(2, 0x10), 1);
    fd.newUniqueOut(2, addOp);
    fd.opInsertEnd(addOp, fx.block);
    fx.run("concat_cascade", fx.copies[0]);
  }
}

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
    if (fd->getName() != "GetStr" || fd->getAddress().getOffset() != 0x36d0)
      throw std::runtime_error("GetStr input identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " + architecture.archid);
    std::cout << "fixture=CONSTSEQ-STRINGCOPY-1204\n";
    std::cout << "architecture=" << architecture.archid << '\n';
    runCases(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: constseq_stringcopy_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "constseq_stringcopy_1204: LowlevelError: " << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "constseq_stringcopy_1204: " << error.what() << '\n';
    return 1;
  }
}
