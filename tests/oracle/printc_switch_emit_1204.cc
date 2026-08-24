/*
 * PRINTC-SWITCH-EMIT-0001: locked Ghidra 12.0.4
 * PrintC::emitBlockSwitch (printc.cc:3313-3353) + PrintC::emitSwitchCase
 * (printc.cc:3129-3158) oracle, covering the switch case emission path:
 * the case-label/group/colon emission points, the case-body emission point
 * (bl2->emit(this), printc.cc:3339-3341 — the call that Rugra's DEAD-guard
 * used to swallow after the BlockSwitch install), the isExit(i)&&!last
 * break placement (cc:3342-3345), and the openBrace(same_line)/startIndent
 * byte layout (cc:3329/3333/3348, option_brace_switch=same_line printc.cc:1593).
 *
 * The fixture builds the production structure-copy shape by hand: original
 * BlockBasic blocks (head with the BRANCHIND, case bodies with 2-input
 * RETURNs) linked by real FlowBlock edges, BlockCopy mirrors created
 * through BlockGraph::newBlockCopy + copymap/replaceUsingMap exactly as
 * BlockGraph::buildCopy (block.cc:1925-1938) does, a JumpTable whose
 * label/block2addr tables drive emitSwitchCase's getLabel/numIndicesByBlock
 * reads, and finally grabCaseBasic + identifyInternal + addBlock — the same
 * calls BlockGraph::newBlockSwitch (block.cc:1904-1919) performs (the
 * BlockSwitch constructor is invoked on a branchless block so the
 * jumptable lookup stays null-safe without a Funcdata; jump is installed
 * directly afterwards).
 *
 * Cases:
 *   1. two_case_return      — labels {0},{1}, RETURN-terminated bodies:
 *                             label/body order, no breaks (isexit=false),
 *                             last-case suppression is moot.
 *   2. single_case_default  — label {5} + a default edge
 *                             (f_defaultswitch_edge): the KEYWORD_DEFAULT
 *                             rendering of emitSwitchCase cc:3140-3145.
 *   3. multi_label_first    — first case block reached by TWO table entries
 *                             (labels {2,3}) — the first-emitted label group
 *                             plus its body (the timing-defect detector:
 *                             first label must precede its body, in order).
 *   4. break_exit_form      — three cases; the first has an out-edge to the
 *                             formal exit (isexit=true, not last) and an
 *                             empty body: the explicit `break;` of
 *                             cc:3342-3345 between the remaining cases.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as blockstruct_goto_cascade_1204.cc): the
// fixture drives production structures whose helpers are protected/private
// (identifyInternal, BlockBasic::insert, JumpTable tables, BlockSwitch::jump,
// FlowBlock::copymap). `class -> struct` + `private -> public` opens them in
// this TU only.
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "blockaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "jumptable.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "printc.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef class
#undef private

using namespace ghidra;

class FixturePrintC final : public PrintC {
public:
  FixturePrintC(void) : PrintC(nullptr, "printc-switch-emit-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  void render(const BlockSwitch *bl) {
    emitBlockSwitch(bl);
    emit->flush();
  }
};

static void append(BlockBasic &block, PcodeOp *op)
{
  block.insert(block.endOp(), op);
}

// One switch under construction. originals are owned by this struct; the
// structure graph owns the BlockCopy/BlockSwitch nodes as in production.
struct SwitchBuild {
  PcodeOpBank bank;
  ConstantSpace constant_space;
  TypeBase int_type;
  TypeOpBranchind branchind_type;
  TypeOpReturn return_type;

  BlockBasic head{nullptr};
  std::vector<BlockBasic *> cases;	// in out-edge order
  BlockBasic *defcase;			// case on the default edge (may be null)
  BlockBasic *exitb;			// formal exit block (may be null)

  JumpTable jt;
  BlockGraph structure;
  BlockSwitch *bs;

  Varnode swvar;			// the BRANCHIND input (switch variable)

  explicit SwitchBuild(uintb switch_var_value)
    : constant_space(nullptr, nullptr), int_type(4, TYPE_INT),
      branchind_type(nullptr), return_type(nullptr), defcase(nullptr),
      exitb(nullptr), jt(nullptr, Address()), bs((BlockSwitch *)0),
      swvar(4, Address(&constant_space, switch_var_value), &int_type)
  {
    new HighVariable(&swvar);
  }

  // 2-input RETURN with value const(value) — Ghidra's post-
  // ActionReturnRecovery shape (coreaction.cc:1836 buildReturnOutput keeps
  // in(0), the return indirect reference, and attaches the value at in(1)).
  PcodeOp *make_return(uintb value)
  {
    Varnode *val = new Varnode(4, Address(&constant_space, value), &int_type);
    new HighVariable(val);
    PcodeOp *op = bank.create(2, Address());
    bank.changeOpcode(op, &return_type);
    op->setInput(&swvar, 0);		// placeholder indirect slot (never read)
    op->setInput(val, 1);
    return op;
  }

  // Build the BRANCHIND-terminated head block and wire the jumptable tables.
  // labels[i] is the case label of out-edge i; a null labels[i] entry means
  // edge i is the default edge.
  void build_head(const std::vector<std::vector<uintb> > &edge_labels)
  {
    PcodeOp *ind = bank.create(1, Address());
    bank.changeOpcode(ind, &branchind_type);
    ind->setInput(&swvar, 0);
    append(head, ind);
    jt.setIndirectOp(ind);
    for (int4 edge = 0; edge < (int4)edge_labels.size(); ++edge)
      for (int4 k = 0; k < (int4)edge_labels[edge].size(); ++k) {
	jt.label.push_back(edge_labels[edge][k]);
	jt.block2addr.push_back(JumpTable::IndexPair(edge, (int4)jt.label.size() - 1));
      }
    std::sort(jt.block2addr.begin(), jt.block2addr.end());
  }

  void edge(FlowBlock *from, FlowBlock *to) { structure.addEdge(from, to); }

  // Mirror BlockGraph::buildCopy (block.cc:1925-1938): one BlockCopy per
  // original, copymap back-references, then replaceUsingMap on each copy.
  // Then install the BlockSwitch through the same calls as
  // BlockGraph::newBlockSwitch (block.cc:1904-1919): grabCaseBasic on the
  // ORIGINAL head (whose in-edges the case lookups read), identifyInternal
  // consuming the copies in cs order, addBlock.
  void finish(const std::vector<FlowBlock *> &extra_originals)
  {
    std::vector<FlowBlock *> originals;
    originals.push_back(&head);
    for (int4 i = 0; i < (int4)cases.size(); ++i) originals.push_back(cases[i]);
    if (defcase != nullptr) originals.push_back(defcase);
    if (exitb != nullptr) originals.push_back(exitb);
    for (int4 i = 0; i < (int4)extra_originals.size(); ++i)
      originals.push_back(extra_originals[i]);

    std::vector<BlockCopy *> copies;
    for (int4 i = 0; i < (int4)originals.size(); ++i) {
      BlockCopy *c = structure.newBlockCopy(originals[i]);
      originals[i]->copymap = c;
      copies.push_back(c);
    }
    for (int4 i = 0; i < (int4)copies.size(); ++i)
      copies[i]->replaceUsingMap();

    std::vector<FlowBlock *> cs;
    cs.push_back(copies[0]);				// head copy = cs[0]
    for (int4 i = 0; i < (int4)cases.size(); ++i)
      cs.push_back(copies[1 + i]);
    if (defcase != nullptr) cs.push_back(copies[1 + (int4)cases.size()]);

    // The BlockSwitch constructor (block.cc:3485) dereferences
    // ind->getJumptable(); on a Funcdata-less block whose lastOp is the
    // BRANCHIND that walk would dereference a null Funcdata, so construct
    // against a branchless block (lastOp()==0 keeps the lookup null) and
    // install the fixture jumptable directly.
    static BlockBasic hollow(nullptr);
    bs = new BlockSwitch(&hollow);
    bs->jump = &jt;
    bs->grabCaseBasic(&head, cs);
    structure.identifyInternal(bs, cs);
    structure.addBlock(bs);
  }

  std::string render(void)
  {
    std::ostringstream output;
    FixturePrintC printer;
    printer.setOutputStream(&output);
    printer.render(bs);
    return output.str();
  }
};

static std::string to_hex(const std::string &value)
{
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (const unsigned char byte : value)
    stream << std::setw(2) << static_cast<unsigned int>(byte);
  return stream.str();
}

// Normalize a raw emit into the structural observation:
//   switch(E)          — the switch header with the control expression elided
//   case <label>:      — verbatim (labels are the core observable)
//   default:           — verbatim
//   <indent><kind>     — body statements reduced to their kind
//                        (break/return/assign/other), indent preserved.
static std::string summarize(const std::string &text)
{
  std::istringstream input(text);
  std::ostringstream out;
  std::string line;
  while (std::getline(input, line)) {
    const std::string body = line.substr(line.find_first_not_of(' ') == std::string::npos
					   ? 0 : line.find_first_not_of(' '));
    const size_t indent = line.size() - body.size();
    const std::string pad(indent, ' ');
    if (body.rfind("switch", 0) == 0)
      out << pad << "switch(E)\n";
    else if (body.rfind("case ", 0) == 0 || body == "default:")
      out << line << '\n';
    else if (body == "break;")
      out << pad << "break\n";
    else if (body.rfind("return", 0) == 0)
      out << pad << "return\n";
    else if (body.find(" = ") != std::string::npos)
      out << pad << "assign\n";
    else if (!body.empty())
      out << pad << "other\n";
  }
  return out.str();
}

static void emit_case(const std::string &name, const std::string &raw, bool hex)
{
  std::cout << name << '=' << (hex ? to_hex(raw) : summarize(raw)) << '\n';
}

int main(int argc, char **argv)
{
  const bool raw = argc == 2 && std::string(argv[1]) == "--raw";
  {
    // 1. two_case_return
    SwitchBuild s(3);
    s.build_head(std::vector<std::vector<uintb> > { {0}, {1} });
    BlockBasic *c0 = new BlockBasic(nullptr), *c1 = new BlockBasic(nullptr);
    append(*c0, s.make_return(10));
    append(*c1, s.make_return(20));
    s.cases = { c0, c1 };
    s.edge(&s.head, c0);
    s.edge(&s.head, c1);
    s.finish({});
    emit_case("two_case_return", s.render(), raw);
  }
  {
    // 2. single_case_default. NOTE: the default edge carries a table entry
    // ({6}) even though emitSwitchCase's default arm (cc:3140-3145) only
    // feeds the value to tagCaseLabel's markup — production jumptables
    // always have an entry for the default destination, and the arm calls
    // getLabel(casenum,0) unconditionally.
    SwitchBuild s(3);
    s.build_head(std::vector<std::vector<uintb> > { {5}, {6} });
    BlockBasic *c5 = new BlockBasic(nullptr);
    BlockBasic *def = new BlockBasic(nullptr);
    append(*c5, s.make_return(60));
    append(*def, s.make_return(7));
    s.cases = { c5 };
    s.defcase = def;
    s.edge(&s.head, c5);
    s.edge(&s.head, def);
    s.head.setOutEdgeFlag(1, FlowBlock::f_defaultswitch_edge);
    s.finish({});
    emit_case("single_case_default", s.render(), raw);
  }
  {
    // 3. multi_label_first
    SwitchBuild s(3);
    s.build_head(std::vector<std::vector<uintb> > { {2, 3}, {9} });
    BlockBasic *ca = new BlockBasic(nullptr), *cb = new BlockBasic(nullptr);
    append(*ca, s.make_return(10));
    append(*cb, s.make_return(20));
    s.cases = { ca, cb };
    s.edge(&s.head, ca);
    s.edge(&s.head, cb);
    s.finish({});
    emit_case("multi_label_first", s.render(), raw);
  }
  {
    // 4. break_exit_form
    SwitchBuild s(3);
    s.build_head(std::vector<std::vector<uintb> > { {0}, {1}, {2} });
    BlockBasic *c0 = new BlockBasic(nullptr);
    BlockBasic *c1 = new BlockBasic(nullptr);
    BlockBasic *c2 = new BlockBasic(nullptr);
    BlockBasic *exitb = new BlockBasic(nullptr);
    append(*c1, s.make_return(30));
    append(*c2, s.make_return(40));
    s.cases = { c0, c1, c2 };
    s.exitb = exitb;
    s.edge(&s.head, c0);
    s.edge(&s.head, c1);
    s.edge(&s.head, c2);
    s.edge(c0, exitb);		// case 0 flows to the formal exit: isexit=true
    s.finish({});
    emit_case("break_exit_form", s.render(), raw);
  }
  return 0;
}
