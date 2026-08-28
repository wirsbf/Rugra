/*
 * PRINTLANGUAGE-ATOM-METADATA-0001
 *
 * Locked Ghidra 12.0.4 projection for PrintLanguage::pushAtom/emitAtom.
 * A hidden RPN operator forces the variable Atom through the RPN stack while
 * a recording emitter observes the exact tagVariable arguments.  Native
 * Varnode/PcodeOp pointers are normalized only to fixture creation-order IDs.
 */

#include <bits/stdc++.h>

// The fixture connects the Varnode to its real consuming input slot.  Ghidra
// normally performs this through Funcdata/PcodeOpBank; test-only private access
// keeps this language-independent fixture free of Architecture bootstrap.
#define private public
#include "printc.hh"
#include "op.hh"
#include "varnode.hh"
#undef private

namespace {

using namespace ghidra;

std::string hexText(const std::string &text) {
  static const char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(text.size() * 2);
  for (std::string::const_iterator iter = text.begin(); iter != text.end(); ++iter) {
    const unsigned char value = static_cast<unsigned char>(*iter);
    result.push_back(digits[value >> 4]);
    result.push_back(digits[value & 0xf]);
  }
  return result;
}

std::string colorName(EmitMarkup::syntax_highlight highlight) {
  if (highlight == EmitMarkup::const_color)
    return "const";
  if (highlight == EmitMarkup::no_color)
    return "none";
  throw LowlevelError("unexpected fixture highlight");
}

class RecordingEmit final : public EmitNoMarkup {
  const std::vector<const Varnode *> &varnodes;
  const std::vector<const PcodeOp *> &ops;
  std::vector<std::string> &events;
  int4 nextGroup;

  std::string varnodeId(const Varnode *vn) const {
    if (vn == (const Varnode *)0)
      return "none";
    for (size_t i = 0; i < varnodes.size(); ++i) {
      if (varnodes[i] == vn)
        return "obj" + std::to_string(i);
    }
    throw LowlevelError("unregistered fixture Varnode pointer");
  }

  std::string opId(const PcodeOp *op) const {
    if (op == (const PcodeOp *)0)
      return "none";
    for (size_t i = 0; i < ops.size(); ++i) {
      if (ops[i] == op)
        return "obj" + std::to_string(varnodes.size() + i);
    }
    throw LowlevelError("unregistered fixture PcodeOp pointer");
  }

  void append(const std::string &kind, const std::string &text,
              EmitMarkup::syntax_highlight highlight,
              const Varnode *vn, const PcodeOp *op,
              const std::string &group) {
    std::ostringstream line;
    line << "event=" << events.size()
         << "|kind=" << kind
         << "|text_hex=" << hexText(text)
         << "|highlight=" << colorName(highlight)
         << "|vn=" << varnodeId(vn)
         << "|op=" << opId(op)
         << "|group=" << group;
    events.push_back(line.str());
  }

public:
  RecordingEmit(const std::vector<const Varnode *> &vnOrder,
                const std::vector<const PcodeOp *> &opOrder,
                std::vector<std::string> &output)
      : varnodes(vnOrder), ops(opOrder), events(output), nextGroup(0) {}

  int4 openGroup(void) override {
    const int4 id = nextGroup++;
    append("open_group", "", no_color, (const Varnode *)0,
           (const PcodeOp *)0, "g" + std::to_string(id));
    return id;
  }

  void closeGroup(int4 id) override {
    if (id < 0 || id >= nextGroup)
      throw LowlevelError("unknown fixture group id");
    append("close_group", "", no_color, (const Varnode *)0,
           (const PcodeOp *)0, "g" + std::to_string(id));
  }

  void tagVariable(const std::string &name, syntax_highlight highlight,
                   const Varnode *vn, const PcodeOp *op) override {
    append("variable", name, highlight, vn, op, "none");
  }

  void print(const std::string &data,
             syntax_highlight highlight = no_color) override {
    append("syntax", data, highlight, (const Varnode *)0,
           (const PcodeOp *)0, "none");
  }
};

class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(RecordingEmit *recorder)
      : PrintC((Architecture *)0, "printlanguage-atom-metadata-1204") {
    delete emit;
    emit = recorder;
  }

  void emitFixture(const Varnode *vn, const PcodeOp *consumer) {
    const std::string constantText("'\\0'");
    const std::string syntaxText(";");
    const OpToken fixtureHidden = {
        "", "", 1, 70, false, OpToken::hiddenfunction, 0, 0,
        (OpToken *)0};

    // The locked PrintC hidden token is a stage-1 operator.  An explicit copy
    // makes the RPN input manifest self-contained while exercising the
    // non-empty stack branch without adding an unrelated visible event.
    pushOp(&fixtureHidden, consumer);
    pushAtom(Atom(constantText, vartoken, EmitMarkup::const_color,
                  consumer, vn, 0));

    // Repeating the same annotations proves identity is stable across events,
    // rather than a per-event pointer rendering artifact.
    pushOp(&fixtureHidden, consumer);
    pushAtom(Atom(constantText, vartoken, EmitMarkup::const_color,
                  consumer, vn, 0));

    // The no-annotation Atom constructor deliberately leaves the union/op
    // members unspecified.  emitAtom's syntax branch must not read them.
    pushAtom(Atom(syntaxText, syntax, EmitMarkup::no_color));

    if (!revpol.empty() || !nodepend.empty() || pending != 0)
      throw LowlevelError("Ghidra fixture did not drain RPN state");
  }
};

} // namespace

int main() {
  Varnode constant(1, Address((AddrSpace *)0, 0), (Datatype *)0);
  constant.flags |= Varnode::constant;
  constant.nzm = 0;
  PcodeOp consumer(1, SeqNum(Address((AddrSpace *)0, 0), 43));
  consumer.setInput(&constant, 0);
  if (!constant.isConstant() || constant.getOffset() != 0 ||
      consumer.getIn(0) != &constant)
    throw LowlevelError("fixture consuming-op precondition failed");

  const std::vector<const Varnode *> varnodeOrder(1, &constant);
  const std::vector<const PcodeOp *> opOrder(1, &consumer);
  std::vector<std::string> events;
  {
    RecordingEmit *recorder = new RecordingEmit(varnodeOrder, opOrder, events);
    FixturePrintC printer(recorder);
    printer.emitFixture(&constant, &consumer);
  }

  std::cout
      << "schema=1|fixture=PRINTLANGUAGE-ATOM-METADATA-0001"
      << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
      << "|covered_projection=MATCH|overall=MISMATCH\n";
  for (std::vector<std::string>::const_iterator iter = events.begin();
       iter != events.end(); ++iter)
    std::cout << *iter << '\n';
  return 0;
}
