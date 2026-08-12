#include "printc.hh"

#include <iostream>
#include <sstream>
#include <string>

namespace {

using namespace ghidra;

class FixturePrintC final : public PrintC {
public:
  FixturePrintC(void) : PrintC(nullptr, "printlanguage-group-1204") {}

  void rootUnary(void) {
    const std::string x("x");
    pushOp(&boolean_not, nullptr);
    pushAtom(Atom(x, syntax, EmitMarkup::no_color));
    emit->flush();
  }

  void rootBinary(void) {
    const std::string a("a");
    const std::string b("b");
    pushOp(&binary_plus, nullptr);
    pushAtom(Atom(a, syntax, EmitMarkup::no_color));
    pushAtom(Atom(b, syntax, EmitMarkup::no_color));
    emit->flush();
  }

  void nestedInvisible(void) {
    const std::string a("a");
    const std::string b("b");
    const std::string c("c");
    pushOp(&binary_plus, nullptr);
    pushAtom(Atom(a, syntax, EmitMarkup::no_color));
    pushOp(&multiply, nullptr);
    pushAtom(Atom(b, syntax, EmitMarkup::no_color));
    pushAtom(Atom(c, syntax, EmitMarkup::no_color));
    emit->flush();
  }

  void nestedParenthesized(void) {
    const std::string a("a");
    const std::string b("b");
    const std::string c("c");
    pushOp(&multiply, nullptr);
    pushAtom(Atom(a, syntax, EmitMarkup::no_color));
    pushOp(&binary_plus, nullptr);
    pushAtom(Atom(b, syntax, EmitMarkup::no_color));
    pushAtom(Atom(c, syntax, EmitMarkup::no_color));
    emit->flush();
  }
};

template <typename Callback>
std::string render(Callback callback) {
  std::ostringstream output;
  FixturePrintC printer;
  printer.setOutputStream(&output);
  callback(printer);
  return output.str();
}

} // namespace

int main() {
  std::cout << "root_unary="
            << render([](FixturePrintC &printer) { printer.rootUnary(); })
            << '\n';
  std::cout << "root_binary="
            << render([](FixturePrintC &printer) { printer.rootBinary(); })
            << '\n';
  std::cout << "nested_invisible="
            << render([](FixturePrintC &printer) { printer.nestedInvisible(); })
            << '\n';
  std::cout << "nested_parenthesized="
            << render([](FixturePrintC &printer) {
                 printer.nestedParenthesized();
               })
            << '\n';
  return 0;
}
