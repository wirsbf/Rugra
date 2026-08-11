#include "database.hh"
#include "printc.hh"
#include "variable.hh"

#include <iostream>
#include <sstream>
#include <string>

namespace {

using namespace ghidra;

class FixtureType final : public TypeBase {
public:
  FixtureType(int4 size, bool is_signed)
      : TypeBase(size, is_signed ? TYPE_INT : TYPE_UINT, "fixture_int") {}

  void forceDisplay(uint4 format) { setDisplayFormat(format); }
};

class FixturePrintC final : public PrintC {
public:
  FixturePrintC(void) : PrintC(nullptr, "printc-display-1204") {}

  void pushInteger(uintb value, int4 size, bool is_signed,
                   const Varnode *varnode) {
    push_integer(value, size, is_signed, syntax, varnode, nullptr);
    emit->flush();
  }
};

std::string render(uintb value, int4 size, bool is_signed, uint4 format) {
  std::ostringstream output;
  FixtureType type(size, is_signed);
  type.forceDisplay(format);
  Varnode varnode(size, Address(), &type);
  new HighVariable(&varnode); // Varnode owns and deletes its HighVariable.
  FixturePrintC printer;
  printer.setOutputStream(&output);
  printer.pushInteger(value, size, is_signed, &varnode);
  return output.str();
}

void printWire(const char *name, uint4 value) {
  std::cout << "wire." << name << '=' << value
            << ":decode=" << Datatype::decodeIntegerFormat(value) << '\n';
}

} // namespace

int main() {
  std::cout << "wire.default=0\n";
  printWire("hex", Datatype::encodeIntegerFormat("hex"));
  printWire("dec", Datatype::encodeIntegerFormat("dec"));
  printWire("oct", Datatype::encodeIntegerFormat("oct"));
  printWire("bin", Datatype::encodeIntegerFormat("bin"));
  printWire("char", Datatype::encodeIntegerFormat("char"));

  std::cout << "format.hex=" << render(65, 1, false, Symbol::force_hex)
            << '\n';
  std::cout << "format.dec=" << render(65, 1, false, Symbol::force_dec)
            << '\n';
  std::cout << "format.oct=" << render(65, 1, false, Symbol::force_oct)
            << '\n';
  std::cout << "format.bin=" << render(65, 1, false, Symbol::force_bin)
            << '\n';
  std::cout << "format.char=" << render(65, 1, false, Symbol::force_char)
            << '\n';
  std::cout << "format.char_signed="
            << render(0xff, 1, true, Symbol::force_char) << '\n';
  std::cout << "format.oct_signed="
            << render(0xff, 1, true, Symbol::force_oct) << '\n';
  std::cout << "format.bin_signed="
            << render(0xff, 1, true, Symbol::force_bin) << '\n';
  return 0;
}
