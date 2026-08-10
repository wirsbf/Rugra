#include "typeop.hh"

#include <cstdlib>
#include <iostream>

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    const int input = std::atoi(argv[i]);
    std::cout << input << ':'
              << ghidra::TypeOpFloatInt2Float::preferredZextSize(input) << '\n';
  }
  return 0;
}
