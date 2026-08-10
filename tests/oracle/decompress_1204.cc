#include "compression.hh"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

namespace {

using namespace ghidra;

const uint1 HELLO_ZLIB[] = {0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
                            0x07, 0x00, 0x06, 0x2c, 0x02, 0x15};
const uint1 WORLD_ZLIB[] = {0x78, 0x9c, 0x2b, 0xcf, 0x2f, 0xca, 0x49,
                            0x01, 0x00, 0x06, 0xa6, 0x02, 0x29};

const char *truth(bool value) { return value ? "true" : "false"; }

void print_hex(const uint1 *buffer, int4 size) {
  std::ios_base::fmtflags flags = std::cout.flags();
  for (int4 i = 0; i < size; ++i)
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<unsigned int>(buffer[i]);
  std::cout.flags(flags);
}

} // namespace

int main() {
  std::cout << "zlib.version=" << zlibVersion() << '\n';

  {
    Decompress stream;
    uint1 output[8] = {};
    int4 remaining = stream.inflate(output, sizeof(output));
    std::cout << "no_input.remaining=" << remaining
              << ":finished=" << truth(stream.isFinished()) << '\n';
  }

  {
    uint1 hello[sizeof(HELLO_ZLIB)];
    uint1 world[sizeof(WORLD_ZLIB)];
    std::memcpy(hello, HELLO_ZLIB, sizeof(hello));
    std::memcpy(world, WORLD_ZLIB, sizeof(world));
    Decompress stream;
    stream.input(hello, sizeof(hello));
    uint1 first[1] = {};
    int4 first_remaining = stream.inflate(first, sizeof(first));
    stream.input(world, sizeof(world));
    uint1 second[64] = {};
    int4 second_remaining = stream.inflate(second, sizeof(second));
    std::cout << "midstream_replace.first_remaining=" << first_remaining
              << ":second_remaining=" << second_remaining
              << ":finished=" << truth(stream.isFinished()) << ":hex=";
    print_hex(second, sizeof(second) - second_remaining);
    std::cout << '\n';
  }

  {
    uint1 hello[sizeof(HELLO_ZLIB)];
    std::memcpy(hello, HELLO_ZLIB, sizeof(hello));
    Decompress stream;
    stream.input(hello, sizeof(hello));
    hello[0] = 0;
    uint1 output[8] = {};
    try {
      stream.inflate(output, sizeof(output));
      std::cout << "alias_mutation.error=none\n";
    } catch (const LowlevelError &error) {
      std::cout << "alias_mutation.error=" << error.explain << '\n';
    }
  }

  {
    uint1 buffer[64] = {};
    std::memcpy(buffer, HELLO_ZLIB, sizeof(HELLO_ZLIB));
    Decompress stream;
    stream.input(buffer, sizeof(HELLO_ZLIB));
    int4 remaining = stream.inflate(buffer, sizeof(HELLO_ZLIB));
    std::cout << "same_address.remaining=" << remaining
              << ":finished=" << truth(stream.isFinished()) << ":hex=";
    print_hex(buffer, sizeof(HELLO_ZLIB) - remaining);
    std::cout << '\n';
  }

  {
    Decompress stream;
    stream.input(const_cast<uint1 *>(HELLO_ZLIB), sizeof(HELLO_ZLIB));
    uint1 first[1] = {};
    int4 first_remaining = stream.inflate(first, sizeof(first));
    std::cout << "stream.first=" << std::string((char *)first, 1)
              << ":remaining=" << first_remaining
              << ":finished=" << truth(stream.isFinished()) << '\n';
    uint1 second[64] = {};
    int4 second_remaining = stream.inflate(second, sizeof(second));
    std::cout << "stream.second="
              << std::string((char *)second, sizeof(second) - second_remaining)
              << ":remaining=" << second_remaining
              << ":finished=" << truth(stream.isFinished()) << '\n';
  }

  {
    uint1 invalid[] = {0xde, 0xad, 0xbe, 0xef};
    Decompress stream;
    stream.input(invalid, sizeof(invalid));
    uint1 output[8] = {};
    try {
      stream.inflate(output, sizeof(output));
      std::cout << "invalid.error=none\n";
    } catch (const LowlevelError &error) {
      std::cout << "invalid.error=" << error.explain
                << ":finished=" << truth(stream.isFinished()) << '\n';
    }
  }

  {
    Decompress stream;
    stream.input(const_cast<uint1 *>(HELLO_ZLIB), sizeof(HELLO_ZLIB));
    stream.input(const_cast<uint1 *>(WORLD_ZLIB), sizeof(WORLD_ZLIB));
    uint1 output[64] = {};
    int4 remaining = stream.inflate(output, sizeof(output));
    std::cout << "replacement.output="
              << std::string((char *)output, sizeof(output) - remaining)
              << ":remaining=" << remaining
              << ":finished=" << truth(stream.isFinished()) << '\n';
  }
  return 0;
}
