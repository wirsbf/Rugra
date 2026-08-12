#include "printc.hh"
#include "funcdata.hh"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <list>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;

// Access control is the only obstacle to constructing a minimal BlockBasic.
// Explicit template instantiation ignores member access control; the invoked
// method is the real locked BlockBasic::insert and preserves parent/order state.
struct BlockInsertTag {
  using type = void (BlockBasic::*)(std::list<PcodeOp *>::iterator, PcodeOp *);
  friend type access(BlockInsertTag);
};

struct OpSetInputTag {
  using type = void (PcodeOp::*)(Varnode *, int4);
  friend type access(OpSetInputTag);
};

template <typename Tag, typename Tag::type Member>
struct PrivateAccess {
  friend typename Tag::type access(Tag) { return Member; }
};

template struct PrivateAccess<BlockInsertTag, &BlockBasic::insert>;
template struct PrivateAccess<OpSetInputTag, &PcodeOp::setInput>;

class FixturePrintC final : public PrintC {
public:
  FixturePrintC(void) : PrintC(nullptr, "printc-terminal-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  void render(const BlockBasic *block, bool no_branch_active) {
    if (no_branch_active)
      setMod(no_branch);
    else
      unsetMod(no_branch);
    emitBlockBasic(block);
    emit->flush();
  }
};

void append(BlockBasic &block, PcodeOp *op) {
  const auto insert = access(BlockInsertTag{});
  (block.*insert)(block.endOp(), op);
}

std::string render(const std::vector<OpCode> &opcodes, bool no_branch_active) {
  PcodeOpBank bank;
  BlockBasic block(nullptr);
  TypeOpBranch branch_type(nullptr);
  TypeOpCbranch cbranch_type(nullptr);
  TypeOpReturn return_type(nullptr);
  ConstantSpace constant_space(nullptr, nullptr);
  TypeBase bool_type(1, TYPE_BOOL);
  Varnode target(8, Address(&constant_space, 0x1000), &bool_type);
  Varnode condition(1, Address(&constant_space, 1), &bool_type);
  new HighVariable(&target);
  new HighVariable(&condition);

  for (const OpCode opcode : opcodes) {
    TypeOp *type = nullptr;
    int4 input_count = 0;
    switch (opcode) {
    case CPUI_BRANCH:
      type = &branch_type;
      break;
    case CPUI_CBRANCH:
      type = &cbranch_type;
      input_count = 2;
      break;
    case CPUI_RETURN:
      type = &return_type;
      break;
    default:
      throw LowlevelError("unsupported fixture opcode");
    }
    PcodeOp *op = bank.create(input_count, Address());
    bank.changeOpcode(op, type);
    if (opcode == CPUI_CBRANCH) {
      const auto set_input = access(OpSetInputTag{});
      (op->*set_input)(&target, 0);
      (op->*set_input)(&condition, 1);
    }
    append(block, op);
  }

  std::ostringstream output;
  FixturePrintC printer;
  printer.setOutputStream(&output);
  printer.render(&block, no_branch_active);
  return output.str();
}

std::string toHex(const std::string &value) {
  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (const unsigned char byte : value)
    stream << std::setw(2) << static_cast<unsigned int>(byte);
  return stream.str();
}

void emitCase(const std::string &name, const std::vector<OpCode> &opcodes,
              bool no_branch_active, bool raw) {
  const std::string output = render(opcodes, no_branch_active);
  std::cout << name << '=';
  if (raw)
    std::cout << toHex(output);
  else
    std::cout << std::count(output.begin(), output.end(), ';');
  std::cout << '\n';
}

} // namespace

int main(int argc, char **argv) {
  const bool raw = argc == 2 && std::string(argv[1]) == "--raw";
  emitCase("cbranch_visible", {CPUI_CBRANCH}, false, raw);
  emitCase("cbranch_suppressed", {CPUI_CBRANCH}, true, raw);
  emitCase("branch_visible", {CPUI_BRANCH}, false, raw);
  emitCase("return_suppressed", {CPUI_RETURN}, true, raw);
  emitCase("mixed_visible", {CPUI_RETURN, CPUI_CBRANCH}, false, raw);
  emitCase("mixed_suppressed", {CPUI_RETURN, CPUI_CBRANCH}, true, raw);
  return 0;
}
