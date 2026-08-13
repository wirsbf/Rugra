#include "op.hh"
#include "typeop.hh"
#include "varmap.hh"
#include "varnode.hh"

#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

using namespace ghidra;

struct OpSetInputTag {
  using type = void (PcodeOp::*)(Varnode *, int4);
  friend type access(OpSetInputTag);
};

struct OpSetOutputTag {
  using type = void (PcodeOp::*)(Varnode *);
  friend type access(OpSetOutputTag);
};

struct VarnodeSetDefTag {
  using type = void (Varnode::*)(PcodeOp *);
  friend type access(VarnodeSetDefTag);
};

struct VarnodeAddDescendTag {
  using type = void (Varnode::*)(PcodeOp *);
  friend type access(VarnodeAddDescendTag);
};

template <typename Tag, typename Tag::type Member>
struct PrivateAccess {
  friend typename Tag::type access(Tag) { return Member; }
};

template struct PrivateAccess<OpSetInputTag, &PcodeOp::setInput>;
template struct PrivateAccess<OpSetOutputTag, &PcodeOp::setOutput>;
template struct PrivateAccess<VarnodeSetDefTag, &Varnode::setDef>;
template struct PrivateAccess<VarnodeAddDescendTag, &Varnode::addDescend>;

size_t countDescendants(const Varnode &vn) {
  return static_cast<size_t>(std::distance(vn.beginDescend(), vn.endDescend()));
}

void dumpState(const std::string &label, const char *phase, const Varnode &output,
               const PcodeOp *op, const std::vector<Varnode *> &inputs) {
  const Datatype *outputType = output.getType();
  std::string outputMetatype;
  metatype2string(outputType->getMetatype(), outputMetatype);
  std::cout << label << '|' << phase
            << "|out_unique=" << (output.getSpace()->getType() == IPTR_INTERNAL)
            << "|out_offset=" << output.getOffset()
            << "|out_size=" << output.getSize()
            << "|out_flags=" << output.getFlags()
            << "|out_consumed=" << output.getConsume()
            << "|out_nzm=" << output.getNZMask()
            << "|def_alias=" << (output.getDef() == op)
            << "|output_alias=" << (op->getOut() == &output)
            << "|out_type_present=" << (outputType != nullptr)
            << "|out_type_name=" << outputType->getName()
            << "|out_type_size=" << outputType->getSize()
            << "|out_type_metatype=" << outputMetatype
            << "|opcode=" << static_cast<int4>(op->code())
            << "|inputs=" << op->numInput()
            << "|dead=" << op->isDead()
            << "|eval=" << op->getEvalType()
            << "|commutative=" << op->isCommutative()
            << "|seq_offset=" << op->getAddr().getOffset()
            << "|seq_order=" << op->getTime();
  for (size_t i = 0; i < inputs.size(); ++i) {
    const Varnode *input = inputs[i];
    const Datatype *inputType = input->getType();
    std::string inputMetatype;
    metatype2string(inputType->getMetatype(), inputMetatype);
    std::cout << "|in" << i << "_constant=" << input->isConstant()
              << "|in" << i << "_offset=" << input->getOffset()
              << "|in" << i << "_size=" << input->getSize()
              << "|in" << i << "_flags=" << input->getFlags()
              << "|in" << i << "_consumed=" << input->getConsume()
              << "|in" << i << "_nzm=" << input->getNZMask()
              << "|in" << i << "_slot_alias=" << (op->getIn(i) == input)
              << "|in" << i << "_descendants=" << countDescendants(*input)
              << "|in" << i << "_type_present=" << (inputType != nullptr)
              << "|in" << i << "_type_name=" << inputType->getName()
              << "|in" << i << "_type_size=" << inputType->getSize()
              << "|in" << i << "_type_metatype=" << inputMetatype
              << "|in" << i << "_type_alias_out=" << (inputType == outputType);
  }
  if (inputs.size() == 2) {
    std::cout << "|input_alias=" << (inputs[0] == inputs[1])
              << "|input_type_alias=" << (inputs[0]->getType() == inputs[1]->getType());
  }
  std::cout << '\n';
}

void runCopy(const std::string &label, int4 size, uintb value) {
  ConstantSpace constantSpace(nullptr, nullptr);
  UniqueSpace uniqueSpace(nullptr, nullptr);
  TypeBase valueType(size, TYPE_UNKNOWN, "fixture_unknown");
  TypeOpCopy copyType(nullptr);
  PcodeOpBank bank;
  PcodeOp *op = bank.create(1, Address(&uniqueSpace, 0x1000));
  bank.changeOpcode(op, &copyType);
  Varnode input(size, Address(&constantSpace, value), &valueType);
  Varnode output(size, Address(&uniqueSpace, 0x2000), &valueType);
  const auto setInput = access(OpSetInputTag{});
  const auto setOutput = access(OpSetOutputTag{});
  const auto setDef = access(VarnodeSetDefTag{});
  const auto addDescend = access(VarnodeAddDescendTag{});
  (op->*setInput)(&input, 0);
  (op->*setOutput)(&output);
  (input.*addDescend)(op);
  (output.*setDef)(op);
  const std::vector<Varnode *> inputs{&input};

  dumpState(label, "before", output, op, inputs);
  const uintb result = AliasChecker::gatherOffset(&output);
  std::cout << label << "|result=0x" << std::hex << result << std::dec << '\n';
  dumpState(label, "after", output, op, inputs);
}

void runAdd(const std::string &label, int4 size, uintb left, uintb right) {
  ConstantSpace constantSpace(nullptr, nullptr);
  UniqueSpace uniqueSpace(nullptr, nullptr);
  TypeBase valueType(size, TYPE_UNKNOWN, "fixture_unknown");
  TypeOpIntAdd addType(nullptr);
  PcodeOpBank bank;
  PcodeOp *op = bank.create(2, Address(&uniqueSpace, 0x1100));
  bank.changeOpcode(op, &addType);
  Varnode input0(size, Address(&constantSpace, left), &valueType);
  Varnode input1(size, Address(&constantSpace, right), &valueType);
  Varnode output(size, Address(&uniqueSpace, 0x2100), &valueType);
  const auto setInput = access(OpSetInputTag{});
  const auto setOutput = access(OpSetOutputTag{});
  const auto setDef = access(VarnodeSetDefTag{});
  const auto addDescend = access(VarnodeAddDescendTag{});
  (op->*setInput)(&input0, 0);
  (op->*setInput)(&input1, 1);
  (op->*setOutput)(&output);
  (input0.*addDescend)(op);
  (input1.*addDescend)(op);
  (output.*setDef)(op);
  const std::vector<Varnode *> inputs{&input0, &input1};

  dumpState(label, "before", output, op, inputs);
  const uintb result = AliasChecker::gatherOffset(&output);
  std::cout << label << "|result=0x" << std::hex << result << std::dec << '\n';
  dumpState(label, "after", output, op, inputs);
}

} // namespace

int main() {
  runCopy("copy8_all_bits", 8, 0xfedcba9876543210ULL);
  runAdd("add8_wrap", 8, 0xfffffffffffffff0ULL, 0x35);
  runAdd("add7_mask", 7, 0x00fffffffffffff0ULL, 0x35);
  return 0;
}
