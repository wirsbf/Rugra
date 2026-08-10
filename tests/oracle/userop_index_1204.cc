#include "pcodecompile.hh"
#include "slgh_compile.hh"

#include <iostream>
#include <vector>

namespace {

using namespace ghidra;

class FixtureCompile final : public PcodeCompile {
  uint4 next_temp;

  uint4 allocateTemp(void) override {
    const uint4 result = next_temp;
    next_temp += 16;
    return result;
  }

  void addSymbol(SleighSymbol *symbol) override { delete symbol; }

public:
  FixtureCompile(AddrSpace *constant_space, AddrSpace *unique_space)
      : next_temp(0x100) {
    setConstantSpace(constant_space);
    setUniqueSpace(unique_space);
  }

  const Location *getLocation(SleighSymbol *) const override { return nullptr; }
  void reportError(const Location *, const std::string &) override {}
  void reportWarning(const Location *, const std::string &) override {}
};

ExprTree *nested_param(FixtureCompile &compiler, AddrSpace *constant_space,
                       OpCode opcode, uintb value) {
  VarnodeTpl *input = new VarnodeTpl(
      ConstTpl(constant_space), ConstTpl(ConstTpl::real, value),
      ConstTpl(ConstTpl::real, 4));
  return compiler.createOp(opcode, new ExprTree(input));
}

const char *space_name(const ConstTpl &space, AddrSpace *constant_space,
                       AddrSpace *unique_space) {
  if (space.getType() != ConstTpl::spaceid)
    return "non-spaceid";
  if (space.getSpace() == constant_space)
    return "const";
  if (space.getSpace() == unique_space)
    return "unique";
  return "other";
}

void print_op(const char *series, std::size_t index, const OpTpl *op,
              AddrSpace *constant_space, AddrSpace *unique_space) {
  std::cout << series << ".op" << index << '=' << get_opname(op->getOpcode());
  if (op->getOut() == nullptr) {
    std::cout << ":out=none";
  } else {
    std::cout << ":out="
              << space_name(op->getOut()->getSpace(), constant_space,
                            unique_space)
              << ',' << op->getOut()->getOffset().getReal() << ','
              << op->getOut()->getSize().getReal();
  }
  std::cout << ":inputs=" << op->numInput();
  for (int4 i = 0; i < op->numInput(); ++i) {
    const VarnodeTpl *input = op->getIn(i);
    std::cout << ":in" << i << '='
              << space_name(input->getSpace(), constant_space, unique_space)
              << ',' << input->getOffset().getReal() << ','
              << input->getSize().getReal();
  }
  std::cout << '\n';
}

void destroy_ops(std::vector<OpTpl *> *ops) {
  for (OpTpl *op : *ops)
    delete op;
  delete ops;
}

} // namespace

int main() {
  SleighCompile symbol_compiler;
  symbol_compiler.parseFromNewFile("userop_index_1204.slaspec");
  symbol_compiler.setEndian(0);
  std::vector<std::string> *first_batch = new std::vector<std::string>;
  first_batch->push_back("alpha");
  first_batch->push_back("beta");
  symbol_compiler.addUserOp(first_batch);
  std::vector<std::string> *second_batch = new std::vector<std::string>;
  second_batch->push_back("gamma");
  symbol_compiler.addUserOp(second_batch);
  UserOpSymbol *alpha =
      static_cast<UserOpSymbol *>(symbol_compiler.findSymbol("alpha"));
  UserOpSymbol *beta =
      static_cast<UserOpSymbol *>(symbol_compiler.findSymbol("beta"));
  UserOpSymbol *gamma =
      static_cast<UserOpSymbol *>(symbol_compiler.findSymbol("gamma"));
  std::cout << "addUserOp.indices=" << alpha->getIndex() << ','
            << beta->getIndex() << ',' << gamma->getIndex() << '\n';

  // PcodeCompile treats these as opaque registered AddrSpace identities.  The
  // fixture never dereferences them; identity lets us prove which configured
  // space createUserOpNoOut placed in input 0 without constructing Architecture.
  AddrSpace *constant_space = reinterpret_cast<AddrSpace *>(0x1000);
  AddrSpace *unique_space = reinterpret_cast<AddrSpace *>(0x2000);
  FixtureCompile compiler(constant_space, unique_space);

  UserOpSymbol statement_symbol("notify");
  statement_symbol.setIndex(37);
  std::vector<ExprTree *> *statement_params = new std::vector<ExprTree *>;
  statement_params->push_back(
      nested_param(compiler, constant_space, CPUI_INT_NEGATE, 0x11));
  statement_params->push_back(
      nested_param(compiler, constant_space, CPUI_INT_2COMP, 0x22));
  std::vector<OpTpl *> *statement =
      compiler.createUserOpNoOut(&statement_symbol, statement_params);
  std::cout << "statement.count=" << statement->size() << '\n';
  for (std::size_t i = 0; i < statement->size(); ++i)
    print_op("statement", i, (*statement)[i], constant_space, unique_space);

  UserOpSymbol expression_symbol("transform");
  expression_symbol.setIndex(91);
  std::vector<ExprTree *> *expression_params = new std::vector<ExprTree *>;
  expression_params->push_back(
      nested_param(compiler, constant_space, CPUI_INT_NEGATE, 0x33));
  expression_params->push_back(
      nested_param(compiler, constant_space, CPUI_INT_2COMP, 0x44));
  ExprTree *expression =
      compiler.createUserOp(&expression_symbol, expression_params);
  std::vector<OpTpl *> *expression_ops = ExprTree::toVector(expression);
  std::cout << "expression.count=" << expression_ops->size() << '\n';
  for (std::size_t i = 0; i < expression_ops->size(); ++i)
    print_op("expression", i, (*expression_ops)[i], constant_space,
             unique_space);

  destroy_ops(statement);
  destroy_ops(expression_ops);
  return 0;
}
