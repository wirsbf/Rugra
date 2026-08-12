#include "printc.hh"
#include "block.hh"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace ghidra;

struct BlockAddTag {
  using type = void (BlockGraph::*)(FlowBlock *);
  friend type access(BlockAddTag);
};

template <typename Tag, typename Tag::type Member>
struct PrivateAccess {
  friend typename Tag::type access(Tag) { return Member; }
};

template struct PrivateAccess<BlockAddTag, &BlockGraph::addBlock>;

class FixturePrintC;

class ProbeBlock final : public FlowBlock {
  int4 marker;
  block_type type;

public:
  ProbeBlock(int4 marker_in, block_type type_in)
      : marker(marker_in), type(type_in) {}

  virtual block_type getType(void) const { return type; }
  virtual void emit(PrintLanguage *language) const;
};

class FixturePrintC final : public PrintC {
  std::vector<int4> visits;

public:
  FixturePrintC(void) : PrintC(nullptr, "printc-blockgraph-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  void record(int4 marker) { visits.push_back(marker); }

  const std::vector<int4> &render(BlockGraph *graph) {
    emitBlockGraph(graph);
    return visits;
  }
};

void ProbeBlock::emit(PrintLanguage *language) const {
  FixturePrintC *printer = dynamic_cast<FixturePrintC *>(language);
  if (printer == nullptr)
    throw LowlevelError("unexpected fixture print language");
  printer->record(marker);
}

void append(BlockGraph &graph, FlowBlock *block) {
  const auto add = access(BlockAddTag{});
  (graph.*add)(block);
}

} // namespace

int main(void) {
  BlockGraph graph;
  append(graph, new ProbeBlock(17, FlowBlock::t_basic));
  append(graph, new ProbeBlock(3, FlowBlock::t_dowhile));
  append(graph, new ProbeBlock(29, FlowBlock::t_basic));

  FixturePrintC printer;
  const std::vector<int4> &visits = printer.render(&graph);
  std::cout << "visit_order=";
  for (size_t i = 0; i < visits.size(); ++i) {
    if (i != 0)
      std::cout << ',';
    std::cout << visits[i];
  }
  std::cout << '\n';
  std::cout << "visit_count=" << visits.size() << '\n';
  std::cout << "dowhile_visits=";
  size_t loop_count = 0;
  for (const int4 marker : visits) {
    if (marker == 3)
      ++loop_count;
  }
  std::cout << loop_count << '\n';
  return 0;
}
