/*
 * BLOCK-STRUCTURED-NEGATE-0001: locked Ghidra 12.0.4 oracle for
 *
 *   FlowBlock::swapEdges             block.cc:218-233
 *   FlowBlock::negateCondition       block.cc:294-301
 *   BlockList::negateCondition       block.cc:2967-2974
 *   BlockCondition::negateCondition  block.cc:3023-3032
 *
 * The probe observes the complete ordered in/out half-edge state: peer
 * identity, raw label, and reverse_index on both halves.  It also records
 * raw block flags (including f_flip_path), the BlockCondition opcode, every
 * virtual child call and its argument, and every virtual return value.
 * Pointer values are never printed; fixed construction names are the sole
 * normalization.
 *
 * BaseProbe has no negateCondition override, so the flow/self/parallel cases
 * invoke the locked FlowBlock virtual body itself. FixedProbe records the
 * argument and returns a configured value without touching state, making the
 * structured parents' virtual dispatch and return aggregation observable
 * without needing a Funcdata/PcodeOpBank merely to manufacture a BlockBasic
 * CBRANCH.
 */

#include <bits/stdc++.h>

// FlowBlock's edge arrays/flags and BlockGraph::addBlock are private in the
// production header.  This translation-unit-only observer changes access,
// never the compiled locked libdecomp implementation.
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "blockaction.hh"
#include "libdecomp.hh"
#include "opcodes.hh"
#undef class
#undef private

using namespace ghidra;

struct BaseProbe : public FlowBlock {};

struct FixedProbe : public FlowBlock {
  bool fixedReturn;
  std::vector<bool> calls;

  FixedProbe(bool fixedReturnIn) : fixedReturn(fixedReturnIn) {}

  virtual bool negateCondition(bool toporbottom)
  {
    calls.push_back(toporbottom);
    return fixedReturn;
  }
};

struct NamedNode {
  std::string name;
  FlowBlock *block;
};

static void wire(FlowBlock *from, FlowBlock *to, uint4 label)
{
  // Production FlowBlock::addInEdge (block.cc:73-79) creates both halves in
  // append order and assigns their reciprocal slots, including self/parallel
  // edges.
  to->addInEdge(from, label);
}

static std::string nameOf(FlowBlock *block, const std::vector<NamedNode> &nodes)
{
  for (std::vector<NamedNode>::const_iterator it = nodes.begin();
       it != nodes.end(); ++it) {
    if (it->block == block)
      return it->name;
  }
  return "?";
}

static std::string callsOf(FlowBlock *block)
{
  FixedProbe *probe = dynamic_cast<FixedProbe *>(block);
  if (probe == (FixedProbe *)0)
    return "-";
  std::ostringstream out;
  out << '[';
  for (size_t i = 0; i < probe->calls.size(); ++i) {
    if (i != 0)
      out << ',';
    out << (probe->calls[i] ? 'T' : 'F');
  }
  out << ']';
  return out.str();
}

static std::string opcodeOf(FlowBlock *block)
{
  BlockCondition *condition = dynamic_cast<BlockCondition *>(block);
  if (condition == (BlockCondition *)0)
    return "-";
  std::ostringstream out;
  out << (int4)condition->opc << ':';
  if (condition->opc == CPUI_BOOL_AND)
    out << "and";
  else if (condition->opc == CPUI_BOOL_OR)
    out << "or";
  else
    out << "other";
  return out.str();
}

static std::string boolResults(const std::vector<bool> &results)
{
  std::ostringstream out;
  out << '[';
  for (size_t i = 0; i < results.size(); ++i) {
    if (i != 0)
      out << ',';
    out << (results[i] ? 'T' : 'F');
  }
  out << ']';
  return out.str();
}

static void observe(const std::string &caseName, FlowBlock *top,
                    const std::vector<NamedNode> &nodes,
                    const std::vector<bool> &results)
{
  std::ostringstream nodeText;
  nodeText << '[';
  for (size_t i = 0; i < nodes.size(); ++i) {
    if (i != 0)
      nodeText << ';';
    nodeText << nodes[i].name
             << ":flags=0x" << std::hex << std::setw(8)
             << std::setfill('0') << nodes[i].block->flags << std::dec
             << ",calls=" << callsOf(nodes[i].block);
  }
  nodeText << ']';

  std::ostringstream outText;
  outText << '[';
  bool first = true;
  for (size_t i = 0; i < nodes.size(); ++i) {
    FlowBlock *block = nodes[i].block;
    for (size_t slot = 0; slot < block->outofthis.size(); ++slot) {
      if (!first)
        outText << ';';
      first = false;
      const BlockEdge &edge(block->outofthis[slot]);
      outText << nodes[i].name << '!' << slot << '>'
              << nameOf(edge.point, nodes)
              << ":label=0x" << std::hex << std::setw(8)
              << std::setfill('0') << edge.label << std::dec
              << ",rev=" << edge.reverse_index;
    }
  }
  outText << ']';

  std::ostringstream inText;
  inText << '[';
  first = true;
  for (size_t i = 0; i < nodes.size(); ++i) {
    FlowBlock *block = nodes[i].block;
    for (size_t slot = 0; slot < block->intothis.size(); ++slot) {
      if (!first)
        inText << ';';
      first = false;
      const BlockEdge &edge(block->intothis[slot]);
      inText << nodes[i].name << '@' << slot << '<'
             << nameOf(edge.point, nodes)
             << ":label=0x" << std::hex << std::setw(8)
             << std::setfill('0') << edge.label << std::dec
             << ",rev=" << edge.reverse_index;
    }
  }
  inText << ']';

  std::cout << "case=" << caseName
            << "|result=" << boolResults(results)
            << "|top=" << nameOf(top, nodes)
            << "|op=" << opcodeOf(top)
            << "|nodes=" << nodeText.str()
            << "|out=" << outText.str()
            << "|in=" << inText.str() << '\n';
}

static void runFlow(const std::string &caseName, bool toporbottom, int4 count)
{
  BaseProbe top;
  BaseProbe falseTarget;
  BaseProbe trueTarget;
  top.flags = FlowBlock::f_mark | FlowBlock::f_label_bumpup;
  wire(&top, &falseTarget, FlowBlock::f_goto_edge | FlowBlock::f_tree_edge);
  wire(&top, &trueTarget, FlowBlock::f_cross_edge | FlowBlock::f_loop_exit_edge);
  std::vector<bool> results;
  for (int4 i = 0; i < count; ++i)
    results.push_back(top.negateCondition(toporbottom));
  observe(caseName, &top,
          {{"top", &top}, {"f", &falseTarget}, {"t", &trueTarget}},
          results);
}

static void runParallel(void)
{
  BaseProbe top;
  BaseProbe target;
  top.flags = FlowBlock::f_mark;
  wire(&top, &target, FlowBlock::f_goto_edge);
  wire(&top, &target, FlowBlock::f_loop_exit_edge);
  const bool result = top.negateCondition(true);
  observe("flow_parallel_true", &top, {{"top", &top}, {"p", &target}},
          {result});
}

static void runSelf(void)
{
  BaseProbe top;
  top.flags = FlowBlock::f_mark;
  wire(&top, &top, FlowBlock::f_loop_edge);
  wire(&top, &top, FlowBlock::f_irreducible);
  const bool result = top.negateCondition(true);
  observe("flow_self_true", &top, {{"top", &top}}, {result});
}

static void runList(const std::string &caseName, bool toporbottom,
                    int4 count, bool childReturn)
{
  FixedProbe *first = new FixedProbe(false);
  FixedProbe *last = new FixedProbe(childReturn);
  BaseProbe falseTarget;
  BaseProbe trueTarget;
  BlockList list;
  // Match Rugra's direct structured-node constructor exactly: the children
  // are owned in order, but their parent field remains null in this isolated
  // method fixture. Production addBlock's parent mutation is outside scope.
  list.list.push_back(first);
  list.list.push_back(last);
  list.flags = FlowBlock::f_mark | FlowBlock::f_label_bumpup;
  wire(&list, &falseTarget, FlowBlock::f_defaultswitch_edge);
  wire(&list, &trueTarget, FlowBlock::f_back_edge | FlowBlock::f_loop_exit_edge);
  std::vector<bool> results;
  for (int4 i = 0; i < count; ++i)
    results.push_back(list.negateCondition(toporbottom));
  observe(caseName, &list,
          {{"list", &list}, {"c0", first}, {"c1", last},
           {"f", &falseTarget}, {"t", &trueTarget}}, results);
}

static void runCondition(const std::string &caseName, OpCode opcode,
                         bool toporbottom, int4 count,
                         bool firstReturn, bool secondReturn)
{
  FixedProbe *first = new FixedProbe(firstReturn);
  FixedProbe *second = new FixedProbe(secondReturn);
  BaseProbe falseTarget;
  BaseProbe trueTarget;
  BlockCondition condition(opcode);
  condition.list.push_back(first);
  condition.list.push_back(second);
  condition.flags = FlowBlock::f_mark | FlowBlock::f_label_bumpup;
  wire(&condition, &falseTarget, FlowBlock::f_forward_edge);
  wire(&condition, &trueTarget,
       FlowBlock::f_goto_edge | FlowBlock::f_loop_exit_edge);
  std::vector<bool> results;
  for (int4 i = 0; i < count; ++i)
    results.push_back(condition.negateCondition(toporbottom));
  observe(caseName, &condition,
          {{"cond", &condition}, {"c0", first}, {"c1", second},
           {"f", &falseTarget}, {"t", &trueTarget}}, results);
}

static void runCollapseCatCounter(void)
{
  BlockGraph graph;
  BaseProbe *first = new BaseProbe();
  BaseProbe *second = new BaseProbe();
  BaseProbe *third = new BaseProbe();
  first->index = 0;
  second->index = 1;
  third->index = 2;
  // Same isolated initial state as the Rust graph: ordered ownership with
  // null parent fields. The production collapse factories establish their
  // own containment during the run.
  graph.list.push_back(first);
  graph.list.push_back(second);
  graph.list.push_back(third);
  wire(first, second, 0);
  wire(second, third, 0);
  CollapseStructure collapse(graph);
  collapse.collapseAll();
  std::cout << "case=collapse_cat_counter_zero"
            << "|count=" << collapse.getChangeCount()
            << "|graph_size=" << graph.getSize()
            << "|cond_calls=-\n";
}

static void runCollapseProperIfCounter(void)
{
  BlockGraph graph;
  FixedProbe *condition = new FixedProbe(true);
  BaseProbe *clause = new BaseProbe();
  BaseProbe *merge = new BaseProbe();
  condition->index = 0;
  clause->index = 1;
  merge->index = 2;
  graph.list.push_back(condition);
  graph.list.push_back(clause);
  graph.list.push_back(merge);
  // Slot 0 is the clause. ruleBlockProperIf must negate it to make the
  // clause the true branch, count the virtual true return once, then perform
  // the structural factory collapse.
  wire(condition, clause, 0);
  wire(condition, merge, 0);
  wire(clause, merge, 0);
  CollapseStructure collapse(graph);
  collapse.collapseAll();
  std::cout << "case=collapse_proper_if_counter_one"
            << "|count=" << collapse.getChangeCount()
            << "|graph_size=" << graph.getSize()
            << "|cond_calls=" << callsOf(condition) << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> specPaths;
  startDecompilerLibrary(specPaths);
  std::cout << "schema=1|fixture=BLOCK-STRUCTURED-NEGATE-0001"
            << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    runFlow("flow_top_false", false, 1);
    runFlow("flow_top_true", true, 1);
    runFlow("flow_double_true_roundtrip", true, 2);
    runParallel();
    runSelf();
    runList("list_top_false_child_true", false, 1, true);
    runList("list_top_true_child_true", true, 1, true);
    runList("list_double_true_roundtrip", true, 2, false);
    runCondition("condition_and_top_false", CPUI_BOOL_AND,
                 false, 1, true, false);
    runCondition("condition_or_top_true", CPUI_BOOL_OR,
                 true, 1, false, true);
    runCondition("condition_double_true_roundtrip", CPUI_BOOL_AND,
                 true, 2, false, false);
    runCollapseCatCounter();
    runCollapseProperIfCounter();
  }
  catch (const std::exception &err) {
    std::cerr << "oracle exception: " << err.what() << '\n';
    return 1;
  }
  catch (...) {
    std::cerr << "oracle non-standard exception\n";
    return 1;
  }
  return 0;
}
