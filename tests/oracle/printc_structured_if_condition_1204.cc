// PRINTC-STRUCTURED-IF-CONDITION-0001: locked Ghidra 12.0.4 oracle for
// PrintC structured-condition virtual dispatch.
//
// The structured emitters are production Ghidra code.  The three op-level
// virtuals below deliberately render deterministic atoms so this fixture
// isolates block routing, modifier propagation/restoration, comment order,
// and object mutation from FuncCallSpecs and datatype presentation.

#include <bits/stdc++.h>

#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "comment.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "printc.hh"
#include "printlanguage.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef class
#undef private

using namespace ghidra;

namespace {

const char *kOracleCommit = "e40ed13014025f82488b1f8f7bca566894ac376b";

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "register", false, 8, 1, 4,
                              AddrSpace::hasphysical, 0, 0));
    SpacebaseSpace *stack = new SpacebaseSpace(this, this, "stack", 5, 8,
                                                getSpace(3), 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = getSpace(4);
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    setDefaultCodeSpace(3);
    dummy_register.space = getSpace(4);
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override {
    return (PcodeInjectLibrary *)0;
  }
  void buildTypegrp(DocumentStorage &) override {}
  void buildCoreTypes(DocumentStorage &) override {}
  void buildCommentDB(DocumentStorage &) override {}
  void buildStringManager(DocumentStorage &) override {}
  void buildConstantPool(DocumentStorage &) override {}
  void buildContext(DocumentStorage &) override {}
  void buildSymbols(DocumentStorage &) override {}
  void buildSpecFile(DocumentStorage &) override {}
  void modifySpaces(Translate *) override {}
  void resolveArchitecture(void) override {}

public:
  FixtureArchitecture() {
    FixtureTranslate *fixture_translate = new FixtureTranslate();
    translate = fixture_translate;
    copySpaces(fixture_translate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void installCommentDB(CommentDatabase *db) { commentdb = db; }
  AddrSpace *ramSpace() const { return translate->getSpace(3); }
  void printMessage(const std::string &) const override {}
};

std::string hex_uint(uintb value) {
  std::ostringstream stream;
  stream << std::hex << std::nouppercase << value;
  return stream.str();
}

std::string fixture_integer(uintb value) {
  // Mirror the locked Rust comparand's default integer presentation for the
  // fixture values: 0x63/0x64 naturally print decimal, the other markers hex.
  if (value == 0x63 || value == 0x64)
    return std::to_string(value);
  return "0x" + hex_uint(value);
}

class FixturePrintC final : public PrintC {
  std::ostringstream output;

public:
  FixturePrintC() : PrintC(nullptr, "printc-structured-if-condition-1204") {
    delete emit;
    emit = new EmitNoMarkup();
    setOutputStream(&output);
  }

  void loadComments(const Funcdata *fd) {
    commsorter.setupFunctionList(instr_comment_type | head_comment_type, fd,
                                 *fd->getArch()->commentdb, option_unplaced);
  }

  void render(const BlockGraph *graph) { emitBlockGraph(graph); }
  std::string raw() const { return output.str(); }

  void opCall(const PcodeOp *op) override {
    emit->print("FUN_" + hex_uint(op->getIn(0)->getOffset()) + "()");
  }

  void opStore(const PcodeOp *op) override {
    const uintb pointer = op->getIn(1)->getOffset();
    const uintb value = op->getIn(2)->getOffset();
    emit->print("*0x" + hex_uint(pointer) + " = " + fixture_integer(value));
  }

  void opCbranch(const PcodeOp *op) override {
    const bool flat_mode = isSet(flat);
    const bool with_parens = !isSet(comma_separate);
    if (flat_mode) {
      emit->tagOp(KEYWORD_IF, EmitMarkup::keyword_color, op);
      emit->spaces(1);
    }
    int4 id = -1;
    if (with_parens)
      id = emit->openParen(OPEN_PAREN);
    else
      id = emit->openGroup();
    emit->print(std::to_string(op->getIn(1)->getOffset()));
    if (with_parens)
      emit->closeParen(CLOSE_PAREN, id);
    else
      emit->closeGroup(id);
    // Direct BlockGraph fixtures have no code-block whitelist on the Rugra
    // side, so its flat CBRANCH prints `if (cond);` without a goto target.
    // This deterministic atom keeps the routing projection byte-comparable.
  }
};

BlockBasic *make_basic(Funcdata &fd, AddrSpace *ram, int4 index, uintb start) {
  BlockBasic *basic = new BlockBasic(&fd);
  basic->index = index;
  fd.setBasicBlockRange(basic, Address(ram, start), Address(ram, start + 0x1f));
  return basic;
}

BlockIf *make_if(int4 index, FlowBlock *condition, FlowBlock *body) {
  BlockIf *result = new BlockIf();
  result->addBlock(condition);
  result->addBlock(body);
  result->index = index;
  return result;
}

BlockCondition *make_condition(int4 index, OpCode opcode, FlowBlock *first,
                               FlowBlock *second) {
  BlockCondition *result = new BlockCondition(opcode);
  result->addBlock(first);
  result->addBlock(second);
  result->index = index;
  return result;
}

BlockList *make_list(int4 index, const std::vector<FlowBlock *> &children) {
  BlockList *result = new BlockList();
  for (FlowBlock *child : children)
    result->addBlock(child);
  result->index = index;
  return result;
}

PcodeOp *add_call(Funcdata &fd, AddrSpace *ram, BlockBasic *block, uintb off,
                  uintb target) {
  PcodeOp *op = fd.newOp(1, Address(ram, off));
  fd.opSetOpcode(op, CPUI_CALL);
  fd.opSetInput(op, fd.newCodeRef(Address(ram, target)), 0);
  fd.opInsertEnd(op, block);
  return op;
}

PcodeOp *add_store(Funcdata &fd, AddrSpace *ram, BlockBasic *block, uintb off,
                   uintb pointer, uintb value) {
  PcodeOp *op = fd.newOp(3, Address(ram, off));
  fd.opSetOpcode(op, CPUI_STORE);
  fd.opSetInput(op, fd.newVarnodeSpace(ram), 0);
  fd.opSetInput(op, fd.newConstant(8, pointer), 1);
  fd.opSetInput(op, fd.newConstant(8, value), 2);
  fd.opInsertEnd(op, block);
  return op;
}

PcodeOp *add_cbranch(Funcdata &fd, AddrSpace *ram, BlockBasic *block, uintb off,
                     uintb target, uintb condition) {
  PcodeOp *op = fd.newOp(2, Address(ram, off));
  fd.opSetOpcode(op, CPUI_CBRANCH);
  fd.opSetInput(op, fd.newCodeRef(Address(ram, target)), 0);
  fd.opSetInput(op, fd.newConstant(1, condition), 1);
  fd.opInsertEnd(op, block);
  return op;
}

BlockBasic *make_sentinel(Funcdata &fd, AddrSpace *ram, uintb base, int4 index) {
  BlockBasic *block = make_basic(fd, ram, index, base);
  add_call(fd, ram, block, base, 0xd00d);
  add_cbranch(fd, ram, block, base + 4, base + 0x40, 1);
  return block;
}

const char *block_type_name(FlowBlock::block_type type) {
  switch (type) {
  case FlowBlock::t_basic:
    return "Basic";
  case FlowBlock::t_if:
    return "If";
  case FlowBlock::t_condition:
    return "Condition";
  case FlowBlock::t_ls:
    return "List";
  default:
    return "Other";
  }
}

const char *opcode_name(OpCode opcode) {
  switch (opcode) {
  case CPUI_CALL:
    return "CALL";
  case CPUI_STORE:
    return "STORE";
  case CPUI_CBRANCH:
    return "CBRANCH";
  default:
    return "OTHER";
  }
}

std::vector<FlowBlock *> child_blocks(FlowBlock *block) {
  const FlowBlock::block_type type = block->getType();
  if (type != FlowBlock::t_if && type != FlowBlock::t_condition &&
      type != FlowBlock::t_ls)
    return {};
  BlockGraph *graph = static_cast<BlockGraph *>(block);
  std::vector<FlowBlock *> result;
  for (int4 i = 0; i < graph->getSize(); ++i)
    result.push_back(graph->getBlock(i));
  return result;
}

void collect_nodes(FlowBlock *block, std::map<FlowBlock *, size_t> &ids,
                   std::vector<FlowBlock *> &order) {
  if (ids.find(block) != ids.end())
    return;
  ids[block] = order.size();
  order.push_back(block);
  for (FlowBlock *child : child_blocks(block))
    collect_nodes(child, ids, order);
}

std::string tree_snapshot(FlowBlock *root) {
  std::map<FlowBlock *, size_t> ids;
  std::vector<FlowBlock *> order;
  collect_nodes(root, ids, order);
  std::ostringstream result;
  for (size_t ordinal = 0; ordinal < order.size(); ++ordinal) {
    if (ordinal != 0)
      result << ';';
    FlowBlock *block = order[ordinal];
    const std::vector<FlowBlock *> children = child_blocks(block);
    std::ostringstream child_text;
    for (size_t i = 0; i < children.size(); ++i) {
      if (i != 0)
        child_text << ',';
      child_text << ids[children[i]];
    }

    std::ostringstream op_text;
    if (block->getType() == FlowBlock::t_basic) {
      BlockBasic *basic = static_cast<BlockBasic *>(block);
      size_t op_ordinal = 0;
      for (auto iter = basic->beginOp(); iter != basic->endOp(); ++iter) {
        if (op_ordinal != 0)
          op_text << ',';
        PcodeOp *op = *iter;
        op_text << opcode_name(op->code()) << '@' << std::hex
                << op->getAddr().getOffset() << std::dec << '/' << op_ordinal;
        ++op_ordinal;
      }
    }

    std::ostringstream edge_text;
    for (int4 slot = 0; slot < block->sizeOut(); ++slot) {
      if (slot != 0)
        edge_text << ',';
      FlowBlock *peer = block->getOut(slot);
      auto found = ids.find(peer);
      edge_text << slot << '>';
      if (found == ids.end())
        edge_text << 'x';
      else
        edge_text << found->second;
      edge_text << '/' << block->getOutRevIndex(slot) << '/'
                << block->outofthis[slot].label;
    }

    result << ordinal << ':' << block_type_name(block->getType()) << ':'
           << block->getIndex() << ":f" << std::hex << block->getFlags()
           << std::dec << ":in" << block->sizeIn() << ":out" << block->sizeOut()
           << ":ch[" << child_text.str() << "]:op[" << op_text.str()
           << "]:ed[" << edge_text.str() << ']';
  }
  return result.str();
}

std::string hex_bytes(const std::string &value) {
  static const char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(value.size() * 2);
  for (unsigned char byte : value) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 0xf]);
  }
  return result;
}

void add_events(std::vector<std::tuple<size_t, size_t, std::string>> &events,
                const std::string &raw, const std::string &needle,
                size_t priority, const std::string &label) {
  size_t offset = 0;
  while (true) {
    const size_t position = raw.find(needle, offset);
    if (position == std::string::npos)
      break;
    events.emplace_back(position, priority, label);
    offset = position + needle.size();
  }
}

std::string event_trace(const std::string &raw,
                        const std::vector<std::string> &comments) {
  std::vector<std::tuple<size_t, size_t, std::string>> events;
  for (const std::string &marker : comments)
    add_events(events, raw, "/* WARNING: " + marker + " */", 0,
               "COMMENT_" + marker);
  const uintb targets[] = {0x1001, 0x2001, 0x2002, 0x3001,
                           0x3002, 0x4001, 0x4002, 0xd00d};
  for (uintb target : targets)
    add_events(events, raw, "FUN_" + hex_uint(target), 1,
               "CALL_" + hex_uint(target));
  add_events(events, raw, " = ", 2, "STORE");
  add_events(events, raw, "if (", 3, "IF");
  add_events(events, raw, " && ", 4, "AND");
  add_events(events, raw, " || ", 5, "OR");
  add_events(events, raw, "goto ", 6, "GOTO");
  std::sort(events.begin(), events.end());
  std::ostringstream result;
  for (size_t i = 0; i < events.size(); ++i) {
    if (i != 0)
      result << ',';
    result << std::get<2>(events[i]);
  }
  return result.str();
}

std::string comment_observation(const std::string &raw,
                                const std::vector<std::string> &comments) {
  std::ostringstream result;
  for (size_t i = 0; i < comments.size(); ++i) {
    if (i != 0)
      result << ',';
    const std::string needle = "/* WARNING: " + comments[i] + " */";
    size_t count = 0;
    size_t offset = 0;
    while (true) {
      const size_t position = raw.find(needle, offset);
      if (position == std::string::npos)
        break;
      ++count;
      offset = position + needle.size();
    }
    result << comments[i] << ':' << count;
  }
  return result.str();
}

std::string render_fresh(const BlockGraph *graph, const Funcdata *fd) {
  FixturePrintC printer;
  if (fd != nullptr)
    printer.loadComments(fd);
  printer.render(graph);
  return printer.raw();
}

void report_case(const std::string &id, Funcdata &fd, FlowBlock *root,
                 BlockGraph &graph, FlowBlock *sentinel,
                 BlockGraph &sentinel_graph,
                 const std::vector<std::string> &comments) {
  const std::string tree_before = tree_snapshot(root);
  const std::string sentinel_before = tree_snapshot(sentinel);
  FixturePrintC printer;
  printer.loadComments(&fd);
  printer.render(&graph);
  const std::string after_first = printer.raw();
  const size_t first_len = after_first.size();
  printer.render(&graph);
  const std::string after_second = printer.raw();
  const std::string pass1 = after_second.substr(0, first_len);
  const std::string pass2 = after_second.substr(first_len);
  const size_t second_len = after_second.size();
  printer.render(&sentinel_graph);
  const std::string after_post = printer.raw();
  const std::string post = after_post.substr(second_len);
  const std::string fresh_post = render_fresh(&sentinel_graph, nullptr);
  const std::string fresh_root = render_fresh(&graph, &fd);
  const std::string tree_after = tree_snapshot(root);
  const std::string sentinel_after = tree_snapshot(sentinel);

  std::cout << "case=" << id << "|tree_before_hex=" << hex_bytes(tree_before)
            << "|tree_after_hex=" << hex_bytes(tree_after)
            << "|tree_equal=" << (tree_before == tree_after ? 1 : 0)
            << "|sentinel_equal=" << (sentinel_before == sentinel_after ? 1 : 0)
            << "|pass1_hex=" << hex_bytes(pass1)
            << "|pass2_hex=" << hex_bytes(pass2)
            << "|fresh_root_hex=" << hex_bytes(fresh_root)
            << "|post_hex=" << hex_bytes(post)
            << "|fresh_post_hex=" << hex_bytes(fresh_post)
            << "|post_fresh_equal=" << (post == fresh_post ? 1 : 0)
            << "|events1=" << event_trace(pass1, comments)
            << "|events2=" << event_trace(pass2, comments)
            << "|events_fresh=" << event_trace(fresh_root, comments)
            << "|comments=" << comment_observation(pass1, comments) << '>'
            << comment_observation(pass2, comments) << '>'
            << comment_observation(fresh_root, comments) << '\n';
}

void case_basic_condition(FixtureArchitecture &architecture, AddrSpace *ram) {
  architecture.installCommentDB(new CommentDatabaseInternal());
  Funcdata fd("basic_condition", "basic_condition",
              architecture.symboltab->getGlobalScope(), Address(ram, 0x1000),
              (FunctionSymbol *)0, 0x200);
  BlockGraph graph;
  BlockBasic *condition = make_basic(fd, ram, 10, 0x1000);
  add_call(fd, ram, condition, 0x1000, 0x1001);
  add_cbranch(fd, ram, condition, 0x1004, 0x1080, 1);
  BlockBasic *body = make_basic(fd, ram, 11, 0x1010);
  add_store(fd, ram, body, 0x1010, 0x5010, 0x61);
  add_cbranch(fd, ram, body, 0x1014, 0x1090, 0);
  BlockIf *root = make_if(12, condition, body);
  graph.addBlock(root);
  BlockGraph sentinel_graph;
  BlockBasic *sentinel = make_sentinel(fd, ram, 0x10c0, 19);
  sentinel_graph.addBlock(sentinel);
  report_case("basic_condition", fd, root, graph, sentinel, sentinel_graph, {});
}

void case_direct_blockif_condition(FixtureArchitecture &architecture,
                                   AddrSpace *ram) {
  architecture.installCommentDB(new CommentDatabaseInternal());
  Funcdata fd("direct_blockif_condition", "direct_blockif_condition",
              architecture.symboltab->getGlobalScope(), Address(ram, 0x2000),
              (FunctionSymbol *)0, 0x200);
  BlockGraph graph;
  BlockBasic *inner_condition = make_basic(fd, ram, 20, 0x2000);
  add_call(fd, ram, inner_condition, 0x2000, 0x2001);
  add_cbranch(fd, ram, inner_condition, 0x2004, 0x2080, 1);
  BlockBasic *inner_body = make_basic(fd, ram, 21, 0x2010);
  add_call(fd, ram, inner_body, 0x2010, 0x2002);
  add_store(fd, ram, inner_body, 0x2014, 0x5020, 0x62);
  add_cbranch(fd, ram, inner_body, 0x2018, 0x2090, 0);
  BlockIf *inner_if = make_if(22, inner_condition, inner_body);
  BlockBasic *outer_body = make_basic(fd, ram, 23, 0x2020);
  add_store(fd, ram, outer_body, 0x2020, 0x5030, 0x63);
  add_cbranch(fd, ram, outer_body, 0x2024, 0x20a0, 1);
  BlockIf *root = make_if(24, inner_if, outer_body);
  graph.addBlock(root);
  BlockGraph sentinel_graph;
  BlockBasic *sentinel = make_sentinel(fd, ram, 0x20c0, 29);
  sentinel_graph.addBlock(sentinel);
  report_case("direct_blockif_condition", fd, root, graph, sentinel,
              sentinel_graph, {});
}

void case_block_condition(FixtureArchitecture &architecture, AddrSpace *ram) {
  architecture.installCommentDB(new CommentDatabaseInternal());
  Funcdata fd("block_condition", "block_condition",
              architecture.symboltab->getGlobalScope(), Address(ram, 0x3000),
              (FunctionSymbol *)0, 0x200);
  BlockGraph graph;
  BlockBasic *first = make_basic(fd, ram, 30, 0x3000);
  add_call(fd, ram, first, 0x3000, 0x3001);
  add_cbranch(fd, ram, first, 0x3004, 0x3080, 1);
  BlockBasic *second = make_basic(fd, ram, 31, 0x3010);
  add_call(fd, ram, second, 0x3010, 0x3002);
  add_cbranch(fd, ram, second, 0x3014, 0x3090, 0);
  BlockCondition *condition =
      make_condition(32, CPUI_BOOL_AND, first, second);
  BlockBasic *body = make_basic(fd, ram, 33, 0x3020);
  add_store(fd, ram, body, 0x3020, 0x5040, 0x64);
  add_cbranch(fd, ram, body, 0x3024, 0x30a0, 1);
  BlockIf *root = make_if(34, condition, body);
  graph.addBlock(root);
  BlockGraph sentinel_graph;
  BlockBasic *sentinel = make_sentinel(fd, ram, 0x30c0, 39);
  sentinel_graph.addBlock(sentinel);
  report_case("block_condition", fd, root, graph, sentinel, sentinel_graph, {});
}

void case_getstr_list_shape(FixtureArchitecture &architecture, AddrSpace *ram) {
  architecture.installCommentDB(new CommentDatabaseInternal());
  Funcdata fd("getstr_list_shape", "getstr_list_shape",
              architecture.symboltab->getGlobalScope(), Address(ram, 0x4000),
              (FunctionSymbol *)0, 0x200);
  BlockGraph graph;
  BlockBasic *a = make_basic(fd, ram, 40, 0x4000);
  add_cbranch(fd, ram, a, 0x4000, 0x4080, 1);
  BlockBasic *inner_body = make_basic(fd, ram, 41, 0x4010);
  PcodeOp *free_call = add_call(fd, ram, inner_body, 0x4010, 0x4001);
  add_store(fd, ram, inner_body, 0x4014, 0x5050, 0x65);
  add_cbranch(fd, ram, inner_body, 0x4018, 0x4090, 0);
  BlockIf *inner_if = make_if(42, a, inner_body);
  BlockBasic *b = make_basic(fd, ram, 43, 0x4020);
  add_cbranch(fd, ram, b, 0x4020, 0x40a0, 1);
  BlockBasic *c = make_basic(fd, ram, 44, 0x4030);
  PcodeOp *c_branch = add_cbranch(fd, ram, c, 0x4030, 0x40b0, 0);
  BlockCondition *condition = make_condition(45, CPUI_BOOL_AND, b, c);
  BlockList *list = make_list(46, {inner_if, condition});
  BlockBasic *outer_body = make_basic(fd, ram, 47, 0x4040);
  add_call(fd, ram, outer_body, 0x4040, 0x4002);
  PcodeOp *outer_store = add_store(fd, ram, outer_body, 0x4044, 0x5060, 0x66);
  add_cbranch(fd, ram, outer_body, 0x4048, 0x40c0, 1);
  BlockIf *root = make_if(48, list, outer_body);
  graph.addBlock(root);
  BlockGraph sentinel_graph;
  BlockBasic *sentinel = make_sentinel(fd, ram, 0x40e0, 49);
  sentinel_graph.addBlock(sentinel);
  fd.warning("INNER_FREE", free_call->getAddr());
  fd.warning("COND_SECOND", c_branch->getAddr());
  fd.warning("OUTER_STORE", outer_store->getAddr());
  report_case("getstr_list_shape", fd, root, graph, sentinel, sentinel_graph,
              {"INNER_FREE", "COND_SECOND", "OUTER_STORE"});
}

} // namespace

int main() {
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  AttributeId::initialize();
  ElementId::initialize();
  std::cout << "schema=1|fixture=PRINTC-STRUCTURED-IF-CONDITION-0001|oracle="
            << kOracleCommit
            << "|overall=MISMATCH|covered_projection=MATCH\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.ramSpace();
    case_basic_condition(architecture, ram);
    case_direct_blockif_condition(architecture, ram);
    case_block_condition(architecture, ram);
    case_getstr_list_shape(architecture, ram);
  } catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
