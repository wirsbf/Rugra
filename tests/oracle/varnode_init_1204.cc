#include <bits/stdc++.h>

// Test-only access is required to construct the same valid def-use graph that
// production Ghidra builds through the friend-only Funcdata/VarnodeBank APIs.
#define private public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef private

using namespace ghidra;

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
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1, 6,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
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

  void printMessage(const std::string &) const override {}
};

static size_t countDescendants(const Varnode *vn) {
  return static_cast<size_t>(std::distance(vn->beginDescend(), vn->endDescend()));
}

static void dumpVarnode(const char *label, const Varnode *vn) {
  const Datatype *type = vn->getType();
  const PcodeOp *def = vn->getDef();
  std::string metatype;
  metatype2string(type->getMetatype(), metatype);
  std::cout << label << ':'
            << "space=" << vn->getSpace()->getName()
            << ",space_id=" << vn->getSpace()->getIndex()
            << ",offset=" << vn->getOffset()
            << ",size=" << vn->getSize()
            << ",flags=" << vn->getFlags()
            << ",type=" << type->getName()
            << ",metatype=" << metatype
            << ",type_size=" << type->getSize()
            << ",type_id=" << type->getId()
            << ",type_inheritable=" << type->getInheritable()
            << ",type_core=" << type->isCoreType()
            << ",def=" << (def != nullptr)
            << ",def_addr=" << (def == nullptr ? 0 : def->getAddr().getOffset())
            << ",def_order=" << (def == nullptr ? 0 : def->getTime())
            << ",has_cover=" << vn->hasCover()
            << ",cover_object=" << (vn->cover != nullptr)
            << ",create=" << vn->getCreateIndex()
            << ",descendants=" << countDescendants(vn)
            << ",consumed=" << vn->getConsume()
            << ",nzm=" << vn->getNZMask()
            << '\n';
}

static char classCode(const Varnode *vn) {
  if (vn->isInput()) return 'I';
  if (vn->isWritten()) return 'W';
  return 'F';
}

static size_t countOps(const Funcdata &fd) {
  return static_cast<size_t>(
      std::distance(fd.beginOpAll(), fd.endOpAll()));
}

static const char *operationLabel(const PcodeOp *op, const PcodeOp *piece,
                                  const PcodeOp *hi_reader,
                                  const PcodeOp *lo_reader,
                                  const PcodeOp *sub_hi,
                                  const PcodeOp *sub_lo) {
  if (op == piece) return "piece";
  if (op == hi_reader) return "hi_reader";
  if (op == lo_reader) return "lo_reader";
  if (op == sub_hi) return "sub_hi";
  if (op == sub_lo) return "sub_lo";
  return "unknown";
}

static std::string descendantLabels(const Varnode *vn, const PcodeOp *piece,
                                    const PcodeOp *hi_reader,
                                    const PcodeOp *lo_reader,
                                    const PcodeOp *sub_hi,
                                    const PcodeOp *sub_lo) {
  std::ostringstream stream;
  bool first = true;
  for (auto iter = vn->beginDescend(); iter != vn->endDescend(); ++iter) {
    if (!first) stream << '/';
    first = false;
    stream << operationLabel(
        *iter, piece, hi_reader, lo_reader, sub_hi, sub_lo);
  }
  return stream.str();
}

static void runCombineFixture() {
  FixtureArchitecture architecture;
  AddrSpace *ram = architecture.getSpace(3);
  AddrSpace *reg = architecture.getSpace(4);
  Scope *global = architecture.symboltab->getGlobalScope();

  {
    Funcdata fd("combine", "combine", global, Address(ram, 0x5000),
                (FunctionSymbol *)0, 0x20);
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = blocks.newBlockBasic(&fd);
    fd.setBasicBlockRange(
        block, Address(ram, 0x5000), Address(ram, 0x5000));

    Varnode *hi = fd.newVarnode(4, Address(reg, 0x24));
    hi = fd.setInputVarnode(hi);
    Varnode *lo = fd.newVarnode(4, Address(reg, 0x20));
    lo = fd.setInputVarnode(lo);

    PcodeOp *piece = fd.newOp(2, Address(ram, 0x5000));
    fd.opSetOpcode(piece, CPUI_PIECE);
    fd.opSetInput(piece, hi, 0);
    fd.opSetInput(piece, lo, 1);
    fd.newUniqueOut(8, piece);
    fd.opInsertEnd(piece, block);

    PcodeOp *hi_reader = fd.newOp(2, Address(ram, 0x5001));
    fd.opSetOpcode(hi_reader, CPUI_INT_ADD);
    fd.opSetInput(hi_reader, hi, 0);
    fd.opSetInput(hi_reader, hi, 1);
    fd.newUniqueOut(4, hi_reader);
    fd.opInsertEnd(hi_reader, block);

    PcodeOp *lo_reader = fd.newOp(1, Address(ram, 0x5002));
    fd.opSetOpcode(lo_reader, CPUI_COPY);
    fd.opSetInput(lo_reader, lo, 0);
    fd.newUniqueOut(4, lo_reader);
    fd.opInsertEnd(lo_reader, block);

    const int4 bank_before = fd.numVarnodes();
    const size_t ops_before = countOps(fd);
    fd.combineInputVarnodes(hi, lo);

    Varnode *combined = piece->getIn(0);
    Varnode *new_hi = hi_reader->getIn(0);
    Varnode *new_lo = lo_reader->getIn(0);
    PcodeOp *sub_hi = new_hi->getDef();
    PcodeOp *sub_lo = new_lo->getDef();
    size_t old_input_edges = 0;
    for (auto iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) {
      PcodeOp *op = (*iter).second;
      for (int4 slot = 0; slot != op->numInput(); ++slot) {
        Varnode *input_vn = op->getIn(slot);
        if (input_vn->isInput() && input_vn->getSpace() == reg &&
            input_vn->getSize() == 4 &&
            (input_vn->getOffset() == 0x20 || input_vn->getOffset() == 0x24))
          old_input_edges += 1;
      }
    }
    Varnode *bank_combined = (Varnode *)0;
    size_t old_input_bank = 0;
    for (auto iter = fd.beginLoc(); iter != fd.endLoc(); ++iter) {
      Varnode *vn = *iter;
      if (vn->isInput() && vn->getSpace() == reg && vn->getOffset() == 0x20 &&
          vn->getSize() == 8)
        bank_combined = vn;
      if (vn->isInput() && vn->getSpace() == reg && vn->getSize() == 4 &&
          (vn->getOffset() == 0x20 || vn->getOffset() == 0x24))
        old_input_bank += 1;
    }
    std::ostringstream block_order;
    bool first = true;
    for (auto iter = block->beginOp(); iter != block->endOp(); ++iter) {
      if (!first) block_order << '/';
      first = false;
      block_order << operationLabel(
          *iter, piece, hi_reader, lo_reader, sub_hi, sub_lo);
    }

    std::cout << "combine_valid:bank=" << bank_before << "->" << fd.numVarnodes()
              << ",ops=" << ops_before << "->" << countOps(fd)
              << ",piece_copy=" << (piece->code() == CPUI_COPY)
              << ",piece_inputs=" << piece->numInput()
              << ",piece_canonical=" << (combined == bank_combined)
              << ",old_input_edges=" << old_input_edges
              << ",old_input_bank=" << old_input_bank
              << ",combined=" << combined->getSpace()->getName() << '/'
              << combined->getSpace()->getIndex() << '/'
              << combined->getOffset() << '/'
              << combined->getSize() << '/' << combined->getFlags() << '/'
              << combined->getCreateIndex()
              << ",combined_desc=" << descendantLabels(
                     combined, piece, hi_reader, lo_reader, sub_hi, sub_lo)
              << ",hi_reader_slots=" << (hi_reader->getIn(0) == new_hi)
              << (hi_reader->getIn(1) == new_hi)
              << ",hi=" << new_hi->getSpace()->getName() << '/'
              << new_hi->getSpace()->getIndex() << '/'
              << new_hi->getOffset() << '/'
              << new_hi->getSize() << '/' << countDescendants(new_hi)
              << ",sub_hi=" << sub_hi->getAddr().getOffset() << '/'
              << sub_hi->numInput() << '/'
              << (sub_hi->getIn(0) == combined) << '/'
              << sub_hi->getIn(1)->getOffset()
              << ",lo_reader_slot=" << (lo_reader->getIn(0) == new_lo)
              << ",lo=" << new_lo->getSpace()->getName() << '/'
              << new_lo->getSpace()->getIndex() << '/'
              << new_lo->getOffset() << '/'
              << new_lo->getSize() << '/' << countDescendants(new_lo)
              << ",sub_lo=" << sub_lo->getAddr().getOffset() << '/'
              << sub_lo->numInput() << '/'
              << (sub_lo->getIn(0) == combined) << '/'
              << sub_lo->getIn(1)->getOffset()
              << ",block_order=" << block_order.str() << '\n';
  }

  std::string noninput_error;
  std::string disjoint_error;
  {
    Funcdata fd("combine_noninput", "combine_noninput", global,
                Address(ram, 0x6000),
                (FunctionSymbol *)0, 1);
    Varnode *hi = fd.newVarnode(4, Address(reg, 0x24));
    Varnode *lo = fd.setInputVarnode(
        fd.newVarnode(4, Address(reg, 0x20)));
    try { fd.combineInputVarnodes(hi, lo); }
    catch (const LowlevelError &error) { noninput_error = error.explain; }
  }
  {
    Funcdata fd("combine_disjoint", "combine_disjoint", global,
                Address(ram, 0x7000),
                (FunctionSymbol *)0, 1);
    Varnode *hi = fd.setInputVarnode(
        fd.newVarnode(4, Address(reg, 0x30)));
    Varnode *lo = fd.setInputVarnode(
        fd.newVarnode(4, Address(reg, 0x20)));
    try { fd.combineInputVarnodes(hi, lo); }
    catch (const LowlevelError &error) { disjoint_error = error.explain; }
  }
  std::cout << "combine_errors:noninput=" << noninput_error
            << ",disjoint=" << disjoint_error << '\n';
}

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureTranslate trans;
  FixtureArchitecture architecture;
  // Draw ct from the factory the way production Funcdata::newVarnode does
  // (glb->types->getBase(s,TYPE_UNKNOWN)): the standalone-flavor core types
  // carry hashName ids and the core flag, matching the Rust comparand's
  // injected Standalone TypeFactory.
  Datatype *unknown8 = architecture.types->getBase(8, TYPE_UNKNOWN);
  Datatype *unknown4 = architecture.types->getBase(4, TYPE_UNKNOWN);
  VarnodeBank bank(&trans);

  PcodeOp defop(0, SeqNum(Address(trans.getSpace(3), 0x1000), 0));
  Varnode *defined = bank.createDef(
      8, Address(trans.getSpace(4), 0x20), unknown8, &defop);
  Varnode *free = bank.create(8, Address(trans.getSpace(4), 0x38), unknown8);
  Varnode *constant = bank.create(
      4, Address(trans.getConstantSpace(), 0x1234), unknown4);
  Varnode *input = bank.create(8, Address(trans.getSpace(4), 0x30), unknown8);
  input = bank.setInput(input);
  Varnode *annotation = bank.create(
      8, Address(trans.getIopSpace(), 0x99), unknown8);
  Varnode *unique0 = bank.createUnique(8, unknown8);
  Varnode *unique1 = bank.createUnique(4, unknown4);
  Varnode *set_def_valid = bank.create(
      8, Address(trans.getSpace(4), 0x28), unknown8);
  Varnode *set_def_source = set_def_valid;
  set_def_valid = bank.setDef(set_def_valid, &defop);

  dumpVarnode("defined", defined);
  dumpVarnode("free", free);
  dumpVarnode("constant", constant);
  dumpVarnode("input", input);
  dumpVarnode("annotation", annotation);
  dumpVarnode("unique0", unique0);
  dumpVarnode("unique1", unique1);
  std::cout << "set_def_valid:canonical_self=" << (set_def_valid == set_def_source)
            << ",flags=" << set_def_valid->getFlags()
            << ",def=" << (set_def_valid->getDef() == &defop)
            << ",create=" << set_def_valid->getCreateIndex() << '\n';
  std::cout << "type_identity:size8="
            << (defined->getType() == free->getType())
            << (defined->getType() == input->getType())
            << (defined->getType() == annotation->getType())
            << (defined->getType() == unique0->getType())
            << (defined->getType() == set_def_valid->getType())
            << ",size4=" << (constant->getType() == unique1->getType()) << '\n';

  input->calcCover();
  const Cover *input_cover = input->getCover();
  const CoverBlock &input_block = input_cover->getCoverBlock(0);
  std::cout << "input_cover:object=" << (input_cover != nullptr)
            << ",raw_start=" << reinterpret_cast<uintp>(input_block.getStart())
            << ",raw_stop=" << reinterpret_cast<uintp>(input_block.getStop())
            << ",semantic_start=" << CoverBlock::getUIndex(input_block.getStart())
            << ",semantic_stop=" << CoverBlock::getUIndex(input_block.getStop())
            << ",flags_after=" << input->getFlags() << '\n';

  const int4 count_before_create_def_duplicate = bank.numVarnodes();
  Varnode *defined_duplicate = bank.createDef(
      8, Address(trans.getSpace(4), 0x20), unknown8, &defop);
  std::cout << "create_def_duplicate:canonical=" << (defined_duplicate == defined)
            << ",bank_delta=" << (bank.numVarnodes() - count_before_create_def_duplicate)
            << '\n';

  Varnode *canonical = bank.create(
      8, Address(trans.getSpace(4), 0x50), unknown8);
  canonical = bank.setInput(canonical);
  Varnode *duplicate = bank.create(
      8, Address(trans.getSpace(4), 0x50), unknown8);
  duplicate->setFlags(Varnode::spacebase);
  PcodeOp reader(2, SeqNum(Address(trans.getSpace(3), 0x1010), 1));
  reader.setInput(duplicate, 0);
  reader.setInput(duplicate, 1);
  duplicate->addDescend(&reader);
  duplicate->addDescend(&reader);
  Varnode *canonical_return = bank.setInput(duplicate);
  bool descend_order = true;
  for (auto iter = canonical->beginDescend(); iter != canonical->endDescend(); ++iter)
    descend_order = descend_order && (*iter == &reader);
  std::cout << "xref_duplicate:canonical=" << (canonical_return == canonical)
            << ",slot0=" << (reader.getIn(0) == canonical)
            << ",slot1=" << (reader.getIn(1) == canonical)
            << ",descendants=" << countDescendants(canonical)
            << ",descend_order=" << descend_order << '\n';

  std::string input_nonfree_error;
  std::string input_constant_error;
  std::string def_nonfree_error;
  std::string def_constant_error;
  Varnode *guard_constant = bank.create(
      4, Address(trans.getConstantSpace(), 0x55), unknown4);
  try { bank.setInput(canonical); } catch (const LowlevelError &err) { input_nonfree_error = err.explain; }
  try { bank.setInput(guard_constant); } catch (const LowlevelError &err) { input_constant_error = err.explain; }
  try { bank.setDef(canonical, &defop); } catch (const LowlevelError &err) { def_nonfree_error = err.explain; }
  try { bank.setDef(guard_constant, &defop); } catch (const LowlevelError &err) { def_constant_error = err.explain; }
  std::cout << "checked_guards:input_nonfree=" << input_nonfree_error
            << ",input_constant=" << input_constant_error
            << ",def_nonfree=" << def_nonfree_error
            << ",def_constant=" << def_constant_error << '\n';

  Varnode *made_free = bank.createDef(
      8, Address(trans.getSpace(4), 0x58), unknown8, &defop);
  const int4 count_before_make_free = bank.numVarnodes();
  bank.makeFree(made_free);
  std::cout << "make_free:flags=" << made_free->getFlags()
            << ",def=" << (made_free->getDef() != nullptr)
            << ",free=" << made_free->isFree()
            << ",bank_delta=" << (bank.numVarnodes() - count_before_make_free) << '\n';

  Varnode *destroy_free = bank.create(
      8, Address(trans.getSpace(4), 0x60), unknown8);
  const int4 count_before_destroy = bank.numVarnodes();
  bank.destroy(destroy_free);
  const int4 destroy_free_delta = bank.numVarnodes() - count_before_destroy;
  Varnode *destroy_defined = bank.createDef(
      8, Address(trans.getSpace(4), 0x68), unknown8, &defop);
  std::string destroy_def_error;
  try { bank.destroy(destroy_defined); }
  catch (const LowlevelError &err) { destroy_def_error = err.explain; }
  Varnode *destroy_descendant = bank.create(
      8, Address(trans.getSpace(4), 0x70), unknown8);
  PcodeOp destroy_reader(1, SeqNum(Address(trans.getSpace(3), 0x1020), 2));
  destroy_reader.setInput(destroy_descendant, 0);
  destroy_descendant->addDescend(&destroy_reader);
  std::string destroy_desc_error;
  try { bank.destroy(destroy_descendant); }
  catch (const LowlevelError &err) { destroy_desc_error = err.explain; }
  std::cout << "destroy:free_delta=" << destroy_free_delta
            << ",def_error=" << destroy_def_error
            << ",desc_error=" << destroy_desc_error << '\n';

  VarnodeBank order_bank(&trans);
  PcodeOp order_op(0, SeqNum(Address(trans.getSpace(3), 0x2000), 2));
  Varnode *class_input = order_bank.create(
      8, Address(trans.getSpace(4), 0xa0), unknown8);
  class_input = order_bank.setInput(class_input);
  order_bank.createDef(8, Address(trans.getSpace(4), 0xa0), unknown8, &order_op);
  order_bank.create(8, Address(trans.getSpace(4), 0xa0), unknown8);
  std::string loc_classes;
  std::string def_classes;
  for (auto iter = order_bank.beginLoc(); iter != order_bank.endLoc(); ++iter)
    if ((*iter)->getSpace()->getIndex() == 4 && (*iter)->getOffset() == 0xa0)
      loc_classes.push_back(classCode(*iter));
  for (auto iter = order_bank.beginDef(); iter != order_bank.endDef(); ++iter)
    if ((*iter)->getSpace()->getIndex() == 4 && (*iter)->getOffset() == 0xa0)
      def_classes.push_back(classCode(*iter));
  std::cout << "class_order:loc=" << loc_classes << ",def=" << def_classes << '\n';

  PcodeOp written_op_late(0, SeqNum(Address(trans.getSpace(3), 0x3000), 9));
  PcodeOp written_op_early(0, SeqNum(Address(trans.getSpace(3), 0x3000), 3));
  order_bank.createDef(8, Address(trans.getSpace(4), 0xb0), unknown8, &written_op_late);
  order_bank.createDef(8, Address(trans.getSpace(4), 0xb0), unknown8, &written_op_early);
  PcodeOp written_pc_late(0, SeqNum(Address(trans.getSpace(3), 0x4000), 4));
  PcodeOp written_pc_early(0, SeqNum(Address(trans.getSpace(3), 0x3500), 5));
  order_bank.createDef(8, Address(trans.getSpace(4), 0xb4), unknown8, &written_pc_late);
  order_bank.createDef(8, Address(trans.getSpace(4), 0xb4), unknown8, &written_pc_early);
  Varnode *free_early = order_bank.create(
      8, Address(trans.getSpace(4), 0xb8), unknown8);
  Varnode *free_late = order_bank.create(
      8, Address(trans.getSpace(4), 0xb8), unknown8);
  std::cout << "tie_breaks:written_loc=";
  for (auto iter = order_bank.beginLoc(); iter != order_bank.endLoc(); ++iter)
    if ((*iter)->isWritten() && (*iter)->getOffset() == 0xb0)
      std::cout << (*iter)->getDef()->getTime();
  std::cout << ",written_def=";
  for (auto iter = order_bank.beginDef(); iter != order_bank.endDef(); ++iter)
    if ((*iter)->isWritten() && (*iter)->getOffset() == 0xb0)
      std::cout << (*iter)->getDef()->getTime();
  std::cout << ",written_pc_loc=";
  for (auto iter = order_bank.beginLoc(); iter != order_bank.endLoc(); ++iter)
    if ((*iter)->isWritten() && (*iter)->getOffset() == 0xb4)
      std::cout << ((*iter)->getDef()->getAddr().getOffset() == 0x3500 ? 'E' : 'L');
  std::cout << ",written_pc_def=";
  for (auto iter = order_bank.beginDef(); iter != order_bank.endDef(); ++iter)
    if ((*iter)->isWritten() && (*iter)->getOffset() == 0xb4)
      std::cout << ((*iter)->getDef()->getAddr().getOffset() == 0x3500 ? 'E' : 'L');
  std::cout << ",free_loc=";
  for (auto iter = order_bank.beginLoc(); iter != order_bank.endLoc(); ++iter)
    if ((*iter)->isFree() && (*iter)->getOffset() == 0xb8)
      std::cout << ((*iter)->getCreateIndex() == free_early->getCreateIndex() ? 'E' : 'L');
  std::cout << ",free_def=";
  for (auto iter = order_bank.beginDef(); iter != order_bank.endDef(); ++iter)
    if ((*iter)->isFree() && (*iter)->getOffset() == 0xb8)
      std::cout << ((*iter)->getCreateIndex() == free_early->getCreateIndex() ? 'E' : 'L');
  std::cout << ",free_distinct="
            << (free_early->getCreateIndex() != free_late->getCreateIndex()) << '\n';

  for (int4 index = 0; index != 8; ++index)
    order_bank.create(8, Address(trans.getSpace(index), 0xc0), unknown8);
  std::cout << "space_order=";
  bool first_space = true;
  for (auto iter = order_bank.beginLoc(); iter != order_bank.endLoc(); ++iter) {
    if ((*iter)->getOffset() != 0xc0) continue;
    if (!first_space) std::cout << ',';
    first_space = false;
    std::cout << (*iter)->getSpace()->getIndex();
  }
  std::cout << '\n';

  Varnode *ram_input = order_bank.create(
      8, Address(trans.getSpace(3), 0xd0), unknown8);
  order_bank.setInput(ram_input);
  Varnode *register_input = order_bank.create(
      8, Address(trans.getSpace(4), 0xd0), unknown8);
  order_bank.setInput(register_input);
  order_bank.createDef(8, Address(trans.getSpace(3), 0xd8), unknown8, &order_op);
  order_bank.createDef(8, Address(trans.getSpace(4), 0xd8), unknown8, &order_op);
  std::cout << "def_storage_order:input=";
  for (auto iter = order_bank.beginDef(); iter != order_bank.endDef(); ++iter)
    if ((*iter)->isInput() && (*iter)->getOffset() == 0xd0)
      std::cout << (*iter)->getSpace()->getIndex();
  std::cout << ",written=";
  for (auto iter = order_bank.beginDef(); iter != order_bank.endDef(); ++iter)
    if ((*iter)->isWritten() && (*iter)->getOffset() == 0xd8)
      std::cout << (*iter)->getSpace()->getIndex();
  std::cout << '\n';

  Datatype *unknown8_identity = defined->getType();
  bank.clear();
  Varnode *after_clear = bank.createUnique(8, unknown8);
  std::cout << "after_clear:offset=" << after_clear->getOffset()
            << ",create=" << after_clear->getCreateIndex()
            << ",type_same=" << (after_clear->getType() == unknown8_identity) << '\n';
  try {
    runCombineFixture();
  } catch (const LowlevelError &error) {
    std::cerr << "combine fixture failed: " << error.explain << '\n';
    return 2;
  }
  return 0;
}
