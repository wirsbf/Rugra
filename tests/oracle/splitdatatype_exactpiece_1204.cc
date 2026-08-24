// SPLITDATATYPE-EXACTPIECE-0001 fixture — C++ side.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Bilateral gate for the RuleSplitLoad/RuleSplitStore exact-piece chain after
// the canonical TypeFactory migration (SPLITDATATYPE-EXACTPIECE-0001):
//
//   gv records     SplitDatatype::getValueDatatype      subflow.cc:2910-2938
//                  (canonical TypeFactory::getExactPiece, type.cc:4090-4117)
//   cat records    SplitDatatype::categorizeDatatype    subflow.cc:2237-2274
//   compat records SplitDatatype::testDatatypeCompatibility
//                                                  subflow.cc:2285-2367
//   apply records  RuleSplitStore/RuleSplitLoad::applyOp
//                                                  subflow.cc:2970-3004
//   stab records   second sweep over every op (rule-repeatapply stability)
//
// Observation planes:
//   A (gate decisions)  — getValueDatatype shape, categorize values, and the
//                         compat piece list, byte-identical both sides.
//   B (structural)      — rule return code, per-store/per-load effective
//                         pointer offset (resolved through the PTRSUB/PTRADD/
//                         INT_ADD constant chain back to the case's root
//                         pointer varnode) and value size, original-op
//                         identity retention, ops-added delta for NO_CHANGE
//                         cases (pre-exception state: nothing is mutated).
//   C (stability)       — a full second sweep over every op reports zero
//                         further changes (rule_repeatapply second round).
//
// The split rewrites' op SHAPES differ (oracle buildPointers emits PTRSUB/
// PTRADD per piece; the Rust stand-in emits INT_ADD off the in(1) pointer)
// — that structural gap is registered in the metadata; the projections here
// are the shared effective semantics (offset+size+identity), never raw DAG
// shapes.
//
// SSA discipline: every varnode read by more than one op is written (defined
// by a COPY from a constant), mirroring the cleanup-phase pipeline Ghidra
// runs these rules in (free varnodes allow a single descendant,
// varnode.cc:333-336).

#include <bits/stdc++.h>
#define private public
#include "address.hh"
#include "architecture.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "op.hh"
#include "subflow.hh"
#include "type.hh"
#include "varnode.hh"
#undef private

using namespace ghidra;

namespace {

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
    std::istringstream organization(
        "<data_organization><size_alignment_map>"
        "<entry size=\"0\" alignment=\"1\"/>"
        "<entry size=\"1\" alignment=\"1\"/>"
        "<entry size=\"2\" alignment=\"2\"/>"
        "<entry size=\"3\" alignment=\"2\"/>"
        "<entry size=\"4\" alignment=\"4\"/>"
        "<entry size=\"8\" alignment=\"8\"/>"
        "<entry size=\"16\" alignment=\"8\"/>"
        "<entry size=\"32\" alignment=\"8\"/>"
        "</size_alignment_map></data_organization>");
    XmlDecode organization_decoder(this);
    organization_decoder.ingestStream(organization);
    types->decodeDataOrganization(organization_decoder);
    types->setupSizes();
    types->setCoreType("undefined1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("undefined2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("undefined4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("undefined8", 8, TYPE_UNKNOWN, false);
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

std::string plainKind(const Datatype *ct)
{
  if (ct == (const Datatype *)0)
    return "null";
  if (dynamic_cast<const TypePartialStruct *>(ct) != (const TypePartialStruct *)0)
    return "partial_struct";
  if (dynamic_cast<const TypePartialUnion *>(ct) != (const TypePartialUnion *)0)
    return "partial_union";
  if (dynamic_cast<const TypePartialEnum *>(ct) != (const TypePartialEnum *)0)
    return "partial_enum";
  if (ct->isEnumType())
    return "enum";
  switch (ct->getMetatype()) {
  case TYPE_STRUCT: return "struct";
  case TYPE_UNION: return "union";
  case TYPE_ARRAY: return "array";
  case TYPE_UINT: return "uint";
  case TYPE_INT: return "int";
  case TYPE_UNKNOWN: return "unknown";
  default: return "other";
  }
}

std::string shortShape(const Datatype *ct)
{
  if (ct == (const Datatype *)0)
    return "null";
  std::ostringstream out;
  out << plainKind(ct) << ':' << ct->getSize();
  return out.str();
}

std::string shape(const Datatype *ct)
{
  if (ct == (const Datatype *)0)
    return "null";
  std::ostringstream out;
  if (const TypePartialStruct *part = dynamic_cast<const TypePartialStruct *>(ct)) {
    out << "partial_struct:" << part->getSize()
        << '@' << part->getOffset()
        << "/parent=" << shortShape(part->getParent());
    return out.str();
  }
  if (const TypeArray *array = dynamic_cast<const TypeArray *>(ct)) {
    out << "array:" << array->getSize()
        << 'x' << array->numElements()
        << "/elem=" << shortShape(array->getBase());
    return out.str();
  }
  return shortShape(ct);
}

// Resolve the byte offset of `vn` relative to the case's root pointer
// varnode, following PTRSUB/INT_ADD/PTRADD constant chains.
int64_t resolveOffset(const Varnode *vn, const Varnode *root, bool &ok)
{
  if (vn == root) {
    ok = true;
    return 0;
  }
  if (!vn->isWritten()) {
    ok = false;
    return 0;
  }
  const PcodeOp *def = vn->getDef();
  OpCode opc = def->code();
  if (opc != CPUI_PTRSUB && opc != CPUI_INT_ADD && opc != CPUI_PTRADD) {
    ok = false;
    return 0;
  }
  const Varnode *base = def->getIn(0);
  const Varnode *offVn = def->getIn(1);
  if (!offVn->isConstant()) {
    ok = false;
    return 0;
  }
  int64_t baseOff = resolveOffset(base, root, ok);
  if (!ok)
    return 0;
  if (opc == CPUI_PTRADD) {
    const Varnode *szVn = def->getIn(2);
    if (!szVn->isConstant()) {
      ok = false;
      return 0;
    }
    return baseOff + ((int64_t)offVn->getOffset()) * ((int64_t)szVn->getOffset());
  }
  return baseOff + (int64_t)offVn->getOffset();
}

} // anonymous namespace

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureArchitecture architecture;
  TypeFactory *types = architecture.types;
  AddrSpace *code = architecture.getDefaultCodeSpace();
  AddrSpace *unique = architecture.getUniqueSpace();

  // ---- shared production type graph --------------------------------------
  Datatype *uint4 = types->getBase(4, TYPE_UINT);

  // FILE-like opaque struct: size 8, zero fields.
  TypeStruct *file8 = types->getTypeStruct("split_file8");
  {
    std::vector<TypeField> fields; // empty: opaque
    types->setFields(fields, file8, 8, 8, 0);
  }
  // _IO_FILE-like struct: flags uint4@0, hole 4..8, 26 x uint8 @8..216.
  TypeStruct *iofile = types->getTypeStruct("split_iofile216");
  {
    std::vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "flags", uint4));
    char namebuf[32];
    for (int4 i = 0; i < 26; ++i) {
      snprintf(namebuf, sizeof(namebuf), "f%d", i);
      fields.push_back(TypeField(i + 1, 8 + 8 * i, namebuf, types->getBase(8, TYPE_UINT)));
    }
    types->setFields(fields, iofile, 216, 8, 0);
  }
  // ProgressData-like struct: 4 x uint4 @0..16, uint8 @16.
  TypeStruct *progress = types->getTypeStruct("split_progress24");
  {
    std::vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "width", uint4));
    fields.push_back(TypeField(1, 4, "height", uint4));
    fields.push_back(TypeField(2, 8, "total", uint4));
    fields.push_back(TypeField(3, 12, "done", uint4));
    fields.push_back(TypeField(4, 16, "extra", types->getBase(8, TYPE_UINT)));
    types->setFields(fields, progress, 24, 4, 0);
  }
  TypeArray *uint4_array6 = types->getTypeArray(6, uint4);

  TypePointer *ptr_file8 = types->getTypePointer(8, file8, 1);
  TypePointer *ptr_iofile = types->getTypePointer(8, iofile, 1);
  TypePointer *ptr_progress = types->getTypePointer(8, progress, 1);
  TypePointer *ptr_array = types->getTypePointer(8, uint4_array6, 1);
  TypePointer *ptr_uint4 = types->getTypePointer(8, uint4, 1);
  TypePointerRel *relptr_progress8 =
      types->getTypePointerRel(ptr_progress, uint4, 8); // ephemeral

  Scope *parent = architecture.symboltab->getGlobalScope();
  // Scratch Funcdata for the read-only getValueDatatype stubs: stub LOADs
  // have no output varnode, so they must never be swept by the rule
  // applications (which read op->getOut()).
  Funcdata fd_stub("stubs", "stubs", parent, Address(code, 0x9000),
                   (FunctionSymbol *)0, 0x10);
  Funcdata fd("fixture", "fixture", parent, Address(code, 0x1000),
              (FunctionSymbol *)0, 0x100);
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);

  int4 unique_counter = 0;

  // Build a written pointer varnode (COPY of a constant), SSA-safe for
  // multiple readers.
  auto make_ptr = [&](Datatype *ptr_type) -> Varnode * {
    Address pc(code, 0x2000 + 0x10 * unique_counter);
    PcodeOp *copy = fd.newOp(1, pc);
    fd.opSetOpcode(copy, CPUI_COPY);
    Varnode *out = fd.newVarnodeOut(8, Address(unique, 0x1000 + 0x10 * unique_counter), copy);
    fd.opSetInput(copy, fd.newConstant(8, 0x400000 + unique_counter), 0);
    out->updateType(ptr_type);
    fd.opInsertEnd(copy, block);
    ++unique_counter;
    return out;
  };
  // Build a written value varnode (COPY of a constant) of the given size.
  auto make_value = [&](int4 size) -> Varnode * {
    Address pc(code, 0x2400 + 0x10 * unique_counter);
    PcodeOp *copy = fd.newOp(1, pc);
    fd.opSetOpcode(copy, CPUI_COPY);
    Varnode *out = fd.newVarnodeOut(size, Address(unique, 0x2000 + 0x10 * unique_counter), copy);
    fd.opSetInput(copy, fd.newConstant(size, 0x300000 + unique_counter), 0);
    fd.opInsertEnd(copy, block);
    ++unique_counter;
    return out;
  };
  // Build a detached LOAD op (in the scratch Funcdata) whose in(1) carries
  // the given pointer type (read-only helper for getValueDatatype).
  auto make_load_stub = [&](Datatype *ptr_type) -> PcodeOp * {
    PcodeOp *load = fd_stub.newOp(2, Address(code, 0x3000 + 0x10 * unique_counter));
    fd_stub.opSetOpcode(load, CPUI_LOAD);
    Varnode *ptr = fd_stub.newVarnode(8, Address(unique, 0x3000 + 0x10 * unique_counter));
    ptr->updateType(ptr_type);
    fd_stub.opSetInput(load, fd_stub.newVarnodeSpace(architecture.getSpaceByName("ram")), 0);
    fd_stub.opSetInput(load, ptr, 1);
    ++unique_counter;
    return load;
  };

  // ---- Plane A: getValueDatatype (subflow.cc:2910-2938) ------------------
  struct GvCase { const char *id; Datatype *ptr; int4 size; };
  const GvCase gv_cases[] = {
    {"file_opaque8", ptr_file8, 8},
    {"iofile8", ptr_iofile, 8},
    {"progress16", ptr_progress, 16},
    {"array_window8", ptr_array, 8},
    {"relptr16", relptr_progress8, 16},
    {"scalar_array16", ptr_uint4, 16},
  };
  for (const GvCase &c : gv_cases) {
    PcodeOp *stub = make_load_stub(c.ptr);
    Datatype *result = SplitDatatype::getValueDatatype(stub, c.size, types);
    std::cout << "gv|case=" << c.id << "|size=" << c.size
              << "|result=" << shape(result) << '\n';
  }

  RuleSplitStore split_store_rule("splitpointer");
  RuleSplitLoad split_load_rule("splitpointer");

  // ---- shared helpers ------------------------------------------------------
  int4 global_second_round_changes = 0;

  // opDestroy marks ops dead; dead ops keep iterating in the all-op tree
  // with null inputs/output, so every observation below is alive-only.
  auto count_ops = [&]() -> int64_t {
    int64_t n = 0;
    for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it)
      ++n;
    return n;
  };
  auto op_alive = [&](PcodeOp *target) -> bool {
    for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it)
      if (*it == target)
        return true;
    return false;
  };
  auto second_round = [&]() -> int4 {
    std::vector<PcodeOp *> snapshot;
    for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it)
      snapshot.push_back(*it);
    int4 changes = 0;
    for (PcodeOp *op : snapshot) {
      if (op->code() == CPUI_STORE) {
        if (split_store_rule.applyOp(op, fd) != 0)
          ++changes;
      } else if (op->code() == CPUI_LOAD) {
        if (split_load_rule.applyOp(op, fd) != 0)
          ++changes;
      }
    }
    return changes;
  };
  auto hex16 = [](uintb v) -> std::string {
    std::ostringstream out;
    out << "0x" << std::hex << v;
    return out.str();
  };

  // Builds a STORE op with the given (already built) pointer and value.
  auto make_store = [&](Varnode *ptr, Varnode *value) -> PcodeOp * {
    PcodeOp *store = fd.newOp(3, Address(code, 0x4000 + 0x10 * unique_counter));
    fd.opSetOpcode(store, CPUI_STORE);
    fd.opSetInput(store, fd.newVarnodeSpace(architecture.getSpaceByName("ram")), 0);
    fd.opSetInput(store, ptr, 1);
    fd.opSetInput(store, value, 2);
    fd.opInsertEnd(store, block);
    ++unique_counter;
    return store;
  };
  // Build a PTRSUB off a written root pointer.
  auto make_ptrsub = [&](Varnode *root, uintb off) -> Varnode * {
    PcodeOp *sub = fd.newOp(2, Address(code, 0x4400 + 0x10 * unique_counter));
    fd.opSetOpcode(sub, CPUI_PTRSUB);
    Varnode *out = fd.newVarnodeOut(8, Address(unique, 0x4000 + 0x10 * unique_counter), sub);
    fd.opSetInput(sub, root, 0);
    fd.opSetInput(sub, fd.newConstant(8, off), 1);
    fd.opInsertEnd(sub, block);
    ++unique_counter;
    return out;
  };

  // ---- Plane A: gate decisions through the public split entry points ----
  // SplitDatatype's categorize/testDatatypeCompatibility members are private
  // by class-default access (no `private:` label), so #define private public
  // cannot expose them; the gate outcomes are observed through the public
  // splitCopy/splitLoad/splitStore members, which take the data-types as
  // explicit arguments (subflow.hh:302-305) and run the exact same gate
  // chain before rewriting.
  Datatype *undef16 = types->getBase(16, TYPE_UNKNOWN);
  Datatype *partial_progress16 = types->getTypePartialStruct(progress, 0, 16);
  Datatype *partial_iofile8 = types->getTypePartialStruct(iofile, 0, 8);
  Datatype *array2_uint4 = types->getTypeArray(2, uint4);

  // whole-struct COPY gate: same Arc both sides, non-constant -> reject
  // (subflow.cc:2304-2305).
  {
    Varnode *in_vn = make_value(24);
    in_vn->updateType(progress);
    Varnode *out_vn = make_value(24);
    out_vn->updateType(progress);
    PcodeOp *copy = fd.newOp(1, Address(code, 0x3400 + 0x10 * unique_counter));
    fd.opSetOpcode(copy, CPUI_COPY);
    fd.opSetInput(copy, in_vn, 0);
    fd.opSetOutput(copy, out_vn);
    fd.opInsertEnd(copy, block);
    ++unique_counter;
    SplitDatatype splitter(fd);
    bool ok = splitter.splitCopy(copy, progress, progress);
    std::cout << "split|case=whole_struct_pd|fn=splitCopy|ok=" << (ok ? 1 : 0) << '\n';
    if (!ok)
      fd.opDestroy(copy);
  }
  auto split_store_gate = [&](const char *id, Datatype *out_type, Varnode *value) {
    Varnode *ptr = make_ptr(ptr_uint4);
    PcodeOp *store = make_store(ptr, value);
    SplitDatatype splitter(fd);
    bool ok = splitter.splitStore(store, out_type);
    std::ostringstream pieces;
    pieces << '-';
    if (ok) {
      std::vector<std::pair<int64_t, int4>> stores;
      for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
        PcodeOp *op = *it;
        if (op->code() != CPUI_STORE)
          continue;
        bool rok = false;
        int64_t off = resolveOffset(op->getIn(1), ptr, rok);
        if (rok)
          stores.push_back(std::make_pair(off, op->getIn(2)->getSize()));
      }
      std::sort(stores.begin(), stores.end());
      pieces.str("");
      for (size_t i = 0; i < stores.size(); ++i) {
        if (i != 0)
          pieces << ',';
        pieces << stores[i].first << ':' << stores[i].second;
      }
    }
    std::cout << "split|case=" << id << "|fn=splitStore|ok=" << (ok ? 1 : 0)
              << "|pieces=" << pieces.str() << '\n';
  };
  {
    Varnode *value = make_value(8); // untyped primitive value
    split_store_gate("array_window_prim", array2_uint4, value);
  }
  {
    Varnode *value = fd.newConstant(8, 0x1122334455667788);
    split_store_gate("array_window_const", array2_uint4, value);
  }
  {
    // iofile partial window: flags + padding hole -> reject (cc:2348-2353)
    Varnode *ptr = make_ptr(ptr_iofile);
    Varnode *value = make_value(8);
    PcodeOp *store = make_store(ptr, value);
    SplitDatatype splitter(fd);
    bool ok = splitter.splitStore(store, partial_iofile8);
    std::cout << "split|case=iofile8_prim|fn=splitStore|ok=" << (ok ? 1 : 0) << '\n';
  }
  {
    // both primitive -> reject (cc:2303)
    Varnode *ptr = make_ptr(ptr_progress);
    PcodeOp *load = fd.newOp(2, Address(code, 0x3800 + 0x10 * unique_counter));
    fd.opSetOpcode(load, CPUI_LOAD);
    fd.newVarnodeOut(16, Address(unique, 0x5800 + 0x10 * unique_counter), load);
    fd.opSetInput(load, fd.newVarnodeSpace(architecture.getSpaceByName("ram")), 0);
    fd.opSetInput(load, ptr, 1);
    fd.opInsertEnd(load, block);
    ++unique_counter;
    SplitDatatype splitter(fd);
    bool ok = splitter.splitLoad(load, undef16);
    std::cout << "split|case=both_primitive|fn=splitLoad|ok=" << (ok ? 1 : 0) << '\n';
    if (!ok)
      fd.opDestroy(load);
  }
  {
    // progress16 partial window with primitive value -> 4 field pieces
    Varnode *ptr = make_ptr(ptr_progress);
    Varnode *value = make_value(16);
    PcodeOp *store = make_store(ptr, value);
    SplitDatatype splitter(fd);
    bool ok = splitter.splitStore(store, partial_progress16);
    std::vector<std::pair<int64_t, int4>> stores;
    if (ok) {
      for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
        PcodeOp *op = *it;
        if (op->code() != CPUI_STORE)
          continue;
        bool rok = false;
        int64_t off = resolveOffset(op->getIn(1), ptr, rok);
        if (rok)
          stores.push_back(std::make_pair(off, op->getIn(2)->getSize()));
      }
      std::sort(stores.begin(), stores.end());
    }
    std::ostringstream pieces;
    pieces << '-';
    if (!stores.empty()) {
      pieces.str("");
      for (size_t i = 0; i < stores.size(); ++i) {
        if (i != 0)
          pieces << ',';
        pieces << stores[i].first << ':' << stores[i].second;
      }
    }
    std::cout << "split|case=progress16_prim|fn=splitStore|ok=" << (ok ? 1 : 0)
              << "|pieces=" << pieces.str() << '\n';
  }

  // apply: file_opaque8_store (FILE* + 8 scalar must NOT be split)
  {
    Varnode *ptr = make_ptr(ptr_file8);
    Varnode *value = make_value(8);
    PcodeOp *store = make_store(ptr, value);
    int64_t before = count_ops();
    int4 ret = split_store_rule.applyOp(store, fd);
    int64_t added = count_ops() - before;
    std::cout << "apply|case=file_opaque8_store|ret=" << ret
              << "|ops_added=" << added << "|orig_kept=" << (op_alive(store) ? 1 : 0)
              << '\n';
  }
  // apply: iofile8_store (window over flags + padding hole must NOT split)
  {
    Varnode *ptr = make_ptr(ptr_iofile);
    Varnode *value = make_value(8);
    PcodeOp *store = make_store(ptr, value);
    int64_t before = count_ops();
    int4 ret = split_store_rule.applyOp(store, fd);
    int64_t added = count_ops() - before;
    std::cout << "apply|case=iofile8_store|ret=" << ret
              << "|ops_added=" << added << "|orig_kept=" << (op_alive(store) ? 1 : 0)
              << '\n';
  }
  // apply: progress16_store (16-byte store -> 4 field stores)
  {
    Varnode *ptr = make_ptr(ptr_progress);
    Varnode *value = make_value(16);
    PcodeOp *store = make_store(ptr, value);
    int4 ret = split_store_rule.applyOp(store, fd);
    std::vector<std::pair<int64_t, int4>> stores; // offset, size
    for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
      PcodeOp *op = *it;
      if (op->code() != CPUI_STORE)
        continue;
      bool ok = false;
      int64_t off = resolveOffset(op->getIn(1), ptr, ok);
      if (ok)
        stores.push_back(std::make_pair(off, op->getIn(2)->getSize()));
    }
    std::sort(stores.begin(), stores.end());
    std::ostringstream list;
    for (size_t i = 0; i < stores.size(); ++i) {
      if (i != 0)
        list << ',';
      list << stores[i].first << ':' << stores[i].second;
    }
    int4 stab = second_round();
    global_second_round_changes += stab;
    std::cout << "apply|case=progress16_store|ret=" << ret
              << "|stores=" << list.str()
              << "|orig_kept=" << (op_alive(store) ? 1 : 0)
              << "|stab=" << stab << '\n';
  }
  // applyload: progress16_load (16-byte load -> 4 field loads)
  {
    Varnode *ptr = make_ptr(ptr_progress);
    PcodeOp *load = fd.newOp(2, Address(code, 0x4800 + 0x10 * unique_counter));
    fd.opSetOpcode(load, CPUI_LOAD);
    fd.newVarnodeOut(16, Address(unique, 0x5000 + 0x10 * unique_counter), load);
    fd.opSetInput(load, fd.newVarnodeSpace(architecture.getSpaceByName("ram")), 0);
    fd.opSetInput(load, ptr, 1);
    fd.opInsertEnd(load, block);
    ++unique_counter;
    int4 ret = split_load_rule.applyOp(load, fd);
    std::vector<std::pair<int64_t, int4>> loads;
    for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
      PcodeOp *op = *it;
      if (op->code() != CPUI_LOAD)
        continue;
      bool ok = false;
      int64_t off = resolveOffset(op->getIn(1), ptr, ok);
      if (ok)
        loads.push_back(std::make_pair(off, op->getOut()->getSize()));
    }
    std::sort(loads.begin(), loads.end());
    std::ostringstream list;
    for (size_t i = 0; i < loads.size(); ++i) {
      if (i != 0)
        list << ',';
      list << loads[i].first << ':' << loads[i].second;
    }
    int4 stab = second_round();
    global_second_round_changes += stab;
    std::cout << "applyload|case=progress16_load|ret=" << ret
              << "|loads=" << list.str()
              << "|orig_gone=" << (op_alive(load) ? 0 : 1)
              << "|stab=" << stab << '\n';
  }
  // apply: progress8_ptrsub_store (store through PTRSUB(root,8))
  {
    Varnode *root = make_ptr(ptr_progress);
    Varnode *field_ptr = make_ptrsub(root, 8);
    field_ptr->updateType(ptr_progress);
    Varnode *value = make_value(8);
    PcodeOp *store = make_store(field_ptr, value);
    int4 ret = split_store_rule.applyOp(store, fd);
    std::vector<std::pair<int64_t, int4>> stores;
    for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
      PcodeOp *op = *it;
      if (op->code() != CPUI_STORE)
        continue;
      bool ok = false;
      int64_t off = resolveOffset(op->getIn(1), root, ok);
      if (ok)
        stores.push_back(std::make_pair(off, op->getIn(2)->getSize()));
    }
    std::sort(stores.begin(), stores.end());
    std::ostringstream list;
    for (size_t i = 0; i < stores.size(); ++i) {
      if (i != 0)
        list << ',';
      list << stores[i].first << ':' << stores[i].second;
    }
    int4 stab = second_round();
    global_second_round_changes += stab;
    std::cout << "apply|case=progress8_ptrsub_store|ret=" << ret
              << "|stores=" << list.str()
              << "|stab=" << stab << '\n';
  }
  // apply: array_window_store (element-pointer non-const -> gate rejects)
  {
    Varnode *ptr = make_ptr(ptr_uint4);
    Varnode *value = make_value(8);
    PcodeOp *store = make_store(ptr, value);
    int64_t before = count_ops();
    int4 ret = split_store_rule.applyOp(store, fd);
    int64_t added = count_ops() - before;
    std::cout << "apply|case=array_window_store|ret=" << ret
              << "|ops_added=" << added << "|orig_kept=" << (op_alive(store) ? 1 : 0)
              << '\n';
  }
  // apply: array_const_store (element-pointer constant -> 2 element stores)
  {
    Varnode *ptr = make_ptr(ptr_uint4);
    Varnode *value = fd.newConstant(8, 0x1122334455667788);
    PcodeOp *store = make_store(ptr, value);
    int4 ret = split_store_rule.applyOp(store, fd);
    struct Rec { int64_t off; int4 size; std::string val; };
    std::vector<Rec> stores;
    for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
      PcodeOp *op = *it;
      if (op->code() != CPUI_STORE)
        continue;
      bool ok = false;
      int64_t off = resolveOffset(op->getIn(1), ptr, ok);
      if (!ok)
        continue;
      const Varnode *val = op->getIn(2);
      if (val->isConstant()) {
        stores.push_back({off, val->getSize(), hex16(val->getOffset() & calc_mask(val->getSize() * 8))});
      } else if (val->isWritten() && val->getDef()->code() == CPUI_SUBPIECE) {
        const Varnode *base = val->getDef()->getIn(0);
        const Varnode *shiftVn = val->getDef()->getIn(1);
        if (base->isConstant() && shiftVn->isConstant()) {
          uintb v = (base->getOffset() >> (shiftVn->getOffset() * 8)) & calc_mask(val->getSize() * 8);
          stores.push_back({off, val->getSize(), hex16(v)});
        }
      }
    }
    std::sort(stores.begin(), stores.end(),
              [](const Rec &a, const Rec &b) { return a.off < b.off; });
    std::ostringstream list;
    for (size_t i = 0; i < stores.size(); ++i) {
      if (i != 0)
        list << ',';
      list << stores[i].off << ':' << stores[i].size << '=' << stores[i].val;
    }
    int4 stab = second_round();
    global_second_round_changes += stab;
    std::cout << "apply|case=array_const_store|ret=" << ret
              << "|stores=" << list.str()
              << "|stab=" << stab << '\n';
  }

  std::cout << "stab|global_changes=" << global_second_round_changes << '\n';
  return 0;
}
