// TYPEFACTORY-EXACTPIECE-CALLERS-0001 fixture — C++ side.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Bilateral gate for the four production getExactPiece call sites after the
// canonical TypeFactory migration (each caller must reach the SAME
// Architecture-owned factory; no local clone/subtype substitute):
//
//   entry records    SymbolEntry::getSizedType          database.cc:151-162
//   finalize records HighVariable::finalizeDatatype     variable.cc:551-566
//   sync records     Funcdata::syncVarnodesWithSymbols  funcdata_varnode.cc:938-989
//                    (per-varnode ct via entry->getSizedType cc:957)
//   rule records     RulePieceStructure::applyOp leaf   ruleaction.cc:7665
//                    (data.getArch()->types->getExactPiece)
//
// Every type comes from the production TypeFactory of the synthetic
// Architecture (alignment map decoded, core undefined1/2/4/8 cached).
// Pointer/Arc addresses are never serialized: identity is projected as
// equality bits (same_symbol/same_expected/repeat_same/direct_same/
// same_before) within one process. Shapes are metatype+size strings with
// partial parent/offset and array element projections, matching the Rust
// twin's grammar byte for byte.
//
// Test-only private writes (precedent funcdata_assign_high_1204.cc):
// HighVariable::symbol/symboloffset are seeded directly because Rugra's
// HighVariable is fixture-constructed the same way; the function under test,
// finalizeDatatype, is the production body.

#include <bits/stdc++.h>
#define private public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "op.hh"
#include "ruleaction.hh"
#include "type.hh"
#include "typeop.hh"
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
  if (const TypePartialUnion *part = dynamic_cast<const TypePartialUnion *>(ct)) {
    out << "partial_union:" << part->getSize()
        << '@' << part->getOffset()
        << "/parent=" << shortShape(part->getParentUnion());
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

int bit(bool value) { return value ? 1 : 0; }

} // anonymous namespace

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureArchitecture architecture;
  TypeFactory *types = architecture.types;
  AddrSpace *stack = architecture.getSpaceByName("stack");
  AddrSpace *unique = architecture.getUniqueSpace();

  // ---- shared production type graph --------------------------------------
  Datatype *uint4 = types->getBase(4, TYPE_UINT);
  Datatype *uint8 = types->getBase(8, TYPE_UINT);
  Datatype *undef4 = types->getBase(4, TYPE_UNKNOWN);

  TypeStruct *inner = types->getTypeStruct("caller_inner8");
  {
    std::vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "lo", uint4));
    fields.push_back(TypeField(1, 4, "hi", uint4));
    types->setFields(fields, inner, 8, 4, 0);
  }
  TypeStruct *outer = types->getTypeStruct("caller_outer24");
  {
    std::vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "head", uint4));
    fields.push_back(TypeField(1, 8, "inner", inner));
    fields.push_back(TypeField(2, 16, "tail", uint8));
    types->setFields(fields, outer, 24, 8, 0);
  }
  TypeUnion *union8 = types->getTypeUnion("caller_union8");
  {
    std::vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "wide", uint8));
    fields.push_back(TypeField(1, 0, "narrow", uint4));
    types->setFields(fields, union8, 8, 8, 0);
  }
  TypeArray *uint4_array3 = types->getTypeArray(3, uint4);

  Scope *parent = architecture.symboltab->getGlobalScope();
  Funcdata fd("fixture", "fixture", parent, Address(architecture.getDefaultCodeSpace(), 0x1000),
              (FunctionSymbol *)0, 0x100);
  ScopeLocal *lm = fd.getScopeLocal();

  // All Varnodes are created BEFORE any symbol is mapped so creation-time
  // queryProperties sees an empty scope on both sides (newVarnode
  // funcdata_varnode.cc:148-169 would otherwise pre-apply entry types).
  // sync varnodes are written (def COPY from a constant) because
  // syncVarnodesWithSymbol skips free varnodes (cc:1073); finalize varnodes
  // stay free (only instances[0]->getSize() is read, variable.cc:559).
  Varnode *fin_vn[5];
  const int4 fin_size[5] = {24, 8, 4, 2, 4};
  for (int4 i = 0; i < 5; ++i)
    fin_vn[i] = fd.newVarnode(fin_size[i], Address(stack, 0x3000 + 0x10 * i));
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);
  Varnode *sync_vn[5];
  const int4 sync_size[5] = {8, 24, 4, 4, 8};
  const uintb sync_off[5] = {0x2008, 0x2000, 0x2002, 0x2400, 0x2500};
  for (int4 i = 0; i < 5; ++i) {
    PcodeOp *def = fd.newOp(1, Address(architecture.getDefaultCodeSpace(), 0x2800 + 0x10 * i));
    fd.opSetOpcode(def, CPUI_COPY);
    sync_vn[i] = fd.newVarnodeOut(sync_size[i], Address(stack, sync_off[i]), def);
    fd.opSetInput(def, fd.newConstant(sync_size[i], 0x100 + i), 0);
    fd.opInsertEnd(def, block);
  }

  // ---- entry: SymbolEntry::getSizedType (database.cc:151-162) -----------
  SymbolEntry *entry_outer =
      lm->addSymbol("entry_outer", outer, Address(stack, 0x1000), Address());
  SymbolEntry *entry_union =
      lm->addSymbol("entry_union", union8, Address(stack, 0x1100), Address());
  SymbolEntry *entry_array =
      lm->addSymbol("entry_array", uint4_array3, Address(stack, 0x1200), Address());

  struct EntryCase {
    const char *id;
    SymbolEntry *entry;
    uintb addr;
    int4 sz;
    Datatype *expected; // null means "expect null result"
    bool has_direct;
  };
  const EntryCase entry_cases[] = {
    {"entry_whole", entry_outer, 0x1000, 24, outer, false},
    {"entry_nested", entry_outer, 0x1008, 8, inner, false},
    {"entry_leaf", entry_outer, 0x100c, 4, uint4, false},
    {"entry_cross_partial", entry_outer, 0x1002, 4, (Datatype *)0, true},
    {"entry_wrong_size_partial", entry_outer, 0x1000, 16, (Datatype *)0, true},
    {"entry_beyond", entry_outer, 0x1016, 16, (Datatype *)0, false},
    {"entry_union_partial", entry_union, 0x1101, 4, (Datatype *)0, true},
    {"entry_array_elem", entry_array, 0x1204, 4, uint4, false},
  };
  for (int4 i = 0; i < 8; ++i) {
    const EntryCase &c = entry_cases[i];
    Datatype *first = c.entry->getSizedType(Address(stack, c.addr), c.sz);
    Datatype *repeat = c.entry->getSizedType(Address(stack, c.addr), c.sz);
    Datatype *direct = (Datatype *)0;
    if (c.id == std::string("entry_cross_partial"))
      direct = types->getTypePartialStruct(outer, 2, 4);
    else if (c.id == std::string("entry_wrong_size_partial"))
      direct = types->getTypePartialStruct(outer, 0, 16);
    else if (c.id == std::string("entry_union_partial"))
      direct = types->getTypePartialUnion(union8, 1, 4);
    Datatype *expected = c.expected;
    if (c.has_direct)
      expected = direct;
    std::cout << "entry|case=" << c.id
              << "|off=" << std::dec << (int4)(c.addr - c.entry->getAddr().getOffset())
              << "|sz=" << c.sz
              << "|result=" << shape(first)
              << "|same_symbol=" << bit(first == c.entry->getSymbol()->getType())
              << "|same_expected=" << bit(first == expected)
              << "|repeat_same=" << bit(first == repeat)
              << "|direct_same=";
    if (c.has_direct)
      std::cout << bit(first == direct);
    else
      std::cout << "na";
    std::cout << '\n';
  }

  // ---- finalize: HighVariable::finalizeDatatype (variable.cc:551-566) ---
  Symbol *sym_outer = entry_outer->getSymbol();
  Symbol *sym_undef = lm->addSymbol("fin_undef", undef4, Address(stack, 0x1300), Address())
                          ->getSymbol();
  struct FinalizeCase {
    const char *id;
    Symbol *sym;
    int4 offset;
    int4 vn_index;
    bool expect_finalized;
  };
  const FinalizeCase fin_cases[] = {
    {"finalize_whole", sym_outer, -1, 0, true},
    {"finalize_nested", sym_outer, 8, 1, true},
    {"finalize_partial", sym_outer, 2, 2, true},
    {"finalize_null", sym_outer, 9, 3, false},
    {"finalize_unknown", sym_undef, 0, 4, false},
  };
  for (int4 i = 0; i < 5; ++i) {
    const FinalizeCase &c = fin_cases[i];
    HighVariable *high = new HighVariable(fin_vn[c.vn_index]);
    high->symbol = c.sym;      // test-only seed (production path is
    high->symboloffset = c.offset; // setSymbolEntry; same fields, cc:555-556)
    const Datatype *before = high->type;
    high->finalizeDatatype(types);
    const Datatype *after = high->type;
    const Datatype *expected = c.expect_finalized ? (const Datatype *)0 : before;
    if (std::string(c.id) == "finalize_whole")
      expected = outer;
    else if (std::string(c.id) == "finalize_nested")
      expected = inner;
    else if (std::string(c.id) == "finalize_partial")
      expected = types->getTypePartialStruct(outer, 2, 4);
    std::cout << "finalize|case=" << c.id
              << "|off=" << c.offset
              << "|sz=" << fin_size[c.vn_index]
              << "|finalized="
              << bit((high->highflags & HighVariable::type_finalized) != 0)
              << "|same_before=" << bit(after == before)
              << "|same_expected=" << bit(after == expected)
              << '\n';
  }

  // ---- sync: Funcdata::syncVarnodesWithSymbols (funcdata_varnode.cc:938-989)
  const Datatype *sync_before[5];
  for (int4 i = 0; i < 5; ++i)
    sync_before[i] = sync_vn[i]->getType();
  lm->addSymbol("sync_outer", outer, Address(stack, 0x2000), Address());
  lm->addSymbol("sync_unk", undef4, Address(stack, 0x2400), Address());
  lm->addSymbol("sync_small", uint4, Address(stack, 0x2500), Address());
  {
    Symbol *s1 = lm->findOverlap(Address(stack, 0x2000), 24)->getSymbol();
    lm->setAttribute(s1, Varnode::typelock);
    Symbol *s2 = lm->findOverlap(Address(stack, 0x2400), 4)->getSymbol();
    lm->setAttribute(s2, Varnode::typelock);
    Symbol *s3 = lm->findOverlap(Address(stack, 0x2500), 4)->getSymbol();
    lm->setAttribute(s3, Varnode::typelock);
  }
  bool updated = fd.syncVarnodesWithSymbols(lm, true, false);
  struct SyncCase {
    const char *id;
    int4 vn_index;
    Datatype *expected; // per-case; null expectation encoded as "before"
  };
  const SyncCase sync_cases[] = {
    {"sync_nested", 0, inner},
    {"sync_whole", 1, outer},
    {"sync_partial", 2, (Datatype *)0}, // filled below via direct construction
    {"sync_unknown_drop", 3, (Datatype *)0},
    {"sync_small_symbol", 4, (Datatype *)0},
  };
  Datatype *sync_partial_direct = types->getTypePartialStruct(outer, 2, 4);
  for (int4 i = 0; i < 5; ++i) {
    const SyncCase &c = sync_cases[i];
    Varnode *vn = sync_vn[c.vn_index];
    const Datatype *after = vn->getType();
    const Datatype *expected = c.expected;
    if (std::string(c.id) == "sync_partial")
      expected = sync_partial_direct;
    else if (expected == (Datatype *)0)
      expected = sync_before[c.vn_index];
    std::cout << "sync|case=" << c.id
              << "|off=" << std::dec << sync_off[c.vn_index]
              << "|sz=" << sync_size[c.vn_index]
              << "|updated=" << bit(updated)
              << "|same_before=" << bit(after == sync_before[c.vn_index])
              << "|same_expected=" << bit(after == expected)
              << "|mapped=" << bit((vn->getFlags() & Varnode::mapped) != 0)
              << "|addrtied=" << bit((vn->getFlags() & Varnode::addrtied) != 0)
              << "|typelock=" << bit((vn->getFlags() & Varnode::typelock) != 0)
              << '\n';
  }

  // ---- rule: RulePieceStructure::applyOp leaf typing (ruleaction.cc:7665)
  try {
    // Leaves are written by COPY defs: a free varnode cannot take a second
    // reader (Varnode::addDescend varnode.cc:334-336) and the rule inserts a
    // COPY that reads each leaf next to its original reader.
    PcodeOp *def0 = fd.newOp(1, Address(architecture.getDefaultCodeSpace(), 0x3050));
    fd.opSetOpcode(def0, CPUI_COPY);
    PcodeOp *def1 = fd.newOp(1, Address(architecture.getDefaultCodeSpace(), 0x3060));
    fd.opSetOpcode(def1, CPUI_COPY);
    PcodeOp *def2 = fd.newOp(1, Address(architecture.getDefaultCodeSpace(), 0x3070));
    fd.opSetOpcode(def2, CPUI_COPY);
    PcodeOp *op_r = fd.newOp(2, Address(architecture.getDefaultCodeSpace(), 0x3000));
    fd.opSetOpcode(op_r, CPUI_PIECE);
    Varnode *vn_o = fd.newVarnodeOut(24, Address(unique, 0x5000), op_r);
    vn_o->updateType(outer);
    Varnode *vn_l0 = fd.newVarnodeOut(8, Address(unique, 0x6010), def0);
    fd.opSetInput(def0, fd.newConstant(8, 0x11), 0);
    fd.opSetInput(op_r, vn_l0, 1); // least-significant leaf, typeOffset 0
    PcodeOp *op_p = fd.newOp(2, Address(architecture.getDefaultCodeSpace(), 0x3010));
    fd.opSetOpcode(op_p, CPUI_PIECE);
    Varnode *vn_m = fd.newVarnodeOut(16, Address(unique, 0x5100), op_p);
    fd.opSetInput(op_r, vn_m, 0); // most-significant piece, typeOffset 8
    Varnode *vn_l1 = fd.newVarnodeOut(8, Address(unique, 0x6020), def1);
    fd.opSetInput(def1, fd.newConstant(8, 0x22), 0);
    fd.opSetInput(op_p, vn_l1, 1); // low of M, typeOffset 8
    Varnode *vn_l2 = fd.newVarnodeOut(8, Address(unique, 0x6030), def2);
    fd.opSetInput(def2, fd.newConstant(8, 0x33), 0);
    fd.opSetInput(op_p, vn_l2, 0); // high of M, typeOffset 16
    fd.opInsertEnd(def0, block);
    fd.opInsertEnd(def1, block);
    fd.opInsertEnd(def2, block);
    fd.opInsertEnd(op_r, block);
    fd.opInsertEnd(op_p, block);
  RulePieceStructure piece_rule("analysis");
  int4 rc = piece_rule.applyOp(op_r, fd);
  Datatype *rule_low_partial_direct = types->getTypePartialStruct(outer, 0, 8);
  Varnode *r_low = op_r->getIn(1);
  Varnode *r_mid = op_r->getIn(0);
  Varnode *p_low = op_p->getIn(1);
  Varnode *p_high = op_p->getIn(0);
  const uintb base = vn_o->getAddr().getOffset();
  std::cout << "rule|case=rule_low_partial"
            << "|applied=" << bit(rc != 0)
            << "|low_result=" << shape(r_low->getType())
            << "|low_same_direct=" << bit(r_low->getType() == rule_low_partial_direct)
            << "|low_def="
            << ((r_low->getDef() != (PcodeOp *)0 && r_low->getDef()->code() == CPUI_COPY)
                    ? "COPY"
                    : "OTHER")
            << "|low_addr_delta=" << std::dec << (int4)(r_low->getAddr().getOffset() - base)
            << "|low_proto=" << bit(r_low->isProtoPartial())
            << '\n';
  std::cout << "rule|case=rule_leaf_identity"
            << "|inner_result=" << shape(p_low->getType())
            << "|inner_same=" << bit(p_low->getType() == inner)
            << "|tail_result=" << shape(p_high->getType())
            << "|tail_same=" << bit(p_high->getType() == uint8)
            << "|mid_addr_delta=" << std::dec << (int4)(r_mid->getAddr().getOffset() - base)
            << "|mid_size=" << r_mid->getSize()
            << '\n';
  } catch (const LowlevelError &error) {
    std::cerr << "rule section LowlevelError: " << error.explain << '\n';
    return 1;
  }
  return 0;
}
