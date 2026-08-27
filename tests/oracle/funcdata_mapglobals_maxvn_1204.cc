// FUNCDATA-MAPGLOBALS-MAXVN-0001 fixture — Funcdata::mapGlobals group
// maxvn carrying (R-MAPGLOBALS REJECT fix-forward discrimination).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Pinned oracle behavior (funcdata_varnode.cc:1653-1719): the inner group
// loop REASSIGNS maxvn on strictly greater size (cc:1685-1686
// `if (vn->getSize() > maxvn->getSize()) maxvn = vn;`), and the group's
// Datatype takes the biggest varnode's high type when it spans exactly
// [addr,endaddr) (cc:1692-1693 `ct = maxvn->getHigh()->getType();`).
// The same-address dual-width persist shape (loc order sorts size
// ascending — varnode.cc:41 — so the 1-byte varnode is the group start)
// is the input class the R-MAPGLOBALS review flagged as latent-UNTESTED:
// the group-start varnode's high type and the max varnode's high type are
// different observables.
//
// Cases (one stdout line each):
//   a_maxvn_type   1B@0x6000 (start, int1) + 8B@0x6000 (maxvn, forced
//                  4-byte uint high type): discovery arm — addSymbol's ct
//                  is the MAX varnode's high type (name base 'u', symbol
//                  type size 4, entry size 4), not the 8-byte span
//                  fallback and not the 1-byte start type.
//   b_entryflip    1B@0x6100 (start, forced 8-byte int high type) + 8B@0x6100
//                  (maxvn, forced 2-byte int high type) with a seeded 4-byte
//                  entry at 0x6100: ct size 2 keeps (addr+ct_size)-1 <=
//                  entry_end-1, so NO inconsistentuse / warningHeader (the
//                  group-start source would read the 8-byte start type and
//                  flip it — the review's entry-arm discrimination). The
//                  entry stays the seeded symbol.
//   c_fallback     8B@0x6200 (start) + 1B@0x6201 (internal, uncovered):
//                  endaddr shrinks to 0x6202 (cc:1684 unconditional),
//                  the maxvn span gate fails, ct = getBase(2,TYPE_UNKNOWN)
//                  — entry size 2, unknown metatype (name not printed:
//                  core-unknown NAMING differs between the fixture type
//                  factory and Rugra's shared factory; only structural
//                  fields are observed).
//   d_nomaxswap    8B@0x6300 (start, uint8) + 8B@0x6300 (equal size, int8):
//                  equal size never swaps maxvn (strictly-greater '>'):
//                  ct = the FIRST (start) varnode's type ('u', size 8).
//   e_multigroup   1B@0x6400 (start) + 8B@0x6400 (maxvn, uint4) + 4B@0x6404
//                  (internal uncovered, discovery arm ignores it): ct =
//                  maxvn's uint4 — same projection as (a) with the extra
//                  trailing member.
//   warn           count of warningheader comments after mapGlobals — 0 in
//                  the aligned state (the buggy span fallback would emit
//                  one from case b).
#include <bits/stdc++.h>

// Test-only access mirrors the house fixture pattern
// (tests/oracle/varnode_copy_symbol_1204.cc): production writes the persist
// bit through the localmap queryProperties channel; the fixture pins the
// varnode flag/type directly to construct the same bank state.
#define private public
#define protected public
#include "architecture.hh"
#include "comment.hh"
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
#undef protected

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
    dummy_register.space = reg;
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
    // Core unknowns use the data-organization spelling (undefinedN) so the
    // mapGlobals span fallback getBase(n,TYPE_UNKNOWN) names identically to
    // Rugra's shared factory; the forced int/uint highs are the observable
    // discriminators (only the first character of a type name is observable
    // through buildVariableName's printNameBase).
    types->setCoreType("undefined1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("undefined2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("undefined4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("undefined8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("int1", 1, TYPE_INT, false);
    types->setCoreType("int2", 2, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
    types->setCoreType("uint4", 4, TYPE_UINT, false);
    types->setCoreType("uint8", 8, TYPE_UINT, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    commentdb = new CommentDatabaseInternal();
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

string metaname(type_metatype meta)
{
  switch (meta) {
  case TYPE_VOID: return "void";
  case TYPE_UNKNOWN: return "unknown";
  case TYPE_INT: return "int";
  case TYPE_UINT: return "uint";
  case TYPE_BOOL: return "bool";
  case TYPE_CODE: return "code";
  case TYPE_FLOAT: return "float";
  case TYPE_PTR: return "ptr";
  case TYPE_ARRAY: return "array";
  case TYPE_STRUCT: return "struct";
  case TYPE_UNION: return "union";
  default: return "other";
  }
}

} // namespace

int main(void)
{
  std::cout << std::unitbuf;
  // libdecomp.cc house pattern (cf. funcdata_assign_high_1204): registers
  // the PrintC capability the base Architecture ctor demands.
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);

  FixtureArchitecture architecture;
  AddrSpace *ram = architecture.translate->getSpaceByName("ram");
  Scope *global_scope = architecture.symboltab->getGlobalScope();

  Funcdata *fd = new Funcdata("mapglobals", "mapglobals",
                              global_scope, Address(ram, 0x5000),
                              (FunctionSymbol *)0, 0x100);
  BlockBasic *block = const_cast<BlockGraph &>(fd->getBasicBlocks()).newBlockBasic(fd);

  // Written persist varnode at (addr,size) with a forced Datatype.
  // cc:1671's group walk only needs written+persist+no-mapentry; the
  // forced type is what maxvn->getHigh()->getType() derives
  // (HighVariable::updateType, variable.cc:400-417, picks the single
  // member's type).
  int pc = 0x5010;
  auto make_persist_out = [&](int4 size, uintb addr,
                              type_metatype meta, int4 tsize) -> Varnode * {
    PcodeOp *op = fd->newOp(1, Address(ram, pc));
    pc += 1;
    fd->opSetOpcode(op, CPUI_COPY);
    Varnode *vn = fd->newVarnodeOut(size, Address(ram, addr), op);
    fd->opSetInput(op, fd->newConstant(size, 0x11), 0);
    fd->opInsertEnd(op, block);
    vn->type = architecture.types->getBase(tsize, meta);
    vn->setFlags(Varnode::persist | Varnode::addrtied);
    return vn;
  };

  Varnode *a1 = make_persist_out(1, 0x6000, TYPE_INT, 1);    // group start
  Varnode *a8 = make_persist_out(8, 0x6000, TYPE_UINT, 4);   // maxvn
  (void)a1; (void)a8;

  Varnode *b1 = make_persist_out(1, 0x6100, TYPE_INT, 8);    // start, 8-byte type
  Varnode *b8 = make_persist_out(8, 0x6100, TYPE_INT, 2);    // maxvn, 2-byte type
  (void)b1; (void)b8;

  Varnode *c8 = make_persist_out(8, 0x6200, TYPE_UINT, 8);   // group start
  Varnode *c1 = make_persist_out(1, 0x6201, TYPE_INT, 1);    // internal
  (void)c8; (void)c1;

  Varnode *d8a = make_persist_out(8, 0x6300, TYPE_UINT, 8);  // start, uint8
  Varnode *d8b = make_persist_out(8, 0x6300, TYPE_INT, 8);   // equal size, int8
  (void)d8a; (void)d8b;

  Varnode *e1 = make_persist_out(1, 0x6400, TYPE_INT, 1);    // group start
  Varnode *e8 = make_persist_out(8, 0x6400, TYPE_UINT, 4);   // maxvn
  Varnode *e4 = make_persist_out(4, 0x6404, TYPE_INT, 4);    // internal
  (void)e1; (void)e8; (void)e4;

  // Channel state AFTER varnode creation (case-b seed + global ownership
  // ranges for discoverScope, database.cc:1353-1366).
  architecture.symboltab->addRange(global_scope, ram, 0, 0xffffffffffffffffULL);
  global_scope->addSymbol("seed_b", architecture.types->getBase(4, TYPE_UINT),
                          Address(ram, 0x6100), Address());

  fd->setHighLevel();
  fd->mapGlobals();

  // Observation helper: the smallest containing entry through the same
  // queryProperties channel mapGlobals used (cc:1701).
  auto describe = [&](uintb addr) -> string {
    uint4 fl = 0;
    SymbolEntry *entry = fd->getScopeLocal()->queryProperties(
        Address(ram, addr), 1, Address(), fl);
    if (entry == (SymbolEntry *)0)
      return "none";
    ostringstream out;
    out << "name=" << entry->getSymbol()->getName()
        << "|size=" << dec << entry->getSize()
        << "|mt=" << metaname(entry->getSymbol()->getType()->getMetatype())
        << "|tsize=" << dec << entry->getSymbol()->getType()->getSize();
    return out.str();
  };

  std::cout << "case=a_maxvn_type|" << describe(0x6000) << "\n";
  std::cout << "case=b_entryflip|" << describe(0x6100) << "\n";
  std::cout << "case=c_fallback|" << describe(0x6200) << "\n";
  std::cout << "case=d_nomaxswap|" << describe(0x6300) << "\n";
  std::cout << "case=e_multigroup|" << describe(0x6400) << "\n";

  int warnings = 0;
  CommentSet::const_iterator iter, enditer;
  iter = architecture.commentdb->beginComment(fd->getAddress());
  enditer = architecture.commentdb->endComment(fd->getAddress());
  for (; iter != enditer; ++iter) {
    if (((*iter)->getType() & Comment::warningheader) != 0)
      warnings += 1;
  }
  std::cout << "case=warn|count=" << dec << warnings << "\n";
  return 0;
}
