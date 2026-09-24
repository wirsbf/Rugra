/*
 * VARMAP-GATHEROPEN-GUARD-0001: locked Ghidra 12.0.4 authoritative oracle —
 * MapState::addGuard (varmap.cc:1003), MapState::gatherSymbols (varmap.cc:1044
 * / 1269), ScopeLocal::annotateRawStackPtr (varmap.cc:386),
 * ScopeLocal::checkUnaliasedReturn (varmap.cc:414), the
 * clearUnlockedCategory(function_parameter)/clearCategory(fake_input) pass
 * gates (varmap.cc:1275-1276) and AliasChecker::deriveBoundaries
 * (varmap.cc:633, wired through gather, varmap.cc:692/1214).
 *
 * The fixture drives a real Funcdata + ScopeLocal whose prototype model is
 * decoded through the production XML path with NO <localrange>/<paramrange>
 * elements, so the model carries the default windows of a negative-growing
 * 8-byte stack: locals = [getHighest()-999999, getHighest()], params =
 * [0,511] — deriveBoundaries therefore sets localBoundary = 511 (the
 * paramrange last), NOT the 0x1000000 model-less default.  Everything
 * downstream is the production call sequence: restructureVarnode(true)
 * (gatherVarnodes → gatherOpen incl. checker.gather + addGuard →
 * gatherSymbols → restructure → category clears → fakeInputSymbols →
 * sortAlias → markUnaliased → checkUnaliasedReturn → annotateRawStackPtr).
 */

#include <bits/stdc++.h>

// Test-only access is required to construct LoadGuard records (LoadGuard's
// data members and set() are implicitly private behind `friend class
// Heritage`), to reach Funcdata::heritage (implicitly private before the
// first public label), and to read the AliasChecker boundary members — the
// Rust comparand constructs the same records through public fields and a
// public observation accessor.  The whole include block runs in a
// class->struct window (no `template <class`/`enum class` exists anywhere in
// the decompiler headers — verified), turning implicitly-private members
// public; the class-key mismatch with later class-key uses is legal C++.
#define private public
#define protected public
#define class struct
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "fspec.hh"
#include "heritage.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varmap.hh"
#include "varnode.hh"
#undef class
#undef private
#undef protected

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
  std::string getRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
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
    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("int", 4, TYPE_INT, false);
    types->setCoreType("long", 8, TYPE_INT, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"gg_default\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const std::string &) const override {}
};

/// Canonical cross-fixture type projection.  The oracle factory spells its
/// unknown bases "xunknownN" while the Rust comparand's factory spells them
/// "undefinedN" — both TYPE_UNKNOWN of the same width — so the untyped-arm
/// cases (7/8) print metatype+align width, never getName().
static std::string type_token(const Datatype *ct)
{
  if (ct == (const Datatype *)0) return "null";
  if (ct->getMetatype() == TYPE_UNKNOWN)
    return "unk" + std::to_string(ct->getAlignSize());
  return std::string("other:") + ct->getName();
}

/// Per-case harness mirroring varmap_localwindow_1204.cc: a fresh Funcdata
/// whose prototype carries the default-window model, plus a real ScopeLocal.
class GatherOpenScope {
public:
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  AddrSpace *stack;
  Funcdata fd;
  ScopeLocal scope;
  TypeFactory *types;
  BlockBasic *blk;

  GatherOpenScope(FixtureArchitecture &a, const std::string &name, uintb fd_off)
    : arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), stack(a.getSpace(5)),
      fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), fd_off),
         (FunctionSymbol *)0, 0x20),
      scope(0x102, a.getSpace(5), &fd, &a), types(a.types),
      blk(fd.bblocks.newBlockBasic(&fd)) {
    fd.getFuncProto().setModel(arch.protoModels["gg_default"]);
    scope.resetLocalWindow();
  }

  /// PcodeOpBank::create starts ops DEAD (op.cc:947 `op->setFlag
  /// PcodeOp::dead`); guard validity (`LoadGuard::isValid`, heritage.hh:169),
  /// getFirstReturnOp and newOpBefore all require live, inserted ops.
  void insert_op(PcodeOp *op) {
    fd.opInsert(op, blk, blk->endOp());
  }

  Datatype *int_t(void) { return types->getBase(4, TYPE_INT); }
  Datatype *char_t(void) { return types->getBase(1, TYPE_INT); }
  Datatype *long_t(void) { return types->getBase(8, TYPE_INT); }
  Datatype *int_ptr(void) { return types->getTypePointer(8, int_t(), 0); }
  Datatype *char_ptr(void) { return types->getTypePointer(8, char_t(), 0); }

  Varnode *stack_copy(uintb off, Datatype *ct, uintb pc) {
    PcodeOp *op = fd.newOp(1, Address(ram, pc));
    fd.opSetOpcode(op, CPUI_COPY);
    fd.opSetInput(op, fd.newConstant(ct->getSize(), 0x1234), 0);
    Varnode *out = fd.newVarnode(ct->getSize(), Address(stack, off), ct);
    fd.opSetOutput(op, out);
    insert_op(op);
    return out;
  }

  /// The input stack pointer Varnode (register:0, the translate-registered
  /// spacebase pointer).
  Varnode *spacebase_input(void) {
    Varnode *sp = fd.newVarnode(8, Address(reg, 0));
    fd.setInputVarnode(sp);
    return sp;
  }

  /// sp + delta, consumed non-additively (INT_EQUAL) so the sum is an
  /// AliasChecker additive root: the alias source for positive offsets.
  Varnode *spacebase_pointer_add(uintb delta, uintb pc) {
    Varnode *sp = spacebase_input();
    PcodeOp *add = fd.newOp(2, Address(ram, pc));
    fd.opSetOpcode(add, CPUI_INT_ADD);
    fd.opSetInput(add, sp, 0);
    fd.opSetInput(add, fd.newConstant(8, delta), 1);
    Varnode *ptr = fd.newUniqueOut(8, add);
    fd.opSetOutput(add, ptr);
    PcodeOp *eq = fd.newOp(2, Address(ram, pc + 8));
    fd.opSetOpcode(eq, CPUI_INT_EQUAL);
    fd.opSetInput(eq, ptr, 0);
    fd.opSetInput(eq, fd.newUnique(8), 1);
    insert_op(add);
    insert_op(eq);
    return ptr;
  }

  /// A raw non-additive read of the stack pointer itself (zero-offset
  /// reference) — the annotateRawStackPtr trigger (alias[0] == 0).
  PcodeOp *raw_stack_ptr_use(uintb pc) {
    Varnode *sp = spacebase_input();
    PcodeOp *eq = fd.newOp(2, Address(ram, pc));
    fd.opSetOpcode(eq, CPUI_INT_EQUAL);
    fd.opSetInput(eq, sp, 0);
    fd.opSetInput(eq, fd.newUnique(8), 1);
    insert_op(eq);
    return eq;
  }

  /// A guarded LOAD whose address input is typed `pt`, returning the op so a
  /// LoadGuard record can reference it.
  PcodeOp *guarded_load(Datatype *pt, int4 outsize, uintb pc) {
    PcodeOp *op = fd.newOp(2, Address(ram, pc));
    fd.opSetOpcode(op, CPUI_LOAD);
    fd.opSetInput(op, fd.newConstant(8, 0), 0);
    Varnode *addr = fd.newUnique(8);
    addr->updateType(types->getTypePointer(8, pt, 0));
    fd.opSetInput(op, addr, 1);
    fd.newUniqueOut(outsize, op);
    insert_op(op);
    return op;
  }

  /// A guarded STORE whose address input is typed `pt`.
  PcodeOp *guarded_store(Datatype *pt, int4 valsize, uintb pc) {
    PcodeOp *op = fd.newOp(3, Address(ram, pc));
    fd.opSetOpcode(op, CPUI_STORE);
    fd.opSetInput(op, fd.newConstant(8, 0), 0);
    Varnode *addr = fd.newUnique(8);
    addr->updateType(types->getTypePointer(8, pt, 0));
    fd.opSetInput(op, addr, 1);
    fd.opSetInput(op, fd.newConstant(valsize, 0x41), 2);
    insert_op(op);
    return op;
  }

  /// A guarded LOAD whose address input is deliberately UNTYPED:
  /// newUnique installs the factory's getBase(8,TYPE_UNKNOWN) and no
  /// updateType overrides it (funcdata_varnode.cc:83-93) — the oracle form
  /// of the Rust comparand's v_type=None address varnode (the addGuard
  /// None-ct branch).  getTypeReadFacing (varnode.cc:639-645) hands that
  /// unknown base to addGuard verbatim.
  PcodeOp *untyped_load(int4 outsize, uintb pc) {
    PcodeOp *op = fd.newOp(2, Address(ram, pc));
    fd.opSetOpcode(op, CPUI_LOAD);
    fd.opSetInput(op, fd.newConstant(8, 0), 0);
    Varnode *addr = fd.newUnique(8);
    fd.opSetInput(op, addr, 1);
    fd.newUniqueOut(outsize, op);
    insert_op(op);
    return op;
  }

  /// A guarded STORE whose address input is deliberately UNTYPED.
  PcodeOp *untyped_store(int4 valsize, uintb pc) {
    PcodeOp *op = fd.newOp(3, Address(ram, pc));
    fd.opSetOpcode(op, CPUI_STORE);
    fd.opSetInput(op, fd.newConstant(8, 0), 0);
    Varnode *addr = fd.newUnique(8);
    fd.opSetInput(op, addr, 1);
    fd.opSetInput(op, fd.newConstant(valsize, 0x41), 2);
    insert_op(op);
    return op;
  }

  /// Append a LoadGuard record for `op` (the shape Heritage's guardLoads/
  /// guardStores leave behind, heritage.hh:159-161 `set`).
  void add_guard_record(PcodeOp *op, int4 step, uintb minimum, uintb maximum,
                        bool range_locked, bool is_store) {
    LoadGuard guard;
    guard.set(op, stack, 0);
    guard.step = step;
    guard.minimumOffset = minimum;
    guard.maximumOffset = maximum;
    guard.analysisState = range_locked ? 2 : 1;
    if (is_store)
      fd.heritage.storeGuard.push_back(guard);
    else
      fd.heritage.loadGuard.push_back(guard);
  }

  /// Install a Symbol with explicit lock flags and category through the
  /// production addSymbol + setCategory path (the shape locked DWARF/localdb
  /// symbols present before restructureVarnode runs).
  Symbol *install_symbol(const std::string &name, Datatype *ct, uintb off,
                         bool typelock, bool namelock, int4 cat) {
    Symbol *sym = scope.addSymbol(name, ct, Address(stack, off), Address())->getSymbol();
    if (typelock) sym->flags |= Varnode::typelock;
    if (namelock) sym->flags |= Varnode::namelock;
    if (cat >= 0) scope.setCategory(sym, cat, scope.getCategorySize(cat));
    return sym;
  }

  /// A RETURN op passing `vn` back as the return value (RETURN in(1)).
  PcodeOp *return_op(Varnode *vn, uintb pc) {
    PcodeOp *op = fd.newOp(2, Address(ram, pc));
    fd.opSetOpcode(op, CPUI_RETURN);
    fd.opSetInput(op, fd.newConstant(8, 0), 0);
    fd.opSetInput(op, vn, 1);
    insert_op(op);
    return op;
  }

  /// Render the scope's created symbols as `start:size:typename` in mapping
  /// order (the same projection as varmap_localwindow_1204).
  std::string symbols_text(void) {
    std::ostringstream out;
    bool first = true;
    MapIterator iter;
    for (iter = scope.begin(); iter != scope.end(); ++iter) {
      const SymbolEntry *entry = *iter;
      if (!first) out << ';';
      first = false;
      Datatype *ct = entry->getSymbol()->getType();
      out << hex << entry->getAddr().getOffset() << ':' << dec << entry->getSize()
          << ':';
      if (ct->getMetatype() == TYPE_ARRAY)
        out << ((TypeArray *)ct)->getBase()->getName() << '['
            << ((TypeArray *)ct)->numElements() << ']';
      else
        out << ct->getName();
    }
    return out.str();
  }

  /// Render the scope's symbol NAMES in mapping order (typelocked-name
  /// survival + category-clear evidence).
  std::string symbol_names_text(void) {
    std::ostringstream out;
    bool first = true;
    MapIterator iter;
    for (iter = scope.begin(); iter != scope.end(); ++iter) {
      if (!first) out << ';';
      first = false;
      out << (*iter)->getSymbol()->getName();
    }
    return out.str();
  }

  /// Render the scope's symbols with canonical type tokens — the
  /// untyped-arm comparand projection `start:size:unkA[num]` (element token
  /// then element count for arrays).
  std::string symbols_token_text(void) {
    std::ostringstream out;
    bool first = true;
    MapIterator iter;
    for (iter = scope.begin(); iter != scope.end(); ++iter) {
      const SymbolEntry *entry = *iter;
      if (!first) out << ';';
      first = false;
      Datatype *ct = entry->getSymbol()->getType();
      out << hex << entry->getAddr().getOffset() << ':' << dec << entry->getSize()
          << ':';
      if (ct->getMetatype() == TYPE_ARRAY)
        out << type_token(((TypeArray *)ct)->getBase()) << '['
            << ((TypeArray *)ct)->numElements() << ']';
      else
        out << type_token(ct);
    }
    return out.str();
  }

  /// Render a RangeList as `first-last` hex pairs, ';'-joined, in tree order.
  static std::string ranges_text(const RangeList &rlist) {
    std::ostringstream out;
    bool first = true;
    set<Range>::const_iterator iter;
    for (iter = rlist.begin(); iter != rlist.end(); ++iter) {
      if (!first) out << ';';
      first = false;
      out << hex << (*iter).getFirst() << '-' << (*iter).getLast();
    }
    return out.str();
  }
};

/// Case 1: addGuard (varmap.cc:1003-1039).  Two intersecting open hints at
/// sp-0x20 — a range-locked LOAD guard (minItems = 0x20/4-1 = 7) and an
/// unanalyzed LOAD guard (minItems = 3) — merge through RangeHint::absorb so
/// the range lock's (highind+1)*size = 32 wins; a STORE guard at sp-0x40
/// extends up to the merged entry (char[32]); an out-size>step LOAD guard
/// between them is rejected (varmap.cc:1020-1023) and leaves no trace.
static void run_guard_open_hints(FixtureArchitecture &arch)
{
  GatherOpenScope t(arch, "guard_open_hints", 0xa000);
  PcodeOp *locked = t.guarded_load(t.int_t(), 4, 0x2000);
  t.add_guard_record(locked, 4, 0xffffffffffffffe0UL, 0xffffffffffffffffUL, true, false);
  PcodeOp *unanalyzed = t.guarded_load(t.int_t(), 4, 0x2010);
  t.add_guard_record(unanalyzed, 4, 0xffffffffffffffe0UL, 0xffffffffffffffffUL, false, false);
  PcodeOp *store = t.guarded_store(t.char_t(), 1, 0x2020);
  t.add_guard_record(store, 1, 0xffffffffffffffc0UL, 0xffffffffffffffffUL, false, true);
  PcodeOp *rejected = t.guarded_load(t.int_t(), 8, 0x2030);
  t.add_guard_record(rejected, 4, 0xfffffffffffffff8UL, 0xffffffffffffffffUL, true, false);
  t.scope.restructureVarnode(true);
  std::cout << "case=guard_open_hints|symbols=[" << t.symbols_text() << ']'
            << '\n';
}

/// Case 2: gatherSymbols (varmap.cc:1269/1044-1059) — the typelocked symbol
/// re-feed.  A name-and-type-locked long at sp-0x30 and a plain written int
/// at sp-0x28 (intersecting the locked entry's extent from the varnode side)
/// restructure so that the locked symbol keeps its name and type.
static void run_gather_symbols_reinput(FixtureArchitecture &arch)
{
  GatherOpenScope t(arch, "gather_symbols_reinput", 0xa100);
  t.install_symbol("locked_local", t.long_t(), 0xffffffffffffffd0UL, true, true, -1);
  t.stack_copy(0xffffffffffffffd0UL, t.long_t(), 0x2100);
  t.stack_copy(0xffffffffffffffc0UL, t.int_t(), 0x2108);
  t.scope.restructureVarnode(true);
  std::cout << "case=gather_symbols_reinput|symbols=[" << t.symbols_text()
            << "]|names=[" << t.symbol_names_text() << ']' << '\n';
}

/// Case 3: the restructureVarnode pass gates (varmap.cc:1275-1276) — an
/// unlocked function_parameter symbol and any fake_input symbol are dropped
/// before fakeInputSymbols rebuilds; the type-and-name-locked parameter
/// symbol survives with its name.
static void run_category_clears(FixtureArchitecture &arch)
{
  GatherOpenScope t(arch, "category_clears", 0xa200);
  t.install_symbol("unlocked_param", t.int_t(), 0x10, false, false,
                   Symbol::function_parameter);
  t.install_symbol("locked_param", t.int_t(), 0x20, true, true,
                   Symbol::function_parameter);
  t.install_symbol("old_fake", t.int_t(), 0x30, false, false,
                   Symbol::fake_input);
  t.scope.restructureVarnode(true);
  std::cout << "case=category_clears|names=[" << t.symbol_names_text() << ']'
            << '\n';
}

/// Case 4: checkUnaliasedReturn (varmap.cc:414-428).  A RETURN whose value
/// lives in the stack space at 0x30: with the nearest alias at 0x10 (below
/// the storage) the return slot is marked unmapped — the union range tree
/// loses [0x30,0x37]; with an alias at 0x34 reaching INTO the storage the
/// tree is untouched.
static void run_check_unaliased_return(FixtureArchitecture &arch)
{
  GatherOpenScope t(arch, "check_unaliased_return", 0xa300);
  Varnode *retvn = t.stack_copy(0x30, t.long_t(), 0x2200);
  t.spacebase_pointer_add(0x10, 0x2210);
  t.return_op(retvn, 0x2220);
  t.scope.restructureVarnode(true);
  std::string marked = GatherOpenScope::ranges_text(t.scope.getRangeTree());

  GatherOpenScope t2(arch, "check_unaliased_return_aliased", 0xa400);
  Varnode *retvn2 = t2.stack_copy(0x30, t2.long_t(), 0x2300);
  t2.spacebase_pointer_add(0x34, 0x2310);
  t2.return_op(retvn2, 0x2320);
  t2.scope.restructureVarnode(true);
  std::string unmarked = GatherOpenScope::ranges_text(t2.scope.getRangeTree());

  std::cout << "case=check_unaliased_return|marked=[" << marked
            << "]|unmarked=[" << unmarked << ']' << '\n';
}

/// Case 5: annotateRawStackPtr (varmap.cc:386-408).  A raw non-additive read
/// of the stack pointer (zero-offset reference, alias[0] == 0) after type
/// recovery has started is rewired through a placeholder PTRSUB(sp,#0).
static void run_annotate_raw_stack_ptr(FixtureArchitecture &arch)
{
  GatherOpenScope t(arch, "annotate_raw_stack_ptr", 0xa500);
  t.fd.startTypeRecovery();
  PcodeOp *eq = t.raw_stack_ptr_use(0x2400);
  t.stack_copy(0xfffffffffffffff8UL, t.long_t(), 0x2410);
  t.scope.restructureVarnode(true);
  Varnode *in0 = eq->getIn(0);
  std::ostringstream out;
  if (in0->isWritten() && in0->getDef()->code() == CPUI_PTRSUB) {
    PcodeOp *ptrsub = in0->getDef();
    out << "ptrsub:" << dec << ptrsub->getIn(1)->getOffset();
  } else {
    out << "none";
  }
  std::cout << "case=annotate_raw_stack_ptr|def=" << out.str() << '\n';
}

/// Case 6: AliasChecker::deriveBoundaries through gather (varmap.cc:692-704,
/// 633-655).  With the default-window model attached, localBoundary =
/// paramrange last = 511 (not the 0x1000000 model-less default); alias bases
/// at +0x200 and +0x300 (above the parameter window, in the old dead zone
/// [511,0x1000000)) shrink aliasBoundary, and hasLocalAlias flips at the
/// window edge.
static void run_derive_boundaries(FixtureArchitecture &arch)
{
  GatherOpenScope t(arch, "derive_boundaries", 0xa600);
  t.spacebase_pointer_add(0x200, 0x2500);
  t.spacebase_pointer_add(0x300, 0x2520);
  AliasChecker checker;
  checker.gather(&t.fd, t.stack, false);
  Varnode *probe_low = t.fd.newVarnode(8, Address(t.stack, 0x1ff));
  Varnode *probe_edge = t.fd.newVarnode(8, Address(t.stack, 0x200));
  Varnode *probe_deep = t.fd.newVarnode(8, Address(t.stack, 0xffffffffffff8000UL));
  std::ostringstream probes;
  probes << (checker.hasLocalAlias(probe_low) ? 1 : 0) << ','
         << (checker.hasLocalAlias(probe_edge) ? 1 : 0) << ','
         << (checker.hasLocalAlias(probe_deep) ? 1 : 0);
  std::ostringstream aliaslist;
  for (size_t i = 0; i < checker.getAlias().size(); ++i) {
    if (i != 0) aliaslist << ',';
    aliaslist << hex << checker.getAlias()[i];
  }
  std::cout << "case=derive_boundaries"
            << "|local=" << hex << checker.localBoundary
            << "|extreme=" << checker.localExtreme
            << "|aliasboundary=" << checker.aliasBoundary
            << "|aliases=[" << aliaslist.str() << ']'
            << "|probes=" << probes.str() << '\n';
}

/// Case 7: addGuard's untyped-address arm (varmap.cc:1009-1038) — the
/// oracle value getTypeReadFacing returns for an address varnode created by
/// newUnique with no updateType is the factory unknown base of the varnode's
/// width (funcdata_varnode.cc:83-93), never a null ct.  A range-locked LOAD
/// with step == element width keeps the address width (unk8, minItems =
/// 0x80/8-1 = 15); an unanalyzed LOAD whose outSize divides the step
/// re-steps to 4 and re-types to unk4 (minItems 3); an unanalyzed STORE
/// re-types to unk2 and extends up to the next hint; an outSize>step LOAD
/// is still rejected (varmap.cc:1020-1023) and leaves no trace.
static void run_guard_untyped_hints(FixtureArchitecture &arch)
{
  GatherOpenScope t(arch, "guard_untyped_hints", 0xa700);
  PcodeOp *locked = t.untyped_load(8, 0x2600);
  t.add_guard_record(locked, 8, 0xffffffffffffff80UL, 0xffffffffffffffffUL, true, false);
  PcodeOp *unanalyzed = t.untyped_load(4, 0x2610);
  t.add_guard_record(unanalyzed, 8, 0xffffffffffffff40UL, 0xffffffffffffffffUL, false, false);
  PcodeOp *store = t.untyped_store(2, 0x2620);
  t.add_guard_record(store, 2, 0xffffffffffffff20UL, 0xffffffffffffffffUL, false, true);
  PcodeOp *rejected = t.untyped_load(16, 0x2630);
  t.add_guard_record(rejected, 8, 0xfffffffffffffff8UL, 0xffffffffffffffffUL, true, false);
  t.scope.restructureVarnode(true);
  std::cout << "case=guard_untyped_hints|symbols=[" << t.symbols_token_text()
            << ']' << '\n';
}

/// Case 8: the field-by-field untyped-arm comparand — the same four
/// untyped guards fed to a hand-built MapState (the varmap.cc:1260-1261
/// construction with the param-range subtraction of varmap.cc:870-875),
/// dumping every collected RangeHint field in gatherOpen's insertion order
/// (loads then stores, varmap.cc:1241-1248) before initialize()'s sort:
/// start / sstart / size / flags / rangeType / highind / type token.
static void run_guard_untyped_dump(FixtureArchitecture &arch)
{
  GatherOpenScope t(arch, "guard_untyped_dump", 0xa800);
  PcodeOp *locked = t.untyped_load(8, 0x2700);
  t.add_guard_record(locked, 8, 0xffffffffffffff80UL, 0xffffffffffffffffUL, true, false);
  PcodeOp *unanalyzed = t.untyped_load(4, 0x2710);
  t.add_guard_record(unanalyzed, 8, 0xffffffffffffff40UL, 0xffffffffffffffffUL, false, false);
  PcodeOp *store = t.untyped_store(2, 0x2720);
  t.add_guard_record(store, 2, 0xffffffffffffff20UL, 0xffffffffffffffffUL, false, true);
  PcodeOp *rejected = t.untyped_load(16, 0x2730);
  t.add_guard_record(rejected, 8, 0xfffffffffffffff8UL, 0xffffffffffffffffUL, true, false);
  MapState state(t.stack, t.scope.getRangeTree(), t.fd.getFuncProto().getParamRange(),
                 t.arch.types->getBase(1, TYPE_UNKNOWN));
  std::list<LoadGuard>::const_iterator giter;
  for (giter = t.fd.heritage.loadGuard.begin(); giter != t.fd.heritage.loadGuard.end(); ++giter)
    state.addGuard(*giter, CPUI_LOAD, t.arch.types);
  for (giter = t.fd.heritage.storeGuard.begin(); giter != t.fd.heritage.storeGuard.end(); ++giter)
    state.addGuard(*giter, CPUI_STORE, t.arch.types);
  std::ostringstream out;
  bool first = true;
  for (size_t i = 0; i < state.maplist.size(); ++i) {
    const RangeHint *hint = state.maplist[i];
    if (!first) out << ';';
    first = false;
    out << hex << hint->start << ':' << dec << hint->sstart << ':' << hint->size
        << ':' << hint->flags << ':' << (int4)hint->rangeType << ':'
        << hint->highind << ':' << type_token(hint->type);
  }
  std::cout << "case=guard_untyped_dump|hints=[" << out.str() << ']' << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=VARMAP-GATHEROPEN-GUARD-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    run_guard_open_hints(arch);
    run_gather_symbols_reinput(arch);
    run_category_clears(arch);
    run_check_unaliased_return(arch);
    run_annotate_raw_stack_ptr(arch);
    run_derive_boundaries(arch);
    run_guard_untyped_hints(arch);
    run_guard_untyped_dump(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
