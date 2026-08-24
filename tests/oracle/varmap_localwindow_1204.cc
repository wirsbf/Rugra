/*
 * VARMAP-LOCALWINDOW-0001: locked Ghidra 12.0.4 authoritative local-window
 * oracle — ProtoModel::defaultLocalRange/defaultParamRange (fspec.cc:2263 /
 * fspec.cc:2292), ScopeLocal::resetLocalWindow (varmap.cc:432), the MapState
 * constructor's param-range subtraction (varmap.cc:864-875),
 * MapState::addRange's inRange gate (varmap.cc:896-919, address.cc:468),
 * MapState::initialize's signed-last-range endpoint (varmap.cc:1063-1082,
 * address.cc:562), ScopeLocal::restructureVarnode/restructure
 * (varmap.cc:1256/1294), and the ScopeLocal::buildVariableName localRange
 * gate (varmap.cc:548-581).
 *
 * The fixture drives a real Funcdata + ScopeLocal whose prototype model is
 * decoded through the production XML path with NO <localrange>/<paramrange>
 * elements, so the model carries the default windows of a negative-growing
 * 8-byte stack: locals = [getHighest()-999999, getHighest()], params =
 * [0,511].  Everything downstream is the production call sequence:
 * resetLocalWindow installs the union tree; synthetic stack Varnodes (COPY
 * of a constant, exactly the shape heritage leaves behind) and a spacebase
 * pointer chain (INT_SUB of the stack pointer consumed by a non-additive
 * op, the gatherOpen shape) feed ScopeLocal::restructureVarnode, whose
 * created Symbols reveal which hints survived the window gate; a trailing
 * open reference with no later fixed hint is bounded by initialize's
 * endpoint; and buildVariableName exercises the in-window Stack branch
 * against the positive-offset parameter fall-through.
 */

#include <bits/stdc++.h>

// Test-only access is required to read SymbolEntry internals through the
// public map iterators (the Rust comparand exposes the same walk through
// public observation accessors), matching what production Ghidra reaches
// through friend-only iterators.
#define private public
#define protected public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varmap.hh"
#include "varnode.hh"
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
        "<prototype name=\"lw_default\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const std::string &) const override {}
};

/// Per-case harness: a fresh Funcdata whose prototype carries the model with
/// the DEFAULT stack windows (no <localrange>/<paramrange> in the XML), plus
/// a real ScopeLocal bound to it the way production builds function scopes.
class LocalWindowScope {
public:
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  AddrSpace *stack;
  Funcdata fd;
  ScopeLocal scope;
  TypeFactory *types;

  LocalWindowScope(FixtureArchitecture &a, const std::string &name, uintb fd_off)
    : arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), stack(a.getSpace(5)),
      fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), fd_off),
         (FunctionSymbol *)0, 0x20),
      scope(0x102, a.getSpace(5), &fd, &a), types(a.types) {
    // The default model decoded by FixtureArchitecture already carries the
    // default windows; bind it to the function prototype the production way
    // (FuncProto::setModel) then install the scope window (funcdata.cc:70).
    fd.getFuncProto().setModel(arch.protoModels["lw_default"]);
    scope.resetLocalWindow();
  }

  Datatype *int_t(void) { return types->getBase(4, TYPE_INT); }
  Datatype *char_t(void) { return types->getBase(1, TYPE_INT); }
  Datatype *long_t(void) { return types->getBase(8, TYPE_INT); }

  /// A written stack Varnode at `off` holding `ct`, defined by COPY of a
  /// constant — the shape heritage leaves for every stack slot (the
  /// gatherVarnodes CPUI_COPY path, varmap.cc:1198-1199).
  Varnode *stack_copy(uintb off, Datatype *ct, uintb pc) {
    PcodeOp *op = fd.newOp(1, Address(ram, pc));
    fd.opSetOpcode(op, CPUI_COPY);
    fd.opSetInput(op, fd.newConstant(ct->getSize(), 0x1234), 0);
    Varnode *out = fd.newVarnode(ct->getSize(), Address(stack, off), ct);
    fd.opSetOutput(op, out);
    return out;
  }

  /// The gatherOpen shape: an input stack-pointer Varnode, an INT_SUB by
  /// `delta` whose result is typed as a pointer to `pt`, and a non-additive
  /// consumer marking the additive root (AliasChecker::gatherAdditiveBase,
  /// varmap.cc:741-815).  Returns the pointer Varnode.
  Varnode *spacebase_pointer_sub(uintb delta, Datatype *pt, uintb pc) {
    Varnode *sp = fd.newVarnode(8, Address(reg, 0));
    fd.setInputVarnode(sp);
    PcodeOp *sub = fd.newOp(2, Address(ram, pc));
    fd.opSetOpcode(sub, CPUI_INT_SUB);
    fd.opSetInput(sub, sp, 0);
    fd.opSetInput(sub, fd.newConstant(8, delta), 1);
    Varnode *ptr = fd.newUniqueOut(8, sub);
    fd.opSetOutput(sub, ptr);
    ptr->updateType(types->getTypePointer(8, pt, 0));
    PcodeOp *eq = fd.newOp(2, Address(ram, pc + 8));
    fd.opSetOpcode(eq, CPUI_INT_EQUAL);
    fd.opSetInput(eq, ptr, 0);
    fd.opSetInput(eq, fd.newUnique(8), 1);
    return ptr;
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

  /// Render the scope's created symbols as `start:size:typename`, ';'-joined,
  /// in mapping order.  Array types render as `element[num]` (the same
  /// projection the Rust comparand's print_raw produces).
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
};

/// Case 1: the default windows of a negative-growing 8-byte stack and the
/// union tree resetLocalWindow installs.
static void run_default_windows(FixtureArchitecture &arch)
{
  LocalWindowScope t(arch, "default_windows", 0x9000);
  std::cout << "case=default_windows"
            << "|grow=" << (t.fd.getFuncProto().isStackGrowsNegative() ? 1 : 0)
            << "|local=" << LocalWindowScope::ranges_text(t.fd.getFuncProto().getLocalRange())
            << "|param=" << LocalWindowScope::ranges_text(t.fd.getFuncProto().getParamRange())
            << "|union=" << LocalWindowScope::ranges_text(t.scope.getRangeTree())
            << '\n';
}

/// Case 2: the addRange inRange gate through the production
/// restructureVarnode path.  Stack slots at the window's first byte, last
/// byte, and deep negative offsets become Symbols; one byte below the
/// window, and the positive-offset parameter region (subtracted from the
/// MapState analysis range, varmap.cc:874), produce nothing.
/// Case 2: the addRange inRange gate through the production
/// restructureVarnode path.  Stack slots at the window's first byte, deep
/// negative offsets, and the window's top (the 8-byte slot ending at the
/// last byte) become Symbols; one byte below the window and the
/// positive-offset parameter region (subtracted from the MapState analysis
/// range, varmap.cc:874) produce nothing.
static void run_gate_and_symbols(FixtureArchitecture &arch)
{
  LocalWindowScope t(arch, "gate_and_symbols", 0x9100);
  t.stack_copy(0xfffffffffff0bdc0UL, t.char_t(), 0x1000); // window first byte
  t.stack_copy(0xfffffffffff0bdbfUL, t.char_t(), 0x1008); // one byte below
  t.stack_copy(0xffffffffffff8000UL, t.int_t(), 0x1010);  // mid negative local
  t.stack_copy(0x0, t.int_t(), 0x1018);                   // parameter region
  t.stack_copy(0x1ff, t.int_t(), 0x1020);                 // parameter region
  t.stack_copy(0xfffffffffffffff8UL, t.long_t(), 0x1028); // spans to the last byte
  t.scope.restructureVarnode(false);
  std::cout << "case=gate_and_symbols"
            << "|symbols=[" << t.symbols_text() << ']'
            << '\n';
}

/// Case 3: the 4096-byte-buffer shape.  An open element reference at
/// sp-0x1010 (the gatherOpen path) extends up to the canary-shaped fixed
/// slot at sp-8 and becomes an array entry; with no later fixed hint the
/// open reference at sp-0x10 is bounded by initialize()'s endpoint at
/// wrapOffset(lastSigned+1) = 0.
static void run_open_array(FixtureArchitecture &arch)
{
  LocalWindowScope t(arch, "open_array", 0x9200);
  t.spacebase_pointer_sub(0x1010, t.int_t(), 0x1100);
  t.stack_copy(0xfffffffffffffff8UL, t.long_t(), 0x1110);
  t.scope.restructureVarnode(false);
  std::string open_to_fixed = t.symbols_text();

  LocalWindowScope t2(arch, "open_endpoint_bound", 0x9300);
  t2.spacebase_pointer_sub(0x10, t2.int_t(), 0x1200);
  t2.scope.restructureVarnode(false);
  std::cout << "case=open_array"
            << "|open_to_fixed=[" << open_to_fixed << ']'
            << "|open_to_endpoint=[" << t2.symbols_text() << ']'
            << '\n';
}

/// Case 4: buildVariableName against the DEFAULT local window — the
/// negative-offset local hits the ScopeLocal Stack branch, the
/// positive-offset parameter region and out-of-window offsets fall through
/// to the ScopeInternal addrtied form.
static void run_naming_branches(FixtureArchitecture &arch)
{
  LocalWindowScope t(arch, "naming_branches", 0x9400);
  Address pc(t.ram, 0x1000);
  int4 index = 1;
  std::ostringstream out;
  out << t.scope.buildVariableName(Address(t.stack, 0xffffffffffffff10UL), pc,
                                   t.int_t(), index, Varnode::addrtied) << ';';
  out << t.scope.buildVariableName(Address(t.stack, 0x10), pc,
                                   t.int_t(), index, Varnode::addrtied) << ';';
  out << t.scope.buildVariableName(Address(t.stack, 0x1ff), pc,
                                   t.int_t(), index, Varnode::addrtied) << ';';
  out << t.scope.buildVariableName(Address(t.stack, 0x200), pc,
                                   t.int_t(), index, Varnode::addrtied) << ';';
  out << t.scope.buildVariableName(Address(t.stack, 0xfffffffffff0bdc0UL), pc,
                                   t.int_t(), index, Varnode::addrtied);
  std::cout << "case=naming_branches|names=" << out.str() << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=VARMAP-LOCALWINDOW-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    run_default_windows(arch);
    run_gate_and_symbols(arch);
    run_open_array(arch);
    run_naming_branches(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
