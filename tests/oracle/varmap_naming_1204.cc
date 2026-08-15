/*
 * VARMAP-NAMING-0001: locked Ghidra 12.0.4 authoritative default-naming
 * oracle — Scope::buildDefaultName (database.cc:1756),
 * ScopeInternal::assignDefaultNames (database.cc:2850),
 * ScopeInternal::buildVariableName (database.cc:2434),
 * ScopeInternal::makeNameUnique (database.cc:2553),
 * ScopeInternal::insertNameTree (database.cc:2712), and
 * ScopeLocal::buildVariableName (varmap.cc:548).
 *
 * The fixture drives real ScopeLocal objects attached to real Funcdata with a
 * prototype-local range, adds symbols through the production addSymbol /
 * setCategory APIs, and observes the complete naming state mutation: the
 * SymbolNameTree walk order, the final name/displayName pair, category and
 * category index, the nameDedup id, and the final value of the single shared
 * int4 base counter.  A second assignDefaultNames run per case observes
 * idempotence.  Direct buildVariableName / makeNameUnique calls cover the
 * flag-driven branches (unaffected / persist / irregular input / parameter /
 * addrtied / indirect_creation / default local) that assignDefaultNames
 * cannot reach from SymbolEntry state alone.
 */

#include <bits/stdc++.h>

// Test-only access is required to read Symbol::nameDedup and to walk the
// ScopeInternal::nametree directly (the Rust comparand exposes the same walk
// through a public observation accessor), matching what production Ghidra
// reaches through friend-only iterators.
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
  std::map<std::pair<uintb, int4>, std::string> fixture_registers;

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
    fixture_registers[std::make_pair((uintb)0x100, 8)] = "SREG1";
    fixture_registers[std::make_pair((uintb)0x108, 4)] = "SREG2";
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb off, int4 size) const override {
    std::map<std::pair<uintb, int4>, std::string>::const_iterator iter =
        fixture_registers.find(std::make_pair(off, size));
    if (iter == fixture_registers.end())
      return "";
    return (*iter).second;
  }
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

/// Per-case scope factory: a fresh Funcdata whose prototype model carries the
/// given local range (installed through the production ProtoModel XML decode
/// path), plus a real ScopeLocal bound to it the way production builds
/// function scopes.
class NamingScope {
public:
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  AddrSpace *stack;
  Funcdata fd;
  ScopeLocal scope;
  TypeFactory *types;
  ProtoModel model;

  NamingScope(FixtureArchitecture &a, const std::string &name,
              const std::string &localrange_xml)
    : arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), stack(a.getSpace(5)),
      fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), 0x9000),
         (FunctionSymbol *)0, 0x20),
      scope(0x102, a.getSpace(5), &fd, &a), types(a.types), model(&a) {
    // Install the local window via the production XML decode path
    // (fspec.cc:2640-2648); an explicit empty <localrange/> keeps
    // defaultLocalRange() (fspec.cc:2263) from filling a default window, so
    // out-of-range stack offsets exercise the ScopeInternal fall-through.
    std::ostringstream xml;
    xml << "<prototype name=\"naming_" << name << "\" extrapop=\"0\">"
        << "<input/><output/>" << localrange_xml << "</prototype>";
    std::istringstream stream(xml.str());
    XmlDecode decoder(&a);
    decoder.ingestStream(stream);
    model.decode(decoder);
    fd.getFuncProto().setModel(&model);
  }

  static std::string range_xml(uintb first, uintb last) {
    std::ostringstream out;
    out << "<localrange><range space=\"stack\" first=\"" << first
        << "\" last=\"" << last << "\"/></localrange>";
    return out.str();
  }

  static std::string empty_range_xml() { return "<localrange/>"; }

  Datatype *int_t(void) { return types->getBase(4, TYPE_INT, "int"); }
  Datatype *char_t(void) { return types->getBase(1, TYPE_INT, "char"); }
  Datatype *long_t(void) { return types->getBase(8, TYPE_INT, "long"); }
  Datatype *ptr_array_int(void) {
    return types->getTypePointer(8, types->getTypeArray(3, int_t()), 0);
  }

  Symbol *add(const std::string &nm, Datatype *ct, uintb offset,
              bool has_usepoint, int4 cat = -1, int4 catidx = -1) {
    Address addr(stack, offset);
    Address usepoint;
    if (has_usepoint)
      usepoint = Address(ram, 0x1000);
    Symbol *sym = scope.addSymbol(nm, ct, addr, usepoint)->getSymbol();
    if (cat >= 0)
      scope.setCategory(sym, cat, catidx);
    return sym;
  }

  /// Render the full naming state in SymbolNameTree order:
  /// name:display:category:catindex:nameDedup per symbol, ';' separated.
  std::string state_text(void) {
    std::ostringstream out;
    out << '[';
    bool first = true;
    SymbolNameTree::const_iterator iter;
    for (iter = scope.nametree.begin(); iter != scope.nametree.end(); ++iter) {
      Symbol *sym = *iter;
      if (!first) out << ';';
      first = false;
      out << sym->getName() << ':' << sym->getDisplayName() << ':'
          << (int4)sym->getCategory() << ':' << (int4)sym->getCategoryIndex()
          << ':' << sym->nameDedup;
    }
    out << ']';
    return out.str();
  }

  void run(const char *case_name, const std::string &extra) {
    std::cout << "case=" << case_name
              << "|pre=" << state_text();
    int4 base = 1;
    scope.assignDefaultNames(base);
    std::cout << "|post=" << state_text() << "|base=" << base;
    scope.assignDefaultNames(base);
    std::cout << "|post2=" << state_text() << "|base2=" << base
              << "|extra=[" << extra << "]\n";
  }
};

/// Case 1: category split + shared base.  Two function_parameter symbols take
/// param_<catindex+1> names without touching the base counter, one stack
/// local inside the local range takes the ScopeLocal Stack path without
/// touching the counter, and two use-pointed locals draw iVar1/cVar2 from the
/// ONE shared counter (per-prefix counters would print iVar1/cVar1).
static void run_cross_category(FixtureArchitecture &arch)
{
  NamingScope t(arch, "cross_category", NamingScope::range_xml(0xffffffffffffff00UL, 0xffffffffffffffffUL));
  t.add("", t.long_t(), 0x10, false, 0, 0);   // param_1
  t.add("", t.char_t(), 0x20, false, 0, 1);  // param_2
  t.add("", t.int_t(), 0xffffffffffffff10UL, false); // iStack_f0 (local range)
  t.add("", t.char_t(), 0xffffffffffffff20UL, true); // cVar?  (default branch)
  t.add("", t.long_t(), 0xffffffffffffff30UL, true); // lVar?  (default branch)
  t.run("cross_category_shared_base", "");
}

/// Case 2: the shared-counter iron proof.  Four use-pointed locals with
/// interleaved type prefixes must number 1,2,3,4 across prefixes, plus one
/// address-tied symbol outside any local range taking the ScopeInternal
/// addrtied form without consuming the counter.
static void run_sequential_increment(FixtureArchitecture &arch)
{
  NamingScope t(arch, "sequential_increment", NamingScope::empty_range_xml()); // empty local range
  t.add("", t.int_t(), 0xffffffffffffff10UL, true);
  t.add("", t.char_t(), 0xffffffffffffff20UL, true);
  t.add("", t.int_t(), 0xffffffffffffff30UL, true);
  t.add("", t.long_t(), 0xffffffffffffff40UL, true);
  t.add("", t.int_t(), 0x50, false); // iStack<16-digit hex> via addrtied
  t.run("sequential_increment_shared_base", "");
}

/// Case 3: named (locked) symbols are never renamed, displayName mirrors
/// name, and the buildVariableName bump loop walks the shared counter past
/// colliding iVar1 before falling back to makeNameUnique sequencing.
static void run_typelock_and_bump(FixtureArchitecture &arch)
{
  NamingScope t(arch, "typelock_bump", NamingScope::empty_range_xml());
  Symbol *cust = t.add("cust_lock", t.long_t(), 0xffffffffffffff10UL, true, 0, 5);
  cust->flags |= Varnode::typelock | Varnode::namelock;
  t.add("iVar1", t.int_t(), 0xffffffffffffff20UL, true);
  t.add("iVar1_00", t.int_t(), 0xffffffffffffff28UL, true);
  t.add("iVar1_01", t.int_t(), 0xffffffffffffff30UL, true);
  t.add("", t.int_t(), 0xffffffffffffff38UL, true); // bump past iVar1
  t.add("", t.int_t(), 0xffffffffffffff40UL, true); // next shared number
  std::ostringstream extra;
  extra << t.scope.makeNameUnique("iVar1") << ';'
        << t.scope.makeNameUnique("iVar1_01") << ';'
        << t.scope.makeNameUnique("iVar9") << ';'
        << t.scope.makeNameUnique("cust_lock");
  t.run("typelock_display_and_bump", extra.str());
}

/// Case 4: the ScopeLocal stack-name paths.  With a negative-growing stack,
/// offsets below 2^63 negate to a negative start (X — caller-allocated),
/// offsets at/above 2^63 negate to a positive start (plain hex, or Y when the
/// raw offset sits below minParamOffset).  The param category and a use-pointed
/// local cover the fall-through branches.  minParamOffset/maxParamOffset are
/// fed through the production mutator (varmap.cc:519-524,
/// markNotMapped parameter=true) before symbols exist.  The local window has
/// two disjoint ranges, exercising multi-range inRange.
static void run_stack_paths(FixtureArchitecture &arch)
{
  // Two disjoint local windows: the high-address window (>= 2^63, positive
  // start after the negative-growth negation) and the mid-address window
  // (< 2^63, negative start — X region).
  NamingScope t(arch, "stack_paths",
                "<localrange>"
                "<range space=\"stack\" first=\"18446744073709547520\" last=\"18446744073709551615\"/>"
                "<range space=\"stack\" first=\"1152921504606846976\" last=\"2305843009213693951\"/>"
                "</localrange>");
  t.scope.markNotMapped(t.stack, 0xffffffffffffff20UL, 1, true); // minParamOffset
  t.scope.markNotMapped(t.stack, 0xffffffffffffff30UL, 1, true); // maxParamOffset
  t.add("", t.int_t(), 0xffffffffffffff10UL, false); // Y region (start>0, off<min)
  t.add("", t.int_t(), 0x1000000000000020UL, false); // X region (start<0)
  t.add("", t.int_t(), 0xfffffffffffffff0UL, false); // plain positive start
  t.add("", t.long_t(), 0x20, false, 0, 2);          // param_3 (out of range)
  t.add("", t.int_t(), 0x1000000000000040UL, true);  // default branch iVar
  t.run("scopelocal_stack_paths", "");
}

/// Case 5: direct buildVariableName flag branches on a fresh scope with the
/// fixture register table: unaffected(+return_address), unaffected with and
/// without a register name, persist with and without a register name,
/// irregular input (index < 0) both ways, regular parameter (index >= 0),
/// indirect_creation both ways, the default local branch, and a
/// pointer-to-array printNameBase recursion.
static void run_direct_flags(FixtureArchitecture &arch)
{
  NamingScope t(arch, "direct_flags", NamingScope::empty_range_xml());
  std::ostringstream extra;
  Address reg100(t.reg, 0x100);
  Address reg108(t.reg, 0x108);
  Address stack40(t.stack, 0x40);
  Address stack20(t.stack, 0x20);
  Address stack0(t.stack, 0);
  Address pc(t.ram, 0x1000);
  int4 idx;
  idx = -1;
  extra << t.scope.buildVariableName(reg100, pc, t.long_t(), idx,
                                     Varnode::unaffected | Varnode::return_address) << ';';
  idx = -1;
  extra << t.scope.buildVariableName(reg100, pc, t.int_t(), idx,
                                     Varnode::unaffected) << ';';
  idx = -1;
  extra << t.scope.buildVariableName(reg100, pc, t.long_t(), idx,
                                     Varnode::unaffected) << ';';
  idx = -1;
  extra << t.scope.buildVariableName(reg100, pc, t.long_t(), idx,
                                     Varnode::persist) << ';';
  idx = -1;
  extra << t.scope.buildVariableName(stack40, pc, t.int_t(), idx,
                                     Varnode::persist) << ';';
  idx = -1;
  extra << t.scope.buildVariableName(reg108, pc, t.int_t(), idx,
                                     Varnode::input) << ';';
  idx = -1;
  extra << t.scope.buildVariableName(stack20, pc, t.int_t(), idx,
                                     Varnode::input) << ';';
  idx = 7;
  extra << t.scope.buildVariableName(stack20, pc, t.int_t(), idx,
                                     Varnode::input) << ';';
  idx = -1;
  extra << t.scope.buildVariableName(reg100, pc, t.long_t(), idx,
                                     Varnode::indirect_creation) << ';';
  idx = -1;
  extra << t.scope.buildVariableName(stack0, pc, t.int_t(), idx,
                                     Varnode::indirect_creation) << ';';
  idx = 1;
  extra << t.scope.buildVariableName(stack20, pc, t.int_t(), idx, 0) << ';';
  idx = 1;
  extra << t.scope.buildVariableName(stack20, pc, t.ptr_array_int(), idx, 0);
  t.run("direct_flag_paths", extra.str());
}

/// Case 6: $$undef placeholder sequencing, insertNameTree nameDedup on
/// duplicate names, and the shared counter flowing through the default
/// branch while duplicates sit untouched.
static void run_undef_dedup(FixtureArchitecture &arch)
{
  NamingScope t(arch, "undef_dedup", NamingScope::empty_range_xml());
  t.add("", t.int_t(), 0xffffffffffffff10UL, true);
  t.add("", t.int_t(), 0xffffffffffffff20UL, true);
  t.add("", t.int_t(), 0xffffffffffffff30UL, true);
  t.add("dup", t.int_t(), 0xffffffffffffff40UL, true);
  t.add("dup", t.int_t(), 0xffffffffffffff50UL, true);
  t.add("dup", t.int_t(), 0xffffffffffffff60UL, true);
  t.run("undef_dedup_and_shared_base", "");
}

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=VARMAP-NAMING-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    run_cross_category(arch);
    run_sequential_increment(arch);
    run_typelock_and_bump(arch);
    run_stack_paths(arch);
    run_direct_flags(arch);
    run_undef_dedup(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
