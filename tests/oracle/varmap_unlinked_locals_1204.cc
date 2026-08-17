/*
 * PRINTC-UNLINKED-REF-0001: locked Ghidra 12.0.4 authoritative
 * local-entry oracle — the ActionNameVars judgment chain that decides
 * which function locals become ScopeLocal symbols:
 *   HighVariable::hasName            (variable.cc:718)
 *   Funcdata::linkSymbol             (funcdata_varnode.cc:1156)
 *   Scope::queryProperties           (database.cc:1263)
 *   Funcdata::handleSymbolConflict   (funcdata_varnode.cc:997)
 *   Scope::addSymbol / Scope::addMapPoint / Scope::addMap (database.cc:1530-1160)
 *   Scope::buildDefaultName          (database.cc:1756)
 *   ScopeLocal::buildVariableName    (varmap.cc:548)
 *   ScopeInternal::buildVariableName (database.cc:2434)
 * plus the ActionNameVars::apply naming loop (coreaction.cc:2988-2997):
 *   for each linked symbol whose name is undefined ->
 *   buildDefaultName(sym, base, vn) -> renameSymbol.
 *
 * The fixture drives REAL Funcdata objects (whose ctor builds the
 * production ScopeLocal localmap and the symbol-backed prototype store at
 * funcdata.cc:69) through the production Varnode/HighVariable APIs, then
 * prints the complete local-scope contents in a canonical (space, offset,
 * size, name) order together with the per-candidate gate results
 * (hasName / linked).  The case set mirrors the glob_url shapes that the
 * E2E differential attributed to PRINTC-UNLINKED-REF-0001:
 *
 *   explicit_register_local  — a written-shaped explicit register local
 *                              (the strlen-result shape): linked + named
 *                              via the default-local branch (lVar1).
 *   implied_unique_temp      — a Unique-space implied temporary (the
 *                              malloc-result shape): hasName refuses it,
 *                              no symbol is created, scope stays empty.
 *   spacebase_stack_pointer  — the stack-pointer input (unaffected, legal
 *                              input, spacebase): hasName refuses it via
 *                              variable.cc:743, scope stays empty.
 *   irregular_input          — an unaffected illegal register input (the
 *                              in_XXX shape): linked + named in_SREG1 via
 *                              the irregular-input branch.
 *   addrtied_stack_local     — an address-tied stack local inside the
 *                              local window: linked + named through the
 *                              ScopeLocal Stack branch (lStack_b8).
 *   formal_param_attach      — an input whose storage already carries a
 *                              category-0 function_parameter symbol: the
 *                              queryProperties/handleSymbolConflict path
 *                              attaches to the existing symbol, no new
 *                              symbol, category 0 survives (the decl-block
 *                              exclusion invariant).
 */

#include <bits/stdc++.h>

// Test-only access is required to read Symbol::nameDedup and to walk the
// ScopeInternal internals directly (the Rust comparand exposes the same walk
// through public observation accessors), matching what production Ghidra
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
    // Same register catalog as varmap_naming_1204: the irregular-input and
    // unaff_ branches consult getRegisterName (translate.hh:380).
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

/// Per-case function factory: a fresh Funcdata whose ctor built the
/// production ScopeLocal localmap (funcdata.cc:69), with the local window
/// installed through the production ProtoModel XML decode path and
/// resetLocalWindow (varmap.cc:432), exactly as ActionRestructureVarnode
/// leaves the scope before ActionNameVars runs.
class CaseFunc {
public:
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  AddrSpace *stack;
  AddrSpace *uniq;
  Funcdata fd;
  ScopeLocal *localmap;
  TypeFactory *types;
  ProtoModel model;

  CaseFunc(FixtureArchitecture &a, const std::string &name)
    : arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), stack(a.getSpace(5)),
      uniq(a.getSpace(2)),
      fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), 0x9000),
         (FunctionSymbol *)0, 0x20),
      localmap((ScopeLocal *)0), types(a.types), model(&a) {
    // Install the local window via the production XML decode path
    // (fspec.cc:2640-2648): one high-address window (>= 2^63) holding the
    // addrtied stack local.  The model stays a member so the prototype's
    // live getLocalRange reads (varmap.cc:555) remain valid through the
    // whole case, exactly as the naming fixture's NamingScope keeps its
    // model alive.
    std::ostringstream xml;
    xml << "<prototype name=\"entry_" << name << "\" extrapop=\"0\">"
        << "<input/><output/>"
        << "<localrange><range space=\"stack\" first=\"18446744073709547520\""
        << " last=\"18446744073709551615\"/></localrange></prototype>";
    std::istringstream stream(xml.str());
    XmlDecode decoder(&a);
    decoder.ingestStream(stream);
    model.decode(decoder);
    fd.getFuncProto().setModel(&model);
    localmap = fd.getScopeLocal();
    localmap->resetLocalWindow();
  }

  Datatype *long_t(void) { return types->getBase(8, TYPE_INT, "long"); }
};

/// Canonical scope-state dump shared with the Rust comparand:
///   case <name>: hasName=<0|1> linked=<0|1>
///     sym name=<n> space=<sp> off=<hex> size=<d> cat=<d> dyn=<0|1> usept=<none|hex>
/// Symbols are listed in sorted (space-name, offset, size, name) order with
/// multi-entry symbols deduplicated to their first whole map, then the
/// dynamic-entry list in insertion order.
static void dump_case(const char *case_name, int4 hasname, int4 linked,
                      Funcdata &fd)
{
  std::cout << "case " << case_name << ": hasName=" << hasname
            << " linked=" << linked << "\n";
  ScopeLocal *localmap = fd.getScopeLocal();
  struct Row {
    std::string name, space;
    uintb off;
    int4 size, cat, dyn;
    std::string usept;
  };
  std::vector<Row> rows;
  std::set<Symbol *> seen;
  MapIterator miter, mend;
  for (miter = localmap->begin(), mend = localmap->end(); miter != mend; ++miter) {
    const SymbolEntry *entry = *miter;
    Symbol *sym = entry->getSymbol();
    if (!seen.insert(sym).second) continue;
    Row row;
    row.name = sym->getName();
    row.space = entry->getAddr().getSpace()->getName();
    row.off = entry->getAddr().getOffset();
    row.size = entry->getSize();
    row.cat = sym->getCategory();
    row.dyn = entry->isDynamic() ? 1 : 0;
    Address use = entry->getFirstUseAddress();
    std::ostringstream u;
    if (use.isInvalid())
      u << "none";
    else
      u << hex << use.getOffset();
    row.usept = u.str();
    rows.push_back(row);
  }
  std::list<SymbolEntry>::const_iterator diter, dend;
  for (diter = localmap->beginDynamic(), dend = localmap->endDynamic();
       diter != dend; ++diter) {
    const SymbolEntry &entry(*diter);
    Symbol *sym = entry.getSymbol();
    if (!seen.insert(sym).second) continue;
    Row row;
    row.name = sym->getName();
    row.space = "dynamic";
    row.off = 0;
    row.size = entry.getSize();
    row.cat = sym->getCategory();
    row.dyn = 1;
    std::ostringstream u;
    u << hex << entry.getFirstUseAddress().getOffset();
    row.usept = u.str();
    rows.push_back(row);
  }
  std::sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
    if (a.space != b.space) return a.space < b.space;
    if (a.off != b.off) return a.off < b.off;
    if (a.size != b.size) return a.size < b.size;
    return a.name < b.name;
  });
  for (const Row &row : rows) {
    std::cout << "  sym name=" << row.name << " space=" << row.space
              << " off=" << hex << row.off << dec << " size=" << row.size
              << " cat=" << row.cat << " dyn=" << row.dyn
              << " usept=" << row.usept << "\n";
  }
}

/// Drive the ActionNameVars local-entry judgment (coreaction.cc:2961-2963 +
/// the naming loop at cc:2988-2997) for one candidate Varnode.
static void run_entry(const char *case_name, Funcdata &fd, Varnode *vn)
{
  HighVariable *high = vn->getHigh();
  int4 hasname = high->hasName() ? 1 : 0;
  int4 linked = 0;
  if (hasname) {
    Symbol *sym = fd.linkSymbol(vn);
    if (sym != (Symbol *)0) {
      linked = 1;
      // coreaction.cc:2988-2997: int4 base = 1; for each namerec varnode
      // whose symbol is still name-undefined, build a default name with the
      // vn representative and rename.
      if (sym->isNameUndefined()) {
        int4 base = 1;
        Scope *scope = sym->getScope();
        string newname = scope->buildDefaultName(sym, base, vn);
        scope->renameSymbol(sym, newname);
      }
    }
  }
  dump_case(case_name, hasname, linked, fd);
}

int main(void)
{
  try {
  // Populate the capability lists (printc.cc's PrintCCapability et al.)
  // the way every production entry point does before building an
  // Architecture (capability.cc:40).
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=PRINTC-UNLINKED-REF-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  FixtureArchitecture arch;

  {
    // The strlen-result shape: an explicit register local.  insert (banked,
    // coverable), no input/addrtied flags: hasName passes, linkSymbol
    // creates a symbol at the register storage named by the default-local
    // branch with the shared base counter (long -> lVar1).
    CaseFunc t(arch, "explicit_register_local");
    Varnode *vn = t.fd.newVarnode(8, Address(t.reg, 0x0), t.long_t());
    vn->setFlags(Varnode::insert);
    t.fd.setHighLevel();
    run_entry("explicit_register_local", t.fd, vn);
  }

  {
    // The malloc-result shape: a Unique-space implied temporary.  The
    // implied flag forbids a name (variable.cc:729-733): no symbol is
    // created, the scope stays empty.
    CaseFunc t(arch, "implied_unique_temp");
    Varnode *vn = t.fd.newVarnode(8, Address(t.uniq, 0x9100), t.long_t());
    vn->setFlags(Varnode::insert);
    vn->setImplied();
    t.fd.setHighLevel();
    run_entry("implied_unique_temp", t.fd, vn);
  }

  {
    // The stack-pointer shape: an unaffected legal input (input +
    // directwrite -> isIllegalInput false) carrying the spacebase flag.
    // variable.cc:743 refuses the name; the scope stays empty.
    CaseFunc t(arch, "spacebase_stack_pointer");
    Varnode *vn = t.fd.newVarnode(8, Address(t.reg, 0x0), t.long_t());
    vn->setFlags(Varnode::insert | Varnode::input | Varnode::directwrite |
                 Varnode::spacebase | Varnode::unaffected);
    t.fd.setHighLevel();
    run_entry("spacebase_stack_pointer", t.fd, vn);
  }

  {
    // The in_XXX shape: an illegal register input (input without
    // directwrite) at a named catalog register, carrying no vn-level
    // unaffected bit (production in_RDX-style inputs name through the
    // irregular-input branch; the unaffected bit would flip the name to
    // unaff_).  hasName passes the fall-through, linkSymbol creates the
    // symbol and the irregular-input branch names it in_SREG1
    // (database.cc:2467-2474 with translate getRegisterName).
    CaseFunc t(arch, "irregular_input");
    Varnode *vn = t.fd.newVarnode(8, Address(t.reg, 0x100), t.long_t());
    vn->setFlags(Varnode::insert | Varnode::input);
    t.fd.setHighLevel();
    run_entry("irregular_input", t.fd, vn);
  }

  {
    // The stack-local shape: an address-tied stack Varnode inside the local
    // window.  linkSymbol maps it at the stack address with an unrestricted
    // use (funcdata_varnode.cc:1175-1176), and buildDefaultName's addrtied
    // path drives ScopeLocal::buildVariableName's Stack branch
    // (varmap.cc:548-577): -0xb8 negates to a positive start -> lStack_b8.
    CaseFunc t(arch, "addrtied_stack_local");
    Varnode *vn = t.fd.newVarnode(8, Address(t.stack, 0xffffffffffffff48UL), t.long_t());
    vn->setFlags(Varnode::insert | Varnode::addrtied);
    t.fd.setHighLevel();
    run_entry("addrtied_stack_local", t.fd, vn);
  }

  {
    // The parameter-attach shape: storage that already carries a category-0
    // function_parameter symbol (the ProtoStoreSymbol state production has
    // from funcdata.cc:69).  linkSymbol's queryProperties finds the entry
    // and handleSymbolConflict attaches the input Varnode to the existing
    // symbol: no new symbol is created, the parameter name and category
    // survive (the no_category decl-walk exclusion invariant).
    CaseFunc t(arch, "formal_param_attach");
    SymbolEntry *entry = t.localmap->addSymbol(
        "p0", t.long_t(), Address(t.reg, 0x100), Address(t.ram, 0x8fff));
    t.localmap->setCategory(entry->getSymbol(), Symbol::function_parameter, 0);
    Varnode *vn = t.fd.newVarnode(8, Address(t.reg, 0x100), t.long_t());
    vn->setFlags(Varnode::insert | Varnode::input | Varnode::unaffected);
    t.fd.setHighLevel();
    run_entry("formal_param_attach", t.fd, vn);
  }

  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << std::endl;
    return 2;
  }
  return 0;
}
