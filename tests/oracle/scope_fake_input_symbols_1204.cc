/*
 * VARMAP-FAKEINPUT-0001: locked Ghidra 12.0.4 authoritative oracle for
 * ScopeLocal::fakeInputSymbols (varmap.cc:1392-1448).
 *
 * The fixture drives the real Funcdata-attached ScopeLocal of a fixture
 * Architecture: input Varnodes are created through the production
 * Funcdata::newVarnode + VarnodeBank::setInput path (bank-level setInput is
 * the exact production entry Funcdata::setInputVarnode calls after its
 * overlap check, so deliberately overlapping inputs — the 507/508 absorption
 * case — can be constructed), the per-case prototype model carrying the
 * paramrange is installed through the production ProtoModel XML decode path
 * via FuncProto::setModel, and then ScopeLocal::fakeInputSymbols runs
 * exactly as ActionRestructureVarnode would call it.
 *
 * Cases cover the decisive semantics:
 *  A. first-address-only (size 1) paramrange filter: flipped negative-growth
 *     local offsets and below-range offsets are filtered; an offset whose
 *     varnode extends past the range end still passes.
 *  B. overlap absorption: start=507,size=2 absorbs a 508 input into one
 *     size-5 symbol, and the same 508 input alone forms its own symbol in a
 *     sibling scope (proving the filtering is absorption, not paramrange).
 *  C. adjacent-but-not-overlapping inputs do NOT merge.
 *  D. cross-space iteration: earlier-space inputs hit the outer continue,
 *     a later-space input breaks the inner merge loop without ending the
 *     scan.
 *  E. a typelocked member skips the whole group, later groups still run.
 *  F. lockedinputs != 0: the queryProperties probe resolves the last
 *     examined (breaker) Varnode to a function_parameter Symbol and skips.
 *  G. lockedinputs != 0: a parameter Symbol covering only the group leader
 *     does NOT skip (the probe queries the breaker, not the leader).
 *  H. flipped paramrange at the top of the space: a group leader whose
 *     extent wraps the 2^64 boundary triggers the addSymbol LowlevelError
 *     ("extends beyond the end of the address space"), routed to
 *     Funcdata::warningHeader, and the scan continues.
 *
 * Observation per case: every whole SymbolEntry in (space, first, last)
 * order with name/displayName/category/catindex/size/typelock, the
 * function_parameter category size, and the warning-header texts. The
 * rangemap's overlap partition (one AddrRange piece per split boundary,
 * rangemap::insert's unzip) is normalized to one record per Symbol via
 * getFirstWholeMap, matching Rugra's one-whole-map-per-Symbol model.
 */

#include <bits/stdc++.h>

// Test-only access to default-private members (Funcdata::vbank,
// ScopeLocal::fakeInputSymbols, CommentDatabaseInternal::commentset,
// Varnode::setFlags are private by class-default, which a private->public
// macro cannot flip) uses the explicit-instantiation access tag idiom.
// Reading ScopeInternal::maptable (explicit `protected:`) additionally uses
// the protected->public define below.
#define protected public
#include "architecture.hh"
#include "comment.hh"
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
#undef protected

using namespace ghidra;

namespace {

struct FuncdataVbankTag {
  using type = VarnodeBank Funcdata::*;
  friend type access(FuncdataVbankTag);
};

struct ScopeFakeInputTag {
  using type = void (ScopeLocal::*)();
  friend type access(ScopeFakeInputTag);
};

struct CommentSetTag {
  using type = CommentSet CommentDatabaseInternal::*;
  friend type access(CommentSetTag);
};

struct VarnodeSetFlagsTag {
  using type = void (Varnode::*)(uint4) const;
  friend type access(VarnodeSetFlagsTag);
};

template <typename Tag, typename Tag::type Member>
struct PrivateAccess {
  friend typename Tag::type access(Tag) { return Member; }
};

template struct PrivateAccess<FuncdataVbankTag, &Funcdata::vbank>;
template struct PrivateAccess<ScopeFakeInputTag, &ScopeLocal::fakeInputSymbols>;
template struct PrivateAccess<CommentSetTag, &CommentDatabaseInternal::commentset>;
template struct PrivateAccess<VarnodeSetFlagsTag, &Varnode::setFlags>;

} // namespace

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

/// Per-case scope factory: a fresh Funcdata whose local ScopeLocal was built
/// by the Funcdata constructor (with the architecture default model
/// installed by FuncProto::setScope's fallback), a per-case prototype model
/// carrying the paramrange decoded through the production XML path, and the
/// observation renderer.
class FakeInputScope {
public:
  FixtureArchitecture &arch;
  AddrSpace *ram;
  AddrSpace *reg;
  AddrSpace *stack;
  AddrSpace *join;
  Funcdata fd;
  ProtoModel model;
  TypeFactory *types;

  FakeInputScope(FixtureArchitecture &a, const std::string &name,
                 const std::string &paramrange_xml)
    : arch(a), ram(a.getSpace(3)), reg(a.getSpace(4)), stack(a.getSpace(5)),
      join(a.getSpace(6)),
      fd(name, name, a.symboltab->getGlobalScope(), Address(a.getSpace(3), 0x9000),
         (FunctionSymbol *)0, 0x20),
      model(&a), types(a.types) {
    std::ostringstream xml;
    xml << "<prototype name=\"fake_input_" << name << "\" extrapop=\"0\">"
        << "<input/><output/>" << paramrange_xml << "</prototype>";
    std::istringstream stream(xml.str());
    XmlDecode decoder(&a);
    decoder.ingestStream(stream);
    model.decode(decoder);
    fd.getFuncProto().setModel(&model);
  }

  /// Create an input varnode through the production
  /// Funcdata::newVarnode + VarnodeBank::setInput pair.
  /// (bank-level setInput is the exact production entry
  /// Funcdata::setInputVarnode calls after its overlap check, so
  /// deliberately overlapping inputs can be constructed.)
  Varnode *add_input(AddrSpace *spc, uintb offset, int4 size, bool typelock) {
    Varnode *vn = fd.newVarnode(size, Address(spc, offset), (Datatype *)0);
    (fd.*access(FuncdataVbankTag{})).setInput(vn);
    if (typelock)
      (vn->*access(VarnodeSetFlagsTag{}))(Varnode::typelock);
    return vn;
  }

  /// Pre-existing parameter symbol (category 0) through the production
  /// addSymbol + setCategory APIs. Returns placeholder-consumed symbol.
  Symbol *add_param(uintb offset, int4 size) {
    Address addr(stack, offset);
    Address usepoint;
    Symbol *sym = fd.getScopeLocal()->addSymbol("", types->getBase(size, TYPE_INT), addr, usepoint)->getSymbol();
    fd.getScopeLocal()->setCategory(sym, Symbol::function_parameter, 0);
    return sym;
  }

  /// Render the complete observable post-state: every whole SymbolEntry in
  /// (space index, first, last) order with name/displayName/category/
  /// catindex/size/typelock, then the function_parameter category size,
  /// then the warning-header texts in comment order.
  void run(const char *case_name) {
    (fd.getScopeLocal()->*access(ScopeFakeInputTag{}))();
    ScopeLocal *scope = fd.getScopeLocal();

    struct Rec {
      int4 spcidx;
      uintb first;
      uintb last;
      std::string name;
      std::string disp;
      int4 cat;
      int4 catidx;
      int4 size;
      bool typelock;
      bool operator<(const Rec &op2) const {
        if (spcidx != op2.spcidx) return spcidx < op2.spcidx;
        if (first != op2.first) return first < op2.first;
        if (last != op2.last) return last < op2.last;
        return name < op2.name;
      }
    };
    std::set<const Symbol *> visited_symbols;
    std::vector<Rec> recs;
    for (int4 i = 0; i < (int4)scope->maptable.size(); ++i) {
      EntryMap *rangemap = scope->maptable[i];
      if (rangemap == (EntryMap *)0) continue;
      EntryMap::const_iterator iter, enditer;
      iter = rangemap->begin();
      enditer = rangemap->end();
      for (; iter != enditer; ++iter) {
        const SymbolEntry &entry(*iter);
        const Symbol *sym = entry.getSymbol();
        // Normalize the rangemap's overlap partition: inserting an
        // overlapping SymbolEntry splits an existing record into multiple
        // AddrRange pieces (rangemap::insert, rangemap.hh unzip), so a
        // direct maptable walk yields one line per piece. Rugra's
        // LocalSymbol models exactly one whole map per Symbol, so observe
        // the symbol-level state instead: deduplicate by Symbol identity
        // and report the first whole map extent. (For the queries in this
        // fixture the piece partition cannot change a containment answer:
        // every query range is either fully inside one piece or inside no
        // piece of the record.)
        if (!sym->getFirstWholeMap()) continue;
        if (visited_symbols.insert(sym).second == false) continue;
        const SymbolEntry &whole(*sym->getFirstWholeMap());
        Rec rec;
        rec.spcidx = whole.getAddr().getSpace()->getIndex();
        rec.first = whole.getAddr().getOffset();
        rec.last = whole.getLast();
        rec.name = sym->getName();
        rec.disp = sym->getDisplayName();
        rec.cat = (int4)sym->getCategory();
        rec.catidx = (int4)sym->getCategoryIndex();
        rec.size = whole.getSize();
        rec.typelock = sym->isTypeLocked();
        recs.push_back(rec);
      }
    }
    std::sort(recs.begin(), recs.end());

    std::ostringstream out;
    out << "case=" << case_name << "|symbols=[";
    for (size_t i = 0; i < recs.size(); ++i) {
      if (i != 0) out << ';';
      out << recs[i].spcidx << ':' << std::dec << recs[i].first << '-'
          << recs[i].last << ':' << recs[i].name << ':' << recs[i].disp << ':'
          << recs[i].cat << ':' << recs[i].catidx << ':' << recs[i].size << ':'
          << (recs[i].typelock ? 1 : 0);
    }
    out << "]|lockedinputs=" << scope->getCategorySize(Symbol::function_parameter);
    out << "|warnings=[";
    bool first = true;
    CommentDatabaseInternal *cdb = (CommentDatabaseInternal *)arch.commentdb;
    const CommentSet &commentset = cdb->*access(CommentSetTag{});
    CommentSet::const_iterator iter, enditer;
    iter = commentset.begin();
    enditer = commentset.end();
    for (; iter != enditer; ++iter) {
      if (!first) out << ';';
      first = false;
      out << (*iter)->getText();
    }
    out << "]\n";
    std::cout << out.str();
  }
};

static std::string paramrange_xml(uintb first, uintb last) {
  std::ostringstream out;
  out << "<paramrange><range space=\"stack\" first=\"" << first
      << "\" last=\"" << last << "\"/></paramrange>";
  return out.str();
}

/// Case A: first-address-only paramrange filter. The flipped negative-growth
/// local (0xfffffffffffffff0) and the below-range offset 4 are filtered;
/// offset 512 passes on its first byte even though the 8-byte extent leaves
/// the [8,515] range.
static void run_range_filter(FixtureArchitecture &arch)
{
  FakeInputScope t(arch, "range_filter", paramrange_xml(8, 515));
  t.add_input(t.stack, 0xfffffffffffffff0UL, 8, false); // negative local: filtered
  t.add_input(t.stack, 4, 8, false);                    // below range: filtered
  t.add_input(t.stack, 512, 8, false);                  // first byte in range: symbol [512,519]
  t.run("range_filter_first_byte_only");
}

/// Case B: overlap absorption. 507(+2) absorbs the overlapping 508(+4) into
/// one size-5 symbol; the standalone sibling scope proves 508 alone forms
/// its own symbol (the group-skip in the first scope is absorption).
static void run_overlap_absorb(FixtureArchitecture &arch)
{
  {
    FakeInputScope t(arch, "overlap_absorb", paramrange_xml(8, 515));
    t.add_input(t.stack, 507, 2, false);
    t.add_input(t.stack, 508, 4, false);
    t.run("overlap_absorb_507_merges_508");
  }
  {
    FakeInputScope t(arch, "overlap_standalone", paramrange_xml(8, 515));
    t.add_input(t.stack, 508, 4, false);
    t.run("overlap_standalone_508");
  }
}

/// Case C: adjacent (non-overlapping) inputs do NOT merge: endpoint 107 <
/// next offset 108 breaks the inner loop (varmap.cc:1412).
static void run_adjacent_no_merge(FixtureArchitecture &arch)
{
  FakeInputScope t(arch, "adjacent", paramrange_xml(8, 515));
  t.add_input(t.stack, 100, 8, false);
  t.add_input(t.stack, 108, 8, false);
  t.run("adjacent_no_merge");
}

/// Case D: cross-space iteration. The register input (space index 4 < 5)
/// hits the outer continue; the join input (index 6 > 5) breaks the inner
/// merge loop of the 0x10 group without ending the scan (0x20 still forms).
static void run_cross_space(FixtureArchitecture &arch)
{
  FakeInputScope t(arch, "cross_space", paramrange_xml(8, 515));
  t.add_input(t.reg, 0x0, 8, false);    // earlier space: outer continue
  t.add_input(t.stack, 0x10, 8, false);
  t.add_input(t.join, 0x0, 8, false);   // later space: inner-loop break
  t.add_input(t.stack, 0x20, 8, false);
  t.run("cross_space_break_and_continue");
}

/// Case E: typelock. The typelocked 0x14 member skips the whole 0x10 group;
/// the later 0x30 group still creates its symbol.
static void run_typelock(FixtureArchitecture &arch)
{
  FakeInputScope t(arch, "typelock", paramrange_xml(8, 515));
  t.add_input(t.stack, 0x10, 8, false);
  t.add_input(t.stack, 0x14, 4, true); // typelocked member: group skipped
  t.add_input(t.stack, 0x30, 8, false);
  t.run("typelock_group_skip");
}

/// Case F: lockedinputs != 0, breaker covered. The parameter symbol
/// [0x38,0x3f] contains the breaker varnode's extent, so the group starting
/// at 0x30 is skipped; the 0x38 group is skipped too (its own probe hits the
/// same parameter symbol). No fake-input symbols at all.
static void run_locked_breaker(FixtureArchitecture &arch)
{
  FakeInputScope t(arch, "locked_breaker", paramrange_xml(8, 515));
  t.add_input(t.stack, 0x30, 4, false);
  t.add_input(t.stack, 0x38, 8, false);
  t.add_param(0x38, 8);
  t.run("lockedinputs_breaker_covered_skip");
}

/// Case G: lockedinputs != 0, only the leader covered. The parameter symbol
/// [0x30,0x37] contains the group leader (0x30,+4) but NOT the breaker
/// (0x40), so the probe (which queries the breaker, varmap.cc:1430) finds
/// nothing and the fake-input symbol IS created — overlapping the parameter.
static void run_locked_leader_only(FixtureArchitecture &arch)
{
  FakeInputScope t(arch, "locked_leader", paramrange_xml(8, 515));
  t.add_input(t.stack, 0x30, 4, false);
  t.add_input(t.stack, 0x40, 8, false);
  t.add_param(0x30, 8);
  t.run("lockedinputs_leader_covered_no_skip");
}

/// Case H: flipped paramrange at the top of the space. The 0xff...ff9c group
/// forms normally; the 0xff...fffd leader wraps the 2^64 boundary, its
/// addSymbol throws "extends beyond the end of the address space"
/// (database.cc:1855-1861), the catch routes it to warningHeader
/// (varmap.cc:1443-1445), and the scan had already completed the earlier
/// group (continuation).
static void run_flipped_wrap(FixtureArchitecture &arch)
{
  FakeInputScope t(arch, "flipped_wrap",
                   paramrange_xml(0xffffffffffffff00UL, 0xffffffffffffffffUL));
  t.add_input(t.stack, 0xffffffffffffff9cUL, 8, false); // symbol [..9c,..a3]
  t.add_input(t.stack, 0xfffffffffffffffdUL, 8, false); // wraps: LowlevelError
  t.run("flipped_wraparound_exception_continue");
}

int main(void) {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  std::cout << "schema=1|fixture=VARMAP-FAKEINPUT-0001|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture arch;
    run_range_filter(arch);
    run_overlap_absorb(arch);
    run_adjacent_no_merge(arch);
    run_cross_space(arch);
    run_typelock(arch);
    run_locked_breaker(arch);
    run_locked_leader_only(arch);
    run_flipped_wrap(arch);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  return 0;
}
