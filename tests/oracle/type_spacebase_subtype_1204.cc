/*
 * TYPE-SPACEBASE-SUBTYPE-DISPATCH-0001: locked Ghidra 12.0.4
 * TypeSpacebase::getSubType / TypePointer::isPtrsubMatching oracle.
 *
 * Observations are emitted as `key=value` records on stdout:
 *   - getSubType symbol hit / mid-symbol / miss / end-boundary,
 *     serialized as `<metaname>:<size>:<renormalized offset>`;
 *   - TypePointer::isPtrsubMatching SPACEBASE-gate verdicts (0/1).
 */
#include "architecture.hh"
#include "database.hh"
#include "type.hh"
#include "translate.hh"
#include "varnode.hh"

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;
using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;

public:
  FixtureTranslate()
  {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false,
                              8, 1, 1, AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register",
                                   false, 8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this, this, "stack", 5, 8,
                                               ram, 1, true);
    insertSpace(stack);
    VarnodeData stackPointer;
    stackPointer.space = reg;
    stackPointer.offset = 0;
    stackPointer.size = 8;
    addSpacebasePointer(stack, stackPointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false,
                              8, 1, 6, AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummyRegister.space = reg;
    dummyRegister.offset = 0;
    dummyRegister.size = 4;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override {
    return dummyRegister;
  }
  string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(map<VarnodeData, string> &) const override {}
  void getUserOpNames(vector<string> &) const override {}
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
  FixtureArchitecture()
  {
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
    max_basetype_size = 10;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("xbool1", 1, TYPE_BOOL, false);
    types->cacheCoreTypes();
    // The global scope is attached by main() as the ProbeScope under test,
    // so getGlobalScope() (TypeSpacebase::getMap, type.cc:2938) returns it.
    symboltab = new Database(this, false);
  }

  void printMessage(const string &) const override {}
};

// Probe subclasses reach the protected members the production importers
// exercise when materializing address-tied global symbols.
class ProbeSymbol final : public Symbol {
public:
  ProbeSymbol(Scope *sc, const string &nm, Datatype *ct)
    : Symbol(sc, nm, ct) {}
  void forceAddrTied(void) { flags |= Varnode::addrtied; }
};

class ProbeScope final : public ScopeInternal {
public:
  ProbeScope(uint8 id, const string &nm, Architecture *g)
    : ScopeInternal(id, nm, g) {}
  SymbolEntry *addProbeSymbol(const string &nm, Datatype *ct,
                              const Address &addr)
  {
    ProbeSymbol *sym = new ProbeSymbol(this, nm, ct);
    sym->forceAddrTied();
    addSymbolInternal(sym);
    return addMapPoint(sym, addr, Address());
  }
};

class FixtureConf final : public TypeStruct {
public:
  explicit FixtureConf(TypeFactory *types)
  {
    vector<TypeField> fields;
    fields.push_back(TypeField(0, 0, "lo", types->getBase(8, TYPE_UINT)));
    fields.push_back(TypeField(1, 8, "hi", types->getBase(8, TYPE_UINT)));
    name = "Conf";
    displayName = name;
    setFields(fields, 16, 8);
    markComplete();
  }
};

string describeSubType(const Datatype *subType, int8 newoff)
{
  if (subType == (const Datatype *)0)
    return "none:0:" + to_string(newoff);
  string meta;
  metatype2string(subType->getMetatype(), meta);
  ostringstream stream;
  stream << meta << ':' << subType->getSize() << ':' << newoff;
  return stream.str();
}

} // namespace

int main(void)
{
  cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  FixtureArchitecture architecture;
  TypeFactory *types = architecture.types;
  AddrSpace *ram = architecture.getSpace(3);

  ProbeScope *probeScope = new ProbeScope(0x202, "", &architecture);
  architecture.symboltab->attachScope(probeScope, (Scope *)0);

  FixtureConf conf(types);
  const uintb configAddr = 0x1000;
  probeScope->addProbeSymbol("config", &conf, Address(ram, configAddr));

  TypeSpacebase *spacebase = types->getTypeSpacebase(ram, Address());

  // --- TypeSpacebase::getSubType (type.cc:2947) ---
  int8 newoff = -1;
  Datatype *sub = spacebase->getSubType((int8)configAddr, &newoff);
  cout << "subtype.hit_start=" << describeSubType(sub, newoff) << '\n';

  sub = spacebase->getSubType((int8)(configAddr + 8), &newoff);
  cout << "subtype.hit_mid=" << describeSubType(sub, newoff) << '\n';

  sub = spacebase->getSubType((int8)0x2000, &newoff);
  cout << "subtype.miss_gap=" << describeSubType(sub, newoff) << '\n';

  sub = spacebase->getSubType((int8)(configAddr + 16), &newoff);
  cout << "subtype.hit_endboundary=" << describeSubType(sub, newoff) << '\n';

  // --- TypePointer::isPtrsubMatching SPACEBASE arm (type.cc:1123) ---
  TypePointer *ptr = types->getTypePointer(8, spacebase, 1);
  cout << "gate.hit_extra0="
       << (ptr->isPtrsubMatching((int8)configAddr, 0, 0) ? 1 : 0) << '\n';
  cout << "gate.hit_extra8="
       << (ptr->isPtrsubMatching((int8)configAddr, 8, 0) ? 1 : 0) << '\n';
  cout << "gate.hit_extra16="
       << (ptr->isPtrsubMatching((int8)configAddr, 16, 0) ? 1 : 0) << '\n';
  cout << "gate.midsym="
       << (ptr->isPtrsubMatching((int8)(configAddr + 8), 0, 0) ? 1 : 0) << '\n';
  cout << "gate.miss_extra0="
       << (ptr->isPtrsubMatching((int8)0x2000, 0, 0) ? 1 : 0) << '\n';
  cout << "gate.miss_extra8="
       << (ptr->isPtrsubMatching((int8)0x2000, 8, 0) ? 1 : 0) << '\n';
  return 0;
}
