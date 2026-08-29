/* VARMAP-DUPDECL-0001: default-name shared-counter fixture.
 *
 * Pins the single shared `int4 base` counter semantics of
 * ScopeInternal::buildVariableName's local-variable arm
 * (database.cc:2501-2504 `s << "Var" << dec << index++`): the
 * ActionNameVars namerec loop (coreaction.cc:2988-2997) and the trailing
 * assignDefaultNames (coreaction.cc:2998, database.cc:2850-2864) draw from
 * ONE monotonically increasing sequence across every printNameBase prefix,
 * so no two distinct symbols can receive the same `<prefix>Var<num>` name —
 * the invariant whose violation produces duplicate C declarations
 * (`int iVar3;` twice, the 181538f numbering family).
 */
#include <bits/stdc++.h>

#include "architecture.hh"
#include "capability.hh"
#include "coreaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"

using namespace std;
using namespace ghidra;

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
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, ram, 1, true);
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
    dummyRegister.size = 8;
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
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const string &) const override {}
};

int main(void)
{
  cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  cout << "schema=1|fixture=VARMAP-DUPDECL-0001"
       << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    TypeFactory *types = architecture.types;

    /* Named atomic types (the SLEIGH core spellings the Rust twin's
     * Standalone factory pre-registers) so printNameBase derives the
     * i/u/f/c prefixes exactly like the platform core types (type.hh:273). */
    Datatype *intType = types->getBase(4, TYPE_INT, "int4");
    Datatype *uintType = types->getBase(4, TYPE_UINT, "uint4");
    Datatype *floatType = types->getBase(4, TYPE_FLOAT, "float4");
    Datatype *charType = types->getBase(1, TYPE_INT, "char");
    Datatype *longType = types->getBase(8, TYPE_INT, "int8");
    Datatype *intPointer = types->getTypePointer(8, intType, 1);

    ScopeInternal scope(0x102, "dupdecl", &architecture);

    /* Six $$undef symbols mapped with a valid usepoint (so
     * buildDefaultName's no-varnode path takes flags == 0, the local-variable
     * arm, on both sides). */
    vector<Symbol *> symbols;
    vector<Datatype *> typesForSymbols;
    typesForSymbols.push_back(intType);
    typesForSymbols.push_back(uintType);
    typesForSymbols.push_back(floatType);
    typesForSymbols.push_back(charType);
    typesForSymbols.push_back(longType);
    typesForSymbols.push_back(intPointer);
    for (int4 index = 0; index < (int4)typesForSymbols.size(); ++index) {
      SymbolEntry *entry = scope.addSymbol(
          "", typesForSymbols[index], Address(ram, 0x6000 + index * 8),
          Address(ram, 0x7000 + index));
      symbols.push_back(entry->getSymbol());
    }

    /* Phase 1: the ActionNameVars namerec loop — the first two
     * still-undefined symbols draw default names from the shared base
     * (coreaction.cc:2992-2996). */
    int4 base = 1;
    for (int4 index = 0; index < 2; ++index) {
      if (symbols[index]->isNameUndefined()) {
        string newname = scope.buildDefaultName(symbols[index], base,
                                                (Varnode *)0);
        scope.renameSymbol(symbols[index], newname);
      }
    }
    /* Phase 2: assignDefaultNames continues with the SAME counter
     * (coreaction.cc:2998). */
    scope.assignDefaultNames(base);

    for (int4 index = 0; index < (int4)symbols.size(); ++index) {
      cout << "name" << index << '=' << symbols[index]->getName() << '\n';
    }
    cout << "base=" << base << '\n';
  }
  catch (const LowlevelError &error) {
    cout << "exception|phase=run|what=" << error.explain << '\n';
    return 1;
  }
  catch (const exception &error) {
    cout << "exception|phase=run|what=" << error.what() << '\n';
    return 1;
  }
  return 0;
}
