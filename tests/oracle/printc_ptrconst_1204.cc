/*
 * PRINTC-PTRCONST-DAT-SYMBOL-0001 locked Ghidra 12.0.4 oracle.
 *
 * This drives the real PrintC::pushConstant -> pushPtrCharConstant ->
 * printCharacterConstant path (printc.cc:1744/1698/1534) and the TYPE_SPACEBASE
 * arm of PrintC::opPtrsub (printc.cc:1057-1097).  Typed constants are
 * installed as slot-1 inputs of CALL PcodeOps so resolveConstant observes the
 * consuming operation's address; the PTRSUB records give in(1) a SymbolEntry
 * (the &DAT_* form) or none (the unnamed-location form).
 *
 * stringManager is the DECLARED GhidraStringManager/Java contract (same
 * subclass shape as tests/oracle/stringmanager_core_1204.cc): detection =
 * charset-valid + NUL-terminated with no 2048-byte search bound, the return
 * truncated at 2048 characters with isTruncated set by assignStringData.
 * The fixture loader, readonly property map, contextual AddressResolver,
 * Database, and explicit DAT Symbol are production Ghidra objects.
 */

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Test-only exposure permits this op-level fixture to call the private
// pushConstant leaf entry without changing the locked oracle sources.
#define private public
#include "architecture.hh"
#include "capability.hh"
#include "comment.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "loadimage.hh"
#include "marshal.hh"
#include "printc.hh"
#include "prettyprint.hh"
#include "stringmanage.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "variable.hh"
#include "varnode.hh"
#undef private

using namespace ghidra;

namespace {

class ContextResolver final : public AddressResolver {
  AddrSpace *ram;

public:
  explicit ContextResolver(AddrSpace *space) : ram(space) {}

  Address resolve(uintb value, int4 size, const Address &point,
                  uintb &fullEncoding) override {
    // size==8 is the ptr-char constant; size==-1 is the global-spacebase
    // sentinel of TypeSpacebase::getAddress (type.cc:3063-3071, "prevent
    // recovery of full encoding").
    if (size != 8 && size != -1)
      throw LowlevelError("ptrconst fixture expected an 8-byte pointer");
    uintb resolved = value;
    if (value == 0x40 && point.getOffset() == 0x5000)
      resolved = 0x2000;
    else if (value == 0x40 && point.getOffset() == 0x5008)
      resolved = 0x2303;
    fullEncoding = resolved;
    return Address(ram, resolved);
  }
};

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1,
                              1, AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false, 8,
                                   1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack =
        new SpacebaseSpace(this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stackPointer;
    stackPointer.space = reg;
    stackPointer.offset = 0;
    stackPointer.size = 8;
    addSpacebasePointer(stack, stackPointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1,
                              6, AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    setDefaultDataSpace(3);
    dummyRegister.space = getSpace(4);
    dummyRegister.offset = 0;
    dummyRegister.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummyRegister;
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

class FixtureLoadImage final : public LoadImage {
  struct Region {
    uintb start;
    std::vector<uint1> bytes;
  };

  AddrSpace *ram;
  std::vector<Region> regions;
  std::map<uintb, int4> reads;

  void addRegion(uintb start, const std::vector<uint1> &initial,
                 uintb padded) {
    Region region;
    region.start = start;
    region.bytes.assign(padded, 0);
    std::copy(initial.begin(), initial.end(), region.bytes.begin());
    regions.push_back(region);
  }

public:
  explicit FixtureLoadImage(AddrSpace *space)
      : LoadImage("printc-ptrconst-1204"), ram(space) {
    addRegion(0x2000, {'a', 'l', 'p', 'h', 'a', 0}, 0x100);
    addRegion(0x2100, {'b', 0xad, 0}, 0x100);
    addRegion(0x2200, {'w', 'r', 'i', 't', 'a', 'b', 'l', 'e', 0}, 0x100);
    addRegion(0x2300, {'p', 'r', 'e', 'f', 'i', 'x', 0}, 0x100);
    // 2050 'A's then the NUL: under the declared Java contract the detection
    // is unbounded, the return truncates at 2048 chars with isTrunc set.
    std::vector<uint1> longString(2050, 'A');
    longString.push_back(0);
    addRegion(0x2400, longString, 0xc00);
  }

  void loadFill(uint1 *ptr, int4 size, const Address &address) override {
    if (address.getSpace() != ram)
      throw DataUnavailError("ptrconst fixture read from a non-RAM space");
    const uintb start = address.getOffset();
    const uintb end = start + size;
    for (const Region &region : regions) {
      if (start >= region.start &&
          end <= region.start + region.bytes.size()) {
        const size_t offset = static_cast<size_t>(start - region.start);
        std::copy(region.bytes.begin() + offset,
                  region.bytes.begin() + offset + size, ptr);
        reads[start] += 1;
        return;
      }
    }
    throw DataUnavailError("ptrconst fixture read outside a region");
  }

  std::string getArchType() const override { return "fixture:x86:LE:64"; }
  void adjustVma(long) override {}

  int4 readCount(uintb address) const {
    std::map<uintb, int4>::const_iterator iter = reads.find(address);
    return iter == reads.end() ? 0 : iter->second;
  }
};

/// The DECLARED Java contract manager (production shape), identical to
/// tests/oracle/stringmanager_core_1204.cc: string_ghidra.cc:42-56 control
/// flow — cache hit, entry allocation before the read, opaque early-exit,
/// then unbounded detection (charset-valid + NUL termination) over the real
/// stringmanage.cc primitives, with assignStringData performing the
/// 2048-char return truncation + isTruncated.
class ContractStringManager final : public StringManager {
  LoadImage *loader;

public:
  ContractStringManager(Architecture *g, int4 max)
      : StringManager(max), loader(g->loader) {}

  const vector<uint1> &getStringData(const Address &addr, Datatype *charType,
                                     bool &isTrunc) override {
    map<Address, StringData>::iterator iter;
    iter = stringMap.find(addr);
    if (iter != stringMap.end()) {
      isTrunc = (*iter).second.isTruncated;
      return (*iter).second.byteData;
    }

    StringData &stringData(stringMap[addr]); // Allocate before reading.
    stringData.isTruncated = false;
    isTrunc = false;

    if (charType->isOpaqueString()) // stringmanage.cc:441-442
      return stringData.byteData;

    const int4 charsize = charType->getSize();
    std::vector<uint1> buffer;
    bool foundTerminator = false;
    try {
      do {
        const int4 amount = 32; // Grab 32 bytes of image at a time.
        buffer.resize(buffer.size() + amount);
        loader->loadFill(buffer.data() + buffer.size() - amount, amount,
                         addr + buffer.size() - amount);
        foundTerminator = hasCharTerminator(buffer.data() + buffer.size() - amount,
                                            amount, charsize);
      } while (!foundTerminator);
    } catch (DataUnavailError &err) {
      return stringData.byteData; // Empty buffer stays cached.
    }

    const int4 size = (int4)buffer.size();
    const int4 numChars = checkCharacters(buffer.data(), size, charsize,
                                          addr.isBigEndian());
    if (numChars < 0)
      return stringData.byteData; // Invalid encoding stays cached empty.
    assignStringData(stringData, buffer.data(), size, charsize, numChars,
                     addr.isBigEndian());
    isTrunc = stringData.isTruncated;
    return stringData.byteData;
  }
};

class FixtureArchitecture final : public Architecture {
  FixtureLoadImage *fixtureLoader;

protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary() override {
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
  void resolveArchitecture() override {}

public:
  FixtureArchitecture() : fixtureLoader((FixtureLoadImage *)0) {
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
    AddrSpace *ram = getSpace(3);
    insertResolver(ram, new ContextResolver(ram));

    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("void", 1, TYPE_VOID, false);
    types->setCoreType("bool", 1, TYPE_BOOL, false);
    types->setCoreType("uint1", 1, TYPE_UINT, false);
    types->setCoreType("uint2", 2, TYPE_UINT, false);
    types->setCoreType("uint4", 4, TYPE_UINT, false);
    types->setCoreType("uint8", 8, TYPE_UINT, false);
    types->setCoreType("int1", 1, TYPE_INT, false);
    types->setCoreType("int2", 2, TYPE_INT, false);
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
    types->setCoreType("float4", 4, TYPE_FLOAT, false);
    types->setCoreType("float8", 8, TYPE_FLOAT, false);
    types->setCoreType("float10", 10, TYPE_FLOAT, false);
    types->setCoreType("float16", 16, TYPE_FLOAT, false);
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("code", 1, TYPE_CODE, false);
    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("wchar2", 2, TYPE_INT, true);
    types->setCoreType("wchar4", 4, TYPE_INT, true);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);

    fixtureLoader = new FixtureLoadImage(ram);
    loader = fixtureLoader;
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    stringManager = new ContractStringManager(this, 2048);
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
  FixtureLoadImage *getFixtureLoader() const { return fixtureLoader; }
};

class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *architecture)
      : PrintC(architecture, "printc-ptrconst-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  void bind(std::ostream &output) { setOutputStream(&output); }
  void renderConstant(uintb value, Datatype *type, const Varnode *vn,
                      const PcodeOp *op) {
    pushConstant(value, type, vartoken, vn, op);
  }
  void renderPtrsub(const PcodeOp *op) { opPtrsub(op); }
};

Varnode *typedConstant(Funcdata &fd, uintb value, Datatype *pointer) {
  Varnode *varnode = fd.newConstant(8, value);
  varnode->updateType(pointer);
  new HighVariable(varnode);
  return varnode;
}

PcodeOp *callOp(Funcdata &fd, Varnode *input, uintb usepoint) {
  AddrSpace *code = fd.getArch()->getDefaultCodeSpace();
  PcodeOp *op = fd.newOp(2, Address(code, usepoint));
  fd.opSetOpcode(op, CPUI_CALL);
  fd.opSetInput(op, fd.newConstant(8, 0), 0);
  fd.opSetInput(op, input, 1);
  return op;
}

/// PTRSUB(spacebase-pointer, constant) with the constant optionally mapped
/// to the DAT Symbol as a constant-address reference, mirroring the
/// ActionMapGlobals state that backs the `&DAT_*` form (printc.cc:1057-1097
/// reads in(1)'s HighVariable symbol, attached for constants via
/// HighVariable::setSymbolReference, variable.cc:283-289, offset 0).
PcodeOp *spacebasePtrsub(Funcdata &fd, Architecture *architecture,
                         Datatype *spacebasePointer, SymbolEntry *datEntry,
                         uintb offset, uintb usepoint) {
  AddrSpace *code = architecture->getDefaultCodeSpace();
  PcodeOp *op = fd.newOp(2, Address(code, usepoint));
  fd.opSetOpcode(op, CPUI_PTRSUB);
  Varnode *base = fd.newConstant(8, 0);
  base->updateType(spacebasePointer);
  new HighVariable(base);
  fd.opSetInput(op, base, 0);
  Varnode *off = fd.newConstant(8, offset);
  HighVariable *offHigh = new HighVariable(off);
  if (datEntry != (SymbolEntry *)0)
    offHigh->setSymbolReference(datEntry->getSymbol(), 0);
  fd.opSetInput(op, off, 1);
  return op;
}

} // namespace

int main() {
  try {
    AttributeId::initialize();
    ElementId::initialize();
    CapabilityPoint::initializeAll();
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    architecture.symboltab->setPropertyRange(
        Varnode::readonly, Range(ram, 0x2000, 0x21ff));
    architecture.symboltab->setPropertyRange(
        Varnode::readonly, Range(ram, 0x2300, 0x23ff));
    architecture.symboltab->setPropertyRange(
        Varnode::readonly, Range(ram, 0x2400, 0x2fff));

    FunctionSymbol *functionSymbol =
        architecture.symboltab->getGlobalScope()->addFunction(
            Address(ram, 0x1000), "ptrconst_fixture");
    Funcdata &fd = *functionSymbol->getFunction();
    Datatype *character = architecture.types->getTypeChar(1);
    Datatype *pointer = architecture.types->getTypePointer(8, character, 1);

    SymbolEntry *datEntry = architecture.symboltab->getGlobalScope()->addSymbol(
        "DAT_00002100", character, Address(ram, 0x2100), Address());

    FixturePrintC printer(&architecture);
    std::ostringstream output;
    printer.bind(output);

    Varnode *valid = typedConstant(fd, 0x2000, pointer);
    output << "valid_ascii=";
    printer.renderConstant(0x2000, pointer, valid, callOp(fd, valid, 0x4000));
    output << '\n';
    Varnode *validRepeat = typedConstant(fd, 0x2000, pointer);
    output << "valid_ascii_repeat=";
    printer.renderConstant(0x2000, pointer, validRepeat,
                           callOp(fd, validRepeat, 0x4008));
    output << '\n';

    Varnode *invalid = typedConstant(fd, 0x2100, pointer);
    output << "invalid_constant=";
    printer.renderConstant(0x2100, pointer, invalid, callOp(fd, invalid, 0x4010));
    output << '\n';
    Varnode *invalidRepeat = typedConstant(fd, 0x2100, pointer);
    output << "invalid_constant_repeat=";
    printer.renderConstant(0x2100, pointer, invalidRepeat,
                           callOp(fd, invalidRepeat, 0x4018));
    output << '\n';

    Varnode *truncated = typedConstant(fd, 0x2400, pointer);
    output << "trunc_literal=";
    printer.renderConstant(0x2400, pointer, truncated,
                           callOp(fd, truncated, 0x4020));
    output << '\n';

    Varnode *writable = typedConstant(fd, 0x2200, pointer);
    output << "nonreadonly=";
    printer.renderConstant(0x2200, pointer, writable,
                           callOp(fd, writable, 0x4028));
    output << '\n';

    Varnode *nullPointer = typedConstant(fd, 0, pointer);
    output << "null=";
    printer.renderConstant(0, pointer, nullPointer,
                           callOp(fd, nullPointer, 0x4030));
    output << '\n';

    Varnode *substring = typedConstant(fd, 0x2303, pointer);
    output << "substring=";
    printer.renderConstant(0x2303, pointer, substring,
                           callOp(fd, substring, 0x4038));
    output << '\n';

    Varnode *contextA = typedConstant(fd, 0x40, pointer);
    output << "context_a=";
    printer.renderConstant(0x40, pointer, contextA, callOp(fd, contextA, 0x5000));
    output << '\n';
    Varnode *contextB = typedConstant(fd, 0x40, pointer);
    output << "context_b=";
    printer.renderConstant(0x40, pointer, contextB, callOp(fd, contextB, 0x5008));
    output << '\n';

    // The &DAT_* form: PTRSUB off the global spacebase whose offset constant
    // carries the DAT SymbolEntry (printc.cc:1057-1097), and the same PTRSUB
    // without a symbol (pushUnnamedLocation, printc.cc:1078-1082).
    TypeSpacebase *spacebase =
        architecture.types->getTypeSpacebase(ram, Address());
    Datatype *spacebasePointer =
        architecture.types->getTypePointer(8, spacebase, 1);
    output << "dat_symbol=";
    printer.renderPtrsub(spacebasePtrsub(fd, &architecture, spacebasePointer,
                                         datEntry, 0x2100, 0x4040));
    output << '\n';
    output << "dat_symbol_unnamed=";
    printer.renderPtrsub(spacebasePtrsub(fd, &architecture, spacebasePointer,
                                         (SymbolEntry *)0, 0x2100, 0x4048));
    output << '\n';

    FixtureLoadImage *loader = architecture.getFixtureLoader();
    output << "reads.2000=" << loader->readCount(0x2000) << '\n'
           << "reads.2100=" << loader->readCount(0x2100) << '\n'
           << "reads.2200=" << loader->readCount(0x2200) << '\n'
           << "reads.2303=" << loader->readCount(0x2303) << '\n'
           << "reads.2400=" << loader->readCount(0x2400) << '\n';
    std::cout << output.str();
  } catch (const LowlevelError &error) {
    std::cerr << "LowlevelError: " << error.explain << std::endl;
    return 2;
  } catch (const std::exception &error) {
    std::cerr << "exception: " << error.what() << std::endl;
    return 3;
  }
  return 0;
}
