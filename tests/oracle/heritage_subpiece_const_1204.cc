/*
 * HERITAGE-SUBPIECE-CONST-1204: locked Ghidra 12.0.4 oracle for the
 * HERITAGE-GUARD-SUBPIECE-CONST-0001 fix — the SUBPIECE truncate
 * constants of Heritage::guardOutputOverlapStack (heritage.cc:1336/1358).
 *
 *  - case=stack_guard_full: the production Heritage::guardOutputOverlapStack
 *    (heritage.cc:1322-1375) driven directly on a real Funcdata with one
 *    CALL op, over five geometries covering every trigger combination:
 *    front+back (x2, one with the call output pre-existing so cc:1329's
 *    getOut()!=null branch runs), back-only (sizeFront==0), front-only
 *    (sizeBack==0). The projection prints every op of the call block in
 *    insertion order (INDIRECT / SUBPIECE / CALL / PIECE ordering pins the
 *    cc:1327 insertPoint chain: opInsertAfter(concatBack, insertPoint)
 *    lands AFTER the front concat) with the SUBPIECE in[1] constants —
 *    the decisive observation. LE truth: front constant = 0 (cc:1336,
 *    op2 == addr), back constant = sizeFront + retSize (cc:1358, addrBack
 *    = retAddr + retSize). The pre-fix Rugra code hardcoded BOTH to 0, so
 *    SUBPIECE(whole, 0) extracted the FRONT bytes for the back piece.
 *  - case=front_back_constant: the exact cc:1336/cc:1358 call shapes
 *    addr.justifiedContain(size, addr, sizeFront, false) and
 *    addr.justifiedContain(size, addrBack, sizeBack, false) on the same
 *    geometries in both a little-endian and a big-endian processor space
 *    (address.cc:138-141 branch key base->isBigEndian() && !forceleft):
 *    LE front 0 / back sizeFront+retSize, BE front size-sizeFront /
 *    back size-sizeFront-retSize-sizeBack = 0.
 *
 * Varnode descriptor shared with the Rust comparand:
 *   constant -> c<size>(<value>); iop -> IOP;
 *   other    -> <hexoffset>:<size>:<I|W|F>{ah}
 * Space letters are deliberately not printed: Rugra's transitional
 * new_varnode_out creates its output varnodes in the register space while
 * Ghidra uses the range space (retAddr) — a registered projected-away
 * divergence that cannot affect the SUBPIECE constants, the op order or
 * the sizes, which are the observations of this fixture.
 */

#include <bits/stdc++.h>

// heritage.hh:296 keeps guardOutputOverlapStack private; the fixture drives
// it directly, so the includes take the class->struct access hack (the same
// pattern as the justified_contain_1204 / fspec_endian_resolver_1204
// fixtures).
#define class struct
#define private public
#define protected public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "heritage.hh"
#include "libdecomp.hh"
#include "op.hh"
#include "opcodes.hh"
#include "space.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef protected
#undef private
#undef class

using namespace ghidra;

// Test-only layout shim mirroring the locked-oracle Funcdata member
// sequence (funcdata.hh:57-95, pinned to commit
// e40ed13014025f82488b1f8f7bca566894ac376b). With the class->struct access
// hack the private members are already public, but the heritage member is
// kept for documentary parity with the heritage_callguard2_1204 fixture.
struct FuncdataHeritageShim {
  uint4 flags;
  uint4 clean_up_index;
  uint4 high_level_index;
  uint4 cast_phase_index;
  uint4 minLanedSize;
  int4 size;
  Architecture *glb;
  FunctionSymbol *functionSymbol;
  string name;
  string displayName;
  Address baseaddr;
  FuncProto funcp;
  ScopeLocal *localmap;
  vector<FuncCallSpecs *> qlst;
  vector<JumpTable *> jumpvec;
  VarnodeBank vbank;
  PcodeOpBank obank;
  BlockGraph bblocks;
  BlockGraph sblocks;
  Heritage heritage;
};

static Heritage &heritageOf(Funcdata &fd)
{
  return reinterpret_cast<FuncdataHeritageShim *>(&fd)->heritage;
}

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new OtherSpace(this, this, OtherSpace::INDEX));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                              8, 1, 3, AddrSpace::hasphysical, 0, 0));
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register",
                                   false, 8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, getSpaceByName("ram"), 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "ram_be", true,
                              8, 1, 6, AddrSpace::hasphysical, 0, 0));
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
    types->setupSizes();
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    // Funcdata's ctor runs FuncProto::setScope -> setModel(defaultfp)
    // (fspec.cc:3879-3884) before ScopeLocal::resetLocalWindow dereferences
    // the model, so a default ProtoModel must exist (same shape as the
    // heritage_callguard2_1204 fixture; its entries are inert for the
    // direct guardOutputOverlapStack drive).
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"subpieceguard\" extrapop=\"0\" strategy=\"standard\">"
        "<input>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x30\" size=\"8\"/></pentry>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x38\" size=\"8\"/></pentry>"
        "</input>"
        "<output>"
        "<pentry minsize=\"1\" maxsize=\"8\"><addr space=\"register\" offset=\"0x0\" size=\"8\"/></pentry>"
        "</output>"
        "</prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const std::string &) const override {}
};

// Varnode descriptor shared with the Rust comparand (see the file header).
static std::string vnDescriptor(const Varnode *vn)
{
  if (vn == (Varnode *)0)
    return "-";
  if (vn->isConstant()) {
    std::ostringstream out;
    out << 'c' << vn->getSize() << '(' << std::dec << vn->getOffset() << ')';
    return out.str();
  }
  AddrSpace *spc = vn->getSpace();
  if (spc->getType() == IPTR_IOP)
    return "IOP";
  std::ostringstream out;
  out << std::hex << vn->getOffset() << std::dec << ':' << vn->getSize() << ':';
  if (vn->isInput())
    out << 'I';
  else if (vn->isWritten())
    out << 'W';
  else
    out << 'F';
  out << '{';
  if (vn->isActiveHeritage())
    out << "ah";
  out << '}';
  return out.str();
}

struct SgGeom { uintb addr; int4 size; uintb ret; int4 retsz; bool pre_out; };

// The five trigger geometries (addr/ret in the LE stack space):
//   0: front+back (4+8) around ret(4) of 16, call without output
//   1: front+back (2+2) around ret(4) of 8
//   2: back only (sizeFront == 0)
//   3: front only (sizeBack == 0)
//   4: front+back (8+4) around ret(4) of 16, call WITH a pre-existing
//      output (cc:1329 getOut() != null branch)
static const SgGeom SG[] = {
  {0x1000, 16, 0x1004, 4, false},
  {0x2000, 8, 0x2002, 4, false},
  {0x3000, 8, 0x3000, 4, false},
  {0x4000, 12, 0x4002, 10, false},
  {0x5000, 16, 0x5008, 4, true},
};
static const int4 NUM_SG = 5;

// Drive the production guardOutputOverlapStack on one geometry and print
// the full op projection of the call block plus the write-list entry.
static void runGuardCase(FixtureArchitecture &arch, const SgGeom &g, int4 index)
{
  Funcdata fd("sg", "sg", arch.symboltab->getGlobalScope(),
              Address(arch.getSpace(3), 0x6000 + 0x10 * index),
              (FunctionSymbol *)0, 0x20);
  AddrSpace *stack = arch.getSpaceByName("stack");
  BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(&fd);
  PcodeOp *call = fd.newOp(1, fd.getAddress());
  fd.opSetOpcode(call, CPUI_CALL);
  fd.opSetInput(call, fd.newConstant(8, 0x4000), 0);
  fd.opInsertEnd(call, block);
  if (g.pre_out)
    fd.newVarnodeOut(g.retsz, Address(stack, g.ret), call);

  vector<Varnode *> write;
  heritageOf(fd).guardOutputOverlapStack(call, Address(stack, g.addr),
                                         g.size, Address(stack, g.ret),
                                         g.retsz, write);

  int4 sf = (int4)(g.ret - g.addr);
  int4 sb = g.size - g.retsz - sf;
  std::cout << "gs geom=" << index << " addr=" << std::hex << g.addr << std::dec
       << " size=" << g.size << " ret=" << std::hex << g.ret << std::dec
       << " retsz=" << g.retsz << " sf=" << sf << " sb=" << sb << '\n';
  int4 pos = 0;
  for (list<PcodeOp *>::const_iterator iter = block->beginOp();
       iter != block->endOp(); ++iter, ++pos) {
    PcodeOp *op = *iter;
    // Opcode number, not name: Ghidra's get_opname(CPUI_INDIRECT) prints
    // "DELAY_SLOT" (opcodes.cc:45) while Rugra's name() prints "INDIRECT";
    // the numeric codes (CALL=7, INDIRECT=61, PIECE=62, SUBPIECE=63) are
    // identical on both sides.
    std::cout << "  op" << pos << ' ' << (int4)op->code() << " in=[";
    for (int4 i = 0; i < op->numInput(); ++i) {
      if (i != 0)
        std::cout << ',';
      std::cout << vnDescriptor(op->getIn(i));
    }
    std::cout << "] out=" << vnDescriptor(op->getOut()) << '\n';
  }
  if (!write.empty())
    std::cout << "  write " << vnDescriptor(write.back()) << '\n';
}

int main(void)
{
  std::cout << std::unitbuf;
  vector<string> spec_paths;
  startDecompilerLibrary(spec_paths);
  FixtureArchitecture arch;
  std::cout << "schema=1|fixture=HERITAGE-SUBPIECE-CONST-1204|"
          "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
       << std::endl;

  // ---- case 1: production guardOutputOverlapStack ---------------------
  std::cout << "case=stack_guard_full" << std::endl;
  for (int4 i = 0; i < NUM_SG; ++i)
    runGuardCase(arch, SG[i], i);

  // ---- case 2: cc:1336/cc:1358 constants in LE and BE spaces ----------
  std::cout << "case=front_back_constant" << std::endl;
  AddrSpace *le = arch.getSpaceByName("ram");
  AddrSpace *be = arch.getSpaceByName("ram_be");
  for (int4 i = 0; i < NUM_SG; ++i) {
    const SgGeom &g = SG[i];
    int4 sf = (int4)(g.ret - g.addr);
    int4 sb = g.size - g.retsz - sf;
    uintb addrBackOff = g.ret + g.retsz;
    int4 amt[2][2];
    for (int e = 0; e < 2; ++e) {
      AddrSpace *spc = (e == 0) ? le : be;
      amt[e][0] = Address(spc, g.addr).justifiedContain(
          g.size, Address(spc, g.addr), sf, false);
      amt[e][1] = Address(spc, g.addr).justifiedContain(
          g.size, Address(spc, addrBackOff), sb, false);
    }
    std::cout << "  sp geom=" << i << " le front=" << amt[0][0]
         << " back=" << amt[0][1] << " be front=" << amt[1][0]
         << " back=" << amt[1][1] << '\n';
  }

  return 0;
}
