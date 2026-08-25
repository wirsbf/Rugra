/* RETURNFOLD-GAPA-PROTOTYPES-0001 fixture — the output-locked direct-attach
 * branch of ActionPrototypeTypes::apply (coreaction.cc:4637-4649) against the
 * locked Ghidra 12.0.4 oracle, driven through the production
 * ActionPrototypeTypes::apply (public, unmodified).
 *
 * Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
 *
 * Scenario A (locked int): FuncProto built the Ghidra-native way — setInternal
 * + setPieces(PrototypePieces{model,outtype=int4}) so updateAllTypes (fspec.cc
 * :4194-4224) runs model->assignParameterStorage and store->setOutput fills
 * the output ProtoParameter (type int4, storage register:0x0 from the model's
 * <output><pentry> register entry). Blocks:
 *   b0: entry fan-out (no ops)
 *   b1: RETURN @0x60010, slot0 const only          -> attach at slot 1
 *   b2: RETURN @0x60018, slot0 const + V(reg 0x40) -> attach APPENDS at slot 2
 *   b3: RETURN @0x60020, flags |= halt             -> skipped (cc:4643)
 *   b4: RETURN @0x60028, flags |= dead             -> skipped (cc:4642)
 * Scenario B (locked void): outtype void -> assignMap leaves address invalid
 * (fspec.cc:1575-1578) and cc:4639's metatype gate skips the whole loop.
 * Scenario C (unlocked): fresh Funcdata -> else-branch initActiveOutput
 * (cc:4650-4651); no varnode is attached.
 *
 * Observable projections (one stdout line per record):
 *   preX    prototype gate state: output lock + return metatype.
 *   retA    per-RETURN post state: input count, last-input descriptor
 *           (the appended locked-output varnode register:0x0:4, free — no
 *           def, not an input —, typelocked, metatype int), and for b2 the
 *           untouched pre-existing slot-1 value.
 *   orderA  the b1 attach precedes the b2 attach (VarnodeBank create index
 *           order pins the beginOp(CPUI_RETURN) address-ordered walk).
 *   pairA   the two attached varnodes are distinct objects.
 *   activeX activeoutput container presence: 0 for both locked scenarios,
 *           1 for the unlocked control (initActiveOutput).
 *   rcX     apply() return code.
 * Test-only access rewrite (#define private public / #define class struct,
 * after the standard headers so it cannot leak into libstdc++) follows the
 * reviewed tests/oracle/returnfold_gapb_1204.cc pattern: it exposes the
 * protected PcodeOp::flags for the halt/dead marker construction; apply()
 * itself is public and unmodified, and the FuncProto construction uses only
 * public API (setInternal/setPieces).
 */
#include <bits/stdc++.h>
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "coreaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "fspec.hh"
#include "grammar.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "typeop.hh"

using namespace std;
using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
public:
  VarnodeData dummyRegister;
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this,this));
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"other",false,8,1,1,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new UniqueSpace(this,this,2,0));
    AddrSpace *ram = new AddrSpace(this,this,IPTR_PROCESSOR,"ram",false,8,1,3,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this,this,IPTR_PROCESSOR,"register",false,8,1,4,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this,this,"stack",5,8,ram,1,true);
    insertSpace(stack);
    VarnodeData stackPointer = { reg, 0, 8 };
    addSpacebasePointer(stack,stackPointer,8,true);
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"join",false,8,1,6,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new IopSpace(this,this,7));
    setDefaultCodeSpace(3);
    dummyRegister = { reg, 0, 8 };
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummyRegister; }
  string getRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  void getAllRegisters(map<VarnodeData,string> &) const override {}
  void getUserOpNames(vector<string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &,const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &,const Address &) const override { return 0; }
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
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1",1,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown2",2,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown4",4,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown8",8,TYPE_UNKNOWN,false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst,types,translate);
    symboltab = new Database(this,false);
    symboltab->attachScope(new ScopeInternal(0x101,"",this),(Scope *)0);
    // The model mirrors Rugra's ProtoModel::default_x86_64 output entry:
    // one register-space output at offset 0, minsize 1 / maxsize 8,
    // inttype small-size extension. Every <register name> resolves through
    // FixtureTranslate::getRegister to register:0x0:8.
    ProtoModel *model = new ProtoModel(this);
    istringstream stream("<prototype name=\"fixture\" extrapop=\"0\">"
                         "<input/>"
                         "<output><pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\">"
                         "<register name=\"outreg\"/>"
                         "</pentry></output>"
                         "</prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }
  void printMessage(const string &) const override {}
};

class Fixture {
  Funcdata &fd;
  AddrSpace *code;
  vector<FlowBlock *> blocks;
  uintb nextPc;

public:
  explicit Fixture(Funcdata &f, uintb basePc)
    : fd(f), code(f.getArch()->getDefaultCodeSpace()), nextPc(basePc) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);
    blocks.push_back(block);
    return block;
  }

  void edge(BlockBasic *from,BlockBasic *to)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    graph.addEdge(from,to);
  }

  Address allocPc(void)
  {
    Address a(code,nextPc);
    nextPc += 8;
    return a;
  }

  string name(const FlowBlock *bl) const
  {
    if (bl == (const FlowBlock *)0) return "-";
    for(size_t i=0;i<blocks.size();++i)
      if (blocks[i] == bl) return "b" + to_string(i);
    return "x";
  }

  static string mtname(type_metatype mt)
  {
    switch (mt) {
    case TYPE_VOID: return "void";
    case TYPE_UNKNOWN: return "unknown";
    case TYPE_INT: return "int";
    case TYPE_UINT: return "uint";
    case TYPE_BOOL: return "bool";
    case TYPE_FLOAT: return "float";
    case TYPE_PTR: return "pointer";
    default: return "other";
    }
  }

  static string vname(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "-";
    ostringstream s;
    s << vn->getSpace()->getName() << ":0x" << hex << vn->getOffset()
      << ':' << dec << vn->getSize();
    return s.str();
  }

  static string vdesc(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "-";
    if (vn->isConstant()) {
      ostringstream s;
      s << "const:0x" << hex << vn->getOffset() << ':' << dec << vn->getSize();
      return s.str();
    }
    return vname(vn);
  }

  // "free" = no def and not a function input (the newVarnode-created
  // locked-output varnode), "input" = marked function input.
  static string defToken(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "-";
    if (vn->getDef() != (const PcodeOp *)0) return "def";
    return vn->isInput() ? "input" : "free";
  }

  // The first op of the given opcode in the block's op list.
  PcodeOp *firstOf(const FlowBlock *bl,OpCode opc) const
  {
    const BlockBasic *bb = (const BlockBasic *)bl;
    for(auto it = bb->beginOp(); it != bb->endOp(); ++it)
      if ((*it)->code() == opc) return *it;
    return (PcodeOp *)0;
  }

  PcodeOp *makeReturnAt(BlockBasic *blk,Varnode *value = (Varnode *)0)
  {
    PcodeOp *op = fd.newOp(value == (Varnode *)0 ? 1 : 2,allocPc());
    fd.opSetOpcode(op,CPUI_RETURN);
    fd.opSetInput(op,fd.newConstant(1,0),0);
    if (value != (Varnode *)0)
      fd.opSetInput(op,value,1);
    fd.opInsertEnd(op,blk);
    return op;
  }

  // Per-RETURN projection: input count, last-input descriptor, and (when the
  // last input is a plain varnode) its free/def/input status, typelock and
  // metatype; for a RETURN with a pre-existing value slot also the untouched
  // slot-1 descriptor.
  void printReturn(const char *label,const FlowBlock *bl) const
  {
    PcodeOp *retop = firstOf(bl,CPUI_RETURN);
    int4 nin = retop->numInput();
    const Varnode *last = retop->getIn(nin-1);
    cout << "retA|blk=" << label << "|nin=" << nin
         << "|in_last=" << vdesc(last);
    if (!last->isConstant()) {
      cout << "|def=" << defToken(last)
           << "|typelock=" << (last->isTypeLock() ? 1 : 0)
           << "|mt=" << mtname(last->getType()->getMetatype());
    }
    if (nin >= 3) {
      const Varnode *in1 = retop->getIn(1);
      cout << "|in1=" << vdesc(in1) << "|in1_def=" << defToken(in1);
    }
    cout << '\n';
  }
};

}  // namespace

int main(void)
{
  cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  cout << "schema=1|fixture=RETURNFOLD-GAPA-PROTOTYPES-0001"
       << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    AddrSpace *reg = architecture.getSpace(4);
    Scope *global = architecture.symboltab->getGlobalScope();

    // ---------------- Scenario A: output-locked int ----------------
    Funcdata fdA("gapa","gapa",global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
    {
      FuncProto &fp = fdA.getFuncProto();
      fp.setInternal(architecture.defaultfp,architecture.types->getTypeVoid());
      PrototypePieces pieces;
      pieces.model = architecture.defaultfp;
      pieces.name = "gapa_locked";
      pieces.outtype = architecture.types->getBase(4,TYPE_INT);
      pieces.firstVarArgSlot = -1;
      fp.setPieces(pieces);
    }
    Fixture fA(fdA,0x60010);
    BlockBasic *a0 = fA.makeBlock();
    BlockBasic *a1 = fA.makeBlock();
    BlockBasic *a2 = fA.makeBlock();
    BlockBasic *a3 = fA.makeBlock();
    BlockBasic *a4 = fA.makeBlock();
    Varnode *V = fdA.newVarnode(4,Address(reg,0x40));
    V = fdA.setInputVarnode(V);
    PcodeOp *rA1 = fA.makeReturnAt(a1);			// 0x60010
    PcodeOp *rA2 = fA.makeReturnAt(a2,V);			// 0x60018
    PcodeOp *rH  = fA.makeReturnAt(a3);			// 0x60020
    PcodeOp *rD  = fA.makeReturnAt(a4);			// 0x60028
    rH->flags |= PcodeOp::halt;				// cc:4643 skip marker
    rD->flags |= PcodeOp::dead;				// cc:4642 skip marker
    fA.edge(a0,a1);
    fA.edge(a0,a2);
    fA.edge(a0,a3);
    fA.edge(a0,a4);
    {
      const FuncProto &fp = fdA.getFuncProto();
      const ProtoParameter *out = fp.getOutput();
      cout << "preA|locked=" << (fp.isOutputLocked() ? 1 : 0)
           << "|mt=" << Fixture::mtname(out->getType()->getMetatype()) << '\n';
    }
    ActionPrototypeTypes actionA("");
    int4 rcA = actionA.apply(fdA);
    fA.printReturn("b1",a1);
    fA.printReturn("b2",a2);
    fA.printReturn("b3halt",a3);
    fA.printReturn("b4dead",a4);
    {
      const Varnode *v1 = rA1->getIn(rA1->numInput()-1);
      const Varnode *v2 = rA2->getIn(rA2->numInput()-1);
      cout << "orderA|b1_lt_b2=" << (v1->getCreateIndex() < v2->getCreateIndex() ? 1 : 0)
           << "|pair_distinct=" << (v1 != v2 ? 1 : 0)
           << "|active=" << (fdA.getActiveOutput() != (ParamActive *)0 ? 1 : 0)
           << "|rc=" << rcA << '\n';
    }

    // ---------------- Scenario B: output-locked void ----------------
    Funcdata fdB("gapb","gapb",global,Address(ram,0x61000),(FunctionSymbol *)0,0x100);
    {
      FuncProto &fp = fdB.getFuncProto();
      fp.setInternal(architecture.defaultfp,architecture.types->getTypeVoid());
      PrototypePieces pieces;
      pieces.model = architecture.defaultfp;
      pieces.name = "gapb_locked_void";
      pieces.outtype = architecture.types->getTypeVoid();
      pieces.firstVarArgSlot = -1;
      fp.setPieces(pieces);
    }
    Fixture fB(fdB,0x61010);
    BlockBasic *b0 = fB.makeBlock();
    PcodeOp *rB = fB.makeReturnAt(b0);
    {
      const FuncProto &fp = fdB.getFuncProto();
      cout << "preB|locked=" << (fp.isOutputLocked() ? 1 : 0)
           << "|mt=" << Fixture::mtname(fp.getOutput()->getType()->getMetatype()) << '\n';
    }
    ActionPrototypeTypes actionB("");
    int4 rcB = actionB.apply(fdB);
    cout << "postB|nin=" << rB->numInput()
         << "|in_last=" << Fixture::vdesc(rB->getIn(rB->numInput()-1))
         << "|active=" << (fdB.getActiveOutput() != (ParamActive *)0 ? 1 : 0)
         << "|rc=" << rcB << '\n';

    // ---------------- Scenario C: unlocked control ----------------
    Funcdata fdC("gapc","gapc",global,Address(ram,0x62000),(FunctionSymbol *)0,0x100);
    Fixture fC(fdC,0x62010);
    BlockBasic *c0 = fC.makeBlock();
    PcodeOp *rC = fC.makeReturnAt(c0);
    {
      const FuncProto &fp = fdC.getFuncProto();
      cout << "preC|locked=" << (fp.isOutputLocked() ? 1 : 0)
           << "|mt=" << Fixture::mtname(fp.getOutput()->getType()->getMetatype()) << '\n';
    }
    ActionPrototypeTypes actionC("");
    int4 rcC = actionC.apply(fdC);
    cout << "postC|nin=" << rC->numInput()
         << "|in_last=" << Fixture::vdesc(rC->getIn(rC->numInput()-1))
         << "|active=" << (fdC.getActiveOutput() != (ParamActive *)0 ? 1 : 0)
         << "|rc=" << rcC << '\n';
  }
  catch (const LowlevelError &error) {
    cout << "exception|phase=main|what=" << error.explain << '\n';
    return 1;
  }
  catch (const exception &error) {
    cout << "exception|phase=main|what=" << error.what() << '\n';
    return 1;
  }
  cout << "case_model_glue|status=UNTESTED|note=Rugra derives the locked output storage from ProtoModel::default_x86_64 output entry (ANN-F glue, FSPEC-0001/FSPEC-0002) because the flat FuncProto has no output ProtoParameter; fixture pins only the observable address/space identity (RETURNFOLD-GAPA-PROTOTYPES-0001)\n";
  cout << "case_multi_output|status=UNTESTED|note=model output list with >1 entry (multi-register return storage) not projected; default x86-64 model has exactly one output entry on both sides\n";
  cout << "case_e2e_fold|status=UNTESTED|note=end-to-end return-value fold (MarkExplicit/MarkImplied/PrintC) needs GAP-D and print-stage fixtures; IR-level attach only here (RETURNFOLD upstream chain)\n";
  return 0;
}
