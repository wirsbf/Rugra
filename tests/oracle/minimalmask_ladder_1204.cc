/*
 * MINIMALMASK-LADDER-CONSUMERS-0001: locked Ghidra 12.0.4 oracle for
 * `minimalmask` (address.hh:525-534, the whole-byte ladder) and the three
 * production consumers of the 7049549b ladder fix:
 *
 *   - ActionDeadCode::markConsumedParameters (coreaction.cc:3840, the
 *     minimalmask read at cc:3856 with the autolive cc:3853-3854 bypass,
 *     the locked/active cc:3845-3849 full-consume return, and the
 *     inputBytesConsumed AND-gate cc:3857-3859);
 *   - ActionDeadCode::gatherConsumedReturn (coreaction.cc:3871, the OR
 *     accumulation cc:3884, the dead/slot-count loop guards cc:3881-3883,
 *     the output-lock early return cc:3874-3875, and the returnBytesConsumed
 *     AND-gate cc:3887-3890);
 *   - JumpTable::foldInNormalization (jumptable.cc:2574, the switchVarConsume
 *     ladder read cc:2581 plus the "mask covers everything" SEXT gate
 *     cc:2582-2589 whose downstream form is ActionDeadCode's BRANCHIND arm
 *     mask = jt->getSwitchVarConsume() coreaction.cc:3984-3992).
 *
 * Synthetic NZMask seeding is the fixture prestate (the same scheme
 * goto_prints_nextflowafter uses for block indexes): constant Varnodes carry
 * their value as nzm natively (Varnode ctor varnode.cc:597), and the two
 * written SEXT/COPY switch variables get nzm assigned directly — the three
 * consumers only READ getNZMask(), so the seeding drives the ladder inputs
 * 0/0xff/0x100/0x7ff/0xffff/0x10000/0xffffffff/0x100000000 through the
 * production code without any fixture-local reimplementation.
 *
 * The ladder block calls the address.hh:525 inline definition itself (it is
 * defined in the header, so this TU instantiates the production body).
 *
 * Mirrors tests/oracle/minimalmask_ladder_1204.rs case for case.
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as goto_prints_nextflowafter_1204.cc).
#define private public
#define protected public
#define class struct
#include "address.hh"
#include "architecture.hh"
#include "block.hh"
#include "blockaction.hh"
#include "coreaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "fspec.hh"
#include "jumptable.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "space.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef class
#undef protected
#undef private

using namespace ghidra;

static string hex16(uintb val)
{
  char buf[32];
  snprintf(buf,sizeof(buf),"%016llx",(unsigned long long)val);
  return string(buf);
}

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;
public:
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
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack,stack_pointer,8,true);
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"join",false,8,1,6,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new IopSpace(this,this,7));
    setDefaultCodeSpace(3);
    dummy_register.space = reg;
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummy_register; }
  string getRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData,string> &) const override {}
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
    FixtureTranslate *fixture_translate = new FixtureTranslate();
    translate = fixture_translate;
    copySpaces(fixture_translate);
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
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }
  void printMessage(const string &message) const override {
    std::cerr << message << '\n';
  }
};

// Per-varnode consume observation after a markConsumedParameters run: the
// ladder output minimalmask produced, the pushConsumed state (consume/vac/
// lis), and whether the varnode entered the propagation worklist
// (pushConsumed coreaction.cc:3556-3568 only lists written varnodes).
static void observeParam(const char *nm,Varnode *vn,
                         const vector<Varnode *> &worklist)
{
  bool inlist = false;
  for(int4 i=0;i<(int4)worklist.size();++i)
    if (worklist[i] == vn) { inlist = true; break; }
  std::cout << "param|" << nm
            << "|size=" << vn->getSize()
            << "|nzm=" << hex16(vn->getNZMask())
            << "|mm=" << hex16(minimalmask(vn->getNZMask()))
            << "|consume=" << hex16(vn->getConsume())
            << "|vac=" << (vn->isConsumeVacuous() ? 1 : 0)
            << "|lis=" << (vn->isConsumeList() ? 1 : 0)
            << "|inwl=" << (inlist ? 1 : 0) << '\n';
}

// Per-case prestate reset mirroring ActionDeadCode::apply's reset loop
// (coreaction.cc:3939-3946): Varnodes are BORN with consume=~0 (varnode.cc:586)
// and production zeroes the field before any consumer pushes, so the direct
// consumer calls must run over the same zeroed state.
static void resetConsumed(Funcdata &fd)
{
  for(VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter) {
    Varnode *vn = *iter;
    vn->clearConsumeList();
    vn->clearConsumeVacuous();
    vn->setConsume(0);
  }
}

int main()
{
  try {
  vector<string> spec_paths;		// registers print language capabilities
  startDecompilerLibrary(spec_paths);
  FixtureArchitecture arch;
  AddrSpace *ram = arch.getSpaceByName("ram");
  Funcdata fd("minimalmask","",arch.symboltab->getGlobalScope(),
              Address(ram,0x1000),(FunctionSymbol *)0,0x10);

  // ---- ladder: the address.hh:525-534 whole-byte boundaries ----
  {
    static const uintb vals[] = {
      0x0,0x1,0xff,0x100,0x7ff,0xffff,
      0x10000,0x7fffffff,0xffffffff,0x100000000ULL,
      0x7fffffffffffffffULL,0xffffffffffffffffULL
    };
    std::cout << "case ladder\n";
    for(int4 i=0;i<12;++i)
      std::cout << "ladder|val=" << hex16(vals[i])
                << "|mm=" << hex16(minimalmask(vals[i])) << '\n';
    std::cout << "end\n";
  }

  // ---- markConsumedParameters, nominal ladder parameters ----
  {
    std::cout << "case callparams_nominal\n";
    Varnode *target = fd.newConstant(8,0);
    Varnode *p1 = fd.newConstant(1,0x0);		// mm 0xff == calc_mask(1)
    Varnode *p2 = fd.newConstant(2,0xff);		// boundary >0xff -> 0xffff
    Varnode *p3 = fd.newConstant(4,0x100);		// >0xffff -> 0xffffffff
    Varnode *p4 = fd.newConstant(4,0x7ff);		// >0xff only -> 0xffff (partial)
    Varnode *p5 = fd.newConstant(8,0xffffffff);		// 0xffffffff < full 8-byte
    Varnode *p6 = fd.newConstant(8,0x100000000ULL);	// >0xffffffff -> ~0
    PcodeOp *copy = fd.newOp(1,Address(ram,0x1100));
    fd.opSetOpcode(copy,CPUI_COPY);
    Varnode *p7 = fd.newUniqueOut(2,copy);		// written: worklist entry
    p7->nzm = 0x100;
    fd.opSetInput(copy,fd.newConstant(2,0x100),0);
    PcodeOp *call = fd.newOp(8,Address(ram,0x1200));
    fd.opSetOpcode(call,CPUI_CALL);
    fd.opSetInput(call,target,0);
    fd.opSetInput(call,p1,1);
    fd.opSetInput(call,p2,2);
    fd.opSetInput(call,p3,3);
    fd.opSetInput(call,p4,4);
    fd.opSetInput(call,p5,5);
    fd.opSetInput(call,p6,6);
    fd.opSetInput(call,p7,7);
    FuncCallSpecs *fc = new FuncCallSpecs(call);
    // ActionDefaultParams' model install (coreaction.cc:2332): a spec with
    // no attached callee gets setInternal(defaultfp, void) in the base
    // group, before deadcode ever queries numParams (the seam
    // COREACTION-CALLIN0-CLOBBER-0001 documented).
    fc->setInternal(arch.defaultfp,arch.types->getTypeVoid());
    resetConsumed(fd);
    vector<Varnode *> worklist;
    ActionDeadCode::markConsumedParameters(fc,worklist);
    observeParam("target",target,worklist);
    observeParam("p1",p1,worklist);
    observeParam("p2",p2,worklist);
    observeParam("p3",p3,worklist);
    observeParam("p4",p4,worklist);
    observeParam("p5",p5,worklist);
    observeParam("p6",p6,worklist);
    observeParam("p7",p7,worklist);
    std::cout << "worklist|size=" << (int4)worklist.size() << '\n';
    std::cout << "end\n";
    delete fc;
  }

  // ---- markConsumedParameters, inputBytesConsumed AND-gate (cc:3857-3859) ----
  {
    std::cout << "case callparams_bytesgate\n";
    Varnode *target = fd.newConstant(8,0);
    Varnode *q1 = fd.newConstant(4,0x100);		// gate 1 byte
    Varnode *q2 = fd.newConstant(4,0x101);		// gate 2 bytes (distinct value:
                                                // the bank dedups equal constants)
    Varnode *q3 = fd.newConstant(2,0x0);		// no hint: ladder only
    Varnode *q4 = fd.newConstant(8,0xffffffff);		// gate 8 bytes: caps at ladder
    PcodeOp *call = fd.newOp(5,Address(ram,0x1300));
    fd.opSetOpcode(call,CPUI_CALL);
    fd.opSetInput(call,target,0);
    fd.opSetInput(call,q1,1);
    fd.opSetInput(call,q2,2);
    fd.opSetInput(call,q3,3);
    fd.opSetInput(call,q4,4);
    FuncCallSpecs *fc = new FuncCallSpecs(call);
    fc->setInternal(arch.defaultfp,arch.types->getTypeVoid());
    fc->setInputBytesConsumed(1,1);
    fc->setInputBytesConsumed(2,2);
    fc->setInputBytesConsumed(4,8);
    resetConsumed(fd);
    vector<Varnode *> worklist;
    ActionDeadCode::markConsumedParameters(fc,worklist);
    observeParam("q1",q1,worklist);
    observeParam("q2",q2,worklist);
    observeParam("q3",q3,worklist);
    observeParam("q4",q4,worklist);
    std::cout << "end\n";
    delete fc;
  }

  // ---- markConsumedParameters, autolive bypass (cc:3853-3854) ----
  {
    std::cout << "case callparams_autolive\n";
    Varnode *target = fd.newConstant(8,0);
    Varnode *a1 = fd.newConstant(4,0x100);
    a1->setAutoLiveHold();
    PcodeOp *call = fd.newOp(2,Address(ram,0x1400));
    fd.opSetOpcode(call,CPUI_CALL);
    fd.opSetInput(call,target,0);
    fd.opSetInput(call,a1,1);
    FuncCallSpecs *fc = new FuncCallSpecs(call);
    fc->setInternal(arch.defaultfp,arch.types->getTypeVoid());
    resetConsumed(fd);
    vector<Varnode *> worklist;
    ActionDeadCode::markConsumedParameters(fc,worklist);
    observeParam("a1",a1,worklist);
    std::cout << "end\n";
    delete fc;
  }

  // ---- markConsumedParameters, locked-prototype full consume (cc:3845-3849) ----
  {
    std::cout << "case callparams_inputlock\n";
    Varnode *target = fd.newConstant(8,0);
    Varnode *l1 = fd.newConstant(4,0x7ff);
    Varnode *l2 = fd.newConstant(2,0xff);
    PcodeOp *call = fd.newOp(3,Address(ram,0x1500));
    fd.opSetOpcode(call,CPUI_CALL);
    fd.opSetInput(call,target,0);
    fd.opSetInput(call,l1,1);
    fd.opSetInput(call,l2,2);
    FuncCallSpecs *fc = new FuncCallSpecs(call);
    fc->setInternal(arch.defaultfp,arch.types->getTypeVoid());
    fc->setInputLock(true);
    resetConsumed(fd);
    vector<Varnode *> worklist;
    ActionDeadCode::markConsumedParameters(fc,worklist);
    observeParam("l1",l1,worklist);
    observeParam("l2",l2,worklist);
    std::cout << "end\n";
    delete fc;
  }

  // ---- gatherConsumedReturn: OR accumulation + loop guards (cc:3879-3886) ----
  {
    std::cout << "case returns_basic\n";
    BlockGraph &rgraph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *rblock = rgraph.newBlockBasic(&fd);
    PcodeOp *r1 = fd.newOp(2,Address(ram,0x1600));
    fd.opSetOpcode(r1,CPUI_RETURN);
    fd.opSetInput(r1,fd.newConstant(8,0),0);
    fd.opSetInput(r1,fd.newConstant(2,0x100),1);	// mm 0xffff
    fd.opInsertEnd(r1,rblock);
    PcodeOp *r2 = fd.newOp(2,Address(ram,0x1700));
    fd.opSetOpcode(r2,CPUI_RETURN);
    fd.opSetInput(r2,fd.newConstant(8,0),0);
    fd.opSetInput(r2,fd.newConstant(4,0x10000),1);	// mm 0xffffffff
    fd.opInsertEnd(r2,rblock);
    PcodeOp *r3 = fd.newOp(1,Address(ram,0x1800));	// numInput()==1: skipped
    fd.opSetOpcode(r3,CPUI_RETURN);
    fd.opSetInput(r3,fd.newConstant(8,0),0);
    fd.opInsertEnd(r3,rblock);
    PcodeOp *r4 = fd.newOp(2,Address(ram,0x1900));	// dead: skipped
    fd.opSetOpcode(r4,CPUI_RETURN);
    fd.opSetInput(r4,fd.newConstant(8,0),0);
    fd.opSetInput(r4,fd.newConstant(8,0x100000000ULL),1);
    fd.opInsertEnd(r4,rblock);
    fd.opDestroy(r4);
    std::cout << "gather|consume=" << hex16(ActionDeadCode::gatherConsumedReturn(fd)) << '\n';
    std::cout << "end\n";
  }

  // ---- gatherConsumedReturn: returnBytesConsumed AND-gate (cc:3887-3890).
  // Hints shrink 2 -> 1 (setReturnBytesConsumed keeps the smallest, fspec.cc:3954). ----
  {
    std::cout << "case returns_bytes\n";
    fd.getFuncProto().setReturnBytesConsumed(2);
    std::cout << "gather|bytes=2|consume="
              << hex16(ActionDeadCode::gatherConsumedReturn(fd)) << '\n';
    fd.getFuncProto().setReturnBytesConsumed(1);
    std::cout << "gather|bytes=1|consume="
              << hex16(ActionDeadCode::gatherConsumedReturn(fd)) << '\n';
    std::cout << "end\n";
  }

  // ---- gatherConsumedReturn: output-lock early return (cc:3874-3875) ----
  {
    std::cout << "case returns_outputlock\n";
    fd.getFuncProto().setOutputLock(true);
    std::cout << "gather|consume=" << hex16(ActionDeadCode::gatherConsumedReturn(fd)) << '\n';
    fd.getFuncProto().setOutputLock(false);
    std::cout << "end\n";
  }

  // ---- foldInNormalization gate forms (jumptable.cc:2574-2591) ----
  // One BRANCHIND + JumpTable/JumpBasic per sub-case; observation is the
  // production switchVarConsume, whether it covers the full switch var
  // (the gate cc:2582 that authorizes subvariable truncation), and the
  // JumpBasic::foldInNormalization in(0) rewrite (jumptable.cc:1551).
  {
    std::cout << "case foldin\n";
    // f1: 1-byte unwritten switchvar — minimalmask >= calc_mask(1) always.
    {
      Varnode *sv = fd.newConstant(1,0x0);
      PcodeOp *bi = fd.newOp(1,Address(ram,0x2000));
      fd.opSetOpcode(bi,CPUI_BRANCHIND);
      fd.opSetInput(bi,fd.newConstant(1,0),0);
      JumpTable *jt = new JumpTable(&arch,Address(ram,0x2000));
      JumpBasic *model = new JumpBasic(jt);
      model->switchvn = sv;
      jt->jmodel = model;
      jt->setIndirectOp(bi);
      jt->foldInNormalization(&fd);
      std::cout << "foldin|f=unwritten_1byte|size=" << sv->getSize()
                << "|nzm=" << hex16(sv->getNZMask())
                << "|consume=" << hex16(jt->getSwitchVarConsume())
                << "|gate=" << ((minimalmask(sv->getNZMask()) >= calc_mask(sv->getSize())) ? 1 : 0)
                << "|in0isswitch=" << ((bi->getIn(0) == sv) ? 1 : 0) << '\n';
      delete jt;
    }
    // f2: 4-byte switchvar written by SEXT of a 1-byte value, nzm seeded to
    // the full 4-byte mask -> gate fires -> consume truncated to calc_mask(1).
    {
      PcodeOp *sext = fd.newOp(1,Address(ram,0x2100));
      fd.opSetOpcode(sext,CPUI_INT_SEXT);
      Varnode *sv = fd.newUniqueOut(4,sext);
      sv->nzm = 0xffffffff;
      fd.opSetInput(sext,fd.newConstant(1,0x7f),0);
      PcodeOp *bi = fd.newOp(1,Address(ram,0x2110));
      fd.opSetOpcode(bi,CPUI_BRANCHIND);
      fd.opSetInput(bi,fd.newConstant(4,0),0);
      JumpTable *jt = new JumpTable(&arch,Address(ram,0x2110));
      JumpBasic *model = new JumpBasic(jt);
      model->switchvn = sv;
      jt->jmodel = model;
      jt->setIndirectOp(bi);
      jt->foldInNormalization(&fd);
      std::cout << "foldin|f=sext_4byte|size=" << sv->getSize()
                << "|nzm=" << hex16(sv->getNZMask())
                << "|consume=" << hex16(jt->getSwitchVarConsume())
                << "|gate=" << ((minimalmask(sv->getNZMask()) >= calc_mask(sv->getSize())) ? 1 : 0)
                << "|in0isswitch=" << ((bi->getIn(0) == sv) ? 1 : 0) << '\n';
      delete jt;
    }
    // f3: same shape but written by COPY — the SEXT arm must not fire.
    {
      PcodeOp *cp = fd.newOp(1,Address(ram,0x2200));
      fd.opSetOpcode(cp,CPUI_COPY);
      Varnode *sv = fd.newUniqueOut(4,cp);
      sv->nzm = 0xffffffff;
      fd.opSetInput(cp,fd.newConstant(4,0xffffffff),0);
      PcodeOp *bi = fd.newOp(1,Address(ram,0x2210));
      fd.opSetOpcode(bi,CPUI_BRANCHIND);
      fd.opSetInput(bi,fd.newConstant(4,0),0);
      JumpTable *jt = new JumpTable(&arch,Address(ram,0x2210));
      JumpBasic *model = new JumpBasic(jt);
      model->switchvn = sv;
      jt->jmodel = model;
      jt->setIndirectOp(bi);
      jt->foldInNormalization(&fd);
      std::cout << "foldin|f=copy_4byte|size=" << sv->getSize()
                << "|nzm=" << hex16(sv->getNZMask())
                << "|consume=" << hex16(jt->getSwitchVarConsume())
                << "|gate=" << ((minimalmask(sv->getNZMask()) >= calc_mask(sv->getSize())) ? 1 : 0)
                << "|in0isswitch=" << ((bi->getIn(0) == sv) ? 1 : 0) << '\n';
      delete jt;
    }
    // f4: 8-byte switchvar by SEXT of 4 bytes, nzm 0xffffffff — the ladder
    // does NOT cover an 8-byte var: gate stays 0, no SEXT truncation.
    {
      PcodeOp *sext = fd.newOp(1,Address(ram,0x2300));
      fd.opSetOpcode(sext,CPUI_INT_SEXT);
      Varnode *sv = fd.newUniqueOut(8,sext);
      sv->nzm = 0xffffffff;
      fd.opSetInput(sext,fd.newConstant(4,0x7fffffff),0);
      PcodeOp *bi = fd.newOp(1,Address(ram,0x2310));
      fd.opSetOpcode(bi,CPUI_BRANCHIND);
      fd.opSetInput(bi,fd.newConstant(8,0),0);
      JumpTable *jt = new JumpTable(&arch,Address(ram,0x2310));
      JumpBasic *model = new JumpBasic(jt);
      model->switchvn = sv;
      jt->jmodel = model;
      jt->setIndirectOp(bi);
      jt->foldInNormalization(&fd);
      std::cout << "foldin|f=sext_8byte_partial|size=" << sv->getSize()
                << "|nzm=" << hex16(sv->getNZMask())
                << "|consume=" << hex16(jt->getSwitchVarConsume())
                << "|gate=" << ((minimalmask(sv->getNZMask()) >= calc_mask(sv->getSize())) ? 1 : 0)
                << "|in0isswitch=" << ((bi->getIn(0) == sv) ? 1 : 0) << '\n';
      delete jt;
    }
    // f5: 2-byte switchvar by SEXT of 1 byte, nzm 0x100 — boundary where the
    // ladder (0xffff) exactly equals calc_mask(2): gate fires -> 0xff.
    {
      PcodeOp *sext = fd.newOp(1,Address(ram,0x2400));
      fd.opSetOpcode(sext,CPUI_INT_SEXT);
      Varnode *sv = fd.newUniqueOut(2,sext);
      sv->nzm = 0x100;
      fd.opSetInput(sext,fd.newConstant(1,0x7f),0);
      PcodeOp *bi = fd.newOp(1,Address(ram,0x2410));
      fd.opSetOpcode(bi,CPUI_BRANCHIND);
      fd.opSetInput(bi,fd.newConstant(2,0),0);
      JumpTable *jt = new JumpTable(&arch,Address(ram,0x2410));
      JumpBasic *model = new JumpBasic(jt);
      model->switchvn = sv;
      jt->jmodel = model;
      jt->setIndirectOp(bi);
      jt->foldInNormalization(&fd);
      std::cout << "foldin|f=sext_2byte_from1|size=" << sv->getSize()
                << "|nzm=" << hex16(sv->getNZMask())
                << "|consume=" << hex16(jt->getSwitchVarConsume())
                << "|gate=" << ((minimalmask(sv->getNZMask()) >= calc_mask(sv->getSize())) ? 1 : 0)
                << "|in0isswitch=" << ((bi->getIn(0) == sv) ? 1 : 0) << '\n';
      delete jt;
    }
    std::cout << "end\n";
  }
  } catch(const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
    return 1;
  } catch(const std::exception &err) {
    std::cerr << "fixture error: " << err.what() << '\n';
    return 1;
  }
  return 0;
}
