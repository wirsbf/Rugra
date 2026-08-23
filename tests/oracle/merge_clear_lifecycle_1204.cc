/*
 * MERGE-CLEAR-LIFECYCLE-0001: locked Ghidra 12.0.4 Funcdata::clear oracle.
 *
 * The fixture builds ONE Funcdata carrying every persistent-state domain
 * that Funcdata::clear (funcdata.cc:84-112) touches, observes the complete
 * state, runs fd.clear(), then observes again — including the external
 * handles that survive (override JumpTable, typelocked+namelocked symbol)
 * and the restart gate (isProcStarted cleared, so startProcessing may run
 * again; Ghidra's restart loop depends on exactly this).
 *
 * Populated domains (Ghidra call sites):
 *   flags              the seven cleared bits + three preserved bits
 *                      (funcdata.hh:57-73 bit values; Rugra's flag bits are
 *                      logically the same set, rendered by name here)
 *   counters           clean_up_index / high_level_index / cast_phase_index
 *                      (funcdata.hh:75-77). NOTE: the Rust side has no
 *                      clean_up_index/cast_phase_index fields, so those two
 *                      are NOT rendered in the bilateral projection; the
 *                      header comment records them as UNTESTED.
 *   minLanedSize       driven to 1000000 via setLanedRegGenerated()
 *                      (funcdata.hh:155); the fixture Architecture carries
 *                      one LanedRegister(4,0xa) so clear re-derives 4.
 *   lanedMap           one entry (persists — clear never touches it).
 *   localmap           two symbols: unlocked_a (dies) and locked_b
 *                      (typelock+namelock → survives with its name,
 *                      database.cc:2042-2064), plus min/maxParamOffset
 *                      driven to 0x40/0x80 (reset by resetLocalWindow,
 *                      varmap.cc:443-444).
 *   activeoutput       ParamActive(false) (funcdata.hh:420-423).
 *   funcp              returnBytesConsumed=7 (fspec.hh:1367; cleared by
 *                      clearUnlockedOutput fspec.cc:4012).
 *   unionMap           one ResolveEdge (funcdata.hh:100).
 *   obank/vbank        two ops / varnodes; uniqid + create_index observed.
 *   callspecs          one FuncCallSpecs over a CALL op (funcdata.cc:464).
 *   jumpvec            an override JumpTable (JumpBasicOverride model,
 *                      maxaddsub=7/collectloads=true — permanent across
 *                      clear, jumptable.cc:2757) and a plain table (dies).
 *   heritage           pass=3, maxdepth=5 (heritage.cc:2855-2866).
 *   covermerge         testCache populated through the production
 *                      HighIntersectTest::intersection (variable.cc:1166,
 *                      caches BOTH HighEdge directions → 2 entries);
 *                      copyTrims/protoPartial deposited directly; the
 *                      stackAffectingOps PcodeOpSet populated through the
 *                      production StackAffectingOps::populate (merge.cc:63)
 *                      which picks up the CALL op via qlst.
 *
 * Dangling handles: after clear the C++ Varnode/PcodeOp objects are FREED
 * (obank/vbank clear); the fixture never dereferences the pre-clear op or
 * varnode pointers afterwards — bank emptiness and uniqid/create_index
 * resets are the observable stand-ins. The override JumpTable handle IS
 * dereferenced post-clear (Ghidra keeps the object).
 *
 * Registered bilateral residuals (metadata coverage):
 *   localmap_typelock_survival — Ghidra keeps locked_b, Rugra's wholesale
 *     symbols.clear() model drops it (varmap nametree is index-addressed;
 *     a faithful retain needs varmap.rs-side clearUnlocked).
 *   funcproto_unlocked_output — fspec.cc:4001-4013 resets
 *     returnBytesConsumed=0 and clears the unlocked output store; Rugra's
 *     fspec.rs clear_unlocked_output is a simplification that leaves
 *     returnBytesConsumed at 7.
 * Everything else must be byte-identical.
 */

#include <bits/stdc++.h>

// Test-only access is required to reach Funcdata's implicit-private data
// section (funcdata.hh:74-100: the class opens with `enum {` + fields and no
// explicit access specifier until `public:` at funcdata.hh:137) and the
// same-shaped Merge data section (merge.hh:84-88). `#define private public`
// alone cannot expose implicit-private members, so this matches the
// `#define class struct` precedent of the address_space_handle /
// address_compat_order fixtures and is confined to this translation unit.
#define class struct
#define private public
#define protected public
#include "architecture.hh"
#include "cover.hh"
#include "database.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "heritage.hh"
#include "jumptable.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "merge.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varmap.hh"
#include "varnode.hh"
#undef protected
#undef private
#undef class

using namespace ghidra;
using std::cerr;
using std::cout;
using std::istringstream;
using std::map;
using std::ostringstream;
using std::set;
using std::string;
using std::vector;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;
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
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override { return (PcodeInjectLibrary *)0; }
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
    ProtoModel *model = new ProtoModel(this);
    istringstream stream("<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
    // One laned register so getMinimumLanedRegisterSize (architecture.cc:312)
    // returns 4 after clear re-derives minLanedSize.
    lanerecords.push_back(LanedRegister(4,0xa));
  }
  void printMessage(const string &) const override {}
};

string bitStr(const char *name, bool value)
{
  ostringstream out;
  out << name << ':' << (value ? 1 : 0);
  return out.str();
}

} // namespace

int main(void)
{
  vector<string> specPaths;
  startDecompilerLibrary((const char *)0); // register capabilities (print languages)
  FixtureArchitecture arch;
  Funcdata fd("lifecycle", "lifecycle", arch.symboltab->getGlobalScope(),
              Address(arch.getSpace(3), 0x7000), (FunctionSymbol *)0, 0x100);
  AddrSpace *ram = arch.getSpace(3);
  AddrSpace *reg = arch.getSpace(4);

  // --- graph: two COPYs in two blocks (gives two HighVariables with covers)
  BlockGraph &bgraph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *b0 = bgraph.newBlockBasic(&fd);
  b0->index = 0;
  BlockBasic *b1 = bgraph.newBlockBasic(&fd);
  b1->index = 1;
  bgraph.addEdge(b0, b1);

  PcodeOp *op1 = fd.newOp(1, Address(ram, 0x7000));
  fd.opSetOpcode(op1, CPUI_COPY);
  Varnode *vnP = fd.newVarnodeOut(4, Address(reg, 0x10), op1);
  fd.opSetInput(op1, fd.newConstant(4, 0x11), 0);
  fd.opInsertEnd(op1, b0);

  PcodeOp *op2 = fd.newOp(1, Address(ram, 0x7001));
  fd.opSetOpcode(op2, CPUI_COPY);
  Varnode *vnQ = fd.newVarnodeOut(4, Address(reg, 0x20), op2);
  fd.opSetInput(op2, fd.newConstant(4, 0x22), 0);
  fd.opInsertEnd(op2, b1);

  // --- CALL op + callspec (feeds StackAffectingOps::populate via qlst)
  PcodeOp *callop = fd.newOp(1, Address(ram, 0x7002));
  fd.opSetOpcode(callop, CPUI_CALL);
  fd.opSetInput(callop, fd.newConstant(8, 0xdeadbeef), 0);
  fd.opInsertEnd(callop, b1);
  fd.qlst.push_back(new FuncCallSpecs(callop));

  // --- high level + production testCache population
  fd.setHighLevel();
  fd.getMerge().testCache.intersection(vnP->getHigh(), vnQ->getHigh());

  // --- merge channels deposited the way earlier merge Actions would
  fd.getMerge().copyTrims.push_back(op1);
  fd.getMerge().protoPartial.push_back(op2);
  fd.getMerge().stackAffectingOps.populate();

  // --- jump tables: one override (kept, permanent fields survive) + one plain (dropped)
  JumpTable *jt1 = new JumpTable(&arch, Address(ram, 0x7100));
  jt1->jmodel = new JumpBasicOverride(jt1);
  jt1->maxaddsub = 7;
  jt1->collectloads = true;
  fd.jumpvec.push_back(jt1);
  JumpTable *jt2 = new JumpTable(&arch, Address(ram, 0x7200));
  fd.jumpvec.push_back(jt2);

  // --- localmap: unlocked symbol dies, typelock+namelock symbol survives
  Symbol *s1 = fd.localmap->addSymbol("unlocked_a", arch.types->getBase(4,TYPE_INT));
  Symbol *s2 = fd.localmap->addSymbol("locked_b", arch.types->getBase(4,TYPE_INT));
  fd.localmap->setAttribute(s2, Varnode::typelock | Varnode::namelock);
  fd.localmap->minParamOffset = 0x40;
  fd.localmap->maxParamOffset = 0x80;

  // --- scalar/flag domains
  fd.flags |= Funcdata::blocks_generated | Funcdata::processing_started |
              Funcdata::typerecovery_start | Funcdata::typerecovery_on |
              Funcdata::double_precis_on | Funcdata::restart_pending;
  // Preserved bits: blocks_unreachable, processing_complete, jumptablerecovery_dont
  fd.flags |= Funcdata::blocks_unreachable | Funcdata::processing_complete |
              Funcdata::jumptablerecovery_dont;
  fd.clean_up_index = 3;
  fd.high_level_index = 7;
  fd.cast_phase_index = 5;
  fd.setLanedRegGenerated(); // minLanedSize = 1000000
  VarnodeData lanedKey = { reg, 0x30, 4 };
  fd.lanedMap[lanedKey] = &arch.lanerecords[0];
  fd.activeoutput = new ParamActive(false);
  fd.funcp.returnBytesConsumed = 7;
  fd.unionMap.insert(std::make_pair(
      ResolveEdge(arch.types->getBase(4,TYPE_INT), op1, 0),
      ResolvedUnion(arch.types->getBase(4,TYPE_INT))));
  fd.heritage.pass = 3;
  fd.heritage.maxdepth = 5;

  // --- observation -------------------------------------------------------
  auto observeCore = [&](const char *stage) {
    ostringstream out;
    out << "case=lifecycle|stage=" << stage
        << "|flags=" << bitStr("f_highlevel",(fd.flags&Funcdata::highlevel_on)!=0)
                     << ',' << bitStr("f_blocks",(fd.flags&Funcdata::blocks_generated)!=0)
                     << ',' << bitStr("f_procstart",(fd.flags&Funcdata::processing_started)!=0)
                     << ',' << bitStr("f_typerec_start",(fd.flags&Funcdata::typerecovery_start)!=0)
                     << ',' << bitStr("f_typerec",(fd.flags&Funcdata::typerecovery_on)!=0)
                     << ',' << bitStr("f_dblprecis",(fd.flags&Funcdata::double_precis_on)!=0)
                     << ',' << bitStr("f_restart",(fd.flags&Funcdata::restart_pending)!=0)
                     << ',' << bitStr("f_unreach",(fd.flags&Funcdata::blocks_unreachable)!=0)
                     << ',' << bitStr("f_proccomplete",(fd.flags&Funcdata::processing_complete)!=0)
                     << ',' << bitStr("f_jtdont",(fd.flags&Funcdata::jumptablerecovery_dont)!=0)
        << "|highlevelidx=" << fd.high_level_index
        << "|minlaned=" << (int4)fd.minLanedSize
        << "|lanedmap=" << fd.lanedMap.size()
        << "|activeout=" << (fd.activeoutput != (ParamActive *)0 ? 1 : 0)
        << "|unionmap=" << fd.unionMap.size()
        << "|ops=" << (fd.obank.alivelist.size() + fd.obank.deadlist.size())
        << "|varnodes=" << std::distance(fd.beginLoc(reg), fd.endLoc(reg))
        << "|opuniqid=" << fd.obank.getUniqId()
        << "|createidx=" << fd.vbank.getCreateIndex()
        << "|calls=" << fd.numCalls()
        << "|jts=" << fd.jumpvec.size()
        << "|jt1_override=" << (jt1->isOverride() ? 1 : 0)
        << "|jt1_maxaddsub=" << jt1->maxaddsub
        << "|jt1_collectloads=" << (jt1->collectloads ? 1 : 0)
        << "|heritage_pass=" << fd.heritage.pass
        << "|heritage_maxdepth=" << fd.heritage.maxdepth
        << "|testcache=" << fd.getMerge().testCache.highedgemap.size()
        << "|copytrims=" << fd.getMerge().copyTrims.size()
        << "|protopartial=" << fd.getMerge().protoPartial.size()
        << "|stackops=" << fd.getMerge().stackAffectingOps.opList.size()
        << "|stackpop=" << (fd.getMerge().stackAffectingOps.isPopulated() ? 1 : 0)
        << "|procstart_gate=" << (fd.isProcStarted() ? 1 : 0)
        << "|restartpend=" << (fd.hasRestartPending() ? 1 : 0)
        << '\n';
    cout << out.str();
  };
  auto observeLocalmap = [&](const char *stage) {
    vector<Symbol *> found;
    fd.localmap->findByName("locked_b", found);
    ostringstream out;
    out << "case=lifecycle|stage=" << stage << "|domain=localmap"
        << "|localsyms=" << fd.localmap->nametree.size()
        << "|paramwin=0x" << std::hex << fd.localmap->minParamOffset
        << "-0x" << fd.localmap->maxParamOffset << std::dec
        << "|locked_found=" << ((!found.empty() && found[0] == s2) ? 1 : 0)
        << '\n';
    cout << out.str();
  };
  auto observeFuncproto = [&](const char *stage) {
    ostringstream out;
    out << "case=lifecycle|stage=" << stage << "|domain=funcproto"
        << "|returnbytes=" << fd.funcp.returnBytesConsumed << '\n';
    cout << out.str();
  };

  observeCore("before");
  observeLocalmap("before");
  observeFuncproto("before");

  // --- the lifecycle event under test (funcdata.cc:84-112)
  fd.clear();

  observeCore("after");
  observeLocalmap("after");
  observeFuncproto("after");
  return 0;
}
