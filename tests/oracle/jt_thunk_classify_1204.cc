/*
 * JT-THUNK-CLASSIFY-1204 (JUMPTABLE-THUNK-CLASSIFY-0001)
 *
 * Locked Ghidra 12.0.4 behavioral fixture for JumpTable::sanityCheck
 * (jumptable.cc:2295-2329) and the recoverAddresses ordering that surrounds
 * it (jumptable.cc:2623-2649).  The fixture observes the strict single-target
 * thunk boundary, override/reachability ordering, exact exception text, and
 * all table/load/partial mutations visible at the catch point.
 */

#include <bits/stdc++.h>

// Test-only access to JumpTable::sanityCheck and its state.  Standard headers
// are included first so the access macro cannot affect libstdc++.
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "database.hh"
#include "funcdata.hh"
#include "jumptable.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#undef class
#undef private

namespace {

using namespace ghidra;
using std::cout;
using std::istringstream;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;
public:
  FixtureTranslate()
  {
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
  FixtureArchitecture()
  {
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
  }
  void printMessage(const string &) const override {}
};

struct ModelState {
  int4 recoverCalls;
  int4 buildCalls;
  int4 sanityCalls;
  ModelState(void) : recoverCalls(0), buildCalls(0), sanityCalls(0) {}
};

class FixtureModel final : public JumpModel {
  bool overrideMode;
  bool sanityResult;
  bool mutateOnReject;
  AddrSpace *code;
  vector<Address> buildTargets;
  vector<LoadTable> buildLoads;
  ModelState *state;
public:
  FixtureModel(JumpTable *jt,bool over,bool sane,bool mutate,AddrSpace *spc,
               const vector<Address> &targets,const vector<LoadTable> &loads,
               ModelState *st)
    : JumpModel(jt), overrideMode(over), sanityResult(sane),
      mutateOnReject(mutate), code(spc), buildTargets(targets),
      buildLoads(loads), state(st) {}

  bool isOverride(void) const override { return overrideMode; }
  int4 getTableSize(void) const override { return buildTargets.size(); }
  bool recoverModel(Funcdata *,PcodeOp *,uint4,uint4) override
  {
    state->recoverCalls += 1;
    return true;
  }
  void buildAddresses(Funcdata *,PcodeOp *,vector<Address> &addresses,
                      vector<LoadTable> *loads,vector<int4> *loadcounts) const override
  {
    state->buildCalls += 1;
    addresses = buildTargets;
    if (loads != (vector<LoadTable> *)0)
      loads->insert(loads->end(),buildLoads.begin(),buildLoads.end());
    if (loadcounts != (vector<int4> *)0) {
      int4 count = (loads == (vector<LoadTable> *)0) ? 0 : loads->size();
      for(size_t i=0;i<buildTargets.size();++i)
        loadcounts->push_back(count);
    }
  }
  void findUnnormalized(uint4,uint4,uint4) override {}
  void buildLabels(Funcdata *,vector<Address> &,vector<uintb> &,const JumpModel *) const override {}
  Varnode *foldInNormalization(Funcdata *,PcodeOp *) override { return (Varnode *)0; }
  bool foldInGuards(Funcdata *,JumpTable *) override { return false; }
  bool sanityCheck(Funcdata *,PcodeOp *,vector<Address> &addresses,
                   vector<LoadTable> &loads,vector<int4> *loadcounts) override
  {
    state->sanityCalls += 1;
    if (mutateOnReject) {
      if (addresses.size() > 1)
        addresses.resize(1);
      loads.push_back(LoadTable(Address(code,0x3008),4));
      if (loadcounts != (vector<int4> *)0)
        loadcounts->push_back(7);
    }
    return sanityResult;
  }
  JumpModel *clone(JumpTable *jt) const override
  {
    return new FixtureModel(jt,overrideMode,sanityResult,mutateOnReject,
                            code,buildTargets,buildLoads,state);
  }
};

struct CaseConfig {
  const char *id;
  vector<uintb> targetOffsets;
  bool unreachable;
  bool overrideMode;
  bool sanityResult;
  bool mutateOnReject;
  bool driveRecover;
};

static string addressesText(const vector<Address> &addresses)
{
  ostringstream s;
  for(size_t i=0;i<addresses.size();++i) {
    if (i != 0) s << ',';
    addresses[i].printRaw(s);
  }
  return s.str();
}

static string loadsText(const vector<LoadTable> &loads)
{
  ostringstream s;
  for(size_t i=0;i<loads.size();++i) {
    if (i != 0) s << ',';
    loads[i].addr.printRaw(s);
    s << '/' << loads[i].size << '/' << loads[i].num;
  }
  return s.str();
}

static string countsText(const vector<int4> &counts)
{
  ostringstream s;
  for(size_t i=0;i<counts.size();++i) {
    if (i != 0) s << ',';
    s << counts[i];
  }
  return s.str();
}

static PcodeOp *buildIndirect(Funcdata &fd,AddrSpace *code,bool unreachable,uintb opOffset)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *switchBlock = graph.newBlockBasic(&fd);
  if (unreachable) {
    BlockBasic *guard = graph.newBlockBasic(&fd);
    BlockBasic *other = graph.newBlockBasic(&fd);
    PcodeOp *cbranch = fd.newOp(2,Address(code,opOffset-8));
    fd.opSetOpcode(cbranch,CPUI_CBRANCH);
    fd.opSetInput(cbranch,fd.newConstant(8,opOffset+0x40),0);
    fd.opSetInput(cbranch,fd.newConstant(1,0),1);
    fd.opInsertEnd(cbranch,guard);
    graph.addEdge(guard,other);       // out(0): surviving false path
    graph.addEdge(guard,switchBlock); // out(1): eliminated switch path
  }
  PcodeOp *indirect = fd.newOp(1,Address(code,opOffset));
  fd.opSetOpcode(indirect,CPUI_BRANCHIND);
  fd.opSetInput(indirect,fd.newConstant(8,opOffset+0x20),0);
  fd.opInsertEnd(indirect,switchBlock);
  return indirect;
}

static void runCase(FixtureArchitecture &architecture,const CaseConfig &config)
{
  const uintb opOffset = 0x100000;
  AddrSpace *code = architecture.getSpace(3);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd(config.id,config.id,global,Address(code,0x90000),
              (FunctionSymbol *)0,0x20000);
  PcodeOp *indirect = buildIndirect(fd,code,config.unreachable,opOffset);

  vector<Address> targets;
  for(size_t i=0;i<config.targetOffsets.size();++i)
    targets.push_back(Address(code,config.targetOffsets[i]));
  vector<LoadTable> initialLoads;
  initialLoads.push_back(LoadTable(Address(code,0x3004),4));
  initialLoads.push_back(LoadTable(Address(code,0x3000),4));
  vector<int4> loadcounts;
  loadcounts.push_back(1);
  loadcounts.push_back(2);

  JumpTable table(&architecture);
  table.setIndirectOp(indirect);
  ModelState state;
  table.jmodel = new FixtureModel(&table,config.overrideMode,config.sanityResult,
                                  config.mutateOnReject,code,targets,initialLoads,&state);
  table.addresstable = config.driveRecover ? vector<Address>() : targets;
  table.loadpoints = config.driveRecover ? vector<LoadTable>() : initialLoads;
  table.collectloads = config.driveRecover;

  string kind = "success";
  string message = "none";
  int4 mode = JumpTable::success;
  try {
    if (config.driveRecover)
      table.recoverAddresses(&fd);
    else
      table.sanityCheck(&fd,&loadcounts);
  }
  catch(const JumptableThunkError &error) {
    kind = "thunk";
    message = error.explain;
    mode = JumpTable::fail_thunk;
  }
  catch(const LowlevelError &error) {
    kind = "lowlevel";
    message = error.explain;
    mode = JumpTable::fail_normal;
  }

  cout << "case|id=" << config.id
       << "|path=" << (config.driveRecover ? "recover" : "sanity")
       << "|kind=" << kind
       << "|mode=" << mode
       << "|msg=" << message
       << "|partial=" << (table.partialTable ? 1 : 0)
       << "|override=" << (table.jmodel->isOverride() ? 1 : 0)
       << "|recover_calls=" << state.recoverCalls
       << "|build_calls=" << state.buildCalls
       << "|sanity_calls=" << state.sanityCalls
       << "|addresses=" << addressesText(table.addresstable)
       << "|loads=" << loadsText(table.loadpoints)
       << "|loadcounts=" << countsText(loadcounts)
       << '\n';
}

static void run(void)
{
  FixtureArchitecture architecture;
  const uintb op = 0x100000;
  const CaseConfig cases[] = {
    { "zero",       { 0 },                 false, false, true,  false, false },
    { "near",       { op + 0x20 },         false, false, true,  false, false },
    { "cutoff",     { op + 0xffff },       false, false, true,  false, false },
    { "over",       { op + 0x10000 },      false, false, true,  false, false },
    { "multi",      { 0, op + 0x20000 },   false, false, true,  false, false },
    { "partial",    { 0 },                 true,  false, true,  false, false },
    { "override",   { 0 },                 true,  true,  true,  false, true  },
    { "model_reject", { op + 0x10, op + 0x20 }, false, false, false, true, false },
  };
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i)
    runCase(architecture,cases[i]);
}

} // namespace

int main(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  try {
    run();
  }
  catch(const LowlevelError &error) {
    std::cerr << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
