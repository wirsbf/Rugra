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
#include "comment.hh"
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
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"tiny",false,1,1,8,
                              AddrSpace::hasphysical,0,0));
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
    commentdb = new CommentDatabaseInternal();
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
  int4 buildLoadsPresent;
  int4 buildCountsPresent;
  vector<int4> observedLoadcounts;
  vector<string> events;
  ModelState(void) : recoverCalls(0), buildCalls(0), sanityCalls(0),
                     buildLoadsPresent(-1), buildCountsPresent(-1) {}
};

class FixtureModel final : public JumpModel {
  bool overrideMode;
  bool transientOverride;
  bool sanityResult;
  bool mutateDuringSanity;
  AddrSpace *code;
  vector<Address> buildTargets;
  vector<LoadTable> buildLoads;
  ModelState *state;
public:
  FixtureModel(JumpTable *jt,bool over,bool transient,bool sane,bool mutate,AddrSpace *spc,
               const vector<Address> &targets,const vector<LoadTable> &loads,
               ModelState *st)
    : JumpModel(jt), overrideMode(over), transientOverride(transient), sanityResult(sane),
      mutateDuringSanity(mutate), code(spc), buildTargets(targets),
      buildLoads(loads), state(st) {}

  bool isOverride(void) const override
  {
    return overrideMode || (transientOverride && state->recoverCalls == 0);
  }
  int4 getTableSize(void) const override { return buildTargets.size(); }
  bool recoverModel(Funcdata *,PcodeOp *,uint4,uint4) override
  {
    state->recoverCalls += 1;
    state->events.push_back("recover");
    return true;
  }
  void buildAddresses(Funcdata *,PcodeOp *,vector<Address> &addresses,
                      vector<LoadTable> *loads,vector<int4> *loadcounts) const override
  {
    state->buildCalls += 1;
    state->events.push_back("build");
    state->buildLoadsPresent = (loads != (vector<LoadTable> *)0) ? 1 : 0;
    state->buildCountsPresent = (loadcounts != (vector<int4> *)0) ? 1 : 0;
    addresses = buildTargets;
    if (loads != (vector<LoadTable> *)0)
      loads->insert(loads->end(),buildLoads.begin(),buildLoads.end());
    if (loadcounts != (vector<int4> *)0) {
      int4 count = (loads == (vector<LoadTable> *)0) ? 0 : loads->size();
      for(size_t i=0;i<buildTargets.size();++i)
        loadcounts->push_back(count);
      state->observedLoadcounts = *loadcounts;
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
    state->events.push_back("sanity");
    if (mutateDuringSanity) {
      if (addresses.size() > 1)
        addresses.resize(1);
      loads.push_back(LoadTable(Address(code,0x3008),4));
      if (loadcounts != (vector<int4> *)0)
        loadcounts->push_back(7);
    }
    if (loadcounts != (vector<int4> *)0)
      state->observedLoadcounts = *loadcounts;
    return sanityResult;
  }
  JumpModel *clone(JumpTable *jt) const override
  {
    return new FixtureModel(jt,overrideMode,transientOverride,sanityResult,mutateDuringSanity,
                            code,buildTargets,buildLoads,state);
  }
};

enum ReachVariant {
  reach_none,
  reach_false,
  reach_two_level,
  reach_flip,
  reach_nonzero,
  reach_size_out,
  reach_non_cbranch,
  reach_nonconstant
};

enum LoadVariant {
  load_default,
  load_equal_three,
  load_equal_sixteen,
  load_equal_seventeen,
  load_equal_thirtytwo,
  load_wrap,
  load_multi_space
};

struct CaseConfig {
  const char *id;
  vector<uintb> targetOffsets;
  ReachVariant reach;
  bool overrideMode;
  bool sanityResult;
  bool mutateDuringSanity;
  bool driveRecover;
  bool collectLoads;
  bool realModel;
  LoadVariant loads;
};

static void appendAddress(ostringstream &s,const Address &address)
{
  AddrSpace *space = address.getSpace();
  s << ((space == (AddrSpace *)0) ? -1 : space->getIndex()) << '@';
  address.printRaw(s);
}

static string addressesText(const vector<Address> &addresses)
{
  ostringstream s;
  for(size_t i=0;i<addresses.size();++i) {
    if (i != 0) s << ',';
    appendAddress(s,addresses[i]);
  }
  return s.str();
}

static string loadsText(const vector<LoadTable> &loads)
{
  ostringstream s;
  for(size_t i=0;i<loads.size();++i) {
    if (i != 0) s << ',';
    appendAddress(s,loads[i].addr);
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

static string eventsText(const vector<string> &events)
{
  ostringstream s;
  for(size_t i=0;i<events.size();++i) {
    if (i != 0) s << '>';
    s << events[i];
  }
  return s.str();
}

static string warningsText(const CommentDatabase *commentdb,const Address &functionAddress)
{
  ostringstream s;
  CommentSet::const_iterator iter = commentdb->beginComment(functionAddress);
  CommentSet::const_iterator enditer = commentdb->endComment(functionAddress);
  for(;iter!=enditer;++iter) {
    if (iter != commentdb->beginComment(functionAddress)) s << ',';
    s << (*iter)->getType() << '@';
    (*iter)->getAddr().printRaw(s);
    s << ':' << (*iter)->getText();
  }
  return s.str();
}

static BlockBasic *addGuard(Funcdata &fd,BlockGraph &graph,AddrSpace *code,
                            BlockBasic *parent,uintb opOffset,uintb condition,
                            bool flip,bool twoEdges,bool cbranch,bool constant)
{
  BlockBasic *guard = graph.newBlockBasic(&fd);
  BlockBasic *other = graph.newBlockBasic(&fd);
  if (cbranch) {
    PcodeOp *op = fd.newOp(2,Address(code,opOffset));
    fd.opSetOpcode(op,CPUI_CBRANCH);
    fd.opSetInput(op,fd.newConstant(8,opOffset+0x40),0);
    fd.opSetInput(op,constant ? fd.newConstant(1,condition) : fd.newUnique(1),1);
    if (flip)
      op->flags |= PcodeOp::boolean_flip;
    fd.opInsertEnd(op,guard);
  }
  else {
    PcodeOp *op = fd.newOp(1,Address(code,opOffset));
    fd.opSetOpcode(op,CPUI_COPY);
    fd.opSetInput(op,fd.newConstant(1,condition),0);
    fd.opInsertEnd(op,guard);
  }
  if (twoEdges)
    graph.addEdge(guard,other); // out(0)
  graph.addEdge(guard,parent);  // out(1), or the only edge
  return guard;
}

static PcodeOp *buildIndirect(Funcdata &fd,AddrSpace *code,ReachVariant reach,uintb opOffset)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *switchBlock = graph.newBlockBasic(&fd);
  switch(reach) {
  case reach_none:
    break;
  case reach_false:
    addGuard(fd,graph,code,switchBlock,opOffset-8,0,false,true,true,true);
    break;
  case reach_two_level: {
    BlockBasic *inner = addGuard(fd,graph,code,switchBlock,opOffset-8,1,
                                 false,true,true,true);
    addGuard(fd,graph,code,inner,opOffset-16,0,false,true,true,true);
    break;
  }
  case reach_flip:
    addGuard(fd,graph,code,switchBlock,opOffset-8,1,true,true,true,true);
    break;
  case reach_nonzero:
    addGuard(fd,graph,code,switchBlock,opOffset-8,1,false,true,true,true);
    break;
  case reach_size_out:
    addGuard(fd,graph,code,switchBlock,opOffset-8,0,false,false,true,true);
    break;
  case reach_non_cbranch:
    addGuard(fd,graph,code,switchBlock,opOffset-8,0,false,true,false,true);
    break;
  case reach_nonconstant:
    addGuard(fd,graph,code,switchBlock,opOffset-8,0,false,true,true,false);
    break;
  }

  PcodeOp *indirect = fd.newOp(1,Address(code,opOffset));
  fd.opSetOpcode(indirect,CPUI_BRANCHIND);
  if (reach == reach_none)
    fd.opSetInput(indirect,fd.newUnique(4),0);
  else
    fd.opSetInput(indirect,fd.newConstant(8,opOffset+0x20),0);
  fd.opInsertEnd(indirect,switchBlock);
  return indirect;
}

static vector<LoadTable> buildLoads(AddrSpace *code,AddrSpace *tiny,LoadVariant variant)
{
  vector<LoadTable> loads;
  switch(variant) {
  case load_default:
    loads.push_back(LoadTable(Address(code,0x3004),4));
    loads.push_back(LoadTable(Address(code,0x3000),4));
    break;
  case load_equal_three:
    loads.push_back(LoadTable(Address(code,0x4000),8,2));
    loads.push_back(LoadTable(Address(code,0x4000),4,3));
    loads.push_back(LoadTable(Address(code,0x4010),8,1));
    break;
  case load_equal_sixteen:
  case load_equal_seventeen:
  case load_equal_thirtytwo: {
    int4 count = (variant == load_equal_sixteen) ? 16
               : (variant == load_equal_seventeen) ? 17 : 32;
    for(int4 i=0;i<count;++i)
      loads.push_back(LoadTable(Address(code,0x4000),(i & 1) ? 8 : 4));
    break;
  }
  case load_wrap:
    loads.push_back(LoadTable(Address(tiny,0xfc),4));
    loads.push_back(LoadTable(Address(tiny,0),4));
    break;
  case load_multi_space:
    loads.push_back(LoadTable(Address(tiny,0),4));
    loads.push_back(LoadTable(Address(code,0x4000),4));
    loads.push_back(LoadTable(Address(tiny,4),4));
    loads.push_back(LoadTable(Address(code,0x4004),4));
    break;
  }
  return loads;
}

static void runCase(FixtureArchitecture &architecture,const CaseConfig &config)
{
  const uintb opOffset = 0x100000;
  architecture.commentdb->clear();
  AddrSpace *code = architecture.getSpace(3);
  AddrSpace *tiny = architecture.getSpace(8);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd(config.id,config.id,global,Address(code,0x90000),
              (FunctionSymbol *)0,0x20000);
  PcodeOp *indirect = buildIndirect(fd,code,config.reach,opOffset);

  vector<Address> targets;
  for(size_t i=0;i<config.targetOffsets.size();++i)
    targets.push_back(Address(code,config.targetOffsets[i]));
  vector<LoadTable> initialLoads = buildLoads(code,tiny,config.loads);
  vector<int4> loadcounts;
  loadcounts.push_back(1);
  loadcounts.push_back(2);

  JumpTable table(&architecture);
  table.setIndirectOp(indirect);
  ModelState state;
  if (!config.realModel)
    table.jmodel = new FixtureModel(&table,config.overrideMode,
                                    config.driveRecover && !config.overrideMode,
                                    config.sanityResult,config.mutateDuringSanity,
                                    code,targets,initialLoads,&state);
  table.addresstable = config.driveRecover ? vector<Address>() : targets;
  table.loadpoints = config.driveRecover ? vector<LoadTable>() : initialLoads;
  table.collectloads = config.collectLoads;

  string kind = "success";
  string message = "none";
  int4 mode = JumpTable::success;
  try {
    if (config.driveRecover) {
      table.recoverAddresses(&fd);
      if (config.collectLoads)
        state.events.push_back("collapse");
    }
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

  const vector<int4> &observedCounts = config.driveRecover
      ? state.observedLoadcounts : loadcounts;
  string warnings = warningsText(architecture.commentdb,fd.getAddress());
  if (warnings.empty()) warnings = "none";

  cout << "case|id=" << config.id
       << "|path=" << (config.driveRecover ? "recover" : "sanity")
       << "|kind=" << kind
       << "|mode=" << mode
       << "|msg=" << message
       << "|partial=" << (table.partialTable ? 1 : 0)
       << "|override=" << ((table.jmodel != (JumpModel *)0 && table.jmodel->isOverride()) ? 1 : 0)
       << "|collect=" << (table.collectloads ? 1 : 0)
       << "|recover_calls=" << state.recoverCalls
       << "|build_calls=" << state.buildCalls
       << "|sanity_calls=" << state.sanityCalls
       << "|build_loads=" << state.buildLoadsPresent
       << "|build_counts=" << state.buildCountsPresent
       << "|events=" << eventsText(state.events)
       << "|addresses=" << addressesText(table.addresstable)
       << "|loads=" << loadsText(table.loadpoints)
       << "|loadcounts=" << countsText(observedCounts)
       << "|warning=" << warnings
       << '\n';
}

static void run(void)
{
  FixtureArchitecture architecture;
  const uintb op = 0x100000;
  const CaseConfig cases[] = {
    { "zero",       { 0 },               reach_none, false, true,  false, false, false, false, load_default },
    { "near",       { op + 0x20 },       reach_none, false, true,  false, false, false, false, load_default },
    { "cutoff",     { op + 0xffff },     reach_none, false, true,  false, false, false, false, load_default },
    { "over",       { op + 0x10000 },    reach_none, false, true,  false, false, false, false, load_default },
    { "multi",      { 0, op + 0x20000 }, reach_none, false, true,  false, false, false, false, load_default },
    { "partial",    { 0 }, reach_false,       false, true, false, false, false, false, load_default },
    { "reach_two",  { 0 }, reach_two_level,   false, true, false, false, false, false, load_default },
    { "reach_flip", { 0 }, reach_flip,        false, true, false, false, false, false, load_default },
    { "reach_nonzero", { 0 }, reach_nonzero,  false, true, false, false, false, false, load_default },
    { "reach_size_out", { 0 }, reach_size_out,false, true, false, false, false, false, load_default },
    { "reach_non_cbranch", { 0 }, reach_non_cbranch,false,true,false,false,false,false,load_default },
    { "reach_nonconstant", { 0 }, reach_nonconstant,false,true,false,false,false,false,load_default },
    { "override",   { 0 }, reach_false, true, true, false, true, true, false, load_default },
    { "recover_model_fail", {}, reach_none, false, true, false, true, true, true, load_default },
    { "recover_table_zero", {}, reach_none, false, true, false, true, true, false, load_default },
    { "recover_no_collect", { op + 0x10, op + 0x20 }, reach_none, false, true, false, true, false, false, load_default },
    { "recover_thunk", { 0 }, reach_none, false, true, false, true, true, false, load_default },
    { "success_truncate", { op + 0x10, op + 0x20 }, reach_none, false, true, true, true, true, false, load_default },
    { "model_reject", { op + 0x10, op + 0x20 }, reach_none, false, false, true, true, true, false, load_default },
    { "sort_equal_three", { op + 0x10, op + 0x20 }, reach_none, false, true, false, true, true, false, load_equal_three },
    { "sort_equal_sixteen", { op + 0x10, op + 0x20 }, reach_none, false, true, false, true, true, false, load_equal_sixteen },
    { "sort_equal_seventeen", { op + 0x10, op + 0x20 }, reach_none, false, true, false, true, true, false, load_equal_seventeen },
    { "sort_equal_thirtytwo", { op + 0x10, op + 0x20 }, reach_none, false, true, false, true, true, false, load_equal_thirtytwo },
    { "wrap_one_byte", { op + 0x10, op + 0x20 }, reach_none, false, true, false, true, true, false, load_wrap },
    { "multi_space", { op + 0x10, op + 0x20 }, reach_none, false, true, false, true, true, false, load_multi_space },
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
