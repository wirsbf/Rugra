/* MERGE-DATATYPE-SCALE-0001: locked Ghidra 12.0.4 production-range oracle. */
#include <bits/stdc++.h>

#define private public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef private

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
  }
  void printMessage(const string &) const override {}
};

Varnode *makeWritten(Funcdata &fd,BlockBasic *block,AddrSpace *space,uintb offset,
                     uintb pc,Datatype *type)
{
  PcodeOp *op = fd.newOp(0,Address(fd.getArch()->getDefaultCodeSpace(),pc));
  fd.opSetOpcode(op,CPUI_COPY);
  Varnode *vn = fd.newVarnodeOut(4,Address(space,offset),op);
  vn->updateType(type);
  fd.opInsertEnd(op,block);
  return vn;
}

string instanceSpaces(HighVariable *high)
{
  ostringstream stream;
  for(int4 i=0;i<high->numInstances();++i) {
    if (i != 0) stream << '/';
    stream << high->getInstance(i)->getSpace()->getIndex();
  }
  return stream.str();
}

void runScale(size_t freeCount)
{
  FixtureArchitecture architecture;
  AddrSpace *unique = architecture.getSpace(2);
  AddrSpace *ram = architecture.getSpace(3);
  AddrSpace *reg = architecture.getSpace(4);
  Scope *global = architecture.symboltab->getGlobalScope();
  Funcdata fd("merge_scale","merge_scale",global,Address(ram,0x8000),
              (FunctionSymbol *)0,0x100);
  BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(&fd);
  fd.setBasicBlockRange(block,Address(ram,0x8000),Address(ram,0x80ff));

  Datatype *common = architecture.types->getBase(4,TYPE_UINT);
  TypeBase *identityA = new TypeBase(4,TYPE_UINT,"identity_same");
  TypeBase *identityB = new TypeBase(4,TYPE_UINT,"identity_same");
  TypeBase *tieType = new TypeBase(4,TYPE_UINT,"same_address_tie");

  vector<Varnode *> freeValues;
  for(size_t i=0;i<freeCount;++i) {
    Varnode *vn = fd.newVarnode(4,Address(reg,0x1000 + i * 8));
    vn->updateType(common);
    freeValues.push_back(vn);
  }

  Varnode *uniqueValue = makeWritten(fd,block,unique,0x30,0x8000,common);
  Varnode *ramValue = makeWritten(fd,block,ram,0x20,0x8001,common);
  Varnode *registerValue = makeWritten(fd,block,reg,0x10,0x8002,common);
  Varnode *implied = makeWritten(fd,block,reg,0x40,0x8003,common);
  implied->setImplied();
  Varnode *protoPartial = makeWritten(fd,block,reg,0x50,0x8004,common);
  protoPartial->setProtoPartial();
  Varnode *spacebase = makeWritten(fd,block,reg,0x60,0x8005,common);
  spacebase->setFlags(Varnode::spacebase);
  Varnode *typeA = makeWritten(fd,block,reg,0x70,0x8006,identityA);
  Varnode *typeB = makeWritten(fd,block,reg,0x80,0x8007,identityB);
  Varnode *tieFirst = makeWritten(fd,block,reg,0x90,0x8008,tieType);
  Varnode *tieSecond = makeWritten(fd,block,reg,0x90,0x8009,tieType);

  fd.setHighLevel();
  HighVariable *expectedSurvivor = uniqueValue->getHigh();
  HighVariable *expectedTieSurvivor = tieFirst->getHigh();
  fd.getMerge().mergeByDatatype(fd.beginLoc(),fd.endLoc());

  set<HighVariable *> freeHighs;
  bool freeSingletons = true;
  for(Varnode *vn : freeValues) {
    freeHighs.insert(vn->getHigh());
    freeSingletons &= vn->getHigh()->numInstances() == 1;
  }
  HighVariable *merged = uniqueValue->getHigh();
  bool legalMerged = merged == ramValue->getHigh() && merged == registerValue->getHigh();
  bool survivor = merged == expectedSurvivor;
  bool filtersSingleton = implied->getHigh()->numInstances() == 1 &&
      protoPartial->getHigh()->numInstances() == 1 &&
      spacebase->getHigh()->numInstances() == 1;
  bool identitySeparate = typeA->getHigh() != typeB->getHigh();
  HighVariable *tieMerged = tieFirst->getHigh();
  bool sameAddressStable = tieMerged == expectedTieSurvivor &&
      tieMerged == tieSecond->getHigh() && tieMerged->numInstances() == 2 &&
      tieMerged->getInstance(0) == tieFirst && tieMerged->getInstance(1) == tieSecond;
  bool marksClear = true;
  set<HighVariable *> observed;
  for(auto iter=fd.beginLoc();iter!=fd.endLoc();++iter) {
    HighVariable *high = (*iter)->getHigh();
    if (observed.insert(high).second)
      marksClear &= !high->isMark();
  }
  cout << "scale=" << freeCount
       << ",free_highs=" << freeHighs.size()
       << ",free_singletons=" << freeSingletons
       << ",legal_merged=" << legalMerged
       << ",sorted_survivor_unique=" << survivor
       << ",legal_instances=" << merged->numInstances()
       << ",instance_spaces=" << instanceSpaces(merged)
       << ",merge_groups=" << uniqueValue->getMergeGroup() << '/'
       << ramValue->getMergeGroup() << '/' << registerValue->getMergeGroup()
       << ",filters_singleton=" << filtersSingleton
       << ",type_identity_separate=" << identitySeparate
       << ",same_address_stable=" << sameAddressStable
       << ",marks_clear=" << marksClear << '\n';
}

} // namespace

int main()
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  try {
    runScale(1);
    runScale(2);
    runScale(32);
    runScale(1024);
  }
  catch(const LowlevelError &error) {
    cerr << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
