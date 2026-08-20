/*
 * RULE-ADDUNSIGNED-TYPEPRECOND-0001
 *
 * Locked Ghidra 12.0.4 oracle for RuleAddUnsigned::getOpList/applyOp
 * (ruleaction.cc:7176-7214). The three cases isolate the read-facing
 * TYPE_UINT precondition from the high-quarter value test:
 *
 *   unknown_ff - newConstant's canonical TYPE_UNKNOWN + 0xff: reject
 *   uint_ff    - same-factory canonical TYPE_UINT + 0xff: rewrite to SUB 1
 *   uint_7f    - same-factory canonical TYPE_UINT + 0x7f: reject
 *
 * The projection records the rule return, opcode, operand/output identities,
 * replacement constant value/type/locks/symbol link, def-use bookkeeping,
 * alive/dead/block membership, and Varnode create indices. It deliberately
 * does not claim the op-aware union, character-print, real SymbolEntry/
 * EquateSymbol, or enum named-value branches.
 */

#include <bits/stdc++.h>

// Test-only access sets a bare namelock bit on uint_ff so copySymbol's exact
// typelock|namelock field transfer is observable without constructing a real
// EquateSymbol (which is an explicitly registered residual below).
#define private public
#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "ruleaction.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef private

#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
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
    VarnodeData stackPointer;
    stackPointer.space = reg;
    stackPointer.offset = 0;
    stackPointer.size = 8;
    addSpacebasePointer(stack,stackPointer,8,true);
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"join",false,8,1,6,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new IopSpace(this,this,7));
    setDefaultCodeSpace(3);
    dummyRegister.space = reg;
    dummyRegister.offset = 0;
    dummyRegister.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummyRegister; }
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
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const string &) const override {}
};

static size_t countDescendants(const Varnode *vn)
{
  return static_cast<size_t>(std::distance(vn->beginDescend(),vn->endDescend()));
}

static const char *metaToken(type_metatype meta)
{
  switch(meta) {
  case TYPE_UNKNOWN: return "unknown";
  case TYPE_UINT: return "uint";
  default: return "other";
  }
}

static size_t countAlive(const Funcdata &fd)
{
  return static_cast<size_t>(std::distance(fd.beginOpAlive(),fd.endOpAlive()));
}

static size_t countDead(const Funcdata &fd)
{
  return static_cast<size_t>(std::distance(fd.beginOpDead(),fd.endOpDead()));
}

static bool aliveContains(const Funcdata &fd,const PcodeOp *op)
{
  for(list<PcodeOp *>::const_iterator iter=fd.beginOpAlive();iter!=fd.endOpAlive();++iter)
    if (*iter == op) return true;
  return false;
}

static size_t countBlockOps(const BlockBasic *block)
{
  return static_cast<size_t>(std::distance(block->beginOp(),block->endOp()));
}

static void emitState(const string &caseName,const string &stage,const string &result,
                      const Funcdata &fd,const BlockBasic *block,const PcodeOp *op,
                      const Varnode *input0,const Varnode *source,const Varnode *output,
                      const Datatype *uintType)
{
  const Varnode *current = op->getIn(1);
  const Datatype *currentType = current->getType();
  std::cout << "case=" << caseName
            << "|stage=" << stage
            << "|result=" << result
            << "|opcode=" << static_cast<int4>(op->code())
            << "|slot0_same=" << (op->getIn(0) == input0 ? 1 : 0)
            << "|slot1_is_source=" << (current == source ? 1 : 0)
            << "|new_constant=" << (current != source ? 1 : 0)
            << "|output_same=" << (op->getOut() == output ? 1 : 0)
            << "|value=" << current->getOffset()
            << "|size=" << current->getSize()
            << "|constant=" << (current->isConstant() ? 1 : 0)
            << "|type_meta=" << metaToken(currentType->getMetatype())
            << "|type_size=" << currentType->getSize()
            << "|type_same_source=" << (currentType == source->getType() ? 1 : 0)
            << "|type_is_factory_uint=" << (currentType == uintType ? 1 : 0)
            << "|type_lock=" << (current->isTypeLock() ? 1 : 0)
            << "|name_lock=" << (current->isNameLock() ? 1 : 0)
            << "|symbol_present=" << (current->getSymbolEntry() != (SymbolEntry *)0 ? 1 : 0)
            << "|symbol_same=" << (current->getSymbolEntry() == source->getSymbolEntry() ? 1 : 0)
            << "|source_desc=" << countDescendants(source)
            << "|current_desc=" << countDescendants(current)
            << "|input0_desc=" << countDescendants(input0)
            << "|output_def_is_op=" << (output->getDef() == op ? 1 : 0)
            << "|current_def_null=" << (current->getDef() == (PcodeOp *)0 ? 1 : 0)
            << "|alive_count=" << countAlive(fd)
            << "|alive_has_op=" << (aliveContains(fd,op) ? 1 : 0)
            << "|dead_count=" << countDead(fd)
            << "|block_count=" << countBlockOps(block)
            << "|parent_is_block=" << (op->getParent() == block ? 1 : 0)
            << "|op_dead=" << (op->isDead() ? 1 : 0)
            << "|source_create=" << source->getCreateIndex()
            << "|current_create=" << current->getCreateIndex()
            << "|input0_create=" << input0->getCreateIndex()
            << "|output_create=" << output->getCreateIndex()
            << '\n';
}

static void runCase(FixtureArchitecture &architecture,const string &caseName,
                    uintb value,bool installUint,bool lockTypeAndName)
{
  Scope *scope = architecture.symboltab->getGlobalScope();
  AddrSpace *ram = architecture.getSpaceByName("ram");
  AddrSpace *reg = architecture.getSpaceByName("register");
  if (scope == (Scope *)0 || ram == (AddrSpace *)0 || reg == (AddrSpace *)0)
    throw std::runtime_error("synthetic architecture is incomplete");

  Funcdata fd("fx","fx",scope,Address(ram,0x1000),(FunctionSymbol *)0,0x20);
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);
  Varnode *input0 = fd.setInputVarnode(fd.newVarnode(1,reg,0x40));
  Varnode *source = fd.newConstant(1,value);
  Datatype *uintType = architecture.types->getBase(1,TYPE_UINT);
  if (installUint)
    source->updateType(uintType,lockTypeAndName,false);
  if (lockTypeAndName)
    source->setFlags(Varnode::namelock);

  PcodeOp *op = fd.newOp(2,Address(ram,0x2000));
  fd.opSetOpcode(op,CPUI_INT_ADD);
  Varnode *output = fd.newUniqueOut(1,op);
  fd.opSetInput(op,input0,0);
  fd.opSetInput(op,source,1);
  fd.opInsertEnd(op,block);

  emitState(caseName,"before","na",fd,block,op,input0,source,output,uintType);
  RuleAddUnsigned rule("analysis");
  int4 result = rule.applyOp(op,fd);
  emitState(caseName,"after",std::to_string(result),fd,block,op,input0,source,
            output,uintType);
}

static void run(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  {
    FixtureArchitecture architecture;
    RuleAddUnsigned rule("analysis");
    vector<uint4> opcodes;
    rule.getOpList(opcodes);
    std::cout << "getoplist:count=" << opcodes.size() << ",opcode="
              << (opcodes.empty() ? -1 : static_cast<int4>(opcodes[0])) << '\n';
    runCase(architecture,"unknown_ff",0xff,false,false);
    runCase(architecture,"uint_ff",0xff,true,true);
    runCase(architecture,"uint_7f",0x7f,true,false);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(void)
{
  try {
    run();
    return 0;
  }
  catch(const ghidra::LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
  }
  catch(const ghidra::DecoderError &error) {
    std::cerr << "Ghidra DecoderError: " << error.explain << '\n';
  }
  catch(const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  return 1;
}
