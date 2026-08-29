/*
 * RULE-2COMP2SUB-0001
 *
 * Locked Ghidra 12.0.4 oracle for Rule2Comp2Sub::getOpList/applyOp
 * (ruleaction.cc:7216-7237). Five cases isolate the lone-INT_ADD gate and
 * both rewrite orientations:
 *
 *   v_plus_negw   - ADD(V, 2COMP(W)): fires; ADD becomes SUB(V,W), the
 *                   2COMP op is destroyed completely.
 *   negw_plus_v   - ADD(2COMP(W), V): fires via the slot-0 swap; the ADD
 *                   becomes SUB(V,W) with V in slot 0.
 *   nonadd_lone   - the 2COMP out feeds a lone INT_MULT: rejected.
 *   no_descend    - the 2COMP out has no descendants: rejected.
 *   two_descend   - the 2COMP out feeds two INT_ADDs: rejected.
 *
 * The projection records the rule return, both ops' opcode/dead state and
 * slot-0/slot-1 identity booleans against V, W and the 2COMP output,
 * V/W/2COMP-output descendant counts, alive/dead op counts, and block
 * membership. The 2COMP output is never touched after a firing applyOp
 * (Funcdata::opDestroy frees it, funcdata_op.cc:203-224); its descendant
 * count prints "-" on after records of fired cases by contract.
 */

#include <bits/stdc++.h>

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

static size_t countAlive(const Funcdata &fd)
{
  return static_cast<size_t>(std::distance(fd.beginOpAlive(),fd.endOpAlive()));
}

static size_t countDead(const Funcdata &fd)
{
  return static_cast<size_t>(std::distance(fd.beginOpDead(),fd.endOpDead()));
}

static size_t countBlockOps(const BlockBasic *block)
{
  return static_cast<size_t>(std::distance(block->beginOp(),block->endOp()));
}

struct UseOp {
  PcodeOp *op;
  UseOp(PcodeOp *o) : op(o) {}
};

static void emitUse(const UseOp &use,const Varnode *v,const Varnode *w,
                    const Varnode *out2c)
{
  if (use.op == (PcodeOp *)0) {
    std::cout << "|use=-";
    return;
  }
  std::cout << "|use_opcode=" << static_cast<int4>(use.op->code())
            << ",in0_is_v=" << (use.op->getIn(0) == v ? 1 : 0)
            << ",in1_is_w=" << (use.op->getIn(1) == w ? 1 : 0)
            << ",in0_is_out2c=" << (use.op->getIn(0) == out2c ? 1 : 0)
            << ",in1_is_out2c=" << (use.op->getIn(1) == out2c ? 1 : 0);
}

static void emitState(const string &caseName,const string &stage,const string &result,
                      const Funcdata &fd,const BlockBasic *block,const PcodeOp *twocomp,
                      const UseOp &use1,const UseOp &use2,const Varnode *v,
                      const Varnode *w,const Varnode *out2c,bool out2cFreed)
{
  std::cout << "case=" << caseName
            << "|stage=" << stage
            << "|result=" << result
            << "|twocomp_opcode=" << static_cast<int4>(twocomp->code())
            << "|twocomp_dead=" << (twocomp->isDead() ? 1 : 0);
  emitUse(use1,v,w,out2c);
  emitUse(use2,v,w,out2c);
  std::cout << "|v_desc=" << countDescendants(v)
            << "|w_desc=" << countDescendants(w)
            << "|out2c_desc="
            << (out2cFreed ? string("-") : std::to_string(countDescendants(out2c)))
            << "|alive=" << countAlive(fd)
            << "|dead=" << countDead(fd)
            << "|block_ops=" << countBlockOps(block)
            << '\n';
}

// Builds: V, W register inputs; a 2COMP(W) at 0x2000; then case-specific
// consumers. Returns via out-params so the caller keeps every pointer.
struct CaseIr {
  BlockBasic *block;
  Varnode *v;
  Varnode *w;
  PcodeOp *twocomp;
  Varnode *out2c;
  PcodeOp *use1;
  PcodeOp *use2;
};

static CaseIr buildCase(FixtureArchitecture &architecture,Funcdata &fd,
                        const string &shape)
{
  AddrSpace *reg = architecture.getSpaceByName("register");
  AddrSpace *ram = architecture.getSpaceByName("ram");
  if (reg == (AddrSpace *)0 || ram == (AddrSpace *)0)
    throw std::runtime_error("synthetic architecture is incomplete");
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);

  Varnode *v = fd.setInputVarnode(fd.newVarnode(4,reg,0x40));
  Varnode *w = fd.setInputVarnode(fd.newVarnode(4,reg,0x50));

  PcodeOp *twocomp = fd.newOp(2,Address(ram,0x2000));
  fd.opSetOpcode(twocomp,CPUI_INT_2COMP);
  Varnode *out2c = fd.newUniqueOut(4,twocomp);
  fd.opSetInput(twocomp,w,0);
  fd.opInsertEnd(twocomp,block);

  PcodeOp *use1 = (PcodeOp *)0;
  PcodeOp *use2 = (PcodeOp *)0;
  if (shape == "add_in1") {		// ADD(V, 2COMP(W))
    use1 = fd.newOp(2,Address(ram,0x2010));
    fd.opSetOpcode(use1,CPUI_INT_ADD);
    fd.newUniqueOut(4,use1);
    fd.opSetInput(use1,v,0);
    fd.opSetInput(use1,out2c,1);
    fd.opInsertEnd(use1,block);
  }
  else if (shape == "add_in0") {	// ADD(2COMP(W), V)
    use1 = fd.newOp(2,Address(ram,0x2010));
    fd.opSetOpcode(use1,CPUI_INT_ADD);
    fd.newUniqueOut(4,use1);
    fd.opSetInput(use1,out2c,0);
    fd.opSetInput(use1,v,1);
    fd.opInsertEnd(use1,block);
  }
  else if (shape == "mult_lone") {	// MULT(2COMP(W), 2)
    use1 = fd.newOp(2,Address(ram,0x2010));
    fd.opSetOpcode(use1,CPUI_INT_MULT);
    fd.newUniqueOut(4,use1);
    fd.opSetInput(use1,out2c,0);
    fd.opSetInput(use1,fd.newConstant(4,2),1);
    fd.opInsertEnd(use1,block);
  }
  else if (shape == "two_adds") {	// two ADDs read the 2COMP out
    use1 = fd.newOp(2,Address(ram,0x2010));
    fd.opSetOpcode(use1,CPUI_INT_ADD);
    fd.newUniqueOut(4,use1);
    fd.opSetInput(use1,out2c,0);
    fd.opSetInput(use1,v,1);
    fd.opInsertEnd(use1,block);
    use2 = fd.newOp(2,Address(ram,0x2020));
    fd.opSetOpcode(use2,CPUI_INT_ADD);
    fd.newUniqueOut(4,use2);
    fd.opSetInput(use2,v,0);
    fd.opSetInput(use2,out2c,1);
    fd.opInsertEnd(use2,block);
  }
  // shape == "none": the 2COMP out has no descendants.

  CaseIr ir;
  ir.block = block;
  ir.v = v;
  ir.w = w;
  ir.twocomp = twocomp;
  ir.out2c = out2c;
  ir.use1 = use1;
  ir.use2 = use2;
  return ir;
}

static void runCase(FixtureArchitecture &architecture,const string &caseName,
                    const string &shape)
{
  Scope *scope = architecture.symboltab->getGlobalScope();
  AddrSpace *ram = architecture.getSpaceByName("ram");
  Funcdata fd("fx","fx",scope,Address(ram,0x1000),(FunctionSymbol *)0,0x20);
  CaseIr ir = buildCase(architecture,fd,shape);
  UseOp use1(ir.use1);
  UseOp use2(ir.use2);

  emitState(caseName,"before","na",fd,ir.block,ir.twocomp,use1,use2,ir.v,ir.w,
            ir.out2c,false);
  Rule2Comp2Sub rule("cleanup");
  int4 result = rule.applyOp(ir.twocomp,fd);
  emitState(caseName,"after",std::to_string(result),fd,ir.block,ir.twocomp,use1,
            use2,ir.v,ir.w,ir.out2c,result != 0);
}

static void run(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  {
    FixtureArchitecture architecture;
    Rule2Comp2Sub rule("cleanup");
    vector<uint4> opcodes;
    rule.getOpList(opcodes);
    std::cout << "getoplist:count=" << opcodes.size() << ",opcode="
              << (opcodes.empty() ? -1 : static_cast<int4>(opcodes[0])) << '\n';
    runCase(architecture,"v_plus_negw","add_in1");
    runCase(architecture,"negw_plus_v","add_in0");
    runCase(architecture,"nonadd_lone","mult_lone");
    runCase(architecture,"no_descend","none");
    runCase(architecture,"two_descend","two_adds");
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
