/*
 * RULE-DOUBLEIN-ARITHGATE-0001 (GEN4-SQ-BYTELANE-STRUCT-0001)
 *
 * Locked Ghidra 12.0.4 oracle for RuleDoubleIn::getOpList/applyOp/
 * attemptMarking (double.cc:3198-3279). Ten records isolate the
 * whole-def arithmetic gate of attemptMarking — the gate deciding whether
 * a SUBPIECE pair reading a 2-byte whole is marked as a double-precision
 * half pair:
 *
 *   int_add_whole    - whole = INT_ADD(a,b):    MARKED (arithmetic_op,
 *                      typeop.cc:1171).
 *   int_mult_whole   - whole = INT_MULT(a,b):   MARKED (typeop.cc:1621).
 *   int_2comp_whole  - whole = INT_2COMP(a):    MARKED (typeop.cc:1384).
 *   int_or_whole     - whole = INT_OR(a,b):     REJECTED — logical_op
 *                      (typeop.cc:1478); the read_inode byte-lane shape.
 *   int_xor_whole    - whole = INT_XOR(a,b):    REJECTED (typeop.cc:1445).
 *   int_and_whole    - whole = INT_AND(a,b):    REJECTED (typeop.cc:1412).
 *   int_negate_whole - whole = INT_NEGATE(a):   REJECTED (typeop.cc:1398).
 *   int_left_whole   - whole = INT_LEFT(a,1):   REJECTED — shift_op only
 *                      (typeop.cc:1506).
 *   int_zext_whole   - whole = INT_ZEXT(a1):    REJECTED — TypeOpIntZext
 *                      carries no arithmetic flag (typeop.cc:1115-1119).
 *   offset_mismatch  - whole = INT_ADD(a,b) but the rule target is the
 *                      SUBPIECE(W,0) lo half: REJECTED by the
 *                      offset==vn->getSize() precondition (double.cc:3227).
 *
 * Every case builds: 2-byte register inputs a,b; the whole-defining op at
 * 0x2000 with a 2-byte unique output W; SUBPIECE(W,1) -> 1-byte hi at
 * 0x2010; SUBPIECE(W,0) -> 1-byte lo at 0x2020. The projection records,
 * per case: the applyOp return, the target output's precisHi flag, the
 * sibling output's precisLo flag after the single applyOp, and the
 * function's alive-op count. The flags pin the marking decision; the op
 * count pins that attemptMarking only sets flags (no restructuring).
 */

#include <bits/stdc++.h>

#define private public
#include "architecture.hh"
#include "database.hh"
#include "double.hh"
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

static size_t countAlive(const Funcdata &fd)
{
  return static_cast<size_t>(std::distance(fd.beginOpAlive(),fd.endOpAlive()));
}

struct CaseIr {
  BlockBasic *block;
  PcodeOp *wholeDef;
  Varnode *whole;
  PcodeOp *hiSub;
  Varnode *hi;
  PcodeOp *loSub;
  Varnode *lo;
};

// Builds: 2-byte register inputs a,b; whole = <defop>(a[,b]) at 0x2000
// (2-byte unique output); SUBPIECE(whole,1) -> 1-byte hi at 0x2010;
// SUBPIECE(whole,0) -> 1-byte lo at 0x2020.
static CaseIr buildCase(FixtureArchitecture &architecture,Funcdata &fd,
                        const string &shape)
{
  AddrSpace *reg = architecture.getSpaceByName("register");
  AddrSpace *ram = architecture.getSpaceByName("ram");
  if (reg == (AddrSpace *)0 || ram == (AddrSpace *)0)
    throw std::runtime_error("synthetic architecture is incomplete");
  BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
  BlockBasic *block = graph.newBlockBasic(&fd);

  Varnode *a = fd.setInputVarnode(fd.newVarnode(2,reg,0x40));
  Varnode *b = fd.setInputVarnode(fd.newVarnode(2,reg,0x50));

  PcodeOp *wholeDef = (PcodeOp *)0;
  if (shape == "int_zext_whole") {
    // ZEXT reads a 1-byte input; give the case its own 1-byte input.
    Varnode *a1 = fd.setInputVarnode(fd.newVarnode(1,reg,0x60));
    wholeDef = fd.newOp(1,Address(ram,0x2000));
    fd.opSetOpcode(wholeDef,CPUI_INT_ZEXT);
    fd.opSetInput(wholeDef,a1,0);
  }
  else if (shape == "int_negate_whole" || shape == "int_2comp_whole") {
    wholeDef = fd.newOp(1,Address(ram,0x2000));
    fd.opSetOpcode(wholeDef,
      shape == "int_negate_whole" ? CPUI_INT_NEGATE : CPUI_INT_2COMP);
    fd.opSetInput(wholeDef,a,0);
  }
  else if (shape == "int_left_whole") {
    wholeDef = fd.newOp(2,Address(ram,0x2000));
    fd.opSetOpcode(wholeDef,CPUI_INT_LEFT);
    fd.opSetInput(wholeDef,a,0);
    fd.opSetInput(wholeDef,fd.newConstant(2,1),1);
  }
  else {
    wholeDef = fd.newOp(2,Address(ram,0x2000));
    OpCode opc = CPUI_INT_ADD;
    if (shape == "int_mult_whole") opc = CPUI_INT_MULT;
    else if (shape == "int_or_whole") opc = CPUI_INT_OR;
    else if (shape == "int_xor_whole") opc = CPUI_INT_XOR;
    else if (shape == "int_and_whole") opc = CPUI_INT_AND;
    fd.opSetOpcode(wholeDef,opc);
    fd.opSetInput(wholeDef,a,0);
    fd.opSetInput(wholeDef,b,1);
  }
  Varnode *whole = fd.newUniqueOut(2,wholeDef);
  fd.opInsertEnd(wholeDef,block);

  PcodeOp *hiSub = fd.newOp(2,Address(ram,0x2010));
  fd.opSetOpcode(hiSub,CPUI_SUBPIECE);
  Varnode *hi = fd.newUniqueOut(1,hiSub);
  fd.opSetInput(hiSub,whole,0);
  fd.opSetInput(hiSub,fd.newConstant(4,1),1);
  fd.opInsertEnd(hiSub,block);

  PcodeOp *loSub = fd.newOp(2,Address(ram,0x2020));
  fd.opSetOpcode(loSub,CPUI_SUBPIECE);
  Varnode *lo = fd.newUniqueOut(1,loSub);
  fd.opSetInput(loSub,whole,0);
  fd.opSetInput(loSub,fd.newConstant(4,0),1);
  fd.opInsertEnd(loSub,block);

  CaseIr ir;
  ir.block = block;
  ir.wholeDef = wholeDef;
  ir.whole = whole;
  ir.hiSub = hiSub;
  ir.hi = hi;
  ir.loSub = loSub;
  ir.lo = lo;
  return ir;
}

static void runCase(FixtureArchitecture &architecture,const string &caseName,
                    const string &shape)
{
  Scope *scope = architecture.symboltab->getGlobalScope();
  AddrSpace *ram = architecture.getSpaceByName("ram");
  Funcdata fd("fx","fx",scope,Address(ram,0x1000),(FunctionSymbol *)0,0x20);
  CaseIr ir = buildCase(architecture,fd,shape);
  RuleDoubleIn rule("analysis");
  // The rule target is the hi SUBPIECE (offset==vn size) except the
  // offset_mismatch case, which aims the rule at the lo SUBPIECE.
  bool aimLo = (caseName == "offset_mismatch");
  PcodeOp *target = aimLo ? ir.loSub : ir.hiSub;
  Varnode *targetOut = aimLo ? ir.lo : ir.hi;
  Varnode *siblingOut = aimLo ? ir.hi : ir.lo;
  int4 result = rule.applyOp(target,fd);
  std::cout << "case=" << caseName
            << "|res=" << result
            << "|target_precis_hi=" << (targetOut->isPrecisHi() ? 1 : 0)
            << "|sibling_precis_lo=" << (siblingOut->isPrecisLo() ? 1 : 0)
            << "|alive=" << countAlive(fd)
            << '\n';
}

static void run(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  {
    FixtureArchitecture architecture;
    RuleDoubleIn rule("analysis");
    vector<uint4> opcodes;
    rule.getOpList(opcodes);
    std::cout << "getoplist:count=" << opcodes.size() << ",opcode="
              << (opcodes.empty() ? -1 : static_cast<int4>(opcodes[0])) << '\n';
    runCase(architecture,"int_add_whole","int_add_whole");
    runCase(architecture,"int_mult_whole","int_mult_whole");
    runCase(architecture,"int_2comp_whole","int_2comp_whole");
    runCase(architecture,"int_or_whole","int_or_whole");
    runCase(architecture,"int_xor_whole","int_xor_whole");
    runCase(architecture,"int_and_whole","int_and_whole");
    runCase(architecture,"int_negate_whole","int_negate_whole");
    runCase(architecture,"int_left_whole","int_left_whole");
    runCase(architecture,"int_zext_whole","int_zext_whole");
    runCase(architecture,"offset_mismatch","int_add_whole");
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
