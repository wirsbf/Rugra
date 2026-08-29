/*
 * VARNODE-GETUSEPOINT-FREELEG-0001 (O-2)
 *
 * Locked Ghidra 12.0.4 oracle for Varnode::getUsePoint (varnode.cc:690-703).
 * Four cases isolate both legs of the sentinel decision:
 *
 *   written_def - a written Varnode reports its defining op's address.
 *   input_param - a function input Varnode reports fd.getAddress()+-1.
 *   free_vn     - a free (unwritten, non-input) Varnode reports the same
 *                 fd.getAddress()+-1 sentinel.
 *   zero_base   - a second Funcdata based at ram:0 where the sentinel
 *                 arithmetic underflows and wraps through the space
 *                 (operator+ -> AddrSpace::wrapOffset, address.hh:423).
 *
 * The projection prints the use-point space name and offset for each case.
 * No state is normalized.
 */

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

#include <iostream>
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

static void emitUsePoint(const string &caseName,const string &leg,
                         const Address &usePoint)
{
  std::cout << "case=" << caseName
            << "|leg=" << leg
            << "|space=" << usePoint.getSpace()->getName()
            << "|usepoint=0x" << std::hex << usePoint.getOffset()
            << std::dec << '\n';
}

static void run(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  {
    FixtureArchitecture architecture;
    Scope *scope = architecture.symboltab->getGlobalScope();
    AddrSpace *ram = architecture.getSpaceByName("ram");
    AddrSpace *reg = architecture.getSpaceByName("register");
    if (scope == (Scope *)0 || ram == (AddrSpace *)0 || reg == (AddrSpace *)0)
      throw std::runtime_error("synthetic architecture is incomplete");

    Funcdata fd("fx","fx",scope,Address(ram,0x1000),(FunctionSymbol *)0,0x20);
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);

    // written_def: the unique out of a COPY at ram:0x2000.
    PcodeOp *defop = fd.newOp(1,Address(ram,0x2000));
    fd.opSetOpcode(defop,CPUI_COPY);
    Varnode *written = fd.newUniqueOut(4,defop);
    fd.opSetInput(defop,fd.newConstant(4,7),0);
    fd.opInsertEnd(defop,block);
    emitUsePoint("written_def","written",written->getUsePoint(fd));

    // input_param: a function input varnode.
    Varnode *inputvn = fd.setInputVarnode(fd.newVarnode(4,reg,0x40));
    emitUsePoint("input_param","input",inputvn->getUsePoint(fd));

    // free_vn: constructed but never written nor marked input.
    Varnode *freevn = fd.newVarnode(4,reg,0x50);
    emitUsePoint("free_vn","free",freevn->getUsePoint(fd));

    // zero_base: underflow wrap through the ram space.
    Funcdata fd2("fz","fz",scope,Address(ram,0),(FunctionSymbol *)0,0x20);
    Varnode *freevn2 = fd2.newVarnode(4,reg,0x60);
    emitUsePoint("zero_base","free",freevn2->getUsePoint(fd2));
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
