// FUNCDATA-CALCNZM-0001: locked Ghidra 12.0.4 oracle fixture for
// Funcdata::calcNZMask (funcdata_varnode.cc:856-926) and its per-op arm
// PcodeOp::getNZMaskLocal (op.cc:547-771).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Observable behaviors pinned by this fixture (one stdout line per case):
//   init       phase-1 unwritten-input initialization (cc:887-896): a
//              constant takes its offset, an unwritten register input takes
//              calc_mask(size), and a SPACEBASE input additionally clears
//              the low byte (~0xff); COPY outputs propagate each mask
//              (op.cc:577-580).
//   andcopy    INT_AND mask convergence (op.cc:590-594) followed by a
//              two-deep COPY chain (phase-1 post-order guarantees the AND
//              output is assigned before the copies pop).
//   piece      PIECE concatenation (op.cc:693-698): hi mask shifted up by
//              the low input size OR'd with the low mask.
//   div        the sc6 shape y = y/64 (INT_DIV, op.cc:648-659):
//              coveringmask(in0) >> mostsigbit_set(const denominator),
//              plus a division by a non-power-of-two constant, a division
//              by a non-constant denominator (no shift term) and INT_REM
//              (op.cc:660-663, coveringmask(denom_nzm - 1)).
//   loopor     MULTIEQUAL loop clipping + phase-2 worklist: a phi with a
//              looping in-edge (BlockGraph::addLoopEdge) feeds an INT_LEFT
//              of its own output. Phase 1 (cliploop=true) skips the looping
//              edge; phase 2 re-propagates without clipping to the OR fixed
//              point. Also prints the block's isLoopIn flags.
//   loopand    the precision observable of clipping: with an INT_AND on the
//              loop-carried edge the clipped phase-1 start reaches a
//              TIGHTER fixed point (0xff00) than the identical graph
//              without the loop-edge label (0xfff0); the AND result differs
//              as well (0xf000 vs 0xf0f0).
//
// All varnodes print their post-calcNZMask nzm through getNZMask()
// (varnode.hh:231, the raw field). Ops are built through newOp/newUniqueOut/
// opSetInput/opInsertEnd/Begin so both sides agree op-for-op.
#include <bits/stdc++.h>

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

using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1, 6,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummy_register.space = reg;
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
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
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const std::string &) const override {}
};

string hx(uintb value)
{
  ostringstream out;
  out << "0x" << std::hex << value;
  return out.str();
}

Funcdata *newFunction(FixtureArchitecture &architecture, AddrSpace *ram)
{
  return new Funcdata("calcnzm", "calcnzm",
                      architecture.symboltab->getGlobalScope(),
                      Address(ram, 0x5000), (FunctionSymbol *)0, 0x100);
}

PcodeOp *newOutputOp(Funcdata *fd, AddrSpace *ram, BlockBasic *block, OpCode opcode,
                     uintb pc, int4 inputs, int4 outputSize,
                     bool atBegin = false)
{
  PcodeOp *op = fd->newOp(inputs, Address(ram, pc));
  fd->opSetOpcode(op, opcode);
  fd->newUniqueOut(outputSize, op);
  if (atBegin)
    fd->opInsertBegin(op, block);
  else
    fd->opInsertEnd(op, block);
  return op;
}

void runInit(FixtureArchitecture &architecture, AddrSpace *ram, AddrSpace *reg)
{
  Funcdata *fd = newFunction(architecture, ram);
  BlockBasic *block = const_cast<BlockGraph &>(fd->getBasicBlocks()).newBlockBasic(fd);
  // Constant input: nzm initialized to the offset (cc:889-890).
  PcodeOp *cpC = newOutputOp(fd, ram, block, CPUI_COPY, 0x5010, 1, 4);
  fd->opSetInput(cpC, fd->newConstant(4, 0x3f0), 0);
  // Unwritten register input: nzm = calc_mask(4) (cc:892).
  PcodeOp *cpR = newOutputOp(fd, ram, block, CPUI_COPY, 0x5011, 1, 4);
  Varnode *edi = fd->newVarnode(4, reg, 0x38);
  edi = fd->setInputVarnode(edi);
  fd->opSetInput(cpR, edi, 0);
  // Spacebase input: nzm = calc_mask(8) & ~0xff (cc:892-894), marked by
  // Funcdata::spacebase (funcdata.cc:230-269) on the stack pointer register.
  PcodeOp *cpS = newOutputOp(fd, ram, block, CPUI_COPY, 0x5012, 1, 8);
  Varnode *sp = fd->newVarnode(8, reg, 0);
  sp = fd->setInputVarnode(sp);
  fd->opSetInput(cpS, sp, 0);
  fd->spacebase();
  fd->calcNZMask();
  std::cout << "init|const=" << hx(cpC->getIn(0)->getNZMask())
            << "|reg=" << hx(cpR->getIn(0)->getNZMask())
            << "|sb=" << hx(cpS->getIn(0)->getNZMask())
            << "|sbflag=" << (cpS->getIn(0)->isSpacebase() ? 1 : 0)
            << "|outs=" << hx(cpC->getOut()->getNZMask())
            << ',' << hx(cpR->getOut()->getNZMask())
            << ',' << hx(cpS->getOut()->getNZMask()) << '\n';
  delete fd;
}

void runAndCopy(FixtureArchitecture &architecture, AddrSpace *ram, AddrSpace *reg)
{
  Funcdata *fd = newFunction(architecture, ram);
  BlockBasic *block = const_cast<BlockGraph &>(fd->getBasicBlocks()).newBlockBasic(fd);
  PcodeOp *andop = newOutputOp(fd, ram, block, CPUI_INT_AND, 0x5020, 2, 4);
  Varnode *edi = fd->newVarnode(4, reg, 0x38);
  edi = fd->setInputVarnode(edi);
  fd->opSetInput(andop, edi, 0);
  fd->opSetInput(andop, fd->newConstant(4, 0x3f0), 1);
  PcodeOp *copy1 = newOutputOp(fd, ram, block, CPUI_COPY, 0x5021, 1, 4);
  fd->opSetInput(copy1, andop->getOut(), 0);
  PcodeOp *copy2 = newOutputOp(fd, ram, block, CPUI_COPY, 0x5022, 1, 4);
  fd->opSetInput(copy2, copy1->getOut(), 0);
  fd->calcNZMask();
  std::cout << "andcopy|and=" << hx(andop->getOut()->getNZMask())
            << "|c1=" << hx(copy1->getOut()->getNZMask())
            << "|c2=" << hx(copy2->getOut()->getNZMask()) << '\n';
  delete fd;
}

void runPiece(FixtureArchitecture &architecture, AddrSpace *ram)
{
  Funcdata *fd = newFunction(architecture, ram);
  BlockBasic *block = const_cast<BlockGraph &>(fd->getBasicBlocks()).newBlockBasic(fd);
  PcodeOp *piece = newOutputOp(fd, ram, block, CPUI_PIECE, 0x5030, 2, 4);
  fd->opSetInput(piece, fd->newConstant(2, 0x1122), 0);
  fd->opSetInput(piece, fd->newConstant(2, 0x3344), 1);
  fd->calcNZMask();
  std::cout << "piece|out=" << hx(piece->getOut()->getNZMask()) << '\n';
  delete fd;
}

void runDiv(FixtureArchitecture &architecture, AddrSpace *ram, AddrSpace *reg)
{
  Funcdata *fd = newFunction(architecture, ram);
  BlockBasic *block = const_cast<BlockGraph &>(fd->getBasicBlocks()).newBlockBasic(fd);
  Varnode *edi = fd->newVarnode(4, reg, 0x38);
  edi = fd->setInputVarnode(edi);
  Varnode *esi = fd->newVarnode(4, reg, 0x40);
  esi = fd->setInputVarnode(esi);
  // y1 = EDI & 0xffff: the tightened dividend mask.
  PcodeOp *andop = newOutputOp(fd, ram, block, CPUI_INT_AND, 0x5040, 2, 4);
  fd->opSetInput(andop, edi, 0);
  fd->opSetInput(andop, fd->newConstant(4, 0xffff), 1);
  // d64 = y1 / 64 (sc6 shape): coveringmask(0xffff) >> 6.
  PcodeOp *d64 = newOutputOp(fd, ram, block, CPUI_INT_DIV, 0x5041, 2, 4);
  fd->opSetInput(d64, andop->getOut(), 0);
  fd->opSetInput(d64, fd->newConstant(4, 64), 1);
  // dfull = EDI / 64: coveringmask(0xffffffff) >> 6.
  PcodeOp *dfull = newOutputOp(fd, ram, block, CPUI_INT_DIV, 0x5042, 2, 4);
  fd->opSetInput(dfull, edi, 0);
  fd->opSetInput(dfull, fd->newConstant(4, 64), 1);
  // dodd = EDI / 3: coveringmask >> mostsigbit_set(3) = 1.
  PcodeOp *dodd = newOutputOp(fd, ram, block, CPUI_INT_DIV, 0x5043, 2, 4);
  fd->opSetInput(dodd, edi, 0);
  fd->opSetInput(dodd, fd->newConstant(4, 3), 1);
  // dvar = EDI / ESI: non-constant denominator keeps coveringmask(in0).
  PcodeOp *dvar = newOutputOp(fd, ram, block, CPUI_INT_DIV, 0x5044, 2, 4);
  fd->opSetInput(dvar, edi, 0);
  fd->opSetInput(dvar, esi, 1);
  // rem = EDI % 0x100: coveringmask(0x100 - 1).
  PcodeOp *rem = newOutputOp(fd, ram, block, CPUI_INT_REM, 0x5045, 2, 4);
  fd->opSetInput(rem, edi, 0);
  fd->opSetInput(rem, fd->newConstant(4, 0x100), 1);
  fd->calcNZMask();
  std::cout << "div|y1=" << hx(andop->getOut()->getNZMask())
            << "|d64=" << hx(d64->getOut()->getNZMask())
            << "|dfull=" << hx(dfull->getOut()->getNZMask())
            << "|dodd=" << hx(dodd->getOut()->getNZMask())
            << "|dvar=" << hx(dvar->getOut()->getNZMask())
            << "|rem=" << hx(rem->getOut()->getNZMask()) << '\n';
  delete fd;
}

void runLoopOr(FixtureArchitecture &architecture, AddrSpace *ram)
{
  Funcdata *fd = newFunction(architecture, ram);
  BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
  BlockBasic *b1 = graph.newBlockBasic(fd);
  BlockBasic *b2 = graph.newBlockBasic(fd);
  graph.addEdge(b1, b2);
  graph.addEdge(b2, b2);
  graph.addLoopEdge(b2, 0);
  // Creation order (== alive order): shift, then phi.
  PcodeOp *shift = newOutputOp(fd, ram, b2, CPUI_INT_LEFT, 0x5050, 2, 4);
  PcodeOp *phi = newOutputOp(fd, ram, b2, CPUI_MULTIEQUAL, 0x5051, 2, 4, true);
  fd->opSetInput(phi, fd->newConstant(4, 0xffff), 0);
  fd->opSetInput(phi, shift->getOut(), 1);
  fd->opSetInput(shift, phi->getOut(), 0);
  fd->opSetInput(shift, fd->newConstant(4, 8), 1);
  fd->calcNZMask();
  std::cout << "loopor|loopin=" << (b2->isLoopIn(0) ? 1 : 0) << ',' << (b2->isLoopIn(1) ? 1 : 0)
            << "|phi=" << hx(phi->getOut()->getNZMask())
            << "|shift=" << hx(shift->getOut()->getNZMask()) << '\n';
  delete fd;
}

// Identical graph to runLoopAnd's clipped twin, with or without the
// loop-edge label; the INT_AND on the loop-carried edge makes the clipped
// phase-1 start converge to a strictly tighter fixed point.
static void buildLoopAndGraph(Funcdata *fd, AddrSpace *ram, bool withLoopEdge,
                              PcodeOp **andOut, PcodeOp **phiOut)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
  BlockBasic *b1 = graph.newBlockBasic(fd);
  BlockBasic *b2 = graph.newBlockBasic(fd);
  graph.addEdge(b1, b2);
  graph.addEdge(b2, b2);
  if (withLoopEdge)
    graph.addLoopEdge(b2, 0);
  // Creation order: and, then phi.
  PcodeOp *andop = newOutputOp(fd, ram, b2, CPUI_INT_AND, 0x5060, 2, 4);
  PcodeOp *phi = newOutputOp(fd, ram, b2, CPUI_MULTIEQUAL, 0x5061, 2, 4, true);
  fd->opSetInput(phi, fd->newConstant(4, 0xff00), 0);
  fd->opSetInput(phi, andop->getOut(), 1);
  fd->opSetInput(andop, phi->getOut(), 0);
  fd->opSetInput(andop, fd->newConstant(4, 0xf0f0), 1);
  *andOut = andop;
  *phiOut = phi;
}

void runLoopAnd(FixtureArchitecture &architecture, AddrSpace *ram)
{
  PcodeOp *andA = (PcodeOp *)0;
  PcodeOp *phiA = (PcodeOp *)0;
  {
    Funcdata *fd = newFunction(architecture, ram);
    buildLoopAndGraph(fd, ram, true, &andA, &phiA);
    fd->calcNZMask();
    std::cout << "loopand|clipped=" << hx(phiA->getOut()->getNZMask())
              << ',' << hx(andA->getOut()->getNZMask());
    delete fd;
  }
  PcodeOp *andB = (PcodeOp *)0;
  PcodeOp *phiB = (PcodeOp *)0;
  {
    Funcdata *fd = newFunction(architecture, ram);
    buildLoopAndGraph(fd, ram, false, &andB, &phiB);
    fd->calcNZMask();
    std::cout << "|plain=" << hx(phiB->getOut()->getNZMask())
              << ',' << hx(andB->getOut()->getNZMask()) << '\n';
    delete fd;
  }
}

void run(const string &name)
{
  (void)name;
  vector<string> spec_paths;
  startDecompilerLibrary(spec_paths);
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpaceByName("ram");
    AddrSpace *reg = architecture.getSpaceByName("register");
    if (ram == (AddrSpace *)0 || reg == (AddrSpace *)0)
      throw std::runtime_error("fixture spaces not found");
    runInit(architecture, ram, reg);
    runAndCopy(architecture, ram, reg);
    runPiece(architecture, ram);
    runDiv(architecture, ram, reg);
    runLoopOr(architecture, ram);
    runLoopAnd(architecture, ram);
  }
  catch (const LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
    shutdownDecompilerLibrary();
    std::exit(1);
  }
  shutdownDecompilerLibrary();
}

}  // namespace

int main()
{
  std::cout << std::unitbuf;
  run("funcdata_calcnzm_1204");
  return 0;
}
