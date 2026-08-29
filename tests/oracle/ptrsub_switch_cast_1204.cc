/* PTRSUB-SWITCH-CAST-RESIDUAL-0001: locked Ghidra 12.0.4
 *
 * Diagnostic fixture for the glob_set switch-expression cast churn:
 * baseline  switch(unique0x10000119 + (int *)*((int *)(int *)unique0x10000111 + ...))
 * formal    switch((int *)unique0x10000119 + (int *)*((int *)(int *)(int *)unique0x10000111 + ...))
 * golden    switch(cVar3)
 *
 * The fixture locks one IR/CFG/type state per case, then runs the REAL
 * ActionSetCasts::apply (coreaction.cc:2722) over it and dumps, per op:
 *   - input/output varnode types (varnode level and high level),
 *   - the TypeOp getOutputToken result ("token="; typeop.cc virtual),
 *   - the apply-side output-token dispatch ("atok="; on Ghidra this is the
 *     same virtual call castOutput makes at coreaction.cc:2541),
 *   - TypeOp getInputCast slot-0 results for PTRSUB/PTRADD
 *     (typeop.cc:2320 / typeop.cc:2250),
 * and after apply: block op order with inserted CAST ops, their types,
 * implied flags, and the ActionSetCasts count delta.  globform additionally
 * renders the BRANCHIND switch-expression tree textually (the fixture-side
 * analogue of PrintC::opBranchind pushVn recursion, printc.cc:582-591) so
 * the (T)-churn nesting is directly visible.
 *
 * Seeding note: pa_in_churn / pa_both_churn poke HighVariable::type
 * directly (variable.hh:141) and set type_finalized on the gB input,
 * reproducing the production post-propagation state where a varnode's own
 * (read-facing) type differs from its merged HighVariable type.  That state
 * is what drives TypeOpPtrsub/Ptradd::getInputCast slot-0 `(int *)` casts
 * and is unreachable with single-instance highs alone.
 */

#include <bits/stdc++.h>

#define private public
#define protected public
#include "action.hh"
#include "architecture.hh"
#include "coreaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "printc.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#include "variable.hh"
#undef protected
#undef private

using namespace ghidra;

class FixtureTranslate final : public Translate {
  VarnodeData dummyRegister;

public:
  FixtureTranslate()
  {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false,
                              8, 1, 1, AddrSpace::hasphysical, 0, 0));
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
    VarnodeData stackPointer;
    stackPointer.space = reg;
    stackPointer.offset = 0;
    stackPointer.size = 8;
    addSpacebasePointer(stack, stackPointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false,
                              8, 1, 6, AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummyRegister.space = reg;
    dummyRegister.offset = 0;
    dummyRegister.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummyRegister;
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
  FixtureArchitecture()
  {
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
    max_basetype_size = 10;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
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
    print->initializeFromArchitecture();
  }

  void printMessage(const std::string &) const override {}
};

class FixtureStruct final : public TypeStruct {
public:
  FixtureStruct(const std::string &nm, const std::vector<TypeField> &fields,
                int4 size, int4 alignment)
  {
    name = nm;
    displayName = nm;
    setFields(fields, size, alignment);
    markComplete();
  }
};

static std::string metaToken(type_metatype meta)
{
  switch (meta) {
  case TYPE_VOID: return "void";
  case TYPE_PTR: return "ptr";
  case TYPE_ARRAY: return "array";
  case TYPE_STRUCT: return "struct";
  case TYPE_SPACEBASE: return "spacebase";
  case TYPE_BOOL: return "bool";
  case TYPE_INT: return "int";
  case TYPE_UINT: return "uint";
  case TYPE_UNKNOWN: return "unknown";
  default: return "other";
  }
}

static std::string typeProj(const Datatype *ct)
{
  if (ct == (const Datatype *)0)
    return "null";
  if (ct->getMetatype() == TYPE_PTR) {
    const TypePointer *pointer = (const TypePointer *)ct;
    return "ptr" + std::to_string(pointer->getSize()) + "w" +
           std::to_string(pointer->getWordSize()) + "->" +
           typeProj(pointer->getPtrTo());
  }
  return metaToken(ct->getMetatype()) + std::to_string(ct->getSize());
}

static std::string opToken(OpCode opcode)
{
  switch (opcode) {
  case CPUI_PTRSUB: return "ptrsub";
  case CPUI_PTRADD: return "ptradd";
  case CPUI_LOAD: return "load";
  case CPUI_INT_ADD: return "int_add";
  case CPUI_INT_MULT: return "int_mult";
  case CPUI_INT_SEXT: return "int_sext";
  case CPUI_CAST: return "cast";
  case CPUI_BRANCHIND: return "branchind";
  default: return "other";
  }
}

struct FixtureTypes {
  Datatype *int4T;
  Datatype *int8T;
  Datatype *u8T;
  Datatype *P_int4;   // ptr8w1->int4   (the `(int *)` churn cast type)
  Datatype *P_int8;   // ptr8w1->int8
  Datatype *P_table;  // ptr8w1->TableStruct
};

// --------------------------------------------------------------------------
// Per-case state tracker: stable names for seeded ops/varnodes plus
// deterministic discovery names for ops/varnodes created by apply().
// --------------------------------------------------------------------------
class CaseTracker {
  std::map<PcodeOp *, std::string> opNames;
  std::map<Varnode *, std::string> vnNames;
  int4 nextFound;

public:
  CaseTracker() : nextFound(0) {}

  void op(PcodeOp *instance, const std::string &name)
  {
    opNames[instance] = name;
  }

  void vn(Varnode *instance, const std::string &name)
  {
    vnNames[instance] = name;
  }

  std::string opName(PcodeOp *instance)
  {
    std::map<PcodeOp *, std::string>::const_iterator iter = opNames.find(instance);
    if (iter != opNames.end())
      return (*iter).second;
    std::ostringstream out;
    out << 'n' << nextFound++;
    opNames[instance] = out.str();
    return out.str();
  }

  std::string vnName(Varnode *instance)
  {
    std::map<Varnode *, std::string>::const_iterator iter = vnNames.find(instance);
    if (iter != vnNames.end())
      return (*iter).second;
    std::ostringstream out;
    out << 'v' << nextFound++;
    vnNames[instance] = out.str();
    return out.str();
  }
};

static std::string inputCell(Varnode *vn, const PcodeOp *readOp)
{
  std::ostringstream out;
  out << "t=" << typeProj(vn->getType()) << ",h=";
  if (vn->getHigh() == (HighVariable *)0)
    out << "nohigh";
  else if (readOp == (const PcodeOp *)0)
    out << typeProj(vn->getHigh()->getType());
  else
    out << typeProj(vn->getHighTypeReadFacing(readOp));
  return out.str();
}

// "token" is the virtual TypeOp::getOutputToken; "atok" documents the same
// value because Ghidra's castOutput consumes exactly that virtual call
// (coreaction.cc:2541).  "ic0" is TypeOp::getInputCast(op,0,strategy) for
// the PTRSUB/PTRADD slot-0 pointer arm.
static std::string preOpDump(PcodeOp *op, CaseTracker &tracker,
                             CastStrategy *strategy)
{
  std::ostringstream out;
  out << tracker.opName(op) << ':' << opToken(op->code());
  for (int4 slot = 0; slot < op->numInput(); ++slot) {
    Varnode *vn = op->getIn(slot);
    out << ":i" << slot << "[";
    if (vn->isConstant())
      out << "c#" << std::dec << vn->getOffset();
    else
      out << inputCell(vn, op);
    out << ']';
  }
  out << ":out[";
  Varnode *outvn = op->getOut();
  if (outvn == (Varnode *)0) {
    out << "none";
  }
  else {
    out << "t=" << typeProj(outvn->getType()) << ",h=";
    if (outvn->getHigh() == (HighVariable *)0)
      out << "nohigh";
    else
      out << typeProj(outvn->getHighTypeReadFacing(op));
  }
  out << ']';
  if (outvn == (Varnode *)0 || op->code() == CPUI_BRANCHIND) {
    out << ":token=na:atok=na";
  }
  else {
    Datatype *token = op->getOpcode()->getOutputToken(op, strategy);
    out << ":token=" << typeProj(token) << ":atok=" << typeProj(token);
  }
  if (op->code() == CPUI_PTRSUB || op->code() == CPUI_PTRADD) {
    Datatype *ic = op->getOpcode()->getInputCast(op, 0, strategy);
    out << ":ic0=" << (ic == (Datatype *)0 ? "none" : typeProj(ic));
  }
  else
    out << ":ic0=na";
  return out.str();
}

static std::string postOpDump(PcodeOp *op, CaseTracker &tracker)
{
  std::ostringstream out;
  out << tracker.opName(op) << ':' << opToken(op->code());
  out << ":impl=" << (op->getOut() != (Varnode *)0 && op->getOut()->isImplied() ? 1 : 0);
  out << ":out=";
  if (op->getOut() == (Varnode *)0)
    out << "none";
  else
    out << typeProj(op->getOut()->getType());
  out << ":in=";
  for (int4 slot = 0; slot < op->numInput(); ++slot) {
    if (slot != 0)
      out << ',';
    Varnode *vn = op->getIn(slot);
    if (vn->isConstant())
      out << "c#" << std::dec << vn->getOffset();
    else
      out << tracker.vnName(vn);
  }
  return out.str();
}

class ProbeSetCasts final : public ActionSetCasts {
public:
  ProbeSetCasts() : ActionSetCasts("fixture")
  {
    count = 0;
    lcount = 0;
  }

  int4 takeCountDelta(void)
  {
    int4 result = count;
    count = 0;
    return result;
  }
};

// --------------------------------------------------------------------------
// Construction helpers
// --------------------------------------------------------------------------
static Varnode *typedInput(Funcdata &fd, AddrSpace *space, uintb offset,
                           int4 size, Datatype *ct)
{
  Varnode *vn = fd.setInputVarnode(fd.newVarnode(size, Address(space, offset)));
  vn->updateType(ct, true, false);
  return vn;
}

static PcodeOp *makeOp(Funcdata &fd, BlockBasic *block, OpCode opcode,
                       int4 inputs, uintb pc, int4 outSize)
{
  AddrSpace *ram = fd.getArch()->getSpace(3);
  PcodeOp *op = fd.newOp(inputs, Address(ram, pc));
  fd.opSetOpcode(op, opcode);
  if (outSize > 0)
    fd.newUniqueOut(outSize, op);
  fd.opInsertEnd(op, block);
  return op;
}

static void seedHigh(Varnode *vn, Datatype *ct)
{
  vn->getHigh()->type = ct;
  vn->getHigh()->highflags |= HighVariable::type_finalized;
}

// --------------------------------------------------------------------------
// Shared shape builder.  withPs=false replaces the PTRSUB producer with a
// direct gB input (varnode int4*, high seeded int8*) so the PTRADD slot-0
// input-cast churn is observed without the PTRSUB's own output cast
// rewiring the edge first.
// --------------------------------------------------------------------------
struct GlobFormOps {
  Varnode *gs;
  Varnode *gA;
  Varnode *gB;
  Varnode *idx;
  PcodeOp *ps;
  PcodeOp *sext;
  PcodeOp *mult;
  PcodeOp *pa;
  PcodeOp *load;
  PcodeOp *ia;
  PcodeOp *bi;
};

static GlobFormOps buildTree(Funcdata &fd, BlockBasic *block,
                             FixtureArchitecture &arch, FixtureTypes &T,
                             CaseTracker &tracker, uintb pcBase,
                             bool withPs, bool withLoad, bool withIa,
                             bool withBi, Datatype *psOutType,
                             Datatype *paOutType, uintb scale)
{
  AddrSpace *ram = arch.getSpace(3);
  AddrSpace *reg = arch.getSpace(4);
  GlobFormOps ops;
  ops.gs = (Varnode *)0;
  ops.gB = (Varnode *)0;
  ops.ps = (PcodeOp *)0;
  ops.load = (PcodeOp *)0;
  ops.ia = (PcodeOp *)0;
  ops.bi = (PcodeOp *)0;
  ops.gA = typedInput(fd, ram, 0x10000119, 8, T.P_int4);
  ops.idx = typedInput(fd, reg, 0x10, 4, T.int4T);
  tracker.vn(ops.gA, "gA");
  tracker.vn(ops.idx, "idx");

  Varnode *paIn0;
  if (withPs) {
    ops.gs = typedInput(fd, ram, 0x10000111, 8, T.P_table);
    tracker.vn(ops.gs, "gs");
    ops.ps = makeOp(fd, block, CPUI_PTRSUB, 2, pcBase + 0, 8);
    fd.opSetInput(ops.ps, ops.gs, 0);
    fd.opSetInput(ops.ps, fd.newConstant(8, 0), 1);
    if (psOutType != (Datatype *)0)
      ops.ps->getOut()->updateType(psOutType);
    tracker.op(ops.ps, "ps");
    tracker.vn(ops.ps->getOut(), "ps_o");
    paIn0 = ops.ps->getOut();
  }
  else {
    ops.gB = typedInput(fd, ram, 0x10000111, 8, T.P_int4);
    tracker.vn(ops.gB, "gB");
    paIn0 = ops.gB;
  }

  ops.sext = makeOp(fd, block, CPUI_INT_SEXT, 1, pcBase + 1, 8);
  fd.opSetInput(ops.sext, ops.idx, 0);
  ops.mult = makeOp(fd, block, CPUI_INT_MULT, 2, pcBase + 2, 8);
  fd.opSetInput(ops.mult, ops.sext->getOut(), 0);
  fd.opSetInput(ops.mult, fd.newConstant(8, 4), 1);
  ops.pa = makeOp(fd, block, CPUI_PTRADD, 3, pcBase + 3, 8);
  fd.opSetInput(ops.pa, paIn0, 0);
  fd.opSetInput(ops.pa, ops.mult->getOut(), 1);
  fd.opSetInput(ops.pa, fd.newConstant(4, scale), 2);
  if (paOutType != (Datatype *)0)
    ops.pa->getOut()->updateType(paOutType);
  tracker.op(ops.sext, "sext");
  tracker.op(ops.mult, "mult");
  tracker.op(ops.pa, "pa");
  tracker.vn(ops.sext->getOut(), "sext_o");
  tracker.vn(ops.mult->getOut(), "mult_o");
  tracker.vn(ops.pa->getOut(), "pa_o");

  Varnode *treeTop = ops.pa->getOut();
  if (withLoad) {
    ops.load = makeOp(fd, block, CPUI_LOAD, 2, pcBase + 4, 8);
    fd.opSetInput(ops.load, fd.newConstant(8, 1), 0);
    fd.opSetInput(ops.load, ops.pa->getOut(), 1);
    ops.load->getOut()->updateType(T.P_int4);
    tracker.op(ops.load, "load");
    tracker.vn(ops.load->getOut(), "load_o");
    treeTop = ops.load->getOut();
  }
  if (withIa) {
    ops.ia = makeOp(fd, block, CPUI_INT_ADD, 2, pcBase + 5, 8);
    fd.opSetInput(ops.ia, treeTop, 0);
    fd.opSetInput(ops.ia, ops.gA, 1);
    tracker.op(ops.ia, "ia");
    tracker.vn(ops.ia->getOut(), "ia_o");
    treeTop = ops.ia->getOut();
  }
  if (withBi) {
    ops.bi = makeOp(fd, block, CPUI_BRANCHIND, 1, pcBase + 6, 0);
    fd.opSetInput(ops.bi, treeTop, 0);
    tracker.op(ops.bi, "bi");
  }

  fd.setHighLevel();
  if (ops.gB != (Varnode *)0)
    seedHigh(ops.gB, T.P_int8);
  return ops;
}

static void runPre(Funcdata &fd, const std::string &name,
                   FixtureArchitecture &arch, CaseTracker &tracker)
{
  CastStrategy *strategy = arch.print->getCastStrategy();
  std::ostringstream ops;
  bool first = true;
  const BlockGraph &blocks(fd.getBasicBlocks());
  BlockBasic *bb = (BlockBasic *)blocks.getBlock(0);
  for (std::list<PcodeOp *>::const_iterator iter = bb->beginOp();
       iter != bb->endOp(); ++iter) {
    if (!first)
      ops << ';';
    first = false;
    ops << preOpDump(*iter, tracker, strategy);
  }
  std::cout << "case=" << name << "|stage=pre|ops=" << ops.str() << '\n';
}

static void runPost(Funcdata &fd, const std::string &name,
                    ProbeSetCasts &action, CaseTracker &tracker)
{
  int4 delta = action.takeCountDelta();
  std::ostringstream ops;
  bool first = true;
  const BlockGraph &blocks(fd.getBasicBlocks());
  BlockBasic *bb = (BlockBasic *)blocks.getBlock(0);
  for (std::list<PcodeOp *>::const_iterator iter = bb->beginOp();
       iter != bb->endOp(); ++iter) {
    if (!first)
      ops << ';';
    first = false;
    ops << postOpDump(*iter, tracker);
  }
  std::cout << "case=" << name << "|stage=post|count=" << delta
            << "|ops=" << ops.str() << '\n';
}

static Funcdata *makeFuncdata(FixtureArchitecture &arch, const char *name,
                              uintb pc)
{
  AddrSpace *ram = arch.getSpace(3);
  Funcdata *fd = new Funcdata(name, name,
                              arch.symboltab->getGlobalScope(), Address(ram, pc),
                              (FunctionSymbol *)0, 0x40);
  return fd;
}

static BlockBasic *makeSingleBlock(Funcdata *fd)
{
  BlockGraph &blocks = const_cast<BlockGraph &>(fd->getBasicBlocks());
  BlockBasic *block = blocks.newBlockBasic(fd);
  AddrSpace *ram = fd->getArch()->getSpace(3);
  fd->setBasicBlockRange(block, Address(ram, 0), Address(ram, 0x100));
  return block;
}

// Fixture-side switch-expression renderer: the analogue of
// PrintC::opBranchind's pushVn(op->getIn(0)) recursion (printc.cc:582-591).
// CAST renders as "(<type>)expr", PTRADD/INT_ADD as "(a + b)", INT_MULT as
// "(a * b)", LOAD as "*(p)", PTRSUB as "PTRSUB(base,#off)", SEXT as "SEXT(a)".
static std::string renderOp(PcodeOp *op, CaseTracker &tracker, int depth);

static std::string renderExpr(Varnode *vn, CaseTracker &tracker, int depth)
{
  if (depth > 32)
    return "DEPTH";
  if (vn->isConstant())
    return "#" + std::to_string(vn->getOffset());
  // The renderer inlines every written varnode (implied or not): the
  // fixture-side analogue of PrintLanguage inlining a non-exp expression.
  if (vn->isWritten())
    return renderOp(vn->getDef(), tracker, depth + 1);
  return tracker.vnName(vn);
}

static std::string renderOp(PcodeOp *op, CaseTracker &tracker, int depth)
{
  switch (op->code()) {
  case CPUI_CAST:
    return "(" + typeProj(op->getOut()->getType()) + ")" +
           renderExpr(op->getIn(0), tracker, depth);
  case CPUI_PTRADD:
  case CPUI_INT_ADD:
    return "(" + renderExpr(op->getIn(0), tracker, depth) + " + " +
           renderExpr(op->getIn(1), tracker, depth) + ")";
  case CPUI_INT_MULT:
    return "(" + renderExpr(op->getIn(0), tracker, depth) + " * " +
           renderExpr(op->getIn(1), tracker, depth) + ")";
  case CPUI_INT_SEXT:
    return "SEXT(" + renderExpr(op->getIn(0), tracker, depth) + ")";
  case CPUI_LOAD:
    return "*(" + renderExpr(op->getIn(1), tracker, depth) + ")";
  case CPUI_PTRSUB:
    return "PTRSUB(" + renderExpr(op->getIn(0), tracker, depth) + ",#" +
           std::to_string(op->getIn(1)->getOffset()) + ")";
  case CPUI_BRANCHIND:
    return "switch(" + renderExpr(op->getIn(0), tracker, depth) + ")";
  default:
    return opToken(op->code()) + "@" + tracker.opName(op);
  }
}

static void runSwexpr(const std::string &name, const std::string &stage,
                      PcodeOp *bi, CaseTracker &tracker)
{
  std::cout << "case=" << name << "|stage=" << stage
            << "|text=" << renderOp(bi, tracker, 0) << '\n';
}

// --------------------------------------------------------------------------
// Cases
// --------------------------------------------------------------------------

// aligned: every ptr output matches its token -> zero casts expected.
static void caseAligned(FixtureArchitecture &arch, FixtureTypes &T)
{
  Funcdata *fd = makeFuncdata(arch, "sw_aligned", 0x5000);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  buildTree(*fd, block, arch, T, tracker, 0x5000, true, false, false, true,
            T.P_int4, T.P_int4, 4);
  runPre(*fd, "aligned", arch, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "aligned", action, tracker);
  delete fd;
}

// pa_out_int8: PTRADD in0 high int4*, output high int8 -> castOutput token
// (=in0 high, typeop.cc:2244) differs from out high -> CAST after the
// PTRADD.  This is the apply-side arm Rugra's coreaction dispatch skips.
static void casePaOutInt8(FixtureArchitecture &arch, FixtureTypes &T)
{
  Funcdata *fd = makeFuncdata(arch, "sw_pa_out", 0x5100);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  buildTree(*fd, block, arch, T, tracker, 0x5100, true, false, false, true,
            T.P_int4, T.int8T, 4);
  runPre(*fd, "pa_out_int8", arch, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "pa_out_int8", action, tracker);
  delete fd;
}

// pa_in_churn: PTRADD in0 is a direct global-table input whose varnode type
// is int4* but merged high is int8* (the post-propagation production
// state).  getInputCast slot-0 (typeop.cc:2250) returns int4* ->
// CAST(int4*) before the PTRADD (the `(int *)base` churn).
static void casePaInChurn(FixtureArchitecture &arch, FixtureTypes &T)
{
  Funcdata *fd = makeFuncdata(arch, "sw_pa_in", 0x5200);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  buildTree(*fd, block, arch, T, tracker, 0x5200, false, false, false, true,
            (Datatype *)0, T.P_int4, 8);
  runPre(*fd, "pa_in_churn", arch, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "pa_in_churn", action, tracker);
  delete fd;
}

// pa_both_churn: input churn + mismatching output -> both the slot-0 input
// CAST and the output CAST (nested `(T)(T)` churn, the formal-output shape).
static void casePaBothChurn(FixtureArchitecture &arch, FixtureTypes &T)
{
  Funcdata *fd = makeFuncdata(arch, "sw_pa_both", 0x5300);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  buildTree(*fd, block, arch, T, tracker, 0x5300, false, false, false, true,
            (Datatype *)0, T.int8T, 8);
  runPre(*fd, "pa_both_churn", arch, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "pa_both_churn", action, tracker);
  delete fd;
}

// ia_token: INT_ADD(int8, const) whose output was type-propagated to int4*.
// Ghidra token = arithmeticOutputStandard(op) (typeop.cc:1175, cast.cc:394)
// = int8 -> castOutput CAST(int4*) after the add.  The apply-side token for
// INT_ADD is the core divergence surface.
static void caseIaToken(FixtureArchitecture &arch, FixtureTypes &T)
{
  Funcdata *fd = makeFuncdata(arch, "sw_ia", 0x5400);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  AddrSpace *ram = arch.getSpace(3);
  Varnode *gA = typedInput(*fd, ram, 0x10000119, 8, T.int8T);
  tracker.vn(gA, "gA8");
  PcodeOp *ia = makeOp(*fd, block, CPUI_INT_ADD, 2, 0x5400, 8);
  fd->opSetInput(ia, gA, 0);
  fd->opSetInput(ia, fd->newConstant(8, 0), 1);
  ia->getOut()->updateType(T.P_int4);
  tracker.op(ia, "ia");
  tracker.vn(ia->getOut(), "ia_o");
  fd->setHighLevel();
  runPre(*fd, "ia_token", arch, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "ia_token", action, tracker);
  delete fd;
}

// cast_chain: an existing implied CAST(int4*) feeding INT_MULT whose
// reqtype is int8.  Ghidra castInput's double-cast guard (coreaction.cc:2675)
// retypes the CAST output in place instead of stacking a second CAST.
static void caseCastChain(FixtureArchitecture &arch, FixtureTypes &T)
{
  Funcdata *fd = makeFuncdata(arch, "sw_chain", 0x5500);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  AddrSpace *reg = arch.getSpace(4);
  Varnode *src = typedInput(*fd, reg, 0x20, 8, T.int8T);
  tracker.vn(src, "src");
  PcodeOp *castOp = makeOp(*fd, block, CPUI_CAST, 1, 0x5500, 8);
  fd->opSetInput(castOp, src, 0);
  castOp->getOut()->updateType(T.P_int4);
  castOp->getOut()->setImplied();
  PcodeOp *mult = makeOp(*fd, block, CPUI_INT_MULT, 2, 0x5501, 8);
  fd->opSetInput(mult, castOp->getOut(), 0);
  fd->opSetInput(mult, fd->newConstant(8, 4), 1);
  tracker.op(castOp, "cast0");
  tracker.op(mult, "mult");
  tracker.vn(castOp->getOut(), "cast0_o");
  tracker.vn(mult->getOut(), "mult_o");
  fd->setHighLevel();
  runPre(*fd, "cast_chain", arch, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "cast_chain", action, tracker);
  delete fd;
}

// globform: the full glob_set shape - global table pointer, PTRSUB field,
// SEXT/MULT scaled index, PTRADD, LOAD of the table entry, INT_ADD with the
// secondary base, BRANCHIND switch.  ps output is int8* (token int4*),
// pa output is int8*, load output is int4*.
static void caseGlobForm(FixtureArchitecture &arch, FixtureTypes &T)
{
  Funcdata *fd = makeFuncdata(arch, "sw_globform", 0x5600);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  GlobFormOps ops = buildTree(*fd, block, arch, T, tracker, 0x5600,
                              true, true, true, true,
                              T.P_int8, T.P_int8, 4);
  runPre(*fd, "globform", arch, tracker);
  runSwexpr("globform", "swexpr_pre", ops.bi, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "globform", action, tracker);
  runSwexpr("globform", "swexpr_post", ops.bi, tracker);
  delete fd;
}

// typedef_typelock: implied + typelock output typed as a typedef of the
// token base.  castOutput's cc:2562-2567 force path must run isOpIdentical,
// which strips the typedef chain (cc:2476-2479) and reports the alias
// op-identical to the base: force stays false, the !force gate's
// castStandard also strips typedefs (cast.cc:325-329) and returns null, so
// no CAST is inserted and the count is 0.  A divergent implementation that
// skips the typedef strip forces a spurious CAST here.
static void caseTypedefTypelock(FixtureArchitecture &arch, FixtureTypes &T,
                                Datatype *tdInt8)
{
  Funcdata *fd = makeFuncdata(arch, "sw_td_lock", 0x5700);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  AddrSpace *ram = arch.getSpace(3);
  Varnode *gA = typedInput(*fd, ram, 0x10000119, 8, T.int8T);
  tracker.vn(gA, "gA8");
  PcodeOp *ia = makeOp(*fd, block, CPUI_INT_ADD, 2, 0x5700, 8);
  fd->opSetInput(ia, gA, 0);
  fd->opSetInput(ia, fd->newConstant(8, 0), 1);
  ia->getOut()->updateType(tdInt8, true, false); // typelock + implied
  ia->getOut()->setImplied();
  tracker.op(ia, "ia");
  tracker.vn(ia->getOut(), "ia_o");
  fd->setHighLevel();
  runPre(*fd, "typedef_typelock", arch, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "typedef_typelock", action, tracker);
  delete fd;
}

// cast_arm_fork: castInput's double-cast guard is TWO nested levels
// (cc:2673 outer isWritten&&def==CAST, cc:2674 inner isImplied).  A
// CAST-produced varnode that is NOT implied — here a pathological
// constant-space output hand-wired via PcodeOp::setOutput +
// Varnode::setDef (the bank would reject opSetOutput on a constant) —
// must skip the ENTIRE else-if chain (constant arm included) and fall
// through to the CAST insert with vnin = vn.  A merged single-level
// condition diverts this input into the constant arm (cc:2687) instead.
static void caseCastArmFork(FixtureArchitecture &arch, FixtureTypes &T)
{
  Funcdata *fd = makeFuncdata(arch, "sw_arm_fork", 0x5800);
  BlockBasic *block = makeSingleBlock(fd);
  CaseTracker tracker;
  AddrSpace *reg = arch.getSpace(4);
  Varnode *src = typedInput(*fd, reg, 0x40, 8, T.int8T);
  tracker.vn(src, "src");
  PcodeOp *castOp = makeOp(*fd, block, CPUI_CAST, 1, 0x5800, 0);
  fd->opSetInput(castOp, src, 0);
  Varnode *constC = fd->newConstant(8, 0x30);
  constC->updateType(T.P_int4);
  // Hand-built wiring: bank-level opSetOutput would reject a constant
  // output; the oracle arm order is only reachable through the direct
  // setters (setDef sets the written flag).
  constC->setDef(castOp);
  castOp->setOutput(constC);
  PcodeOp *mult = makeOp(*fd, block, CPUI_INT_MULT, 2, 0x5801, 8);
  fd->opSetInput(mult, constC, 0);
  fd->opSetInput(mult, fd->newConstant(8, 4), 1);
  tracker.op(castOp, "cast0");
  tracker.op(mult, "mult");
  tracker.vn(constC, "constC");
  tracker.vn(mult->getOut(), "mult_o");
  fd->setHighLevel();
  runPre(*fd, "cast_arm_fork", arch, tracker);
  ProbeSetCasts action;
  action.apply(*fd);
  runPost(*fd, "cast_arm_fork", action, tracker);
  delete fd;
}

int main(void)
{
  std::cout << std::unitbuf;
  std::cout << "schema=1|fixture=PTRSUB-SWITCH-CAST-0001"
            << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    std::vector<std::string> specPaths;
    startDecompilerLibrary(specPaths);
    FixtureArchitecture architecture;
    FixtureTypes T;
    T.int4T = architecture.types->getBase(4, TYPE_INT);
    T.int8T = architecture.types->getBase(8, TYPE_INT);
    T.u8T = architecture.types->getBase(8, TYPE_UNKNOWN);
    std::vector<TypeField> tableFields;
    tableFields.push_back(TypeField(0, 0, "sel", T.int4T));
    tableFields.push_back(TypeField(1, 4, "pad", T.int4T));
    Datatype *table = new FixtureStruct("TableStruct", tableFields, 8, 4);
    T.P_int4 = architecture.types->getTypePointer(8, T.int4T, 1);
    T.P_int8 = architecture.types->getTypePointer(8, T.int8T, 1);
    T.P_table = architecture.types->getTypePointer(8, table, 1);
    Datatype *tdInt8 = architecture.types->getTypedef(
        T.int8T, "td_int8", Datatype::hashName("td_int8"), 0);

    caseAligned(architecture, T);
    casePaOutInt8(architecture, T);
    casePaInChurn(architecture, T);
    casePaBothChurn(architecture, T);
    caseIaToken(architecture, T);
    caseCastChain(architecture, T);
    caseGlobForm(architecture, T);
    caseTypedefTypelock(architecture, T, tdInt8);
    caseCastArmFork(architecture, T);
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
    return 1;
  }
  catch (const LowlevelError &error) {
    std::cerr << "fixture LowlevelError: " << error.explain << '\n';
    return 1;
  }
  catch (const DecoderError &error) {
    std::cerr << "fixture DecoderError: " << error.explain << '\n';
    return 1;
  }
  return 0;
}
