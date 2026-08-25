/* RETURNFOLD-GAPB-CONDCONST-0001 fixture — the CPUI_RETURN special case of
 * ActionConditionalConst::propagateConstant (coreaction.cc:4439-4448) against
 * the locked Ghidra 12.0.4 oracle, driven through the production
 * ActionConditionalConst::apply + findConstCompare path; `count` is read
 * through a CountProbe subclass (action.hh:60).
 *
 * Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
 *
 * Input graph (blocks named by creation ordinal; edges added in slot order):
 *   b0: t = INT_EQUAL X, 5 ; CBRANCH t   out0=b4 (false) out1=b1 (true)
 *   b1: CBRANCH q          out0=b2 out1=b3     (constBlock; q unwritten)
 *   b2: INT_ADD y = X+1 ; RETURN X            (dominated by b1)
 *   b3: RETURN X                                (dominated by b1)
 *   b4: RETURN X                                (NOT dominated: negative ctl)
 * X = register:0x0:4 input varnode read by 5 ops (descend order
 * INT_EQUAL,INT_ADD,RETURN,RETURN,RETURN), so findConstCompare's
 * loneDescend gate admits the X==5 point down b0's true edge.
 *
 * Observable projections pinned by this fixture (one stdout line per record):
 *   pre    graph inventory after structureReset (creation names pin the RPO
 *          reorder), X's location + descend order, per-block op orders, the
 *          return_copy flags on the three RETURNs (set by TypeOpReturn
 *          typeop.cc:879 via opSetOpcode).
 *   ret    per-RETURN post state: dominated RETURNs (b2/b3) read the output
 *          of a freshly inserted copyBeforeRet COPY at slot 1 — never a
 *          constant — whose output varnode sits at X's exact
 *          (space,offset,size) (cc:4445), whose pc equals the RETURN's pc
 *          (cc:4442), which carries NO return_copy flag (unlike the heritage
 *          guardReturns COPY), and whose input 0 is a fresh constant
 *          (opSetInput const dedup cc:108-115). The non-dominated RETURN
 *          (b4) keeps reading X directly. RETURN value slots (slot>=1)
 *          across the whole function never hold a constant.
 *   add    the non-RETURN dominated read (INT_ADD in b2) takes the constant
 *          directly in its slot (cc:4449-4452) with no COPY inserted.
 *   pass1  count=3 via CountProbe (1 INT_ADD + 2 RETURN arms), X's residual
 *          descend list (INT_EQUAL + the untouched b4 RETURN only), the two
 *          COPY input constants are distinct varnodes (opSetInput dedup).
 *   pass2  reset + re-apply: count=0 and the IR projection is unchanged
 *          (findConstCompare's loneDescend gate now rejects X).
 *   ruleprop a full RulePropagateCopy sweep (all opcodes, ruleaction.hh:730)
 *          after the propagation: hits=0 — the RETURN targets are skipped by
 *          the cc:3933 isReturnCopy() guard, so the copyBeforeRet COPY is
 *          never folded into the RETURN and the `RETURN const` form is
 *          never created.
 *   case_* fixed UNTESTED note lines (apply return-value asymmetry,
 *          MULTIEQUAL phi arm, implied-boolean arm, print-stage fold).
 * Test-only access rewrite (#define private public / #define class struct,
 * after the standard headers so it cannot leak into libstdc++) follows the
 * reviewed tests/oracle/condexe_success_state_1204.cc pattern: it exposes
 * the private Funcdata::structureReset (funcdata.hh:121) so the fixture can
 * establish the production reverse-post-order indices and immediate
 * dominators before apply. apply() itself is public and unmodified; the
 * count accumulator is read through the CountProbe subclass.
 */
#include <bits/stdc++.h>
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "coreaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "ruleaction.hh"
#include "translate.hh"
#include "typeop.hh"

using namespace std;
using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
public:
  VarnodeData dummyRegister;
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

// Reads the protected Action::count accumulator (action.hh:60) through a
// subclass probe — apply() itself is public and unmodified. The direct
// apply() invocations below bypass Action::perform, which is where Ghidra
// zeroes count (action.cc:306 status_start); zeroCount restores the per-apply
// counting boundary so both sides report changes per apply (Rugra's apply
// zeroes its count internally — accumulator reset-point asymmetry recorded
// as CONDCONST-APPLY-RETURN-0001).
class CountProbe : public ActionConditionalConst {
public:
  CountProbe(void) : ActionConditionalConst("") {}
  int4 getCount(void) const { return count; }
  void zeroCount(void) { count = 0; }
};

class Fixture {
  Funcdata &fd;
  AddrSpace *code;
  AddrSpace *unique;
  vector<FlowBlock *> blocks;
  uintb nextPc;

public:
  explicit Fixture(Funcdata &f)
    : fd(f), code(f.getArch()->getDefaultCodeSpace()),
      unique(f.getArch()->getSpaceByName("unique")), nextPc(0x60000) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);
    blocks.push_back(block);
    return block;
  }

  void edge(BlockBasic *from,BlockBasic *to)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    graph.addEdge(from,to);
  }

  Address allocPc(void)
  {
    Address a(code,nextPc);
    nextPc += 8;
    return a;
  }

  AddrSpace *uniqueSpace(void) const { return unique; }

  Varnode *makeOut(int4 size,AddrSpace *space,uintb offset,PcodeOp *op)
  {
    return fd.newVarnodeOut(size,Address(space,offset),op);
  }

  PcodeOp *makeCbranchAt(BlockBasic *blk,Varnode *boolvn,Address pc)
  {
    PcodeOp *op = fd.newOp(2,pc);
    fd.opSetOpcode(op,CPUI_CBRANCH);
    fd.opSetInput(op,fd.newConstant(8,0x4000),0);
    fd.opSetInput(op,boolvn,1);
    fd.opInsertEnd(op,blk);
    return op;
  }

  string name(const FlowBlock *bl) const
  {
    if (bl == (const FlowBlock *)0) return "-";
    for(size_t i=0;i<blocks.size();++i)
      if (blocks[i] == bl) return "b" + to_string(i);
    return "x";
  }

  string graphInventory(void) const
  {
    const BlockGraph &graph = fd.getBasicBlocks();
    ostringstream s;
    for(int4 i=0;i<graph.getSize();++i) {
      if (i != 0) s << ',';
      const BlockBasic *bb = (const BlockBasic *)graph.getBlock(i);
      int4 nops = 0;
      for(auto it = bb->beginOp(); it != bb->endOp(); ++it)
        ++nops;
      s << name(bb) << ':' << nops;
    }
    return s.str();
  }

  string opsOf(const FlowBlock *bl) const
  {
    const BlockBasic *bb = (const BlockBasic *)bl;
    ostringstream s;
    bool first = true;
    for(auto it = bb->beginOp(); it != bb->endOp(); ++it) {
      if (!first) s << ',';
      first = false;
      s << get_opname((*it)->code());
    }
    return s.str();
  }

  static string vname(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "-";
    ostringstream s;
    s << vn->getSpace()->getName() << ":0x" << hex << vn->getOffset()
      << ':' << dec << vn->getSize();
    return s.str();
  }

  static string vdesc(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "-";
    if (vn->isConstant()) {
      ostringstream s;
      s << "const:0x" << hex << vn->getOffset() << ':' << dec << vn->getSize();
      return s.str();
    }
    return vname(vn);
  }

  static string defToken(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return "-";
    const PcodeOp *def = vn->getDef();
    if (def == (const PcodeOp *)0) return "input";
    return get_opname(def->code());
  }

  string descendOpcodes(const Varnode *source) const
  {
    ostringstream s;
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter = source->beginDescend();
        iter != source->endDescend(); ++iter) {
      if (!first) s << ',';
      first = false;
      s << get_opname((*iter)->code());
    }
    return s.str();
  }

  // The first op of the given opcode in the block's op list.
  PcodeOp *firstOf(const FlowBlock *bl,OpCode opc) const
  {
    const BlockBasic *bb = (const BlockBasic *)bl;
    for(auto it = bb->beginOp(); it != bb->endOp(); ++it)
      if ((*it)->code() == opc) return *it;
    return (PcodeOp *)0;
  }

  // Per-RETURN projection: slot-1 descriptor, the feeding COPY's geometry,
  // flags, and the block's op order.
  void printReturn(const char *label,const FlowBlock *bl) const
  {
    PcodeOp *retop = firstOf(bl,CPUI_RETURN);
    const Varnode *in1 = retop->getIn(1);
    cout << "ret|blk=" << label
         << "|in1_const=" << (in1->isConstant() ? 1 : 0)
         << "|in1=" << vname(in1)
         << "|in1_def=" << defToken(in1)
         << "|ret_pc=0x" << hex << retop->getAddr().getOffset() << dec
         << "|ret_retflag=" << (retop->isReturnCopy() ? 1 : 0);
    const PcodeOp *def = in1->getDef();
    if (def != (const PcodeOp *)0 && def->code() == CPUI_COPY) {
      cout << "|copy_pc=0x" << hex << def->getAddr().getOffset() << dec
           << "|copy_retflag=" << (def->isReturnCopy() ? 1 : 0)
           << "|copy_in0=" << vdesc(def->getIn(0))
           << "|copy_out=" << vname(def->getOut());
    }
    cout << "|blk_ops=" << opsOf(bl) << '\n';
  }

  // Count RETURN ops holding a constant in any value slot (slot >= 1).
  int4 returnsWithConstValueSlot(void) const
  {
    int4 total = 0;
    const BlockGraph &graph = fd.getBasicBlocks();
    for(int4 i=0;i<graph.getSize();++i) {
      const BlockBasic *bb = (const BlockBasic *)graph.getBlock(i);
      for(auto it = bb->beginOp(); it != bb->endOp(); ++it) {
        PcodeOp *op = *it;
        if (op->code() != CPUI_RETURN) continue;
        for(int4 slot=1;slot<op->numInput();++slot)
          if (op->getIn(slot)->isConstant()) { total += 1; break; }
      }
    }
    return total;
  }

  // Full RulePropagateCopy sweep: the rule applies to all opcodes
  // (ruleaction.hh:730), so mirror the pool driver by visiting every live op.
  int4 runRulePropagateCopy(void)
  {
    RulePropagateCopy rule("");
    int4 hits = 0;
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    for(int4 i=0;i<graph.getSize();++i) {
      BlockBasic *bb = (BlockBasic *)graph.getBlock(i);
      vector<PcodeOp *> snapshot;
      for(auto it = bb->beginOp(); it != bb->endOp(); ++it)
        snapshot.push_back(*it);
      for(PcodeOp *op : snapshot)
        hits += rule.applyOp(op,fd);
    }
    return hits;
  }
};

}  // namespace

int main(void)
{
  cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  cout << "schema=1|fixture=RETURNFOLD-GAPB-CONDCONST-0001"
       << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    AddrSpace *reg = architecture.getSpace(4);
    Scope *global = architecture.symboltab->getGlobalScope();
    Funcdata fd("gapb","gapb",global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);
    // Heritage info list must exist before apply: numHeritagePasses(stack)
    // (cc:4522) dereferences getInfo() unconditionally (same prerequisite as
    // the condexe fixtures). pass=0, stack delay=1 -> numPasses=-1 <= 0 ->
    // useMultiequal=false.
    fd.heritage.buildInfoList();
    Fixture f(fd);
    BlockBasic *b0 = f.makeBlock();	// compare + CBRANCH
    BlockBasic *b1 = f.makeBlock();	// constBlock (b0 true edge)
    BlockBasic *b2 = f.makeBlock();	// INT_ADD + RETURN (dominated)
    BlockBasic *b3 = f.makeBlock();	// RETURN (dominated)
    BlockBasic *b4 = f.makeBlock();	// RETURN (not dominated)

    Varnode *X = fd.newVarnode(4,Address(reg,0x0));
    fd.setInputVarnode(X);
    Varnode *q = fd.newVarnode(1,Address(reg,0x8));
    fd.setInputVarnode(q);
    Varnode *const5 = fd.newConstant(4,5);

    Varnode *t;
    {
      PcodeOp *eq = fd.newOp(2,f.allocPc());			// 0x60000
      fd.opSetOpcode(eq,CPUI_INT_EQUAL);
      t = f.makeOut(1,f.uniqueSpace(),0x900,eq);
      fd.opSetInput(eq,X,0);
      fd.opSetInput(eq,const5,1);
      fd.opInsertEnd(eq,b0);
    }
    {
      PcodeOp *add = fd.newOp(2,f.allocPc());			// 0x60008
      fd.opSetOpcode(add,CPUI_INT_ADD);
      f.makeOut(4,f.uniqueSpace(),0x904,add);
      fd.opSetInput(add,X,0);
      fd.opSetInput(add,fd.newConstant(4,1),1);
      fd.opInsertEnd(add,b2);
    }
    {
      PcodeOp *r5 = fd.newOp(2,f.allocPc());			// 0x60010
      fd.opSetOpcode(r5,CPUI_RETURN);
      fd.opSetInput(r5,fd.newConstant(1,0),0);
      fd.opSetInput(r5,X,1);
      fd.opInsertEnd(r5,b2);
    }
    {
      PcodeOp *r6 = fd.newOp(2,f.allocPc());			// 0x60018
      fd.opSetOpcode(r6,CPUI_RETURN);
      fd.opSetInput(r6,fd.newConstant(1,0),0);
      fd.opSetInput(r6,X,1);
      fd.opInsertEnd(r6,b3);
    }
    {
      PcodeOp *r3 = fd.newOp(2,f.allocPc());			// 0x60020
      fd.opSetOpcode(r3,CPUI_RETURN);
      fd.opSetInput(r3,fd.newConstant(1,0),0);
      fd.opSetInput(r3,X,1);
      fd.opInsertEnd(r3,b4);
    }
    f.makeCbranchAt(b1,q,f.allocPc());				// 0x60028
    f.makeCbranchAt(b0,t,f.allocPc());				// 0x60030
    f.edge(b0,b4);	// CBRANCH out0 = false path
    f.edge(b0,b1);	// CBRANCH out1 = true path (X == 5 holds)
    f.edge(b1,b2);
    f.edge(b1,b3);
    fd.structureReset();

    cout << "pre|blocks=" << f.graphInventory()
         << "|x_loc=" << Fixture::vname(X)
         << "|x_desc=" << f.descendOpcodes(X)
         << "|b0_ops=" << f.opsOf(b0)
         << "|b1_ops=" << f.opsOf(b1)
         << "|b2_ops=" << f.opsOf(b2)
         << "|b3_ops=" << f.opsOf(b3)
         << "|b4_ops=" << f.opsOf(b4)
         << "|retflags=b2:" << (f.firstOf(b2,CPUI_RETURN)->isReturnCopy() ? 1 : 0)
         << ",b3:" << (f.firstOf(b3,CPUI_RETURN)->isReturnCopy() ? 1 : 0)
         << ",b4:" << (f.firstOf(b4,CPUI_RETURN)->isReturnCopy() ? 1 : 0)
         << '\n';

    CountProbe action;
    action.zeroCount();
    action.apply(fd);
    cout << "pass1|count=" << action.getCount()
         << "|x_desc_after=" << f.descendOpcodes(X)
         << "|returns_const_value_slot=" << f.returnsWithConstValueSlot()
         << "|distinct_copy_in0="
         << (f.firstOf(b2,CPUI_COPY)->getIn(0) != f.firstOf(b3,CPUI_COPY)->getIn(0) ? 1 : 0)
         << "|copies=b2:" << (f.firstOf(b2,CPUI_COPY) != (PcodeOp *)0 ? 1 : 0)
         << ",b3:" << (f.firstOf(b3,CPUI_COPY) != (PcodeOp *)0 ? 1 : 0)
         << ",b4:" << (f.firstOf(b4,CPUI_COPY) != (PcodeOp *)0 ? 1 : 0)
         << '\n';
    f.printReturn("b2",b2);
    f.printReturn("b3",b3);
    f.printReturn("b4",b4);
    {
      PcodeOp *add = f.firstOf(b2,CPUI_INT_ADD);
      cout << "add|blk=b2|in0=" << Fixture::vdesc(add->getIn(0))
           << "|in0_const=" << (add->getIn(0)->isConstant() ? 1 : 0)
           << "|in1=" << Fixture::vdesc(add->getIn(1)) << '\n';
    }

    action.zeroCount();
    action.apply(fd);
    cout << "pass2|count=" << action.getCount()
         << "|x_desc_after=" << f.descendOpcodes(X)
         << "|b2_ops=" << f.opsOf(b2)
         << "|b3_ops=" << f.opsOf(b3)
         << "|b4_ops=" << f.opsOf(b4)
         << "|returns_const_value_slot=" << f.returnsWithConstValueSlot()
         << '\n';

    int4 hits = f.runRulePropagateCopy();
    cout << "ruleprop|hits=" << hits
         << "|in1_def_b2=" << Fixture::defToken(f.firstOf(b2,CPUI_RETURN)->getIn(1))
         << "|in1_def_b3=" << Fixture::defToken(f.firstOf(b3,CPUI_RETURN)->getIn(1))
         << "|in1_const_b2="
         << (f.firstOf(b2,CPUI_RETURN)->getIn(1)->isConstant() ? 1 : 0)
         << "|in1_const_b3="
         << (f.firstOf(b3,CPUI_RETURN)->getIn(1)->isConstant() ? 1 : 0)
         << "|b2_ops=" << f.opsOf(b2)
         << "|b3_ops=" << f.opsOf(b3)
         << '\n';
  }
  catch (const LowlevelError &error) {
    cout << "exception|phase=after_pre|what=" << error.explain << '\n';
    return 1;
  }
  catch (const exception &error) {
    cout << "exception|phase=after_pre|what=" << error.what() << '\n';
    return 1;
  }
  cout << "case_apply_return|status=UNTESTED|note=Ghidra apply returns 0 unconditionally (cc:4545) while Rugra returns count>0; apply return value not projected (CONDCONST-APPLY-RETURN-0001)\n";
  cout << "case_phi_arm|status=UNTESTED|note=MULTIEQUAL phi replacement arm (handlePhiNodes) not exercised; use_multiequal=false on both sides here (CONDCONST-MULTIEQUAL-GUARD-0001)\n";
  cout << "case_implied_bool|status=UNTESTED|note=implied-boolean points require boolVn without lone descendant; fixture boolVn t is read only by its CBRANCH (CONDCONST-IMPLIEDBOOL-0001)\n";
  cout << "case_print_fold|status=UNTESTED|note=return 10 print folding needs MarkExplicit/MarkImplied/PrintC downstream (RETURNFOLD upstream GAP-A/GAP-D); IR-level only here\n";
  return 0;
}
