/*
 * BLOCK-FINALIZE-DEFAULT-RECURSE-0001: locked Ghidra 12.0.4
 * BlockGraph::finalizePrinting recursion oracle for the switch DEFAULT arm
 * (block.cc:3556-3559 BlockSwitch::finalizePrinting ->
 *  block.cc:1364-1371 BlockGraph::finalizePrinting ->
 *  block.cc:3403-3424 BlockWhileDo::finalizePrinting).
 *
 * The fixture drives the production structure sweeps over a switch whose
 * DEFAULT edge (f_defaultswitch_edge, marked by Funcdata::installSwitchDefaults,
 * funcdata_block.cc:687-700, standing in for jumptable recovery) targets a
 * while-loop:
 *
 *   b0 (entry, BRANCHIND x, for-initializer `i = 0` COPY before it)
 *      out0 -> b1  (case body, RETURN)
 *      out1 -> b2  (DEFAULT edge)
 *   b2 (loop head: i = MULTIEQUAL(i0, i_next); c = INT_LESS(i, 10);
 *                CBRANCH c)   out0 -> b4 exit, out1 -> b3 body
 *   b3 (loop body: i_next = INT_ADD(i, 1))  out0 -> b2
 *   b4 (formal exit block, RETURN)
 *
 * ruleBlockWhileDo (blockaction.cc:1518) forms W=[b2,b3] first, then
 * ruleBlockSwitch (blockaction.cc:1655) consumes cs=[b0,b1,W] via
 * newBlockSwitch (block.cc:1904-1919) — the default arm W is a STRUCTURE
 * MEMBER (identifyInternal), so BlockGraph::finalizePrinting's plain
 * list walk reaches it and BlockWhileDo::finalizePrinting runs the
 * for-extraction: testTerminal -> testIterateForm -> findInitializer ->
 * data.opMarkNonPrinting(iterateOp/initializeOp) (block.cc:3409-3424).
 * The observable: the INT_ADD iterator and the COPY initializer are
 * flagged notPrinted, everything else is not.
 *
 * i0/i_next carry Varnode::setExplicit() standing in for varmap's
 * explicitness marking (production runs ActionFinalStructure after
 * HighVariable merging); the switch's f_switch_out flag stands in for
 * jumptable recovery marking.
 *
 * Sequence mirrors ActionBlockStructure (blockaction.cc:2170-2183) +
 * ActionStructureTransform (cc:2109-2115) + ActionFinalStructure head
 * (cc:2185-2192): installSwitchDefaults -> structureReset -> buildCopy ->
 * W/newBlockSwitch install -> finalTransform -> orderBlocks ->
 * finalizePrinting. The ActionFinalStructure tail (scopeBreak/
 * markUnstructured/markLabelBumpUp) is not needed for this observable and
 * is not run.
 *
 * STRUCTURE INSTALL NOTE: the corpus has no switch whose default arm
 * carries a loop (the latent-defect premise of BLOCK-FINALIZE-DEFAULT-
 * RECURSE-0001), and a single CollapseStructure run consumes the raw
 * default target before the loop can form under it (ruleSwitch's obvious-
 * exit scan takes any 2-in successor). The tree is therefore installed
 * through the PRODUCTION FACTORIES in the order the collapse rules would
 * produce when W forms first: ruleBlockWhileDo's newBlockWhileDo
 * (blockaction.cc:1526-1546 -> block.cc:1856-1868), then ruleBlockSwitch's
 * newBlockSwitch over cs=[head,case,W] (blockaction.cc:1714-1721 ->
 * block.cc:1904-1919) — the same direct-construction family as
 * printc_switch_emit_1204.cc. finalizePrinting itself runs unmodified.
 *
 * Observation is printed as independent sorted fact lines (tree node
 * identity reduced to node TYPES, op identity to block ordinal + opcode:
 * fresh BlockCopy indices and seqnum addresses differ between tree
 * builders — same normalization family as
 * blockstruct_scopebreak_gototype_1204).
 */

#include <bits/stdc++.h>

// Test-only access (same scheme as condexe_success_state_1204.cc /
// printc_switch_emit_1204.cc): production structures whose helpers are
// protected/private (BlockGraph::newBlockBasic/addEdge, JumpTable tables,
// Funcdata::jumpvec, BlockWhileDo::iterateOp/initializeOp) open in this
// TU only.
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "blockaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "jumptable.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef class
#undef private

using namespace ghidra;
using std::cout;
using std::cerr;

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

string type_name(FlowBlock::block_type bt)
{
  switch (bt) {
  case FlowBlock::t_basic: return "basic";
  case FlowBlock::t_copy: return "copy";
  case FlowBlock::t_graph: return "graph";
  case FlowBlock::t_plain: return "plain";
  case FlowBlock::t_goto: return "goto";
  case FlowBlock::t_multigoto: return "multigoto";
  case FlowBlock::t_ls: return "list";
  case FlowBlock::t_condition: return "condition";
  case FlowBlock::t_if: return "properif";
  case FlowBlock::t_whiledo: return "whiledo";
  case FlowBlock::t_dowhile: return "dowhile";
  case FlowBlock::t_switch: return "switch";
  case FlowBlock::t_infloop: return "infloop";
  }
  return "?";
}

void collect_tree_lines(FlowBlock *bl, vector<string> &lines)
{
  const string ty = type_name(bl->getType());
  if (bl->getType() == FlowBlock::t_whiledo) {
    BlockWhileDo *wd = (BlockWhileDo *)bl;
    lines.push_back("node whiledo iterate=" +
      (wd->iterateOp != (PcodeOp *)0 ? string(get_opname(wd->iterateOp->code())) : string("-")) +
      " initialize=" +
      (wd->initializeOp != (PcodeOp *)0 ? string(get_opname(wd->initializeOp->code())) : string("-")) +
      " loopdef=" +
      (wd->loopDef != (PcodeOp *)0 ? string(get_opname(wd->loopDef->code())) : string("-")));
  }
  else if (bl->getType() == FlowBlock::t_switch) {
    BlockSwitch *sw = (BlockSwitch *)bl;
    int4 ndefault = 0;
    vector<string> memberTypes;
    BlockGraph *g = (BlockGraph *)bl;
    for(int4 i=0;i<g->getSize();++i)
      memberTypes.push_back(type_name(g->getBlock(i)->getType()));
    for(int4 i=0;i<(int4)sw->caseblocks.size();++i)
      if (sw->caseblocks[i].isdefault) ndefault += 1;
    sort(memberTypes.begin(),memberTypes.end());
    ostringstream members;
    for(int4 i=0;i<(int4)memberTypes.size();++i) {
      if (i != 0) members << ",";
      members << memberTypes[i];
    }
    ostringstream line;
    line << "node switch members=" << members.str()
         << " caseblocks=" << sw->caseblocks.size()
         << " defaultcases=" << ndefault;
    lines.push_back(line.str());
  }
  else {
    lines.push_back("node " + ty);
  }
  // Walk children through the uniform BlockGraph component protocol
  // (getBlock(i)); leaves (basic/copy) and non-graph nodes have none.
  if (BlockGraph *g = dynamic_cast<BlockGraph *>(bl)) {
    for(int4 i=0;i<g->getSize();++i)
      collect_tree_lines(g->getBlock(i), lines);
  }
}

} // namespace

int main(void)
{
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);
  FixtureArchitecture arch;
  AddrSpace *ram = arch.getSpaceByName("ram");
  AddrSpace *reg = arch.getSpaceByName("register");
  Scope *global = arch.symboltab->getGlobalScope();

  Funcdata fd("f","f",global,Address(ram,0x60000),(FunctionSymbol *)0,0x100);

  BlockGraph &bblocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
  vector<BlockBasic *> bb(5);
  for(int4 i=0;i<5;++i)
    bb[i] = bblocks.newBlockBasic(&fd);

  // Ops. Addresses ascending within each block; block order fixed by creation.
  // b0: i0 = COPY 0;  BRANCHIND x
  PcodeOp *initOp = fd.newOp(1,Address(ram,0x60000));
  fd.opSetOpcode(initOp,CPUI_COPY);
  Varnode *i0 = fd.newUniqueOut(4,initOp);
  fd.opSetInput(initOp,fd.newConstant(4,0),0);
  fd.opInsertEnd(initOp,bb[0]);
  PcodeOp *indOp = fd.newOp(1,Address(ram,0x60004));
  fd.opSetOpcode(indOp,CPUI_BRANCHIND);
  Varnode *x = fd.newVarnode(4,Address(reg,0));
  fd.opSetInput(indOp,x,0);
  fd.opInsertEnd(indOp,bb[0]);
  // b1: RETURN
  PcodeOp *ret1 = fd.newOp(1,Address(ram,0x60010));
  fd.opSetOpcode(ret1,CPUI_RETURN);
  fd.opSetInput(ret1,fd.newConstant(1,0),0);
  fd.opInsertEnd(ret1,bb[1]);
  // b2: i = MULTIEQUAL(i0, i_next); c = INT_LESS(i, 10); CBRANCH
  PcodeOp *meOp = fd.newOp(2,Address(ram,0x60020));
  fd.opSetOpcode(meOp,CPUI_MULTIEQUAL);
  Varnode *i = fd.newUniqueOut(4,meOp);
  PcodeOp *addOp = fd.newOp(2,Address(ram,0x60040)); // created early: i_next needed as meOp input
  fd.opSetOpcode(addOp,CPUI_INT_ADD);
  Varnode *iNext = fd.newUniqueOut(4,addOp);
  fd.opSetInput(meOp,i0,0);
  fd.opSetInput(meOp,iNext,1);
  fd.opInsertEnd(meOp,bb[2]);
  PcodeOp *ltOp = fd.newOp(2,Address(ram,0x60024));
  fd.opSetOpcode(ltOp,CPUI_INT_LESS);
  Varnode *c = fd.newUniqueOut(1,ltOp);
  fd.opSetInput(ltOp,i,0);
  fd.opSetInput(ltOp,fd.newConstant(4,10),1);
  fd.opInsertEnd(ltOp,bb[2]);
  PcodeOp *cbOp = fd.newOp(2,Address(ram,0x60028));
  fd.opSetOpcode(cbOp,CPUI_CBRANCH);
  fd.opSetInput(cbOp,fd.newConstant(8,0x60080),0);
  fd.opSetInput(cbOp,c,1);
  fd.opInsertEnd(cbOp,bb[2]);
  // b3: i_next = INT_ADD(i, 1)
  fd.opSetInput(addOp,i,0);
  fd.opSetInput(addOp,fd.newConstant(4,1),1);
  fd.opInsertEnd(addOp,bb[3]);
  // b4: RETURN
  PcodeOp *ret2 = fd.newOp(1,Address(ram,0x60060));
  fd.opSetOpcode(ret2,CPUI_RETURN);
  fd.opSetInput(ret2,fd.newConstant(1,1),0);
  fd.opInsertEnd(ret2,bb[4]);

  // Explicitness: varmap's marking, stood in for the finalize gate
  // (testTerminal cc:3231 `vn->isExplicit()`).
  i0->setExplicit();
  iNext->setExplicit();

  // Edges (order fixes slot semantics):
  bblocks.addEdge(bb[0],bb[1]);	// b0 out0: case
  bblocks.addEdge(bb[0],bb[2]);	// b0 out1: DEFAULT (b2 in0)
  bblocks.addEdge(bb[2],bb[4]);	// b2 out0: loop exit (fallthru)
  bblocks.addEdge(bb[2],bb[3]);	// b2 out1: loop body (true)
  bblocks.addEdge(bb[3],bb[2]);	// b3 out0: back edge (b2 in1)

  // bb[0] carries f_switch_out automatically: BlockBasic::insert sets it
  // when the BRANCHIND lands (block.cc:2394-2396) — the jumptable-recovery
  // stand-in is the registered table below.
  JumpTable *jt = new JumpTable(&arch,Address());
  jt->setIndirectOp(indOp);
  jt->defaultBlock = 1;		// out-edge 1 of bb[0] is the default
  fd.jumpvec.push_back(jt);

  // Production runs finalizePrinting after HighVariable merging; the
  // highlevel_on gate stands in for that phase (assignHigh is a no-op
  // until Funcdata::setHighLevel() runs, cc:48-56).
  fd.setHighLevel();
  // ActionBlockStructure (blockaction.cc:2170-2183). Order matters:
  // structureReset -> structureLoops -> findSpanningTree clears ALL edge
  // flags (block.cc:1047 clearEdgeFlags(~0)), so the default-edge mark is
  // installed AFTER the reset, exactly like production (the final
  // structureReset happens at flow-follow time; ActionBlockStructure then
  // runs installSwitchDefaults -> buildCopy).
  fd.structureReset();
  fd.installSwitchDefaults();
  BlockGraph &graph(fd.getStructure());
  graph.buildCopy(fd.getBasicBlocks());

  // ruleBlockWhileDo (blockaction.cc:1518-1546) forms W=[cond,body] first
  // (production factory block.cc:1856-1868), so the switch's default arm
  // is the structured loop when ruleBlockSwitch consumes cs (below).
  // Copies resolve through copymap (buildCopy's mirror map, block.cc:1930):
  // structureReset's structureLoops reordered the list into reverse post
  // order, so positional getBlock(i) is NOT the creation index.
  BlockCopy *condCopy = (BlockCopy *)bb[2]->copymap;
  BlockCopy *bodyCopy = (BlockCopy *)bb[3]->copymap;
  BlockWhileDo *w;
  try {
    w = graph.newBlockWhileDo(condCopy, bodyCopy);
  }
  catch(const LowlevelError &error) {
    cerr << "newBlockWhileDo: " << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 3;
  }

  // ruleBlockSwitch (blockaction.cc:1655-1721) with exitblock = bb[4]:
  // cases = [head copy, caseA copy, W] — W rides the installSwitchDefaults-
  // marked default edge (out-edge 1), production factory block.cc:1904-1919.
  vector<FlowBlock *> cs;
  cs.push_back(bb[0]->copymap);				// head copy
  cs.push_back(bb[1]->copymap);				// caseA copy
  cs.push_back(w);					// the default arm
  try {
    graph.newBlockSwitch(cs, true);
  }
  catch(const LowlevelError &error) {
    cerr << "newBlockSwitch: " << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 3;
  }
  // ActionStructureTransform (cc:2109-2115)
  graph.finalTransform(fd);
  // ActionFinalStructure head (cc:2185-2192)
  graph.orderBlocks();
  try {
    graph.finalizePrinting(fd);
  }
  catch(const LowlevelError &error) {
    cerr << "finalizePrinting LowlevelError: " << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 2;
  }

  // ---- Observation ----
  vector<string> lines;
  cout << "case switch_default_whiledo\n";
  cout << "analyze_for_loops=" << (arch.analyze_for_loops ? 1 : 0) << "\n";
  cout << "structure_roots=" << graph.getSize() << "\n";
  for(int4 i=0;i<graph.getSize();++i)
    collect_tree_lines(graph.getBlock(i), lines);
  for(int4 b=0;b<bblocks.getSize();++b) {
    BlockBasic *bl = (BlockBasic *)bblocks.getBlock(b);
    int4 ordinal = 0;
    for(list<PcodeOp *>::const_iterator iter=bl->op.begin();iter!=bl->op.end();++iter) {
      PcodeOp *op = *iter;
      ostringstream line;
      line << "op blk" << b << "#" << ordinal << " " << get_opname(op->code())
           << " notprinted=" << (op->notPrinted() ? 1 : 0);
      lines.push_back(line.str());
      ordinal += 1;
    }
  }
  sort(lines.begin(),lines.end());
  for(int4 i=0;i<(int4)lines.size();++i)
    cout << lines[i] << "\n";
  cout << "end\n";
  shutdownDecompilerLibrary();
  return 0;
}
