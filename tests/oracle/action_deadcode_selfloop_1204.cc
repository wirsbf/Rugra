/*
 * Locked Ghidra 12.0.4 ActionDeadCode self-loop/full-state oracle.
 *
 * The runner compiles this file against an immutable archive of commit
 * e40ed13014025f82488b1f8f7bca566894ac376b.  It adds read-only fixture
 * accessors and makes ActionDeadCode's private helpers callable in that
 * temporary archive only.  Production Ghidra sources are never modified.
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::set;
using std::string;
using std::vector;

class InspectableDeadCode : public ActionDeadCode {
public:
  InspectableDeadCode(void) : ActionDeadCode("analysis") {
    // Action::Action deliberately leaves these two protected fields
    // uninitialized.  Action::perform normally initializes them; this fixture
    // calls apply() directly so it must remove that otherwise-observable UB.
    count = 0;
    lcount = 0;
  }
  int4 fixtureCount(void) const { return count; }
};

class Fixture {
  Funcdata &fd;
  vector<BlockBasic *> blocks;
  map<BlockBasic *,string> blockNames;
  vector<PcodeOp *> ops;
  map<PcodeOp *,string> opNames;
  vector<Varnode *> varnodes;
  map<Varnode *,string> varnodeNames;

  string blockName(BlockBasic *block) const
  {
    if (block == (BlockBasic *)0) return "-";
    map<BlockBasic *,string>::const_iterator iter = blockNames.find(block);
    if (iter == blockNames.end()) throw std::runtime_error("unknown block");
    return (*iter).second;
  }

  string opName(PcodeOp *op) const
  {
    if (op == (PcodeOp *)0) return "-";
    map<PcodeOp *,string>::const_iterator iter = opNames.find(op);
    if (iter == opNames.end()) throw std::runtime_error("unknown op");
    return (*iter).second;
  }

  string varnodeName(Varnode *vn) const
  {
    if (vn == (Varnode *)0) return "-";
    map<Varnode *,string>::const_iterator iter = varnodeNames.find(vn);
    if (iter == varnodeNames.end()) throw std::runtime_error("unknown varnode");
    return (*iter).second;
  }

  string spaceName(AddrSpace *space) const
  {
    if (space == (AddrSpace *)0) return "-";
    switch(space->getType()) {
    case IPTR_CONSTANT: return "const";
    case IPTR_PROCESSOR: return "register";
    case IPTR_SPACEBASE: return "stack";
    case IPTR_INTERNAL: return "unique";
    case IPTR_IOP: return "iop";
    case IPTR_FSPEC: return "fspec";
    case IPTR_JOIN: return "join";
    default: break;
    }
    if (space == fd.getArch()->getDefaultDataSpace()) return "ram";
    return space->getName();
  }

  set<PcodeOp *> liveOps(void) const
  {
    set<PcodeOp *> result;
    for(PcodeOpTree::const_iterator iter=fd.beginOpAll();
        iter!=fd.endOpAll();++iter)
      result.insert((*iter).second);
    return result;
  }

  set<Varnode *> liveVarnodes(void) const
  {
    set<Varnode *> result;
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();
        iter!=fd.endLoc();++iter)
      result.insert(*iter);
    return result;
  }

  template<typename Iterator>
  string opList(Iterator iter,Iterator enditer) const
  {
    ostringstream out;
    bool first = true;
    for(;iter!=enditer;++iter) {
      if (!first) out << ',';
      first = false;
      out << opName(*iter);
    }
    return out.str();
  }

  string blockState(void) const
  {
    ostringstream out;
    for(vector<BlockBasic *>::const_iterator iter=blocks.begin();
        iter!=blocks.end();++iter) {
      if (iter != blocks.begin()) out << ';';
      BlockBasic *block = *iter;
      out << blockName(block) << "{index=" << block->getIndex() << ",in=[";
      for(int4 i=0;i<block->sizeIn();++i) {
        if (i != 0) out << ',';
        out << blockName((BlockBasic *)block->getIn(i));
      }
      out << "],out=[";
      for(int4 i=0;i<block->sizeOut();++i) {
        if (i != 0) out << ',';
        out << blockName((BlockBasic *)block->getOut(i));
      }
      out << "],ops=[" << opList(block->beginOp(),block->endOp()) << "]}";
    }
    return out.str();
  }

  string opState(PcodeOp *op,const set<PcodeOp *> &live) const
  {
    ostringstream out;
    out << opName(op) << "{present=";
    if (live.find(op) == live.end()) {
      out << "0}";
      return out.str();
    }
    out << "1,opc=" << static_cast<int4>(op->code())
        << ",flags=" << std::hex << op->fixtureGetFlags()
        << ",addl=" << op->fixtureGetAdditionalFlags() << std::dec
        << ",dead=" << op->isDead()
        << ",indirect=" << op->isIndirectSource()
        << ",parent=" << blockName(op->getParent())
        << ",addr=" << std::hex << op->getAddr().getOffset() << std::dec
        << ",time=" << op->getSeqNum().getTime()
        << ",order=" << op->getSeqNum().getOrder()
        << ",inputs=[";
    for(int4 i=0;i<op->numInput();++i) {
      if (i != 0) out << ',';
      out << varnodeName(op->getIn(i));
    }
    out << "],output=" << varnodeName(op->getOut()) << '}';
    return out.str();
  }

  string varnodeState(Varnode *vn,const set<Varnode *> &live) const
  {
    ostringstream out;
    out << varnodeName(vn) << "{present=";
    if (live.find(vn) == live.end()) {
      out << "0}";
      return out.str();
    }
    uintb displayOffset = vn->getOffset();
    if (varnodeName(vn) == "space")
      displayOffset = vn->getSpaceFromConst()->getIndex();
    out << "1,space=" << spaceName(vn->getSpace())
        << ",size=" << vn->getSize()
        << ",offset=" << std::hex << displayOffset
        << ",flags=" << vn->getFlags()
        << ",addl=" << vn->fixtureGetAdditionalFlags()
        << ",consume=" << vn->getConsume() << std::dec
        << ",vac=" << vn->isConsumeVacuous()
        << ",lis=" << vn->isConsumeList()
        << ",input=" << vn->isInput()
        << ",written=" << vn->isWritten()
        << ",autolive=" << vn->isAutoLive()
        << ",free=" << vn->isFree()
        << ",cover=" << vn->hasCover()
        << ",coverobj=" << vn->fixtureHasCoverObject()
        << ",locbank=" << (live.find(vn) != live.end())
        << ",defbank=" << (fd.fixtureHasDefVarnode(vn) ? 1 : 0)
        << ",def=" << opName(vn->getDef()) << ",desc=[";
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();
        iter!=vn->endDescend();++iter) {
      PcodeOp *descendant = *iter;
      int4 slot = descendant->getRepeatSlot(vn,descendant->getSlot(vn),iter);
      if (!first) out << ',';
      first = false;
      out << opName(descendant) << '.' << slot;
    }
    out << "]}";
    return out.str();
  }

  string deadRemoved(void) const
  {
    ostringstream out;
    const char *names[] = { "register", "unique", "stack" };
    for(int4 i=0;i<3;++i) {
      if (i != 0) out << ',';
      AddrSpace *space = fd.getArch()->getSpaceByName(names[i]);
      out << names[i] << ':';
      if (space == (AddrSpace *)0)
        out << '-';
      else
        out << fd.fixtureGetDeadRemoved(space);
    }
    return out.str();
  }

public:
  explicit Fixture(Funcdata &func) : fd(func) {}

  BlockBasic *makeBlock(const string &name)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);
    blocks.push_back(block);
    blockNames.insert(std::make_pair(block,name));
    return block;
  }

  void addEdge(BlockBasic *from,BlockBasic *to)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    graph.addEdge(from,to);
  }

  void rememberVarnode(Varnode *vn,const string &name)
  {
    if (varnodeNames.insert(std::make_pair(vn,name)).second)
      varnodes.push_back(vn);
  }

  void rememberOp(PcodeOp *op,const string &name)
  {
    if (opNames.insert(std::make_pair(op,name)).second)
      ops.push_back(op);
  }

  Varnode *makeInput(const string &name,int4 size,uintb offset)
  {
    AddrSpace *space = fd.getArch()->getSpaceByName("register");
    Varnode *vn = fd.setInputVarnode(fd.newVarnode(size,space,offset));
    rememberVarnode(vn,name);
    return vn;
  }

  Varnode *makeConstant(const string &name,int4 size,uintb value)
  {
    Varnode *vn = fd.newConstant(size,value);
    rememberVarnode(vn,name);
    return vn;
  }

  Varnode *makeSpace(const string &name,AddrSpace *space)
  {
    Varnode *vn = fd.newVarnodeSpace(space);
    rememberVarnode(vn,name);
    return vn;
  }

  Varnode *makeFree(const string &name,int4 size,uintb offset)
  {
    AddrSpace *space = fd.getArch()->getSpaceByName("register");
    Varnode *vn = fd.newVarnode(size,space,offset);
    rememberVarnode(vn,name);
    return vn;
  }

  PcodeOp *makeOp(const string &name,OpCode opcode,int4 inputs,int4 outputSize)
  {
    PcodeOp *op = fd.newOp(inputs,Address(fd.getArch()->getDefaultCodeSpace(),0x4c20));
    fd.opSetOpcode(op,opcode);
    rememberOp(op,name);
    if (outputSize != 0) {
      Varnode *out = fd.newUniqueOut(outputSize,op);
      rememberVarnode(out,name + "_out");
    }
    return op;
  }

  void setInput(PcodeOp *op,Varnode *vn,int4 slot) { fd.opSetInput(op,vn,slot); }
  void insertEnd(PcodeOp *op,BlockBasic *block) { fd.opInsertEnd(op,block); }

  void clearConsume(void)
  {
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter) {
      Varnode *vn = *iter;
      vn->setConsume(0);
      vn->clearConsumeList();
      vn->clearConsumeVacuous();
    }
  }

  string worklistState(const vector<Varnode *> &worklist) const
  {
    ostringstream out;
    for(vector<Varnode *>::const_iterator iter=worklist.begin();
        iter!=worklist.end();++iter) {
      if (iter != worklist.begin()) out << ',';
      out << varnodeName(*iter);
    }
    return out.str();
  }

  void trace(const string &caseName,const string &event,
             const vector<Varnode *> &worklist,const string &popped="-") const
  {
    set<PcodeOp *> liveop = liveOps();
    set<Varnode *> livevn = liveVarnodes();
    ostringstream states;
    for(vector<Varnode *>::const_iterator iter=varnodes.begin();
        iter!=varnodes.end();++iter) {
      if (iter != varnodes.begin()) states << ';';
      states << varnodeState(*iter,livevn);
    }
    std::cout << "trace=" << caseName << "|event=" << event
              << "|popped=" << popped
              << "|work=[" << worklistState(worklist) << ']'
              << "|varnodes=[" << states.str() << "]\n";
  }

  void dump(const string &caseName,const string &stage,const string &result,
            int4 actionCount) const
  {
    set<PcodeOp *> liveop = liveOps();
    set<Varnode *> livevn = liveVarnodes();
    ostringstream opstates;
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      if (iter != ops.begin()) opstates << ';';
      opstates << opState(*iter,liveop);
    }
    ostringstream vnstates;
    for(vector<Varnode *>::const_iterator iter=varnodes.begin();
        iter!=varnodes.end();++iter) {
      if (iter != varnodes.begin()) vnstates << ';';
      vnstates << varnodeState(*iter,livevn);
    }
    AddrSpace *reg = fd.getArch()->getSpaceByName("register");
    AddrSpace *uniq = fd.getArch()->getSpaceByName("unique");
    std::cout << "case=" << caseName << "|stage=" << stage
              << "|result=" << result << "|count=" << actionCount
              << "|heritage=" << fd.getHeritagePass()
              << "|allowed=[register:" << fd.deadRemovalAllowed(reg)
              << ",unique:" << fd.deadRemovalAllowed(uniq) << ']'
              << "|seen=[" << deadRemoved() << ']'
              << "|blocks=[" << blockState() << ']'
              << "|alive=[" << opList(fd.beginOpAlive(),fd.endOpAlive()) << ']'
              << "|dead=[" << opList(fd.beginOpDead(),fd.endOpDead()) << ']'
              << "|ops=[" << opstates.str() << ']'
              << "|varnodes=[" << vnstates.str() << "]\n";
  }
};

void prepare(Funcdata &fd,int4 heritagePass)
{
  fd.clear();
  fd.fixtureSetHeritagePass(heritagePass);
  if (fd.getHeritagePass() != heritagePass)
    throw std::runtime_error("heritage pass setup failed");
}

void applyAndDump(Fixture &fixture,Funcdata &fd,const string &name)
{
  InspectableDeadCode action;
  fixture.dump(name,"before","na",action.fixtureCount());
  int4 result = action.apply(fd);
  fixture.dump(name,"after",std::to_string(result),action.fixtureCount());
}

void runOrdinaryChain(Funcdata &fd)
{
  prepare(fd,1);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *x = f.makeInput("x",8,0x40);
  x->setLockedInput();
  PcodeOp *first = f.makeOp("first",CPUI_COPY,1,8);
  PcodeOp *second = f.makeOp("second",CPUI_COPY,1,8);
  f.setInput(first,x,0);
  f.setInput(second,first->getOut(),0);
  f.insertEnd(first,block);
  f.insertEnd(second,block);
  applyAndDump(f,fd,"ordinary_chain_no_seed");
}

void runSelfLoop(Funcdata &fd)
{
  prepare(fd,1);
  fd.getFuncProto().setReturnBytesConsumed(1);
  Fixture f(fd);
  BlockBasic *left = f.makeBlock("b0");
  BlockBasic *right = f.makeBlock("b1");
  BlockBasic *loop = f.makeBlock("b2");
  f.addEdge(left,loop);
  f.addEdge(right,loop);
  f.addEdge(loop,loop);
  Varnode *x = f.makeInput("x",8,0x40);
  Varnode *returnTarget = f.makeConstant("return_target",8,0);
  PcodeOp *phi = f.makeOp("phi",CPUI_MULTIEQUAL,3,8);
  PcodeOp *ret = f.makeOp("ret",CPUI_RETURN,2,0);
  f.setInput(phi,x,0);
  f.setInput(phi,x,1);
  f.setInput(phi,phi->getOut(),2);
  f.setInput(ret,returnTarget,0);
  f.setInput(ret,phi->getOut(),1);
  f.insertEnd(phi,loop);
  f.insertEnd(ret,loop);
  applyAndDump(f,fd,"selfloop_repeated_live");
}

void runTwoPhiCycle(Funcdata &fd)
{
  prepare(fd,1);
  fd.getFuncProto().setReturnBytesConsumed(1);
  Fixture f(fd);
  BlockBasic *entry = f.makeBlock("b0");
  BlockBasic *loop = f.makeBlock("b1");
  f.addEdge(entry,loop);
  f.addEdge(loop,loop);
  Varnode *x = f.makeInput("x",8,0x40);
  Varnode *y = f.makeInput("y",8,0x50);
  Varnode *returnTarget = f.makeConstant("return_target",8,0);
  PcodeOp *a = f.makeOp("a",CPUI_MULTIEQUAL,2,8);
  PcodeOp *b = f.makeOp("b",CPUI_MULTIEQUAL,2,8);
  PcodeOp *ret = f.makeOp("ret",CPUI_RETURN,2,0);
  f.setInput(a,x,0);
  f.setInput(a,b->getOut(),1);
  f.setInput(b,y,0);
  f.setInput(b,a->getOut(),1);
  f.setInput(ret,returnTarget,0);
  f.setInput(ret,a->getOut(),1);
  f.insertEnd(a,loop);
  f.insertEnd(b,loop);
  f.insertEnd(ret,loop);
  applyAndDump(f,fd,"two_phi_cycle_live");
}

void runAutoLive(Funcdata &fd)
{
  prepare(fd,1);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *autoInput = f.makeInput("auto_input",8,0x40);
  autoInput->setLockedInput();
  autoInput->setAutoLiveHold();
  Varnode *x = f.makeInput("x",8,0x50);
  PcodeOp *dead = f.makeOp("dead",CPUI_COPY,1,8);
  PcodeOp *held = f.makeOp("held",CPUI_COPY,1,8);
  held->getOut()->setAutoLiveHold();
  f.setInput(dead,autoInput,0);
  f.setInput(held,x,0);
  f.insertEnd(dead,block);
  f.insertEnd(held,block);
  applyAndDump(f,fd,"autolive_input_output");
}

void runCall(Funcdata &fd)
{
  prepare(fd,1);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *userop = f.makeConstant("userop",4,0);
  Varnode *argument = f.makeInput("argument",8,0x40);
  PcodeOp *call = f.makeOp("call",CPUI_CALLOTHER,2,8);
  call->setHoldOutput();
  f.setInput(call,userop,0);
  f.setInput(call,argument,1);
  f.insertEnd(call,block);
  applyAndDump(f,fd,"callother_without_spec_hold_output");
}

void runDeadCallOutput(Funcdata &fd)
{
  prepare(fd,1);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *userop = f.makeConstant("userop",4,0);
  Varnode *argument = f.makeInput("argument",8,0x40);
  PcodeOp *call = f.makeOp("call",CPUI_CALLOTHER,2,8);
  call->getOut()->fixtureCalcCover();
  f.setInput(call,userop,0);
  f.setInput(call,argument,1);
  f.insertEnd(call,block);
  applyAndDump(f,fd,"callother_dead_output_unset_only");
}

void runDirectUnsetOutput(Funcdata &fd)
{
  prepare(fd,1);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *x = f.makeInput("x",8,0x40);
  PcodeOp *copy = f.makeOp("copy",CPUI_COPY,1,8);
  copy->getOut()->fixtureCalcCover();
  f.setInput(copy,x,0);
  f.insertEnd(copy,block);
  f.dump("direct_op_unset_output","before","na",0);
  fd.opUnsetOutput(copy);
  f.dump("direct_op_unset_output","after","0",0);
}

void runDirectSetOutput(Funcdata &fd)
{
  prepare(fd,1);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  PcodeOp *copy = f.makeOp("copy",CPUI_COPY,0,0);
  Varnode *output = f.makeFree("free_out",8,0x60);
  f.insertEnd(copy,block);
  fd.opSetOutput(copy,output);
  f.dump("direct_op_set_output","before","na",0);
  fd.opUnsetOutput(copy);
  f.dump("direct_op_set_output","after","0",0);
}

void runDirectNewVarnodeOut(Funcdata &fd)
{
  prepare(fd,1);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  PcodeOp *copy = f.makeOp("copy",CPUI_COPY,0,0);
  f.insertEnd(copy,block);
  AddrSpace *space = fd.getArch()->getSpaceByName("register");
  Varnode *output = fd.newVarnodeOut(8,Address(space,0x70),copy);
  f.rememberVarnode(output,"new_out");
  f.dump("direct_new_varnode_out","before","na",0);
  fd.opUnsetOutput(copy);
  f.dump("direct_new_varnode_out","after","0",0);
}

void runLoad(Funcdata &fd,int4 pass,const string &name)
{
  prepare(fd,pass);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  AddrSpace *ram = fd.getArch()->getDefaultDataSpace();
  Varnode *space = f.makeSpace("space",ram);
  Varnode *address = f.makeConstant("address",8,0x1234);
  PcodeOp *load = f.makeOp("load",CPUI_LOAD,2,8);
  f.setInput(load,space,0);
  f.setInput(load,address,1);
  f.insertEnd(load,block);
  applyAndDump(f,fd,name);
}

void runHelperTrace(Funcdata &fd)
{
  prepare(fd,1);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *x = f.makeInput("x",8,0x40);
  Varnode *y = f.makeInput("y",8,0x50);
  PcodeOp *direct = f.makeOp("direct",CPUI_MULTIEQUAL,3,8);
  PcodeOp *a = f.makeOp("a",CPUI_MULTIEQUAL,2,8);
  PcodeOp *b = f.makeOp("b",CPUI_MULTIEQUAL,2,8);
  f.setInput(direct,x,0);
  f.setInput(direct,direct->getOut(),1);
  f.setInput(direct,direct->getOut(),2);
  f.setInput(a,x,0);
  f.setInput(a,b->getOut(),1);
  f.setInput(b,y,0);
  f.setInput(b,a->getOut(),1);
  f.insertEnd(direct,block);
  f.insertEnd(a,block);
  f.insertEnd(b,block);

  vector<Varnode *> worklist;
  f.clearConsume();
  f.trace("helper_unwritten_input","initial",worklist);
  ActionDeadCode::pushConsumed(0,x,worklist);
  f.trace("helper_unwritten_input","push_zero",worklist);
  ActionDeadCode::pushConsumed(0,x,worklist);
  f.trace("helper_unwritten_input","push_zero_duplicate",worklist);

  worklist.clear();
  f.clearConsume();
  f.trace("helper_direct_selfloop","initial",worklist);
  ActionDeadCode::pushConsumed(0,direct->getOut(),worklist);
  f.trace("helper_direct_selfloop","push_zero",worklist);
  ActionDeadCode::pushConsumed(0,direct->getOut(),worklist);
  f.trace("helper_direct_selfloop","push_zero_duplicate",worklist);
  ActionDeadCode::pushConsumed(0xff,direct->getOut(),worklist);
  f.trace("helper_direct_selfloop","grow_pending",worklist);
  string popped = f.worklistState(worklist).empty() ? "-" : "direct_out";
  ActionDeadCode::propagateConsumed(worklist);
  f.trace("helper_direct_selfloop","pop",worklist,popped);

  worklist.clear();
  f.clearConsume();
  f.trace("helper_two_phi_growth","initial",worklist);
  ActionDeadCode::pushConsumed(1,a->getOut(),worklist);
  f.trace("helper_two_phi_growth","seed_a_1",worklist);
  ActionDeadCode::propagateConsumed(worklist);
  f.trace("helper_two_phi_growth","pop_a",worklist,"a_out");
  ActionDeadCode::pushConsumed(2,a->getOut(),worklist);
  f.trace("helper_two_phi_growth","grow_a_2",worklist);
  ActionDeadCode::propagateConsumed(worklist);
  f.trace("helper_two_phi_growth","pop_a_lifo",worklist,"a_out");
  ActionDeadCode::propagateConsumed(worklist);
  f.trace("helper_two_phi_growth","pop_b",worklist,"b_out");
}

void run(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0 || fd->getAddress().getOffset() != 0x36d0)
      throw std::runtime_error("GetStr fixture identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("architecture/compiler identity drifted");

    runOrdinaryChain(*fd);
    runSelfLoop(*fd);
    runTwoPhiCycle(*fd);
    runAutoLive(*fd);
    runCall(*fd);
    runDeadCallOutput(*fd);
    runDirectUnsetOutput(*fd);
    runDirectSetOutput(*fd);
    runDirectNewVarnodeOut(*fd);
    runLoad(*fd,1,"last_chance_load_pass1");
    runLoad(*fd,2,"last_chance_load_pass2_gate");
    runHelperTrace(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: action_deadcode_selfloop_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1],argv[2]);
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
