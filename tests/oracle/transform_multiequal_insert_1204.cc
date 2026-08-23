/* TRANSFORM-MULTIEQUAL-INSERT-0001: locked Ghidra 12.0.4 fixture. */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "transform.hh"

#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

string snapshot(const Funcdata *fd,BlockBasic *block)
{
  vector<PcodeOp *> ops;
  map<PcodeOp *,int4> opIndex;
  for(list<PcodeOp *>::const_iterator iter=block->beginOp();iter!=block->endOp();++iter) {
    opIndex[*iter] = ops.size();
    ops.push_back(*iter);
  }
  vector<Varnode *> vars;
  map<Varnode *,int4> varIndex;
  for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
    PcodeOp *op = *iter;
    Varnode *outvn = op->getOut();
    if (outvn != (Varnode *)0 && varIndex.find(outvn) == varIndex.end()) {
      varIndex[outvn] = vars.size();
      vars.push_back(outvn);
    }
    for(int4 slot=0;slot<op->numInput();++slot) {
      Varnode *invn = op->getIn(slot);
      if (invn == (Varnode *)0)
	continue;			// NULL slot survives only pre-placeInputs (error partial state)
      if (varIndex.find(invn) == varIndex.end()) {
	varIndex[invn] = vars.size();
	vars.push_back(invn);
      }
    }
  }
  ostringstream out;
  out << "ops[";
  for(int4 index=0;index<ops.size();++index) {
    if (index != 0) out << ';';
    PcodeOp *op = ops[index];
    out << 'o' << index << ':' << (int4)op->code()
        << "/t" << op->getSeqNum().getTime()
        << "/r" << op->getSeqNum().getOrder()
        << "/p" << (op->getParent() == block ? block->getIndex() : -1)
        << "/I" << (op->isIndirectCreation() ? 1 : 0)
        << "/o";
    if (op->getOut() == (Varnode *)0)
      out << '_';
    else
      out << 'v' << varIndex[op->getOut()];
    out << "/i";
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (slot != 0) out << ',';
      Varnode *invn = op->getIn(slot);
      if (invn == (Varnode *)0)
	out << '_';
      else
	out << 'v' << varIndex[invn];
    }
  }
  out << "]vars[";
  for(int4 index=0;index<vars.size();++index) {
    if (index != 0) out << ';';
    Varnode *vn = vars[index];
    out << 'v' << index << ":c" << vn->getCreateIndex()
        << "/s" << vn->getSize()
        << "/sp" << vn->getSpace()->getIndex()
        << "/k" << (vn->isConstant() ? 1 : 0);
    if (vn->isConstant()) out << ':' << vn->getOffset();
    out << "/x" << ((vn->getFlags() & Varnode::indirect_creation) != 0 ? 1 : 0);
    out << "/d";
    map<PcodeOp *,int4>::const_iterator defiter = opIndex.find(vn->getDef());
    if (defiter == opIndex.end()) out << '_'; else out << 'o' << (*defiter).second;
    out << "/u";
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      if (!first) out << ',';
      first = false;
      map<PcodeOp *,int4>::const_iterator useiter = opIndex.find(*iter);
      if (useiter == opIndex.end()) out << 'x'; else out << 'o' << (*useiter).second;
    }
  }
  out << "]count=" << ops.size()
      << ',' << vars.size()
      << ',' << std::distance(fd->beginOpAlive(),fd->endOpAlive())
      << ',' << std::distance(fd->beginOpDead(),fd->endOpDead())
      << ',' << std::distance(fd->beginOpAll(),fd->endOpAll())
      << ',' << fd->numVarnodes();
  return out.str();
}

BlockBasic *newBlock(Funcdata *fd)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
  return graph.newBlockBasic(fd);
}

PcodeOp *newAnchor(Funcdata *fd,BlockBasic *block,uintb address)
{
  PcodeOp *op = fd->newOp(0,Address(fd->getArch()->getDefaultCodeSpace(),address));
  fd->opSetOpcode(op,CPUI_COPY);
  fd->opInsertEnd(op,block);
  return op;
}

void wire(TransformManager &manager,TransformOp *op,int4 inputs,int4 outputSize,uintb valueBase)
{
  TransformVar *output = manager.newUnique(outputSize);
  manager.opSetOutput(op,output);
  for(int4 slot=0;slot<inputs;++slot) {
    TransformVar *input = manager.newConstant(outputSize,0,valueBase + slot);
    manager.opSetInput(op,input,slot);
  }
}

// wire() without the output placeholder: for preexisting ops (their real
// output is untouched, transform.hh:553-561) and for the output==nullptr
// createReplacement branch (transform.cc:241).
void wireInputs(TransformManager &manager,TransformOp *op,int4 inputs,int4 size,uintb valueBase)
{
  for(int4 slot=0;slot<inputs;++slot) {
    TransformVar *input = manager.newConstant(size,0,valueBase + slot);
    manager.opSetInput(op,input,slot);
  }
}

void runReplace(BfdArchitecture &architecture,const string &functionName,const string &label,OpCode opcode,int4 inputs)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x8000);
  TransformManager manager(fd);
  TransformOp *first = manager.newOpReplace(inputs,opcode,anchor);
  wire(manager,first,inputs,2,0x10);
  TransformOp *second = manager.newOpReplace(inputs,opcode,anchor);
  wire(manager,second,inputs,2,0x20);
  manager.apply();
  std::cout << label << "|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

void runFollow(BfdArchitecture &architecture,const string &functionName,const string &label,OpCode opcode,int4 inputs)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x9000);
  TransformManager manager(fd);
  TransformOp *follow = manager.newOpReplace(1,CPUI_COPY,anchor);
  wire(manager,follow,1,2,0x30);
  TransformOp *first = manager.newOp(inputs,opcode,follow);
  wire(manager,first,inputs,2,0x40);
  TransformOp *second = manager.newOp(inputs,opcode,follow);
  wire(manager,second,inputs,2,0x50);
  manager.apply();
  std::cout << label << "|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

// TransformOp::createReplacement op_preexisting arm (transform.cc:228-237):
// opcode retarget plus input shrink (3 -> 1), clear, and grow (1 -> 3) on two
// already-inserted ops; replacement identity is the original op and no
// insertion or opDestroy happens for them.
void runPreexisting(BfdArchitecture &architecture,const string &functionName)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x8000);
  PcodeOp *shrink = fd->newOp(3,Address(fd->getArch()->getDefaultCodeSpace(),0x8100));
  fd->opSetOpcode(shrink,CPUI_INT_AND);
  fd->opSetOutput(shrink,fd->newUniqueOut(4,shrink));
  for(int4 slot=0;slot<3;++slot)
    fd->opSetInput(shrink,fd->newConstant(4,0xa0+slot),slot);
  fd->opInsertEnd(shrink,block);
  PcodeOp *grow = fd->newOp(1,Address(fd->getArch()->getDefaultCodeSpace(),0x8200));
  fd->opSetOpcode(grow,CPUI_INT_OR);
  fd->opSetOutput(grow,fd->newUniqueOut(4,grow));
  fd->opSetInput(grow,fd->newConstant(4,0xb0),0);
  fd->opInsertEnd(grow,block);
  TransformManager manager(fd);
  TransformOp *shrinkOp = manager.newPreexistingOp(1,CPUI_INT_XOR,shrink);
  wireInputs(manager,shrinkOp,1,4,0x10);
  TransformOp *growOp = manager.newPreexistingOp(3,CPUI_INT_SUB,grow);
  wireInputs(manager,growOp,3,4,0x20);
  manager.apply();
  std::cout << "preexisting_ops|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

// Nested follow chain top -> mid -> follow (attemptInsertion,
// transform.cc:254-269): pass 2 inserts mid first (MULTIEQUAL at block begin)
// then top (COPY before mid), the deepest chain reachable through newOp.
void runNestedFollow(BfdArchitecture &architecture,const string &functionName)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x9000);
  TransformManager manager(fd);
  TransformOp *follow = manager.newOpReplace(1,CPUI_COPY,anchor);
  wire(manager,follow,1,2,0x30);
  TransformOp *mid = manager.newOp(2,CPUI_MULTIEQUAL,follow);
  wire(manager,mid,2,2,0x40);
  TransformOp *top = manager.newOp(1,CPUI_COPY,mid);
  wire(manager,top,1,2,0x50);
  manager.apply();
  std::cout << "nested_follow|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

// inheritIndirect (transform.cc:273-282) plus specialHandling ->
// markIndirectCreation (transform.cc:654-660, funcdata_op.cc:736-748): the
// preexisting INDIRECT is marked by the fixture, the placeholder inherits
// indirect_creation (zero input) or indirect_creation_possible_out, and the
// replacement op/output/input(0) flags are compared. The non-INDIRECT follow
// replacement also exercises opInsertBefore's preceding-INDIRECT skip
// (funcdata_op.cc:351-362).
void runIndirect(BfdArchitecture &architecture,const string &functionName,const string &label,bool possibleOutput)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *indOp = fd->newOp(2,Address(fd->getArch()->getDefaultCodeSpace(),0x9100));
  fd->opSetOpcode(indOp,CPUI_INDIRECT);
  fd->opSetOutput(indOp,fd->newUniqueOut(4,indOp));
  fd->opSetInput(indOp,fd->newConstant(4,0),0);
  fd->opSetInput(indOp,fd->newConstant(4,0x99),1);
  fd->opInsertEnd(indOp,block);
  fd->markIndirectCreation(indOp,possibleOutput);
  PcodeOp *anchor = newAnchor(fd,block,0x9000);
  TransformManager manager(fd);
  TransformOp *follow = manager.newOpReplace(1,CPUI_COPY,anchor);
  wire(manager,follow,1,2,0x30);
  TransformOp *newind = manager.newOp(2,CPUI_INDIRECT,follow);
  newind->inheritIndirect(indOp);
  wire(manager,newind,2,2,0x60);
  manager.apply();
  std::cout << label << "|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

// Ghidra reaches a misaligned TransformVar::piece only through a
// preserveAddress override (cf. SubfloatFlow::preserveAddress,
// subflow.cc:3451-3454); this subclass forces piece-hood so apply() throws
// LowlevelError("Varnode piece is not byte aligned") mid-createVarnodes and
// the pre-exception partial state (ops already created and inserted, output
// Varnodes materialized, no inputs placed, removeOld not run) is compared.
class MisalignManager : public TransformManager {
public:
  MisalignManager(Funcdata *fd) : TransformManager(fd) {}
  bool preserveAddress(Varnode *vn,int4 bitSize,int4 lsbOffset) const { return true; }
};

void runPieceError(BfdArchitecture &architecture,const string &functionName)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x8000);
  Varnode *big = fd->newVarnode(4,Address(fd->getArch()->getDefaultCodeSpace(),0x2000));
  string message;
  try {
    MisalignManager manager(fd);
    TransformOp *rep = manager.newOpReplace(2,CPUI_INT_ADD,anchor);
    wire(manager,rep,2,2,0x10);
    manager.newPiece(big,8,4);		// val=4 is not byte aligned
    manager.apply();
  }
  catch(const LowlevelError &error) {
    message = error.explain;
  }
  std::cout << "piece_error|msg=" << message << "|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

// createReplacement with output == nullptr (transform.cc:241-242): one
// zero-input COPY and one two-input MULTIEQUAL placeholder produce
// replacement ops with no output Varnode.
void runOutputNull(BfdArchitecture &architecture,const string &functionName)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x9000);
  TransformManager manager(fd);
  TransformOp *follow = manager.newOpReplace(1,CPUI_COPY,anchor);
  wire(manager,follow,1,2,0x30);
  TransformOp *bare = manager.newOp(0,CPUI_COPY,follow);
  TransformOp *barePhi = manager.newOp(2,CPUI_MULTIEQUAL,follow);
  wireInputs(manager,barePhi,2,2,0x70);
  manager.apply();
  std::cout << "output_null|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

// BlockBasic::insert SeqNum midpoint exhaustion (block.cc:2280-2283): 25
// MULTIEQUAL followers inserted at block begin halve the ordbefore=2 gap each
// time until ordafter-ordbefore <= 1, forcing BlockBasic::setOrder()
// (block.cc:2638-2651) to renumber the whole block.
void runSeqNum(BfdArchitecture &architecture,const string &functionName)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw std::runtime_error("function not found: " + functionName);
  BlockBasic *block = newBlock(fd);
  PcodeOp *anchor = newAnchor(fd,block,0x9000);
  TransformManager manager(fd);
  TransformOp *follow = manager.newOpReplace(1,CPUI_COPY,anchor);
  wire(manager,follow,1,2,0x30);
  for(int4 i=0;i<25;++i) {
    TransformOp *extra = manager.newOp(2,CPUI_MULTIEQUAL,follow);
    wire(manager,extra,2,2,0x100+i);
  }
  manager.apply();
  std::cout << "seqnum_renumber|after=" << snapshot(fd,block)
            << "|anchor=" << (anchor->isDead() ? 1 : 0)
            << ',' << (anchor->getParent() == (BlockBasic *)0 ? 1 : 0) << '\n';
}

void run(const string &specDirectory,const string &binary)
{
  vector<string> specPaths(1,specDirectory);
  startDecompilerLibrary(specPaths);
  {
    ostringstream messages;
    BfdArchitecture architecture(binary,"default",&messages);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    runReplace(architecture,"GetStr","replace_phi",CPUI_MULTIEQUAL,2);
    runFollow(architecture,"main_free","follow_phi",CPUI_MULTIEQUAL,2);
    runReplace(architecture,"hugehelp","replace_copy",CPUI_COPY,1);
    runFollow(architecture,"main_init","follow_copy",CPUI_COPY,1);
    runPreexisting(architecture,"my_fwrite");
    runNestedFollow(architecture,"myprogress");
    runIndirect(architecture,"my_get_token","indirect_zero",false);
    runIndirect(architecture,"my_get_line","indirect_possible",true);
    runPieceError(architecture,"helpf");
    runOutputNull(architecture,"glob_word");
    runSeqNum(architecture,"glob_set");
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: transform_multiequal_insert_1204 SPEC_ROOT CURL_BINARY\n";
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
