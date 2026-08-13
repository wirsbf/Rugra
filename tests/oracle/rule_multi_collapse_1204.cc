/*
 * Locked Ghidra 12.0.4 RuleMultiCollapse::applyOp full-state oracle.
 *
 * Pointer values are used only as in-process identity keys.  Every fixture
 * object has a semantic identity and every unexpected bank object receives a
 * deterministic discovery identity.  No address, SeqNum, storage offset,
 * flag, bank order, block order, alias, def-use edge, or mark is normalized.
 *
 * Funcdata::opDestroy deletes an output Varnode.  Consequently the snapshot
 * first enumerates the live VarnodeBank and prints removed semantic identities
 * as present=0 without dereferencing their stale fixture pointers.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

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

class Fixture {
  Funcdata &fd;
  vector<BlockBasic *> blocks;
  map<BlockBasic *,string> blockNames;
  vector<PcodeOp *> ops;
  map<PcodeOp *,string> opNames;
  vector<Varnode *> varnodes;
  map<Varnode *,string> varnodeNames;
  int4 nextOp;
  int4 nextVarnode;

  void rememberOp(PcodeOp *op,const string &name)
  {
    if (opNames.insert(std::make_pair(op,name)).second)
      ops.push_back(op);
  }

  void rememberVarnode(Varnode *vn,const string &name)
  {
    if (varnodeNames.insert(std::make_pair(vn,name)).second)
      varnodes.push_back(vn);
  }

  string blockName(BlockBasic *block) const
  {
    if (block == (BlockBasic *)0)
      return "-";
    map<BlockBasic *,string>::const_iterator iter = blockNames.find(block);
    if (iter == blockNames.end())
      throw std::runtime_error("unregistered fixture block");
    return (*iter).second;
  }

  string opName(PcodeOp *op) const
  {
    if (op == (PcodeOp *)0)
      return "-";
    map<PcodeOp *,string>::const_iterator iter = opNames.find(op);
    if (iter == opNames.end())
      throw std::runtime_error("unregistered fixture op");
    return (*iter).second;
  }

  string varnodeName(Varnode *vn) const
  {
    if (vn == (Varnode *)0)
      return "-";
    map<Varnode *,string>::const_iterator iter = varnodeNames.find(vn);
    if (iter == varnodeNames.end())
      throw std::runtime_error("unregistered fixture varnode");
    return (*iter).second;
  }

  set<Varnode *> discover(void)
  {
    for(PcodeOpTree::const_iterator iter=fd.beginOpAll();
        iter!=fd.endOpAll();++iter) {
      PcodeOp *op = (*iter).second;
      if (opNames.find(op) == opNames.end()) {
        ostringstream name;
        name << 'n' << nextOp++;
        rememberOp(op,name.str());
      }
    }

    set<Varnode *> live;
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();
        iter!=fd.endLoc();++iter) {
      Varnode *vn = *iter;
      live.insert(vn);
      if (varnodeNames.find(vn) == varnodeNames.end()) {
        ostringstream name;
        name << 'g' << nextVarnode++;
        rememberVarnode(vn,name.str());
      }
    }
    return live;
  }

  template<typename Iterator>
  string opList(Iterator iter,Iterator enditer) const
  {
    ostringstream out;
    bool first = true;
    for(;iter!=enditer;++iter) {
      PcodeOp *op = *iter;
      if (!first) out << ',';
      first = false;
      out << opName(op);
    }
    return out.str();
  }

  string allOpList(void) const
  {
    ostringstream out;
    bool first = true;
    for(PcodeOpTree::const_iterator iter=fd.beginOpAll();
        iter!=fd.endOpAll();++iter) {
      if (!first) out << ',';
      first = false;
      out << opName((*iter).second);
    }
    return out.str();
  }

  string blockStates(void) const
  {
    ostringstream out;
    for(vector<BlockBasic *>::const_iterator iter=blocks.begin();
        iter!=blocks.end();++iter) {
      if (iter != blocks.begin()) out << ';';
      BlockBasic *block = *iter;
      out << blockName(block) << "{index=" << block->getIndex()
          << ",in=[";
      for(int4 slot=0;slot<block->sizeIn();++slot) {
        if (slot != 0) out << ',';
        out << blockName((BlockBasic *)block->getIn(slot));
      }
      out << "],out=[";
      for(int4 slot=0;slot<block->sizeOut();++slot) {
        if (slot != 0) out << ',';
        out << blockName((BlockBasic *)block->getOut(slot));
      }
      out << "],ops=[" << opList(block->beginOp(),block->endOp()) << "]}";
    }
    return out.str();
  }

  string opState(PcodeOp *op) const
  {
    ostringstream out;
    out << opName(op)
        << "{opc=" << static_cast<int4>(op->code())
        << ",dead=" << op->isDead()
        << ",mark=" << op->isMark()
        << ",marker=" << op->isMarker()
        << ",commutative=" << op->isCommutative()
        << ",modified=" << op->isModified()
        << ",parent=" << blockName(op->getParent())
        << ",addr=" << std::hex << op->getAddr().getOffset() << std::dec
        << ",time=" << op->getSeqNum().getTime()
        << ",order=" << op->getSeqNum().getOrder()
        << ",inputs=[";
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (slot != 0) out << ',';
      out << varnodeName(op->getIn(slot));
    }
    out << "],output=" << varnodeName(op->getOut()) << '}';
    return out.str();
  }

  int4 descendantSlot(Varnode *vn,PcodeOp *op,int4 occurrence) const
  {
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (op->getIn(slot) != vn)
        continue;
      if (occurrence == 0)
        return slot;
      occurrence -= 1;
    }
    throw std::runtime_error("descendant has no matching occurrence slot");
  }

  string varnodeState(Varnode *vn,const set<Varnode *> &live) const
  {
    ostringstream out;
    out << varnodeName(vn) << "{present=";
    if (live.find(vn) == live.end()) {
      out << "0}";
      return out.str();
    }

    bool loadSpace = false;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();
        iter!=vn->endDescend();++iter) {
      PcodeOp *descendant = *iter;
      if (descendant->code() == CPUI_LOAD && descendant->getIn(0) == vn) {
        loadSpace = true;
        break;
      }
    }
    out << "1,space=" << vn->getSpace()->getName()
        << ",size=" << vn->getSize()
        << ",offset=";
    if (loadSpace)
      out << "spaceid:" << vn->getSpaceFromConst()->getName();
    else
      out << std::hex << vn->getOffset() << std::dec;
    out
        << ",create=" << vn->getCreateIndex()
        << ",flags=" << std::hex << vn->getFlags() << std::dec
        << ",mark=" << vn->isMark()
        << ",constant=" << vn->isConstant()
        << ",input=" << vn->isInput()
        << ",written=" << vn->isWritten()
        << ",free=" << vn->isFree()
        << ",heritage=" << vn->isHeritageKnown()
        << ",def=" << opName(vn->getDef())
        << ",desc=[";
    map<PcodeOp *,int4> occurrences;
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();
        iter!=vn->endDescend();++iter) {
      PcodeOp *descendant = *iter;
      int4 occurrence = occurrences[descendant]++;
      if (!first) out << ',';
      first = false;
      out << opName(descendant) << '.'
          << descendantSlot(vn,descendant,occurrence);
    }
    out << "]}";
    return out.str();
  }

  string varnodeLocList(void) const
  {
    ostringstream out;
    bool first = true;
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();
        iter!=fd.endLoc();++iter) {
      if (!first) out << ',';
      first = false;
      out << varnodeName(*iter);
    }
    return out.str();
  }

  string varnodeDefList(void) const
  {
    ostringstream out;
    bool first = true;
    for(VarnodeDefSet::const_iterator iter=fd.beginDef();
        iter!=fd.endDef();++iter) {
      if (!first) out << ',';
      first = false;
      out << varnodeName(*iter);
    }
    return out.str();
  }

public:
  explicit Fixture(Funcdata &func)
    : fd(func), nextOp(0), nextVarnode(0)
  {
  }

  BlockBasic *makeBlock(const string &name)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);
    blocks.push_back(block);
    blockNames.insert(std::make_pair(block,name));
    return block;
  }

  Varnode *makeInput(const string &name,int4 size,uintb offset)
  {
    AddrSpace *registerSpace = fd.getArch()->getSpaceByName("register");
    if (registerSpace == (AddrSpace *)0)
      throw std::runtime_error("fixture requires the register space");
    Varnode *vn = fd.setInputVarnode(fd.newVarnode(size,registerSpace,offset));
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

  void addEdge(BlockBasic *from,BlockBasic *to)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    graph.addEdge(from,to);
  }

  PcodeOp *makeOp(const string &name,OpCode opcode,int4 inputs,int4 outputSize)
  {
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(inputs,Address(codeSpace,0x1000));
    fd.opSetOpcode(op,opcode);
    rememberOp(op,name);
    Varnode *outvn = fd.newUniqueOut(outputSize,op);
    rememberVarnode(outvn,name + "_out");
    return op;
  }

  void setInput(PcodeOp *op,Varnode *vn,int4 slot)
  {
    fd.opSetInput(op,vn,slot);
  }

  void insertEnd(PcodeOp *op,BlockBasic *block)
  {
    fd.opInsertEnd(op,block);
  }

  void dump(const string &caseName,const string &stage,const string &result)
  {
    set<Varnode *> live = discover();

    ostringstream opStates;
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      if (iter != ops.begin()) opStates << ';';
      opStates << opState(*iter);
    }

    ostringstream varnodeStates;
    for(vector<Varnode *>::const_iterator iter=varnodes.begin();
        iter!=varnodes.end();++iter) {
      if (iter != varnodes.begin()) varnodeStates << ';';
      varnodeStates << varnodeState(*iter,live);
    }

    std::cout << "case=" << caseName
              << "|stage=" << stage
              << "|result=" << result
              << "|blocks=[" << blockStates() << ']'
              << "|all=[" << allOpList() << ']'
              << "|alive=[" << opList(fd.beginOpAlive(),fd.endOpAlive()) << ']'
              << "|dead=[" << opList(fd.beginOpDead(),fd.endOpDead()) << ']'
              << "|loads=[" << opList(fd.beginOp(CPUI_LOAD),fd.endOp(CPUI_LOAD)) << ']'
              << "|stores=[" << opList(fd.beginOp(CPUI_STORE),fd.endOp(CPUI_STORE)) << ']'
              << "|returns=[" << opList(fd.beginOp(CPUI_RETURN),fd.endOp(CPUI_RETURN)) << ']'
              << "|userops=[" << opList(fd.beginOp(CPUI_CALLOTHER),fd.endOp(CPUI_CALLOTHER)) << ']'
              << "|ops=[" << opStates.str() << ']'
              << "|vloc=[" << varnodeLocList() << ']'
              << "|vdef=[" << varnodeDefList() << ']'
              << "|varnodes=[" << varnodeStates.str() << "]\n";
  }
};

void applyAndDump(Fixture &fixture,Funcdata &fd,const string &name,PcodeOp *root)
{
  fixture.dump(name,"before","na");
  RuleMultiCollapse rule("analysis");
  int4 result = rule.applyOp(root,fd);
  fixture.dump(name,"after",std::to_string(result));
}

void runAbsoluteRoot(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  BlockBasic *block = fixture.makeBlock("b0");
  Varnode *x = fixture.makeInput("x",8,0x40);
  PcodeOp *root = fixture.makeOp("root",CPUI_MULTIEQUAL,2,8);
  PcodeOp *use = fixture.makeOp("use",CPUI_COPY,1,8);
  fixture.setInput(root,x,0);
  fixture.setInput(root,x,1);
  fixture.setInput(use,root->getOut(),0);
  fixture.insertEnd(root,block);
  fixture.insertEnd(use,block);
  applyAndDump(fixture,fd,"absolute_root_skiplist_1",root);
}

void runLoopSelfReference(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  BlockBasic *block = fixture.makeBlock("b0");
  Varnode *x = fixture.makeInput("x",8,0x40);
  PcodeOp *root = fixture.makeOp("root",CPUI_MULTIEQUAL,3,8);
  PcodeOp *use = fixture.makeOp("use",CPUI_COPY,1,8);
  fixture.setInput(root,x,0);
  fixture.setInput(root,root->getOut(),1);
  fixture.setInput(root,x,2);
  fixture.setInput(use,root->getOut(),0);
  fixture.insertEnd(root,block);
  fixture.insertEnd(use,block);
  applyAndDump(fixture,fd,"loop_self_reference_mark_clear",root);
}

void runNestedSkiplist(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  BlockBasic *block = fixture.makeBlock("b0");
  Varnode *x = fixture.makeInput("x",8,0x40);
  PcodeOp *nested = fixture.makeOp("nested",CPUI_MULTIEQUAL,2,8);
  PcodeOp *root = fixture.makeOp("root",CPUI_MULTIEQUAL,2,8);
  PcodeOp *nestedUse = fixture.makeOp("nested_use",CPUI_COPY,1,8);
  PcodeOp *rootUse = fixture.makeOp("root_use",CPUI_COPY,1,8);
  fixture.setInput(nested,x,0);
  fixture.setInput(nested,x,1);
  fixture.setInput(root,nested->getOut(),0);
  fixture.setInput(root,x,1);
  fixture.setInput(nestedUse,nested->getOut(),0);
  fixture.setInput(rootUse,root->getOut(),0);
  fixture.insertEnd(nested,block);
  fixture.insertEnd(root,block);
  fixture.insertEnd(nestedUse,block);
  fixture.insertEnd(rootUse,block);
  applyAndDump(fixture,fd,"nested_skiplist",root);
}

void runFunctionalCse(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  BlockBasic *left = fixture.makeBlock("b0");
  BlockBasic *right = fixture.makeBlock("b1");
  BlockBasic *merge = fixture.makeBlock("b2");
  fixture.addEdge(left,merge);
  fixture.addEdge(right,merge);
  Varnode *x = fixture.makeInput("x",8,0x40);
  Varnode *leftConstant = fixture.makeConstant("left_const",8,5);
  Varnode *rightConstant = fixture.makeConstant("right_const",8,5);
  Varnode *cseConstant = fixture.makeConstant("cse_const",8,5);
  PcodeOp *leftAdd = fixture.makeOp("left_add",CPUI_INT_ADD,2,8);
  PcodeOp *rightAdd = fixture.makeOp("right_add",CPUI_INT_ADD,2,8);
  PcodeOp *root = fixture.makeOp("root",CPUI_MULTIEQUAL,2,8);
  PcodeOp *cse = fixture.makeOp("cse",CPUI_INT_ADD,2,8);
  PcodeOp *use = fixture.makeOp("use",CPUI_COPY,1,8);
  fixture.setInput(leftAdd,x,0);
  fixture.setInput(leftAdd,leftConstant,1);
  fixture.setInput(rightAdd,x,0);
  fixture.setInput(rightAdd,rightConstant,1);
  fixture.setInput(root,leftAdd->getOut(),0);
  fixture.setInput(root,rightAdd->getOut(),1);
  fixture.setInput(cse,x,0);
  fixture.setInput(cse,cseConstant,1);
  fixture.setInput(use,root->getOut(),0);
  fixture.insertEnd(leftAdd,left);
  fixture.insertEnd(rightAdd,right);
  fixture.insertEnd(root,merge);
  fixture.insertEnd(cse,merge);
  fixture.insertEnd(use,merge);
  applyAndDump(fixture,fd,"functional_existing_cse",root);
}

void runFunctionalRewrite(Funcdata &fd)
{
  fd.clear();
  Fixture fixture(fd);
  BlockBasic *left = fixture.makeBlock("b0");
  BlockBasic *right = fixture.makeBlock("b1");
  BlockBasic *merge = fixture.makeBlock("b2");
  fixture.addEdge(left,merge);
  fixture.addEdge(right,merge);
  Varnode *pointer = fixture.makeInput("pointer",8,0x40);
  Varnode *guard = fixture.makeInput("guard",8,0x50);
  AddrSpace *ram = fd.getArch()->getDefaultDataSpace();
  Varnode *leftSpace = fixture.makeSpace("left_space",ram);
  Varnode *rightSpace = fixture.makeSpace("right_space",ram);
  PcodeOp *leftLoad = fixture.makeOp("left_load",CPUI_LOAD,2,8);
  PcodeOp *rightLoad = fixture.makeOp("right_load",CPUI_LOAD,2,8);
  PcodeOp *root = fixture.makeOp("root",CPUI_MULTIEQUAL,2,8);
  PcodeOp *anchor = fixture.makeOp("anchor",CPUI_MULTIEQUAL,2,8);
  PcodeOp *use = fixture.makeOp("use",CPUI_COPY,1,8);
  fixture.setInput(leftLoad,leftSpace,0);
  fixture.setInput(leftLoad,pointer,1);
  fixture.setInput(rightLoad,rightSpace,0);
  fixture.setInput(rightLoad,pointer,1);
  fixture.setInput(root,leftLoad->getOut(),0);
  fixture.setInput(root,rightLoad->getOut(),1);
  fixture.setInput(anchor,guard,0);
  fixture.setInput(anchor,guard,1);
  fixture.setInput(use,root->getOut(),0);
  fixture.insertEnd(leftLoad,left);
  fixture.insertEnd(rightLoad,right);
  fixture.insertEnd(root,merge);
  fixture.insertEnd(anchor,merge);
  fixture.insertEnd(use,merge);
  applyAndDump(fixture,fd,"functional_load_no_cse_rewrite_reinsert",root);
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
    if (fd == (Funcdata *)0)
      throw std::runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->getName() != "GetStr" ||
        fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
      throw std::runtime_error("GetStr input identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " +
                               architecture.archid);

    runAbsoluteRoot(*fd);
    runLoopSelfReference(*fd);
    runNestedSkiplist(*fd);
    runFunctionalCse(*fd);
    runFunctionalRewrite(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: rule_multi_collapse_1204 SPEC_ROOT CURL_BINARY\n";
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
