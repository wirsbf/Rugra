/*
 * Locked Ghidra 12.0.4 functionalEqualityLevel raw-output and
 * RulePushMulti unary-contingent caller fixture.
 *
 * Part A pre-fills both two-slot output arrays with semantic sentinels and
 * calls the production functionalEqualityLevel entry. Part B invokes the
 * production RulePushMulti::applyOp on the parseconfig failure shape and
 * serializes a declared target projection of the synthetic Funcdata IR before
 * and after the rule. Metadata records the state outside this projection.
 */

#include "bfd_arch.hh"
#include "expression.hh"
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

class EqualityCase {
  Funcdata &fd;
  map<Varnode *,string> names;
  uintb nextRegister;

  void remember(Varnode *vn,const string &name)
  {
    names[vn] = name;
  }

public:
  explicit EqualityCase(Funcdata &func) : fd(func), nextRegister(0x100) {}

  Varnode *input(const string &name,int4 size)
  {
    AddrSpace *space = fd.getArch()->getSpaceByName("register");
    if (space == (AddrSpace *)0)
      throw std::runtime_error("fixture requires register space");
    Varnode *vn = fd.setInputVarnode(fd.newVarnode(size,space,nextRegister));
    nextRegister += 0x10;
    remember(vn,name);
    return vn;
  }

  Varnode *freeVarnode(const string &name,int4 size)
  {
    AddrSpace *space = fd.getArch()->getSpaceByName("register");
    if (space == (AddrSpace *)0)
      throw std::runtime_error("fixture requires register space");
    Varnode *vn = fd.newVarnode(size,space,nextRegister);
    nextRegister += 0x10;
    remember(vn,name);
    return vn;
  }

  Varnode *constant(const string &name,int4 size,uintb value)
  {
    Varnode *vn = fd.newConstant(size,value);
    remember(vn,name);
    return vn;
  }

  Varnode *space(const string &name,AddrSpace *addressSpace)
  {
    Varnode *vn = fd.newVarnodeSpace(addressSpace);
    remember(vn,name);
    return vn;
  }

  Varnode *op(const string &name,OpCode opcode,const vector<Varnode *> &inputs,
      int4 outputSize=8,uintb address=0x1000)
  {
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *op = fd.newOp(inputs.size(),Address(codeSpace,address));
    fd.opSetOpcode(op,opcode);
    for(int4 i=0;i<(int4)inputs.size();++i)
      fd.opSetInput(op,inputs[i],i);
    Varnode *output = fd.newUniqueOut(outputSize,op);
    remember(output,name + "_out");
    return output;
  }

  string name(Varnode *vn) const
  {
    map<Varnode *,string>::const_iterator iter = names.find(vn);
    if (iter == names.end())
      throw std::runtime_error("unregistered equality varnode");
    return (*iter).second;
  }

  void observe(const string &caseName,Varnode *vn1,Varnode *vn2)
  {
    Varnode *sentinel10 = constant("sentinel10",8,0xf10);
    Varnode *sentinel11 = constant("sentinel11",8,0xf11);
    Varnode *sentinel20 = constant("sentinel20",8,0xf20);
    Varnode *sentinel21 = constant("sentinel21",8,0xf21);
    Varnode *res1[2] = { sentinel10, sentinel11 };
    Varnode *res2[2] = { sentinel20, sentinel21 };

    int4 code = functionalEqualityLevel(vn1,vn2,res1,res2);
    bool equal = functionalEquality(vn1,vn2);
    std::cout << "fel|case=" << caseName
              << "|code=" << code
              << "|equal=" << equal
              << "|written="
              << (res1[0] != sentinel10)
              << (res1[1] != sentinel11)
              << (res2[0] != sentinel20)
              << (res2[1] != sentinel21)
              << "|res1=[" << name(res1[0]) << ',' << name(res1[1]) << ']'
              << "|res2=[" << name(res2[0]) << ',' << name(res2[1]) << "]\n";
  }

  void observeAddExpression(const string &caseName,Varnode *vn1,Varnode *vn2)
  {
    AddExpression expr1;
    AddExpression expr2;
    expr1.gatherTwoTermsRoot(vn1);
    expr2.gatherTwoTermsRoot(vn2);
    std::cout << "addexpr|case=" << caseName
              << "|equivalent=" << expr1.isEquivalent(expr2) << "\n";
  }
};

void runEqualityCases(Funcdata &fd)
{
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *same = f.input("same",8);
    f.observe("early_same_pointer",same,same);
  }
  {
    fd.clear(); EqualityCase f(fd);
    f.observe("early_constants_equal",f.constant("left",8,7),f.constant("right",8,7));
  }
  {
    fd.clear(); EqualityCase f(fd);
    f.observe("early_constants_unequal",f.constant("left",8,7),f.constant("right",8,8));
  }
  {
    fd.clear(); EqualityCase f(fd);
    f.observe("early_size_mismatch",f.input("left",4),f.input("right",8));
  }
  {
    fd.clear(); EqualityCase f(fd);
    f.observe("early_free",f.freeVarnode("left",8),f.freeVarnode("right",8));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *left = f.input("left",4);
    Varnode *right = f.input("right",4);
    f.observe("guard_opcode",
        f.op("op1",CPUI_INT_ZEXT,vector<Varnode *>(1,left)),
        f.op("op2",CPUI_COPY,vector<Varnode *>(1,right)));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *a = f.input("a",8);
    Varnode *b = f.input("b",8);
    vector<Varnode *> one(1,a);
    vector<Varnode *> two; two.push_back(a); two.push_back(b);
    f.observe("guard_arity",f.op("op1",CPUI_INT_ADD,one),f.op("op2",CPUI_INT_ADD,two));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *a = f.input("a",8);
    Varnode *b = f.input("b",8);
    vector<Varnode *> one(1,a);
    vector<Varnode *> two(1,b);
    f.observe("guard_marker",f.op("op1",CPUI_MULTIEQUAL,one),f.op("op2",CPUI_MULTIEQUAL,two));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *a = f.constant("target1",8,0x1111);
    Varnode *b = f.constant("target2",8,0x2222);
    f.observe("guard_call",f.op("op1",CPUI_CALL,vector<Varnode *>(1,a)),
        f.op("op2",CPUI_CALL,vector<Varnode *>(1,b)));
  }
  {
    fd.clear(); EqualityCase f(fd);
    AddrSpace *ram = fd.getArch()->getDefaultDataSpace();
    Varnode *pointer = f.input("pointer",8);
    vector<Varnode *> leftInputs;
    leftInputs.push_back(f.space("left_space",ram)); leftInputs.push_back(pointer);
    vector<Varnode *> rightInputs;
    rightInputs.push_back(f.space("right_space",ram)); rightInputs.push_back(pointer);
    f.observe("guard_load_address",f.op("op1",CPUI_LOAD,leftInputs,8,0x1000),
        f.op("op2",CPUI_LOAD,rightInputs,8,0x1001));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *base = f.input("base",8);
    Varnode *index = f.input("index",8);
    vector<Varnode *> left;
    left.push_back(base); left.push_back(index); left.push_back(f.constant("elsize1",8,4));
    vector<Varnode *> right;
    right.push_back(base); right.push_back(index); right.push_back(f.constant("elsize2",8,8));
    f.observe("guard_ptradd_slot2",f.op("op1",CPUI_PTRADD,left),f.op("op2",CPUI_PTRADD,right));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *shared = f.input("shared",4);
    f.observe("unary_exact",f.op("op1",CPUI_INT_ZEXT,vector<Varnode *>(1,shared)),
        f.op("op2",CPUI_INT_ZEXT,vector<Varnode *>(1,shared)));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *left = f.input("left",4);
    Varnode *right = f.input("right",4);
    f.observe("unary_contingent",f.op("op1",CPUI_INT_ZEXT,vector<Varnode *>(1,left)),
        f.op("op2",CPUI_INT_ZEXT,vector<Varnode *>(1,right)));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *shared = f.input("shared",4);
    Varnode *left = f.op("op1",CPUI_INT_ZEXT,vector<Varnode *>(1,shared));
    Varnode *right = f.op("op2",CPUI_INT_ZEXT,vector<Varnode *>(1,shared));
    f.observeAddExpression("unary_structural_equal",left,right);
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *shared0 = f.input("shared0",8);
    Varnode *shared1 = f.input("shared1",8);
    vector<Varnode *> both; both.push_back(shared0); both.push_back(shared1);
    f.observe("binary_exact",f.op("op1",CPUI_INT_SUB,both),f.op("op2",CPUI_INT_SUB,both));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *shared = f.input("shared",8);
    Varnode *left = f.input("left",8);
    Varnode *right = f.input("right",8);
    vector<Varnode *> a; a.push_back(shared); a.push_back(left);
    vector<Varnode *> b; b.push_back(shared); b.push_back(right);
    f.observe("binary_slot0_exact_slot1_contingent",f.op("op1",CPUI_INT_SUB,a),f.op("op2",CPUI_INT_SUB,b));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *shared = f.input("shared",8);
    vector<Varnode *> a; a.push_back(shared); a.push_back(f.constant("left_const",8,1));
    vector<Varnode *> b; b.push_back(shared); b.push_back(f.constant("right_const",8,2));
    f.observe("binary_slot0_exact_slot1_impossible",f.op("op1",CPUI_INT_SUB,a),f.op("op2",CPUI_INT_SUB,b));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *left = f.input("left",8);
    Varnode *right = f.input("right",8);
    Varnode *shared = f.input("shared",8);
    vector<Varnode *> a; a.push_back(left); a.push_back(shared);
    vector<Varnode *> b; b.push_back(right); b.push_back(shared);
    f.observe("binary_slot0_contingent_slot1_exact",f.op("op1",CPUI_INT_SUB,a),f.op("op2",CPUI_INT_SUB,b));
  }
  {
    fd.clear(); EqualityCase f(fd);
    vector<Varnode *> a; a.push_back(f.input("a",8)); a.push_back(f.input("b",8));
    vector<Varnode *> b; b.push_back(f.input("c",8)); b.push_back(f.input("d",8));
    f.observe("noncomm_both_contingent",f.op("op1",CPUI_INT_SUB,a),f.op("op2",CPUI_INT_SUB,b));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *a = f.input("a",8); Varnode *b = f.input("b",8);
    vector<Varnode *> left; left.push_back(a); left.push_back(b);
    vector<Varnode *> right; right.push_back(b); right.push_back(a);
    f.observe("comm_cross_exact",f.op("op1",CPUI_INT_ADD,left),f.op("op2",CPUI_INT_ADD,right));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *a = f.input("a",8); Varnode *b = f.input("b",8); Varnode *c = f.input("c",8);
    vector<Varnode *> left; left.push_back(a); left.push_back(b);
    vector<Varnode *> right; right.push_back(c); right.push_back(a);
    f.observe("comm1_exact",f.op("op1",CPUI_INT_ADD,left),f.op("op2",CPUI_INT_ADD,right));
  }
  {
    fd.clear(); EqualityCase f(fd);
    Varnode *a = f.input("a",8); Varnode *b = f.input("b",8); Varnode *c = f.input("c",8);
    vector<Varnode *> left; left.push_back(a); left.push_back(b);
    vector<Varnode *> right; right.push_back(b); right.push_back(c);
    f.observe("comm2_exact",f.op("op1",CPUI_INT_ADD,left),f.op("op2",CPUI_INT_ADD,right));
  }
  {
    fd.clear(); EqualityCase f(fd);
    vector<Varnode *> left; left.push_back(f.input("a",8)); left.push_back(f.input("b",8));
    vector<Varnode *> right; right.push_back(f.input("c",8)); right.push_back(f.input("d",8));
    f.observe("comm_original_preferred",f.op("op1",CPUI_INT_ADD,left),f.op("op2",CPUI_INT_ADD,right));
  }
  {
    fd.clear(); EqualityCase f(fd);
    vector<Varnode *> left; left.push_back(f.input("a4",4)); left.push_back(f.input("b8",8));
    vector<Varnode *> right; right.push_back(f.input("c4",4)); right.push_back(f.input("d8",8));
    f.observe("comm_cross_impossible_original_valid",f.op("op1",CPUI_INT_ADD,left),f.op("op2",CPUI_INT_ADD,right));
  }
  {
    fd.clear(); EqualityCase f(fd);
    vector<Varnode *> left; left.push_back(f.input("a4",4)); left.push_back(f.input("b8",8));
    vector<Varnode *> right; right.push_back(f.input("c8",8)); right.push_back(f.input("d4",4));
    f.observe("comm_final_res2_swap",f.op("op1",CPUI_INT_ADD,left),f.op("op2",CPUI_INT_ADD,right));
  }
}

class RuleFixture {
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

  set<Varnode *> discover(void)
  {
    for(PcodeOpTree::const_iterator iter=fd.beginOpAll();iter!=fd.endOpAll();++iter) {
      PcodeOp *op = (*iter).second;
      if (opNames.find(op) == opNames.end()) {
        ostringstream name; name << 'n' << nextOp++;
        rememberOp(op,name.str());
      }
    }
    set<Varnode *> live;
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter) {
      Varnode *vn = *iter;
      live.insert(vn);
      if (varnodeNames.find(vn) == varnodeNames.end()) {
        ostringstream name; name << 'g' << nextVarnode++;
        rememberVarnode(vn,name.str());
      }
    }
    return live;
  }

  string opList(list<PcodeOp *>::const_iterator iter,list<PcodeOp *>::const_iterator end) const
  {
    ostringstream out;
    for(bool first=true;iter!=end;++iter) {
      if (!first) out << ',';
      first = false;
      out << opName(*iter);
    }
    return out.str();
  }

  int4 descendantSlot(Varnode *vn,PcodeOp *op,int4 occurrence) const
  {
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (op->getIn(slot) != vn) continue;
      if (occurrence == 0) return slot;
      occurrence -= 1;
    }
    throw std::runtime_error("descendant slot is absent");
  }

public:
  explicit RuleFixture(Funcdata &func)
    : fd(func), nextOp(0), nextVarnode(0) {}

  string blockName(BlockBasic *block) const
  {
    if (block == (BlockBasic *)0) return "-";
    map<BlockBasic *,string>::const_iterator iter = blockNames.find(block);
    if (iter == blockNames.end()) throw std::runtime_error("unregistered block");
    return (*iter).second;
  }

  string opName(PcodeOp *op) const
  {
    if (op == (PcodeOp *)0) return "-";
    map<PcodeOp *,string>::const_iterator iter = opNames.find(op);
    if (iter == opNames.end()) throw std::runtime_error("unregistered op");
    return (*iter).second;
  }

  string varnodeName(Varnode *vn) const
  {
    if (vn == (Varnode *)0) return "-";
    map<Varnode *,string>::const_iterator iter = varnodeNames.find(vn);
    if (iter == varnodeNames.end()) throw std::runtime_error("unregistered varnode");
    return (*iter).second;
  }

  BlockBasic *block(const string &name)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *result = graph.newBlockBasic(&fd);
    blocks.push_back(result); blockNames[result] = name;
    return result;
  }

  void edge(BlockBasic *from,BlockBasic *to)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    graph.addEdge(from,to);
  }

  Varnode *input(const string &name,int4 size,uintb offset)
  {
    AddrSpace *space = fd.getArch()->getSpaceByName("register");
    Varnode *vn = fd.setInputVarnode(fd.newVarnode(size,space,offset));
    rememberVarnode(vn,name); return vn;
  }

  PcodeOp *op(const string &name,OpCode opcode,int4 inputCount,int4 outputSize,uintb address)
  {
    AddrSpace *codeSpace = fd.getArch()->getDefaultCodeSpace();
    PcodeOp *result = fd.newOp(inputCount,Address(codeSpace,address));
    fd.opSetOpcode(result,opcode); rememberOp(result,name);
    Varnode *output = fd.newUniqueOut(outputSize,result);
    rememberVarnode(output,name + "_out");
    return result;
  }

  void setInput(PcodeOp *op,Varnode *vn,int4 slot) { fd.opSetInput(op,vn,slot); }
  void insertEnd(PcodeOp *op,BlockBasic *block) { fd.opInsertEnd(op,block); }

  string opState(PcodeOp *op) const
  {
    ostringstream out;
    out << opName(op) << "{opc=" << static_cast<int4>(op->code())
        << ",dead=" << op->isDead()
        << ",marker=" << op->isMarker()
        << ",commutative=" << op->isCommutative()
        << ",modified=" << op->isModified()
        << ",parent=" << blockName(op->getParent())
        << ",addr=" << std::hex << op->getAddr().getOffset() << std::dec
        << ",time=" << op->getSeqNum().getTime() << ",order=" << op->getSeqNum().getOrder()
        << ",inputs=[";
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (slot != 0) out << ',';
      out << varnodeName(op->getIn(slot));
    }
    out << "],output=" << varnodeName(op->getOut()) << '}';
    return out.str();
  }

  string varnodeState(Varnode *vn,const set<Varnode *> &live) const
  {
    ostringstream out;
    out << varnodeName(vn) << "{present=";
    if (live.find(vn) == live.end()) { out << "0}"; return out.str(); }
    out << "1,space=" << vn->getSpace()->getName()
        << ",size=" << vn->getSize() << ",offset=" << std::hex << vn->getOffset() << std::dec
        << ",create=" << vn->getCreateIndex() << ",flags=" << std::hex << vn->getFlags() << std::dec
        << ",consume=" << std::hex << vn->getConsume() << ",nzm=" << vn->getNZMask() << std::dec
        << ",def=" << opName(vn->getDef()) << ",desc=[";
    map<PcodeOp *,int4> occurrences;
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      if (!first) out << ',';
      first = false;
      PcodeOp *descendant = *iter;
      out << opName(descendant) << '.' << descendantSlot(vn,descendant,occurrences[descendant]++);
    }
    out << "]}";
    return out.str();
  }

  void dump(const string &stage,const string &result)
  {
    set<Varnode *> live = discover();
    ostringstream blockState;
    for(vector<BlockBasic *>::const_iterator iter=blocks.begin();iter!=blocks.end();++iter) {
      if (iter != blocks.begin()) blockState << ';';
      BlockBasic *bb = *iter;
      blockState << blockName(bb) << "{index=" << bb->getIndex() << ",in=[";
      for(int4 i=0;i<bb->sizeIn();++i) { if (i) blockState << ','; blockState << blockName((BlockBasic *)bb->getIn(i)); }
      blockState << "],out=[";
      for(int4 i=0;i<bb->sizeOut();++i) { if (i) blockState << ','; blockState << blockName((BlockBasic *)bb->getOut(i)); }
      blockState << "],ops=[" << opList(bb->beginOp(),bb->endOp()) << "]}";
    }
    ostringstream opStates;
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      if (iter != ops.begin()) opStates << ';';
      opStates << opState(*iter);
    }
    ostringstream vnStates;
    for(vector<Varnode *>::const_iterator iter=varnodes.begin();iter!=varnodes.end();++iter) {
      if (iter != varnodes.begin()) vnStates << ';';
      vnStates << varnodeState(*iter,live);
    }
    ostringstream all;
    for(PcodeOpTree::const_iterator iter=fd.beginOpAll();iter!=fd.endOpAll();++iter) {
      if (iter != fd.beginOpAll()) all << ',';
      all << opName((*iter).second);
    }
    ostringstream loc;
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter) {
      if (iter != fd.beginLoc()) loc << ',';
      loc << varnodeName(*iter);
    }
    ostringstream def;
    for(VarnodeDefSet::const_iterator iter=fd.beginDef();iter!=fd.endDef();++iter) {
      if (iter != fd.beginDef()) def << ',';
      def << varnodeName(*iter);
    }
    std::cout << "rule|case=parseconfig_unary_zext|stage=" << stage << "|result=" << result
              << "|blocks=[" << blockState.str() << "]|all=[" << all.str() << ']'
              << "|alive=[" << opList(fd.beginOpAlive(),fd.endOpAlive()) << ']'
              << "|dead=[" << opList(fd.beginOpDead(),fd.endOpDead()) << ']'
              << "|ops=[" << opStates.str() << "]|vloc=[" << loc.str() << ']'
              << "|vdef=[" << def.str() << "]|varnodes=[" << vnStates.str() << "]\n";
  }
};

void runRuleCaller(Funcdata &fd)
{
  fd.clear();
  RuleFixture f(fd);
  BlockBasic *left = f.block("b0");
  BlockBasic *right = f.block("b1");
  BlockBasic *merge = f.block("b2");
  f.edge(left,merge); f.edge(right,merge);
  Varnode *leftInput = f.input("left_input",4,0x40);
  Varnode *rightInput = f.input("right_input",4,0x50);
  PcodeOp *leftZext = f.op("left_zext",CPUI_INT_ZEXT,1,8,0x3d99);
  PcodeOp *rightZext = f.op("right_zext",CPUI_INT_ZEXT,1,8,0x3e1f);
  PcodeOp *root = f.op("root",CPUI_MULTIEQUAL,2,8,0x3da0);
  PcodeOp *use = f.op("use",CPUI_COPY,1,8,0x3da1);
  f.setInput(leftZext,leftInput,0); f.setInput(rightZext,rightInput,0);
  f.setInput(root,leftZext->getOut(),0); f.setInput(root,rightZext->getOut(),1);
  f.setInput(use,root->getOut(),0);
  f.insertEnd(leftZext,left); f.insertEnd(rightZext,right);
  f.insertEnd(root,merge); f.insertEnd(use,merge);
  f.dump("before","na");
  RulePushMulti rule("analysis");
  int4 result = rule.applyOp(root,fd);
  f.dump("after",std::to_string(result));
}

void run(const string &specDirectory,const string &binary)
{
  vector<string> specPaths; specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0) throw std::runtime_error("GetStr not found");
    runEqualityCases(*fd);
    runRuleCaller(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: functional_equality_level_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try { run(argv[1],argv[2]); return 0; }
  catch(const ghidra::LowlevelError &error) { std::cerr << "Ghidra LowlevelError: " << error.explain << '\n'; }
  catch(const ghidra::DecoderError &error) { std::cerr << "Ghidra DecoderError: " << error.explain << '\n'; }
  catch(const std::exception &error) { std::cerr << "fixture error: " << error.what() << '\n'; }
  return 1;
}
