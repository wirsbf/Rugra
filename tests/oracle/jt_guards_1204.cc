/* JT-GUARDS-1204 (JUMPTABLE-GUARDS-0001): locked Ghidra 12.0.4 fixture.
 *
 * Observes JumpBasic::analyzeGuards (jumptable.cc:1046-1112),
 * JumpBasic::checkUnrolledGuard (jumptable.cc:1338-1370) via the
 * sizeIn>1 walk-back path, GuardRecord::valueMatch
 * (jumptable.cc:637-680) and GuardRecord::quasiCopy
 * (jumptable.cc:719-786) on synthetic guard CFGs built inside a
 * vehicle Funcdata loaded from the pinned curl binary.
 *
 * GuardRecord's vn/baseVn/bitsPreserved fields are private, so the
 * record-level observation uses only the public accessors
 * (getBranch/getReadOp/getPath/getRange/isUnrolled) plus valueMatch
 * probes against fixture varnodes, and quasiCopy is observed directly
 * through its public static entry.
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "jumptable.hh"

#include <iostream>
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

class TestableJumpBasic : public JumpBasic {
public:
  TestableJumpBasic(JumpTable *jt) : JumpBasic(jt) {}
  using JumpBasic::analyzeGuards;
  vector<GuardRecord> &guards(void) { return selectguards; }
};

struct Lab {
  Funcdata *fd;
  AddrSpace *code;
  map<const BlockBasic *, string> blockName;
  map<const Varnode *, string> varName;
  map<const PcodeOp *, string> opName;
  int seq;

  Lab(Funcdata *f) : fd(f), code(f->getArch()->getDefaultCodeSpace()), seq(0) {}

  BlockBasic *blk(const string &name)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    BlockBasic *b = graph.newBlockBasic(fd);
    blockName[b] = name;
    return b;
  }
  Varnode *var(const string &name,int4 size)
  {
    Varnode *vn = fd->newUnique(size);
    varName[vn] = name;
    return vn;
  }
  Varnode *cnst(const string &name,int4 size,uintb val)
  {
    Varnode *vn = fd->newConstant(size,val);
    varName[vn] = name;
    return vn;
  }
  Varnode *coderef(const string &name,uintb off)
  {
    Varnode *vn = fd->newCodeRef(Address(code,off));
    varName[vn] = name;
    return vn;
  }
  PcodeOp *op(const string &name,BlockBasic *block,OpCode opc,int4 inputs)
  {
    PcodeOp *o = fd->newOp(inputs,Address(code,0x500000 + (seq++)));
    fd->opSetOpcode(o,opc);
    fd->opInsertEnd(o,block);
    opName[o] = name;
    return o;
  }
  Varnode *out(const string &name,PcodeOp *o,int4 size)
  {
    Varnode *vn = fd->newUniqueOut(size,o);
    varName[vn] = name;
    return vn;
  }
  void in(PcodeOp *o,Varnode *vn,int4 slot) { fd->opSetInput(o,vn,slot); }
  void setInput(Varnode *vn) { fd->setInputVarnode(vn); }
  void edge(BlockBasic *a,BlockBasic *b)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    graph.addEdge(a,b);
  }
  string vnName(const Varnode *vn) const
  {
    if (vn == (const Varnode *)0) return string("null");
    map<const Varnode *,string>::const_iterator iter = varName.find(vn);
    return (iter == varName.end()) ? string("?") : (*iter).second;
  }
  string opNameOf(const PcodeOp *o) const
  {
    if (o == (const PcodeOp *)0) return string("null");
    map<const PcodeOp *,string>::const_iterator iter = opName.find(o);
    return (iter == opName.end()) ? string("?") : (*iter).second;
  }
  string rangeRaw(const CircleRange &rng) const
  {
    ostringstream s;
    s << rng.getMin() << '/' << rng.getEnd() << '/' << rng.getMask()
      << '/' << rng.getStep() << '/' << (rng.isEmpty() ? 1 : 0);
    return s.str();
  }
  string quasi(const string &name,Varnode *vn)
  {
    int4 bits;
    Varnode *base = GuardRecord::quasiCopy(vn,bits);
    ostringstream q;
    q << "q:" << name << '=' << vnName(base) << '/' << bits;
    return q.str();
  }
};

// Dump the public projection of every GuardRecord plus valueMatch
// probes against each candidate varnode.
void report(const string &label,const Lab &lab,TestableJumpBasic &basic,
	    const vector<Varnode *> &candidates)
{
  vector<GuardRecord> &guards = basic.guards();
  ostringstream s;
  s << label << "|count=" << guards.size();
  for(size_t i=0;i<guards.size();++i) {
    const GuardRecord &g = guards[i];
    s << "|g" << i << ":cb=" << lab.opNameOf(g.getBranch())
      << ",ro=" << lab.opNameOf(g.getReadOp())
      << ",ip=" << g.getPath()
      << ",rng=" << lab.rangeRaw(g.getRange())
      << ",unr=" << (g.isUnrolled() ? 1 : 0);
  }
  for(size_t i=0;i<guards.size();++i) {
    const GuardRecord &g = guards[i];
    for(size_t j=0;j<candidates.size();++j) {
      int4 bits;
      Varnode *base = GuardRecord::quasiCopy(candidates[j],bits);
      s << "|vm" << i << '_' << j << '='
	<< g.valueMatch(candidates[j],base,bits);
    }
  }
  std::cout << s.str() << '\n';
}

// SC1: two chained range guards (x>2 && x<10) over a 4-byte switch
// variable.  Exercises the walk-back loop, both CBRANCH iterations
// (i=0 and i=1) and the pullBack expansion through INT_SLESS/INT_LESS.
void scenarioChainRange(Lab &lab)
{
  Varnode *x = lab.var("x",4);
  lab.setInput(x);
  BlockBasic *E = lab.blk("E");
  BlockBasic *B = lab.blk("B");
  BlockBasic *S = lab.blk("S");
  BlockBasic *D = lab.blk("D");
  BlockBasic *D2 = lab.blk("D2");
  PcodeOp *cmp1 = lab.op("E.cmp1",E,CPUI_INT_LESS,2);
  Varnode *b0 = lab.out("b0",cmp1,1);
  lab.in(cmp1,x,0);
  lab.in(cmp1,lab.cnst("c10",4,10),1);
  PcodeOp *cbE = lab.op("E.cb",E,CPUI_CBRANCH,2);
  lab.in(cbE,lab.coderef("refE",0x6000),0);
  lab.in(cbE,b0,1);
  PcodeOp *cmp2 = lab.op("B.cmp2",B,CPUI_INT_SLESS,2);
  Varnode *b1 = lab.out("b1",cmp2,1);
  lab.in(cmp2,lab.cnst("c3",4,3),0);
  lab.in(cmp2,x,1);
  PcodeOp *cbB = lab.op("B.cb",B,CPUI_CBRANCH,2);
  lab.in(cbB,lab.coderef("refB",0x6010),0);
  lab.in(cbB,b1,1);
  PcodeOp *biS = lab.op("S.bi",S,CPUI_BRANCHIND,1);
  lab.in(biS,lab.var("swtarget",4),0);
  lab.edge(E,B);
  lab.edge(E,D);
  lab.edge(B,S);
  lab.edge(B,D2);

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(biS);
  TestableJumpBasic basic(&jt);
  basic.analyzeGuards(S,-1);
  vector<Varnode *> candidates;
  candidates.push_back(x);
  candidates.push_back(b0);
  candidates.push_back(b1);
  report("sc1_chain_range",lab,basic,candidates);
}

// SC2: unrolled guard.  Two blocks duplicate the guard calculation and
// flow into a common block M (sizeIn=2), which flows into the switch.
// Exercises checkUnrolledGuard: the MULTIEQUAL path at j=0 and the
// duplicateVarnodes path at j=1 after liftVerifyUnroll.
void scenarioUnrolled(Lab &lab)
{
  Varnode *x2 = lab.var("x2",4);
  lab.setInput(x2);
  BlockBasic *U1 = lab.blk("U1");
  BlockBasic *U2 = lab.blk("U2");
  BlockBasic *M = lab.blk("M");
  BlockBasic *DU = lab.blk("DU");
  BlockBasic *S2 = lab.blk("S2");
  PcodeOp *cmpU1 = lab.op("U1.cmp",U1,CPUI_INT_LESS,2);
  Varnode *bU1 = lab.out("bU1",cmpU1,1);
  lab.in(cmpU1,x2,0);
  lab.in(cmpU1,lab.cnst("c5",4,5),1);
  PcodeOp *cbU1 = lab.op("U1.cb",U1,CPUI_CBRANCH,2);
  lab.in(cbU1,lab.coderef("refU1",0x6100),0);
  lab.in(cbU1,bU1,1);
  PcodeOp *cmpU2 = lab.op("U2.cmp",U2,CPUI_INT_LESS,2);
  Varnode *bU2 = lab.out("bU2",cmpU2,1);
  lab.in(cmpU2,x2,0);
  lab.in(cmpU2,lab.cnst("c5b",4,5),1);
  PcodeOp *cbU2 = lab.op("U2.cb",U2,CPUI_CBRANCH,2);
  lab.in(cbU2,lab.coderef("refU2",0x6110),0);
  lab.in(cbU2,bU2,1);
  PcodeOp *phi = lab.op("M.phi",M,CPUI_MULTIEQUAL,2);
  Varnode *mout = lab.out("mout",phi,1);
  lab.in(phi,bU1,0);
  lab.in(phi,bU2,1);
  PcodeOp *biS2 = lab.op("S2.bi",S2,CPUI_BRANCHIND,1);
  lab.in(biS2,lab.var("swtarget2",4),0);
  lab.edge(U1,M);
  lab.edge(U1,DU);
  lab.edge(U2,M);
  lab.edge(U2,DU);
  lab.edge(M,S2);

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(biS2);
  TestableJumpBasic basic(&jt);
  basic.analyzeGuards(S2,-1);
  vector<Varnode *> candidates;
  candidates.push_back(x2);
  candidates.push_back(bU1);
  candidates.push_back(bU2);
  candidates.push_back(mout);
  report("sc2_unrolled",lab,basic,candidates);
}

// SC3: single guard with a negative signed constant (x >=s -5).
void scenarioNegConst(Lab &lab)
{
  Varnode *x3 = lab.var("x3",4);
  BlockBasic *G3 = lab.blk("G3");
  BlockBasic *S3 = lab.blk("S3");
  BlockBasic *D3 = lab.blk("D3");
  PcodeOp *cmp3 = lab.op("G3.cmp",G3,CPUI_INT_SLESS,2);
  Varnode *b3 = lab.out("b3",cmp3,1);
  lab.in(cmp3,x3,0);
  lab.in(cmp3,lab.cnst("cneg5",4,0xfffffffb),1);
  PcodeOp *cbG3 = lab.op("G3.cb",G3,CPUI_CBRANCH,2);
  lab.in(cbG3,lab.coderef("refG3",0x6200),0);
  lab.in(cbG3,b3,1);
  PcodeOp *biS3 = lab.op("S3.bi",S3,CPUI_BRANCHIND,1);
  lab.in(biS3,lab.var("swtarget3",4),0);
  lab.edge(G3,S3);
  lab.edge(G3,D3);

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(biS3);
  TestableJumpBasic basic(&jt);
  basic.analyzeGuards(S3,-1);
  vector<Varnode *> candidates;
  candidates.push_back(x3);
  candidates.push_back(b3);
  report("sc3_neg_const",lab,basic,candidates);
}

// SC4: at i!=0 the OTHER out-edge of the second CBRANCH's block leads
// to a foreign BRANCHIND (not this table's indirect op): analyzeGuards
// must break and produce no guards for that CBRANCH.
void scenarioOtherSwitch(Lab &lab)
{
  Varnode *x4 = lab.var("x4",4);
  lab.setInput(x4);
  BlockBasic *X4 = lab.blk("X4");
  BlockBasic *A4 = lab.blk("A4");
  BlockBasic *O4 = lab.blk("O4");
  BlockBasic *S4 = lab.blk("S4");
  BlockBasic *D4 = lab.blk("D4");
  PcodeOp *cmp4 = lab.op("X4.cmp",X4,CPUI_INT_LESS,2);
  Varnode *b4 = lab.out("b4",cmp4,1);
  lab.in(cmp4,x4,0);
  lab.in(cmp4,lab.cnst("c7",4,7),1);
  PcodeOp *cbX4 = lab.op("X4.cb",X4,CPUI_CBRANCH,2);
  lab.in(cbX4,lab.coderef("refX4",0x6300),0);
  lab.in(cbX4,b4,1);
  PcodeOp *cmp4b = lab.op("A4.cmp",A4,CPUI_INT_LESS,2);
  Varnode *b4b = lab.out("b4b",cmp4b,1);
  lab.in(cmp4b,x4,0);
  lab.in(cmp4b,lab.cnst("c3b",4,3),1);
  PcodeOp *cbA4 = lab.op("A4.cb",A4,CPUI_CBRANCH,2);
  lab.in(cbA4,lab.coderef("refA4",0x6310),0);
  lab.in(cbA4,b4b,1);
  PcodeOp *biO4 = lab.op("O4.bi",O4,CPUI_BRANCHIND,1);
  lab.in(biO4,lab.var("foreigntarget",4),0);
  PcodeOp *biS4 = lab.op("S4.bi",S4,CPUI_BRANCHIND,1);
  lab.in(biS4,lab.var("swtarget4",4),0);
  lab.edge(X4,A4);
  lab.edge(X4,O4);
  lab.edge(A4,S4);
  lab.edge(A4,D4);

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(biS4);
  TestableJumpBasic basic(&jt);
  basic.analyzeGuards(S4,-1);
  vector<Varnode *> candidates;
  candidates.push_back(x4);
  candidates.push_back(b4);
  candidates.push_back(b4b);
  report("sc4_other_switch",lab,basic,candidates);
}

// SC5: pathout stepping (JumpBasic2 style).  analyzeGuards(X5,1) where
// X5 ends with the CBRANCH and has two out edges; out(1) leads to the
// switch block.  The first iteration must step through the pathout
// edge and analyze X5's own CBRANCH (indpath=1), then walk back at
// i=1 and break on the foreign BRANCHIND of EX5.
void scenarioPathout(Lab &lab)
{
  Varnode *x5 = lab.var("x5",4);
  lab.setInput(x5);
  BlockBasic *W5 = lab.blk("W5");
  BlockBasic *X5 = lab.blk("X5");
  BlockBasic *A5 = lab.blk("A5");
  BlockBasic *EX5 = lab.blk("EX5");
  BlockBasic *S5 = lab.blk("S5");
  PcodeOp *cmp5 = lab.op("W5.cmp",W5,CPUI_INT_LESS,2);
  Varnode *b5 = lab.out("b5",cmp5,1);
  lab.in(cmp5,x5,0);
  lab.in(cmp5,lab.cnst("c20",4,20),1);
  PcodeOp *cbW5 = lab.op("W5.cb",W5,CPUI_CBRANCH,2);
  lab.in(cbW5,lab.coderef("refW5",0x6400),0);
  lab.in(cbW5,b5,1);
  PcodeOp *cmp5b = lab.op("X5.cmp",X5,CPUI_INT_LESS,2);
  Varnode *b5b = lab.out("b5b",cmp5b,1);
  lab.in(cmp5b,x5,0);
  lab.in(cmp5b,lab.cnst("c8",4,8),1);
  PcodeOp *cbX5 = lab.op("X5.cb",X5,CPUI_CBRANCH,2);
  lab.in(cbX5,lab.coderef("refX5",0x6410),0);
  lab.in(cbX5,b5b,1);
  PcodeOp *biEX5 = lab.op("EX5.bi",EX5,CPUI_BRANCHIND,1);
  lab.in(biEX5,lab.var("exittarget",4),0);
  PcodeOp *biS5 = lab.op("S5.bi",S5,CPUI_BRANCHIND,1);
  lab.in(biS5,lab.var("swtarget5",4),0);
  lab.edge(W5,X5);
  lab.edge(W5,EX5);
  lab.edge(X5,A5);
  lab.edge(X5,S5);

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(biS5);
  TestableJumpBasic basic(&jt);
  basic.analyzeGuards(X5,1);
  vector<Varnode *> candidates;
  candidates.push_back(x5);
  candidates.push_back(b5);
  candidates.push_back(b5b);
  report("sc5_pathout",lab,basic,candidates);
}

// SC6: quasiCopy walks and valueMatch deep branches, observed after
// calcNZMask so that INT_AND's mask walk is live.
void scenarioQuasiValueMatch(Lab &lab)
{
  Varnode *y = lab.var("y",4);
  lab.setInput(y);
  BlockBasic *Q = lab.blk("Q");
  PcodeOp *and1 = lab.op("Q.and1",Q,CPUI_INT_AND,2);
  Varnode *v1 = lab.out("v1",and1,4);
  lab.in(and1,y,0);
  lab.in(and1,lab.cnst("cf",4,0xf),1);
  PcodeOp *and2 = lab.op("Q.and2",Q,CPUI_INT_AND,2);
  Varnode *v2 = lab.out("v2",and2,4);
  lab.in(and2,y,0);
  lab.in(and2,lab.cnst("cfb",4,0xf),1);
  PcodeOp *add1 = lab.op("Q.add1",Q,CPUI_INT_ADD,2);
  Varnode *w1 = lab.out("w1",add1,4);
  lab.in(add1,y,0);
  lab.in(add1,lab.cnst("c4",4,4),1);
  PcodeOp *add2 = lab.op("Q.add2",Q,CPUI_INT_ADD,2);
  Varnode *w2 = lab.out("w2",add2,4);
  lab.in(add2,y,0);
  lab.in(add2,lab.cnst("c4b",4,4),1);
  PcodeOp *add3 = lab.op("Q.add3",Q,CPUI_INT_ADD,2);
  Varnode *w3 = lab.out("w3",add3,4);
  lab.in(add3,y,0);
  lab.in(add3,lab.cnst("c6",4,6),1);
  PcodeOp *copy1 = lab.op("Q.copy1",Q,CPUI_COPY,1);
  Varnode *u1 = lab.out("u1",copy1,4);
  lab.in(copy1,y,0);
  PcodeOp *copy2 = lab.op("Q.copy2",Q,CPUI_COPY,1);
  Varnode *u2 = lab.out("u2",copy2,4);
  lab.in(copy2,y,0);
  Varnode *z = lab.var("z",8);
  lab.setInput(z);
  PcodeOp *padd1 = lab.op("Q.padd1",Q,CPUI_INT_ADD,2);
  Varnode *p1 = lab.out("p1",padd1,8);
  lab.in(padd1,z,0);
  lab.in(padd1,lab.cnst("c8_64",8,8),1);
  PcodeOp *padd2 = lab.op("Q.padd2",Q,CPUI_INT_ADD,2);
  Varnode *p2 = lab.out("p2",padd2,8);
  lab.in(padd2,z,0);
  lab.in(padd2,lab.cnst("c8b_64",8,8),1);
  PcodeOp *padd3 = lab.op("Q.padd3",Q,CPUI_INT_ADD,2);
  Varnode *p3 = lab.out("p3",padd3,8);
  lab.in(padd3,z,0);
  lab.in(padd3,lab.cnst("c16_64",8,16),1);
  Varnode *sp1 = lab.cnst("sp1",8,0x2);
  Varnode *sp1b = lab.cnst("sp1b",8,0x2);
  PcodeOp *load1 = lab.op("Q.load1",Q,CPUI_LOAD,2);
  Varnode *l1 = lab.out("l1",load1,4);
  lab.in(load1,sp1,0);
  lab.in(load1,p1,1);
  PcodeOp *load2 = lab.op("Q.load2",Q,CPUI_LOAD,2);
  Varnode *l2 = lab.out("l2",load2,4);
  lab.in(load2,sp1b,0);
  lab.in(load2,p2,1);
  PcodeOp *load3 = lab.op("Q.load3",Q,CPUI_LOAD,2);
  Varnode *l3 = lab.out("l3",load3,4);
  lab.in(load3,sp1,0);
  lab.in(load3,p3,1);
  PcodeOp *sext = lab.op("Q.sext",Q,CPUI_INT_SEXT,1);
  Varnode *s1 = lab.out("s1",sext,8);
  lab.in(sext,y,0);
  PcodeOp *sub = lab.op("Q.sub",Q,CPUI_SUBPIECE,2);
  Varnode *t1 = lab.out("t1",sub,4);
  lab.in(sub,z,0);
  lab.in(sub,lab.cnst("c0",8,0),1);
  PcodeOp *dummy = lab.op("Q.dummy",Q,CPUI_COPY,1);
  lab.in(dummy,y,0);
  Varnode *k1 = lab.cnst("k1",4,5);
  Varnode *k2 = lab.cnst("k2",4,9);
  Varnode *k3 = lab.cnst("k3",4,6);

  // Compute non-zero masks so INT_AND's quasiCopy mask walk is live.
  lab.fd->calcNZMask();

  ostringstream s;
  s << "sc6_quasi_vm";
  s << '|' << lab.quasi("y",y);
  s << '|' << lab.quasi("v1",v1);
  s << '|' << lab.quasi("v2",v2);
  s << '|' << lab.quasi("u1",u1);
  s << '|' << lab.quasi("s1",s1);
  s << '|' << lab.quasi("t1",t1);
  s << '|' << lab.quasi("p1",p1);
  s << '|' << lab.quasi("l1",l1);

  GuardRecord guardAnd(dummy,dummy,0,CircleRange(true),v1,false);
  int4 bits;
  Varnode *base;
  base = GuardRecord::quasiCopy(v2,bits);
  s << "|vm_and_samebase=" << guardAnd.valueMatch(v2,base,bits);
  base = GuardRecord::quasiCopy(y,bits);
  s << "|vm_and_y=" << guardAnd.valueMatch(y,base,bits);
  base = GuardRecord::quasiCopy(v1,bits);
  s << "|vm_and_samevn=" << guardAnd.valueMatch(v1,base,bits);

  GuardRecord guardAdd(dummy,dummy,0,CircleRange(true),w1,false);
  base = GuardRecord::quasiCopy(w2,bits);
  s << "|vm_add_oneoff=" << guardAdd.valueMatch(w2,base,bits);
  base = GuardRecord::quasiCopy(w3,bits);
  s << "|vm_add_offconst=" << guardAdd.valueMatch(w3,base,bits);

  GuardRecord guardCopy(dummy,dummy,0,CircleRange(false),u1,false);
  base = GuardRecord::quasiCopy(u2,bits);
  s << "|vm_copy_samebase=" << guardCopy.valueMatch(u2,base,bits);

  GuardRecord guardLoad(dummy,dummy,0,CircleRange(true),l1,false);
  base = GuardRecord::quasiCopy(l2,bits);
  s << "|vm_load_equiv=" << guardLoad.valueMatch(l2,base,bits);
  base = GuardRecord::quasiCopy(l3,bits);
  s << "|vm_load_offdiff=" << guardLoad.valueMatch(l3,base,bits);

  GuardRecord guardConst(dummy,dummy,0,CircleRange(true),k1,false);
  base = GuardRecord::quasiCopy(k2,bits);
  s << "|vm_const_bitsdiff=" << guardConst.valueMatch(k2,base,bits);
  base = GuardRecord::quasiCopy(k3,bits);
  s << "|vm_const_basediff=" << guardConst.valueMatch(k3,base,bits);
  std::cout << s.str() << '\n';
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
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0) throw std::runtime_error("function not found: GetStr");
    Lab lab(fd);
    scenarioChainRange(lab);
    scenarioUnrolled(lab);
    scenarioNegConst(lab);
    scenarioOtherSwitch(lab);
    scenarioPathout(lab);
    scenarioQuasiValueMatch(lab);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: jt_guards_1204 SPEC_ROOT CURL_BINARY\n";
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
