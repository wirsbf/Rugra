/* JT-CALCRANGE-1204 (JUMPTABLE-CALCRANGE-0001): locked Ghidra 12.0.4 fixture.
 *
 * Observes JumpBasic::calcRange (jumptable.cc:1120-1156),
 * JumpBasic::markFoldableGuards (jumptable.cc:1239-1251) and
 * JumpBasic::markModel (jumptable.cc:1254-1267) on synthetic guard CFGs
 * built inside a vehicle Funcdata loaded from the pinned curl binary.
 *
 * calcRange is driven both through the public recoverModel entry (sc1/sc3:
 * jrange size after guard intersection) and directly after analyzeGuards
 * (sc2: constant varnode input).  markModel's skip semantics are observed
 * via PcodeOp::isMark() after markFoldableGuards has cleared the
 * valueMatch==0 guards (their CBRANCH becomes null and their readOp must
 * NOT be marked).
 *
 * Guards use unsigned comparisons only (INT_LESS): the signed pullback and
 * calc_nz_mask residuals are covered by JT-GUARDS-1204 and stay out of
 * this fixture's write-set.
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
  using JumpBasic::calcRange;
  using JumpBasic::markModel;
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
};

// SC1: two chained unsigned range guards (x<8 and x<10) over a 4-byte
// switch variable fed straight into BRANCHIND.  recoverModel drives
// findDeterminingVarnodes + analyzeGuards + findSmallestNormal +
// markFoldableGuards.  calcRange is then probed on: the switch variable
// (guard intersection written back: [0,8) size 8), the boolean comparison
// outputs (isBoolOutput branch: [0,2) restricted by the bool guard to {1}),
// and an unrelated input (no matching guard: full range truncated to the
// positive half).  The jrange observation locks the resulting table size.
void scenarioRangeGuard(Lab &lab)
{
  Varnode *x = lab.var("x",4);
  lab.setInput(x);
  Varnode *u = lab.var("u",4);
  lab.setInput(u);
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
  PcodeOp *cmp2 = lab.op("B.cmp2",B,CPUI_INT_LESS,2);
  Varnode *b1 = lab.out("b1",cmp2,1);
  lab.in(cmp2,x,0);
  lab.in(cmp2,lab.cnst("c8",4,8),1);
  PcodeOp *cbB = lab.op("B.cb",B,CPUI_CBRANCH,2);
  lab.in(cbB,lab.coderef("refB",0x6010),0);
  lab.in(cbB,b1,1);
  PcodeOp *biS = lab.op("S.bi",S,CPUI_BRANCHIND,1);
  lab.in(biS,x,0);
  lab.edge(E,D);			// out(0): default path
  lab.edge(E,B);			// out(1): switch path
  lab.edge(B,D2);			// out(0): default path
  lab.edge(B,S);			// out(1): switch path

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(biS);
  TestableJumpBasic basic(&jt);
  bool ok = basic.recoverModel(lab.fd,biS,0,500);

  vector<GuardRecord> &guards = basic.guards();
  ostringstream s;
  s << "sc1_range_guard|ok=" << (ok ? 1 : 0);
  s << "|count=" << guards.size();
  for(size_t i=0;i<guards.size();++i) {
    const GuardRecord &g = guards[i];
    s << "|g" << i << ":cb=" << lab.opNameOf(g.getBranch())
      << ",ro=" << lab.opNameOf(g.getReadOp())
      << ",ip=" << g.getPath()
      << ",rng=" << lab.rangeRaw(g.getRange())
      << ",unr=" << (g.isUnrolled() ? 1 : 0);
  }
  CircleRange rng;
  basic.calcRange(x,rng);
  s << "|cr_x=" << lab.rangeRaw(rng);
  basic.calcRange(b0,rng);
  s << "|cr_b0=" << lab.rangeRaw(rng);
  basic.calcRange(b1,rng);
  s << "|cr_b1=" << lab.rangeRaw(rng);
  basic.calcRange(u,rng);
  s << "|cr_u=" << lab.rangeRaw(rng);
  const JumpValuesRange *vr = basic.getValueRange();
  s << "|jsz=" << vr->getSize()
    << "|jsvn=" << lab.vnName(vr->getStartVarnode())
    << "|jsop=" << lab.opNameOf(vr->getStartOp());
  std::cout << s.str() << '\n';
}

// SC2: constant varnode as the CBRANCH boolean (size-1 constant 1 with
// toswitchval=true).  The first GuardRecord's vn is the constant itself,
// so calcRange must NOT early-return on constants: the guard range {1} is
// intersected into single(1) (identity here; the disjoint/empty case needs
// the full CircleRange::intersect port, RANGE-0001).  A 4-byte constant
// with no matching guard keeps its single range and skips the positive
// truncation (size 1).
void scenarioConstantInput(Lab &lab)
{
  BlockBasic *G = lab.blk("G");
  BlockBasic *S = lab.blk("S");
  BlockBasic *D = lab.blk("D");
  Varnode *k1 = lab.cnst("k1",1,1);
  PcodeOp *cbG = lab.op("G.cb",G,CPUI_CBRANCH,2);
  lab.in(cbG,lab.coderef("refG",0x6200),0);
  lab.in(cbG,k1,1);
  PcodeOp *biS = lab.op("S.bi",S,CPUI_BRANCHIND,1);
  lab.in(biS,lab.var("w",4),0);
  lab.edge(G,D);			// out(0): default path
  lab.edge(G,S);			// out(1): switch path

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(biS);
  TestableJumpBasic basic(&jt);
  basic.analyzeGuards(S,-1);

  vector<GuardRecord> &guards = basic.guards();
  ostringstream s;
  s << "sc2_constant_input";
  s << "|count=" << guards.size();
  for(size_t i=0;i<guards.size();++i) {
    const GuardRecord &g = guards[i];
    s << "|g" << i << ":cb=" << lab.opNameOf(g.getBranch())
      << ",ro=" << lab.opNameOf(g.getReadOp())
      << ",ip=" << g.getPath()
      << ",rng=" << lab.rangeRaw(g.getRange())
      << ",unr=" << (g.isUnrolled() ? 1 : 0);
  }
  CircleRange rng;
  basic.calcRange(k1,rng);
  s << "|cr_k1=" << lab.rangeRaw(rng);
  Varnode *k2 = lab.cnst("k2",4,0x90000000);
  basic.calcRange(k2,rng);
  s << "|cr_k2=" << lab.rangeRaw(rng);
  std::cout << s.str() << '\n';
}

// SC3: markModel skip semantics.  Same chained-guard shape as SC1; after
// recoverModel the two boolean guards are cleared by markFoldableGuards
// (valueMatch==0 against the selected switch variable x).  markModel(true)
// must mark pathMeld ops and surviving guards' readOps but SKIP the cleared
// guards entirely (getBranch()==null continues before readOp).  markModel
// (false) then clears every mark again.
void scenarioMarkModelSkip(Lab &lab)
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
  lab.in(cbE,lab.coderef("refE",0x6300),0);
  lab.in(cbE,b0,1);
  PcodeOp *cmp2 = lab.op("B.cmp2",B,CPUI_INT_LESS,2);
  Varnode *b1 = lab.out("b1",cmp2,1);
  lab.in(cmp2,x,0);
  lab.in(cmp2,lab.cnst("c8",4,8),1);
  PcodeOp *cbB = lab.op("B.cb",B,CPUI_CBRANCH,2);
  lab.in(cbB,lab.coderef("refB",0x6310),0);
  lab.in(cbB,b1,1);
  PcodeOp *biS = lab.op("S.bi",S,CPUI_BRANCHIND,1);
  lab.in(biS,x,0);
  lab.edge(E,D);
  lab.edge(E,B);
  lab.edge(B,D2);
  lab.edge(B,S);

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(biS);
  TestableJumpBasic basic(&jt);
  bool ok = basic.recoverModel(lab.fd,biS,0,500);

  vector<GuardRecord> &guards = basic.guards();
  ostringstream s;
  s << "sc3_markmodel_skip|ok=" << (ok ? 1 : 0);
  for(size_t i=0;i<guards.size();++i)
    s << "|gn" << i << '=' << (guards[i].getBranch() == (PcodeOp *)0 ? 1 : 0);
  basic.markModel(true);
  s << "|on_Sbi=" << (biS->isMark() ? 1 : 0)
    << "|on_Bcmp2=" << (cmp2->isMark() ? 1 : 0)
    << "|on_Ecmp1=" << (cmp1->isMark() ? 1 : 0)
    << "|on_Bcb=" << (cbB->isMark() ? 1 : 0)
    << "|on_Ecb=" << (cbE->isMark() ? 1 : 0);
  basic.markModel(false);
  s << "|off_Sbi=" << (biS->isMark() ? 1 : 0)
    << "|off_Bcmp2=" << (cmp2->isMark() ? 1 : 0)
    << "|off_Ecmp1=" << (cmp1->isMark() ? 1 : 0)
    << "|off_Bcb=" << (cbB->isMark() ? 1 : 0)
    << "|off_Ecb=" << (cbE->isMark() ? 1 : 0);
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
    scenarioRangeGuard(lab);
    scenarioConstantInput(lab);
    scenarioMarkModelSkip(lab);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: jt_calcrange_1204 SPEC_ROOT CURL_BINARY\n";
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
