/* JT-PIPELINE-S1-1204 (JUMPTABLE-PIPELINE-0001 segment 1): locked Ghidra
 * 12.0.4 fixture.
 *
 * Observation surface (jumptable.rs domain):
 *   - sel_basic            JumpTable::recoverModel selection chain reaches
 *                          JumpBasic, findNormalized (jumptable.cc:1204) is
 *                          entered through recoverModel's cc:1427 call shape
 *                          (guards + smallest normal + size gate), and
 *                          buildAddresses produces the guarded table.
 *   - sel_override         The override model short-circuits the chain
 *                          (cc:2257-2261): setOverride addresses survive
 *                          recovery verbatim.
 *   - sel_basic2_default   JumpBasic fails on the unguarded MULTIEQUAL join,
 *                          JumpBasic2 (initializeStart of the failed
 *                          pathMeld, cc:2278-2280) recovers the two-path
 *                          default model, extra value emitted last.
 *   - sel_allfail          Every model rejects (no parent-free shortcut, no
 *                          Trivial fallback): recoverAddresses throws
 *                          "Could not recover jumptable ... Too many
 *                          branches" (cc:2627-2630).
 *   - emulfn_load_ok       EmulateFunction evaluates a real LOAD through the
 *                          LoadImage bridge (EmulatePcodeOp::executeLoad,
 *                          emulateutil.cc:81) with loadpoints collection and
 *                          LoadTable::collapseTable.
 *   - emulfn_load_dataunavail  A LOAD outside every mapped section raises
 *                          DataUnavailError, caught by emulatePath
 *                          (jumptable.cc:246-250) and rethrown as
 *                          "Could not emulate address calculation at <addr>".
 *   - emulfn_channels      Direct EmulateFunction::emulatePath probes:
 *                          BRANCH / RETURN / taken-CBRANCH LowlevelError
 *                          texts, fallthru CBRANCH value, MULTIEQUAL
 *                          lastOp-edge resolution (failure and success).
 *
 * Every address embedded in a message is normalized to <A> so the two
 * language stacks' Address printers cannot diverge.
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

struct Lab {
  Funcdata *fd;
  AddrSpace *code;
  map<const Varnode *, string> varName;
  map<const PcodeOp *, string> opName;
  int seq;

  Lab(Funcdata *f) : fd(f), code(f->getArch()->getDefaultCodeSpace()), seq(0) {}

  BlockBasic *blk(const string &name)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
    BlockBasic *b = graph.newBlockBasic(fd);
    (void)name;
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
};

// Normalize a Ghidra exception message: any address following " at " is
// replaced with <A> so Address-printer differences cannot leak.
string canon(const string &msg)
{
  size_t pos = msg.find(" at ");
  if (pos == string::npos) return msg;
  size_t rest = msg.find('.', pos + 4);
  if (rest == string::npos) return msg.substr(0, pos + 4) + "<A>";
  return msg.substr(0, pos + 4) + "<A>" + msg.substr(rest);
}

string hx(uintb v)
{
  ostringstream s;
  s << std::hex << v;
  return s.str();
}

// Run JumpTable::recoverAddresses and print the observation line.
// (loadpoints themselves are private to JumpTable on the C++ side; the
// collect=1 flag still drives the collection/collapse code path.)
void runTable(const string &label,Lab &lab,JumpTable &jt,bool loadCollect)
{
  ostringstream s;
  s << label << "|collect=" << (loadCollect ? 1 : 0);
  try {
    jt.setLoadCollect(loadCollect);
    jt.recoverAddresses(lab.fd);
    s << "|ok=1|n=" << jt.numEntries();
    for(uint4 i=0;i<jt.numEntries();++i)
      s << "|a" << i << '=' << hx(jt.getAddressByIndex(i).getOffset());
  }
  catch(JumptableThunkError &err) {
    s << "|ok=0|mode=2|msg=" << canon(err.explain);
  }
  catch(LowlevelError &err) {
    s << "|ok=0|mode=1|msg=" << canon(err.explain);
  }
  std::cout << s.str() << '\n';
}

// SC sel_basic: guarded switch x in [0,4); BRANCHIND target = x + 0x7000.
void scenarioBasic(Lab &lab)
{
  Varnode *x = lab.var("x",4);
  lab.setInput(x);
  BlockBasic *G = lab.blk("G");
  BlockBasic *S = lab.blk("S");
  BlockBasic *D = lab.blk("D");
  PcodeOp *cmp = lab.op("G.cmp",G,CPUI_INT_LESS,2);
  Varnode *b0 = lab.out("b0",cmp,1);
  lab.in(cmp,x,0);
  lab.in(cmp,lab.cnst("c4",4,4),1);
  PcodeOp *cb = lab.op("G.cb",G,CPUI_CBRANCH,2);
  lab.in(cb,lab.coderef("ref",0x6000),0);
  lab.in(cb,b0,1);
  PcodeOp *bi = lab.op("S.bi",S,CPUI_BRANCHIND,1);
  PcodeOp *add = lab.op("S.add",S,CPUI_INT_ADD,2);
  Varnode *t = lab.out("t",add,4);
  lab.in(add,x,0);
  lab.in(add,lab.cnst("c7000",4,0x7000),1);
  lab.fd->opSetInput(bi,t,0);
  lab.edge(G,D);  // out(0) = default (b0 == 0)
  lab.edge(G,S);  // out(1) = switch   (b0 == 1)
  lab.fd->calcNZMask();

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(bi);
  runTable("sel_basic",lab,jt,false);
}

// SC sel_override: manual override wins before any model analysis.
void scenarioOverride(Lab &lab)
{
  BlockBasic *S = lab.blk("SO");
  PcodeOp *bi = lab.op("SO.bi",S,CPUI_BRANCHIND,1);
  lab.in(bi,lab.var("rawt",4),0);
  lab.fd->calcNZMask();

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(bi);
  vector<Address> ad;
  ad.push_back(Address(lab.code,0x2000));
  ad.push_back(Address(lab.code,0x2100));
  jt.setOverride(ad,Address(),0,0);
  runTable("sel_override",lab,jt,false);
}

// SC sel_basic2_default: BRANCHIND target = MULTIEQUAL(default-copy, x) + 0x3000.
// JumpBasic fails (join is a marker prune, range unbounded); JumpBasic2
// recovers with the guarded x range and appends the default value entry.
void scenarioBasic2(Lab &lab)
{
  Varnode *x = lab.var("x2",4);
  lab.setInput(x);
  BlockBasic *A = lab.blk("A");
  BlockBasic *C = lab.blk("C");
  BlockBasic *S = lab.blk("S2");
  BlockBasic *D = lab.blk("D2");
  PcodeOp *cmp = lab.op("A.cmp",A,CPUI_INT_LESS,2);
  Varnode *b0 = lab.out("b0",cmp,1);
  lab.in(cmp,x,0);
  lab.in(cmp,lab.cnst("c4b",4,4),1);
  PcodeOp *cb = lab.op("A.cb",A,CPUI_CBRANCH,2);
  lab.in(cb,lab.coderef("ref2",0x6100),0);
  lab.in(cb,b0,1);
  PcodeOp *cp = lab.op("C.cp",C,CPUI_COPY,1);
  Varnode *c1 = lab.out("c1",cp,4);
  lab.in(cp,lab.cnst("cdef",4,0x4141),0);
  PcodeOp *me = lab.op("S2.me",S,CPUI_MULTIEQUAL,2);
  Varnode *j = lab.out("j",me,4);
  lab.in(me,c1,0);
  lab.in(me,x,1);
  PcodeOp *bi = lab.op("S2.bi",S,CPUI_BRANCHIND,1);
  PcodeOp *add = lab.op("S2.add",S,CPUI_INT_ADD,2);
  Varnode *t2 = lab.out("t2",add,4);
  lab.in(add,j,0);
  lab.in(add,lab.cnst("c3000",4,0x3000),1);
  lab.fd->opSetInput(bi,t2,0);
  lab.edge(A,D);  // A out(0) = default guard target
  lab.edge(C,S);  // S in(0) = C (const path)  -- ME.in(0) = c1 must flow from in(0)
  lab.edge(A,S);  // A out(1) = switch (b0 == 1); S in(1) = A -- ME.in(1) = x
  lab.fd->calcNZMask();

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(bi);
  runTable("sel_basic2_default",lab,jt,false);
}

// SC sel_allfail: def-less raw register read, no guard, no parent block
// shortcut: every model in the chain rejects.
void scenarioAllFail(Lab &lab)
{
  BlockBasic *E = lab.blk("E");
  BlockBasic *S = lab.blk("S3");
  PcodeOp *bi = lab.op("S3.bi",S,CPUI_BRANCHIND,1);
  lab.in(bi,lab.var("raw8",8),0);
  PcodeOp *dummy = lab.op("E.dummy",E,CPUI_COPY,1);
  lab.in(dummy,lab.var("dv",4),0);
  lab.edge(E,S);
  lab.fd->calcNZMask();

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(bi);
  runTable("sel_allfail",lab,jt,false);
}

// SC emulfn_load_ok: guarded x in [0,4);
// target = ZEXT(LOAD(ram, 0x6100 + x), 1->4) + 0x8000, loadpoints collected.
// SC emulfn_load_dataunavail: same but the LOAD base is outside every mapped
// section -> DataUnavailError -> wrapped LowlevelError from emulatePath.
void scenarioLoad(Lab &lab,const string &label,uintb base)
{
  Varnode *x = lab.var("lx",4);
  lab.setInput(x);
  BlockBasic *G = lab.blk("LG");
  BlockBasic *S = lab.blk("LS");
  BlockBasic *D = lab.blk("LD");
  PcodeOp *cmp = lab.op("LG.cmp",G,CPUI_INT_LESS,2);
  Varnode *b0 = lab.out("lb0",cmp,1);
  lab.in(cmp,x,0);
  lab.in(cmp,lab.cnst("lc4",4,4),1);
  PcodeOp *cb = lab.op("LG.cb",G,CPUI_CBRANCH,2);
  lab.in(cb,lab.coderef("lref",0x6200),0);
  lab.in(cb,b0,1);
  PcodeOp *addp = lab.op("LG.addp",G,CPUI_INT_ADD,2);
  Varnode *ptr = lab.out("lptr",addp,4);
  lab.in(addp,x,0);
  lab.in(addp,lab.cnst("lbase",4,base),1);
  PcodeOp *ld = lab.op("LG.ld",G,CPUI_LOAD,2);
  Varnode *lv = lab.out("lv",ld,1);
  lab.in(ld,lab.cnst("lspc",8,(uintb)(uintp)lab.code),0);  // space-id constant holds the AddrSpace* (varnode.hh:426)
  lab.in(ld,ptr,1);
  PcodeOp *zx = lab.op("LG.zx",G,CPUI_INT_ZEXT,1);
  Varnode *zv = lab.out("lzv",zx,4);
  lab.in(zx,lv,0);
  PcodeOp *bi = lab.op("LS.bi",S,CPUI_BRANCHIND,1);
  PcodeOp *add2 = lab.op("LS.add",S,CPUI_INT_ADD,2);
  Varnode *t3 = lab.out("t3",add2,4);
  lab.in(add2,zv,0);
  lab.in(add2,lab.cnst("lc8000",4,0x8000),1);
  lab.fd->opSetInput(bi,t3,0);
  lab.edge(G,D);
  lab.edge(G,S);
  lab.fd->calcNZMask();

  JumpTable jt(lab.fd->getArch());
  jt.setIndirectOp(bi);
  runTable(label,lab,jt,true);
}

// Direct EmulateFunction::emulatePath channel probes.
void scenarioChannels(Lab &lab)
{
  ostringstream s;
  s << "emulfn_channels";

  // (a) BRANCH inside the meld -> LowlevelError (jumptable.cc:126-130).
  {
    Varnode *v = lab.cnst("cv1",4,0x33);
    PcodeOp *br = lab.op("CH.br",lab.blk("CHB1"),CPUI_BRANCH,1);
    Varnode *bo = lab.out("bo",br,4);
    lab.in(br,v,0);
    PcodeOp *bi = lab.op("CHB1.bi",lab.blk("CHB2"),CPUI_BRANCHIND,1);
    lab.in(bi,bo,0);
    vector<PcodeOpNode> path;
    path.push_back(PcodeOpNode(bi,0));
    path.push_back(PcodeOpNode(br,0));
    PathMeld pm;
    pm.set(path);
    EmulateFunction emul(lab.fd);
    try {
      uintb res = emul.emulatePath(1,pm,br,v);
      s << "|a=ok:" << hx(res);
    }
    catch(LowlevelError &err) { s << "|a=err:" << err.explain; }
  }
  // (b) RETURN inside the meld -> "Indirect branch encountered ..." (cc:132).
  {
    Varnode *v = lab.cnst("cv2",4,0x44);
    PcodeOp *ret = lab.op("CH.ret",lab.blk("CHR1"),CPUI_RETURN,1);
    Varnode *ro = lab.out("ro",ret,4);
    lab.in(ret,v,0);
    PcodeOp *bi = lab.op("CHR1.bi",lab.blk("CHR2"),CPUI_BRANCHIND,1);
    lab.in(bi,ro,0);
    vector<PcodeOpNode> path;
    path.push_back(PcodeOpNode(bi,0));
    path.push_back(PcodeOpNode(ret,0));
    PathMeld pm;
    pm.set(path);
    EmulateFunction emul(lab.fd);
    try {
      uintb res = emul.emulatePath(1,pm,ret,v);
      s << "|b=ok:" << hx(res);
    }
    catch(LowlevelError &err) { s << "|b=err:" << err.explain; }
  }
  // (c) CBRANCH taken (cond const 1) -> branch error; not taken (cond 0)
  // falls through and the final value reads back (jumptable.cc:126 +
  // emulateutil.cc:107).
  for (int4 variant = 0; variant < 2; ++variant) {
    Varnode *v = lab.cnst("cv3",4,0x55);
    Varnode *cond = lab.cnst("cond",1,variant);
    BlockBasic *bb = lab.blk("CHC");
    PcodeOp *cb = lab.op("CHC.cb",bb,CPUI_CBRANCH,2);
    lab.in(cb,lab.coderef("cref",0x6300),0);
    lab.in(cb,cond,1);
    PcodeOp *bi = lab.op("CHC.bi",lab.blk("CHD"),CPUI_BRANCHIND,1);
    lab.in(bi,v,0);
    vector<PcodeOpNode> path;
    path.push_back(PcodeOpNode(bi,0));
    path.push_back(PcodeOpNode(cb,0));
    PathMeld pm;
    pm.set(path);
    EmulateFunction emul(lab.fd);
    try {
      uintb res = emul.emulatePath(1,pm,cb,v);
      s << "|c" << variant << "=ok:" << hx(res);
    }
    catch(LowlevelError &err) { s << "|c" << variant << "=err:" << err.explain; }
  }
  // (d) MULTIEQUAL whose parent block has no in-edge from lastOp's block ->
  // "Could not execute MULTIEQUAL" (emulateutil.cc:100-105).
  {
    BlockBasic *Z = lab.blk("CHZ");
    BlockBasic *M = lab.blk("CHM");   // two in-edges, neither from Z
    BlockBasic *W1 = lab.blk("CHW1");
    BlockBasic *W2 = lab.blk("CHW2");
    lab.edge(W1,M);
    lab.edge(W2,M);
    Varnode *v = lab.cnst("cv4",4,0x66);
    PcodeOp *cp = lab.op("CHZ.cp",Z,CPUI_COPY,1);
    Varnode *w = lab.out("w",cp,4);
    lab.in(cp,v,0);
    PcodeOp *me = lab.op("CHM.me",M,CPUI_MULTIEQUAL,2);
    Varnode *mo = lab.out("mo",me,4);
    lab.in(me,w,0);
    lab.in(me,lab.var("mw2",4),1);
    PcodeOp *bi = lab.op("CHM.bi",M,CPUI_BRANCHIND,1);
    lab.in(bi,mo,0);
    vector<PcodeOpNode> path;
    path.push_back(PcodeOpNode(bi,0));
    path.push_back(PcodeOpNode(me,0));
    path.push_back(PcodeOpNode(cp,0));
    PathMeld pm;
    pm.set(path);
    EmulateFunction emul(lab.fd);
    try {
      uintb res = emul.emulatePath(0x77,pm,cp,v);
      s << "|d=ok:" << hx(res);
    }
    catch(LowlevelError &err) { s << "|d=err:" << err.explain; }
  }
  // (e) MULTIEQUAL success: in-edge from lastOp's block exists (edge Z->M).
  {
    BlockBasic *Z = lab.blk("CHZ2");
    BlockBasic *M = lab.blk("CHM2");
    lab.edge(Z,M);
    lab.edge(lab.blk("CHW3"),M);
    Varnode *v = lab.cnst("cv5",4,0x88);
    PcodeOp *cp = lab.op("CHZ2.cp",Z,CPUI_COPY,1);
    Varnode *w = lab.out("w2",cp,4);
    lab.in(cp,v,0);
    PcodeOp *me = lab.op("CHM2.me",M,CPUI_MULTIEQUAL,2);
    Varnode *mo = lab.out("mo2",me,4);
    lab.in(me,w,0);          // slot 0 = edge index of Z in M's in-list (0)
    lab.in(me,lab.var("mw4",4),1);
    PcodeOp *bi = lab.op("CHM2.bi",M,CPUI_BRANCHIND,1);
    lab.in(bi,mo,0);
    vector<PcodeOpNode> path;
    path.push_back(PcodeOpNode(bi,0));
    path.push_back(PcodeOpNode(me,0));
    path.push_back(PcodeOpNode(cp,0));
    PathMeld pm;
    pm.set(path);
    EmulateFunction emul(lab.fd);
    try {
      uintb res = emul.emulatePath(0x99,pm,cp,v);
      s << "|e=ok:" << hx(res);
    }
    catch(LowlevelError &err) { s << "|e=err:" << err.explain; }
  }
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
    scenarioBasic(lab);
    scenarioOverride(lab);
    scenarioBasic2(lab);
    scenarioAllFail(lab);
    scenarioLoad(lab,"emulfn_load_ok",0x6100);
    scenarioLoad(lab,"emulfn_load_dataunavail",0x9000000);
    scenarioChannels(lab);
    // Module-level environment note (identical on both stacks): the fixture
    // hand-builds the stageJumpTable environment; production wiring is the
    // registered segment-2 residual.
    std::cout << "pipeline_env_note|stageJumpTable=MISSING_segment2|"
                 "raw_fd_recover=fail_closed_parent_contract|"
                 "jumpassist_payload=NO_ORACLE" << '\n';
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: jtpipeline_s1_1204 SPEC_ROOT CURL_BINARY\n";
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
