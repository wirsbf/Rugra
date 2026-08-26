/*
 * Locked Ghidra 12.0.4 ActionDirectWrite collection oracle
 * (ACTIONDW-COPYDEF-MARKING-0001).
 *
 * The runner compiles this file against an immutable archive of commit
 * e40ed13014025f82488b1f8f7bca566894ac376b.  The only temporary
 * instrumentation is a one-line public Varnode::fixtureSetFlag so the
 * fixture can set persist/spacebase/indirect_creation main flags the way
 * production analysis would; production Ghidra sources are never modified.
 *
 * Coverage targets (coreaction.cc:1350-1434):
 *   - cc:1368-1371 possibleInputParam input branch
 *   - cc:1381-1394 COPY defs are NOT collected (isStackStore trace is the
 *     sole exception, single-level source unroll to a marker def)
 *   - cc:1401-1408 marker(INDIRECT) collection branch (address change /
 *     persist), gated on !propagateIndirect, never enqueued
 *   - cc:1427-1429 phase-2 INDIRECT push gate (propagateIndirect ||
 *     code()!=INDIRECT || isIndirectStore())
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

class Fixture {
  Funcdata &fd;
  vector<BlockBasic *> blocks;
  map<BlockBasic *,string> blockNames;
  vector<PcodeOp *> ops;
  map<PcodeOp *,string> opNames;
  vector<Varnode *> varnodes;
  map<Varnode *,string> varnodeNames;

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

  set<Varnode *> liveVarnodes(void) const
  {
    set<Varnode *> result;
    for(VarnodeLocSet::const_iterator iter=fd.beginLoc();
        iter!=fd.endLoc();++iter)
      result.insert(*iter);
    return result;
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

  Varnode *makeFree(const string &name,int4 size,uintb offset)
  {
    AddrSpace *space = fd.getArch()->getSpaceByName("register");
    Varnode *vn = fd.newVarnode(size,space,offset);
    rememberVarnode(vn,name);
    return vn;
  }

  Varnode *makeConstant(const string &name,int4 size,uintb value)
  {
    Varnode *vn = fd.newConstant(size,value);
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

  // Construct an op whose output lives at an explicit register address, so
  // INDIRECT in/out address-change cases (cc:1403) are observable.
  PcodeOp *makeOpAt(const string &name,OpCode opcode,int4 inputs,uintb outOffset)
  {
    PcodeOp *op = fd.newOp(inputs,Address(fd.getArch()->getDefaultCodeSpace(),0x4c20));
    fd.opSetOpcode(op,opcode);
    rememberOp(op,name);
    AddrSpace *space = fd.getArch()->getSpaceByName("register");
    Varnode *out = fd.newVarnode(8,space,outOffset);
    fd.opSetOutput(op,out);
    rememberVarnode(out,name + "_out");
    return op;
  }

  Varnode *makeIop(const string &name,PcodeOp *op)
  {
    Varnode *vn = fd.newVarnodeIop(op);
    rememberVarnode(vn,name);
    return vn;
  }

  void setInput(PcodeOp *op,Varnode *vn,int4 slot) { fd.opSetInput(op,vn,slot); }
  void insertEnd(PcodeOp *op,BlockBasic *block) { fd.opInsertEnd(op,block); }
  void setPersist(Varnode *vn) { vn->fixtureSetFlag(Varnode::persist); }
  void setSpacebase(Varnode *vn) { vn->fixtureSetFlag(Varnode::spacebase); }
  void setIndirectCreation(Varnode *vn) { vn->fixtureSetFlag(Varnode::indirect_creation); }
  void setStackStore(Varnode *vn) { vn->setStackStore(); }
  void setIndirectStore(PcodeOp *op) { op->fixtureSetFlag(PcodeOp::indirect_store); }

  string varnodeState(Varnode *vn,const set<Varnode *> &live) const
  {
    ostringstream out;
    out << varnodeName(vn) << "{present=";
    if (live.find(vn) == live.end()) {
      out << "0}";
      return out.str();
    }
    out << "1,space=" << spaceName(vn->getSpace())
        << ",size=" << vn->getSize();
    // The iop-space offset encodes the referenced PcodeOp's process pointer
    // (newVarnodeIop).  Render it as the referenced op's fixture name on
    // both sides — a stable semantic identity with zero information loss
    // for this action (ActionDirectWrite never reads iop offsets).
    if (vn->getSpace()->getType() == IPTR_IOP)
      out << ",offset=" << opName((PcodeOp *)(uintp)vn->getOffset());
    else
      out << ",offset=" << std::hex << vn->getOffset();
    out << ",flags=" << std::hex << vn->getFlags() << std::dec
        << ",input=" << vn->isInput()
        << ",written=" << vn->isWritten()
        << ",persist=" << vn->isPersist()
        << ",dw=" << vn->isDirectWrite()
        << ",ss=" << vn->isStackStore()
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

  string pipState(const vector<Varnode *> &probe) const
  {
    ostringstream out;
    for(vector<Varnode *>::const_iterator iter=probe.begin();
        iter!=probe.end();++iter) {
      Varnode *vn = *iter;
      if (iter != probe.begin()) out << ',';
      out << varnodeName(vn) << ':'
          << (fd.getFuncProto().possibleInputParam(vn->getAddr(),vn->getSize()) ? 1 : 0);
    }
    return out.str();
  }

  string opState(PcodeOp *op) const
  {
    ostringstream out;
    out << opName(op) << "{opc=" << static_cast<int4>(op->code())
        << ",marker=" << op->isMarker()
        << ",istore=" << op->isIndirectStore()
        << ",nin=" << op->numInput()
        << ",inputs=[";
    for(int4 i=0;i<op->numInput();++i) {
      if (i != 0) out << ',';
      out << varnodeName(op->getIn(i));
    }
    out << "],output=" << varnodeName(op->getOut()) << '}';
    return out.str();
  }

  void dump(const string &caseName,const string &reg,const string &stage,
            int4 result,const vector<Varnode *> &probe) const
  {
    set<Varnode *> livevn = liveVarnodes();
    ostringstream vnstates;
    for(vector<Varnode *>::const_iterator iter=varnodes.begin();
        iter!=varnodes.end();++iter) {
      if (iter != varnodes.begin()) vnstates << ';';
      vnstates << varnodeState(*iter,livevn);
    }
    ostringstream opstates;
    for(vector<PcodeOp *>::const_iterator iter=ops.begin();
        iter!=ops.end();++iter) {
      if (iter != ops.begin()) opstates << ';';
      opstates << opState(*iter);
    }
    std::cout << "case=" << caseName << "|reg=" << reg
              << "|stage=" << stage << "|result=" << result
              << "|pip=[" << pipState(probe) << ']'
              << "|ops=[" << opstates.str() << ']'
              << "|varnodes=[" << vnstates.str() << "]\n";
  }
};

void prepare(Funcdata &fd)
{
  fd.clear();
  if (fd.getFuncProto().numParams() != 0)
    throw std::runtime_error("fixture requires an unlocked zero-param FuncProto");
}

void applyAndDump(Fixture &fixture,Funcdata &fd,const string &name,bool prop,
                  const vector<Varnode *> &probe)
{
  const string reg = prop ? "a" : "b";
  fixture.dump(name,reg,"before",-1,probe);
  ActionDirectWrite action("fixture",prop);
  int4 result = action.apply(fd);
  fixture.dump(name,reg,"after",result,probe);
}

// cc:1368 possibleInputParam input branch + cc:1381 plain COPY defs.
void runParamInputs(Funcdata &fd)
{
  prepare(fd);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *rdi = f.makeInput("rdi",8,0x38);	// x86-64 gcc param register
  Varnode *r10 = f.makeInput("r10",8,0x50);	// not a param register
  // NOTE: the spacebase flag is planted on r11 rather than the real RSP
  // (register 0x20) because Ghidra's Funcdata::setInputVarnode tail
  // (funcdata_varnode.cc:365-367) derives `unaffected` from the model
  // effectlist for RSP — a bank-level input-state derivation Rugra has not
  // ported.  ActionDirectWrite reads only the flag (cc:1364), so planting
  // it on a register whose input state is otherwise identical on both sides
  // keeps the fixture a strict same-input comparison.
  Varnode *r11 = f.makeInput("r11",8,0x58);
  f.setSpacebase(r11);
  PcodeOp *t = f.makeOp("t",CPUI_COPY,1,8);	// COPY of unmarked input
  f.setInput(t,r10,0);
  PcodeOp *t2 = f.makeOp("t2",CPUI_COPY,1,8);	// COPY of a marked param
  f.setInput(t2,rdi,0);
  f.insertEnd(t,block);
  f.insertEnd(t2,block);
  vector<Varnode *> probe;
  probe.push_back(rdi);
  probe.push_back(r10);
  probe.push_back(r11);
  applyAndDump(f,fd,"param_inputs",true,probe);
  applyAndDump(f,fd,"param_inputs",false,probe);
}

// cc:1382-1393 isStackStore COPY-source trace (single-level unroll).
void runStackStoreTrace(Funcdata &fd)
{
  prepare(fd);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *srcfree = f.makeFree("srcfree",8,0x60);
  Varnode *five = f.makeConstant("five",8,5);
  PcodeOp *ind = f.makeOp("ind",CPUI_INDIRECT,2,8);
  Varnode *iop = f.makeIop("ind_iop",ind);
  f.setInput(ind,srcfree,0);
  f.setInput(ind,iop,1);
  PcodeOp *c1 = f.makeOp("c1",CPUI_COPY,1,8);	// one COPY hop to the marker
  f.setInput(c1,ind->getOut(),0);
  PcodeOp *ss = f.makeOp("ss",CPUI_COPY,1,8);
  f.setInput(ss,c1->getOut(),0);
  f.setStackStore(ss->getOut());
  PcodeOp *use = f.makeOp("use",CPUI_COPY,1,8);
  f.setInput(use,ss->getOut(),0);
  PcodeOp *c2 = f.makeOp("c2",CPUI_COPY,1,8);	// two COPY hops: too deep
  f.setInput(c2,ind->getOut(),0);
  PcodeOp *c3 = f.makeOp("c3",CPUI_COPY,1,8);
  f.setInput(c3,c2->getOut(),0);
  PcodeOp *ss2 = f.makeOp("ss2",CPUI_COPY,1,8);
  f.setInput(ss2,c3->getOut(),0);
  f.setStackStore(ss2->getOut());
  Varnode *srcfree2 = f.makeFree("srcfree2",8,0x68);
  PcodeOp *ssn = f.makeOp("ssn",CPUI_COPY,1,8);	// stack store of unwritten src
  f.setInput(ssn,srcfree2,0);
  f.setStackStore(ssn->getOut());
  PcodeOp *d1 = f.makeOp("d1",CPUI_COPY,1,8);	// plain COPY of a marker out
  f.setInput(d1,ind->getOut(),0);
  PcodeOp *k = f.makeOp("k",CPUI_COPY,1,8);	// stack store of a constant
  f.setInput(k,five,0);
  f.setStackStore(k->getOut());
  f.insertEnd(ind,block);
  f.insertEnd(c1,block);
  f.insertEnd(ss,block);
  f.insertEnd(use,block);
  f.insertEnd(c2,block);
  f.insertEnd(c3,block);
  f.insertEnd(ss2,block);
  f.insertEnd(ssn,block);
  f.insertEnd(d1,block);
  f.insertEnd(k,block);
  vector<Varnode *> probe;
  applyAndDump(f,fd,"stackstore_trace",true,probe);
  applyAndDump(f,fd,"stackstore_trace",false,probe);
}

// cc:1401-1408 marker(INDIRECT) collection branch (a/b discriminating).
void runIndirectMarker(Funcdata &fd)
{
  prepare(fd);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *ia_in = f.makeFree("ia_in",8,0x70);
  Varnode *mma = f.makeFree("mma",8,0xa0);
  Varnode *mmb = f.makeFree("mmb",8,0xa4);
  Varnode *pwin = f.makeFree("pwin",8,0xa8);
  Varnode *pw2n = f.makeFree("pw2n",8,0xac);
  PcodeOp *iaddr = f.makeOpAt("iaddr",CPUI_INDIRECT,2,0x78); // addr changes
  Varnode *iop1 = f.makeIop("iaddr_iop",iaddr);
  f.setInput(iaddr,ia_in,0);
  f.setInput(iaddr,iop1,1);
  PcodeOp *use_i = f.makeOp("use_i",CPUI_COPY,1,8);
  f.setInput(use_i,iaddr->getOut(),0);
  Varnode *is_in = f.makeFree("is_in",8,0x80);
  PcodeOp *isame = f.makeOpAt("isame",CPUI_INDIRECT,2,0x80); // addr stable
  Varnode *iop2 = f.makeIop("isame_iop",isame);
  f.setInput(isame,is_in,0);
  f.setInput(isame,iop2,1);
  Varnode *ip_in = f.makeFree("ip_in",8,0x84);
  PcodeOp *ipersist = f.makeOpAt("ipersist",CPUI_INDIRECT,2,0x84); // persist out
  Varnode *iop3 = f.makeIop("ipersist_iop",ipersist);
  f.setInput(ipersist,ip_in,0);
  f.setInput(ipersist,iop3,1);
  f.setPersist(ipersist->getOut());
  PcodeOp *mm = f.makeOp("mm",CPUI_MULTIEQUAL,2,8);	// marker, not INDIRECT
  f.setInput(mm,mma,0);
  f.setInput(mm,mmb,1);
  PcodeOp *pw = f.makeOp("pw",CPUI_INT_ADD,2,8);	// persist + non-marker def
  f.setInput(pw,pwin,0);
  f.setInput(pw,pw2n,1);
  f.setPersist(pw->getOut());
  f.insertEnd(iaddr,block);
  f.insertEnd(use_i,block);
  f.insertEnd(isame,block);
  f.insertEnd(ipersist,block);
  f.insertEnd(mm,block);
  f.insertEnd(pw,block);
  vector<Varnode *> probe;
  applyAndDump(f,fd,"indirect_marker",true,probe);
  applyAndDump(f,fd,"indirect_marker",false,probe);
}

// cc:1427-1429 phase-2 push gate through call-based INDIRECTs.
void runPhase2Push(Funcdata &fd)
{
  prepare(fd);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *seven = f.makeConstant("seven",8,7);
  Varnode *seven2 = f.makeConstant("seven2",8,7);
  Varnode *eight = f.makeConstant("eight",8,8);

  PcodeOp *x = f.makeOp("x",CPUI_INDIRECT,2,8);	// call-based, no store flag
  Varnode *iopx = f.makeIop("x_iop",x);
  f.setInput(x,seven,0);
  f.setInput(x,iopx,1);
  PcodeOp *y = f.makeOp("y",CPUI_COPY,1,8);
  f.setInput(y,x->getOut(),0);
  PcodeOp *z = f.makeOp("z",CPUI_INDIRECT,2,8);	// indirect STORE variant
  Varnode *iopz = f.makeIop("z_iop",z);
  f.setInput(z,eight,0);
  f.setInput(z,iopz,1);
  f.setIndirectStore(z);
  PcodeOp *w = f.makeOp("w",CPUI_COPY,1,8);
  f.setInput(w,z->getOut(),0);
  PcodeOp *n = f.makeOp("n",CPUI_COPY,1,8);
  f.setInput(n,seven2,0);
  f.insertEnd(x,block);
  f.insertEnd(y,block);
  f.insertEnd(z,block);
  f.insertEnd(w,block);
  f.insertEnd(n,block);
  vector<Varnode *> probe;
  applyAndDump(f,fd,"phase2_push",true,probe);
  applyAndDump(f,fd,"phase2_push",false,probe);
}

// cc:1395-1399 non-COPY exclusions + cc:1410-1414 constant branches.
void runNoncopyDefs(Funcdata &fd)
{
  prepare(fd);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *hi = f.makeFree("hi",4,0x90);
  Varnode *lo = f.makeFree("lo",4,0x94);
  Varnode *f1 = f.makeFree("f1",8,0x98);
  Varnode *f2 = f.makeFree("f2",8,0x9c);
  Varnode *subin = f.makeFree("subin",8,0xb0);
  Varnode *one = f.makeConstant("one",8,1);
  PcodeOp *piece = f.makeOp("piece",CPUI_PIECE,2,8);
  f.setInput(piece,hi,0);
  f.setInput(piece,lo,1);
  PcodeOp *sub = f.makeOp("sub",CPUI_SUBPIECE,2,4);
  f.setInput(sub,subin,0);
  f.setInput(sub,one,1);
  PcodeOp *ad = f.makeOp("ad",CPUI_INT_ADD,2,8);
  f.setInput(ad,f1,0);
  f.setInput(ad,f2,1);
  PcodeOp *mul = f.makeOp("mul",CPUI_COPY,1,8);
  f.setInput(mul,ad->getOut(),0);
  Varnode *iz = f.makeConstant("iz",8,0);
  f.setIndirectCreation(iz);
  f.insertEnd(piece,block);
  f.insertEnd(sub,block);
  f.insertEnd(ad,block);
  f.insertEnd(mul,block);
  vector<Varnode *> probe;
  probe.push_back(hi);
  probe.push_back(lo);
  applyAndDump(f,fd,"noncopy_defs",true,probe);
  applyAndDump(f,fd,"noncopy_defs",false,probe);
}

// cc:1428 isIndirectStore push leg: an INDIRECT with equal in/out addresses
// (no ④ mark under b) whose output is tainted from a persist input — the
// w2 COPY can only be marked under the b registration via the store leg.
void runIndirectStorePush(Funcdata &fd)
{
  prepare(fd);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  // 0xe0 is outside both the model's unaffected set (callee-saved regs) and
  // its input-param entries, so the bank-level input state is identical on
  // both sides (see the r11 note in runParamInputs).
  const uintb at = 0xe0;
  Varnode *iszin = f.makeInput("iszin",8,at);
  f.setPersist(iszin);
  PcodeOp *isz = f.makeOpAt("isz",CPUI_INDIRECT,2,at); // equal addresses
  Varnode *iop4 = f.makeIop("isz_iop",isz);
  f.setInput(isz,iszin,0);
  f.setInput(isz,iop4,1);
  f.setIndirectStore(isz);
  PcodeOp *w2 = f.makeOp("w2",CPUI_COPY,1,8);
  f.setInput(w2,isz->getOut(),0);
  f.insertEnd(isz,block);
  f.insertEnd(w2,block);
  vector<Varnode *> probe;
  applyAndDump(f,fd,"indirect_store_push",true,probe);
  applyAndDump(f,fd,"indirect_store_push",false,probe);
}

// fspec.cc:4369 voidinputlock gate.  Runs last: setInputLock(true) also
// latches modellock (fspec.cc:3925), which possibleInputParam ignores.
void runVoidInputLock(Funcdata &fd)
{
  prepare(fd);
  fd.getFuncProto().setInputLock(true);
  Fixture f(fd);
  BlockBasic *block = f.makeBlock("b0");
  Varnode *rdi = f.makeInput("rdi",8,0x38);
  PcodeOp *v = f.makeOp("v",CPUI_COPY,1,8);
  f.setInput(v,rdi,0);
  f.insertEnd(v,block);
  vector<Varnode *> probe;
  probe.push_back(rdi);
  applyAndDump(f,fd,"void_input_lock",true,probe);
  applyAndDump(f,fd,"void_input_lock",false,probe);
  fd.getFuncProto().setInputLock(false);
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

    runParamInputs(*fd);
    runStackStoreTrace(*fd);
    runIndirectMarker(*fd);
    runPhase2Push(*fd);
    runIndirectStorePush(*fd);
    runNoncopyDefs(*fd);
    runVoidInputLock(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: actiondw_copydef_1204 SPEC_ROOT CURL_BINARY\n";
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
