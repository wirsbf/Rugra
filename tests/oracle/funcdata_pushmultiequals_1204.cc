/* FUNCDATA-PUSHMULTIEQUALS-0001: locked Ghidra 12.0.4 fixture.
   Drives Funcdata::pushMultiequals (funcdata_block.cc:84-171) on three
   hand-built block graphs that share the cc:84 shape (bb = single-out
   do-nothing block whose MULTIEQUAL feeds an out-block MULTIEQUAL):
     reader_beyond   - needreplace path: a reader beyond outblock forces the
                       artificial MULTIEQUAL + descend rewrite (cc:126-127,131-169)
     dead_edge_only  - needreplace=false path: every read goes through the dead
                       edge, nothing is constructed (cc:129)
     addrtied_unique - neednewunique path: addrtied origvn feeding a
                       same-address MULTIEQUAL in outblock forces a unique
                       replacement varnode (cc:118-122,132-133)
   The Funcdata is a virgin queryFunction result (no decompilation ran), so
   Varnode create-index and SeqNum counters start at zero on both sides.
*/
#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::list;
using std::map;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

// Funcdata::pushMultiequals and Varnode::setFlags are private in the oracle
// (funcdata.hh:119, varnode.hh:164). The fixture reaches them through the
// explicit-template-instantiation access idiom: the address-of-private in an
// explicit instantiation's template-argument list is not access-checked, and
// the stolen member pointers are stored in explicit (non-inline) statics so
// the fixture compiles as C++11 like the rest of the oracle harness.
template <typename Tag>
struct PMember {
    static typename Tag::type ptr;
};
template <typename Tag>
typename Tag::type PMember<Tag>::ptr = nullptr;

template <typename Tag, typename Tag::type P>
struct StealRegistration {
    static bool init() { PMember<Tag>::ptr = P; return true; }
    static const bool registered;
};
template <typename Tag, typename Tag::type P>
const bool StealRegistration<Tag, P>::registered = StealRegistration<Tag, P>::init();

struct PushMultiTag {
    typedef void (ghidra::Funcdata::*type)(ghidra::BlockBasic *);
};
struct SetFlagsTag {
    typedef void (ghidra::Varnode::*type)(ghidra::uint4) const;
};

} // anonymous namespace

template struct StealRegistration<PushMultiTag, &ghidra::Funcdata::pushMultiequals>;
template struct StealRegistration<SetFlagsTag, &ghidra::Varnode::setFlags>;

namespace {

inline void pushMultiequals(Funcdata *fd,BlockBasic *bb)
{
  (fd->*PMember<PushMultiTag>::ptr)(bb);
}

inline void varnodeSetFlags(Varnode *vn,uint4 fl)
{
  (vn->*PMember<SetFlagsTag>::ptr)(fl);
}

struct Graph {
  BlockBasic *p1;			// pred of m (edge 1)
  BlockBasic *p2;			// pred of m (edge 2)
  BlockBasic *m;			// dying block, single out edge to o
  BlockBasic *a;			// alternate pred of o
  BlockBasic *o;			// out block: in[0] = m, in[1] = a
  BlockBasic *d;			// block beyond o
};

BlockBasic *newBlock(Funcdata *fd)
{
  BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
  return graph.newBlockBasic(fd);
}

Graph buildGraph(Funcdata *fd)
{
  Graph g;
  g.p1 = newBlock(fd);
  g.p2 = newBlock(fd);
  g.m = newBlock(fd);
  g.a = newBlock(fd);
  g.o = newBlock(fd);
  g.d = newBlock(fd);
  BlockGraph &graph = const_cast<BlockGraph &>(fd->getBasicBlocks());
  graph.addEdge(g.p1,g.m);
  graph.addEdge(g.p2,g.m);
  graph.addEdge(g.m,g.o);		// o in[0] = m  (dead edge slot 0)
  graph.addEdge(g.a,g.o);		// o in[1] = a
  graph.addEdge(g.o,g.d);
  return g;
}

// Outputs use the newVarnode+opSetOutput idiom (the same idiom
// pushMultiequals itself uses at cc:135/151 for replacevn), so the space
// assignment is identical on both sides of the fixture.
PcodeOp *makePhi(Funcdata *fd,BlockBasic *blk,Varnode *in0,Varnode *in1,
		 const Address &outaddr,uintb pc)
{
  PcodeOp *op = fd->newOp(2,Address(fd->getArch()->getDefaultCodeSpace(),pc));
  fd->opSetOpcode(op,CPUI_MULTIEQUAL);
  fd->opSetOutput(op,fd->newVarnode(8,outaddr));
  fd->opSetInput(op,in0,0);
  fd->opSetInput(op,in1,1);
  fd->opInsertEnd(op,blk);
  return op;
}

PcodeOp *makeCopy(Funcdata *fd,BlockBasic *blk,Varnode *in0,
		  const Address &outaddr,uintb pc)
{
  PcodeOp *op = fd->newOp(1,Address(fd->getArch()->getDefaultCodeSpace(),pc));
  fd->opSetOpcode(op,CPUI_COPY);
  fd->opSetOutput(op,fd->newVarnode(8,outaddr));
  fd->opSetInput(op,in0,0);
  fd->opInsertEnd(op,blk);
  return op;
}

// Canonicalized snapshot: ops of [m, o, d] in block order, each tagged with
// its block label and slot-in-block; varnode table in first-appearance order
// (create index, size, space index, is-const, offset); the descend list of
// origvn as canonical (block,slot) pairs; bank counts.
string snapshot(Funcdata *fd,const Graph &g,Varnode *origvn)
{
  static const char *labels[3] = { "m", "o", "d" };
  BlockBasic *blocks[3];
  blocks[0] = g.m;
  blocks[1] = g.o;
  blocks[2] = g.d;

  vector<string> opTags;
  vector<PcodeOp *> ops;
  map<Varnode *,int4> varIndex;
  vector<Varnode *> vars;
  for(int4 b=0;b<3;++b) {
    int4 slot = 0;
    for(list<PcodeOp *>::const_iterator iter=blocks[b]->beginOp();
	iter!=blocks[b]->endOp();++iter,++slot) {
      PcodeOp *op = *iter;
      ostringstream tag;
      tag << labels[b] << ':' << slot << ':' << (int4)op->code()
	  << "/t" << op->getSeqNum().getTime();
      opTags.push_back(tag.str());
      ops.push_back(op);
      Varnode *outvn = op->getOut();
      if (outvn != (Varnode *)0 && varIndex.find(outvn) == varIndex.end()) {
	varIndex[outvn] = vars.size();
	vars.push_back(outvn);
      }
      for(int4 i=0;i<op->numInput();++i) {
	Varnode *invn = op->getIn(i);
	if (invn == (Varnode *)0) continue;
	if (varIndex.find(invn) == varIndex.end()) {
	  varIndex[invn] = vars.size();
	  vars.push_back(invn);
	}
      }
    }
  }

  ostringstream out;
  out << "ops[";
  for(int4 index=0;index<ops.size();++index) {
    if (index != 0) out << ';';
    PcodeOp *op = ops[index];
    out << opTags[index] << "/o";
    if (op->getOut() == (Varnode *)0) out << '_';
    else out << 'v' << varIndex[op->getOut()];
    out << "/i";
    for(int4 i=0;i<op->numInput();++i) {
      if (i != 0) out << ',';
      Varnode *invn = op->getIn(i);
      if (invn == (Varnode *)0) out << '_';
      else out << 'v' << varIndex[invn];
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
    else out << ":x" << vn->getOffset();
  }
  out << "]origdesc=";
  bool first = true;
  for(list<PcodeOp *>::const_iterator iter=origvn->beginDescend();
      iter!=origvn->endDescend();++iter) {
    if (!first) out << ',';
    first = false;
    PcodeOp *op = *iter;
    for(int4 b=0;b<3;++b) {
      int4 slot = 0;
      for(list<PcodeOp *>::const_iterator iter2=blocks[b]->beginOp();
	  iter2!=blocks[b]->endOp();++iter2,++slot) {
	if (*iter2 == op) {
	  out << labels[b] << ':' << slot;
	  b = 3;
	  break;
	}
      }
    }
  }
  out << "]counts=" << ops.size()
      << ',' << std::distance(fd->beginOpAlive(),fd->endOpAlive())
      << ',' << std::distance(fd->beginOpDead(),fd->endOpDead())
      << ',' << fd->numVarnodes();
  return out.str();
}

void runReaderBeyond(BfdArchitecture &architecture,const string &functionName)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw runtime_error("function not found: " + functionName);
  AddrSpace *ram = architecture.getDefaultCodeSpace();
  Graph g = buildGraph(fd);
  Varnode *v1 = fd->newVarnode(8,Address(ram,0x1000));
  Varnode *v2 = fd->newVarnode(8,Address(ram,0x1010));
  Varnode *w = fd->newVarnode(8,Address(ram,0x1020));
  PcodeOp *origphi = makePhi(fd,g.m,v1,v2,Address(ram,0x2000),0x3000);
  Varnode *origvn = origphi->getOut();
  makePhi(fd,g.o,origvn,w,Address(ram,0x2010),0x3010);
  makeCopy(fd,g.d,origvn,Address(ram,0x2020),0x3020);
  pushMultiequals(fd,g.m);
  std::cout << "reader_beyond|after=" << snapshot(fd,g,origvn) << '\n';
}

void runDeadEdgeOnly(BfdArchitecture &architecture,const string &functionName)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw runtime_error("function not found: " + functionName);
  AddrSpace *ram = architecture.getDefaultCodeSpace();
  Graph g = buildGraph(fd);
  Varnode *v1 = fd->newVarnode(8,Address(ram,0x1000));
  Varnode *v2 = fd->newVarnode(8,Address(ram,0x1010));
  Varnode *w = fd->newVarnode(8,Address(ram,0x1020));
  PcodeOp *origphi = makePhi(fd,g.m,v1,v2,Address(ram,0x2000),0x3100);
  Varnode *origvn = origphi->getOut();
  makePhi(fd,g.o,origvn,w,Address(ram,0x2010),0x3110);
  pushMultiequals(fd,g.m);
  std::cout << "dead_edge_only|after=" << snapshot(fd,g,origvn) << '\n';
}

void runAddrtiedUnique(BfdArchitecture &architecture,const string &functionName)
{
  Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(functionName);
  if (fd == (Funcdata *)0) throw runtime_error("function not found: " + functionName);
  AddrSpace *ram = architecture.getDefaultCodeSpace();
  Graph g = buildGraph(fd);
  Varnode *v1 = fd->newVarnode(8,Address(ram,0x1000));
  Varnode *v2 = fd->newVarnode(8,Address(ram,0x1010));
  Varnode *w = fd->newVarnode(8,Address(ram,0x1020));
  PcodeOp *origphi = makePhi(fd,g.m,v1,v2,Address(ram,0x2000),0x3200);
  Varnode *origvn = origphi->getOut();
  // cc:118-122 precondition: addrtied origvn feeding a MULTIEQUAL at the
  // SAME address in outblock -> neednewunique.
  varnodeSetFlags(origvn,Varnode::addrtied|Varnode::insert);
  makePhi(fd,g.o,origvn,w,Address(ram,0x2000),0x3210);
  makeCopy(fd,g.d,origvn,Address(ram,0x2020),0x3220);
  pushMultiequals(fd,g.m);
  std::cout << "addrtied_unique|after=" << snapshot(fd,g,origvn) << '\n';
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
    runReaderBeyond(architecture,"GetStr");
    runDeadEdgeOnly(architecture,"main_free");
    runAddrtiedUnique(architecture,"hugehelp");
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: funcdata_pushmultiequals_1204 SPEC_ROOT CURL_BINARY\n";
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
