/*
 * RULE-PORT-EARLYREMOVAL-0001
 *
 * Locked Ghidra 12.0.4 oracle for RuleEarlyRemoval::applyOp,
 * Heritage::deadRemovalAllowedSeen, AddrSpace::doesDeadcode, and the default
 * Rule::getOpList dispatch contract.  Every mutation is performed through
 * Funcdata/PcodeOp/Varnode public APIs.  The runner adds three fixture-only
 * Heritage state accessors to its immutable archive so pass and deadremoved
 * can be observed without changing any production algorithm.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "ruleaction.hh"

#include <algorithm>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::ostringstream;
using std::string;
using std::vector;

static bool containsOp(list<PcodeOp *>::const_iterator iter,
                       list<PcodeOp *>::const_iterator enditer,
                       const PcodeOp *needle)
{
  for(;iter!=enditer;++iter)
    if (*iter == needle) return true;
  return false;
}

static bool containsVarnode(const Funcdata &fd,const Varnode *needle)
{
  if (needle == (const Varnode *)0) return false;
  for(VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter)
    if (*iter == needle) return true;
  return false;
}

static bool containsBlockOp(const BlockBasic *block,const PcodeOp *needle)
{
  for(list<PcodeOp *>::const_iterator iter=block->beginOp();
      iter!=block->endOp();++iter)
    if (*iter == needle) return true;
  return false;
}

class Graph {
public:
  Funcdata fd;
  Architecture &arch;
  AddrSpace *code;
  AddrSpace *unique;
  AddrSpace *other;
  BlockBasic *block;
  uintb nextPc;
  uintb nextOther;

  Graph(Architecture &a,const string &name,uintb base,int4 pass)
    : fd(name,name,a.symboltab->getGlobalScope(),
         Address(a.getDefaultCodeSpace(),base),(FunctionSymbol *)0,0x100),
      arch(a),code(a.getDefaultCodeSpace()),unique(a.getUniqueSpace()),
      other(a.getSpaceByName("OTHER")),block((BlockBasic *)0),
      nextPc(base),nextOther(0x9000)
  {
    if (other == (AddrSpace *)0)
      other = a.getSpaceByName("other");
    if (code == (AddrSpace *)0 || unique == (AddrSpace *)0 ||
        other == (AddrSpace *)0)
      throw std::runtime_error("required code/unique/OTHER space is absent");
    BlockGraph &blocks = const_cast<BlockGraph &>(fd.getBasicBlocks());
    block = blocks.newBlockBasic(&fd);
    fd.fixtureSetHeritagePass(pass);
  }

  PcodeOp *newOp(OpCode opcode,int4 inputCount,bool withOutput,AddrSpace *space)
  {
    PcodeOp *op = fd.newOp(inputCount,Address(code,nextPc++));
    fd.opSetOpcode(op,opcode);
    if (inputCount > 0)
      fd.opSetInput(op,fd.newConstant(4,nextPc),0);
    if (withOutput) {
      if (space == unique)
        fd.newUniqueOut(4,op);
      else {
        Varnode *out = fd.newVarnode(4,Address(space,nextOther++));
        fd.opSetOutput(op,out);
      }
    }
    fd.opInsertEnd(op,block);
    return op;
  }
};

struct CaseSpec {
  const char *name;
  OpCode opcode;
  int4 pass;
  int4 deadDelay;
  bool withOutput;
  bool indirectSource;
  bool descendant;
  bool writeMask;
  bool autoLive;
  bool otherSpace;
};

static void runCase(Architecture &arch,const CaseSpec &spec,uintb base)
{
  Graph graph(arch,spec.name,base,spec.pass);
  AddrSpace *outSpace = spec.otherSpace ? graph.other : graph.unique;
  graph.fd.setDeadCodeDelay(outSpace,spec.deadDelay);
  PcodeOp *op = graph.newOp(spec.opcode,1,spec.withOutput,outSpace);
  if (spec.indirectSource)
    op->setIndirectSource();
  Varnode *input = op->getIn(0);
  Varnode *output = op->getOut();
  if (output != (Varnode *)0) {
    if (spec.writeMask) output->setWriteMask();
    if (spec.autoLive) output->setAutoLiveHold();
  }
  if (spec.descendant) {
    if (output == (Varnode *)0)
      throw std::runtime_error("descendant case requires an output");
    PcodeOp *sink = graph.newOp(CPUI_COPY,1,true,graph.unique);
    graph.fd.opSetInput(sink,output,0);
  }

  const int4 descBefore = output == (Varnode *)0 ? -1 :
    (int4)std::distance(output->beginDescend(),output->endDescend());
  const int4 inputDescBefore =
    (int4)std::distance(input->beginDescend(),input->endDescend());
  const bool callBefore = op->isCall();
  const bool indirectBefore = op->isIndirectSource();
  const bool writeBefore = output != (Varnode *)0 && output->isWriteMask();
  const bool autoBefore = output != (Varnode *)0 && output->isAutoLive();
  const bool spaceDeadcode = output != (Varnode *)0 &&
    output->getSpace()->doesDeadcode();

  RuleEarlyRemoval rule("deadcode");
  int4 result = rule.applyOp(op,graph.fd);
  const int4 inputDescAfter =
    (int4)std::distance(input->beginDescend(),input->endDescend());
  const bool alive = containsOp(graph.fd.beginOpAlive(),graph.fd.endOpAlive(),op);
  const bool dead = containsOp(graph.fd.beginOpDead(),graph.fd.endOpDead(),op);
  const bool blockMember = containsBlockOp(graph.block,op);
  const bool outputPresent = containsVarnode(graph.fd,output);
  const bool outputAttached = op->getOut() != (Varnode *)0;
  const int4 deadremoved = graph.fd.fixtureGetDeadRemoved(outSpace);

  std::cout << "case=" << spec.name
            << "|result=" << result
            << "|pass=" << spec.pass
            << "|delay=" << spec.deadDelay
            << "|call=" << callBefore
            << "|indirect=" << indirectBefore
            << "|output=" << (output == (Varnode *)0 ? 0 : 1)
            << "|desc=" << descBefore
            << "|writemask=" << writeBefore
            << "|autolive=" << autoBefore
            << "|space_deadcode=" << spaceDeadcode
            << "|deadremoved=" << deadremoved
            << "|alive=" << alive
            << "|dead=" << dead
            << "|block=" << blockMember
            << "|output_present=" << outputPresent
            << "|output_attached=" << outputAttached
            << "|input_desc=" << inputDescBefore << "->" << inputDescAfter
            << '\n';

  if (string(spec.name) == "neither_allowed") {
    std::cout << "residual=nullable_input_arity"
              << "|post_num_inputs=" << op->numInput()
              << "|slot0_null=" << (op->getIn(0)==(Varnode *)0 ? 1 : 0)
              << "|status=MISMATCH" << '\n';
  }
}

static string joinOpcodes(const vector<uint4> &opcodes,bool typedOnly)
{
  ostringstream out;
  bool first = true;
  for(vector<uint4>::const_iterator iter=opcodes.begin();iter!=opcodes.end();++iter) {
    if (typedOnly && (*iter == 0 || *iter == 45)) continue;
    if (!first) out << ',';
    first = false;
    out << *iter;
  }
  return out.str();
}

static string aliveOpcodes(const Funcdata &fd)
{
  ostringstream out;
  bool first = true;
  for(list<PcodeOp *>::const_iterator iter=fd.beginOpAlive();
      iter!=fd.endOpAlive();++iter) {
    if (!first) out << ',';
    first = false;
    out << static_cast<int4>((*iter)->code());
  }
  return out.str();
}

static void runDispatch(Architecture &arch)
{
  Graph graph(arch,"typed_dispatch",0x7200,1);
  graph.fd.setDeadCodeDelay(graph.unique,0);
  RuleEarlyRemoval *rule = new RuleEarlyRemoval("deadcode");
  vector<uint4> raw;
  rule->getOpList(raw);
  vector<uint4> typed;
  for(vector<uint4>::const_iterator iter=raw.begin();iter!=raw.end();++iter)
    if (*iter != 0 && *iter != 45) typed.push_back(*iter);

  std::cout << "typed_oplist=" << joinOpcodes(raw,true)
            << "|count=" << typed.size() << '\n';
  std::cout << "residual=raw_dispatch|raw=" << joinOpcodes(raw,false)
            << "|count=" << raw.size()
            << "|untyped=0,45|status=MISMATCH" << '\n';

  for(vector<uint4>::const_iterator iter=typed.begin();iter!=typed.end();++iter)
    graph.newOp((OpCode)*iter,0,true,graph.unique);

  ActionPool pool(0,"earlyremoval_dispatch");
  pool.addRule(rule);
  int4 result = pool.perform(graph.fd);
  size_t deadCount = (size_t)std::distance(graph.fd.beginOpDead(),
                                           graph.fd.endOpDead());
  std::cout << "dispatch|perform=" << result
            << "|status=" << pool.getStatus()
            << "|tests=" << rule->getNumTests()
            << "|apply=" << rule->getNumApply()
            << "|alive=" << aliveOpcodes(graph.fd)
            << "|dead_count=" << deadCount
            << "|deadremoved="
            << graph.fd.fixtureGetDeadRemoved(graph.unique)
            << '\n';
}

static void run(Architecture &arch)
{
  const CaseSpec cases[] = {
    {"call_guard",CPUI_CALL,1,0,true,false,false,false,false,false},
    {"indirect_guard",CPUI_COPY,1,0,true,true,false,false,false,false},
    {"no_output_guard",CPUI_COPY,1,0,false,false,false,false,false,false},
    {"descendant_guard",CPUI_COPY,1,0,true,false,true,false,false,false},
    {"autolive_only",CPUI_COPY,1,0,true,false,false,false,true,false},
    {"write_and_autolive",CPUI_COPY,1,0,true,false,false,true,true,false},
    {"write_mask_only",CPUI_COPY,1,0,true,false,false,true,false,false},
    {"neither_allowed",CPUI_COPY,1,0,true,false,false,false,false,false},
    {"delay_zero_equal",CPUI_COPY,0,0,true,false,false,false,false,false},
    {"delay_one_equal",CPUI_COPY,1,1,true,false,false,false,false,false},
    {"delay_one_after",CPUI_COPY,2,1,true,false,false,false,false,false},
    {"no_deadcode_other",CPUI_COPY,0,0,true,false,false,false,false,true},
  };
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i)
    runCase(arch,cases[i],0x7000 + (uintb)i * 0x20);
  runDispatch(arch);
  std::cout << "residual=heritage_manager_projection"
            << "|scope=full_manager_state_and_late_generation_warning"
            << "|status=UNTESTED" << '\n';
}

} // anonymous namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: rule_earlyremoval_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    vector<string> specPaths;
    specPaths.push_back(argv[1]);
    startDecompilerLibrary(specPaths);
    {
      std::ostringstream diagnostics;
      BfdArchitecture architecture(argv[2],"default",&diagnostics);
      DocumentStorage store;
      architecture.init(store);
      architecture.readLoaderSymbols("::");
      Funcdata *getstr = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
      if (getstr == (Funcdata *)0 || getstr->getAddress().getOffset() != 0x36d0)
        throw std::runtime_error("GetStr input identity drifted");
      if (architecture.archid != "x86:LE:64:default:gcc")
        throw std::runtime_error("runtime architecture/compiler drifted: " +
                                 architecture.archid);
      run(architecture);
    }
    shutdownDecompilerLibrary();
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
