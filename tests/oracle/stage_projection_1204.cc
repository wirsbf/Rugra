/*
 * Stage projection producer for the locked Ghidra 12.0.4 decompiler.
 *
 * This is a fixture wrapper: it only drives the production Action tree and
 * reads observation points (including protected Action counters exposed by
 * the test-only access macros).  It does not alter Action, Rule, or Funcdata
 * semantics.
 */

#include <bits/stdc++.h>

#define private public
#define protected public
#include "action.hh"
#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "op.hh"
#include "space.hh"
#include "varnode.hh"
#undef protected
#undef private

using namespace ghidra;
using std::ostream;
using std::string;
using std::vector;

namespace {

const char *ORACLE_COMMIT =
    "e40ed13014025f82488b1f8f7bca566894ac376b";

struct ActionNode {
  Action *action;
  string path;
  bool group;
  ActionNode(Action *a,const string &p,bool g) : action(a),path(p),group(g) {}
};

struct Event {
  ActionNode node;
  uint64_t seq;
  uint4 tests;
  uint4 apply;
  Event(const ActionNode &n,uint64_t s)
      : node(n),seq(s),tests(n.action->getNumTests()),
        apply(n.action->getNumApply()) {}
};

// RUGRA-GLUE: fixture-only tree enumeration.  The production tree remains
// untouched; DFS follows ActionGroup insertion order.
static void collectTree(Action *action,const string &path,
                        vector<ActionNode> &all,vector<ActionNode> &leaves)
{
  ActionGroup *group = dynamic_cast<ActionGroup *>(action);
  const bool isGroup = group != (ActionGroup *)0;
  ActionNode node(action,path,isGroup);
  all.push_back(node);
  if (!isGroup) {
    leaves.push_back(node);
    return;
  }
  for (vector<Action *>::iterator iter=group->list.begin();
       iter!=group->list.end();++iter)
    collectTree(*iter,path+":"+(*iter)->getName(),all,leaves);
}

static bool isPrefix(const string &prefix,const string &path)
{
  return path == prefix ||
      (path.size() > prefix.size() &&
       path.compare(0,prefix.size(),prefix) == 0 &&
       path[prefix.size()] == ':');
}

static ActionNode findHit(const vector<ActionNode> &leaves)
{
  for (vector<ActionNode>::const_iterator iter=leaves.begin();
       iter!=leaves.end();++iter) {
    uint4 status = iter->action->status;
    if (status == Action::status_breakstarthit ||
        status == Action::status_actionbreak)
      return *iter;
  }
  return ActionNode((Action *)0,string(),false);
}

// The complete descriptor grammar is intentionally centralized here.  This
// is the only function that decides how constant, named-space, unique, and
// null Varnodes are rendered in the projection.
//
// Spaceid constants: SLEIGH encodes the "space" input of a dynamic LOAD or
// STORE as the raw AddrSpace object pointer (sleigh.cc:236/269:
// `(uintb)(uintp)spc`), which Ghidra itself decodes back with
// Varnode::getSpaceFromConst (constseq.cc:911, coreaction.cc:976).  The
// pointer value changes between processes (ASLR), so an exact-match table
// of live AddrSpace object addresses is used to render the stable space
// name instead (`s:<name>`); the pointer encoding itself is not
// reproducible by any second run or by the Rust side and carries no
// cross-run semantics.
static std::map<uintb, string> g_spaceIdNames;

static void writeSeqNum(ostream &out,const PcodeOp *op)
{
  out << std::hex << op->getAddr().getOffset() << ':' << op->getTime()
      << std::dec;
}

// slotOp is the PcodeOp whose output/input slot is being rendered; it owns
// any fspec-space varnode (the FuncCallSpecs of that call site), so its
// SeqNum is the stable pseudonym.  iopNames maps live PcodeOp object
// addresses to SeqNum strings for iop-space references (pointer encodings
// from Funcdata::newVarnodeCallSpecs / newVarnodeIop change between
// processes exactly like the spaceid constant above).
static void writeVarnodeDescriptor(ostream &out,const Varnode *vn,
                                   const PcodeOp *slotOp,
                                   const std::map<const PcodeOp *,string> *iopNames)
{
  if (vn == (const Varnode *)0) {
    out << '-';
    return;
  }
  AddrSpace *space = vn->getSpace();
  out << std::hex;
  if (space->getType() == IPTR_CONSTANT) {
    if (vn->getSize() == sizeof(AddrSpace *)) {
      std::map<uintb,string>::const_iterator found =
          g_spaceIdNames.find(vn->getOffset());
      if (found != g_spaceIdNames.end()) {
        out << "s:" << found->second;
        out << std::dec;
        return;
      }
    }
    out << "c:" << vn->getOffset() << ':' << std::dec << vn->getSize();
  }
  else if (space->getName() == "unique")
    out << "u:" << vn->getOffset() << ':' << std::dec << vn->getSize();
  else if (space->getName() == "fspec")
  {
    // One call site owns exactly one FuncCallSpecs; render the call op's
    // own SeqNum so distinct call sites keep distinct identities.
    out << "f:";
    writeSeqNum(out,slotOp);
  }
  else if (space->getName() == "iop")
  {
    // Reference to another PcodeOp; render the referenced op's SeqNum
    // from the live-op table of this snapshot.
    out << "o:";
    std::map<const PcodeOp *,string>::const_iterator found =
        iopNames->find((const PcodeOp *)vn->getOffset());
    if (found != iopNames->end())
      out << found->second;
    else
      out << '-';
  }
  else
    out << "n:" << space->getName() << ':' << vn->getOffset() << ':'
        << std::dec << vn->getSize();
  out << std::dec;
}

static void writeOp(ostream &out,const PcodeOp *op,
                    const std::map<const PcodeOp *,string> &iopNames)
{
  // d= follows op.cc:380-381 semantics: dead OR unattached (no parent).
  out << std::hex << op->getAddr().getOffset() << ':' << op->getTime()
      << std::dec << ' ' << op->getOpName()
      << " d=" << ((op->isDead() || op->getParent() == (BlockBasic *)0) ? 1 : 0)
      << " out=";
  writeVarnodeDescriptor(out,op->getOut(),op,&iopNames);
  out << " in=";
  for (int4 slot=0;slot<op->numInput();++slot) {
    if (slot != 0) out << ',';
    writeVarnodeDescriptor(out,op->getIn(slot),op,&iopNames);
  }
  if (op->numInput() == 0) out << '-';
  out << '\n';
}

static void writeSnapshot(ostream &out,uint64_t seq,Funcdata &fd)
{
  uint64_t count = 0;
  std::map<const PcodeOp *,string> iopNames;
  for (PcodeOpTree::const_iterator iter=fd.beginOpAll();
       iter!=fd.endOpAll();++iter) {
    std::ostringstream rendered;
    writeSeqNum(rendered,(*iter).second);
    iopNames[(*iter).second] = rendered.str();
    ++count;
  }
  out << "@SNAP " << seq << " ops " << count << '\n';
  for (PcodeOpTree::const_iterator iter=fd.beginOpAll();
       iter!=fd.endOpAll();++iter)
    writeOp(out,(*iter).second,iopNames);
}

static void beginEvent(ostream &out,vector<Event> &active,
                       const ActionNode &node,uint64_t &nextSeq)
{
  if (!node.action) return;
  for (vector<Event>::const_iterator iter=active.begin();
       iter!=active.end();++iter)
    if (iter->node.path == node.path)
      return;
  uint64_t seq = nextSeq++;
  out << "@BEGIN " << seq << ' ' << node.path << '\n';
  active.push_back(Event(node,seq));
}

static void endEvent(ostream &out,vector<Event> &active,size_t index,
                     Funcdata &fd,int4 resultOverride,bool useOverride)
{
  Event event = active[index];
  Action *action = event.node.action;
  int4 count = action->count;
  int4 result = useOverride ? resultOverride : count;
  out << "@END " << event.seq << ' ' << event.node.path
      << " result=" << result << " count=" << count
      << " tests=" << (action->getNumTests()-event.tests)
      << " apply=" << (action->getNumApply()-event.apply) << '\n';
  writeSnapshot(out,event.seq,fd);
  active.erase(active.begin()+static_cast<ptrdiff_t>(index));
}

static void closeInactive(ostream &out,vector<Event> &active,Funcdata &fd,
                          const string &currentPath)
{
  for (size_t i=active.size();i>0;--i) {
    size_t index = i-1;
    Action *action = active[index].node.action;
    // Spec (iii): the restart root stays open across restart rounds; its
    // own status flips to status_start at a restart boundary while its
    // apply() is still on the stack, so it is exempt from the status test.
    bool root = active[index].node.path == "universal";
    bool keep = root ||
        (isPrefix(active[index].node.path,currentPath) &&
         (action->status == Action::status_mid ||
          action->status == Action::status_breakstarthit ||
          action->status == Action::status_actionbreak));
    if (!keep)
      endEvent(out,active,index,fd,0,false);
  }
}

static void closeAll(ostream &out,vector<Event> &active,Funcdata &fd,
                     int4 rootResult,bool useRootResult)
{
  while (!active.empty()) {
    size_t index = active.size()-1;
    bool root = active[index].node.path == "universal";
    endEvent(out,active,index,fd,rootResult,useRootResult && root);
  }
}

static int run(const string &specRoot,const string &binary,uintb entry,
               const string &output,const string &binarySha,
               const string &producer,const string &options)
{
  vector<string> specPaths(1,specRoot);
  startDecompilerLibrary(specPaths);
  try {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(
        Address(architecture.getDefaultCodeSpace(),entry));
    if (!fd)
      throw std::runtime_error("function entry was not found in BFD symbols");
    if (fd->hasNoCode())
      throw std::runtime_error("selected function has no code");

    AddrSpace *code = architecture.getDefaultCodeSpace();

    // META identity keys are DERIVED from the live conf object, not
    // hardcoded: the language id (x86.ldefs language id="x86:LE:64:default")
    // and the resolved compiler-spec id (the ldefs <compiler> tag id — "gcc"
    // for this language; "x86-64-gcc" is the spec FILE name, not the id).
    // Resolution mirrors SleighArchitecture::buildSpecFile (sleigh_arch.cc:
    // 354-367): the compiler segment is the text after the last ':' of
    // archid, and LanguageDescription::getCompiler performs the tag lookup.
    SleighArchitecture *sleigh = dynamic_cast<SleighArchitecture *>(&architecture);
    int4 languageIndex = sleigh ? sleigh->fixtureGetLanguageIndex() : -1;
    if (!sleigh || languageIndex < 0)
      throw std::runtime_error("projection requires a resolved SLEIGH language");
    const LanguageDescription &language =
        SleighArchitecture::fixtureGetLanguage(languageIndex);
    const string archIdentity = language.getId();
    const string compilerSegment =
        sleigh->archid.substr(sleigh->archid.rfind(':') + 1);
    const CompilerTag &compilerTag = language.getCompiler(compilerSegment);
    const string cspecIdentity = compilerTag.getId();
    std::cerr << "[stage_projection] archid=" << sleigh->archid
              << " arch=" << archIdentity << " cspec=" << cspecIdentity << '\n';

    // Spaceid normalization table: every registered space's live object
    // address -> stable name.  Only values matching these addresses are
    // rewritten (they are exactly the values getSpaceFromConst decodes).
    for (int4 i = 0;i < architecture.numSpaces();++i) {
      AddrSpace *spc = architecture.getSpace(i);
      if (spc != (AddrSpace *)0)
        g_spaceIdNames[(uintb)(uintp)spc] = spc->getName();
    }

    fd->followFlow(Address(code,0),Address(code,code->getHighest()));
    Action *root = architecture.allacts.getCurrent();
    ActionRestartGroup *restart = dynamic_cast<ActionRestartGroup *>(root);
    if (!root || !restart)
      throw std::runtime_error("missing universal restart action");
    root->clearBreakPoints();
    root->reset(*fd);

    vector<ActionNode> all;
    vector<ActionNode> leaves;
    collectTree(root,root->getName(),all,leaves);
    if (leaves.empty())
      throw std::runtime_error("universal action tree has no leaves");

    // The output argument is intentionally accepted by the fixture so callers
    // can redirect atomically; stdout remains the canonical producer stream.
    if (!output.empty() && output != "-") {
      if (!freopen(output.c_str(),"w",stdout))
        throw std::runtime_error("unable to open projection output");
    }
    std::cout << std::unitbuf;
    std::cout << "META side=oracle oracle_commit=" << ORACLE_COMMIT
              << " arch=" << archIdentity << " cspec=" << cspecIdentity << '\n';
    std::cout << "META analysis_options=" << options
              << " build_flags=v1-no-OPACTION_DEBUG\n";
    std::cout << "META binary_sha256=" << binarySha
              << " func_entry=0x" << std::hex << fd->getAddress().getOffset()
              << std::dec << " func_name=" << fd->getName()
              << " load_mode=single_function_bfd\n";
    std::cout << "META producer=" << producer << " maxrestarts=1 unique_base=0x"
              << std::hex << architecture.translate->getUniqueBase() << std::dec
              << '\n';

    for (vector<ActionNode>::const_iterator iter=leaves.begin();
         iter!=leaves.end();++iter) {
      // Prefer the production name-path resolver.  A few universal nodes
      // intentionally share a name at one level (for example the two
      // DirectWrite leaves), for which getSubAction correctly reports an
      // ambiguity; the fixture then sets the same bit on the already-resolved
      // node pointer without changing the Action state machine.
      if (!root->setBreakPoint(Action::break_start,iter->path))
        iter->action->breakpoint |= Action::break_start;
      // A repeat leaf needs an action breakpoint so every changed apply in
      // the repeat group becomes its own event.  A no-change completion then
      // falls through to the next start breakpoint.
      if ((iter->action->flags & Action::rule_repeatapply) != 0 &&
          !root->setBreakPoint(Action::break_action,iter->path))
        iter->action->breakpoint |= Action::break_action;
    }

    vector<Event> active;
    uint64_t nextSeq = 1;
    int4 oldStart = restart->fixtureGetCurstart();
    int4 performResult = root->perform(*fd);
    while (true) {
      ActionNode hit = findHit(leaves);
      int4 currentStart = restart->fixtureGetCurstart();
      if (currentStart != oldStart && currentStart >= 0) {
        // Spec (iii): the restart group is mid-apply at a restart boundary.
        // Only round-N tail events close here; the root event stays open
        // across @RESTART and ends at final completion with its fully
        // accumulated count. Action::reset preserves count/count_tests/
        // count_apply (action.cc:100-105), so tail @END fields still read
        // the completion values after the restart reset.
        while (active.size() > 1)
          endEvent(std::cout,active,active.size()-1,*fd,0,false);
        std::cout << "@RESTART " << currentStart << '\n';
        oldStart = currentStart;
      }

      if (performResult < 0) {
        if (!hit.action)
          throw std::runtime_error("perform stopped without a leaf breakpoint");
        closeInactive(std::cout,active,*fd,hit.path);
        // Open group ancestors in DFS order, then the leaf itself.  Group
        // events stay open across child breakpoints and end after resumption.
        for (vector<ActionNode>::const_iterator iter=all.begin();
             iter!=all.end();++iter)
          if (iter->group && isPrefix(iter->path,hit.path))
            beginEvent(std::cout,active,*iter,nextSeq);
        beginEvent(std::cout,active,hit,nextSeq);

        if (hit.action->status == Action::status_actionbreak) {
          // This stop is after one changed repeatapply.  Complete its event,
          // then begin the next apply immediately before resuming perform().
          for (size_t i=active.size();i>0;--i)
            if (active[i-1].node.path == hit.path) {
              endEvent(std::cout,active,i-1,*fd,0,false);
              break;
            }
          beginEvent(std::cout,active,hit,nextSeq);
        }
        performResult = root->perform(*fd);
        continue;
      }

      closeAll(std::cout,active,*fd,performResult,true);
      break;
    }
    shutdownDecompilerLibrary();
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "LowlevelError: " << error.explain << '\n';
  }
  catch (const DecoderError &error) {
    std::cerr << "DecoderError: " << error.explain << '\n';
  }
  catch (const std::exception &error) {
    std::cerr << "fixture error: " << error.what() << '\n';
  }
  shutdownDecompilerLibrary();
  return 1;
}

} // namespace

int main(int argc,char **argv)
{
  if (argc != 8) {
    std::cerr << "usage: stage_projection_1204 SPEC_ROOT BINARY ENTRY OUTPUT "
                 "BINARY_SHA PRODUCER OPTIONS\n";
    return 2;
  }
  uintb entry = 0;
  std::stringstream parsed;
  parsed << std::hex << argv[3];
  parsed >> entry;
  return run(argv[1],argv[2],entry,argv[4],argv[5],argv[6],argv[7]);
}
