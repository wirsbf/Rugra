/*
 * Locked Ghidra 12.0.4 (e40ed130) OPACTION_DEBUG per-application drill
 * harness for Funcdata "next_url" of examples/curl.
 *
 * Investigation fixture for stage-bisect v2 (per-application modified-op
 * down-drill).  Design: /dev/shm/rugra-tests/sb-drill/DRILL_DESIGN.md;
 * collection route B of tools/stage_bisect_projection.cc [5].
 *
 * The fixture loads one function with the exact per-function drive protocol
 * of tools/regen_ghidra_golden.py decompileFunction() (full flow range,
 * universal action to completion, resuming past any breakpoint), but:
 *   - the Architecture debug stream is routed into a framing sink so every
 *     native Funcdata::debugModPrint flush (= one Action/Rule application,
 *     funcdata.cc:1035-1057) becomes one captured frame, and
 *   - a break_start ladder (breakpoint on every tree Action node,
 *     action.hh:73-104) brackets the run so each perform() call covers
 *     exactly one node visit; the stopped node is identified with
 *     Action::printState (action.cc:148-164, 444-454).
 *
 * Every captured application block keeps the native DEBUG text verbatim
 * (op.cc:376 printDebug; dead/unattached ops print "<seqnum>: **"); the
 * fixture never reformats, escapes, or rewrites those lines.
 *
 * Compile ONLY with -DOPACTION_DEBUG (library AND this file, via
 * tools/build_stage_drill_oracle.sh); a run produced without the switch, or
 * without recording the switch, is NO_ORACLE for gate purposes.
 *
 * Known, accepted deviations from a breakpoint-free native run (must be
 * recorded in the metadata of any evidence built on this drill):
 *   - Action::count_tests is not incremented for a status_start pass that
 *     stops at a start breakpoint (action.cc:305-312 falls through
 *     breakstarthit on resume), so statistics counters differ; apply()
 *     order, IR results, and the DEBUG stream content do not.
 *   - rule_debug flags are never set (they gate nothing in this path);
 *     debugSetBreak is never called so opactdbg_breakon stays false.
 *
 * Oracle mechanisms consumed (locked commit e40ed130):
 *   funcdata.cc:1010-1052   debugModCheck / debugModClear / debugModPrint
 *   funcdata.cc:1059-1098   debugSetRange / debugCheckRange (invalid PC +
 *                           all-ones unique bounds = whole-function trace)
 *   op.cc:376               PcodeOp::printDebug
 *   action.cc:52-60         checkStartBreak (break_start is sticky)
 *   action.cc:132-144       Action::print (tree listing for walk discovery)
 *   action.cc:148-164       Action::printState (stopped-node chain)
 *   action.cc:171-185       Action::setBreakPoint / path addressing
 *   action.cc:298-362       Action::perform state machine
 *   action.cc:317-321,839-845  debugActivate / debugModPrint boundaries
 *   architecture.hh:255-256   setDebugStream / printDebug capture point
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::runtime_error;
using std::string;
using std::vector;

// ---------------------------------------------------------------------------
// Framing sink: one completed frame per Architecture::printDebug flush
// (architecture.hh:256 does `*debugstream << message << endl`; endl triggers
// ostream::flush -> streambuf::sync).  debugModPrint sends exactly one such
// flush per application, so frame boundaries == application boundaries.
// ---------------------------------------------------------------------------
class DrillSinkBuf : public std::streambuf
{
  vector<string> frames;
  string pending;

  int_type overflow(int_type ch) override
  {
    if (ch != traits_type::eof())
      pending.push_back(static_cast<char>(ch));
    return ch;
  }

  std::streamsize xsputn(const char *s,std::streamsize count) override
  {
    pending.append(s,static_cast<size_t>(count));
    return count;
  }

  int sync() override
  {
    if (!pending.empty()) {
      frames.push_back(pending);
      pending.clear();
    }
    return 0;
  }

public:
  vector<string> drain()
  {
    vector<string> result;
    result.swap(frames);
    return result;
  }
};

// ---------------------------------------------------------------------------
// Action tree model, discovered from Action::print at run time.
// ---------------------------------------------------------------------------
struct TreeNode
{
  string name;
  string path;           // ':'-joined from the tree root (root: "universal")
  int depth;
  bool isRule;
  bool isPool;           // action node whose children are all rules
  bool isGroup;          // action node with at least one action child
  vector<size_t> children;
};

// Parse the Action::print listing (action.cc:132-144, 739-761).  Action
// lines: 4-wide num, 8-char repeat field, 3 flag chars, depth*5+2 spaces,
// name (a group may append "  <-- ").  Rule lines: 4-wide num, 2 flag
// chars, depth*5+2 spaces, name.  Consequently the name column is
// 17+5*depth for actions and 8+5*depth for rules (disjoint modulo 5).
vector<TreeNode> parseTreeListing(const string &listing)
{
  vector<TreeNode> nodes;
  std::istringstream input(listing);
  string line;
  while (std::getline(input,line)) {
    const string marker = "  <-- ";
    if (line.size() >= marker.size() && line.compare(line.size()-marker.size(),marker.size(),marker) == 0)
      line.resize(line.size()-marker.size());
    const size_t nameStart = line.find_last_not_of(' ');
    if (nameStart == string::npos)
      continue;
    const size_t nameBegin = line.find_last_of(' ',nameStart);
    const string name = (nameBegin == string::npos) ? line : line.substr(nameBegin+1);
    const size_t nameCol = (nameBegin == string::npos) ? 0 : nameBegin+1;
    if (name.empty() || nameCol < 8)
      throw runtime_error("unparseable tree listing line: " + line);
    const size_t fromActionBase = nameCol - 17;   // action: nameCol = 17+5d
    const size_t fromRuleBase = nameCol - 8;      // rule:   nameCol = 8+5d
    TreeNode node;
    node.name = name;
    node.isPool = false;
    node.isGroup = false;
    if (nameCol >= 17 && fromActionBase % 5 == 0) {
      node.depth = static_cast<int>(fromActionBase / 5);
      node.isRule = false;
    }
    else if (fromRuleBase % 5 == 0) {
      node.depth = static_cast<int>(fromRuleBase / 5);
      node.isRule = true;
    }
    else
      throw runtime_error("tree listing column neither action nor rule: " + line);
    if (nodes.empty()) {
      if (node.depth != 0 || node.isRule)
        throw runtime_error("tree listing does not start with the root action");
      node.path = name;
      nodes.push_back(node);
      continue;
    }
    nodes.push_back(node);
  }
  return nodes;
}

// Link children and compute path/chainPrefix/isPool.  Kept separate from
// parseTreeListing because depth-only parenting is easier with indices.
void linkTree(vector<TreeNode> &nodes)
{
  vector<size_t> stack; // ancestors by index, innermost last
  for (size_t i = 0;i < nodes.size();++i) {
    TreeNode &node = nodes[i];
    while (!stack.empty() && nodes[stack.back()].depth >= node.depth)
      stack.pop_back();
    if (stack.empty()) {
      if (i != 0)
        throw runtime_error("multiple depth-0 nodes in tree listing");
    }
    else {
      TreeNode &parent = nodes[stack.back()];
      if (parent.isRule)
        throw runtime_error("rule node has children: " + parent.name);
      parent.children.push_back(i);
      node.path = parent.path + ":" + node.name;
    }
    stack.push_back(i);
  }
  for (TreeNode &node : nodes) {
    if (node.isRule || node.children.empty())
      continue;
    bool allRules = true;
    for (size_t child : node.children)
      if (!nodes[child].isRule) { allRules = false; break; }
    node.isPool = allRules;
    node.isGroup = !allRules;
  }
}

// Identify the node a root->printState chain points at.  printState renders
// "rootname:childname:...:nodename" plus a status suffix (" start" for a
// start-breakpoint hit, ":" for status_mid; action.cc:148-164, 444-454), so
// the deepest action whose ':'-joined path matches the chain head, followed
// by a suffix boundary, is the stopped node.
size_t matchChain(const vector<TreeNode> &nodes,const string &chain)
{
  size_t best = 0;
  for (size_t i = 0;i < nodes.size();++i) {
    const TreeNode &node = nodes[i];
    if (node.isRule)
      continue;
    if (chain.compare(0,node.path.size(),node.path) != 0)
      continue;
    const size_t rest = node.path.size();
    if (rest == chain.size() || chain[rest] == ' ' || chain[rest] == ':') {
      if (node.depth > nodes[best].depth)
        best = i;
    }
  }
  return best;
}

// A native DEBUG frame starts with "DEBUG <n>: <leafname>"; any other debug
// stream flush is auxiliary OPACTION_DEBUG output (MapState "Add Range",
// deadcode listings, symbol entries; DRILL_DESIGN.md section 2.4) and is
// preserved verbatim under an @AUX block instead of an application block.
bool parseDebugHeader(const string &frame,long *seq,string *leaf)
{
  istringstream head(frame);
  string literal;
  long value = -1;
  char colon = '\0';
  if (!(head >> literal >> value >> colon))
    return false;
  if (literal != "DEBUG" || colon != ':')
    return false;
  if (!std::getline(head,*leaf) || leaf->empty())
    return false;
  leaf->erase(0,leaf->find_first_not_of(' '));
  if (seq != nullptr)
    *seq = value;
  return true;
}

// ---------------------------------------------------------------------------
// Fixture body
// ---------------------------------------------------------------------------
void runFixture(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("next_url");
    if (fd == (Funcdata *)0)
      throw runtime_error("next_url was not found in the BFD symbol table");
    if (fd->hasNoCode())
      throw runtime_error("next_url has no code");
    if (fd->getAddress().getOffset() != 0x4ff0)
      throw runtime_error("next_url entry identity drifted: offset=" +
                          std::to_string(fd->getAddress().getOffset()));

    // Drive protocol of tools/regen_ghidra_golden.py decompileFunction().
    AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
    fd->followFlow(Address(codeSpace,0),Address(codeSpace,codeSpace->getHighest()));

    Action *root = architecture.allacts.getCurrent();
    if (root == (Action *)0)
      throw runtime_error("no current decompile action");

    // Discover the action tree from the oracle's own listing.
    std::ostringstream listing;
    root->print(listing,0,0);
    vector<TreeNode> nodes = parseTreeListing(listing.str());
    linkTree(nodes);
    if (std::getenv("STAGE_DRILL_DUMP_TREE") != nullptr) {
      std::cerr << listing.str() << '\n';
      for (const TreeNode &node : nodes)
        std::cerr << "node d=" << node.depth << (node.isRule ? " R" : " A")
                  << (node.isGroup ? " G" : "") << (node.isPool ? " P" : "")
                  << " path=" << node.path << '\n';
    }

    // Ladder: a sticky start breakpoint on every non-root Action node
    // (action.cc:52-60 keeps break_start set; onceperfunc nodes in
    // status_end skip the check at action.cc:343-344 and are never hit).
    // Duplicate names in the tree (e.g. ActionDirectWrite twice in
    // mainloop) make ActionGroup::getSubAction return null
    // (action.cc:469-477 matchcount>1), so those nodes cannot be
    // breakpoint-addressed; they run unbracketed inside a neighbour's
    // bracket and their frames are re-attributed by native leaf name.
    vector<string> unbreakable;
    for (const TreeNode &node : nodes) {
      if (node.isRule || node.depth == 0)
        continue;
      if (!root->setBreakPoint(Action::break_start,node.path))
        unbreakable.push_back(node.path);
    }
    for (const string &path : unbreakable)
      std::cerr << "stage_drill_1204: no breakpoint for ambiguous path " << path << '\n';

    // Whole-function trace: invalid PC bounds skip the PC filter and the
    // default all-ones unique bounds skip the unique filter
    // (funcdata.cc:1076-1097).
    fd->debugSetRange(Address(),Address());
    fd->debugEnable();

    DrillSinkBuf sinkBuf;
    std::ostream drillStream(&sinkBuf);
    architecture.setDebugStream(&drillStream);

    std::cout << "META side=oracle oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b"
              << " build_flags=OPACTION_DEBUG func=next_url entry=0x4ff0"
              << " arch=x86:LE:64:default cspec=gcc"
              << " format=raw-native-printdebug record_seq=native_opactdbg_count"
              << " boundary_seq=1based_perform_bracket ladder=break_start_all_nodes"
              << " unbreakable_paths=" << unbreakable.size() << '\n';

    size_t cursor = 0;                 // node resumed by the next perform()
    long blocks = 0;                   // 1-based boundary seq
    long records = 0;                  // native DEBUG frames
    long nativeCount = 0;              // running opactdbg_count value
    int4 res = 0;
    long iterations = 0;
    const long maxIterations = 2000000;
    do {
      res = root->perform(*fd);
      vector<string> frames = sinkBuf.drain();
      ++iterations;
      if (iterations > maxIterations)
        throw runtime_error("perform ladder exceeded iteration budget");

      const TreeNode &bracket = nodes[cursor];
      for (const string &frame : frames) {
        long seq = -1;
        string leaf;
        if (!parseDebugHeader(frame,&seq,&leaf)) {
          ++blocks;
          std::cout << "@AUX " << blocks << ' ' << bracket.path << '\n'
                    << frame << "@ENDAUX " << blocks << '\n';
          continue;
        }
        ++records;
        ++blocks;
        if (seq != nativeCount)
          throw runtime_error("native opactdbg_count jumped: expected " +
                              std::to_string(nativeCount) + " got " + std::to_string(seq));
        nativeCount = seq + 1;
        string path = bracket.path;
        if (bracket.isPool) {
          path += ":" + leaf;
          bool known = false;
          for (size_t child : bracket.children)
            if (nodes[child].name == leaf) { known = true; break; }
          if (!known)
            path += "?unknown-rule";
        }
        else if (!bracket.isGroup && leaf == bracket.name)
          path = bracket.path;             // the bracketed node's own application
        else
          path += ":" + leaf + "?unbracketed"; // ambiguous/unbreakable neighbour
        std::cout << "@BEGIN " << blocks << ' ' << path << '\n'
                  << frame
                  << "@END " << blocks << ' ' << path << '\n';
      }
      if (frames.empty() && !bracket.isGroup && !bracket.isRule) {
        // The visited node applied without modifying any traced op (or a
        // pool pass applied no traced modification): keep the v1.1-style
        // empty boundary so the application is still observable.
        ++blocks;
        std::cout << "@BEGIN " << blocks << ' ' << bracket.path
                  << " empty=1\n@END " << blocks << ' ' << bracket.path << '\n';
      }

      if (res < 0) {
        std::ostringstream chain;
        root->printState(chain);
        cursor = matchChain(nodes,chain.str());
      }
    } while (res < 0);

    architecture.setDebugStream(&std::cerr);
    fd->debugDisable();

    std::cout << "@DONE applications=" << blocks << " records=" << records
              << " opactdbg_final=" << nativeCount
              << " perform_calls=" << iterations
              << " final_return=" << res << " nodes=" << nodes.size() << '\n';
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: stage_drill_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[2]);
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
