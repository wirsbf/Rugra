/*
 * CSPEC-JUMPDEST-INSTSYM-0001: locked Ghidra 12.0.4 JUMPSYM snippet-compiler
 * oracle.  Boots a bare SLEIGH engine on the production x86-64.sla (no
 * BfdArchitecture, matching PcodeInjectLibrarySleigh::parseInject's use of
 * `const SleighBase *slgh`), then compiles p-code snippets that use the
 * language's JUMPSYM symbols through the same PcodeSnippet compiler the
 * callfixup/jumpassist ingest path uses (inject_sleigh.cc:387
 * `PcodeSnippet compiler(slgh)`), printing:
 *   - the symbol_type of each JUMPSYM name as resolved by
 *     SleighBase::findSymbol (pcodeparse.cc:3223 via PcodeSnippet::lex),
 *     proving inst_start/inst_next/inst_next2 are serialized into the
 *     .sla (slgh_compile.cc:1986-1991 predefinedSymbols) while
 *     inst_dest/inst_ref only exist in the snippet-local tree
 *     (pcodeparse.y:693-694),
 *   - the compiled ConstructTpl XML (ConstructTpl::encode(encoder,-1),
 *     the exact encoding InjectPayloadSleigh::printTemplate uses) for
 *     each snippet, covering the two grammar positions with different
 *     re-wrap rules: `jumpdest: JUMPSYM` (pcodeparse.y:195, space
 *     j_curspace + size j_curspace_size) and `varnode:
 *     specificsymbol->getVarnode()` (pcodeparse.y:202, constant space +
 *     sz_zero, then propagateSize fills from the 8-byte destination),
 *   - the lexer fallback observations: an unknown name in jumpdest
 *     position and the predefined-but-not-JUMPSYM `epsilon` symbol in
 *     varnode position.
 */
#include "loadimage.hh"
#include "marshal.hh"
#include "pcodeparse.hh"
#include "sleigh.hh"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::istringstream;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

// A LoadImage that answers every fetch with zeros; snippet compilation
// never fetches instruction bytes (the PcodeSnippet constructor at
// pcodeparse.y:676-696 only reads the symbol/space tables).
class ZeroLoadImage : public LoadImage {
public:
  ZeroLoadImage(void) : LoadImage("jumpdest_instsym_zero") {}
  virtual void loadFill(unsigned char *ptr, int4 size, const Address &addr)
  {
    for (int4 i = 0; i < size; ++i)
      ptr[i] = 0;
  }
  virtual string getArchType(void) const { return "jumpdest-instsym"; }
  virtual void adjustVma(long) {}
};

string escapeNewlines(const string &value)
{
  string out;
  for (string::const_iterator iter = value.begin(); iter != value.end(); ++iter) {
    if (*iter == '\n')
      out += "\\n";
    else
      out += *iter;
  }
  return out;
}

// Compile one snippet with a fresh PcodeSnippet (exactly the
// PcodeInjectLibrarySleigh::parseInject lifecycle: fresh compiler, no
// operands, default tempbase 0, one parseStream call) and print the
// result: the encoded template on success, the first error otherwise.
void runSnippet(const SleighBase *slgh, int index, const string &snippet)
{
  PcodeSnippet compiler(slgh);
  istringstream stream(snippet);
  bool ok = compiler.parseStream(stream);
  if (!ok || compiler.hasErrors()) {
    cout << "SNIP|" << index << "|ERR|" << escapeNewlines(compiler.getErrorMessage())
         << "\n";
    return;
  }
  ConstructTpl *tpl = compiler.releaseResult();
  if (tpl == (ConstructTpl *)0) {
    cout << "SNIP|" << index << "|ERR|no result\n";
    return;
  }
  ostringstream buffer;
  XmlEncode encoder(buffer);
  tpl->encode(encoder, -1);
  delete tpl;
  cout << "SNIP|" << index << "|OK|" << escapeNewlines(buffer.str()) << "\n";
}

void runFixture(const string &specDirectory)
{
  const string slaPath = specDirectory + "/x86-64.sla";
  ZeroLoadImage loader;
  ContextInternal contextDatabase;
  Sleigh engine(&loader, &contextDatabase);
  DocumentStorage store;
  // SleighArchitecture::buildSpecFile (sleigh_arch.cc:412-417): the .sla is
  // registered as a synthetic <sleigh>path</sleigh> tag; Sleigh::initialize
  // (sleigh.cc:558-568) then streams the binary file through
  // sla::FormatDecode.
  istringstream sleighTag("<sleigh>" + slaPath + "</sleigh>");
  Document *doc = store.parseDocument(sleighTag);
  store.registerTag(doc->getRoot());
  engine.initialize(store);

  cout << "SCHEMA|1\n";

  // SleighBase::findSymbol observations for every name the snippets use.
  // symbol_type ordinals follow slghsymbol.hh:28-32 (space_symbol=0 ...
  // start_symbol=9, end_symbol=10, next2_symbol=11 ... epsilon_symbol=17,
  // flowdest_symbol=19, flowref_symbol=20).
  const char *probeNames[] = {
    "inst_start", "inst_next", "inst_next2", "inst_dest", "inst_ref", "epsilon",
  };
  for (int i = 0; i < 6; ++i) {
    const SleighSymbol *sym = engine.findSymbol(probeNames[i]);
    if (sym == (const SleighSymbol *)0)
      cout << "SYM|" << probeNames[i] << "|ABSENT\n";
    else
      cout << "SYM|" << probeNames[i] << "|" << (int4)sym->getType() << "\n";
  }

  // Snippets.  Each exercises one grammar position / symbol pairing.
  const char *snippets[] = {
    "goto inst_dest;",       // 0: jumpdest x local flowdest symbol
    "goto inst_ref;",        // 1: jumpdest x local flowref symbol
    "goto inst_next;",       // 2: jumpdest x language EndSymbol
    "goto inst_start;",      // 3: jumpdest x language StartSymbol
    "goto inst_next2;",      // 4: jumpdest x language Next2Symbol
    "local x:8 = inst_ref;", // 5: varnode x local flowref (size propagation)
    "local y:8 = inst_dest;",// 6: varnode x local flowdest
    "local z:8 = inst_next;",// 7: varnode x language EndSymbol
    "goto nosuchsym;",       // 8: unknown jump destination (y:200)
    "local w:8 = epsilon;",  // 9: predefined but not JUMPSYM -> STRING
  };
  const int snippetCount = (int)(sizeof(snippets) / sizeof(snippets[0]));
  for (int i = 0; i < snippetCount; ++i)
    runSnippet((const SleighBase *)&engine, i, snippets[i]);

  cout << "DONE\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 2) {
    cerr << "usage: jumpdest_instsym_1204 <specdir>\n";
    return 2;
  }
  try {
    runFixture(argv[1]);
  }
  catch (exception &error) {
    cerr << "jumpdest_instsym_1204: " << error.what() << "\n";
    return 1;
  }
  catch (...) {
    cerr << "jumpdest_instsym_1204: unknown exception\n";
    return 1;
  }
  return 0;
}
