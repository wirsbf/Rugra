/* Translate::initialize / DocumentStorage oracle fixture
 * (TRANSLATE-DOCSTORE-UNIFY-0001).
 *
 * Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
 *
 * Drives a real Sleigh engine through the Translate::initialize
 * DocumentStorage contract (translate.hh:332 -> sleigh.cc:555-565):
 *   - empty store: getTag("sleigh") returns null -> exact LowlevelError
 *     "Could not find sleigh tag" (sleigh.cc:560-561),
 *   - store holding only a differently-named registered root,
 *   - store with a registered <sleigh> tag whose content is the .sla path:
 *     the failed ifstream open surfaces the element content verbatim in
 *     "Could not open .sla file: <content>" (sleigh.cc:563-565),
 *   - same-name re-registration overwrites (xml.cc:2463-2467 tagmap
 *     operator[]), so the SECOND path is the one initialize observes,
 *   - a multi-tag store keeps name-keyed isolation.
 * Each case uses a fresh uninitialized engine (SleighBase::isInitialized is
 * root != null, sleighbase.hh:78). The .sla ingest past the open check is
 * the SLEIGH engine domain and is intentionally not exercised here.
 * The Rust fixture must produce byte-identical output.
 */

#include "sleigh.hh"

#include <iostream>
#include <sstream>
#include <string>

using namespace ghidra;

static void run_initialize(const std::string &label, Sleigh &trans,
                           DocumentStorage &store)
{
  try {
    trans.initialize(store);
    std::cout << "I|" << label << "|UNEXPECTED_OK\n";
  }
  catch (const LowlevelError &e) {
    std::cout << "I|" << label << "|" << e.explain << '\n';
  }
}

static void parse_and_register(DocumentStorage &store, const std::string &text)
{
  std::istringstream s(text);
  Document *doc = store.parseDocument(s);
  store.registerTag(doc->getRoot());
}

int main(void)
{
  // -- case 1: empty store -> getTag miss -> exact message ----------------
  {
    Sleigh trans((LoadImage *)0, (ContextDatabase *)0);
    DocumentStorage store;
    run_initialize("no_tag", trans, store);
  }

  // -- case 2: only a differently-named tag is registered -----------------
  {
    Sleigh trans((LoadImage *)0, (ContextDatabase *)0);
    DocumentStorage store;
    parse_and_register(store, "<processor_spec><programcounter/></processor_spec>");
    run_initialize("wrong_name", trans, store);
  }

  // -- case 3: registered <sleigh> tag, nonexistent .sla path -------------
  {
    Sleigh trans((LoadImage *)0, (ContextDatabase *)0);
    DocumentStorage store;
    parse_and_register(store,
      "<sleigh>/nonexistent/translate/docstore/first.sla</sleigh>");
    run_initialize("bad_path", trans, store);
  }

  // -- case 4: same-name overwrite: second registration wins --------------
  {
    Sleigh trans((LoadImage *)0, (ContextDatabase *)0);
    DocumentStorage store;
    parse_and_register(store,
      "<sleigh>/nonexistent/translate/docstore/first.sla</sleigh>");
    parse_and_register(store,
      "<sleigh>/nonexistent/translate/docstore/second.sla</sleigh>");
    run_initialize("overwrite", trans, store);
  }

  // -- case 5: multi-tag store, name-keyed lookup isolation ---------------
  {
    Sleigh trans((LoadImage *)0, (ContextDatabase *)0);
    DocumentStorage store;
    parse_and_register(store, "<compiler_spec><default_proto/></compiler_spec>");
    parse_and_register(store,
      "<sleigh>/nonexistent/translate/docstore/multi.sla</sleigh>");
    std::cout << "I|multi_siblings|"
              << (store.getTag("compiler_spec") != (const Element *)0)
              << '\n';
    run_initialize("multi", trans, store);
  }

  std::cout << "S|DONE\n";
  return 0;
}
