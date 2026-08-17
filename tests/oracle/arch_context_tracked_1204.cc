/*
 * ARCH-CONTEXT-TRACKED-0001: locked Ghidra 12.0.4 pspec <context_data>
 * tracked-register ingest oracle for
 * ContextInternal::decodeFromSpec (globalcontext.cc:531-549) ->
 * Range::decodeFromAttributes (address.cc:316-353) +
 * Range::getLastAddrOpen (address.cc:265-281) +
 * ContextInternal::createSet (globalcontext.cc:470-475, partmap
 * clearRange partmap.hh:144-157) + ContextDatabase::decodeTracked
 * (globalcontext.cc:85-93) + TrackedContext::decode (globalcontext.cc:56-63)
 * + VarnodeData::decodeFromAttributes (pcoderaw.cc:33-53), reached in
 * production through Architecture::init -> restoreFromSpec ->
 * parseProcessorConfig's ELEM_CONTEXT_DATA arm (architecture.cc:1190).
 *
 * Observations:
 *  - production: the live BfdArchitecture context database after init on
 *    the locked spec set: <context_set> child count from the processor_spec
 *    DOM, the default tracked set, and getTrackedSet probes across the
 *    whole ram space (the x86-64.pspec <tracked_set space="ram"> shape).
 *  - cases: synthetic <context_data> documents on fresh ContextInternal
 *    objects: minimal whole-space set, explicit first/last range with two
 *    <set> children (document order), a later tracked_set overriding an
 *    earlier one inside its range, the register-name range form
 *    (<tracked_set name="DF">), and the explicit space/offset/size <set>
 *    form alongside a max-uintb value.
 *  - errors: verbatim oracle texts for the missing range space, an unknown
 *    child element, a reversed range, an unknown register name, an unknown
 *    space name, and a non-<set> child of <tracked_set>.
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "globalcontext.hh"
#include "xml.hh"

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
using std::runtime_error;
using std::string;
using std::vector;

string jsonEscape(const string &value)
{
  std::ostringstream out;
  for (string::const_iterator iter = value.begin(); iter != value.end(); ++iter) {
    unsigned char ch = static_cast<unsigned char>(*iter);
    switch (ch) {
    case '\\': out << "\\\\"; break;
    case '"': out << "\\\""; break;
    case '\n': out << "\\n"; break;
    case '\r': out << "\\r"; break;
    case '\t': out << "\\t"; break;
    default:
      if (ch < 0x20) {
        const char hex[] = "0123456789abcdef";
        out << "\\u00" << hex[ch >> 4] << hex[ch & 0xf];
      }
      else
        out << static_cast<char>(ch);
      break;
    }
  }
  return out.str();
}

const Element *findChild(const Element *parent, const string &name)
{
  const List &children = parent->getChildren();
  for (List::const_iterator iter = children.begin(); iter != children.end(); ++iter) {
    if ((*iter)->getName() == name)
      return *iter;
  }
  return (const Element *)0;
}

void writeTrackedEntry(std::ostream &out, const TrackedContext &ctx)
{
  out << "{\"space\":\"" << ctx.loc.space->getName()
      << "\",\"off\":\"0x" << std::hex << ctx.loc.offset << std::dec
      << "\",\"size\":" << ctx.loc.size
      << ",\"val\":" << ctx.val << '}';
}

void writeProbe(std::ostream &out, ContextDatabase *db, AddrSpace *spc,
                const string &spaceName, uintb off)
{
  const TrackedSet &set(db->getTrackedSet(Address(spc, off)));
  out << "{\"space\":\"" << spaceName << "\",\"off\":\"0x" << std::hex << off
      << std::dec << "\",\"count\":" << set.size() << ",\"entries\":[";
  for (size_t i = 0; i < set.size(); ++i) {
    if (i != 0)
      out << ',';
    writeTrackedEntry(out, set[i]);
  }
  out << "]}";
}

// Decode one synthetic <context_data> document into a fresh ContextInternal.
string decodeSynthetic(Architecture &architecture, ContextInternal &fresh,
                       const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  fresh.decodeFromSpec(decoder);
  return "";
}

string observeError(Architecture &architecture, const string &xml)
{
  try {
    ContextInternal fresh;
    decodeSynthetic(architecture, fresh, xml);
    return "NO_ERROR";
  }
  catch (DecoderError &error) {
    return error.explain;
  }
  catch (LowlevelError &error) {
    return error.explain;
  }
}

void runFixture(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary, "default", &std::cerr);
  DocumentStorage documents;
  architecture.init(documents);

  AddrSpace *ram = architecture.getSpaceByName("ram");
  if (ram == (AddrSpace *)0)
    throw runtime_error("missing ram space");
  AddrSpace *reg = architecture.getSpaceByName("register");
  if (reg == (AddrSpace *)0)
    throw runtime_error("missing register space");

  // --- production: the real init chain already ran decodeFromSpec on the
  //     locked x86-64.pspec <context_data> (architecture.cc:1190).
  ContextDatabase *production = architecture.context;
  const Element *processorSpec = documents.getTag("processor_spec");
  if (processorSpec == (const Element *)0)
    throw runtime_error("missing parsed processor_spec");
  const Element *contextData = findChild(processorSpec, "context_data");
  if (contextData == (const Element *)0)
    throw runtime_error("missing context_data element");
  int4 contextSetChildren = 0;
  {
    const List &children = contextData->getChildren();
    for (List::const_iterator iter = children.begin(); iter != children.end(); ++iter) {
      if ((*iter)->getName() == "context_set")
        contextSetChildren += 1;
    }
  }
  const TrackedSet &productionDefault(production->getTrackedDefault());

  // --- synthetic cases on fresh ContextInternal objects (register/space
  //     resolution still through the live architecture).
  ContextInternal c1;
  decodeSynthetic(architecture, c1,
                  "<context_data><tracked_set space=\"ram\">"
                  "<set name=\"DF\" val=\"0\"/>"
                  "</tracked_set></context_data>");

  ContextInternal c2;
  decodeSynthetic(architecture, c2,
                  "<context_data><tracked_set space=\"ram\" first=\"0x100\" last=\"0x1ff\">"
                  "<set name=\"DF\" val=\"0\"/>"
                  "<set name=\"EAX\" val=\"1\"/>"
                  "</tracked_set></context_data>");

  ContextInternal c3;
  decodeSynthetic(architecture, c3,
                  "<context_data>"
                  "<tracked_set space=\"ram\" first=\"0x100\" last=\"0x2ff\">"
                  "<set name=\"DF\" val=\"0\"/>"
                  "</tracked_set>"
                  "<tracked_set space=\"ram\" first=\"0x200\" last=\"0x2ff\">"
                  "<set name=\"DF\" val=\"1\"/>"
                  "</tracked_set>"
                  "</context_data>");

  ContextInternal c4;
  decodeSynthetic(architecture, c4,
                  "<context_data><tracked_set name=\"DF\">"
                  "<set name=\"DF\" val=\"0\"/>"
                  "</tracked_set></context_data>");

  ContextInternal c5;
  decodeSynthetic(architecture, c5,
                  "<context_data><tracked_set space=\"ram\">"
                  "<set space=\"register\" offset=\"0x20a\" size=\"1\" val=\"0x123\"/>"
                  "<set name=\"RAX\" val=\"0xffffffffffffffff\"/>"
                  "</tracked_set></context_data>");

  cout << "{\"schema\":1,\"fixture\":\"ARCH-CONTEXT-TRACKED-0001\""
       << ",\"production\":{"
       << "\"ram_highest\":\"0x" << std::hex << ram->getHighest() << std::dec
       << "\",\"context_set_children\":" << contextSetChildren
       << ",\"default_count\":" << productionDefault.size()
       << ",\"probes\":[";
  writeProbe(cout, production, ram, "ram", 0x0);
  cout << ',';
  writeProbe(cout, production, ram, "ram", 0x403000);
  cout << ',';
  writeProbe(cout, production, ram, "ram", ram->getHighest());
  cout << "]},\"cases\":["
       << "{\"name\":\"c1_minimal_whole_space\",\"probes\":[";
  writeProbe(cout, &c1, ram, "ram", 0x0);
  cout << ',';
  writeProbe(cout, &c1, ram, "ram", 0x403000);
  cout << ',';
  writeProbe(cout, &c1, ram, "ram", ram->getHighest());
  cout << "]},{\"name\":\"c2_explicit_range_two_sets\",\"probes\":[";
  writeProbe(cout, &c2, ram, "ram", 0xff);
  cout << ',';
  writeProbe(cout, &c2, ram, "ram", 0x100);
  cout << ',';
  writeProbe(cout, &c2, ram, "ram", 0x1ff);
  cout << ',';
  writeProbe(cout, &c2, ram, "ram", 0x200);
  cout << "]},{\"name\":\"c3_later_set_overrides\",\"probes\":[";
  writeProbe(cout, &c3, ram, "ram", 0x1ff);
  cout << ',';
  writeProbe(cout, &c3, ram, "ram", 0x200);
  cout << ',';
  writeProbe(cout, &c3, ram, "ram", 0x2ff);
  cout << ',';
  writeProbe(cout, &c3, ram, "ram", 0x300);
  cout << "]},{\"name\":\"c4_register_name_range\",\"probes\":[";
  writeProbe(cout, &c4, reg, "register", 0x209);
  cout << ',';
  writeProbe(cout, &c4, reg, "register", 0x20a);
  cout << ',';
  writeProbe(cout, &c4, reg, "register", 0x20b);
  cout << "]},{\"name\":\"c5_explicit_varnode_and_max_val\",\"probes\":[";
  writeProbe(cout, &c5, ram, "ram", 0x0);
  cout << "]}],\"errors\":["
       << "{\"name\":\"e1_missing_space\",\"error\":\""
       << jsonEscape(observeError(architecture,
                                  "<context_data><tracked_set>"
                                  "<set name=\"DF\" val=\"0\"/>"
                                  "</tracked_set></context_data>"))
       << "\"},{\"name\":\"e2_bad_child\",\"error\":\""
       << jsonEscape(observeError(architecture,
                                  "<context_data><bogus/></context_data>"))
       << "\"},{\"name\":\"e2b_bad_child_with_range\",\"error\":\""
       << jsonEscape(observeError(architecture,
                                  "<context_data><bogus space=\"ram\"/></context_data>"))
       << "\"},{\"name\":\"e3_reversed_range\",\"error\":\""
       << jsonEscape(observeError(architecture,
                                  "<context_data><tracked_set space=\"ram\" first=\"0x10\" last=\"0x8\">"
                                  "<set name=\"DF\" val=\"0\"/>"
                                  "</tracked_set></context_data>"))
       << "\"},{\"name\":\"e4_unknown_register\",\"error\":\""
       << jsonEscape(observeError(architecture,
                                  "<context_data><tracked_set space=\"ram\">"
                                  "<set name=\"NOSUCHREG\" val=\"0\"/>"
                                  "</tracked_set></context_data>"))
       << "\"},{\"name\":\"e5_unknown_space\",\"error\":\""
       << jsonEscape(observeError(architecture,
                                  "<context_data><tracked_set space=\"nosuchspace\">"
                                  "<set name=\"DF\" val=\"0\"/>"
                                  "</tracked_set></context_data>"))
       << "\"},{\"name\":\"e6_non_set_child\",\"error\":\""
       << jsonEscape(observeError(architecture,
                                  "<context_data><tracked_set space=\"ram\">"
                                  "<register val=\"0\"/>"
                                  "</tracked_set></context_data>"))
       << "\"}],\"done\":1}\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: arch_context_tracked_1204 <spec-directory> <binary>\n";
    return 2;
  }
  try {
    runFixture(argv[1], argv[2]);
    return 0;
  }
  catch (LowlevelError &error) {
    cerr << error.explain << '\n';
  }
  catch (DecoderError &error) {
    cerr << error.explain << '\n';
  }
  catch (exception &error) {
    cerr << error.what() << '\n';
  }
  return 1;
}
