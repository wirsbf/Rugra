/*
 * CSPEC-TYPEORG-STATE-0001: locked Ghidra 12.0.4 data-organization state
 * oracle for TypeFactory::{decodeDataOrganization, decodeAlignmentMap,
 * setupSizes} plus the getAlignment/getPrimitiveAlignSize readers
 * (type.cc:3137-3170, 3296-3320, 4583-4656).
 *
 * Observations:
 *  - arch_inputs: the Architecture facts setupSizes derives from.
 *  - production:  the live factory state after BfdArchitecture::init
 *                 (parseCompilerConfig decode + setupSizes).
 *  - raw_decode:  a standalone factory decoding the production
 *                 <data_organization> element (pre-setupSizes state).
 *  - cases:       synthetic <data_organization> documents covering sparse
 *                 forward-fill, empty map + error text + default install,
 *                 explicit size-0 entry, duplicate entries / zero
 *                 alignment, skipped children, and setupSizes derivation
 *                 (including the int!=4 long branch and negative sizes).
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "type.hh"
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

// "int":i,"long":i,"char":i,"wchar":i,"pointer":i,"alt_pointer":i
// (object members only; callers place them inside their own braces)
void writeSizesFields(std::ostream &out, const TypeFactory &factory)
{
  out << "\"int\":" << factory.getSizeOfInt()
      << ",\"long\":" << factory.getSizeOfLong()
      << ",\"char\":" << factory.getSizeOfChar()
      << ",\"wchar\":" << factory.getSizeOfWChar()
      << ",\"pointer\":" << factory.getSizeOfPointer()
      << ",\"alt_pointer\":" << factory.getSizeOfAltPointer();
}

// {"int":i,"long":i,"char":i,"wchar":i,"pointer":i,"alt_pointer":i}
void writeSizes(std::ostream &out, const TypeFactory &factory)
{
  out << '{';
  writeSizesFields(out, factory);
  out << '}';
}

void writeAlignProbes(std::ostream &out, TypeFactory &factory, uint4 first, uint4 last)
{
  out << '[';
  for (uint4 size = first; size <= last; ++size) {
    if (size != first)
      out << ',';
    out << factory.getAlignment(size);
  }
  out << ']';
}

void writePrimitiveProbes(std::ostream &out, TypeFactory &factory, uint4 first, uint4 last)
{
  out << '[';
  for (uint4 size = first; size <= last; ++size) {
    if (size != first)
      out << ',';
    out << factory.getPrimitiveAlignSize(size);
  }
  out << ']';
}

string observeAlignError(TypeFactory &factory, uint4 size)
{
  try {
    factory.getAlignment(size);
    return "NO_ERROR";
  }
  catch (LowlevelError &error) {
    return error.explain;
  }
}

// Decode one synthetic <data_organization> document into `factory`.
void decodeSynthetic(Architecture &architecture, TypeFactory &factory, const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  factory.decodeDataOrganization(decoder);
}

void runFixture(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary, "default", &std::cerr);
  DocumentStorage documents;
  architecture.init(documents);

  const Element *compilerSpec = documents.getTag("compiler_spec");
  if (compilerSpec == (const Element *)0)
    throw runtime_error("missing parsed compiler_spec");
  const Element *dataOrganization = findChild(compilerSpec, "data_organization");
  if (dataOrganization == (const Element *)0)
    throw runtime_error("missing data_organization element");

  // --- arch_inputs: the exact facts TypeFactory::setupSizes reads (type.cc:3142-3167).
  AddrSpace *stackSpace = architecture.getStackSpace();
  int4 stackSpacebaseSize = -1;
  if (stackSpace != (AddrSpace *)0)
    stackSpacebaseSize = stackSpace->getSpacebase(0).size;
  AddrSpace *dataSpace = architecture.getDefaultDataSpace();
  SegmentOp *segOp = architecture.getSegmentOp(dataSpace);
  const bool farPointer =
      (segOp != (SegmentOp *)0) && segOp->hasFarPointerSupport();

  // --- production: post-init state of the architecture's own factory.
  TypeFactory &production = *architecture.types;
  const int4 productionAlignProbes = 17;

  // --- raw_decode: standalone factory decodes the production element
  //     (setupSizes has NOT run on it, so absent sizes stay 0).
  TypeFactory rawFactory(&architecture);
  {
    XmlDecode decoder(&architecture, dataOrganization);
    rawFactory.decodeDataOrganization(decoder);
  }
  const int4 rawAlignProbes = 17;

  // --- cases -------------------------------------------------------------
  // c1: sparse map -> forward fill from nearest earlier explicit value;
  //     index 0 keeps -1 (no explicit size-0 entry).
  TypeFactory c1(&architecture);
  decodeSynthetic(architecture, c1,
                  "<data_organization><size_alignment_map>"
                  "<entry size=\"3\" alignment=\"4\"/>"
                  "<entry size=\"7\" alignment=\"8\"/>"
                  "</size_alignment_map></data_organization>");

  // c2: empty <size_alignment_map> -> map stays empty (getAlignment raises
  //     the oracle LowlevelError), then setupSizes installs the default map.
  TypeFactory c2(&architecture);
  decodeSynthetic(architecture, c2,
                  "<data_organization><size_alignment_map>"
                  "</size_alignment_map></data_organization>");
  const string c2Error = observeAlignError(c2, 1);
  c2.setupSizes();

  // c3: explicit size-0 entry makes alignMap[0] observable (1, not -1);
  //     primitive size 0 is then a safe probe (0 % 1 == 0).
  TypeFactory c3(&architecture);
  decodeSynthetic(architecture, c3,
                  "<data_organization><size_alignment_map>"
                  "<entry size=\"0\" alignment=\"1\"/>"
                  "<entry size=\"2\" alignment=\"2\"/>"
                  "</size_alignment_map></data_organization>");

  // c4: out-of-order entries, a later duplicate size=8 wins, and an explicit
  //     zero alignment is kept. No primitive probes: align 0 is a division
  //     by zero for getPrimitiveAlignSize in the oracle.
  TypeFactory c4(&architecture);
  decodeSynthetic(architecture, c4,
                  "<data_organization><size_alignment_map>"
                  "<entry size=\"8\" alignment=\"8\"/>"
                  "<entry size=\"3\" alignment=\"2\"/>"
                  "<entry size=\"8\" alignment=\"4\"/>"
                  "<entry size=\"5\" alignment=\"0\"/>"
                  "</size_alignment_map></data_organization>");

  // c5: only char_size decoded; everything else derives in setupSizes from
  //     the real architecture (stack spacebase 8 -> int 4, long 8).
  TypeFactory c5(&architecture);
  decodeSynthetic(architecture, c5,
                  "<data_organization><char_size value=\"3\"/></data_organization>");
  c5.setupSizes();

  // c6: skipped children around one consumed size; int != 4 makes
  //     sizeOfLong copy sizeOfInt instead of becoming 8.
  TypeFactory c6(&architecture);
  decodeSynthetic(architecture, c6,
                  "<data_organization><machine_alignment value=\"2\"/>"
                  "<default_alignment value=\"1\"/>"
                  "<short_size value=\"2\"/>"
                  "<integer_size value=\"2\"/>"
                  "<float_size value=\"4\"/>"
                  "<double_size value=\"8\"/>"
                  "</data_organization>");
  c6.setupSizes();

  // c7: negative size survives decode (int4 storage) and flows through the
  //     sizeOfLong = (int==4) ? 8 : int branch.
  TypeFactory c7(&architecture);
  decodeSynthetic(architecture, c7,
                  "<data_organization><integer_size value=\"-2\"/>"
                  "</data_organization>");
  c7.setupSizes();

  // c8: children AFTER <size_alignment_map> are still consumed — Ghidra's
  //     sam branch falls through to the unified closeElement(subId)
  //     (type.cc:4604-4612). A missing close would leave the decoder on
  //     the sam element and silently drop the trailing char_size.
  TypeFactory c8(&architecture);
  decodeSynthetic(architecture, c8,
                  "<data_organization><size_alignment_map>"
                  "<entry size=\"1\" alignment=\"1\"/>"
                  "</size_alignment_map>"
                  "<char_size value=\"3\"/>"
                  "</data_organization>");

  cout << "{\"schema\":1,\"fixture\":\"CSPEC-TYPEORG-STATE-0001\""
       << ",\"arch_inputs\":{\"default_size\":" << architecture.getDefaultSize()
       << ",\"stack_spacebase_size\":" << stackSpacebaseSize
       << ",\"default_data_space_addr_size\":" << dataSpace->getAddrSize()
       << ",\"far_pointer\":" << (farPointer ? 1 : 0) << '}'
       << ",\"production\":{";
  writeSizesFields(cout, production);
  cout << ",\"align\":";
  writeAlignProbes(cout, production, 0, productionAlignProbes);
  cout << ",\"primitive\":";
  writePrimitiveProbes(cout, production, 1, productionAlignProbes);
  cout << "},\"raw_decode\":{";
  writeSizesFields(cout, rawFactory);
  cout << ",\"align\":";
  writeAlignProbes(cout, rawFactory, 0, rawAlignProbes);
  cout << ",\"primitive\":";
  writePrimitiveProbes(cout, rawFactory, 1, rawAlignProbes);
  cout << "},\"cases\":["
       << "{\"name\":\"c1_sparse_map\",\"decoded\":";
  writeSizes(cout, c1);
  cout << ",\"align\":";
  writeAlignProbes(cout, c1, 0, 8);
  cout << ",\"primitive\":";
  writePrimitiveProbes(cout, c1, 1, 8);
  cout << "},{\"name\":\"c2_empty_map\",\"align_error\":\""
       << jsonEscape(c2Error) << "\",\"setup\":";
  writeSizes(cout, c2);
  cout << ",\"align\":";
  writeAlignProbes(cout, c2, 0, 9);
  cout << ",\"primitive\":";
  writePrimitiveProbes(cout, c2, 1, 9);
  cout << "},{\"name\":\"c3_zero_entry\",\"decoded\":";
  writeSizes(cout, c3);
  cout << ",\"align\":";
  writeAlignProbes(cout, c3, 0, 3);
  cout << ",\"primitive\":";
  writePrimitiveProbes(cout, c3, 0, 3);
  cout << "},{\"name\":\"c4_duplicate_zero_align\",\"decoded\":";
  writeSizes(cout, c4);
  cout << ",\"align\":";
  writeAlignProbes(cout, c4, 0, 9);
  cout << "},{\"name\":\"c5_char_only_setup\",\"decoded\":";
  {
    TypeFactory c5Decoded(&architecture);
    decodeSynthetic(architecture, c5Decoded,
                    "<data_organization><char_size value=\"3\"/></data_organization>");
    writeSizes(cout, c5Decoded);
  }
  cout << ",\"setup\":";
  writeSizes(cout, c5);
  cout << ",\"align\":";
  writeAlignProbes(cout, c5, 0, 9);
  cout << ",\"primitive\":";
  writePrimitiveProbes(cout, c5, 1, 9);
  cout << "},{\"name\":\"c6_unknown_children_setup\",\"setup\":";
  writeSizes(cout, c6);
  cout << ",\"align\":";
  writeAlignProbes(cout, c6, 0, 9);
  cout << ",\"primitive\":";
  writePrimitiveProbes(cout, c6, 1, 9);
  cout << "},{\"name\":\"c7_negative_setup\",\"setup\":";
  writeSizes(cout, c7);
  cout << ",\"align\":";
  writeAlignProbes(cout, c7, 0, 9);
  cout << ",\"primitive\":";
  writePrimitiveProbes(cout, c7, 1, 9);
  cout << "},{\"name\":\"c8_sam_followed_by_child\",\"decoded\":";
  writeSizes(cout, c8);
  cout << ",\"align\":";
  writeAlignProbes(cout, c8, 0, 1);
  cout << "}],\"done\":1}\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: cspec_typeorg_state_1204 <spec-directory> <binary>\n";
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
