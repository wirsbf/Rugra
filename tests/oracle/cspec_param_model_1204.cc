/*
 * CSPEC-PARAMMODEL-0001: locked Ghidra 12.0.4 compiler-spec parameter oracle.
 */
#include "bfd_arch.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "xml.hh"

#include <iostream>
#include <list>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::runtime_error;

class FixtureBfdArchitecture : public BfdArchitecture {
public:
  FixtureBfdArchitecture(const string &filename,const string &target,ostream *estream)
    : BfdArchitecture(filename,target,estream) {}

  ProtoModel *decodeFixtureProto(Decoder &decoder)
  {
    return decodeProto(decoder);
  }
};

string jsonEscape(const string &value)
{
  ostringstream out;
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

const Element *findChild(const Element *parent,const string &name)
{
  const List &children = parent->getChildren();
  for (List::const_iterator iter = children.begin(); iter != children.end(); ++iter) {
    if ((*iter)->getName() == name)
      return *iter;
  }
  return (const Element *)0;
}

const Element *findPrototype(const Element *compilerSpec,const string &name)
{
  const List &children = compilerSpec->getChildren();
  for (List::const_iterator iter = children.begin(); iter != children.end(); ++iter) {
    const Element *candidate = *iter;
    if (candidate->getName() != "prototype")
      continue;
    if (candidate->getAttributeValue("name") == name)
      return candidate;
  }
  return (const Element *)0;
}

void writeRanges(ostream &out,const RangeList &ranges)
{
  out << '[';
  bool first = true;
  for (set<Range>::const_iterator iter = ranges.begin(); iter != ranges.end(); ++iter) {
    if (!first) out << ',';
    first = false;
    out << "{\"space\":\"" << iter->getSpace()->getName()
        << "\",\"first\":" << iter->getFirst()
        << ",\"last\":" << iter->getLast() << '}';
  }
  out << ']';
}

void writeEntries(ostream &out,const ParamListStandard &params)
{
  out << '[';
  bool firstEntry = true;
  const list<ParamEntry> &entries = params.getEntry();
  for (list<ParamEntry>::const_iterator iter = entries.begin(); iter != entries.end(); ++iter) {
    if (!firstEntry) out << ',';
    firstEntry = false;
    out << "{\"space\":\"" << iter->getSpace()->getName()
        << "\",\"offset\":" << iter->getBase()
        << ",\"size\":" << iter->getSize()
        << ",\"minsize\":" << iter->getMinSize()
        << ",\"align\":" << iter->getAlign()
        << ",\"type\":" << static_cast<int4>(iter->getType())
        << ",\"groups\":[";
    const vector<int4> &groups = iter->getAllGroups();
    for (size_t index = 0; index < groups.size(); ++index) {
      if (index != 0) out << ',';
      out << groups[index];
    }
    out << "],\"reverse\":" << iter->isReverseStack()
        << ",\"grouped\":" << iter->isGrouped()
        << ",\"overlap\":" << iter->isOverlap()
        << ",\"first_in_class\":" << iter->isFirstInClass() << '}';
  }
  out << ']';
}

void decodeParamList(Architecture &architecture,const Element *element,
                     bool normalStack,ParamListStandard &params,
                     vector<EffectRecord> &effects)
{
  XmlDecode decoder(&architecture,element);
  params.decode(decoder,effects,normalStack);
}

void decodeParamList(Architecture &architecture,const string &xml,
                     bool normalStack,ParamListStandard &params,
                     vector<EffectRecord> &effects)
{
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  params.decode(decoder,effects,normalStack);
}

ProtoModel *decodeProto(FixtureBfdArchitecture &architecture,const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&architecture);
  decoder.ingestStream(stream);
  return architecture.decodeFixtureProto(decoder);
}

string observeError(Architecture &architecture,const string &xml,bool normalStack)
{
  try {
    ParamListStandard params;
    vector<EffectRecord> effects;
    decodeParamList(architecture,xml,normalStack,params,effects);
    return "NO_ERROR";
  }
  catch (LowlevelError &error) {
    return error.explain;
  }
  catch (DecoderError &error) {
    return error.explain;
  }
}

void writeError(ostream &out,const string &name,const string &message)
{
  out << "{\"case\":\"" << name << "\",\"message\":\""
      << jsonEscape(message) << "\"}";
}

void runFixture(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  FixtureBfdArchitecture architecture(binary,"default",&std::cerr);
  DocumentStorage documents;
  architecture.init(documents);

  const Element *compilerSpec = documents.getTag("compiler_spec");
  if (compilerSpec == (const Element *)0)
    throw runtime_error("missing parsed compiler_spec");
  const Element *defaultWrapper = findChild(compilerSpec,"default_proto");
  if (defaultWrapper == (const Element *)0)
    throw runtime_error("missing default_proto");
  const Element *defaultPrototype = findChild(defaultWrapper,"prototype");
  if (defaultPrototype == (const Element *)0)
    throw runtime_error("missing default prototype");
  const Element *defaultInput = findChild(defaultPrototype,"input");
  if (defaultInput == (const Element *)0)
    throw runtime_error("missing default input");
  const Element *msabiPrototype = findPrototype(compilerSpec,"MSABI");
  if (msabiPrototype == (const Element *)0)
    throw runtime_error("missing MSABI prototype");
  const Element *msabiInput = findChild(msabiPrototype,"input");
  if (msabiInput == (const Element *)0)
    throw runtime_error("missing MSABI input");

  ParamListStandard defaultParams;
  vector<EffectRecord> defaultEffects;
  decodeParamList(architecture,defaultInput,true,defaultParams,defaultEffects);
  RangeList defaultStackRanges;
  defaultParams.getRangeList(architecture.getStackSpace(),defaultStackRanges);

  ParamListStandard msabiParams;
  vector<EffectRecord> msabiEffects;
  decodeParamList(architecture,msabiInput,true,msabiParams,msabiEffects);
  RangeList msabiStackRanges;
  msabiParams.getRangeList(architecture.getStackSpace(),msabiStackRanges);

  const string flippedXml =
    "<input><pentry minsize=\"1\" maxsize=\"16\" align=\"4\">"
    "<addr space=\"stack\" offset=\"100\"/></pentry></input>";
  ParamListStandard flippedParams;
  vector<EffectRecord> flippedEffects;
  decodeParamList(architecture,flippedXml,false,flippedParams,flippedEffects);
  RangeList flippedRanges;
  flippedParams.getRangeList(architecture.getStackSpace(),flippedRanges);

  XmlDecode prototypeDecoder(&architecture,defaultPrototype);
  ProtoModel decodedModel(&architecture);
  decodedModel.decode(prototypeDecoder);

  if (architecture.defaultfp == (ProtoModel *)0)
    throw runtime_error("architecture has no default model");
  ProtoModel *oldDefaultHandle = architecture.defaultfp;
  ProtoModel *mapModel = architecture.getModel(oldDefaultHandle->getName());
  const bool initialMapIdentity = mapModel == oldDefaultHandle;
  const string identityPrototype =
    "<prototype name=\"__fixture_external\" extrapop=\"0\"></prototype>";
  ProtoModel *decodedHandle = decodeProto(architecture,identityPrototype);
  ProtoModel *decodedMap = architecture.getModel(decodedHandle->getName());
  const bool decodeReturnMapIdentity = decodedHandle == decodedMap;
  architecture.setDefaultModel(decodedHandle);
  const bool decodeReturnDefaultIdentity = decodedHandle == architecture.defaultfp;
  const bool oldPrintedAfterSelect = oldDefaultHandle->printInDecl();
  const bool decodedPrintedWhenDefault = decodedHandle->printInDecl();
  architecture.setDefaultModel(oldDefaultHandle);
  const bool decodedPrintedAfterRestore = decodedHandle->printInDecl();
  const bool oldPrintedAfterRestore = oldDefaultHandle->printInDecl();
  const bool restoredDefaultIdentity = oldDefaultHandle == architecture.defaultfp;

  const string errors[][3] = {
    {
      "missing_size",
      "<input><pentry minsize=\"1\"><addr space=\"stack\" offset=\"0\"/>"
      "</pentry></input>",
      "normal"
    },
    {
      "bad_extension",
      "<input><pentry minsize=\"1\" maxsize=\"8\" extension=\"mystery\">"
      "<register name=\"RDI\"/></pentry></input>",
      "normal"
    },
    {
      "flipped_misaligned_size",
      "<input><pentry minsize=\"1\" maxsize=\"10\" align=\"4\">"
      "<addr space=\"stack\" offset=\"100\"/></pentry></input>",
      "flipped"
    },
    {
      "entry_after_rule",
      "<input><rule><datatype name=\"any\"/><consume storage=\"general\"/></rule>"
      "<pentry minsize=\"1\" maxsize=\"8\"><register name=\"RDI\"/>"
      "</pentry></input>",
      "normal"
    },
    {
      "ambiguous_group",
      "<input><group><pentry minsize=\"1\" maxsize=\"8\">"
      "<register name=\"RDI\"/></pentry><pentry minsize=\"1\" maxsize=\"8\">"
      "<register name=\"RSI\"/></pentry></group></input>",
      "normal"
    }
  };

  cout << "{\"schema\":1,\"fixture\":\"CSPEC-PARAMMODEL-0001\""
       << ",\"source\":{\"root\":\"" << compilerSpec->getName()
       << "\",\"default_wrapper_children\":" << defaultWrapper->getChildren().size()
       << "},\"default_input\":{\"entry_count\":" << defaultParams.getEntry().size()
       << ",\"entries\":";
  writeEntries(cout,defaultParams);
  cout << ",\"stack_ranges\":";
  writeRanges(cout,defaultStackRanges);
  cout << "},\"msabi_input\":{\"entry_count\":" << msabiParams.getEntry().size()
       << ",\"entries\":";
  writeEntries(cout,msabiParams);
  cout << ",\"stack_ranges\":";
  writeRanges(cout,msabiStackRanges);
  cout << "},\"flipped\":{\"entries\":";
  writeEntries(cout,flippedParams);
  cout << ",\"stack_ranges\":";
  writeRanges(cout,flippedRanges);
  cout << "},\"model\":{\"name\":\"" << decodedModel.getName()
       << "\",\"extrapop\":" << decodedModel.getExtraPop()
       << ",\"param_ranges\":";
  writeRanges(cout,decodedModel.getParamRange());
  cout << ",\"architecture_default_name\":\"" << architecture.defaultfp->getName()
       << "\",\"default_map_identity\":" << initialMapIdentity
       << ",\"default_printed\":" << architecture.defaultfp->printInDecl()
       << ",\"stable_identity\":{\"decode_return_map\":" << decodeReturnMapIdentity
       << ",\"decode_return_default\":" << decodeReturnDefaultIdentity
       << ",\"old_printed_after_select\":" << oldPrintedAfterSelect
       << ",\"decoded_printed_when_default\":" << decodedPrintedWhenDefault
       << ",\"decoded_printed_after_restore\":" << decodedPrintedAfterRestore
       << ",\"old_printed_after_restore\":" << oldPrintedAfterRestore
       << ",\"restored_default_identity\":" << restoredDefaultIdentity << '}'
       << "},\"errors\":[";
  for (size_t index = 0; index < sizeof(errors) / sizeof(errors[0]); ++index) {
    if (index != 0) cout << ',';
    writeError(
      cout,
      errors[index][0],
      observeError(architecture,errors[index][1],errors[index][2] == "normal")
    );
  }
  cout << "]}\n";
}

} // namespace

int main(int argc,char **argv)
{
  if (argc != 3) {
    cerr << "usage: cspec_param_model_1204 <spec-directory> <binary>\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[2]);
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
