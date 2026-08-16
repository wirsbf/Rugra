/*
 * CSPEC-TEXT-INGEST-0001: locked Ghidra 12.0.4 compiler-spec text-ingest
 * oracle.  Loads the real production x86-64-gcc.cspec through a full
 * BfdArchitecture::init (which drives Architecture::parseCompilerConfig)
 * and prints the published state projections that the Rust fixture must
 * reproduce byte for byte from the same cspec bytes:
 *   - the address-space table (index/name/type/addrsize/highest),
 *   - the deferred <global> application to the global scope (sorted
 *     (space index, first) like Scope::printBounds),
 *   - Architecture::defaultReturnAddr (space/offset/size),
 *   - the <stackpointer> effects (stack space name + growth direction),
 *   - per-model default return-address injection (fspec.cc:2689),
 *   - the 16 <callfixup> registrations (ids/names/params) plus their
 *     compiled templates via InjectPayloadSleigh::printTemplate,
 *   - synthetic <callotherfixup>/<volatile> decode probes through
 *     UserOpManage (userop.cc decode chain), including the
 *     non-transactional library residue after the error paths.
 */
#include "bfd_arch.hh"
#include "fspec.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "xml.hh"

#include <fstream>
#include <iostream>
#include <list>
#include <sstream>
#include <stdexcept>
#include <string>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;
using std::exception;
using std::getline;
using std::istringstream;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

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

string observeError(void (*action)(Architecture &, const string &), Architecture &arch, const string &xml)
{
  try {
    action(arch, xml);
    return "NO_ERROR";
  }
  catch (LowlevelError &error) {
    return error.explain;
  }
  catch (DecoderError &error) {
    return error.explain;
  }
}

void runCallOtherFixup(Architecture &arch, const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&arch);
  decoder.ingestStream(stream);
  arch.userops.decodeCallOtherFixup(decoder, &arch);
}

// Reviewer probe F1: a <callfixup> whose <pcode> declares a nameless
// <input> — InjectPayload::decodeParameter (pcodeinject.cc:62-63) throws
// LowlevelError("Missing inject parameter name") which propagates through
// decodePayloadParams and aborts the decode, leaving the allocated payload
// unregistered (getPayloadId == -1).
void runCallFixupParamName(Architecture &arch, const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&arch);
  decoder.ingestStream(stream);
  arch.pcodeinjectlib->decodeInject(arch.archid + " : compiler spec", "",
                                    InjectPayload::CALLFIXUP_TYPE, decoder);
}

// Reviewer probe F2/F3: rebuild the architecture against a surgically
// modified copy of the production cspec (identical byte-level transform on
// both fixture sides) to drive the full parseCompilerConfig chain.
string readFile(const string &path)
{
  ifstream in(path.c_str());
  if (!in)
    throw runtime_error("cannot read " + path);
  ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

void copyFile(const string &from, const string &to)
{
  ofstream out(to.c_str());
  out << readFile(from);
}

string replaceReturnAddressBlock(const string &cspec, const string &replacement,
                                 const string &extraChild)
{
  const size_t start = cspec.find("<returnaddress>");
  const size_t end = cspec.find("</returnaddress>", start);
  if (start == string::npos || end == string::npos)
    throw runtime_error("returnaddress block not found");
  return cspec.substr(0, start) + replacement + extraChild +
         cspec.substr(end + strlen("</returnaddress>"));
}

// Private working copy of the spec set (never mutates the input directory):
// specpaths.findFile resolves by first-registered directory, so the probe
// transforms must overwrite the cspec IN the one registered directory.
string makeWorkSpecDir(const string &specDirectory)
{
  char templatePath[] = "/tmp/cspec-text-ingest-work.XXXXXX";
  const char *created = ::mkdtemp(templatePath);
  if (created == (const char *)0)
    throw runtime_error("mkdtemp failed");
  const string dir(created);
  const char *names[] = {"x86.ldefs", "x86-64.pspec", "x86-64.sla", "x86-64-gcc.cspec"};
  for (int i = 0; i < 4; ++i)
    copyFile(specDirectory + "/" + names[i], dir + "/" + names[i]);
  return dir;
}

void writeCspec(const string &workDir, const string &cspecText)
{
  ofstream out((workDir + "/x86-64-gcc.cspec").c_str());
  out << cspecText;
}

void runVolatile(Architecture &arch, const string &xml)
{
  istringstream stream(xml);
  XmlDecode decoder(&arch);
  decoder.ingestStream(stream);
  // Architecture::decodeVolatile (architecture.cc:884) opens the
  // <volatile> element before delegating the attributes to
  // UserOpManage::decodeVolatile; the range children that follow belong to
  // the Database property domain and are absent from this synthetic probe.
  uint4 elemId = decoder.openElement();
  arch.userops.decodeVolatile(decoder, &arch);
  decoder.closeElement(elemId);
}

int countLibraryPayloads(Architecture &arch)
{
  // Ids are dense from zero; scan while any per-type name vector yields a
  // name for the id.
  int4 total = 0;
  for (int4 id = 0; id < 4096; ++id) {
    bool present = (arch.pcodeinjectlib->getCallFixupName(id).size() != 0) ||
                   (arch.pcodeinjectlib->getCallOtherTarget(id).size() != 0) ||
                   (arch.pcodeinjectlib->getCallMechanismName(id).size() != 0);
    if (!present)
      break;
    total += 1;
  }
  return total;
}

void runFixture(const string &specDirectory, const string &binary)
{
  const string workDir = makeWorkSpecDir(specDirectory);
  vector<string> specPaths;
  specPaths.push_back(workDir);
  startDecompilerLibrary(specPaths);
  BfdArchitecture arch(binary, "default", &std::cerr);
  DocumentStorage documents;
  arch.init(documents);

  cout << "SCHEMA|1\n";

  // Address-space table (locked x86-64 language facts the Rust host must
  // mirror: index, name, type, address size, highest offset).
  for (int4 i = 0; i < arch.numSpaces(); ++i) {
    AddrSpace *spc = arch.getSpace(i);
    if (spc == (AddrSpace *)0)
      continue;
    cout << "SPACE|" << i << "|" << spc->getName() << "|" << (int4)spc->getType()
         << "|" << spc->getAddrSize() << "|0x" << std::hex << spc->getHighest()
         << std::dec << "\n";
  }

  // Deferred <global> application result: the global scope's range tree,
  // printed through the public Scope::printBounds (sorted by
  // (space index, first) via Range::operator<).
  {
    const Scope *globalScope = arch.symboltab->getGlobalScope();
    ostringstream buffer;
    globalScope->printBounds(buffer);
    istringstream lines(buffer.str());
    string line;
    while (getline(lines, line)) {
      if (line == "all")
        continue;
      cout << "GLOBAL|" << line << "\n";
    }
  }

  // Architecture::defaultReturnAddr (architecture.cc:898 decode).
  cout << "RET|" << arch.defaultReturnAddr.space->getName() << "|"
       << arch.defaultReturnAddr.offset << "|" << arch.defaultReturnAddr.size
       << "\n";

  // <stackpointer> effects (architecture.cc:979 decode): the created stack
  // space and its growth direction.
  cout << "STACK|" << arch.getStackSpace()->getName() << "|"
       << (arch.getStackSpace()->stackGrowsNegative() ? 1 : 0) << "\n";

  // Per-model default return-address injection (fspec.cc:2689-2691): count
  // the return_address effect records of each registered model and print
  // the first one (space/offset/size).
  for (map<string, ProtoModel *>::const_iterator iter = arch.protoModels.begin();
       iter != arch.protoModels.end(); ++iter) {
    ProtoModel *model = (*iter).second;
    int4 count = 0;
    string first = "NONE";
    for (vector<EffectRecord>::const_iterator fx = model->effectBegin();
         fx != model->effectEnd(); ++fx) {
      if (fx->getType() != EffectRecord::return_address)
        continue;
      if (count == 0) {
        ostringstream out;
        out << fx->getAddress().getSpace()->getName() << "|" << fx->getAddress().getOffset()
            << "|" << fx->getSize();
        first = out.str();
      }
      count += 1;
    }
    cout << "MODELRET|" << (*iter).first << "|" << count << "|" << first << "\n";
  }

  // The __thiscall alias clone (architecture.cc:1343-1347).
  {
    map<string, ProtoModel *>::const_iterator found = arch.protoModels.find("__thiscall");
    cout << "THISCALL|" << (found == arch.protoModels.end() ? "absent" : "present") << "|"
         << (found == arch.protoModels.end() ? string("") : string(found->second->printInDecl() ? "1" : "0"))
         << "\n";
  }

  // <callfixup> registrations + compiled templates.
  for (int4 id = 0; id < 64; ++id) {
    string name = arch.pcodeinjectlib->getCallFixupName(id);
    if (name.size() == 0)
      continue;
    InjectPayload *payload = arch.pcodeinjectlib->getPayload(id);
    cout << "FIXUP|" << id << "|" << name << "|" << payload->sizeInput() << "|"
         << payload->sizeOutput() << "|" << payload->getParamShift() << "|"
         << (payload->isDynamic() ? 1 : 0) << "|"
         << (payload->isIncidentalCopy() ? 1 : 0) << "\n";
    ostringstream buffer;
    payload->printTemplate(buffer);
    cout << "TPL|" << id << "|" << escapeNewlines(buffer.str()) << "\n";
  }

  // Synthetic <callotherfixup> probes (userop.cc:85-96 + userop.cc:589).
  // Probe 1: compile failure — the body references undeclared parameters,
  // so parseInject (inject_sleigh.cc:373) fails AFTER
  // registerCallOtherFixup, leaving the registered map entry and the grown
  // injection vector behind (non-transactional residue).
  {
    cout << "CALLOTHER_COUNT_BEFORE|" << countLibraryPayloads(arch) << "\n";
    const string message = observeError(runCallOtherFixup, arch,
      "<callotherfixup targetop=\"zz_compile_fail\">"
      "<pcode><body>out1 = in0;</body></pcode></callotherfixup>");
    cout << "CALLOTHER_COMPILEFAIL|" << message << "\n";
    cout << "CALLOTHER_COUNT_AFTER|" << countLibraryPayloads(arch) << "\n";
    cout << "CALLOTHER_RESIDUE_ID|"
         << arch.pcodeinjectlib->getPayloadId(InjectPayload::CALLOTHERFIXUP_TYPE, "zz_compile_fail")
         << "\n";
  }

  // Probe 2: declared parameters compile cleanly, so registration succeeds
  // and the failure moves to the unknown userop lookup in
  // InjectedUserOp::decode (userop.cc:89-90).
  {
    const string message = observeError(runCallOtherFixup, arch,
      "<callotherfixup targetop=\"zz_unknown_target\">"
      "<pcode><input name=\"in0\" size=\"8\"/><output name=\"out1\" size=\"8\"/>"
      "<body>out1 = in0;</body></pcode></callotherfixup>");
    cout << "CALLOTHER_UNKNOWN|" << message << "\n";
    cout << "CALLOTHER_COUNT_AFTER2|" << countLibraryPayloads(arch) << "\n";
    cout << "CALLOTHER_RESIDUE_ID2|"
         << arch.pcodeinjectlib->getPayloadId(InjectPayload::CALLOTHERFIXUP_TYPE, "zz_unknown_target")
         << "\n";
  }

  // Probe 3: a real userop name ("segment", the x86-64 user op at index 0)
  // customizes the unspecialized record into an InjectedUserOp.
  {
    const string message = observeError(runCallOtherFixup, arch,
      "<callotherfixup targetop=\"segment\">"
      "<pcode><input name=\"in0\" size=\"8\"/><output name=\"out1\" size=\"8\"/>"
      "<body>out1 = in0;</body></pcode></callotherfixup>");
    cout << "CALLOTHER_SEGMENT|" << message << "\n";
    cout << "CALLOTHER_COUNT_AFTER3|" << countLibraryPayloads(arch) << "\n";
    UserPcodeOp *op = arch.userops.getOp("segment");
    cout << "CALLOTHER_SEGMENT_TYPE|" << (op == (UserPcodeOp *)0 ? -1 : (int4)op->getType()) << "|"
         << (op == (UserPcodeOp *)0 ? -1 : op->getIndex()) << "\n";
  }

  // Synthetic <volatile> probes (userop.cc:551-583): registration and the
  // duplicate-registration error.
  {
    const string first = observeError(runVolatile, arch,
      "<volatile inputop=\"zz_read\" outputop=\"zz_write\"/>");
    cout << "VOLATILE1|" << first << "\n";
    UserPcodeOp *readOp = arch.userops.getOp(UserPcodeOp::BUILTIN_VOLATILE_READ);
    UserPcodeOp *writeOp = arch.userops.getOp(UserPcodeOp::BUILTIN_VOLATILE_WRITE);
    cout << "VOLATILE_NAMES|" << (readOp == (UserPcodeOp *)0 ? string("null") : readOp->getName())
         << "|" << (writeOp == (UserPcodeOp *)0 ? string("null") : writeOp->getName()) << "\n";
    const string second = observeError(runVolatile, arch,
      "<volatile inputop=\"zz_read2\" outputop=\"zz_write2\"/>");
    cout << "VOLATILE2|" << second << "\n";
  }

  // Reviewer probe F1: nameless <input> aborts the callfixup decode with
  // the exact LowlevelError and leaves the payload unregistered.
  {
    const string message = observeError(runCallFixupParamName, arch,
      "<callfixup name=\"zz_param_name\">"
      "<pcode><input size=\"8\"/><body>RAX = RBX;</body></pcode></callfixup>");
    cout << "CALLFIXUP_PARAMNAME|" << message << "\n";
    cout << "CALLFIXUP_PARAMNAME_ID|"
         << arch.pcodeinjectlib->getPayloadId(InjectPayload::CALLFIXUP_TYPE, "zz_param_name")
         << "\n";
  }

  // Reviewer probes F2/F3: full-chain parses of surgically modified cspec
  // copies.  RA_EMPTY: two attribute-less <returnaddress><varnode/>
  // elements decode to the null-space sentinel (pcoderaw.cc:33-52), so
  // neither the cc:904 guard nor the fspec.cc:2689 injection sees a set
  // default return address.  NOHIGHPTR_HEX: a hex <range> exercises
  // XmlDecode's istringstream hex auto-detection (marshal.cc:353-361).
  {
    const string cspec = readFile(workDir + "/x86-64-gcc.cspec");
    const string emptyCspec = replaceReturnAddressBlock(
        cspec,
        "<returnaddress><varnode/></returnaddress><returnaddress><varnode/></returnaddress>",
        "<nohighptr><range space=\"ram\" first=\"0x100\" last=\"0x2ff\"/></nohighptr>");
    writeCspec(workDir, emptyCspec);
    try {
      BfdArchitecture arch2(binary, "default", &std::cerr);
      DocumentStorage docs2;
      arch2.init(docs2);
      cout << "RA_EMPTY_CHAIN|"
           << (arch2.defaultReturnAddr.space == (AddrSpace *)0 ? "unset" : "set") << "\n";
      // set<Range> iterates sorted by (space index, first).
      {
        ostringstream out;
        int4 count = 0;
        for (set<Range>::const_iterator it = arch2.nohighptr.begin();
             it != arch2.nohighptr.end(); ++it) {
          if (count != 0)
            out << '|';
          out << "0x" << hex << it->getFirst() << "-0x" << it->getLast();
          count += 1;
        }
        cout << "NOHIGHPTR_HEX|" << count << "|" << out.str() << dec << "\n";
      }
    }
    catch (LowlevelError &error) {
      cout << "RA_EMPTY_CHAIN|ERROR|" << error.explain << "\n";
    }
  }
  {
    const string cspec = readFile(workDir + "/x86-64-gcc.cspec");
    const string doubleCspec = replaceReturnAddressBlock(
        cspec,
        "<returnaddress><varnode space=\"ram\" offset=\"0\" size=\"8\"/></returnaddress>"
        "<returnaddress><varnode space=\"ram\" offset=\"0\" size=\"8\"/></returnaddress>",
        "");
    writeCspec(workDir, doubleCspec);
    try {
      BfdArchitecture arch3(binary, "default", &std::cerr);
      DocumentStorage docs3;
      arch3.init(docs3);
      cout << "RA_DOUBLE_CHAIN|NO_ERROR\n";
    }
    catch (LowlevelError &error) {
      cout << "RA_DOUBLE_CHAIN|" << error.explain << "\n";
    }
    catch (DecoderError &error) {
      cout << "RA_DOUBLE_CHAIN|" << error.explain << "\n";
    }
  }

  cout << "DONE\n";
}

} // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    cerr << "usage: cspec_text_ingest_1204 <spec-directory> <binary>\n";
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
