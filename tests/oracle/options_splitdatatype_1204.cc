/*
 * OPTIONS-SPLITDATATYPE-SEMANTICS-0001: locked Ghidra 12.0.4 oracle
 * projection for the OptionSplitDatatypes option semantics.
 *
 * Code under observation (options.cc / options.hh / architecture.cc):
 *   - OptionSplitDatatypes::getOptionBit (options.cc:982-990): token->bit
 *     mapping ""=0, "struct"=1, "array"=2, "pointer"=4 and the
 *     LowlevelError("Unknown data-type split option: ...") rejection.
 *   - OptionSplitDatatypes::apply (options.cc:999-1022): p1 assigns, p2/p3
 *     OR in; the splitcopy/splitpointer action-group toggles driven by the
 *     resulting bits; partial mutation when a later token throws; the
 *     "set"/"unchanged" return messages.
 *   - The Architecture default split_datatype_config = struct|array|pointer
 *     (architecture.cc:1430-1431) and the default "decompile" root group
 *     membership (coreaction.cc:5424-5432 includes "splitcopy" and
 *     "splitpointer").
 *   - OptionDatabase XML decode (options.cc:163-199): the
 *     <splitdatatype> element name resolves through the registered
 *     ElementId (options.cc:57, id 270) to the option; <param1>/<param2>/
 *     <param3> content strings and the no-children ATTRIB_CONTENT form feed
 *     p1/p2/p3 in order.
 *
 * Group-membership observations read the live ActionDatabase group list of
 * the current root Action (allacts.getGroup(allacts.getCurrentName())),
 * which is exactly what toggleAction (action.cc:1036-1053) mutates. Error
 * cases leave that group list untouched, exposing the no-toggle-on-throw
 * timing.
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "action.hh"
#include "marshal.hh"
#include "options.hh"
#include "xml.hh"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using namespace std;

void emitConfig(const Architecture *glb,const string &prefix)

{
  cout << prefix << ".config=" << glb->split_datatype_config << '\n';
}

void emitGroups(const Architecture *glb,const string &prefix)

{
  const ActionGroupList &grp(glb->allacts.getGroup(glb->allacts.getCurrentName()));
  cout << prefix << ".splitcopy_in=" << (grp.contains("splitcopy") ? 1 : 0) << '\n';
  cout << prefix << ".splitpointer_in=" << (grp.contains("splitpointer") ? 1 : 0) << '\n';
}

void emitBit(const string &token)

{
  try {
    uint4 bit = OptionSplitDatatypes::getOptionBit(token);
    cout << "bit." << token << ".value=" << bit << '\n';
  }
  catch(const LowlevelError &err) {
    cout << "bit." << token << ".error=LowlevelError: " << err.explain << '\n';
  }
}

// One direct OptionSplitDatatypes::apply observation: configuration value,
// live group membership after the (possibly aborted) call, and either the
// confirmation message or the thrown LowlevelError text.
void emitApplyCase(Architecture *glb,const string &name,
                   const string &p1,const string &p2,const string &p3)

{
  OptionSplitDatatypes opt;
  string prefix = "apply." + name;
  try {
    string msg = opt.apply(glb,p1,p2,p3);
    emitConfig(glb,prefix);
    emitGroups(glb,prefix);
    cout << prefix << ".msg=" << msg << '\n';
  }
  catch(const LowlevelError &err) {
    emitConfig(glb,prefix);
    emitGroups(glb,prefix);
    cout << prefix << ".error=LowlevelError: " << err.explain << '\n';
  }
}

// One <optionslist> decode observation through the Architecture's live
// OptionDatabase (options.cc:192-199 -> decodeOne options.cc:163-190 ->
// set options.cc:150-161 -> apply).
void emitXmlCase(Architecture *glb,const string &name,const string &xmlText)

{
  string prefix = "xml." + name;
  istringstream stream(xmlText);
  Document *doc = xml_tree(stream);
  XmlDecode decoder(glb->translate,doc->getRoot());
  try {
    glb->options->decode(decoder);
    emitConfig(glb,prefix);
    emitGroups(glb,prefix);
  }
  catch(const LowlevelError &err) {
    // ParseError derives from LowlevelError (error.hh:95), so this handler
    // covers every error the decode path can raise.
    emitConfig(glb,prefix);
    emitGroups(glb,prefix);
    cout << prefix << ".error=LowlevelError: " << err.explain << '\n';
  }
  delete doc;
}

void runFixture(const string &specDirectory,const string &binary)

{
  vector<string> specPaths(1,specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary,"default",&cerr);
  DocumentStorage store;
  architecture.init(store);
  if (architecture.archid != "x86:LE:64:default:gcc")
    throw runtime_error("runtime architecture/compiler drifted: " + architecture.archid);

  cout << "fixture=OPTIONS-SPLITDATATYPE-SEMANTICS-0001" << '\n';
  cout << "architecture=" << architecture.archid << '\n';

  // ---- Default state (architecture.cc:1430-1431, coreaction.cc:5424-5432) ----
  emitConfig(&architecture,"default");
  cout << "default.current_name=" << architecture.allacts.getCurrentName() << '\n';
  emitGroups(&architecture,"default");

  // ---- getOptionBit token->bit mapping (options.cc:982-990) ----
  emitBit("");
  emitBit("struct");
  emitBit("array");
  emitBit("pointer");
  // Old 11.x-era token and garbage are rejected.
  emitBit("float");
  emitBit("bogus");

  // ---- apply semantics (options.cc:999-1022) ----
  // All-empty parameters reset the configuration to 0 and switch both
  // groups off (options.cc:1007-1009).
  emitApplyCase(&architecture,"empty","","","");
  // struct alone: splitcopy on, splitpointer off (options.cc:1010-1013).
  emitApplyCase(&architecture,"struct","struct","","");
  // pointer alone: neither struct nor array bit, so both groups off.
  emitApplyCase(&architecture,"pointer_only","pointer","","");
  // array + pointer: splitcopy and splitpointer both on.
  emitApplyCase(&architecture,"array_pointer","array","pointer","");
  // All three tokens across the three parameter slots.
  emitApplyCase(&architecture,"all3","struct","array","pointer");
  // Repeating the same configuration returns "unchanged" but still runs
  // the toggleAction calls (options.cc:1007-1016 precede the return).
  emitApplyCase(&architecture,"all3_repeat","struct","array","pointer");
  // Bad p1 throws before the assignment: configuration and groups intact.
  emitApplyCase(&architecture,"bad_p1","bogus","","");
  // Bad p2 throws after p1's assignment: configuration holds bit("")==0
  // while the groups keep their previous state (no toggleAction ran).
  emitApplyCase(&architecture,"bad_p2_partial","","bogus","");
  // The 11.x-era "float" token throws exactly like any unknown token.
  emitApplyCase(&architecture,"float_token","float","","");

  // ---- XML <optionslist> decode (options.cc:163-199) ----
  // <param1>/<param2> positional content feeds p1/p2.
  emitXmlCase(&architecture,"struct_pointer",
    "<optionslist><splitdatatype><param1>pointer</param1>"
    "<param2>struct</param2></splitdatatype></optionslist>");
  // A bad token inside the XML throws out of decode; state is untouched.
  emitXmlCase(&architecture,"bad_token",
    "<optionslist><splitdatatype><param1>float</param1>"
    "</splitdatatype></optionslist>");
  // No children: the element's ATTRIB_CONTENT text is p1 (options.cc:181).
  emitXmlCase(&architecture,"no_children_content",
    "<optionslist><splitdatatype>array</splitdatatype></optionslist>");
  // <param3> reaches the third parameter slot.
  emitXmlCase(&architecture,"param3",
    "<optionslist><splitdatatype><param1>struct</param1>"
    "<param2>array</param2><param3>pointer</param3>"
    "</splitdatatype></optionslist>");
}

} // namespace

int main(int argc,char **argv)

{
  try {
    if (argc != 3)
      throw invalid_argument("usage: options_splitdatatype_1204 SPEC_DIRECTORY BINARY");
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const LowlevelError &err) {
    cerr << "LowlevelError: " << err.explain << '\n';
  }
  catch(const exception &err) {
    cerr << "std::exception: " << err.what() << '\n';
  }
  return 1;
}
