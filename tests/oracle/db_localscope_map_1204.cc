/*
 * Locked Ghidra 12.0.4 fixture for DB-LOCALSCOPE-MAP-0001: the addMap
 * property fold (database.cc:1153) + the Database flagbase partmap
 * (database.cc:3220-3265, partmap.hh:50-160).
 *
 * Every observable comes from production paths on the real BfdArchitecture
 * of function GetStr: Database::setPropertyRange / clearPropertyRange /
 * getProperty, Database::encode/decode, ScopeInternal::decodeHole (via
 * <hole> children in document order), Scope::addSymbol / addMapPoint ->
 * Scope::addMap, and Scope::queryProperties.
 *
 * Cases:
 *   setup                      space indices of the live architecture.
 *   fb_accumulate              two OVERLAPPING property ranges: the shared
 *                              partitions accumulate readonly|volatile
 *                              (database.cc:3236 `|=`, not overwrite).
 *   fb_clear_subrange          clearPropertyRange over a SUB-RANGE of an
 *                              installed range: only the listed bits clear,
 *                              only inside [first,last_open)
 *                              (database.cc:3260-3263); the neighbours keep
 *                              theirs.
 *   fb_roundtrip               Database::encode -> decode: the changepoint
 *                              sequence (split points + cumulative values)
 *                              survives the round-trip exactly
 *                              (database.cc:3273-3288 / 3325-3335
 *                              flagbase.split(addr) = val).
 *   fb_hole_interleave_*       <hole> children inside <symbollist> hit
 *                              setPropertyRange at their DOCUMENT POSITION
 *                              (database.cc:2768-2784 -> 2683-2685): a
 *                              <mapsym> BEFORE the hole installs without the
 *                              property fold, one AFTER folds — and with the
 *                              hole first, BOTH fold.
 *   fold_ro_after /            the addMap fold (database.cc:1149-1153): a
 *   fold_vol_after             static map with an EMPTY uselimit ORs the
 *                              flagbase bits at the mapping START into the
 *                              SYMBOL's flags — visible in getAllFlags
 *                              (database.hh:271) through queryProperties.
 *   fold_overlap_*             overlapping ranges folded per mapping START
 *                              address: both bits / readonly-only /
 *                              volatile-only.
 *   fold_tail_overlap          a property range that starts INSIDE the
 *                              symbol's extent: the fold reads entry.addr
 *                              (the START) only — nothing folds.
 *   fold_usepoint_guard        a usepoint-restricted map (non-empty
 *                              uselimit) takes NEITHER addrtied NOR the
 *                              fold (database.cc:1149-1154 guard); at the
 *                              invalid usepoint the entry does not answer
 *                              and the scope-only branch supplies
 *                              mapped|addrtied|property.
 *   fold_victim_before         the scopelocal-review victim scenario: the
 *                              symbol is installed BEFORE the property
 *                              range — no fold into its flags; the property
 *                              is observable only through the query-time
 *                              getProperty of the scope-only branch
 *                              (database.cc:1273-1276).
 *   fold_global_persist        a global-scope symbol in a readonly range:
 *                              persist (database.cc:1131-1132) AND the fold
 *                              both land — getAllFlags =
 *                              mapped|addrtied|persist|readonly.
 *   fold_discovery_clear       the decisive database.cc:1133-1142
 *                              interaction: a LOCAL symbol mapped at an
 *                              address inside the GLOBAL scope's discovery
 *                              range with a USEPOINT gets persist AND its
 *                              uselimit CLEARED — the cleared uselimit then
 *                              feeds the addrtied + fold branch, so the
 *                              entry answers at an INVALID usepoint with
 *                              mapped|addrtied|persist|readonly.
 */

#include "bfd_arch.hh"
#include "funcdata.hh"
#include "libdecomp.hh"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::istringstream;
using std::ostringstream;
using std::string;
using std::vector;

const char *scopeName(int4 which)
{
  switch (which) {
  case 0: return "none";
  case 1: return "this";
  case 2: return "parent";
  }
  return "?";
}

// One queryProperties observation (same projection the scopelocal fixture
// uses): entry identity + getAllFlags + the answering scope derived from
// the return value.
struct QpResult {
  SymbolEntry *entry;
  uint4 flags;
  int4 answeredScope; // 0 none, 1 this, 2 parent/global
};

QpResult queryPropertiesObserved(Scope *lm, const Address &addr, int4 size,
                                 const Address &usepoint)
{
  QpResult res;
  res.entry = lm->queryProperties(addr, size, usepoint, res.flags);
  if (res.entry != (SymbolEntry *)0) {
    res.answeredScope =
        (res.entry->getSymbol()->getScope() == (const Scope *)lm) ? 1 : 2;
    return res;
  }
  if ((res.flags & Varnode::persist) != 0) {
    res.answeredScope = 2;
    return res;
  }
  if ((res.flags & (Varnode::mapped | Varnode::addrtied)) ==
      (Varnode::mapped | Varnode::addrtied)) {
    res.answeredScope = 1;
    return res;
  }
  res.answeredScope = 0;
  return res;
}

void dumpQp(const string &caseName, AddrSpace *spc, uintb offset, int4 size,
            const Address &usepoint, SymbolEntry *entry, uint4 flags,
            int4 answeredScope)
{
  ostringstream out;
  out << "case=" << caseName << "|kind=qp"
      << "|query=0x" << std::hex << offset << ':' << size;
  if (usepoint.isInvalid())
    out << "|up=inv";
  else
    out << "|up=0x" << std::hex << usepoint.getOffset();
  if (entry == (SymbolEntry *)0) {
    out << "|result=null";
  }
  else {
    out << "|result=" << entry->getSymbol()->getName()
        << "|first=0x" << std::hex << entry->getFirst()
        << "|last=0x" << std::hex << entry->getLast()
        << "|off=" << std::dec << entry->getOffset();
  }
  out << "|flags=0x" << std::hex << flags
      << "|scope=" << scopeName(answeredScope);
  std::cout << out.str() << '\n';
  std::cout.flush();
}

void dumpQpCase(const string &caseName, Scope *lm, AddrSpace *spc,
                uintb offset, int4 size, const Address &usepoint)
{
  QpResult r = queryPropertiesObserved(lm, Address(spc, offset), size, usepoint);
  dumpQp(caseName, spc, offset, size, usepoint, r.entry, r.flags, r.answeredScope);
}

void dumpProp(const string &caseName, Database *db, AddrSpace *spc,
              const uintb *offsets, int4 count)
{
  ostringstream out;
  out << "case=" << caseName;
  for (int4 i = 0; i < count; ++i)
    out << "|p" << i << "=0x" << std::hex << db->getProperty(Address(spc, offsets[i]));
  std::cout << out.str() << '\n';
  std::cout.flush();
}

// The changepoint sequence of a Database's flagbase (split point offsets +
// cumulative values), used for the encode/decode round-trip projection.
void dumpChangepoints(const string &caseName, Database *db)
{
  ostringstream out;
  const partmap<Address, uint4> &props = db->getProperties();
  int4 count = 0;
  partmap<Address, uint4>::const_iterator iter, enditer;
  iter = props.begin();
  enditer = props.end();
  for (; iter != enditer; ++iter)
    ++count;
  out << "case=" << caseName << "|changepoints=" << std::dec << count;
  for (iter = props.begin(); iter != enditer; ++iter) {
    out << "|cp=0x" << std::hex << (*iter).first.getOffset()
        << ":0x" << std::hex << (*iter).second;
  }
  std::cout << out.str() << '\n';
  std::cout.flush();
}

// Decode one hand-written <db> document into a FRESH Database and report
// the getAllFlags of each named mapsym (queried at its address with an
// invalid usepoint) plus the property at two sample addresses.
void decodeInterleave(Architecture *glb, const string &xml,
                      const vector<string> &names, const vector<uintb> &addrs,
                      const char *caseName)
{
  istringstream in(xml);
  Document *doc = xml_tree(in);
  Database db(glb, false);
  // Production shape: the global Scope exists before any decode
  // (Architecture::init creates it); attach one so <scope id="0"> resolves.
  db.attachScope(new ScopeInternal(0, "", glb), (Scope *)0);
  XmlDecode decoder(glb, doc->getRoot());
  db.decode(decoder);
  // The single <scope name="" id="0"> becomes the fresh Database's global
  // scope (attachScope with a null parent, database.cc:2985-2996).
  Scope *global = db.getGlobalScope();
  if (global == (Scope *)0)
    throw std::runtime_error("interleave db has no global scope");
  for (int4 i = 0; i < names.size(); ++i) {
    SymbolEntry *entry =
        global->queryByAddr(Address(glb->getDefaultCodeSpace(), addrs[i]), Address());
    if (entry == (SymbolEntry *)0) {
      std::cout << "case=" << caseName << "|sym=" << names[i] << "|result=null\n";
    }
    else {
      std::cout << "case=" << caseName << "|sym=" << names[i]
                << "|result=" << entry->getSymbol()->getName()
                << "|flags=0x" << std::hex << entry->getAllFlags() << '\n';
    }
    std::cout.flush();
  }
  // ScopeInternal::decodeHole writes through `glb->symboltab`
  // (database.cc:2684) — in production that IS the Database being decoded;
  // the fresh fixture Database models the isolated decode, so the property
  // samples read the seam the oracle actually wrote: the architecture's
  // symbol table flagbase.
  ostringstream out;
  out << "case=" << caseName << "-prop"
      << "|p0=0x" << std::hex << glb->symboltab->getProperty(Address(glb->getDefaultCodeSpace(), addrs[0]))
      << "|p1=0x" << std::hex << glb->symboltab->getProperty(Address(glb->getDefaultCodeSpace(), addrs[1]));
  std::cout << out.str() << '\n';
  std::cout.flush();
  delete doc;
  (void)global;
}

void runCases(Funcdata &fd)
{
  Architecture *glb = fd.getArch();
  AddrSpace *stack = glb->getStackSpace();
  AddrSpace *code = glb->getDefaultCodeSpace();
  AddrSpace *unique = glb->getUniqueSpace();
  AddrSpace *constspc = glb->getConstantSpace();
  TypeFactory *types = glb->types;
  ScopeLocal *lm = fd.getScopeLocal();
  Scope *globals = glb->symboltab->getGlobalScope();
  Database *db = glb->symboltab;

  {
    ostringstream out;
    out << "case=setup|const_index=" << std::dec << constspc->getIndex()
        << "|ram_index=" << code->getIndex()
        << "|stack_index=" << stack->getIndex()
        << "|unique_index=" << unique->getIndex();
    std::cout << out.str() << '\n';
    std::cout.flush();
  }

  // fb_accumulate: readonly [0x7e100000,0x7e1000ff], volatile
  // [0x7e100080,0x7e10017f] — the shared partitions carry both bits.
  db->setPropertyRange(Varnode::readonly,
                       Range(code, 0x7e100000, 0x7e1000ff));
  db->setPropertyRange(Varnode::volatil,
                       Range(code, 0x7e100080, 0x7e10017f));
  {
    const uintb offs[] = {0x7e0fffff, 0x7e100040, 0x7e1000a0, 0x7e100120,
                          0x7e100180};
    dumpProp("fb_accumulate", db, code, offs, 5);
  }

  // fb_clear_subrange: clear readonly over [0x7e100040,0x7e10005f] — a
  // sub-range of the readonly span and of nothing else. Inside the cleared
  // hole the value drops to 0; the neighbours (and the volatile bits of the
  // overlapping range) survive.
  db->clearPropertyRange(Varnode::readonly,
                         Range(code, 0x7e100040, 0x7e10005f));
  {
    const uintb offs[] = {0x7e100030, 0x7e100050, 0x7e100060, 0x7e1000a0};
    dumpProp("fb_clear_subrange", db, code, offs, 4);
  }

  // fb_roundtrip: a manually populated FRESH Database encodes its flagbase
  // as <property_changepoint> split points (database.cc:3273-3288); a
  // decode into another fresh Database assigns each split point its exact
  // value (database.cc:3334), preserving the partition boundaries.
  {
    Database db1(glb, false);
    db1.setPropertyRange(Varnode::readonly,
                         Range(code, 0x7e110000, 0x7e1100ff));
    db1.setPropertyRange(Varnode::volatil,
                         Range(code, 0x7e110080, 0x7e11017f));
    db1.clearPropertyRange(Varnode::readonly,
                           Range(code, 0x7e1100c0, 0x7e1100df));
    ostringstream encoded;
    XmlEncode encoder(encoded, false);
    db1.encode(encoder);
    istringstream in(encoded.str());
    Document *doc = xml_tree(in);
    Database db2(glb, false);
    XmlDecode decoder(glb, doc->getRoot());
    db2.decode(decoder);
    dumpChangepoints("fb_roundtrip", &db2);
    {
      const uintb offs[] = {0x7e110040, 0x7e1100a0, 0x7e1100d0, 0x7e110120};
      dumpProp("fb_roundtrip_prop", &db2, code, offs, 4);
    }
    delete doc;
  }

  // fb_hole_interleave: <hole> children apply at their document position
  // (database.cc:2768-2784). pre_victim installs BEFORE the hole — no fold;
  // post_folded installs AFTER — readonly folds into its symbol flags.
  {
    const char *xml =
        "<db>"
        "<scope name=\"\" id=\"0\">"
        "<symbollist>"
        "<mapsym><symbol name=\"pre_victim\"><type name=\"int\" size=\"4\" metatype=\"int\"/></symbol>"
        "<addr space=\"ram\" offset=\"0x7e120000\"/><rangelist/></mapsym>"
        "<hole space=\"ram\" first=\"0x7e120000\" last=\"0x7e1200ff\" readonly=\"true\"/>"
        "<mapsym><symbol name=\"post_folded\"><type name=\"int\" size=\"4\" metatype=\"int\"/></symbol>"
        "<addr space=\"ram\" offset=\"0x7e120010\"/><rangelist/></mapsym>"
        "</symbollist>"
        "</scope>"
        "</db>";
    vector<string> names;
    names.push_back("pre_victim");
    names.push_back("post_folded");
    vector<uintb> addrs;
    addrs.push_back(0x7e120000);
    addrs.push_back(0x7e120010);
    decodeInterleave(glb, xml, names, addrs, "fb_hole_interleave");
  }
  // Same content, hole FIRST: both mapsyms fold.
  {
    const char *xml =
        "<db>"
        "<scope name=\"\" id=\"0\">"
        "<symbollist>"
        "<hole space=\"ram\" first=\"0x7e130000\" last=\"0x7e1300ff\" readonly=\"true\"/>"
        "<mapsym><symbol name=\"hole_first_a\"><type name=\"int\" size=\"4\" metatype=\"int\"/></symbol>"
        "<addr space=\"ram\" offset=\"0x7e130000\"/><rangelist/></mapsym>"
        "<mapsym><symbol name=\"hole_first_b\"><type name=\"int\" size=\"4\" metatype=\"int\"/></symbol>"
        "<addr space=\"ram\" offset=\"0x7e130010\"/><rangelist/></mapsym>"
        "</symbollist>"
        "</scope>"
        "</db>";
    vector<string> names;
    names.push_back("hole_first_a");
    names.push_back("hole_first_b");
    vector<uintb> addrs;
    addrs.push_back(0x7e130000);
    addrs.push_back(0x7e130010);
    decodeInterleave(glb, xml, names, addrs, "fb_hole_interleave_flipped");
  }

  // The local scope owns [0x900,0xfff] of the stack (like the scopelocal
  // fixture) so the scope-only queryProperties branch can answer.
  glb->symboltab->addRange(lm, stack, 0x900, 0xfff);

  // fold_ro_after: property range FIRST, then the symbol — the addMap fold
  // (database.cc:1149-1153) ORs readonly into the symbol flags.
  db->setPropertyRange(Varnode::readonly, Range(stack, 0x900, 0x97f));
  lm->addSymbol("foldro", types->getBase(4, TYPE_INT),
                Address(stack, 0x900), Address());
  dumpQpCase("fold_ro_after", lm, stack, 0x902, 2, Address());

  // fold_vol_after: the volatile variant.
  db->setPropertyRange(Varnode::volatil, Range(stack, 0xa00, 0xa7f));
  lm->addSymbol("foldvol", types->getBase(4, TYPE_INT),
                Address(stack, 0xa00), Address());
  dumpQpCase("fold_vol_after", lm, stack, 0xa02, 2, Address());

  // fold_overlap: readonly [0xb00,0xb5f] + volatile [0xb20,0xb7f]. The fold
  // reads the property at each symbol's mapping START:
  //   0xb20 -> both bits, 0xb10 -> readonly only, 0xb60 -> volatile only.
  db->setPropertyRange(Varnode::readonly, Range(stack, 0xb00, 0xb5f));
  db->setPropertyRange(Varnode::volatil, Range(stack, 0xb20, 0xb7f));
  lm->addSymbol("foldboth", types->getBase(4, TYPE_INT),
                Address(stack, 0xb20), Address());
  lm->addSymbol("foldroonly", types->getBase(4, TYPE_INT),
                Address(stack, 0xb10), Address());
  lm->addSymbol("foldvolonly", types->getBase(4, TYPE_INT),
                Address(stack, 0xb60), Address());
  dumpQpCase("fold_overlap_both", lm, stack, 0xb22, 2, Address());
  dumpQpCase("fold_overlap_ro_only", lm, stack, 0xb12, 2, Address());
  dumpQpCase("fold_overlap_vol_only", lm, stack, 0xb62, 2, Address());

  // fold_tail_overlap: the property range starts INSIDE the symbol extent —
  // the fold reads entry.addr (0xc00) only, so nothing folds.
  db->setPropertyRange(Varnode::readonly, Range(stack, 0xc04, 0xc0f));
  lm->addSymbol("tailover", types->getBase(8, TYPE_INT),
                Address(stack, 0xc00), Address());
  dumpQpCase("fold_tail_overlap", lm, stack, 0xc00, 4, Address());

  // fold_usepoint_guard: a usepoint-restricted map inside a readonly range
  // takes neither addrtied nor the fold. At the usepoint the entry answers
  // with bare mapped; at the INVALID usepoint it does not answer at all,
  // and the scope-only branch supplies mapped|addrtied|readonly.
  db->setPropertyRange(Varnode::readonly, Range(stack, 0xd00, 0xd7f));
  lm->addSymbol("guarded", types->getBase(4, TYPE_INT),
                Address(stack, 0xd00), Address(code, 0x1000));
  dumpQpCase("fold_usepoint_guard_hit", lm, stack, 0xd00, 4, Address(code, 0x1000));
  dumpQpCase("fold_usepoint_guard_miss", lm, stack, 0xd00, 4, Address());

  // fold_victim_before: symbol FIRST, property AFTER — no fold into the
  // symbol flags (getAllFlags has no readonly); the property shows up only
  // through the query-time getProperty of the scope-only branch
  // (database.cc:1273-1276) at an UNMAPPED address inside the range.
  lm->addSymbol("victim2", types->getBase(4, TYPE_INT),
                Address(stack, 0xe00), Address());
  db->setPropertyRange(Varnode::readonly, Range(stack, 0xe00, 0xe7f));
  dumpQpCase("fold_victim_before", lm, stack, 0xe02, 2, Address());
  dumpQpCase("fold_victim_scope_only", lm, stack, 0xe40, 1, Address());

  // fold_global_persist: a global-scope symbol in a readonly ram range —
  // persist (database.cc:1131-1132) AND the fold both land.
  db->setPropertyRange(Varnode::readonly,
                       Range(code, 0x7e140000, 0x7e1400ff));
  globals->addSymbol("gfold", types->getBase(8, TYPE_INT),
                     Address(code, 0x7e140000), Address());
  dumpQpCase("fold_global_persist", globals, code, 0x7e140002, 2, Address());

  // fold_discovery_clear: extend the global scope's ownership over a ram
  // window, install the readonly range, then map a LOCAL symbol there WITH
  // a usepoint — database.cc:1133-1142 sets persist and CLEARS the
  // uselimit, so the entry becomes addrtied, folds readonly, and answers
  // at an INVALID usepoint.
  db->addRange(globals, code, 0x7e150000, 0x7e1500ff);
  db->setPropertyRange(Varnode::readonly,
                       Range(code, 0x7e150000, 0x7e1500ff));
  lm->addSymbol("discovery", types->getBase(4, TYPE_INT),
                Address(code, 0x7e150010), Address(code, 0x1000));
  dumpQpCase("fold_discovery_clear", lm, code, 0x7e150010, 4, Address());
  // The cleared uselimit is observable: the entry answers without one.
  {
    SymbolEntry *entry =
        lm->queryByAddr(Address(code, 0x7e150010), Address());
    ostringstream out;
    out << "case=fold_discovery_uselimit"
        << "|result=" << (entry != (SymbolEntry *)0
                              ? entry->getSymbol()->getName()
                              : "null")
        << "|uselimit_empty="
        << ((entry != (SymbolEntry *)0 && entry->getUseLimit().empty()) ? 1 : 0);
    std::cout << out.str() << '\n';
    std::cout.flush();
  }
}

void run(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    // Loader overlap warnings route to the architecture's print stream;
    // capture them so both fixture stderr streams stay empty (the runner
    // requires it).
    std::ostringstream diagnostics;
    BfdArchitecture architecture(binary, "default", &diagnostics);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw std::runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->getName() != "GetStr" ||
        fd->getAddress().getOffset() != 0x36d0 || fd->getSize() != 0)
      throw std::runtime_error("GetStr input identity drifted");
    if (architecture.archid != "x86:LE:64:default:gcc")
      throw std::runtime_error("runtime architecture/compiler drifted: " +
                               architecture.archid);
    runCases(*fd);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: db_localscope_map_1204 SPEC_ROOT CURL_BINARY\n";
    return 2;
  }
  try {
    run(argv[1], argv[2]);
    return 0;
  }
  catch (const LowlevelError &error) {
    std::cerr << "db_localscope_map_1204: LowlevelError: "
              << error.explain << '\n';
    return 1;
  }
  catch (const DecoderError &error) {
    std::cerr << "db_localscope_map_1204: DecoderError: "
              << error.explain << '\n';
    return 1;
  }
  catch (const std::exception &error) {
    std::cerr << "db_localscope_map_1204: " << error.what() << '\n';
    return 1;
  }
}
