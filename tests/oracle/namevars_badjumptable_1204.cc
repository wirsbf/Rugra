/*
 * namevars_badjumptable_1204.cc — locked Ghidra 12.0.4 (e40ed130)
 * CSPEC2-CR-N2 debt fixture: the real-oracle observation of the
 * bad-jump-table rename chain on httpd's ap_vhost_iterate_given_conn
 * (BFD VMA 0x2da50; the BRANCHIND at 0x2daeb fails table recovery with
 * "Too many branches", the FailNormal arm of
 * FlowInfo::truncateIndirectJump flow.cc:751-755).
 *
 * Load contract = the direct-runner golden generator
 * (tools/regen_ghidra_golden.py --direct-runner, same as
 * tests/oracle/getstr_pipeline_1204.cc / stage_seed_diag.cc):
 * BfdArchitecture over the raw binary, readLoaderSymbols, the dynamic
 * symtab function registration, full-range followFlow, the universal
 * action driven to completion, PrintC::docFunction to stdout, the final
 * local scope dump to stderr.
 *
 * Observation set (CSPEC2-CR-N2 trigger path):
 *   stderr [CALLSPEC-BADJT] one line per FuncCallSpecs in registration
 *                          order (Funcdata::numCalls/getCallSpecs,
 *                          funcdata.hh:273-274): call op address, opcode
 *                          name, isBadJumpTable() (fspec.hh:1702) — the
 *                          flag produced by flow.cc:754 and consumed by
 *                          ActionNameVars::lookForBadJumpTables
 *                          (coreaction.cc:2779-2803, called from apply at
 *                          coreaction.cc:2985).
 *   stderr [SYMDUMP-FINAL] ScopeLocal::printEntries — the post-rename
 *                          symbol map tree (database.cc:2791); the
 *                          renamed parameter symbol must appear as
 *                          UNRECOVERED_JUMPTABLE (renameSymbol at
 *                          database.cc:2152 rewrites name+displayName and
 *                          reinserts into the name tree).
 *   stdout                 META line + the rendered C. The signature
 *                          parameter names come from the backing scope
 *                          symbols: PrintC::emitPrototypeInputs
 *                          (printc.cc:2222-2250) prints
 *                          param->getSymbol() through emitVarDecl when the
 *                          ProtoStoreSymbol channel backs the parameter,
 *                          so the renamed symbol's displayName reaches the
 *                          signature text (`code *UNRECOVERED_JUMPTABLE`)
 *                          and every call-site use of the same symbol.
 *
 * usage: namevars_badjumptable_1204 SPEC_ROOT BINARY
 *   target via STAGE_DRILL_FUNC (default ap_vhost_iterate_given_conn)
 *             STAGE_DRILL_ADDR (default 0x2da50)
 */

#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

using namespace ghidra;
using std::runtime_error;
using std::string;

uintb parseEntryAddress(const string &text)
{
  string digits = text;
  if (digits.size() >= 2 && (digits.compare(0,2,"0x") == 0 || digits.compare(0,2,"0X") == 0))
    digits = digits.substr(2);
  if (digits.empty() || digits.find_first_not_of("0123456789abcdefABCDEF") != string::npos)
    throw runtime_error("entry address is not hexadecimal: " + text);
  try {
    return static_cast<uintb>(std::stoull(digits,nullptr,16));
  }
  catch (const std::exception &) {
    throw runtime_error("entry address out of range: " + text);
  }
}

// Exact mirror of the canonical golden generator's loader ingestion for
// stripped binaries (LoadImageBfd reads only the static table; the
// exported functions live in the dynamic symtab).
void registerDynamicFunctionSymbols(Architecture &architecture,const string &binary)
{
  bfd *abfd = bfd_openr(binary.c_str(),"default");
  if (abfd == (bfd *)0)
    throw runtime_error("bfd_openr failed: " + binary);
  if (!bfd_check_format(abfd,bfd_object)) {
    bfd_close(abfd);
    return;
  }
  long upper = bfd_get_dynamic_symtab_upper_bound(abfd);
  if (upper <= 0) {
    bfd_close(abfd);
    return;
  }
  asymbol **symbols = (asymbol **)malloc(static_cast<size_t>(upper));
  if (symbols == (asymbol **)0) {
    bfd_close(abfd);
    throw runtime_error("dynamic symbol table malloc failed");
  }
  long count = bfd_canonicalize_dynamic_symtab(abfd,symbols);
  AddrSpace *code = architecture.getDefaultCodeSpace();
  for (long index = 0;index < count;++index) {
    asymbol *symbol = symbols[index];
    if (symbol == (asymbol *)0 || symbol->name == (const char *)0) continue;
    if ((symbol->flags & BSF_FUNCTION) == 0) continue;
    if (symbol->section == (asection *)0 || bfd_is_und_section(symbol->section))
      continue;
    Address address(code,bfd_asymbol_value(symbol));
    if (architecture.symboltab->getGlobalScope()->queryFunction(address) != (Funcdata *)0)
      continue;
    string basename;
    Scope *scope = architecture.symboltab->findCreateScopeFromSymbolName(
        symbol->name,"::",basename,(Scope *)0);
    scope->addFunction(address,basename);
  }
  free(symbols);
  bfd_close(abfd);
}

void runFixture(const string &specDirectory,const string &binary)
{
  const char *funcEnv = std::getenv("STAGE_DRILL_FUNC");
  const string funcName = (funcEnv != nullptr && *funcEnv != '\0')
    ? string(funcEnv) : string("ap_vhost_iterate_given_conn");
  const char *addrEnv = std::getenv("STAGE_DRILL_ADDR");
  const string addrText = (addrEnv != nullptr && *addrEnv != '\0')
    ? string(addrEnv) : string("0x2da50");
  const uintb entryAddr = parseEntryAddress(addrText);
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    registerDynamicFunctionSymbols(architecture,binary);
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction(funcName);
    if (fd == (Funcdata *)0)
      throw runtime_error(funcName + " was not found in the BFD symbol table");
    if (fd->hasNoCode())
      throw runtime_error(funcName + " has no code");
    if (fd->getAddress().getOffset() != entryAddr) {
      std::ostringstream detail;
      detail << funcName << " entry identity drifted: offset=0x" << std::hex
             << fd->getAddress().getOffset() << " expected=0x" << entryAddr;
      throw runtime_error(detail.str());
    }

    // Drive protocol of the direct-runner golden generator: full flow
    // range (this is where recoverJumpTables fails for the 0x2daeb
    // BRANCHIND and truncateIndirectJump's fail_normal arm runs
    // setBadJumpTable(true) + the "Treating indirect jump as call"
    // warning), then the universal action to completion (this is where
    // ActionNameVars::apply -> lookForBadJumpTables renames the switch
    // variable's scope symbol).
    AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
    fd->followFlow(Address(codeSpace,0),Address(codeSpace,codeSpace->getHighest()));

    Action *root = architecture.allacts.getCurrent();
    if (root == (Action *)0)
      throw runtime_error("no current decompile action");
    root->reset(*fd);
    int4 result;
    do {
      result = root->perform(*fd);
    } while (result < 0);

    std::cout << "META side=oracle-badjt oracle_commit=e40ed13014025f82488b1f8f7bca566894ac376b"
              << " func=" << funcName << " entry=0x" << std::hex << entryAddr << std::dec
              << " arch=x86:LE:64:default cspec=gcc seed=none"
              << " observations=callspec-badjt+symdump-final+c-render" << '\n';

    // Observation 1: every FuncCallSpecs in registration order with its
    // call op address and the bad-jump-table flag. In the healthy chain
    // exactly the truncated 0x2daeb CALLIND carries 1.
    for(int4 i=0;i<fd->numCalls();++i) {
      FuncCallSpecs *fc = fd->getCallSpecs(i);
      const PcodeOp *op = fc->getOp();
      std::cerr << "[CALLSPEC-BADJT] i=" << i
                << " opaddr=0x" << std::hex << op->getAddr().getOffset() << std::dec
                << " opcode=" << get_opname(op->code())
                << " badjt=" << (fc->isBadJumpTable() ? 1 : 0) << '\n';
    }

    // Observation 2: the final local scope map tree. The renamed
    // parameter symbol appears with its UNRECOVERED_JUMPTABLE name.
    std::ostringstream symdump;
    fd->getScopeLocal()->printEntries(symdump);
    std::cerr << "[SYMDUMP-FINAL]\n" << symdump.str() << std::endl;

    // Observation 3: the rendered C — signature parameters print through
    // the backing scope symbols (printc.cc:2222-2250), so the rename is
    // visible in the signature and at the call sites.
    std::ostringstream cOutput;
    architecture.print->setOutputStream(&cOutput);
    architecture.print->docFunction(fd);
    std::cout << cOutput.str();
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 3) {
    std::cerr << "usage: namevars_badjumptable_1204 SPEC_ROOT BINARY\n"
              << "  target via STAGE_DRILL_FUNC / STAGE_DRILL_ADDR\n";
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
