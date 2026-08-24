/*
 * Locked Ghidra 12.0.4 oracle fixture for PRINTC-UNLINKED-REF-FAMILY slice C
 * (A35 audit, /tmp/rugra-reports/A35-PRINTC-UNLINKED-REF.md section 5).
 *
 * Three observation surfaces over the unnamed/symbol-less print fallback
 * family that the E2E differential blamed for the uVar_<hex> label set:
 *
 *   stage=branch — the buildVariableName branch projection: for each
 *     candidate shape the ActionNameVars chain (hasName -> linkSymbol ->
 *     coreaction.cc:2988-2997 buildDefaultName loop) names the symbol and
 *     the fixture records the finished name plus the flag-derived branch
 *     label {stack-form, stack-form-X, counter, persist-reg, in_}.
 *
 *   stage=reach — the symbolization reach five-tuple for the unique-space
 *     temporaries of the seven-function shapes (helpf's `& 2` predicate,
 *     match_url's `!= '#'`, an implied temp the hasName gate must refuse,
 *     an explicit register control): has_high / has_name gate verdict /
 *     link_symbol outcome / final symbol name / print-time lhs token.
 *
 *   stage=print — the print-time fallback truth: a symbol-less explicit
 *     unique varnode fed straight to PrintC::emitStatement goes through
 *     PrintLanguage::pushSymbolDetail (printlanguage.cc:238-257) whose
 *     sym==0 arm calls PrintC::pushUnnamedLocation (printc.cc:1938-1945):
 *     space name + printRaw of the HIGH NAME REPRESENTATIVE's address.
 *     The multi-instance case pins the representative-vs-instance axis:
 *     both defining statements print the representative's label.
 *
 *   stage=uniqid — the creation-order projection (varnode.cc:1265-1271
 *     createUnique, uniqid reset by Funcdata::clear -> VarnodeBank::clear
 *     varnode.cc:1240-1243): every unique-space varnode in offset order
 *     with (offset, size, def-op SeqNum time, opcode).  Byte-equal on both
 *     sides pins the allocation sequence; any later executor-order drift
 *     shows up here one stage before the C text diff.
 *
 * The print statements are normalized (outer whitespace stripped, inner
 * whitespace runs collapsed to single spaces) identically on both sides;
 * no other normalization.  Expected divergence (the gap evidence this
 * fixture locks): Ghidra prints `uniq<printRaw-of-representative>` while
 * current Rugra prints `uVar_<current-instance-offset>` — registered per
 * line in the runner, never excised.
 */

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Test-only access is required to reach Varnode::setFlags (the flag-shaping
// calls the production pipeline drives through Symbol properties), matching
// the varmap_unlinked_locals_1204 fixture's observer shim.
#define private public
#define protected public
#include "bfd_arch.hh"
#include "coreaction.hh"
#include "libdecomp.hh"
#include "opcodes.hh"
#include "printc.hh"
#include "prettyprint.hh"
#undef private
#undef protected

namespace {

using namespace ghidra;
using std::map;
using std::ostringstream;
using std::string;
using std::vector;

const char *const kOracleCommit =
    "e40ed13014025f82488b1f8f7bca566894ac376b";

// Expose the protected statement/scope entries and swap the default
// EmitMarkup emitter for the plain-text EmitNoMarkup stream (same pattern
// as printc_symbol_decl_1204.cc).
class FixturePrintC final : public PrintC {
public:
  explicit FixturePrintC(Architecture *g) : PrintC(g, "printc-unnamed-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  // printc.cc:2285 emitStatement through the exact docFunction entry path:
  // docFunction pushed the function's local scope at printc.cc:2597 before
  // emitting the body, so pushSymbol's scope qualification resolves against
  // the local scope exactly as production does.
  void renderStatement(const Funcdata *fd, const PcodeOp *op,
                       std::ostream &out) {
    setOutputStream(&out);
    pushScope(fd->getScopeLocal());
    emitStatement(op);
    popScope();
  }
};

// Collapse inner whitespace runs to single spaces and strip the ends — the
// transport normalization shared with the Rust comparand.
string normalizeStatement(const string &raw)
{
  string out;
  bool pending = false;
  for (size_t i = 0; i < raw.size(); ++i) {
    char c = raw[i];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      if (!out.empty())
        pending = true;
      continue;
    }
    if (pending) {
      out += ' ';
      pending = false;
    }
    out += c;
  }
  return out;
}

class Fixture {
  Funcdata &fd;

public:
  explicit Fixture(Funcdata &func) : fd(func) {}

  Funcdata &funcdata(void) { return fd; }

  AddrSpace *regSpace(void) { return fd.getArch()->getSpaceByName("register"); }
  AddrSpace *stackSpace(void) { return fd.getArch()->getSpaceByName("stack"); }
  AddrSpace *codeSpace(void) { return fd.getArch()->getDefaultCodeSpace(); }
  AddrSpace *uniqSpace(void) {
    return fd.getArch()->getSpaceByName("unique");
  }
  TypeFactory *types(void) { return fd.getArch()->types; }

  // The printc_symbol_decl written-temp shape: a def op writing the
  // varnode plus a reader COPY so the temporary has SSA use edges.
  Varnode *makeWrittenTemp(uintb pc, uintb value, int4 size,
                           OpCode opc = CPUI_COPY, uintb value2 = 0)
  {
    PcodeOp *op = fd.newOp(opc == CPUI_COPY ? 1 : 2, Address(codeSpace(), pc));
    fd.opSetOpcode(op, opc);
    fd.opSetInput(op, fd.newConstant(size, value), 0);
    if (opc != CPUI_COPY)
      fd.opSetInput(op, fd.newConstant(size, value2), 1);
    Varnode *vn = fd.newUniqueOut(size, op);
    PcodeOp *use = fd.newOp(1, Address(codeSpace(), pc + 0x10));
    fd.opSetOpcode(use, CPUI_COPY);
    fd.opSetInput(use, vn, 0);
    fd.newUniqueOut(size, use);
    return vn;
  }

  Varnode *makeWrittenRegister(int4 size, uintb offset, uintb pc)
  {
    PcodeOp *op = fd.newOp(1, Address(codeSpace(), pc));
    fd.opSetOpcode(op, CPUI_COPY);
    fd.opSetInput(op, fd.newConstant(size, 5), 0);
    Varnode *vn = fd.newVarnode(size, regSpace(), offset);
    fd.opSetOutput(op, vn);
    PcodeOp *use = fd.newOp(1, Address(codeSpace(), pc + 0x10));
    fd.opSetOpcode(use, CPUI_COPY);
    fd.opSetInput(use, vn, 0);
    fd.newUniqueOut(size, use);
    return vn;
  }

  Varnode *makeWrittenStack(int4 size, uintb offset, uintb pc)
  {
    PcodeOp *op = fd.newOp(1, Address(codeSpace(), pc));
    fd.opSetOpcode(op, CPUI_COPY);
    fd.opSetInput(op, fd.newConstant(size, 5), 0);
    Varnode *vn = fd.newVarnode(size, stackSpace(), offset);
    fd.opSetOutput(op, vn);
    PcodeOp *use = fd.newOp(1, Address(codeSpace(), pc + 0x10));
    fd.opSetOpcode(use, CPUI_COPY);
    fd.opSetInput(use, vn, 0);
    fd.newUniqueOut(size, use);
    return vn;
  }

  void setHigh(void) { fd.setHighLevel(); }

  void runNameVars(void)
  {
    ActionNameVars action("analysis");
    action.perform(fd);
  }

  // The candidate's finished symbol name: resolve through the high's
  // symbol link exactly like pushSymbolDetail does at print time.
  string symbolNameFor(Varnode *vn)
  {
    HighVariable *high = vn->getHigh();
    if (high == (HighVariable *)0)
      return "none";
    Symbol *sym = high->getSymbol();
    if (sym == (Symbol *)0)
      return "none";
    return sym->getDisplayName();
  }

  string renderLhsStatement(Varnode *vn)
  {
    PcodeOp *def = vn->getDef();
    FixturePrintC printer(fd.getArch());
    ostringstream out;
    printer.renderStatement(&fd, def, out);
    return normalizeStatement(out.str());
  }

  void printBranch(const string &caseName, Varnode *vn,
                   const string &branchLabel)
  {
    std::cout << "case=" << caseName << "|stage=branch|name="
              << symbolNameFor(vn) << "|branch=" << branchLabel << "\n";
  }

  // Five-tuple: has_high / pre-chain hasName gate verdict / post-chain
  // link outcome / final symbol display name.
  void printReach(const string &caseName, Varnode *vn, int4 hasNamePre)
  {
    HighVariable *high = vn->getHigh();
    int4 hasHigh = (high != (HighVariable *)0) ? 1 : 0;
    int4 linked = 0;
    string sym = "none";
    if (hasHigh == 1) {
      Symbol *symobj = high->getSymbol();
      if (symobj != (Symbol *)0) {
        linked = 1;
        sym = symobj->getDisplayName();
      }
    }
    std::cout << "case=" << caseName << "|stage=reach|has_high=" << hasHigh
              << "|has_name=" << hasNamePre << "|link=" << linked
              << "|sym=" << sym << "\n";
  }

  void printStatement(const string &caseName, const string &site,
                      const string &text)
  {
    std::cout << "case=" << caseName << "|stage=print|site=" << site
              << "|text=" << text << "\n";
  }

  // Creation-order projection: every unique-space varnode in offset order.
  void printUniqid(const string &caseName)
  {
    vector<Varnode *> rows;
    VarnodeLocSet::const_iterator iter, enditer;
    for (iter = fd.beginLoc(uniqSpace()), enditer = fd.endLoc(uniqSpace());
         iter != enditer; ++iter)
      rows.push_back(*iter);
    std::sort(rows.begin(), rows.end(), [](Varnode *a, Varnode *b) {
      if (a->getOffset() != b->getOffset())
        return a->getOffset() < b->getOffset();
      return a->getSize() < b->getSize();
    });
    for (Varnode *vn : rows) {
      PcodeOp *def = vn->getDef();
      ostringstream off;
      off << std::hex << vn->getOffset();
      std::cout << "case=" << caseName << "|stage=uniqid|off=" << off.str()
                << "|size=" << std::dec << vn->getSize();
      if (def != (PcodeOp *)0)
        std::cout << "|seq=" << def->getSeqNum().getTime()
                  << "|op=" << get_opname(def->code());
      else
        std::cout << "|seq=none|op=none";
      std::cout << "\n";
    }
  }
};

void run(const string &specDirectory, const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary, "default", &std::cerr);
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

    std::cout << "schema=1|fixture=PRINTC-UNLINKED-REF-FAMILY|slice=C"
              << "|oracle=" << kOracleCommit << "\n";

    // ---- stage=branch: the buildVariableName branch projection ----

    { // i) addrtied stack local, negative offset (-0xb8), long: lStack_b8.
      fd->clear();
      Fixture t(*fd);
      Varnode *vn = t.makeWrittenStack(8, 0xffffffffffffff48UL, 0x1000);
      vn->setFlags(Varnode::addrtied);
      t.setHigh();
      t.runNameVars();
      t.printBranch("stack_local_neg", vn, "stack-form");
    }

    { // ii) addrtied stack local, positive offset 0x20 inside the cspec's
      // [8,39] stack-parameter localrange: the X-marker branch (caller
      // allocated) — varmap.cc:565-573.
      fd->clear();
      Fixture t(*fd);
      Varnode *vn = t.makeWrittenStack(8, 0x20, 0x1010);
      vn->setFlags(Varnode::addrtied);
      t.setHigh();
      t.runNameVars();
      t.printBranch("stack_local_pos", vn, "stack-form-X");
    }

    { // iii) zero extra flags high (written register temp): the counter
      // branch <typebase>Var<index++> (database.cc:2501-2517) — int4 -> iVar1.
      fd->clear();
      Fixture t(*fd);
      Varnode *vn = t.makeWrittenRegister(4, 0x40, 0x1020);
      vn->updateType(t.types()->getBase(4, TYPE_INT));
      t.setHigh();
      t.runNameVars();
      t.printBranch("zero_flag_counter", vn, "counter");
    }

    { // iv) unaffected illegal input carrying the return_address bit: the
      // unaffected branch's unaff_retaddr spelling (database.cc:2441-2443).
      // The persist branch needs a pre-existing GLOBAL symbol to name
      // through (linkSymbol routes persist storage to the global scope),
      // which this local-only fixture cannot observe — the unaffected
      // input is its local-side sibling.
      fd->clear();
      Fixture t(*fd);
      Varnode *vn = t.funcdata().setInputVarnode(
          t.funcdata().newVarnode(8, t.regSpace(), 0x18));
      vn->setFlags(Varnode::unaffected | Varnode::return_address);
      t.setHigh();
      t.runNameVars();
      t.printBranch("unaff_retaddr_input", vn, "unaff");
    }

    { // v) irregular input at RCX: the irregular-input branch in_<reg>
      // (database.cc:2467-2474) — in_RCX.
      fd->clear();
      Fixture t(*fd);
      Varnode *vn =
          t.funcdata().setInputVarnode(t.funcdata().newVarnode(8, t.regSpace(), 0x08));
      vn->updateType(t.types()->getBase(8, TYPE_INT));
      t.setHigh();
      t.runNameVars();
      t.printBranch("irregular_input", vn, "in_");
    }

    // ---- stage=print: the unnamed-location fallback truth ----

    { // vi) symbol-less explicit unique temp fed straight to print: NO
      // ActionNameVars, so the high never links a symbol and
      // pushSymbolDetail takes the sym==0 arm -> pushUnnamedLocation ->
      // "uniq" + printRaw of the representative address (printc.cc:1938).
      fd->clear();
      Fixture t(*fd);
      Varnode *vn = t.makeWrittenTemp(0x1040, 5, 4);
      t.setHigh();
      t.printStatement("symbolless_unique_direct", "a",
                       t.renderLhsStatement(vn));
      t.printUniqid("symbolless_unique_direct");
    }

    // ---- stage=reach: the symbolization reach five-tuple ----

    { // vii) helpf's `& 2` predicate shape: INT_AND temp, full
      // ActionNameVars chain, both the shape temp and the print face.
      fd->clear();
      Fixture t(*fd);
      Varnode *shape = t.makeWrittenTemp(0x1050, 6, 4, CPUI_INT_AND, 2);
      Varnode *face = t.makeWrittenTemp(0x1070, 5, 4);
      shape->updateType(t.types()->getBase(4, TYPE_INT));
      face->updateType(t.types()->getBase(4, TYPE_INT));
      t.setHigh();
      int4 hasNamePre = shape->getHigh()->hasName() ? 1 : 0;
      t.runNameVars();
      t.printReach("helpf_and2_shape", shape, hasNamePre);
      t.printStatement("helpf_and2_shape", "a", t.renderLhsStatement(face));
      t.printUniqid("helpf_and2_shape");
    }

    { // viii) match_url's `!= '#'` shape: INT_NOTEQUAL temp.
      fd->clear();
      Fixture t(*fd);
      Varnode *shape = t.makeWrittenTemp(0x1060, 0x23, 4, CPUI_INT_NOTEQUAL, 0x23);
      Varnode *face = t.makeWrittenTemp(0x1080, 5, 4);
      shape->updateType(t.types()->getBase(4, TYPE_INT));
      face->updateType(t.types()->getBase(4, TYPE_INT));
      t.setHigh();
      int4 hasNamePre = shape->getHigh()->hasName() ? 1 : 0;
      t.runNameVars();
      t.printReach("match_url_hash_shape", shape, hasNamePre);
      t.printStatement("match_url_hash_shape", "a", t.renderLhsStatement(face));
      t.printUniqid("match_url_hash_shape");
    }

    { // ix) implied unique temp: the hasName gate refuses implied members
      // (variable.cc:729-733) — no symbol survives to print, so the print
      // face takes the unnamed-location arm on a refused temp.
      fd->clear();
      Fixture t(*fd);
      Varnode *shape = t.makeWrittenTemp(0x1090, 7, 4);
      shape->setImplied();
      t.setHigh();
      int4 hasNamePre = shape->getHigh()->hasName() ? 1 : 0;
      t.runNameVars();
      t.printReach("implied_temp_refusal", shape, hasNamePre);
      t.printStatement("implied_temp_refusal", "a",
                       t.renderLhsStatement(shape));
      t.printUniqid("implied_temp_refusal");
    }

    { // x) explicit register control: the shape that must symbolize end to
      // end (the strlen-result / myprogress counter shape) — the positive
      // control for the print face with a linked symbol.
      fd->clear();
      Fixture t(*fd);
      Varnode *face = t.makeWrittenRegister(4, 0x40, 0x10a0);
      face->updateType(t.types()->getBase(4, TYPE_INT));
      t.setHigh();
      int4 hasNamePre = face->getHigh()->hasName() ? 1 : 0;
      t.runNameVars();
      t.printReach("explicit_register_control", face, hasNamePre);
      t.printStatement("explicit_register_control", "a",
                       t.renderLhsStatement(face));
      t.printUniqid("explicit_register_control");
    }

    { // xi) multi-instance symbol-less high: two written unique temps whose
      // highs merge through the production HighVariable::merge
      // (variable.cc:675).  getNameRepresentative prefers the earlier
      // written instance (variable.cc:490-493), so BOTH defining
      // statements print the SAME unnamed label — the fragmentation axis
      // the E2E my_get_line/next_url/glob_word families exposed.
      fd->clear();
      Fixture t(*fd);
      Varnode *ta = t.makeWrittenTemp(0x10b0, 5, 4);
      Varnode *tb = t.makeWrittenTemp(0x10c0, 6, 4);
      t.setHigh();
      HighVariable *ha = ta->getHigh();
      HighVariable *hb = tb->getHigh();
      ha->merge(hb, (HighIntersectTest *)0, false);
      ostringstream rep;
      rep << std::hex << ha->getNameRepresentative()->getOffset();
      std::cout << "case=multi_instance_unnamed|stage=rep|rep=" << rep.str()
                << "\n";
      t.printStatement("multi_instance_unnamed", "a",
                       t.renderLhsStatement(ta));
      t.printStatement("multi_instance_unnamed", "b",
                       t.renderLhsStatement(tb));
      t.printUniqid("multi_instance_unnamed");
    }
  }
  shutdownDecompilerLibrary();
}

}  // namespace

int main(int argc, char **argv)
{
  if (argc != 3) {
    std::cerr << "usage: printc_unnamed_1204 <spec-directory> <binary>\n";
    return 2;
  }
  std::cout << std::unitbuf;
  try {
    run(argv[1], argv[2]);
  } catch (const LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << std::endl;
    return 2;
  } catch (const std::exception &err) {
    std::cerr << "error: " << err.what() << std::endl;
    return 2;
  }
  return 0;
}
