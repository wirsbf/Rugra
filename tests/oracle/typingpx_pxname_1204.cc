// TYPINGPX-PXNAME-0001 fixture — Funcdata::mapGlobals discovery-arm naming
// with POINTER-typed highs: the px/pax/pi/pc/ppx first-character family of
// ScopeInternal::buildVariableName's persist arm (lane TYPINGPX, 2026-09-26).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7a9e3a6689e97…
// (exact: e40ed13014025f82488b1f8f7bca566894ac376b).
//
// Pinned oracle behavior:
//   funcdata_varnode.cc:1706-1710 — the discovery arm builds the symbol
//   name via `discover->buildVariableName(addr, usepoint, ct, index,
//   Varnode::addrtied|Varnode::persist)`; database.cc:2455-2466 (the
//   persist arm) prints `ct->printNameBase(s)` then the capitalized space
//   name + 2*addrsize hex digits. The pointer contribution is
//   TypePointer::printNameBase (type.hh:424): `s << 'p';
//   ptrto->printNameBase(s)` — RECURSIVE, so pointer-to-array gives
//   'p'+'a'+base, pointer-to-pointer gives 'p'+'p'+base. Base types print
//   name[0] (type.hh:273). This fixture drives the ct through the same
//   forced-high channel as funcdata_mapglobals_maxvn_1204 (single written
//   persist varnode per address, forced v_type, setHighLevel, mapGlobals)
//   and observes the created symbol through the same queryProperties
//   channel (cc:1701).
//
// The httpd mirror-gate witnesses this family carries (lane evidence,
// fresh-scope oracle drill vs Rugra probe, 1:1): ap_fini_vhost_config
//   0xa0820/0xa0828 = xunknown8 * -> pxRam…, 0xa0830 = int8 * -> piRam…;
//   ap_set_name_virtual_host 0xa0820 = xunknown1 [16] * -> paxRam…;
//   ap_update_vhost_given_ip 0xa0830 = xunknown8 * -> pxRam…;
//   ap_field_noparam 0x9cb38 = code * -> pcRam…; main = xunknown8/int8 ->
//   xRam…/iRam….
//
// Cases (one stdout line each; single 8-byte persist varnode per case):
//   a_px    ct = xunknown8 *                 -> pxRam0000000000007000
//   b_pax   ct = xunknown1 [16] *            -> paxRam0000000000007100
//   c_pi    ct = int8 *                      -> piRam0000000000007200
//   d_pc    ct = code *                      -> pcRam0000000000007300
//   e_ppx   ct = xunknown1 * *               -> ppxRam0000000000007400
//   f_x     ct = xunknown8 (non-ptr control) -> xRam0000000000007500
// Core unknowns are registered under the sleigh_arch spelling (xunknownN,
// sleigh_arch.cc:229 cacheCoreTypes) so the name base is the golden's
// 'x' character, matching Rugra's shared-factory core naming.
#include <bits/stdc++.h>

// Test-only access mirrors the house fixture pattern
// (tests/oracle/funcdata_mapglobals_maxvn_1204.cc).
#define private public
#define protected public
#include "architecture.hh"
#include "comment.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"
#undef private
#undef protected

using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
  VarnodeData dummy_register;

public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this, this));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "other", false, 8, 1, 1,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new UniqueSpace(this, this, 2, 0));
    AddrSpace *ram = new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false,
                                   8, 1, 3, AddrSpace::hasphysical, 0, 0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this, this, IPTR_PROCESSOR, "register", false,
                                   8, 1, 4, AddrSpace::hasphysical, 0, 0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(
        this, this, "stack", 5, 8, ram, 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = reg;
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "join", false, 8, 1, 6,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new IopSpace(this, this, 7));
    setDefaultCodeSpace(3);
    dummy_register.space = reg;
    dummy_register.offset = 0;
    dummy_register.size = 8;
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    return dummy_register;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override { return ""; }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &, const Address &) const override { return 0; }
};

class FixtureArchitecture final : public Architecture {
protected:
  Translate *buildTranslator(DocumentStorage &) override { return (Translate *)0; }
  void buildLoader(DocumentStorage &) override {}
  PcodeInjectLibrary *buildPcodeInjectLibrary(void) override {
    return (PcodeInjectLibrary *)0;
  }
  void buildTypegrp(DocumentStorage &) override {}
  void buildCoreTypes(DocumentStorage &) override {}
  void buildCommentDB(DocumentStorage &) override {}
  void buildStringManager(DocumentStorage &) override {}
  void buildConstantPool(DocumentStorage &) override {}
  void buildContext(DocumentStorage &) override {}
  void buildSymbols(DocumentStorage &) override {}
  void buildSpecFile(DocumentStorage &) override {}
  void modifySpaces(Translate *) override {}
  void resolveArchitecture(void) override {}

public:
  FixtureArchitecture() {
    FixtureTranslate *fixture_translate = new FixtureTranslate();
    translate = fixture_translate;
    copySpaces(fixture_translate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    // Core unknowns use the sleigh_arch spelling (sleigh_arch.cc:229
    // cacheCoreTypes -> "xunknownN"), so printNameBase contributes the
    // golden's 'x' character on both sides (Rugra's shared factory names
    // its unknown cores identically).
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("int8", 8, TYPE_INT, false);
    types->setCoreType("code", 1, TYPE_CODE, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
    commentdb = new CommentDatabaseInternal();
    ProtoModel *model = new ProtoModel(this);
    std::istringstream stream(
        "<prototype name=\"fixture\" extrapop=\"0\"><input/><output/></prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }

  void printMessage(const std::string &) const override {}
};

string metaname(type_metatype meta)
{
  switch (meta) {
  case TYPE_VOID: return "void";
  case TYPE_UNKNOWN: return "unknown";
  case TYPE_INT: return "int";
  case TYPE_UINT: return "uint";
  case TYPE_BOOL: return "bool";
  case TYPE_CODE: return "code";
  case TYPE_FLOAT: return "float";
  case TYPE_PTR: return "ptr";
  case TYPE_ARRAY: return "array";
  case TYPE_STRUCT: return "struct";
  case TYPE_UNION: return "union";
  default: return "other";
  }
}

} // namespace

int main(void)
{
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);

  FixtureArchitecture architecture;
  AddrSpace *ram = architecture.translate->getSpaceByName("ram");
  Scope *global_scope = architecture.symboltab->getGlobalScope();

  Funcdata *fd = new Funcdata("pxname", "pxname",
                              global_scope, Address(ram, 0x5000),
                              (FunctionSymbol *)0, 0x100);
  BlockBasic *block = const_cast<BlockGraph &>(fd->getBasicBlocks()).newBlockBasic(fd);

  // The forced ct per case, built through the fixture's own factory
  // (getTypePointer/getTypeArray interned forms; the base pointees are
  // the registered core types).
  TypeFactory *types = architecture.types;
  Datatype *xu1 = types->getBase(1, TYPE_UNKNOWN);
  Datatype *xu8 = types->getBase(8, TYPE_UNKNOWN);
  Datatype *i8 = types->getBase(8, TYPE_INT);
  Datatype *code = types->getBase(1, TYPE_CODE);
  Datatype *arr16 = types->getTypeArray(16, xu1);

  int pc = 0x5010;
  auto make_persist_out = [&](uintb addr, Datatype *ct) -> Varnode * {
    PcodeOp *op = fd->newOp(1, Address(ram, pc));
    pc += 1;
    fd->opSetOpcode(op, CPUI_COPY);
    Varnode *vn = fd->newVarnodeOut(8, Address(ram, addr), op);
    fd->opSetInput(op, fd->newConstant(8, 0x11), 0);
    fd->opInsertEnd(op, block);
    vn->type = ct;
    vn->setFlags(Varnode::persist | Varnode::addrtied);
    return vn;
  };

  Varnode *a = make_persist_out(0x7000, types->getTypePointer(8, xu8, 1));
  Varnode *b = make_persist_out(0x7100, types->getTypePointer(8, arr16, 1));
  Varnode *c = make_persist_out(0x7200, types->getTypePointer(8, i8, 1));
  Varnode *d = make_persist_out(0x7300, types->getTypePointer(8, code, 1));
  Varnode *e = make_persist_out(0x7400,
      types->getTypePointer(8, types->getTypePointer(8, xu1, 1), 1));
  Varnode *f = make_persist_out(0x7500, xu8);
  (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;

  // Channel state AFTER varnode creation: global ownership range for
  // discoverScope (database.cc:1353-1366).
  architecture.symboltab->addRange(global_scope, ram, 0, 0xffffffffffffffffULL);

  fd->setHighLevel();
  fd->mapGlobals();

  // Observation helper: the smallest containing entry through the same
  // queryProperties channel mapGlobals used (cc:1701).
  auto describe = [&](uintb addr) -> string {
    uint4 fl = 0;
    SymbolEntry *entry = fd->getScopeLocal()->queryProperties(
        Address(ram, addr), 1, Address(), fl);
    if (entry == (SymbolEntry *)0)
      return "none";
    ostringstream out;
    out << "name=" << entry->getSymbol()->getName()
        << "|size=" << dec << entry->getSize()
        << "|mt=" << metaname(entry->getSymbol()->getType()->getMetatype())
        << "|tsize=" << dec << entry->getSymbol()->getType()->getSize();
    return out.str();
  };

  std::cout << "case=a_px|" << describe(0x7000) << "\n";
  std::cout << "case=b_pax|" << describe(0x7100) << "\n";
  std::cout << "case=c_pi|" << describe(0x7200) << "\n";
  std::cout << "case=d_pc|" << describe(0x7300) << "\n";
  std::cout << "case=e_ppx|" << describe(0x7400) << "\n";
  std::cout << "case=f_x|" << describe(0x7500) << "\n";
  return 0;
}
