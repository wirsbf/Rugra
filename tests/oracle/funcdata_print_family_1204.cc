// FUNCDATA-PRINT-0001 bilateral fixture — the Funcdata raw printing family.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Covered definitions:
//   printRaw (funcdata.cc:209-225)        — no-blocks branch (full raw text
//                                           with the SeqNum decimal-uniq
//                                           form of address.cc:32-38) and
//                                           the empty-bank RecovError
//                                           branch
//   printLocalRange (funcdata.cc:597-608) — empty window ("all") and the
//                                           installed stack window lines
//   printVarnodeTree (funcdata.cc:579-591) — def-order iteration projected
//                                           as the per-line count + the
//                                           def-class sequence (the full
//                                           Varnode::printInfo text is a
//                                           registered varnode.rs residual:
//                                           FUNCDATA-VARNODE-PRINTINFO-0001)
#include <bits/stdc++.h>

#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "translate.hh"
#include "type.hh"
#include "typeop.hh"
#include "varnode.hh"

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
    types->setCoreType("xunknown1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("xunknown8", 8, TYPE_UNKNOWN, false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst, types, translate);
    symboltab = new Database(this, false);
    symboltab->attachScope(new ScopeInternal(0x101, "", this), (Scope *)0);
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

}  // namespace

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  try {
    FixtureTranslate trans;
    FixtureArchitecture architecture;
    AddrSpace *ram = trans.getSpace(3);
    AddrSpace *stack = trans.getSpace(5);
    Funcdata fd("print_family", "print_family",
                architecture.symboltab->getGlobalScope(),
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x20);
    BlockBasic *b0 = const_cast<BlockGraph &>(fd.getBasicBlocks()).newBlockBasic(&fd);

    // One alive COPY with output+input, one dead ADD (raw pre-block state).
    PcodeOp *copy = fd.newOp(1, Address(ram, 0x5010));
    fd.opSetOpcode(copy, CPUI_COPY);
    fd.opInsertEnd(copy, b0);
    fd.opMarkStartInstruction(copy);
    fd.newVarnodeOut(8, Address(ram, 0x1000), copy);
    Varnode *src = fd.newVarnode(8, Address(ram, 0x2000));
    fd.opSetInput(copy, src, 0);
    PcodeOp *add = fd.newOp(2, Address(ram, 0x5020));
    fd.opSetOpcode(add, CPUI_INT_ADD);

    // case=print_raw_ops: the no-blocks raw text. A SECOND Funcdata holds
    // the ops with no basic block so printRaw takes the "Raw operations:"
    // branch (funcdata.cc:212-222).
    {
      Funcdata fd3("print_noblocks", "print_noblocks",
                   architecture.symboltab->getGlobalScope(),
                   Address(ram, 0x7000), (FunctionSymbol *)0, 0x20);
      PcodeOp *copy3 = fd3.newOp(1, Address(ram, 0x7010));
      fd3.opSetOpcode(copy3, CPUI_COPY);
      fd3.opMarkStartInstruction(copy3);
      fd3.newVarnodeOut(8, Address(ram, 0x1100), copy3);
      Varnode *src3 = fd3.newVarnode(8, Address(ram, 0x2200));
      fd3.opSetInput(copy3, src3, 0);
      PcodeOp *add3 = fd3.newOp(2, Address(ram, 0x7020));
      fd3.opSetOpcode(add3, CPUI_INT_ADD);
      std::ostringstream text;
      fd3.printRaw(text);
      std::cout << "case=print_raw_ops|begin" << '\n' << text.str() << "|end" << '\n';
    }

    // case=print_raw_empty: empty bank throws RecovError.
    {
      Funcdata fd2("print_empty", "print_empty",
                   architecture.symboltab->getGlobalScope(),
                   Address(ram, 0x6000), (FunctionSymbol *)0, 0x20);
      try {
        std::ostringstream text;
        fd2.printRaw(text);
        std::cout << "case=print_raw_empty|no-throw" << '\n';
      } catch (const RecovError &err) {
        std::cout << "case=print_raw_empty|" << err.explain << '\n';
      }
    }

    // case=print_local_range: the fresh-ctor window (the Funcdata ctor runs
    // resetLocalWindow over the default model, fspec.cc:2278/2303 defaults)
    // then the explicitly installed stack window.
    {
      std::ostringstream ctor_text;
      fd.printLocalRange(ctor_text);
      RangeList window;
      window.insertRange(stack, 0, 511);
      window.insertRange(stack, 0xffffffffffffffff - 999999,
                         0xffffffffffffffff);
      architecture.symboltab->setRange(fd.getScopeLocal(), window);
      std::ostringstream window_text;
      fd.printLocalRange(window_text);
      std::cout << "case=print_local_range|ctor_begin" << '\n'
                << ctor_text.str() << "|ctor_end|window_begin" << '\n'
                << window_text.str() << "|window_end" << '\n';
    }

    // case=print_varnode_tree: def-order iteration projected as the count
    // plus per-varnode def-class (input/written/free), keeping the full
    // Varnode::printInfo text out of the comparison (varnode.rs residual:
    // FUNCDATA-VARNODE-PRINTINFO-0001).
    {
      std::ostringstream text;
      fd.printVarnodeTree(text);
      (void)text;
      size_t count = 0;
      std::ostringstream classes;
      for (auto iter = fd.beginDef(); iter != fd.endDef(); ++iter) {
        const Varnode *vn = *iter;
        if (count > 0) classes << ',';
        if (vn->isInput())
          classes << 'i';
        else if (vn->isWritten())
          classes << 'w';
        else
          classes << 'f';
        ++count;
      }
      std::cout << "case=print_varnode_tree|count=" << count
                << "|classes=" << classes.str() << '\n';
    }
  } catch (const LowlevelError &err) {
    std::cout << "case=lowlevel_error|" << err.explain << '\n';
    return 1;
  }
  return 0;
}
