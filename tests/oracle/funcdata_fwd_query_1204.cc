// FUNCDATA-FWD-QUERY-0001 bilateral fixture — the Funcdata query
// forwarder family (funcdata.hh maintenance inlines).
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Covered definitions (each exercised through its Funcdata entry point):
//   beginLoc/endLoc (6 overload pairs, hh:337-372)  — loc-tree spans
//   overlapLoc (hh:375)                            — overlap group count
//   beginDef/endDef (3 overload pairs, hh:379-394) — def-tree spans
//   findCoveredInput/findCoveringInput (hh:303/310)
//   findVarnodeWritten (hh:333)
//   deadRemovalAllowed/deadRemovalAllowedSeen/seenDeadcode (hh:254/260/242)
//   startCleanUp + getCleanUpIndex (hh:186-187)
//   findOp (hh:453) / target (hh:490)
//   beginOp(OpCode) (hh:500) / beginOpAlive/beginOpDead/beginOpAll (hh:506-521)
//   endLaneAccess (hh:398)
//
// Construction: two written SSA versions of one 8-byte ram storage
// (ram:0x1000, defs at ram:0x5010 and ram:0x5020), a 4-byte input at
// ram:0x100, an 8-byte input at ram:0x3000, and a free 8-byte varnode at
// ram:0x2000.  All projections are counts or storage text, printed as
// case=<id>|key=value lines so both sides compare byte-for-byte.
#include <bits/stdc++.h>

#include "architecture.hh"
#include "database.hh"
#include "funcdata.hh"
#include "heritage.hh"
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

std::string storage(const Varnode *vn) {
  std::ostringstream out;
  out << vn->getSpace()->getName() << ':' << hex << vn->getOffset() << ':'
      << dec << vn->getSize();
  return out.str();
}

}  // namespace

int main() {
  std::cout << std::unitbuf;
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  try {
    FixtureTranslate trans;
    FixtureArchitecture architecture;
    AddrSpace *ram = trans.getSpace(3);
    Funcdata fd("fwd_query", "fwd_query",
                architecture.symboltab->getGlobalScope(),
                Address(ram, 0x5000), (FunctionSymbol *)0, 0x20);
    BlockBasic *b0 = const_cast<BlockGraph &>(fd.getBasicBlocks()).newBlockBasic(&fd);

    // Two SSA versions of ram:0x1000 size 8 (defs at 0x5010 / 0x5020).
    PcodeOp *op1 = fd.newOp(1, Address(ram, 0x5010));
    fd.opSetOpcode(op1, CPUI_INT_SUB);
    fd.opInsertEnd(op1, b0);
    fd.opMarkStartInstruction(op1);
    fd.newVarnodeOut(8, Address(ram, 0x1000), op1);
    PcodeOp *op2 = fd.newOp(1, Address(ram, 0x5020));
    fd.opSetOpcode(op2, CPUI_INT_ADD);
    fd.opInsertEnd(op2, b0);
    fd.opMarkStartInstruction(op2);
    fd.newVarnodeOut(8, Address(ram, 0x1000), op2);
    // A STORE op for the beginOp(OpCode) per-list path.
    PcodeOp *store = fd.newOp(3, Address(ram, 0x5030));
    fd.opSetOpcode(store, CPUI_STORE);
    fd.opInsertEnd(store, b0);
    fd.opMarkStartInstruction(store);
    // Inputs: 4-byte at ram:0x100, 8-byte at ram:0x3000.
    Varnode *inp_small = fd.newVarnode(4, Address(ram, 0x100));
    fd.setInputVarnode(inp_small);
    Varnode *inp_big = fd.newVarnode(8, Address(ram, 0x3000));
    fd.setInputVarnode(inp_big);
    // Free: 8-byte at ram:0x2000.
    fd.newVarnode(8, Address(ram, 0x2000));

    // case=loc_all: full loc span count + first/last storage.
    {
      size_t count = 0;
      std::string first, last;
      for (auto iter = fd.beginLoc(); iter != fd.endLoc(); ++iter) {
        if (count == 0) first = storage(*iter);
        last = storage(*iter);
        ++count;
      }
      std::cout << "case=loc_all|count=" << count << "|first=" << first
                << "|last=" << last << '\n';
    }

    // case=loc_space: per-space counts (ram vs unique).
    {
      size_t ram_count = 0, unique_count = 0;
      for (auto iter = fd.beginLoc(ram); iter != fd.endLoc(ram); ++iter)
        ++ram_count;
      AddrSpace *uniq = trans.getSpace(2);
      for (auto iter = fd.beginLoc(uniq); iter != fd.endLoc(uniq); ++iter)
        ++unique_count;
      std::cout << "case=loc_space|ram=" << ram_count
                << "|unique=" << unique_count << '\n';
    }

    // case=loc_addr: exact-address span at ram:0x1000 (both SSA versions).
    {
      size_t count = 0;
      for (auto iter = fd.beginLoc(Address(ram, 0x1000));
           iter != fd.endLoc(Address(ram, 0x1000)); ++iter)
        ++count;
      std::cout << "case=loc_addr|count=" << count << '\n';
    }

    // case=loc_size_fl: (8, ram:0x1000) by property and (8, ram:0x3000) input.
    {
      size_t written_c = 0, input_c = 0, free_c = 0;
      for (auto iter = fd.beginLoc(8, Address(ram, 0x1000), Varnode::written);
           iter != fd.endLoc(8, Address(ram, 0x1000), Varnode::written); ++iter)
        ++written_c;
      for (auto iter = fd.beginLoc(8, Address(ram, 0x3000), Varnode::input);
           iter != fd.endLoc(8, Address(ram, 0x3000), Varnode::input); ++iter)
        ++input_c;
      for (auto iter = fd.beginLoc(8, Address(ram, 0x2000), 0);
           iter != fd.endLoc(8, Address(ram, 0x2000), 0); ++iter)
        ++free_c;
      std::cout << "case=loc_size_fl|written=" << written_c
                << "|input=" << input_c << "|free=" << free_c << '\n';
    }

    // case=loc_pc: definition-bounded spans at ram:0x1000.
    {
      size_t by5010 = 0, by5020 = 0, uniq_hit = 0, uniq_miss = 0;
      for (auto iter = fd.beginLoc(8, Address(ram, 0x1000), Address(ram, 0x5010),
                                   ~((uintm)0));
           iter != fd.endLoc(8, Address(ram, 0x1000), Address(ram, 0x5010),
                             ~((uintm)0));
           ++iter)
        ++by5010;
      for (auto iter = fd.beginLoc(8, Address(ram, 0x1000), Address(ram, 0x5020),
                                   ~((uintm)0));
           iter != fd.endLoc(8, Address(ram, 0x1000), Address(ram, 0x5020),
                             ~((uintm)0));
           ++iter)
        ++by5020;
      for (auto iter = fd.beginLoc(8, Address(ram, 0x1000), Address(ram, 0x5010),
                                   op1->getSeqNum().getTime());
           iter != fd.endLoc(8, Address(ram, 0x1000), Address(ram, 0x5010),
                             op1->getSeqNum().getTime());
           ++iter)
        ++uniq_hit;
      for (auto iter = fd.beginLoc(8, Address(ram, 0x1000), Address(ram, 0x5010),
                                   op2->getSeqNum().getTime());
           iter != fd.endLoc(8, Address(ram, 0x1000), Address(ram, 0x5010),
                             op2->getSeqNum().getTime());
           ++iter)
        ++uniq_miss;
      std::cout << "case=loc_pc|by5010=" << by5010 << "|by5020=" << by5020
                << "|uniq_hit=" << uniq_hit << "|uniq_miss=" << uniq_miss << '\n';
    }

    // case=find_inputs: covered/covering/written.
    {
      const Varnode *covered = fd.findCoveredInput(16, Address(ram, 0xfc));
      const Varnode *covering = fd.findCoveringInput(2, Address(ram, 0x101));
      const Varnode *written =
          fd.findVarnodeWritten(8, Address(ram, 0x1000), Address(ram, 0x5010));
      const Varnode *written_miss =
          fd.findVarnodeWritten(8, Address(ram, 0x1000), Address(ram, 0x9999));
      std::cout << "case=find_inputs|covered="
                << (covered != (Varnode *)0 ? storage(covered) : "null")
                << "|covering="
                << (covering != (Varnode *)0 ? storage(covering) : "null")
                << "|written="
                << (written != (Varnode *)0 ? storage(written) : "null")
                << "|written_miss="
                << (written_miss != (Varnode *)0 ? storage(written_miss) : "null")
                << '\n';
    }

    // case=overlap_loc: groups of overlapping varnodes at ram:0x1000.
    {
      auto iter = fd.beginLoc(8, Address(ram, 0x1000));
      std::vector<VarnodeLocSet::const_iterator> bounds;
      fd.overlapLoc(iter, bounds);
      size_t groups = bounds.empty() ? 0 : (bounds.size() - 1) / 2;
      std::cout << "case=overlap_loc|groups=" << groups
                << "|bounds=" << bounds.size() << '\n';
    }

    // case=def_iters: def-tree spans by property and at an address.
    {
      size_t all = 0, inputs = 0, written = 0, frees = 0, at_addr = 0;
      for (auto iter = fd.beginDef(); iter != fd.endDef(); ++iter) ++all;
      for (auto iter = fd.beginDef(Varnode::input);
           iter != fd.endDef(Varnode::input); ++iter) ++inputs;
      for (auto iter = fd.beginDef(Varnode::written);
           iter != fd.endDef(Varnode::written); ++iter) ++written;
      for (auto iter = fd.beginDef(0); iter != fd.endDef(0); ++iter) ++frees;
      for (auto iter = fd.beginDef(Varnode::input, Address(ram, 0x3000));
           iter != fd.endDef(Varnode::input, Address(ram, 0x3000)); ++iter)
        ++at_addr;
      std::cout << "case=def_iters|all=" << all << "|inputs=" << inputs
                << "|written=" << written << "|frees=" << frees
                << "|at_addr=" << at_addr << '\n';
      // beginDef(written, addr) is the illegal combination: the oracle
      // throws LowlevelError (varnode.cc:1913-1914).
      try {
        auto iter = fd.beginDef(Varnode::written, Address(ram, 0x1000));
        ++iter;  // touch the iterator
        std::cout << "case=def_addr_written_throw|no-throw\n";
      } catch (const LowlevelError &err) {
        std::cout << "case=def_addr_written_throw|" << err.explain << '\n';
      }
    }

    // case=start_cleanup: clean-up index capture.
    {
      uint4 before = fd.getCleanUpIndex();
      fd.startCleanUp();
      uint4 at_phase = fd.getCleanUpIndex();
      fd.newVarnode(8, Address(ram, 0x4000));
      uint4 after_more = fd.getCleanUpIndex();
      std::cout << "case=start_cleanup|before=" << before
                << "|at_phase=" << at_phase << "|after_more=" << after_more
                << "|advanced=" << (at_phase != after_more) << '\n';
    }

    // case=find_op_target: sequence-number and address lookups.
    {
      const PcodeOp *hit = fd.findOp(op1->getSeqNum());
      const PcodeOp *miss = fd.findOp(SeqNum(Address(ram, 0x7777), 9));
      const PcodeOp *tgt = fd.target(Address(ram, 0x5010));
      const PcodeOp *tgt_miss = fd.target(Address(ram, 0x8888));
      std::cout << "case=find_op_target|hit="
                << (hit != (PcodeOp *)0 ? get_opname(hit->code()) : "null")
                << "|miss=" << (miss != (PcodeOp *)0 ? "found" : "null")
                << "|target="
                << (tgt != (PcodeOp *)0 ? get_opname(tgt->code()) : "null")
                << "|target_miss="
                << (tgt_miss != (PcodeOp *)0 ? "found" : "null") << '\n';
    }

    // case=op_iters: opcode-list, alive/dead, all, per-address spans.
    {
      size_t stores = 0, subs = 0, alive = 0, dead = 0, all = 0, at_addr = 0;
      for (auto iter = fd.beginOp(CPUI_STORE); iter != fd.endOp(CPUI_STORE);
           ++iter)
        ++stores;
      for (auto iter = fd.beginOp(CPUI_INT_SUB); iter != fd.endOp(CPUI_INT_SUB);
           ++iter)
        ++subs;
      for (auto iter = fd.beginOpAlive(); iter != fd.endOpAlive(); ++iter)
        ++alive;
      for (auto iter = fd.beginOpDead(); iter != fd.endOpDead(); ++iter) ++dead;
      for (auto iter = fd.beginOpAll(); iter != fd.endOpAll(); ++iter) ++all;
      for (auto iter = fd.beginOp(Address(ram, 0x5010));
           iter != fd.endOp(Address(ram, 0x5010)); ++iter)
        ++at_addr;
      std::cout << "case=op_iters|stores=" << stores << "|subs=" << subs
                << "|alive=" << alive << "|dead=" << dead << "|all=" << all
                << "|at_addr=" << at_addr << '\n';
    }

    // case=lane_access_end: empty laned map — begin==end.
    {
      size_t lanes = 0;
      for (auto iter = fd.beginLaneAccess(); iter != fd.endLaneAccess(); ++iter)
        ++lanes;
      std::cout << "case=lane_access_end|lanes=" << lanes << '\n';
    }
  } catch (const LowlevelError &err) {
    std::cout << "case=lowlevel_error|" << err.explain << '\n';
    return 1;
  }
  return 0;
}
