// COMMENT-SORTER-ITERATORS-0001 fixture — CommentSorter's shared-iterator
// walking machinery against locked Ghidra 12.0.4.
//
// Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
//
// Covers comment.cc:270-404 as one state machine:
//   findPosition     (comment.cc:270-325) header-at-entry, PcodeOpTree lower
//                    bound placement, previous-op 0xffffffff placement,
//                    migrated-op backupOp placement, op-less setBlock(0,0),
//                    displayUnplaced salvage, excised drop, dead-op throw.
//   setupFunctionList(comment.cc:334-355) NO setup-stage type filtering (a
//                    USER1 comment outside the tp mask is still placed), pos
//                    counter increments only on placement, setEmitted(false).
//   setupBlockList   (comment.cc:379-390) start=lower_bound((bl,0,0)),
//                    stop=upper_bound((bl,MAX,MAX)).
//   setupOpList      (comment.cc:362-374) opstop=upper_bound((bl,order,MAX));
//                    NULL op sets opstop=stop.
//   setupHeader      (comment.cc:394-404) start/opstop over (-1,headerType,*).
//   hasNext/getNext  (comment.hh:250-251) interleaved consumption: successive
//                    landmarks narrow opstop while start persists, so only
//                    the comments between landmarks are emitted.
//
// Function graph (chain, reverse-post-order indexes from findSpanningTree):
//   bb_a idx0 [0x1000,0x100a] ops A@0x1000, B@0x100a
//   bb_b idx1 [0x1009,0x100e] ops H@0x1009, I@0x100e   (overlapping cover)
//   bb_c idx2 [0x1012,0x1012] no ops                    (empty block)
//   bb_d idx3 [0x2000,0x2005] ops M1@0x1015, M2@0x1012, C@0x2000, D@0x2005
//                              (M1/M2 migrated into bb_d)
//   bb_e idx4 [0x3000,0x3010] ops E@0x3000, F@0x3005, G@0x3010
//
// Block ranges use Funcdata::setBasicBlockRange with end == the address of
// the block's last op (bb_c degenerates to its start), the same range the
// Rugra side projects from [start_addr, last-op addr].
#include <bits/stdc++.h>

// Test-only access, same pattern as tests/oracle/block_index_assign_1204.cc:
// BlockGraph::findSpanningTree (the production reverse-post-order index
// assigner, block.cc:1009) sits in BlockGraph's implicit-private section, so
// `#define private public` alone cannot reach it.  `class -> struct` opens
// the implicit-private section; no decompile header uses `template<class...>`
// or `enum class`, and <bits/stdc++.h> above has already pulled every
// standard header, so the rewrite only touches Ghidra declarations in this
// translation unit.
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
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
#undef class
#undef private

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
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "ram", false, 8, 1, 3,
                              AddrSpace::hasphysical, 0, 0));
    insertSpace(new AddrSpace(this, this, IPTR_PROCESSOR, "register", false, 8, 1, 4,
                              AddrSpace::hasphysical, 0, 0));
    SpacebaseSpace *stack = new SpacebaseSpace(this, this, "stack", 5, 8,
                                               getSpace(3), 1, true);
    insertSpace(stack);
    VarnodeData stack_pointer;
    stack_pointer.space = getSpace(4);
    stack_pointer.offset = 0;
    stack_pointer.size = 8;
    addSpacebasePointer(stack, stack_pointer, 8, true);
    setDefaultCodeSpace(3);
    dummy_register.space = getSpace(4);
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

static void drain_walk(CommentSorter &sorter, const char *case_id, const char *ev) {
  int4 count = 0;
  while (sorter.hasNext()) {
    Comment *comm = sorter.getNext();
    count += 1;
    std::cout << "case=" << case_id << "|ev=" << ev << "|n=" << count
              << "|type=" << comm->getType()
              << "|emitted=" << (comm->isEmitted() ? 1 : 0)
              << "|text=" << comm->getText() << '\n';
  }
  std::cout << "case=" << case_id << "|ev=" << ev << "|drained=" << count << '\n';
}

}  // namespace

int main() {
  std::vector<std::string> spec_paths;
  startDecompilerLibrary(spec_paths);
  AttributeId::initialize();
  ElementId::initialize();
  std::cout << "schema=1|fixture=COMMENT-SORTER-ITERATORS-0001|oracle="
            << "e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureTranslate trans;
    FixtureArchitecture architecture;
    AddrSpace *ram = trans.getSpace(3);
    Address fad(ram, 0x1000);
    Funcdata fd("sorter", "sorter", architecture.symboltab->getGlobalScope(),
                fad, (FunctionSymbol *)0, 0x20);

    BlockGraph graph;
    BlockBasic *bb_a = graph.newBlockBasic(&fd);
    BlockBasic *bb_b = graph.newBlockBasic(&fd);
    BlockBasic *bb_c = graph.newBlockBasic(&fd);
    BlockBasic *bb_d = graph.newBlockBasic(&fd);
    BlockBasic *bb_e = graph.newBlockBasic(&fd);
    fd.setBasicBlockRange(bb_a, Address(ram, 0x1000), Address(ram, 0x100a));
    fd.setBasicBlockRange(bb_b, Address(ram, 0x1009), Address(ram, 0x100e));
    fd.setBasicBlockRange(bb_c, Address(ram, 0x1012), Address(ram, 0x1012));
    fd.setBasicBlockRange(bb_d, Address(ram, 0x2000), Address(ram, 0x2005));
    fd.setBasicBlockRange(bb_e, Address(ram, 0x3000), Address(ram, 0x3010));
    graph.addEdge(bb_a, bb_b);
    graph.addEdge(bb_b, bb_c);
    graph.addEdge(bb_c, bb_d);
    graph.addEdge(bb_d, bb_e);
    std::vector<FlowBlock *> preorder;
    std::vector<FlowBlock *> rootlist;
    graph.findSpanningTree(preorder, rootlist);

    // Ops are created and inserted in one fixed order mirrored by the Rust
    // fixture: creation order fixes SeqNum::uniq, insertion order fixes the
    // BlockBasic::insert order ladder.
    PcodeOp *op_a = fd.newOp(0, Address(ram, 0x1000));
    fd.opSetOpcode(op_a, CPUI_COPY);
    fd.opInsertEnd(op_a, bb_a);
    PcodeOp *op_b = fd.newOp(0, Address(ram, 0x100a));
    fd.opSetOpcode(op_b, CPUI_COPY);
    fd.opInsertEnd(op_b, bb_a);
    PcodeOp *op_m1 = fd.newOp(0, Address(ram, 0x1015));
    fd.opSetOpcode(op_m1, CPUI_COPY);
    fd.opInsertEnd(op_m1, bb_d);
    PcodeOp *op_m2 = fd.newOp(0, Address(ram, 0x1012));
    fd.opSetOpcode(op_m2, CPUI_COPY);
    fd.opInsertEnd(op_m2, bb_d);
    PcodeOp *op_c = fd.newOp(0, Address(ram, 0x2000));
    fd.opSetOpcode(op_c, CPUI_COPY);
    fd.opInsertEnd(op_c, bb_d);
    PcodeOp *op_d = fd.newOp(0, Address(ram, 0x2005));
    fd.opSetOpcode(op_d, CPUI_COPY);
    fd.opInsertEnd(op_d, bb_d);
    PcodeOp *op_e = fd.newOp(0, Address(ram, 0x3000));
    fd.opSetOpcode(op_e, CPUI_COPY);
    fd.opInsertEnd(op_e, bb_e);
    PcodeOp *op_f = fd.newOp(0, Address(ram, 0x3005));
    fd.opSetOpcode(op_f, CPUI_COPY);
    fd.opInsertEnd(op_f, bb_e);
    PcodeOp *op_g = fd.newOp(0, Address(ram, 0x3010));
    fd.opSetOpcode(op_g, CPUI_COPY);
    fd.opInsertEnd(op_g, bb_e);
    PcodeOp *op_h = fd.newOp(0, Address(ram, 0x1009));
    fd.opSetOpcode(op_h, CPUI_COPY);
    fd.opInsertEnd(op_h, bb_b);
    PcodeOp *op_i = fd.newOp(0, Address(ram, 0x100e));
    fd.opSetOpcode(op_i, CPUI_COPY);
    fd.opInsertEnd(op_i, bb_b);

    CommentDatabaseInternal db;
    db.addComment(Comment::header, fad, fad, "hdr-basic");
    db.addComment(Comment::warningheader, fad, fad, "warn-hdr");
    db.addComment(Comment::warning, fad, fad, "inline-entry");
    db.addComment(Comment::warning, fad, Address(ram, 0x1008), "tail-a");
    db.addComment(Comment::user1, fad, Address(ram, 0x100a), "at-b");
    db.addComment(Comment::user2, fad, Address(ram, 0x1013), "unplaced");
    db.addComment(Comment::user2, fad, Address(ram, 0x1015), "migrated");
    db.addComment(Comment::warning, fad, Address(ram, 0x2003), "mid-d");
    db.addComment(Comment::header, fad, Address(ram, 0x3000), "hdr-away");
    db.addComment(Comment::warning, fad, Address(ram, 0x3002), "between-ef");
    db.addComment(Comment::warning, fad, Address(ram, 0x3005), "at-f");
    db.addComment(Comment::warning, fad, Address(ram, 0x3008), "between-fg");
    db.addComment(0, fad, Address(ram, 0x3000), "zerotype");

    const uint4 tp = Comment::header | Comment::warning | Comment::warningheader;

    CommentSorter sorter1;
    sorter1.setupFunctionList(tp, &fd, db, true);
    sorter1.setupHeader(CommentSorter::header_basic);
    drain_walk(sorter1, "placed", "hdr-basic");
    sorter1.setupHeader(CommentSorter::header_unplaced);
    drain_walk(sorter1, "placed", "hdr-unplaced");

    sorter1.setupBlockList(bb_a);
    sorter1.setupOpList(op_a);
    drain_walk(sorter1, "placed", "bbA-atA");
    sorter1.setupOpList(op_b);
    drain_walk(sorter1, "placed", "bbA-atB");
    sorter1.setupOpList((const PcodeOp *)0);
    drain_walk(sorter1, "placed", "bbA-null");

    sorter1.setupBlockList(bb_d);
    sorter1.setupOpList(op_m1);
    drain_walk(sorter1, "placed", "bbD-atM1");
    sorter1.setupOpList(op_c);
    drain_walk(sorter1, "placed", "bbD-atC");
    sorter1.setupOpList(op_d);
    drain_walk(sorter1, "placed", "bbD-atD");
    sorter1.setupOpList((const PcodeOp *)0);
    drain_walk(sorter1, "placed", "bbD-null");

    sorter1.setupBlockList(bb_e);
    sorter1.setupOpList(op_e);
    drain_walk(sorter1, "placed", "bbE-atE");
    sorter1.setupOpList(op_f);
    drain_walk(sorter1, "placed", "bbE-atF");
    sorter1.setupOpList(op_g);
    drain_walk(sorter1, "placed", "bbE-atG");
    sorter1.setupOpList((const PcodeOp *)0);
    drain_walk(sorter1, "placed", "bbE-null");

    sorter1.setupBlockList(bb_c);
    sorter1.setupOpList((const PcodeOp *)0);
    drain_walk(sorter1, "placed", "bbC-null");

    CommentSorter sorter2;
    sorter2.setupFunctionList(tp, &fd, db, false);
    sorter2.setupHeader(CommentSorter::header_basic);
    drain_walk(sorter2, "nounsplaced", "hdr-basic");
    sorter2.setupHeader(CommentSorter::header_unplaced);
    drain_walk(sorter2, "nounsplaced", "hdr-unplaced");
    sorter2.setupBlockList(bb_a);
    sorter2.setupOpList((const PcodeOp *)0);
    drain_walk(sorter2, "nounsplaced", "bbA-null");

    // Dead op: created (in the optree) but never inserted into a block.
    {
      Funcdata fd2("dead", "dead", architecture.symboltab->getGlobalScope(),
                   Address(ram, 0x4000), (FunctionSymbol *)0, 0x10);
      PcodeOp *dead = fd2.newOp(0, Address(ram, 0x6000));
      fd2.opSetOpcode(dead, CPUI_COPY);
      CommentDatabaseInternal db2;
      db2.addComment(Comment::warning, Address(ram, 0x4000), Address(ram, 0x6000),
                     "doomed");
      CommentSorter sorter3;
      std::string error;
      try {
        sorter3.setupFunctionList(0xffff, &fd2, db2, true);
      }
      catch (const LowlevelError &err) {
        error = err.explain;
      }
      std::cout << "case=deadop|error=" << error << '\n';
    }

    // Op-less function: every placeable comment lands at block 0 order 0
    // (comment.cc:316-318).
    {
      Funcdata fd3("noops", "noops", architecture.symboltab->getGlobalScope(),
                   Address(ram, 0x5000), (FunctionSymbol *)0, 0x10);
      BlockGraph graph3;
      BlockBasic *bb_f = graph3.newBlockBasic(&fd3);
      fd3.setBasicBlockRange(bb_f, Address(ram, 0x5000), Address(ram, 0x5000));
      CommentDatabaseInternal db3;
      db3.addComment(Comment::warning, Address(ram, 0x5000), Address(ram, 0x5500),
                     "noops-walk");
      CommentSorter sorter4;
      sorter4.setupFunctionList(tp, &fd3, db3, false);
      sorter4.setupBlockList(bb_f);
      sorter4.setupOpList((const PcodeOp *)0);
      drain_walk(sorter4, "noops", "bbF-null");
    }
  }
  catch (const LowlevelError &error) {
    std::cerr << "Ghidra LowlevelError: " << error.explain << '\n';
    shutdownDecompilerLibrary();
    return 1;
  }
  shutdownDecompilerLibrary();
  return 0;
}
