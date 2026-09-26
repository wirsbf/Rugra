/*
 * FSPEC-SCORE-MERGED-1204: locked Ghidra 12.0.4 oracle for the
 * MIGW-FSPEC wave (ScoreProtoModel / ProtoModelMerged / ParamListMerged /
 * ParamListStandard resolver population).
 *
 *  - case=score_penalty_walk: ScoreProtoModel (fspec.cc:2705-2775) over a
 *    two-entry exclusion model: the exact-fit walk scores 0, a slot-0 hole
 *    scores penalty[0]=16, a duplicated slot scores 20 (mismatchpenalty),
 *    each unmatched address adds 20*mismatch, and 25 mismatches reach the
 *    500 selectModel threshold exactly.
 *  - case=param_list_merged_fold_in: ParamListMerged::foldIn
 *    (fspec.cc:1794-1833) — empty-union adoption, distinct append, the
 *    subsume-with-matching-minsize replacement, the minsize-mismatch
 *    demotion to append, and the different-stacks refusal.
 *  - case=resolver_population: ParamListStandard::populateResolver
 *    (fspec.cc:1191-1216) through the observable characterizeAsParam /
 *    possibleParamWithSlot queries of the merged list after finalize().
 *  - case=proto_model_merged_fold_in: ProtoModelMerged::foldIn
 *    (fspec.cc:2834-2870) — first-fold adoption of extrapop/effects/trash,
 *    the extrapop disagreement demoting to extrapop_unknown, the
 *    inject-id disagreement refusal, and the effect/trash intersections.
 *  - case=select_model: ProtoModelMerged::selectModel
 *    (fspec.cc:2877-2902) — the best-scoring model wins, and an all-active
 *    25-mismatch trial set (score 500, not < 500) throws "No model
 *    matches : missing default".
 *
 * ProtoModel construction uses a minimal concrete Architecture whose
 * translate provides a ram space and a stack space (the ProtoModel ctor's
 * defaultLocalRange/defaultParamRange need a stack space), with fields
 * staged directly through the class->struct access hack (same pattern as
 * the fspec_endian_resolver_1204 fixture).
 */

#include <bits/stdc++.h>

#define class struct
#define private public
#define protected public
#include "libdecomp.hh"
#include "fspec.hh"
#include "opcodes.hh"
#include "space.hh"
#include "translate.hh"
#include "architecture.hh"
#undef protected
#undef private
#undef class

using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
  }

  std::string tryInsertSpace(AddrSpace *spc) {
    try {
      insertSpace(spc);
      return "ok";
    }
    catch (LowlevelError &err) {
      return std::string("err ") + err.explain;
    }
  }

  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    static VarnodeData dummy;
    return dummy;
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
public:
  void printMessage(const std::string &) const override {}
  Translate *buildTranslator(DocumentStorage &) override {
    return (Translate *)0;
  }
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
};

// Fill ParamEntry fields directly (mirrors the staged cspec loader in the
// fspec_endian_resolver_1204 fixture).
ParamEntry makeEntry(int4 grp, AddrSpace *spc, uintb base, int4 size,
                     int4 minsize, int4 alignment, uint4 flags) {
  ParamEntry e(grp);
  e.flags = flags;
  e.type = TYPECLASS_GENERAL;
  e.groupSet.clear();
  e.groupSet.push_back(grp);
  e.spaceid = spc;
  e.addressbase = base;
  e.size = size;
  e.minsize = minsize;
  e.alignment = alignment;
  e.numslots = (alignment != 0) ? (size / alignment) : 1;
  e.joinrec = (JoinRecord *)0;
  return e;
}

ParamListStandard *makeInputList(AddrSpace *reg) {
  ParamListStandard *lst = new ParamListStandard();
  lst->numgroup = 2;
  lst->maxdelay = 0;
  lst->thisbeforeret = true;
  lst->autoKilledByCall = false;
  lst->entry.push_back(makeEntry(0, reg, 0x100, 8, 8, 0, 0));
  lst->entry.push_back(makeEntry(1, reg, 0x200, 8, 8, 0, 0));
  lst->spacebase = (AddrSpace *)0;
  lst->populateResolver();
  return lst;
}

ProtoModel *makeModel(FixtureArchitecture *arch, AddrSpace *reg,
                      const char *nm, int4 extrapop, int4 injectEntry,
                      int4 injectReturn, int4 trashOffset2) {
  ProtoModel *model = new ProtoModel(arch);
  model->name = nm;
  model->extrapop = extrapop;
  model->input = makeInputList(reg);
  ParamListStandardOut *out = new ParamListStandardOut();
  out->numgroup = 1;
  out->maxdelay = 0;
  out->thisbeforeret = true;
  out->autoKilledByCall = false;
  out->entry.push_back(makeEntry(0, reg, 0x300, 8, 1, 0, 0));
  out->spacebase = (AddrSpace *)0;
  // The real decode path populates the output resolver too (fspec.cc:1504
  // runs populateResolver for both lists after <pentry> decoding), and
  // 12.0.4's findEntry consults the resolver — staging without it would
  // test an unconfigured state rather than the oracle algorithm.
  out->populateResolver();
  model->output = out;
  model->injectUponEntry = injectEntry;
  model->injectUponReturn = injectReturn;

  VarnodeData eff1, eff2, eff3;
  eff1.space = reg; eff1.offset = 0x500; eff1.size = 8;
  model->effectlist.push_back(EffectRecord(eff1, EffectRecord::unaffected));
  eff2.space = reg; eff2.offset = 0x600; eff2.size = 8;
  model->effectlist.push_back(EffectRecord(eff2, EffectRecord::killedbycall));
  eff3.space = reg; eff3.offset = 0x700; eff3.size = 8;
  model->effectlist.push_back(EffectRecord(eff3, EffectRecord::return_address));
  std::sort(model->effectlist.begin(), model->effectlist.end(),
            EffectRecord::compareByAddress);

  VarnodeData trash1, trash2;
  trash1.space = reg; trash1.offset = 0x500; trash1.size = 8;
  model->likelytrash.push_back(trash1);
  trash2.space = reg; trash2.offset = trashOffset2; trash2.size = 8;
  model->likelytrash.push_back(trash2);
  std::sort(model->likelytrash.begin(), model->likelytrash.end());
  return model;
}

} // namespace

int main(void) {
  std::cout << "schema=1|fixture=FSPEC-SCORE-MERGED-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;

  // Register capabilities (the print language the Architecture base ctor
  // builds comes from the PrintCCapability static registration;
  // startDecompilerLibrary's empty-path form only runs the initializers).
  startDecompilerLibrary(std::vector<std::string>());

  FixtureTranslate tr;
  FixtureArchitecture arch;
  // NOTE: arch.translate stays null — the Architecture destructor owns and
  // frees whatever translate it holds, and a stack reference would crash
  // at exit; the space constructors only need the Translate* for
  // per-space bookkeeping defaults.
  // The ProtoModel constructor reads glb->getStackSpace() (the
  // AddrSpaceManager member), so the fixture spaces live on the
  // Architecture itself; the FixtureTranslate is only the Translate*
  // bookkeeping handle the space constructors require.
  AddrSpace *ram = new AddrSpace(&arch, &tr, IPTR_PROCESSOR, "ram", false, 8,
                                 1, 3, AddrSpace::hasphysical, 0, 0);
  arch.insertSpace(ram);
  SpacebaseSpace *stack = new SpacebaseSpace(&arch, &tr, "stack", 6, 8,
                                             ram, 0, true);
  arch.insertSpace(stack);

  // ---- case 1: ScoreProtoModel penalty walk --------------------------
  std::cout << "case=score_penalty_walk" << std::endl;
  {
    ProtoModel *model = makeModel(&arch, ram, "m1", 0, -1, -1, 0x800);
    // Exact fit: slots 0 and 1 (entry group ids 0,1).
    {
      ScoreProtoModel sm(true, model, 2);
      sm.addParameter(Address(ram, 0x100), 8);
      sm.addParameter(Address(ram, 0x200), 8);
      sm.doScore();
      std::cout << "  walk=exact score=" << sm.getScore()
                << " mismatch=" << sm.getNumMismatch() << std::endl;
    }
    // Hole at slot 0: only slot 1 hit -> penalty[0] = 16.
    {
      ScoreProtoModel sm(true, model, 1);
      sm.addParameter(Address(ram, 0x200), 8);
      sm.doScore();
      std::cout << "  walk=hole0 score=" << sm.getScore()
                << " mismatch=" << sm.getNumMismatch() << std::endl;
    }
    // Duplication: slot 0 twice -> 20.
    {
      ScoreProtoModel sm(true, model, 2);
      sm.addParameter(Address(ram, 0x100), 8);
      sm.addParameter(Address(ram, 0x100), 8);
      sm.doScore();
      std::cout << "  walk=dup score=" << sm.getScore()
                << " mismatch=" << sm.getNumMismatch() << std::endl;
    }
    // Hole + duplication + mismatch: 16 + 20 + 20.
    {
      ScoreProtoModel sm(true, model, 4);
      sm.addParameter(Address(ram, 0x200), 8);
      sm.addParameter(Address(ram, 0x200), 8);
      sm.addParameter(Address(ram, 0x900), 8);
      sm.doScore();
      std::cout << "  walk=mixed score=" << sm.getScore()
                << " mismatch=" << sm.getNumMismatch() << std::endl;
    }
    // 25 mismatches: 500 exactly (the selectModel threshold).
    {
      ScoreProtoModel sm(true, model, 25);
      for (int4 i = 0; i < 25; ++i)
        sm.addParameter(Address(ram, 0x900 + i), 8);
      sm.doScore();
      std::cout << "  walk=mismatch25 score=" << sm.getScore()
                << " mismatch=" << sm.getNumMismatch() << std::endl;
    }
    // Output scoring over the output list (0x300).
    {
      ScoreProtoModel sm(false, model, 1);
      sm.addParameter(Address(ram, 0x300), 4);
      sm.doScore();
      std::cout << "  walk=output score=" << sm.getScore()
                << " mismatch=" << sm.getNumMismatch() << std::endl;
    }
    delete model;
  }

  // ---- case 2: ParamListMerged::foldIn -------------------------------
  std::cout << "case=param_list_merged_fold_in" << std::endl;
  {
    ParamListMerged merged;
    ParamListStandard *a = new ParamListStandard();
    a->numgroup = 1; a->maxdelay = 0; a->thisbeforeret = true;
    a->autoKilledByCall = false;
    a->entry.push_back(makeEntry(0, ram, 0x100, 8, 4, 0, 0));
    a->populateResolver();
    ParamListStandard *b = new ParamListStandard();
    b->numgroup = 2; b->maxdelay = 0; b->thisbeforeret = true;
    b->autoKilledByCall = false;
    b->entry.push_back(makeEntry(0, ram, 0x100, 16, 4, 0, 0));
    b->entry.push_back(makeEntry(1, ram, 0x200, 8, 4, 0, 0));
    b->populateResolver();
    ParamListStandard *stackList = new ParamListStandard();
    stackList->numgroup = 1; stackList->maxdelay = 0;
    stackList->thisbeforeret = true; stackList->autoKilledByCall = false;
    stackList->entry.push_back(makeEntry(0, stack, 0x20, 8, 1, 8, 0));
    stackList->spacebase = stack;
    stackList->populateResolver();

    // Empty union adopts a verbatim.
    merged.foldIn(*a);
    std::cout << "  fold=adopt size=" << merged.entry.size()
              << " base=0x" << std::hex << merged.entry.front().getBase()
              << std::dec << std::endl;
    // b subsumes a's entry with matching minsize -> replace + append.
    merged.foldIn(*b);
    std::cout << "  fold=replace size=" << merged.entry.size();
    {
      const ParamEntry &front = merged.entry.front();
      std::cout << " front_size=" << front.getSize()
                << " back_group=" << merged.entry.back().getGroup();
    }
    std::cout << std::endl;
    // Same entry again: fully subsumed (typeint 2, minsize matches) -> no change.
    merged.foldIn(*a);
    std::cout << "  fold=subsumed size=" << merged.entry.size() << std::endl;
    // Stack conflict: refusal.
    try {
      merged.foldIn(*stackList);
      std::cout << "  fold=stackconflict UNEXPECTED-OK" << std::endl;
    }
    catch (LowlevelError &err) {
      std::cout << "  fold=stackconflict err=" << err.explain << std::endl;
    }
    // finalize populates the resolver; observe through characterizeAsParam.
    merged.finalize();
    std::cout << "  fold=finalize char_0x100_16="
              << merged.characterizeAsParam(Address(ram, 0x100), 16)
              << " char_0x200_8="
              << merged.characterizeAsParam(Address(ram, 0x200), 8)
              << " char_0x400_8="
              << merged.characterizeAsParam(Address(ram, 0x400), 8)
              << std::endl;
    int4 slot = -1, slotsize = -1;
    bool isparam = merged.possibleParamWithSlot(Address(ram, 0x200), 8,
                                                slot, slotsize);
    std::cout << "  fold=slot isparam=" << (isparam ? 1 : 0)
              << " slot=" << slot << " slotsize=" << slotsize << std::endl;
    delete a;
    delete b;
    delete stackList;
  }

  // ---- case 3: ProtoModelMerged::foldIn + selectModel ----------------
  std::cout << "case=proto_model_merged_fold_in" << std::endl;
  std::cout << "case=select_model" << std::endl;
  {
    ProtoModel *m1 = makeModel(&arch, ram, "m1", 0, -1, -1, 0x800);
    ProtoModel *m2 = makeModel(&arch, ram, "m2", 8, -1, -1, 0x900);
    ProtoModel *m3 = makeModel(&arch, ram, "m3", 0, 5, -1, 0x800);

    ProtoModelMerged merged(&arch);
    merged.foldIn(m1);
    std::cout << "  pm=first nummodels=" << merged.numModels()
              << " extrapop=" << merged.extrapop
              << " effects=" << merged.effectlist.size()
              << " trash=" << merged.likelytrash.size() << std::endl;
    merged.foldIn(m2);
    std::cout << "  pm=second nummodels=" << merged.numModels()
              << " extrapop_unknown="
              << (merged.extrapop == ProtoModel::extrapop_unknown ? 1 : 0)
              << " effects=" << merged.effectlist.size()
              << " trash=" << merged.likelytrash.size() << std::endl;
    // foldIn never touches modellist (fspec.cc:2834-2870) — decode's
    // `modellist.push_back(mymodel)` (fspec.cc:2918) is the appender. The
    // selectModel walk below needs constituents, so the fixture performs
    // decode's push directly, mirroring the two folds above.
    merged.modellist.push_back(m1);
    merged.modellist.push_back(m2);
    try {
      merged.foldIn(m3);
      std::cout << "  pm=injectmismatch UNEXPECTED-OK" << std::endl;
    }
    catch (LowlevelError &err) {
      std::cout << "  pm=injectmismatch err=" << err.explain << std::endl;
    }
    std::cout << "  pm=ismerged=" << (merged.isMerged() ? 1 : 0)
              << " nummodels=" << merged.numModels()
              << " model1=" << merged.getModel(1)->name << std::endl;

    // selectModel: trials hitting only slot 1 favor m1 (both models share
    // the input list, so the first model wins the strict-< tie).
    {
      ParamActive active(true);
      active.registerTrial(Address(ram, 0x200), 8);
      active.getTrial(0).markActive();
      ProtoModel *sel = merged.selectModel(&active);
      std::cout << "  sel=firstactive model=" << sel->name << std::endl;
    }
    // All-inactive trials: zero entries -> score 0 -> first model.
    {
      ParamActive active(true);
      active.registerTrial(Address(ram, 0x100), 8);
      ProtoModel *sel = merged.selectModel(&active);
      std::cout << "  sel=nosub model=" << sel->name << std::endl;
    }
    // 25 mismatching ACTIVE trials: score 500 -> refusal.
    {
      ParamActive active(true);
      for (int4 i = 0; i < 25; ++i)
        active.registerTrial(Address(ram, 0x900 + i), 8);
      for (int4 i = 0; i < active.getNumTrials(); ++i)
        active.getTrial(i).markActive();
      try {
        merged.selectModel(&active);
        std::cout << "  sel=threshold UNEXPECTED-OK" << std::endl;
      }
      catch (LowlevelError &err) {
        std::cout << "  sel=threshold err=" << err.explain << std::endl;
      }
    }
    delete m1;
    delete m2;
    delete m3;
  }

  std::cout << "done" << std::endl;
  return 0;
}
