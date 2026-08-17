/*
 * SPACE-PRINTRAW-SPECIAL-1204: locked Ghidra 12.0.4 oracle for
 * JoinSpace::printRaw (space.cc:590-609) through the manager-side join
 * record halves (AddrSpaceManager::findAddJoin/findJoin,
 * translate.cc:671-715/746-762), the SPACE-PRINTRAW-SPECIAL-0001 half of
 * the SPACE-PRINTRAW integration residual.
 *
 * The join cases lock, byte for byte:
 *   - the pieces form `{addr1,addr2,...}`: each piece is printed by its own
 *     space's printRaw (space.cc:602 `vdat.space->printRaw(s,vdat.offset)`),
 *     comma-separated, no spaces, wrapped in braces,
 *   - a 2-piece register join (classic register pair),
 *   - a 3-piece ram+register+register join (per-space widths: the 8-byte ram
 *     offset shrinks to the 4-byte field via the >>32 rule),
 *   - the 1-piece float-extension form `{piece:logicalsize}` — the loop's
 *     szsum accumulator is discarded and replaced by the unified (logical)
 *     size when num==1 (space.cc:604-606),
 *   - the piece recursion through a wordsize-2 space (byteToAddress scaling
 *     plus the "+cut" off-cut suffix inside the braces),
 *   - findAddJoin dedup (identical pieces return the pre-existing record
 *     and offset) and the 16-byte-rounded joinallocate sequence,
 *   - and the unlinked-address failure: printRaw on a join offset with no
 *     JoinRecord throws LowlevelError("Unlinked join address")
 *     (translate.cc:761).
 *
 * The IopSpace::printRaw specialization (op.cc:41-59) is deliberately NOT
 * exercised: both of its terminal renders read the space of the op's
 * SeqNum pc / the branch target block start, which the current Rugra
 * legacy model carries spacelessly (SPACE-IOP-PRINTRAW-0001 residual,
 * blocked by ADDRESS-0001); no byte-exact Rust comparand exists yet.
 */

#include <bits/stdc++.h>

// Test-only access for protected AddrSpaceManager::insertSpace via the
// `class -> struct` precedent of the space_registry_1204 fixture,
// confined to this translation unit.
#define class struct
#define private public
#include "address.hh"
#include "error.hh"
#include "fspec.hh"
#include "op.hh"
#include "space.hh"
#include "translate.hh"
#undef private
#undef class

using namespace ghidra;

class FixtureTranslate final : public Translate {
public:
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
  }
  // AddrSpaceManager protected bridge, exactly like production Translate
  // subclasses (space_registry_1204 fixture precedent).
  void insert(AddrSpace *spc) { insertSpace(spc); }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const std::string &) const override {
    static VarnodeData dummy;
    return dummy;
  }
  std::string getRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  std::string getExactRegisterName(AddrSpace *, uintb, int4) const override {
    return "";
  }
  void getAllRegisters(std::map<VarnodeData, std::string> &) const override {}
  void getUserOpNames(std::vector<std::string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &, const Address &) const override {
    return 0;
  }
  int4 printAssembly(AssemblyEmit &, const Address &) const override {
    return 0;
  }
};

static void printJoinRaw(const AddrSpace *join, uintb off) {
  std::ostringstream hold;
  join->printRaw(hold, off);
  std::cout << "  join off=0x" << std::hex << off << " -> " << hold.str()
            << std::endl;
}

int main(void) {
  std::cout << "schema=1|fixture=SPACE-PRINTRAW-SPECIAL-1204|"
               "oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << std::endl;
  FixtureTranslate mgr;

  // Fixture-shaped registry: const=0, unique=2, ram=3, register=4, ws2=5
  // (addrsize 4, wordsize 2), join=6, iop=7 — the same shape as the Rust
  // comparand's registry. All spaces are heap-allocated because
  // ~AddrSpaceManager deletes every registered space whose refcount fell to
  // one (translate.cc:492-502), the space_registry_1204 precedent.
  ConstantSpace *constspc = new ConstantSpace(&mgr, &mgr);
  UniqueSpace *uniqspc = new UniqueSpace(&mgr, &mgr, 2, 0);
  AddrSpace *ram = new AddrSpace(&mgr, &mgr, IPTR_PROCESSOR, "ram", false, 8,
                                 1, 3, AddrSpace::hasphysical, 0, 0);
  AddrSpace *reg = new AddrSpace(&mgr, &mgr, IPTR_PROCESSOR, "register",
                                 false, 8, 1, 4, AddrSpace::hasphysical, 0, 0);
  AddrSpace *ws2 = new AddrSpace(&mgr, &mgr, IPTR_PROCESSOR, "ws2", false, 4,
                                 2, 5, 0, 0, 0);
  JoinSpace *joinspc = new JoinSpace(&mgr, &mgr, 6);
  IopSpace *iopspc = new IopSpace(&mgr, &mgr, 7);
  mgr.insert(constspc);
  mgr.insert(uniqspc);
  mgr.insert(ram);
  mgr.insert(reg);
  mgr.insert(ws2);
  mgr.insert(joinspc);
  mgr.insert(iopspc);

  // ---- case 1: JoinSpace::printRaw pieces forms --------------------------
  std::cout << "case=join_printraw" << std::endl;
  {
    // A: 2-piece register pair (MS to LS).
    std::vector<VarnodeData> piecesA;
    VarnodeData hi; hi.space = reg; hi.offset = 0x18; hi.size = 4;
    VarnodeData lo; lo.space = reg; lo.offset = 0x10; lo.size = 4;
    piecesA.push_back(hi);
    piecesA.push_back(lo);
    JoinRecord *recA = mgr.findAddJoin(piecesA, 0);
    uintb offA = recA->getUnified().offset;
    printJoinRaw(joinspc, offA);
    // Dedup: identical pieces return the same record and offset.
    JoinRecord *recA2 = mgr.findAddJoin(piecesA, 0);
    std::cout << "  dedup same_record=" << (recA2 == recA ? 1 : 0)
              << " off=0x" << std::hex << recA2->getUnified().offset
              << std::endl;

    // B: 3-piece ram + register + register.
    std::vector<VarnodeData> piecesB;
    VarnodeData b0; b0.space = ram; b0.offset = 0x1000; b0.size = 4;
    VarnodeData b1; b1.space = reg; b1.offset = 0x20; b1.size = 2;
    VarnodeData b2; b2.space = reg; b2.offset = 0x22; b2.size = 2;
    piecesB.push_back(b0);
    piecesB.push_back(b1);
    piecesB.push_back(b2);
    JoinRecord *recB = mgr.findAddJoin(piecesB, 0);
    printJoinRaw(joinspc, recB->getUnified().offset);

    // C: 1-piece float extension (real size 8, logical size 4).
    std::vector<VarnodeData> piecesC;
    VarnodeData c0; c0.space = reg; c0.offset = 0x100; c0.size = 8;
    piecesC.push_back(c0);
    JoinRecord *recC = mgr.findAddJoin(piecesC, 4);
    printJoinRaw(joinspc, recC->getUnified().offset);

    // D: piece recursion through the wordsize-2 space (0x101 -> 0x80+1).
    std::vector<VarnodeData> piecesD;
    VarnodeData d0; d0.space = ws2; d0.offset = 0x101; d0.size = 2;
    VarnodeData d1; d1.space = reg; d1.offset = 0x30; d1.size = 2;
    piecesD.push_back(d0);
    piecesD.push_back(d1);
    JoinRecord *recD = mgr.findAddJoin(piecesD, 0);
    printJoinRaw(joinspc, recD->getUnified().offset);
  }

  // ---- case 2: join-space allocation sequence -----------------------------
  std::cout << "case=join_allocation" << std::endl;
  {
    // The allocation counter is private on both sides, so the sequence is
    // locked through the observable offsets: records A-D printed 0x0, 0x10,
    // 0x20, 0x30 in case 1; a fresh 5th record allocates 0x40 (each
    // allocation rounds the counter up to a multiple of 16,
    // translate.cc:706-710).
    std::vector<VarnodeData> piecesE;
    VarnodeData e0; e0.space = ram; e0.offset = 0x2000; e0.size = 1;
    VarnodeData e1; e1.space = reg; e1.offset = 0x40; e1.size = 1;
    piecesE.push_back(e0);
    piecesE.push_back(e1);
    JoinRecord *recE = mgr.findAddJoin(piecesE, 0);
    std::cout << "  next_alloc off=0x" << std::hex
              << recE->getUnified().offset << std::endl;
  }

  // ---- case 3: unlinked join address throws -------------------------------
  std::cout << "case=join_printraw_unlinked" << std::endl;
  {
    try {
      printJoinRaw(joinspc, 0xdeadb0);
    } catch (LowlevelError &err) {
      std::cout << "  printRaw(0xdeadb0) threw: " << err.explain << std::endl;
    }
  }
  return 0;
}
