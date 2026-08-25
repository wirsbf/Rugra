/* RETURNFOLD-GAPA-UPSTREAM-0001 fixture — the e2e return-value fold chain
 * (ActionMarkExplicit::baseExplicit multi-instance rule cc:3020-3021 +
 * multipleInteraction/processMultiplier cc:3091/3166 + ActionMarkImplied
 * count cc:3434 + PrintC implied inlining: printc.cc:754 opReturn /
 * printlanguage.cc:526-534 recurse / printc.cc:2703-2705 emitBlockBasic
 * statement omission) against the locked Ghidra 12.0.4 oracle, driven
 * through the production ActionMarkExplicit::apply, ActionMarkImplied::apply
 * and PrintC::emitBlockBasic (public, unmodified).
 *
 * Locked oracle: Ghidra_12.0.4_build e40ed13014025f82488b1f8f7bca566894ac376b.
 *
 * Scenarios (each a fresh Funcdata; per Ghidra pipeline order the fixture
 * runs setHighLevel (ActionAssignHigh, coreaction.cc:5717) before
 * ActionMarkExplicit (cc:5719), then ActionMarkImplied (cc:5720), then
 * prints each block):
 *   s1_fold       t = COPY 10; RETURN t — single-instance high, one
 *                 descendant: implied. Folded print `return 10;`, no
 *                 standalone COPY statement (cc:2704-2705 skip), MarkImplied
 *                 count=1, MarkExplicit count=0.
 *   s2_merged     two COPY-written instances merged into one HighVariable
 *                 (HighVariable::merge): baseExplicit cc:3020-3021 forces
 *                 both explicit. MarkExplicit count=2, MarkImplied count=0,
 *                 print keeps both assign statements and returns read the
 *                 variable tokens.
 *   s3_dup3       t = COPY 10 read by three RETURNs: desccount=3 exceeds
 *                 max_implied_ref=2 → cc:3078 `return -1` explicit. One
 *                 assign + three var returns. (Pins the maxref boundary; a
 *                 regression to `return desccount` would leave t implied
 *                 with zero assign lines.)
 *   s4_mult2      t = COPY 10 read by two RETURNs: desccount=2 == maxref →
 *                 multlist candidate; processMultiplier counts 1 term <=
 *                 max_term_duplication=2 → stays implicit-eligible →
 *                 implied; both returns fold. MarkExplicit count=0,
 *                 MarkImplied count=1.
 *
 * Observable projections (one stdout line each):
 *   scen          scenario gate line.
 *   flag          per tracked varnode: explicit/implied bits after both
 *                 actions (read directly, mirroring the oracle flag store).
 *   mark          the Action::perform return codes for both actions — the
 *                 inherited Action::count that perform zeroes at
 *                 status_start (action.cc:306) and returns (action.cc:361).
 *                 The ctor does not initialize count, so the fixture never
 *                 reads the field after a bare apply().
 *   text          normalized block emission: each emitted statement line
 *                 reduced to its kind (return/assign/other) with the value
 *                 argument classified by standalone token (lit10/lit3/var),
 *                 `;`-joined in block order. The literal classification is
 *                 the A51 observable: folded returns carry the constant,
 *                 explicit-form returns carry the variable token.
 *   case_*        residual UNTESTED declarations for branches of this chain
 *                 the fixture does not drive.
 *
 * Test-only access rewrite (#define private public / #define class struct
 * after the standard headers so it cannot leak into libstdc++) follows the
 * reviewed tests/oracle/returnfold_gapa_1204.cc pattern: it opens the
 * block-graph construction helpers; perform/apply/emitBlockBasic themselves
 * are public and unmodified, and HighVariable::merge /
 * Funcdata::setHighLevel are public API.
 */
#include <bits/stdc++.h>
#define private public
#define class struct
#include "architecture.hh"
#include "block.hh"
#include "coreaction.hh"
#include "database.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include "libdecomp.hh"
#include "marshal.hh"
#include "op.hh"
#include "fspec.hh"
#include "printc.hh"
#include "translate.hh"
#include "typeop.hh"
#include "varnode.hh"

using namespace std;
using namespace ghidra;

namespace {

class FixtureTranslate final : public Translate {
public:
  VarnodeData dummyRegister;
  FixtureTranslate() {
    setBigEndian(false);
    setUniqueBase(0);
    insertSpace(new ConstantSpace(this,this));
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"other",false,8,1,1,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new UniqueSpace(this,this,2,0));
    AddrSpace *ram = new AddrSpace(this,this,IPTR_PROCESSOR,"ram",false,8,1,3,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(ram);
    AddrSpace *reg = new AddrSpace(this,this,IPTR_PROCESSOR,"register",false,8,1,4,
                                   AddrSpace::hasphysical,0,0);
    insertSpace(reg);
    SpacebaseSpace *stack = new SpacebaseSpace(this,this,"stack",5,8,ram,1,true);
    insertSpace(stack);
    VarnodeData stackPointer = { reg, 0, 8 };
    addSpacebasePointer(stack,stackPointer,8,true);
    insertSpace(new AddrSpace(this,this,IPTR_PROCESSOR,"join",false,8,1,6,
                              AddrSpace::hasphysical,0,0));
    insertSpace(new IopSpace(this,this,7));
    setDefaultCodeSpace(3);
    dummyRegister = { reg, 0, 8 };
  }
  void initialize(DocumentStorage &) override {}
  const VarnodeData &getRegister(const string &) const override { return dummyRegister; }
  string getRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  string getExactRegisterName(AddrSpace *,uintb,int4) const override { return ""; }
  void getAllRegisters(map<VarnodeData,string> &) const override {}
  void getUserOpNames(vector<string> &) const override {}
  int4 instructionLength(const Address &) const override { return 0; }
  int4 oneInstruction(PcodeEmit &,const Address &) const override { return 0; }
  int4 printAssembly(AssemblyEmit &,const Address &) const override { return 0; }
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
    FixtureTranslate *fixtureTranslate = new FixtureTranslate();
    translate = fixtureTranslate;
    copySpaces(fixtureTranslate);
    max_basetype_size = 16;
    types = new TypeFactory(this);
    types->setupSizes();
    types->setCoreType("xunknown1",1,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown2",2,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown4",4,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown8",8,TYPE_UNKNOWN,false);
    types->cacheCoreTypes();
    TypeOp::registerInstructions(inst,types,translate);
    symboltab = new Database(this,false);
    symboltab->attachScope(new ScopeInternal(0x101,"",this),(Scope *)0);
    // The default model mirrors the gapa fixture: Funcdata's ctor wires
    // funcproto.setInternal(glb->defaultfp, ...) and ScopeLocal::
    // resetLocalWindow reads model stack growth, so defaultfp must exist.
    ProtoModel *model = new ProtoModel(this);
    istringstream stream("<prototype name=\"fixture\" extrapop=\"0\">"
                         "<input/>"
                         "<output><pentry minsize=\"1\" maxsize=\"8\" extension=\"inttype\">"
                         "<register name=\"outreg\"/>"
                         "</pentry></output>"
                         "</prototype>");
    XmlDecode decoder(this);
    decoder.ingestStream(stream);
    model->decode(decoder);
    protoModels[model->getName()] = model;
    setDefaultModel(model);
  }
  void printMessage(const string &) const override {}
};

class FixturePrintC final : public PrintC {
public:
  FixturePrintC(void) : PrintC(nullptr, "printc-returnfold-upstream-1204") {
    delete emit;
    emit = new EmitNoMarkup();
  }

  void renderBlock(const BlockBasic *bb) {
    emitBlockBasic(bb);
    emit->flush();
  }
};

class Fixture {
  Funcdata &fd;
  AddrSpace *code;
  vector<BlockBasic *> blocks;
  uintb nextPc;

public:
  explicit Fixture(Funcdata &f, uintb basePc)
    : fd(f), code(f.getArch()->getDefaultCodeSpace()), nextPc(basePc) {}

  BlockBasic *makeBlock(void)
  {
    BlockGraph &graph = const_cast<BlockGraph &>(fd.getBasicBlocks());
    BlockBasic *block = graph.newBlockBasic(&fd);
    blocks.push_back(block);
    return block;
  }

  Address allocPc(void)
  {
    Address a(code,nextPc);
    nextPc += 8;
    return a;
  }

  // b = COPY const(value); placed at the head of blk. Returns the written
  // output varnode (unique space, fresh offset).
  Varnode *makeCopyAssign(BlockBasic *blk,uintb value)
  {
    PcodeOp *op = fd.newOp(1,allocPc());
    fd.opSetOpcode(op,CPUI_COPY);
    Varnode *out = fd.newUniqueOut(4,op);
    fd.opSetInput(op,fd.newConstant(4,value),0);
    fd.opInsertEnd(op,blk);
    return out;
  }

  // RETURN value at the end of blk (slot 0 holds the placeholder indirect
  // constant, matching the production post-guardReturns shape).
  void makeReturn(BlockBasic *blk,Varnode *value)
  {
    PcodeOp *op = fd.newOp(2,allocPc());
    fd.opSetOpcode(op,CPUI_RETURN);
    fd.opSetInput(op,fd.newConstant(1,0),0);
    fd.opSetInput(op,value,1);
    fd.opInsertEnd(op,blk);
  }

  const vector<BlockBasic *> &blocksMade(void) const { return blocks; }
};

// Does text contain the given standalone token? Tokens are maximal
// alphanumeric runs, so "0x10" is a single token != "10", while "(int)10"
// yields the token "10".
bool has_token(const string &text,const char *tok)
{
  string clean;
  for(char c : text) {
    if (isalnum((unsigned char)c)) clean += c;
    else {
      if (clean == tok) return true;
      clean.clear();
    }
  }
  return clean == tok;
}

string classify_arg(const string &text)
{
  if (has_token(text,"10")) return "lit10";
  if (has_token(text,"3")) return "lit3";
  return "var";
}

string summarize(const string &text)
{
  istringstream input(text);
  ostringstream out;
  string line;
  bool first = true;
  while (getline(input,line)) {
    size_t p = line.find_first_not_of(' ');
    if (p == string::npos) continue;
    string body = line.substr(p);
    string kind;
    if (body.rfind("return",0) == 0)
      kind = "return+" + classify_arg(body);
    else if (body.find(" = ") != string::npos)
      kind = "assign+" + classify_arg(body.substr(body.find(" = ") + 3));
    else
      kind = "other";
    if (!first) out << ';';
    out << kind;
    first = false;
  }
  return out.str();
}

void drive(const char *name,Funcdata &fd,const Fixture &f,
           const vector<Varnode *> &tracked)
{
  cout << "scen|name=" << name << '\n';
  fd.setHighLevel();			// ActionAssignHigh (coreaction.cc:5717)
  ActionMarkExplicit me("");
  // perform() is the production entry (public): it zeroes the inherited
  // count at status_start (action.cc:306), runs apply, and returns count
  // (action.cc:361). The Action ctor deliberately does not initialize
  // count, so reading it after a bare apply() would read indeterminate
  // memory — the perform return code is the sanctioned count observable.
  int4 me_rc = me.perform(fd);		// coreaction.cc:5719
  ActionMarkImplied mi("");
  int4 mi_rc = mi.perform(fd);		// coreaction.cc:5720
  for(size_t i=0;i<tracked.size();++i) {
    const Varnode *vn = tracked[i];
    cout << "flag|scen=" << name << "|vn=t" << i
         << "|explicit=" << (vn->isExplicit() ? 1 : 0)
         << "|implied=" << (vn->isImplied() ? 1 : 0) << '\n';
  }
  cout << "mark|scen=" << name << "|me_count=" << me_rc
       << "|mi_count=" << mi_rc << '\n';
  ostringstream output;
  FixturePrintC printer;
  printer.setOutputStream(&output);
  for(BlockBasic *bb : f.blocksMade())
    printer.renderBlock(bb);
  cout << "text|scen=" << name << "|" << summarize(output.str()) << '\n';
}

}  // namespace

int main(void)
{
  cout << std::unitbuf;
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  cout << "schema=1|fixture=RETURNFOLD-GAPA-UPSTREAM-0001"
       << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  try {
    FixtureArchitecture architecture;
    AddrSpace *ram = architecture.getSpace(3);
    Scope *global = architecture.symboltab->getGlobalScope();

    // ---------------- s1_fold: single instance, one reader ----------------
    {
      Funcdata fd("rf1","rf1",global,Address(ram,0x63000),(FunctionSymbol *)0,0x100);
      Fixture f(fd,0x63010);
      BlockBasic *b1 = f.makeBlock();
      Varnode *t = f.makeCopyAssign(b1,10);
      f.makeReturn(b1,t);
      drive("s1_fold",fd,f,{ t });
    }

    // ------------- s2_merged: two instances in one HighVariable -----------
    {
      Funcdata fd("rf2","rf2",global,Address(ram,0x63100),(FunctionSymbol *)0,0x100);
      Fixture f(fd,0x63110);
      BlockBasic *b1 = f.makeBlock();
      BlockBasic *b2 = f.makeBlock();
      Varnode *t1 = f.makeCopyAssign(b1,10);
      f.makeReturn(b1,t1);
      Varnode *t2 = f.makeCopyAssign(b2,3);
      f.makeReturn(b2,t2);
      fd.setHighLevel();
      t1->getHigh()->merge(t2->getHigh(),(HighIntersectTest *)0,false);
      drive("s2_merged",fd,f,{ t1, t2 });
    }

    // ------------- s3_dup3: three readers exceed max_implied_ref ----------
    {
      Funcdata fd("rf3","rf3",global,Address(ram,0x63200),(FunctionSymbol *)0,0x100);
      Fixture f(fd,0x63210);
      BlockBasic *b0 = f.makeBlock();
      BlockBasic *b1 = f.makeBlock();
      BlockBasic *b2 = f.makeBlock();
      BlockBasic *b3 = f.makeBlock();
      Varnode *t = f.makeCopyAssign(b0,10);
      f.makeReturn(b1,t);
      f.makeReturn(b2,t);
      f.makeReturn(b3,t);
      drive("s3_dup3",fd,f,{ t });
    }

    // ---------- s4_mult2: two readers == maxref, multlist survives ---------
    {
      Funcdata fd("rf4","rf4",global,Address(ram,0x63300),(FunctionSymbol *)0,0x100);
      Fixture f(fd,0x63310);
      BlockBasic *b0 = f.makeBlock();
      BlockBasic *b1 = f.makeBlock();
      BlockBasic *b2 = f.makeBlock();
      Varnode *t = f.makeCopyAssign(b0,10);
      f.makeReturn(b1,t);
      f.makeReturn(b2,t);
      drive("s4_mult2",fd,f,{ t });
    }
  }
  catch (const LowlevelError &error) {
    cout << "exception|phase=main|what=" << error.explain << '\n';
    return 1;
  }
  catch (const exception &error) {
    cout << "exception|phase=main|what=" << error.what() << '\n';
    return 1;
  }
  cout << "case_new_constructor|status=UNTESTED|note=checkNewToConstructor (cc:3205-3235, CPUI_NEW + CALLIND special print) not driven; needs NEW call machinery\n";
  cout << "case_addrtied_branches|status=UNTESTED|note=baseExplicit addr-tied SUBPIECE/ZEXT/PIECE sub-branches (cc:3022-3049) need addrtied varnodes + PieceNode/partialroot infra (MERGE-ADDRTIED-CLOSURE-0001; Rugra PcodeOp::partialroot flag absent)\n";
  cout << "case_cover_crossing|status=UNTESTED|note=checkImpliedCover LOAD/STORE/CALL crossing (cc:3384-3412) not driven; Rugra block-level approximations stand (is_possible_alias reserved)\n";
  cout << "case_marking_order|status=UNTESTED|note=Rugra MarkImplied iterates loc order flat vs Ghidra DFS post-order cc:3430-3451; flags and total count argued equal, not pinned by this fixture\n";
  return 0;
}
