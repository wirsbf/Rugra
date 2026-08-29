/*
 * Locked Ghidra 12.0.4 hierarchical pipeline snapshot for curl::GetStr.
 *
 * This fixture intentionally observes public decompiler objects directly.  It
 * does not parse console text and it never normalizes away object identity or
 * traversal order.  The companion Rust example emits the same JSON schema.
 */

#include "bfd_arch.hh"
#include "libdecomp.hh"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::ofstream;
using std::ostream;
using std::ostringstream;
using std::runtime_error;
using std::string;
using std::vector;

string jsonEscape(const string &value)

{
  ostringstream out;
  for (string::const_iterator iter = value.begin(); iter != value.end(); ++iter) {
    unsigned char ch = static_cast<unsigned char>(*iter);
    switch (ch) {
    case '"': out << "\\\""; break;
    case '\\': out << "\\\\"; break;
    case '\b': out << "\\b"; break;
    case '\f': out << "\\f"; break;
    case '\n': out << "\\n"; break;
    case '\r': out << "\\r"; break;
    case '\t': out << "\\t"; break;
    default:
      if (ch < 0x20) {
        out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<unsigned int>(ch) << std::dec;
      }
      else
        out << static_cast<char>(ch);
      break;
    }
  }
  return out.str();
}

void writeString(ostream &out,const string &value)

{
  out << '"' << jsonEscape(value) << '"';
}

void writeAddress(ostream &out,const Address &address)

{
  if (address.isInvalid()) {
    out << "null";
    return;
  }
  AddrSpace *space = address.getSpace();
  out << "{\"space\":" << space->getIndex() << ",\"space_name\":";
  writeString(out,space->getName());
  out << ",\"offset\":" << address.getOffset() << '}';
}

struct SnapshotIds {
  Architecture *architecture;
  vector<const PcodeOp *> ops;
  map<const PcodeOp *,uint8> opId;
  vector<const Varnode *> varnodes;
  map<const Varnode *,uint8> varnodeId;

  explicit SnapshotIds(const Funcdata &fd) : architecture(fd.getArch())
  {
    for (PcodeOpTree::const_iterator iter=fd.beginOpAll();iter!=fd.endOpAll();++iter) {
      const PcodeOp *op = (*iter).second;
      opId[op] = ops.size();
      ops.push_back(op);
    }
    for (vector<const PcodeOp *>::const_iterator iter=ops.begin();iter!=ops.end();++iter) {
      const PcodeOp *op = *iter;
      addVarnode(op->getOut());
      for(int4 slot=0;slot<op->numInput();++slot)
        addVarnode(op->getIn(slot));
    }
    for (VarnodeLocSet::const_iterator iter=fd.beginLoc();iter!=fd.endLoc();++iter)
      addVarnode(*iter);
  }

  void addVarnode(const Varnode *vn)
  {
    if (vn == (const Varnode *)0) return;
    if (varnodeId.find(vn) != varnodeId.end()) return;
    varnodeId[vn] = varnodes.size();
    varnodes.push_back(vn);
  }

  int8 getOp(const PcodeOp *op) const
  {
    map<const PcodeOp *,uint8>::const_iterator iter = opId.find(op);
    return (iter == opId.end()) ? -1 : static_cast<int8>((*iter).second);
  }

  int8 getVarnode(const Varnode *vn) const
  {
    map<const Varnode *,uint8>::const_iterator iter = varnodeId.find(vn);
    return (iter == varnodeId.end()) ? -1 : static_cast<int8>((*iter).second);
  }

  int4 getSpaceReference(const Varnode *vn) const
  {
    bool isSpaceInput = false;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      const PcodeOp *op = *iter;
      if ((op->code() == CPUI_LOAD || op->code() == CPUI_STORE) &&
          op->numInput() != 0 && op->getIn(0) == vn) {
        isSpaceInput = true;
        break;
      }
    }
    if (!isSpaceInput) return -1;
    for(int4 index=0;index<architecture->numSpaces();++index) {
      AddrSpace *space = architecture->getSpace(index);
      if (space != (AddrSpace *)0 && (uintb)(uintp)space == vn->getOffset())
        return space->getIndex();
    }
    throw runtime_error("LOAD/STORE space input does not name a registered address space");
  }

  int8 getFspecReference(const Varnode *vn) const
  {
    if (vn->getSpace()->getType() != IPTR_FSPEC) return -1;
    FuncCallSpecs *fc = FuncCallSpecs::getFspecFromConst(vn->getAddr());
    if (fc == (FuncCallSpecs *)0 || fc->getEntryAddress().isInvalid())
      throw runtime_error("Fspec varnode does not name a valid call specification");
    return fc->getEntryAddress().getOffset();
  }

  int8 getIopReference(const Varnode *vn) const
  {
    if (vn->getSpace()->getType() != IPTR_IOP) return -1;
    PcodeOp *op = PcodeOp::getOpFromConst(vn->getAddr());
    if (op == (PcodeOp *)0)
      throw runtime_error("Iop varnode does not name a PcodeOp");
    int8 id = getOp(op);
    if (id >= 0) return id;
    return -2 - static_cast<int8>(op->getSeqNum().getTime());
  }
};

void writeOpProperties(ostream &out,const PcodeOp *op)

{
  out << "{\"dead\":" << (op->isDead() ? "true" : "false")
      << ",\"call\":" << (op->isCall() ? "true" : "false")
      << ",\"marker\":" << (op->isMarker() ? "true" : "false")
      << ",\"branch\":" << (op->isBranch() ? "true" : "false")
      << ",\"bool_output\":" << (op->isBoolOutput() ? "true" : "false")
      << ",\"boolean_flip\":" << (op->isBooleanFlip() ? "true" : "false")
      << ",\"instruction_start\":" << (op->isInstructionStart() ? "true" : "false")
      << ",\"indirect_source\":" << (op->isIndirectSource() ? "true" : "false")
      << ",\"ptr_flow\":" << (op->isPtrFlow() ? "true" : "false") << '}';
}

void writeType(ostream &out,const Datatype *type);

void writeOps(ostream &out,const SnapshotIds &ids,bool includeHighReadTypes)

{
  out << '[';
  for(uint8 index=0;index<ids.ops.size();++index) {
    if (index != 0) out << ',';
    const PcodeOp *op = ids.ops[index];
    out << "{\"id\":" << index << ",\"address\":";
    writeAddress(out,op->getAddr());
    out << ",\"time\":" << op->getSeqNum().getTime()
        << ",\"order\":" << op->getSeqNum().getOrder()
        << ",\"opcode\":" << static_cast<int4>(op->code()) << ",\"opcode_name\":";
    writeString(out,op->getOpName());
    out << ",\"parent_block\":";
    if (op->getParent() == (const BlockBasic *)0)
      out << "null";
    else
      out << op->getParent()->getIndex();
    out << ",\"output\":";
    if (op->getOut() == (const Varnode *)0)
      out << "null";
    else
      out << ids.getVarnode(op->getOut());
    out << ",\"inputs\":[";
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (slot != 0) out << ',';
      out << ids.getVarnode(op->getIn(slot));
    }
    out << "],\"input_high_read_types\":[";
    for(int4 slot=0;slot<op->numInput();++slot) {
      if (slot != 0) out << ',';
      const Varnode *vn = op->getIn(slot);
      if (!includeHighReadTypes || vn->isAnnotation())
        out << "null";
      else
        writeType(out,vn->getHighTypeReadFacing(op));
    }
    out << "],\"properties\":";
    writeOpProperties(out,op);
    out << '}';
  }
  out << ']';
}

void writeType(ostream &out,const Datatype *type)

{
  if (type == (const Datatype *)0) {
    out << "null";
    return;
  }
  string metatype;
  metatype2string(type->getMetatype(),metatype);
  out << "{\"name\":";
  writeString(out,type->getName());
  out << ",\"size\":" << type->getSize() << ",\"metatype\":";
  writeString(out,metatype);
  out << '}';
}

void writeVarnodes(ostream &out,const SnapshotIds &ids)

{
  out << '[';
  for(uint8 index=0;index<ids.varnodes.size();++index) {
    if (index != 0) out << ',';
    const Varnode *vn = ids.varnodes[index];
    int4 spaceReference = ids.getSpaceReference(vn);
    int8 fspecReference = ids.getFspecReference(vn);
    int8 iopReference = ids.getIopReference(vn);
    out << "{\"id\":" << index << ",\"space\":" << vn->getSpace()->getIndex()
        << ",\"space_name\":";
    writeString(out,vn->getSpace()->getName());
    out << ",\"offset\":";
    if (spaceReference < 0)
      if (fspecReference >= 0)
        out << fspecReference;
      else if (iopReference != -1)
        out << iopReference;
      else
        out << vn->getOffset();
    else
      out << spaceReference;
    out << ",\"space_ref_index\":";
    if (spaceReference < 0)
      out << "null";
    else
      out << spaceReference;
    out << ",\"pointer_ref_kind\":";
    if (spaceReference >= 0)
      writeString(out,"space");
    else if (fspecReference >= 0)
      writeString(out,"fspec");
    else if (iopReference != -1)
      writeString(out,"iop");
    else
      out << "null";
    out << ",\"size\":" << vn->getSize()
        << ",\"flags\":" << vn->getFlags()
        << ",\"create_index\":" << vn->getCreateIndex()
        << ",\"def\":";
    if (vn->getDef() == (const PcodeOp *)0)
      out << "null";
    else
      out << ids.getOp(vn->getDef());
    out << ",\"uses\":[";
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
      if (!first) out << ',';
      first = false;
      out << ids.getOp(*iter);
    }
    out << "],\"type\":";
    writeType(out,vn->getType());
    out << '}';
  }
  out << ']';
}

void writeOutEdges(ostream &out,const FlowBlock *block)

{
  out << '[';
  for(int4 slot=0;slot<block->sizeOut();++slot) {
    if (slot != 0) out << ',';
    out << "{\"slot\":" << slot << ",\"target\":" << block->getOut(slot)->getIndex()
        << ",\"reverse\":" << block->getOutRevIndex(slot)
        << ",\"loop\":" << (block->isLoopOut(slot) ? "true" : "false")
        << ",\"default\":" << (block->isDefaultBranch(slot) ? "true" : "false")
        << ",\"back\":" << (block->isBackEdgeOut(slot) ? "true" : "false")
        << ",\"irreducible\":" << (block->isIrreducibleOut(slot) ? "true" : "false")
        << ",\"goto\":" << (block->isGotoOut(slot) ? "true" : "false") << '}';
  }
  out << ']';
}

void writeInEdges(ostream &out,const FlowBlock *block)

{
  out << '[';
  for(int4 slot=0;slot<block->sizeIn();++slot) {
    if (slot != 0) out << ',';
    out << "{\"slot\":" << slot << ",\"source\":" << block->getIn(slot)->getIndex()
        << ",\"reverse\":" << block->getInRevIndex(slot)
        << ",\"loop\":" << (block->isLoopIn(slot) ? "true" : "false")
        << ",\"tree\":" << (block->isTreeEdgeIn(slot) ? "true" : "false")
        << ",\"back\":" << (block->isBackEdgeIn(slot) ? "true" : "false")
        << ",\"irreducible\":" << (block->isIrreducibleIn(slot) ? "true" : "false")
        << ",\"goto\":" << (block->isGotoIn(slot) ? "true" : "false") << '}';
  }
  out << ']';
}

void writeBlock(ostream &out,const FlowBlock *block,const SnapshotIds &ids)

{
  out << "{\"index\":" << block->getIndex() << ",\"type\":";
  writeString(out,FlowBlock::typeToName(block->getType()));
  out << ",\"flags\":" << block->getFlags() << ",\"start\":";
  writeAddress(out,block->getStart());
  out << ",\"stop\":";
  writeAddress(out,block->getStop());
  out << ",\"ops\":[";
  const BlockBasic *basic = dynamic_cast<const BlockBasic *>(block);
  if (basic != (const BlockBasic *)0) {
    bool first = true;
    for(list<PcodeOp *>::const_iterator iter=basic->beginOp();iter!=basic->endOp();++iter) {
      if (!first) out << ',';
      first = false;
      out << ids.getOp(*iter);
    }
  }
  out << "],\"out_edges\":";
  writeOutEdges(out,block);
  out << ",\"in_edges\":";
  writeInEdges(out,block);
  out << '}';
}

void writeBlocks(ostream &out,const BlockGraph &graph,const SnapshotIds &ids)

{
  out << '[';
  for(int4 index=0;index<graph.getSize();++index) {
    if (index != 0) out << ',';
    writeBlock(out,graph.getBlock(index),ids);
  }
  out << ']';
}

void writeStructureNode(ostream &out,const FlowBlock *block)

{
  out << "{\"index\":" << block->getIndex() << ",\"type\":";
  writeString(out,FlowBlock::typeToName(block->getType()));
  out << ",\"flags\":" << block->getFlags() << ",\"children\":[";
  bool first = true;
  const BlockGraph *graph = dynamic_cast<const BlockGraph *>(block);
  if (graph != (const BlockGraph *)0) {
    for(int4 index=0;index<graph->getSize();++index) {
      if (!first) out << ',';
      first = false;
      writeStructureNode(out,graph->getBlock(index));
    }
  }
  else if (block->getType() == FlowBlock::t_copy) {
    const FlowBlock *child = block->subBlock(0);
    if (child != (const FlowBlock *)0)
      writeStructureNode(out,child);
  }
  out << "]}";
}

void writeFunction(ostream &out,const Funcdata &fd)

{
  out << "{\"name\":";
  writeString(out,fd.getName());
  out << ",\"entry\":";
  writeAddress(out,fd.getAddress());
  out << ",\"size\":" << fd.getSize() << '}';
}

void writeSnapshot(const string &path,const string &stage,const Funcdata &fd,
                   bool includeOps,bool includeVarnodes,bool includeBlocks,
                   bool includeStructure,const string *text)

{
  SnapshotIds ids(fd);
  ofstream out(path.c_str(),std::ios::binary);
  if (!out) throw runtime_error("unable to create snapshot: " + path);
  out << "{\"schema\":1,\"state\":\"OK\",\"stage\":";
  writeString(out,stage);
  out << ",\"function\":";
  writeFunction(out,fd);
  out << ",\"ops\":";
  if (includeOps) writeOps(out,ids,stage == "03_action_ir"); else out << "[]";
  out << ",\"varnodes\":";
  if (includeVarnodes) writeVarnodes(out,ids); else out << "[]";
  out << ",\"blocks\":";
  if (includeBlocks) writeBlocks(out,fd.getBasicBlocks(),ids); else out << "[]";
  out << ",\"structure\":";
  if (includeStructure) writeStructureNode(out,&fd.getStructure()); else out << "null";
  out << ",\"text\":";
  if (text == (const string *)0) out << "null"; else writeString(out,*text);
  out << "}\n";
}

string joinPath(const string &directory,const string &name)

{
  if (!directory.empty() && directory[directory.size()-1] == '/')
    return directory + name;
  return directory + '/' + name;
}

void runFixture(const string &specDirectory,const string &binary,const string &outputDirectory)

{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  {
    BfdArchitecture architecture(binary,"default",&std::cerr);
    DocumentStorage store;
    architecture.init(store);
    architecture.readLoaderSymbols("::");
    Funcdata *fd = architecture.symboltab->getGlobalScope()->queryFunction("GetStr");
    if (fd == (Funcdata *)0)
      throw runtime_error("GetStr was not found in the BFD symbol table");
    if (fd->hasNoCode())
      throw runtime_error("GetStr has no code");

    AddrSpace *codeSpace = architecture.getDefaultCodeSpace();
    fd->followFlow(Address(codeSpace,0),Address(codeSpace,codeSpace->getHighest()));
    writeSnapshot(joinPath(outputDirectory,"00_raw_pcode.json"),"00_raw_pcode",*fd,
                  true,true,false,false,(const string *)0);
    writeSnapshot(joinPath(outputDirectory,"01_cfg.json"),"01_cfg",*fd,
                  false,false,true,false,(const string *)0);

    Action *root = architecture.allacts.getCurrent();
    if (root == (Action *)0)
      throw runtime_error("Ghidra did not configure a current decompile action");
    if (!root->setBreakPoint(Action::tmpbreak_start,"paramdouble"))
      throw runtime_error("unable to place the post-heritage breakpoint");
    root->reset(*fd);
    int4 result = root->perform(*fd);
    if (result >= 0)
      throw runtime_error("decompile action completed without hitting paramdouble breakpoint");
    writeSnapshot(joinPath(outputDirectory,"02_heritage_ssa.json"),"02_heritage_ssa",*fd,
                  true,true,true,false,(const string *)0);

    do {
      result = root->perform(*fd);
    } while(result < 0);
    writeSnapshot(joinPath(outputDirectory,"03_action_ir.json"),"03_action_ir",*fd,
                  true,true,true,false,(const string *)0);
    writeSnapshot(joinPath(outputDirectory,"04_structure.json"),"04_structure",*fd,
                  false,false,false,true,(const string *)0);

    ostringstream cOutput;
    architecture.print->setOutputStream(&cOutput);
    architecture.print->docFunction(fd);
    string cText = cOutput.str();
    writeSnapshot(joinPath(outputDirectory,"05_c.json"),"05_c",*fd,
                  false,false,false,false,&cText);
  }
  shutdownDecompilerLibrary();
}

} // anonymous namespace

int main(int argc,char **argv)

{
  if (argc != 4) {
    std::cerr << "usage: getstr_pipeline_1204 SPEC_ROOT CURL_BINARY OUTPUT_DIRECTORY\n";
    return 2;
  }
  try {
    runFixture(argv[1],argv[2],argv[3]);
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
