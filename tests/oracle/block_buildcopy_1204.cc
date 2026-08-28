/*
 * BLOCK-BUILDCOPY-STATE-0001 locked Ghidra 12.0.4 oracle.
 *
 * Directly exercises BlockGraph::buildCopy/newBlockCopy, the BlockCopy
 * live-delegation contract, BlockBasic end insertion, and reciprocal
 * parallel-edge deletion after swapEdges. Test-only private access exposes
 * the complete FlowBlock state without changing the locked oracle sources.
 */
#include <bits/stdc++.h>

#define private public
#define class struct
#include "block.hh"
#undef class
#undef private

namespace {

using namespace ghidra;

class Names {
  std::map<const FlowBlock *, std::string> blocks;
  std::map<const PcodeOp *, std::string> ops;
public:
  void block(const FlowBlock *ptr,const std::string &name) { blocks[ptr] = name; }
  void op(const PcodeOp *ptr,const std::string &name) { ops[ptr] = name; }

  std::string block(const FlowBlock *ptr) const
  {
    if (ptr == (const FlowBlock *)0) return "null";
    std::map<const FlowBlock *,std::string>::const_iterator iter = blocks.find(ptr);
    return iter == blocks.end() ? "?" : iter->second;
  }

  std::string op(const PcodeOp *ptr) const
  {
    if (ptr == (const PcodeOp *)0) return "null";
    std::map<const PcodeOp *,std::string>::const_iterator iter = ops.find(ptr);
    return iter == ops.end() ? "?" : iter->second;
  }
};

class ProbeBasic : public BlockBasic {
public:
  PcodeOp *firstToken;
  PcodeOp *lastToken;
  FlowBlock *splitToken;
  bool complexToken;

  ProbeBasic(void) : BlockBasic((Funcdata *)0)
  {
    firstToken = (PcodeOp *)0;
    lastToken = (PcodeOp *)0;
    splitToken = (FlowBlock *)0;
    complexToken = false;
  }

  virtual PcodeOp *firstOp(void) const { return firstToken; }
  virtual PcodeOp *lastOp(void) const { return lastToken; }
  virtual FlowBlock *getSplitPoint(void) { return splitToken; }
  virtual bool isComplex(void) const { return complexToken; }
};

void setState(FlowBlock *block,int4 index,int4 visit,int4 numdesc,uint4 flags,
              FlowBlock *immedDom)
{
  block->index = index;
  block->visitcount = visit;
  block->numdesc = numdesc;
  block->flags = flags;
  block->immed_dom = immedDom;
  block->copymap = (FlowBlock *)0;
}

void addLabeledEdge(BlockGraph &graph,FlowBlock *source,FlowBlock *target,uint4 label)
{
  int4 outslot = source->outofthis.size();
  int4 inslot = target->intothis.size();
  graph.addEdge(source,target);
  source->outofthis[outslot].label = label;
  target->intothis[inslot].label = label;
}

std::string edgeList(const FlowBlock *block,bool outgoing,const Names &names)
{
  const std::vector<BlockEdge> &edges = outgoing ? block->outofthis : block->intothis;
  std::ostringstream result;
  result << '[';
  for(int4 slot=0;slot<edges.size();++slot) {
    if (slot != 0) result << ',';
    result << names.block(edges[slot].point) << ':'
           << edges[slot].reverse_index << ':' << edges[slot].label;
  }
  result << ']';
  return result.str();
}

std::string slottedEdgeList(const FlowBlock *block,bool outgoing,const Names &names)
{
  const std::vector<BlockEdge> &edges = outgoing ? block->outofthis : block->intothis;
  std::ostringstream result;
  result << '[';
  for(int4 slot=0;slot<edges.size();++slot) {
    if (slot != 0) result << ',';
    result << slot << '>' << names.block(edges[slot].point) << ':'
           << edges[slot].reverse_index << ':' << edges[slot].label;
  }
  result << ']';
  return result.str();
}

std::string opList(const BlockBasic *block,const Names &names)
{
  std::ostringstream result;
  result << '[';
  int4 slot = 0;
  for(std::list<PcodeOp *>::const_iterator iter=block->beginOp();
      iter!=block->endOp();++iter) {
    if (slot != 0) result << ',';
    const PcodeOp *op = *iter;
    result << slot << '>' << names.op(op)
           << ":time=" << op->getSeqNum().getTime()
           << ":order=" << op->getSeqNum().getOrder()
           << ":parent=" << names.block(op->getParent());
    slot += 1;
  }
  result << ']';
  return result.str();
}

bool reciprocal(const FlowBlock *block,bool outgoing)
{
  const std::vector<BlockEdge> &edges = outgoing ? block->outofthis : block->intothis;
  for(int4 slot=0;slot<edges.size();++slot) {
    const BlockEdge &edge = edges[slot];
    if (edge.reverse_index < 0) return false;
    const std::vector<BlockEdge> &reverse = outgoing
        ? edge.point->intothis : edge.point->outofthis;
    if (edge.reverse_index >= reverse.size()) return false;
    const BlockEdge &other = reverse[edge.reverse_index];
    if (other.point != block || other.reverse_index != slot || other.label != edge.label)
      return false;
  }
  return true;
}

std::string blockState(const FlowBlock *block,const Names &names,bool includeCopyMap)
{
  std::ostringstream result;
  result << "type=" << FlowBlock::typeToName(block->getType())
         << ",index=" << block->index
         << ",flags=" << block->flags
         << ",visit=" << block->visitcount
         << ",numdesc=" << block->numdesc
         << ",idom=" << names.block(block->immed_dom);
  if (includeCopyMap)
    result << ",copymap=" << names.block(block->copymap);
  result << ",in=" << edgeList(block,false,names)
         << ",out=" << edgeList(block,true,names)
         << ",in_ok=" << (reciprocal(block,false) ? 1 : 0)
         << ",out_ok=" << (reciprocal(block,true) ? 1 : 0);
  return result.str();
}

std::string listState(const BlockGraph &graph,const Names &names)
{
  std::ostringstream result;
  result << '[';
  for(int4 i=0;i<graph.list.size();++i) {
    if (i != 0) result << ',';
    result << names.block(graph.list[i]);
  }
  result << ']';
  return result.str();
}

void observeCopy(const std::string &caseName,const std::string &phase,
                 BlockCopy *copy,const Names &names)
{
  std::cout << "case=" << caseName << "|phase=" << phase
            << "|block=" << names.block(copy)
            << '|' << blockState(copy,names,false)
            << ",sub0=" << names.block(copy->subBlock(0))
            << ",sub7=" << names.block(copy->subBlock(7))
            << "\n";
}

void incomingOrder62(void)
{
  BlockGraph source;
  Names names;
  names.block(&source,"source_graph");
  std::vector<BlockBasic *> original;
  for(int4 i=0;i<8;++i) {
    BlockBasic *block = source.newBlockBasic((Funcdata *)0);
    original.push_back(block);
    names.block(block,"s" + std::to_string(i));
  }

  const int4 indices[8] = {70,11,52,34,26,63,45,18};
  const uint4 flags[8] = {
    FlowBlock::f_entry_point | FlowBlock::f_mark,
    FlowBlock::f_duplicate_block,
    FlowBlock::f_joined_block | FlowBlock::f_mark2,
    FlowBlock::f_label_bumpup,
    FlowBlock::f_unstructured_targ,
    FlowBlock::f_donothing_loop,
    FlowBlock::f_interior_gotoout,
    FlowBlock::f_interior_gotoin
  };
  FlowBlock *idoms[8] = {
    (FlowBlock *)0,original[0],original[0],original[1],
    original[2],original[2],original[0],original[6]
  };
  for(int4 i=0;i<8;++i)
    setState(original[i],indices[i],90+i,300+i,flags[i],idoms[i]);
  source.index = 11;

  // Target s4 deliberately receives s6 before s2 although s2 precedes s6
  // in source.list.  A source-major edge reconstruction changes this order.
  addLabeledEdge(source,original[6],original[4],0x81);
  addLabeledEdge(source,original[2],original[4],0x102);
  addLabeledEdge(source,original[0],original[1],0x10);
  addLabeledEdge(source,original[1],original[3],0x21);
  addLabeledEdge(source,original[1],original[5],0x42);
  addLabeledEdge(source,original[1],original[6],0x84);
  addLabeledEdge(source,original[1],original[7],0x108);
  addLabeledEdge(source,original[7],original[5],0x49);

  BlockGraph target;
  names.block(&target,"target_graph");
  target.buildCopy(source);
  std::vector<BlockCopy *> copies;
  for(int4 i=0;i<target.list.size();++i) {
    BlockCopy *copy = dynamic_cast<BlockCopy *>(target.list[i]);
    copies.push_back(copy);
    names.block(copy,"c" + std::to_string(i));
  }

  std::cout << "case=incoming_order_6_2|phase=graph|source_list="
            << listState(source,names) << "|target_list=" << listState(target,names)
            << "|source_index=" << source.index << "|target_index=" << target.index << "\n";
  for(int4 i=0;i<original.size();++i) {
    std::cout << "case=incoming_order_6_2|phase=source|block=s" << i
              << '|' << blockState(original[i],names,true) << "\n";
  }
  for(int4 i=0;i<copies.size();++i)
    observeCopy("incoming_order_6_2","copy",copies[i],names);
}

void appendPrefixUntouched(void)
{
  BlockGraph source;
  Names names;
  names.block(&source,"source_graph");
  std::vector<BlockBasic *> original;
  for(int4 i=0;i<3;++i) {
    BlockBasic *block = source.newBlockBasic((Funcdata *)0);
    original.push_back(block);
    names.block(block,"s" + std::to_string(i));
  }
  setState(original[0],31,41,51,FlowBlock::f_entry_point,(FlowBlock *)0);
  setState(original[1],32,42,52,FlowBlock::f_mark,original[0]);
  setState(original[2],33,43,53,FlowBlock::f_duplicate_block,original[1]);
  source.index = 31;
  addLabeledEdge(source,original[2],original[1],0x62);
  addLabeledEdge(source,original[0],original[2],0x23);

  BlockGraph target;
  names.block(&target,"target_graph");
  BlockBasic *p0 = target.newBlockBasic((Funcdata *)0);
  BlockBasic *p1 = target.newBlockBasic((Funcdata *)0);
  names.block(p0,"p0");
  names.block(p1,"p1");
  setState(p0,901,71,81,FlowBlock::f_joined_block,(FlowBlock *)0);
  setState(p1,902,72,82,FlowBlock::f_label_bumpup,p0);
  p0->copymap = p1;
  p1->copymap = p0;
  target.index = 901;
  addLabeledEdge(target,p1,p0,0x141);

  std::cout << "case=append_prefix_untouched|phase=before|target_list="
            << listState(target,names) << "\n";
  std::cout << "case=append_prefix_untouched|phase=prefix_before|block=p0|"
            << blockState(p0,names,true) << "\n";
  std::cout << "case=append_prefix_untouched|phase=prefix_before|block=p1|"
            << blockState(p1,names,true) << "\n";

  target.buildCopy(source);
  std::vector<BlockCopy *> copies;
  for(int4 i=0;i<original.size();++i) {
    BlockCopy *copy = dynamic_cast<BlockCopy *>(target.list[i+2]);
    copies.push_back(copy);
    names.block(copy,"c" + std::to_string(i));
  }

  std::cout << "case=append_prefix_untouched|phase=after|target_list="
            << listState(target,names) << "|target_index=" << target.index << "\n";
  std::cout << "case=append_prefix_untouched|phase=prefix_after|block=p0|"
            << blockState(p0,names,true) << "\n";
  std::cout << "case=append_prefix_untouched|phase=prefix_after|block=p1|"
            << blockState(p1,names,true) << "\n";
  for(int4 i=0;i<original.size();++i) {
    std::cout << "case=append_prefix_untouched|phase=source|block=s" << i
              << '|' << blockState(original[i],names,true) << "\n";
  }
  for(int4 i=0;i<copies.size();++i)
    observeCopy("append_prefix_untouched","copy",copies[i],names);
}

void liveDelegate(void)
{
  PcodeOp op0(0,SeqNum());
  PcodeOp op1(0,SeqNum());
  PcodeOp op2(0,SeqNum());
  Names names;
  names.op(&op0,"op0");
  names.op(&op1,"op1");
  names.op(&op2,"op2");

  BlockGraph source;
  names.block(&source,"source_graph");
  ProbeBasic *probe = new ProbeBasic();
  source.addBlock(probe);
  BlockBasic *split = new BlockBasic((Funcdata *)0);
  source.addBlock(split);
  names.block(probe,"s0");
  names.block(split,"s1");
  setState(probe,401,99,77,FlowBlock::f_mark,split);
  setState(split,402,98,76,FlowBlock::f_duplicate_block,probe);
  source.index = 401;
  probe->firstToken = &op0;
  probe->lastToken = &op1;
  probe->splitToken = split;
  probe->complexToken = false;

  BlockGraph target;
  names.block(&target,"target_graph");
  target.buildCopy(source);
  BlockCopy *copy = dynamic_cast<BlockCopy *>(target.list[0]);
  BlockCopy *splitCopy = dynamic_cast<BlockCopy *>(target.list[1]);
  names.block(copy,"c0");
  names.block(splitCopy,"c1");

  std::cout << "case=live_delegate|phase=before|block=c0"
            << "|type=" << FlowBlock::typeToName(copy->getType())
            << "|sub0=" << names.block(copy->subBlock(0))
            << "|sub7=" << names.block(copy->subBlock(7))
            << "|exit_self=" << (copy->getExitLeaf() == copy ? 1 : 0)
            << "|first=" << names.op(copy->firstOp())
            << "|last=" << names.op(copy->lastOp())
            << "|complex=" << (copy->isComplex() ? 1 : 0)
            << "|split=" << names.block(copy->getSplitPoint()) << "\n";

  probe->firstToken = &op2;
  probe->lastToken = &op2;
  probe->splitToken = (FlowBlock *)0;
  probe->complexToken = true;
  std::cout << "case=live_delegate|phase=after|block=c0"
            << "|type=" << FlowBlock::typeToName(copy->getType())
            << "|sub0=" << names.block(copy->subBlock(0))
            << "|sub7=" << names.block(copy->subBlock(7))
            << "|exit_self=" << (copy->getExitLeaf() == copy ? 1 : 0)
            << "|first=" << names.op(copy->firstOp())
            << "|last=" << names.op(copy->lastOp())
            << "|complex=" << (copy->isComplex() ? 1 : 0)
            << "|split=" << names.block(copy->getSplitPoint()) << "\n";
}

void blockBasicInsertEnd(void)
{
  TypeOpCopy copyType((TypeFactory *)0);
  TypeOpBranchind branchindType((TypeFactory *)0);
  PcodeOp op0(0,SeqNum(Address(),10));
  PcodeOp op1(0,SeqNum(Address(),11));
  PcodeOp op2(0,SeqNum(Address(),12));
  op0.setOpcode(&copyType);
  op1.setOpcode(&copyType);
  op2.setOpcode(&branchindType);

  BlockGraph graph;
  Names names;
  BlockBasic *block = graph.newBlockBasic((Funcdata *)0);
  names.block(block,"s0");
  names.op(&op0,"op0");
  names.op(&op1,"op1");
  names.op(&op2,"op2");

  std::cout << "case=blockbasic_insert_end|phase=before|block=s0|ops="
            << opList(block,names) << "|flags=" << block->getFlags() << "\n";
  block->insert(block->endOp(),&op0);
  block->insert(block->endOp(),&op1);
  block->insert(block->endOp(),&op2);
  std::cout << "case=blockbasic_insert_end|phase=after|block=s0|ops="
            << opList(block,names)
            << "|flags=" << block->getFlags()
            << "|switch_out=" << ((block->getFlags() & FlowBlock::f_switch_out) != 0 ? 1 : 0)
            << "|last=" << names.op(block->lastOp()) << "\n";
}

void observeParallelRemove(const char *phase,BlockBasic *source,BlockBasic *target,
                           const Names &names)
{
  std::cout << "case=parallel_remove_after_swap|phase=" << phase
            << "|src_out=" << slottedEdgeList(source,true,names)
            << "|dst_in=" << slottedEdgeList(target,false,names)
            << "|src_flags=" << source->getFlags()
            << "|src_ok=" << (reciprocal(source,true) ? 1 : 0)
            << "|dst_ok=" << (reciprocal(target,false) ? 1 : 0) << "\n";
}

void parallelRemoveAfterSwap(void)
{
  BlockGraph graph;
  Names names;
  BlockBasic *source = graph.newBlockBasic((Funcdata *)0);
  BlockBasic *target = graph.newBlockBasic((Funcdata *)0);
  names.block(source,"s0");
  names.block(target,"d0");
  addLabeledEdge(graph,source,target,0x31);
  addLabeledEdge(graph,source,target,0x62);

  observeParallelRemove("before",source,target,names);
  source->swapEdges();
  observeParallelRemove("swapped",source,target,names);
  graph.removeEdge(source,target);
  observeParallelRemove("removed",source,target,names);
}

} // anonymous namespace

int main(void)
{
  std::cout << "schema=1|fixture=BLOCK-BUILDCOPY-STATE-0001"
            << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
            << "|overall=MISMATCH|covered_projection=MATCH\n";
  incomingOrder62();
  appendPrefixUntouched();
  liveDelegate();
  blockBasicInsertEnd();
  parallelRemoveAfterSwap();
  return 0;
}
