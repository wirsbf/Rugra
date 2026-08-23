/*
 * BLOCK-HALFDELETE-REVIDX-0001 locked Ghidra 12.0.4 oracle.
 *
 * Directly exercises FlowBlock::halfDeleteInEdge/halfDeleteOutEdge on
 * production BlockBasic edge lists.  Test-only private access exposes the
 * two functions and the complete BlockEdge state without changing the
 * locked source.
 */
#include <bits/stdc++.h>

#define private public
#include "block.hh"
#undef private

namespace {

using namespace ghidra;

struct CaseGraph {
  BlockGraph graph;
  std::vector<BlockBasic *> blocks;

  BlockBasic *make(void)
  {
    BlockBasic *block = graph.newBlockBasic((Funcdata *)0);
    blocks.push_back(block);
    return block;
  }

  std::string name(const FlowBlock *block) const
  {
    for(int4 i=0;i<blocks.size();++i)
      if (blocks[i] == block) return "b" + std::to_string(i);
    return "?";
  }

  void edge(FlowBlock *source,FlowBlock *target,uint4 label)
  {
    int4 outSlot = source->outofthis.size();
    int4 inSlot = target->intothis.size();
    graph.addEdge(source,target);
    source->outofthis[outSlot].label = label;
    target->intothis[inSlot].label = label;
  }

  std::string edgeList(const FlowBlock *block,bool outgoing) const
  {
    const std::vector<BlockEdge> &edges = outgoing ? block->outofthis : block->intothis;
    std::ostringstream result;
    result << '[';
    for(int4 slot=0;slot<edges.size();++slot) {
      if (slot != 0) result << ',';
      result << name(edges[slot].point) << ':'
             << edges[slot].reverse_index << ':' << edges[slot].label;
    }
    result << ']';
    return result.str();
  }

  bool reciprocal(const FlowBlock *block,bool outgoing) const
  {
    const std::vector<BlockEdge> &edges = outgoing ? block->outofthis : block->intothis;
    for(int4 slot=0;slot<edges.size();++slot) {
      const BlockEdge &edge = edges[slot];
      if (edge.reverse_index < 0) return false;
      const std::vector<BlockEdge> &other = outgoing
          ? edge.point->intothis : edge.point->outofthis;
      if (edge.reverse_index >= other.size()) return false;
      const BlockEdge &reverse = other[edge.reverse_index];
      if (reverse.point != block || reverse.reverse_index != slot ||
          reverse.label != edge.label)
        return false;
    }
    return true;
  }

  void observe(const std::string &caseName,const std::string &phase,
               const FlowBlock *focus,
               const std::vector<std::string> &phi = std::vector<std::string>()) const
  {
    std::cout << "case=" << caseName << "|phase=" << phase << "|blocks=[";
    for(int4 i=0;i<blocks.size();++i) {
      if (i != 0) std::cout << ';';
      std::cout << name(blocks[i]) << "{in=" << edgeList(blocks[i],false)
                << ",out=" << edgeList(blocks[i],true) << '}';
    }
    std::cout << "]|focus_in_ok=" << (reciprocal(focus,false) ? 1 : 0)
              << "|focus_out_ok=" << (reciprocal(focus,true) ? 1 : 0)
              << "|phi=[";
    for(int4 slot=0;slot<phi.size();++slot) {
      if (slot != 0) std::cout << ',';
      std::cout << name(focus->intothis[slot].point) << ':' << phi[slot];
    }
    std::cout << "]\n";
  }
};

void inNonlastPhi(void)
{
  CaseGraph fixture;
  BlockBasic *s0=fixture.make(), *s1=fixture.make(), *s2=fixture.make();
  BlockBasic *s3=fixture.make(), *target=fixture.make();
  fixture.edge(s0,target,10);
  fixture.edge(s1,target,20);
  fixture.edge(s2,target,30);
  fixture.edge(s3,target,40);
  std::vector<std::string> phi{"v0","v1","v2","v3"};
  fixture.observe("in_nonlast_phi","before",target,phi);
  target->halfDeleteInEdge(1);
  phi.erase(phi.begin()+1);
  fixture.observe("in_nonlast_phi","after",target,phi);
}

void outNonlastOrdered(void)
{
  CaseGraph fixture;
  BlockBasic *source=fixture.make(), *t0=fixture.make(), *t1=fixture.make();
  BlockBasic *t2=fixture.make(), *t3=fixture.make();
  fixture.edge(source,t0,11);
  fixture.edge(source,t1,21);
  fixture.edge(source,t2,31);
  fixture.edge(source,t3,41);
  fixture.observe("out_nonlast_ordered","before",source);
  source->halfDeleteOutEdge(1);
  fixture.observe("out_nonlast_ordered","after",source);
}

void consecutiveInPhi(void)
{
  CaseGraph fixture;
  BlockBasic *s0=fixture.make(), *s1=fixture.make(), *s2=fixture.make();
  BlockBasic *s3=fixture.make(), *s4=fixture.make(), *target=fixture.make();
  fixture.edge(s0,target,12);
  fixture.edge(s1,target,22);
  fixture.edge(s2,target,32);
  fixture.edge(s3,target,42);
  fixture.edge(s4,target,52);
  std::vector<std::string> phi{"p0","p1","p2","p3","p4"};
  fixture.observe("consecutive_in_phi","before",target,phi);
  target->halfDeleteInEdge(1);
  phi.erase(phi.begin()+1);
  fixture.observe("consecutive_in_phi","after_first",target,phi);
  target->halfDeleteInEdge(1);
  phi.erase(phi.begin()+1);
  fixture.observe("consecutive_in_phi","after_second",target,phi);
}

void selfParallelIn(void)
{
  CaseGraph fixture;
  BlockBasic *focus=fixture.make(), *left=fixture.make(), *right=fixture.make();
  fixture.edge(focus,focus,13);
  fixture.edge(left,focus,23);
  fixture.edge(focus,focus,33);
  fixture.edge(right,focus,43);
  fixture.observe("self_parallel_in","before",focus);
  focus->halfDeleteInEdge(0);
  fixture.observe("self_parallel_in","after",focus);
}

void selfParallelOut(void)
{
  CaseGraph fixture;
  BlockBasic *focus=fixture.make(), *left=fixture.make(), *right=fixture.make();
  fixture.edge(focus,focus,14);
  fixture.edge(focus,left,24);
  fixture.edge(focus,focus,34);
  fixture.edge(focus,right,44);
  fixture.observe("self_parallel_out","before",focus);
  focus->halfDeleteOutEdge(0);
  fixture.observe("self_parallel_out","after",focus);
}

void bidirectionalOrdered(void)
{
  CaseGraph fixture;
  BlockBasic *a=fixture.make(), *b=fixture.make(), *c=fixture.make();
  fixture.edge(a,b,15);
  fixture.edge(b,a,25);
  fixture.edge(a,c,35);
  fixture.edge(c,a,45);
  fixture.edge(a,b,55);
  fixture.edge(b,a,65);
  std::vector<std::string> phi{"ba0","ca","ba1"};
  fixture.observe("bidirectional_ordered","before",a,phi);
  a->halfDeleteInEdge(1);
  phi.erase(phi.begin()+1);
  fixture.observe("bidirectional_ordered","after_in",a,phi);
  a->halfDeleteOutEdge(1);
  fixture.observe("bidirectional_ordered","after_out",a,phi);
}

void validBoundarySlots(void)
{
  {
    CaseGraph fixture;
    BlockBasic *source=fixture.make(), *target=fixture.make();
    fixture.edge(source,target,16);
    fixture.observe("single_out_slot","before",source);
    source->halfDeleteOutEdge(0);
    fixture.observe("single_out_slot","after",source);
  }
  {
    CaseGraph fixture;
    BlockBasic *s0=fixture.make(), *s1=fixture.make(), *target=fixture.make();
    fixture.edge(s0,target,26);
    fixture.edge(s1,target,36);
    std::vector<std::string> phi{"q0","q1"};
    fixture.observe("last_in_slot","before",target,phi);
    target->halfDeleteInEdge(1);
    phi.pop_back();
    fixture.observe("last_in_slot","after",target,phi);
  }
}

} // anonymous namespace

int main(void)
{
  std::cout << "schema=1|fixture=BLOCK-HALFDELETE-REVIDX-0001"
            << "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b\n";
  inNonlastPhi();
  outNonlastOrdered();
  consecutiveInPhi();
  selfParallelIn();
  selfParallelOut();
  bidirectionalOrdered();
  validBoundarySlots();
  return 0;
}
