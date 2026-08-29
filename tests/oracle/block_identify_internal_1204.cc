/*
 * BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001 locked Ghidra 12.0.4 oracle.
 *
 * Directly exercises BlockGraph::identifyInternal + selfIdentify + dedup
 * (block.cc:940-963 / 895-931 / 525-539) through the public factory
 * BlockGraph::newBlockList (block.cc:1758-1774).  Observed state: composite
 * children order, component parent ownership, raw block flags (components
 * are NEVER f_dead), inherited boundary edge slots/labels/reverse indices
 * on the composite, retargeted peer halves, parallel-edge dedup label
 * merge, FlowBlock::f_switch_out / f_interior_goto* flag propagation, and internal
 * (component-to-component) edge retention.
 *
 * Top-level list positions are normalized to sorted membership: Ghidra
 * appends the composite at the end of the graph list (block.cc:1695),
 * Rugra installs it at the first component's slot — a registered model
 * divergence outside this fixture's covered projection.  Every other
 * observation is printed raw.
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
public:
  void add(const FlowBlock *ptr,const std::string &name) { blocks[ptr] = name; }

  std::string block(const FlowBlock *ptr) const
  {
    if (ptr == (const FlowBlock *)0) return "null";
    std::map<const FlowBlock *,std::string>::const_iterator iter = blocks.find(ptr);
    return iter == blocks.end() ? "?" : iter->second;
  }

  std::string parent(const FlowBlock *ptr) const { return block(ptr->getParent()); }

  std::string sortedMembers(const std::vector<FlowBlock *> &list) const
  {
    std::vector<std::string> names;
    for(int4 i=0;i<list.size();++i)
      names.push_back(block(list[i]));
    std::sort(names.begin(),names.end());
    std::ostringstream result;
    result << '[';
    for(int4 i=0;i<names.size();++i) {
      if (i != 0) result << ',';
      result << names[i];
    }
    result << ']';
    return result.str();
  }
};

void setIndex(FlowBlock *bl,int4 index)
{
  bl->index = index;
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

// Reciprocal-consistency check mirroring FlowBlock::checkEdges
// (block.cc:545-570) without the BLOCKCONSISTENT_DEBUG guard.
bool edgesConsistent(const FlowBlock *bl)
{
  for(int4 i=0;i<bl->intothis.size();++i) {
    const BlockEdge &edge(bl->intothis[i]);
    int4 rev = edge.reverse_index;
    const FlowBlock *peer = edge.point;
    if (rev < 0 || peer->outofthis.size() <= rev) return false;
    if (peer->outofthis[rev].point != bl) return false;
    if (peer->outofthis[rev].reverse_index != i) return false;
  }
  for(int4 i=0;i<bl->outofthis.size();++i) {
    const BlockEdge &edge(bl->outofthis[i]);
    int4 rev = edge.reverse_index;
    const FlowBlock *peer = edge.point;
    if (rev < 0 || peer->intothis.size() <= rev) return false;
    if (peer->intothis[rev].point != bl) return false;
    if (peer->intothis[rev].reverse_index != i) return false;
  }
  return true;
}

// Case 1: plain cat identify. P -> A -> B -> C -> Q, plus an external
// in-edge P -> A with label, consumed set {A,B}.
void caseCatBasic()
{
  BlockGraph g;
  FlowBlock *P = g.newBlock();
  FlowBlock *A = g.newBlock();
  FlowBlock *B = g.newBlock();
  FlowBlock *C = g.newBlock();
  FlowBlock *Q = g.newBlock();
  setIndex(P,0); setIndex(A,1); setIndex(B,2); setIndex(C,3); setIndex(Q,4);

  addLabeledEdge(g,P,A,0x21);
  addLabeledEdge(g,A,B,0x0);
  addLabeledEdge(g,B,C,0x0);
  addLabeledEdge(g,C,Q,0x42);

  Names names;
  names.add(P,"P"); names.add(A,"A"); names.add(B,"B"); names.add(C,"C"); names.add(Q,"Q");
  names.add((const FlowBlock *)&g,"G");	// top-level blocks' parent (addBlock, block.cc:873)

  std::vector<FlowBlock *> nodes;
  nodes.push_back(A);
  nodes.push_back(B);
  FlowBlock *W = g.newBlockList(nodes);
  names.add(W,"W");

  std::cout << "case=cat_basic|top_members=" << names.sortedMembers(g.getList())
            << "|graph_size=" << g.getSize()
            << "|w_index=" << W->getIndex()
            << "|w_children=" << names.sortedMembers(((BlockGraph *)W)->getList())
            << "|parent_A=" << names.parent(A)
            << "|parent_B=" << names.parent(B)
            << "|parent_P=" << names.parent(P)
            << "|flags_A=" << std::hex << A->flags
            << "|flags_B=" << B->flags
            << "|flags_W=" << W->flags
            << "|dead_A=" << ((A->flags & FlowBlock::f_dead) != 0)
            << "|dead_B=" << ((B->flags & FlowBlock::f_dead) != 0)
            << "|w_in=" << edgeList(W,false,names)
            << "|w_out=" << edgeList(W,true,names)
            << "|a_in=" << edgeList(A,false,names)
            << "|a_out=" << edgeList(A,true,names)
            << "|b_in=" << edgeList(B,false,names)
            << "|b_out=" << edgeList(B,true,names)
            << "|p_out=" << edgeList(P,true,names)
            << "|c_in=" << edgeList(C,false,names)
            << "|c_out=" << edgeList(C,true,names)
            << "|q_in=" << edgeList(Q,false,names)
            << "|consistent_W=" << edgesConsistent(W)
            << "|consistent_P=" << edgesConsistent(P)
            << "|consistent_C=" << edgesConsistent(C)
            << "|consistent_A=" << edgesConsistent(A)
            << "|consistent_B=" << edgesConsistent(B)
            << std::dec << std::endl;
}

// Case 2: parallel boundary edges through one peer; selfIdentify's final
// dedup (block.cc:930) must merge the composite's duplicate halves, keep the
// FIRST slot, OR the labels (block.cc:488 eliminateOutDups), and remove the
// peer's mirrored duplicate half.
void caseParallelDedup()
{
  BlockGraph g;
  FlowBlock *P = g.newBlock();
  FlowBlock *A = g.newBlock();
  FlowBlock *B = g.newBlock();
  FlowBlock *M = g.newBlock();
  setIndex(P,0); setIndex(A,1); setIndex(B,2); setIndex(M,3);

  addLabeledEdge(g,P,A,0x1);
  addLabeledEdge(g,A,B,0x0);
  addLabeledEdge(g,A,M,0x5);
  addLabeledEdge(g,B,M,0x9);

  Names names;
  names.add(P,"P"); names.add(A,"A"); names.add(B,"B"); names.add(M,"M");
  names.add((const FlowBlock *)&g,"G");

  std::vector<FlowBlock *> nodes;
  nodes.push_back(A);
  nodes.push_back(B);
  FlowBlock *W = g.newBlockList(nodes);
  names.add(W,"W");

  std::cout << "case=parallel_dedup|w_children=" << names.sortedMembers(((BlockGraph *)W)->getList())
            << "|parent_A=" << names.parent(A)
            << "|parent_B=" << names.parent(B)
            << "|dead_A=" << ((A->flags & FlowBlock::f_dead) != 0)
            << "|dead_B=" << ((B->flags & FlowBlock::f_dead) != 0)
            << "|w_in=" << edgeList(W,false,names)
            << "|w_out=" << edgeList(W,true,names)
            << "|m_in=" << edgeList(M,false,names)
            << "|a_out=" << edgeList(A,true,names)
            << "|b_out=" << edgeList(B,true,names)
            << "|consistent_W=" << edgesConsistent(W)
            << "|consistent_M=" << edgesConsistent(M)
            << std::endl;
}

// Case 3: flag propagation. f_switch_out propagates from a component that
// has an EXTERNAL out edge (selfIdentify block.cc:925-926), but not from a
// fully internal switch-out component; f_interior_gotoout/f_interior_gotoin
// OR-accumulate from every component (identifyInternal block.cc:951).
void caseFlagPropagation()
{
  BlockGraph g;
  FlowBlock *P = g.newBlock();
  FlowBlock *A = g.newBlock();	// switch-out WITH external out edge
  FlowBlock *B = g.newBlock();	// switch-out, external in edge only
  FlowBlock *S = g.newBlock();	// interior goto marks
  FlowBlock *X = g.newBlock();
  FlowBlock *Y = g.newBlock();
  setIndex(P,0); setIndex(A,1); setIndex(B,2); setIndex(S,3); setIndex(X,4); setIndex(Y,5);

  addLabeledEdge(g,P,A,0x0);
  addLabeledEdge(g,A,X,0x0);	// A external out
  addLabeledEdge(g,Y,B,0x0);	// B external in
  addLabeledEdge(g,A,B,0x0);	// internal chain
  addLabeledEdge(g,B,S,0x0);

  A->flags |= FlowBlock::f_switch_out;
  B->flags |= FlowBlock::f_switch_out;	// must NOT propagate (no external out)
  S->flags |= FlowBlock::f_interior_gotoout;
  B->flags |= FlowBlock::f_interior_gotoin;

  Names names;
  names.add(P,"P"); names.add(A,"A"); names.add(B,"B"); names.add(S,"S");
  names.add(X,"X"); names.add(Y,"Y");

  std::vector<FlowBlock *> nodes;
  nodes.push_back(A);
  nodes.push_back(B);
  nodes.push_back(S);
  FlowBlock *W = g.newBlockList(nodes);
  names.add(W,"W");

  std::cout << "case=flag_propagation|flags_W=" << std::hex << W->flags << std::dec
            << "|switch_out_W=" << ((W->flags & FlowBlock::f_switch_out) != 0)
            << "|interior_gotoout_W=" << ((W->flags & FlowBlock::f_interior_gotoout) != 0)
            << "|interior_gotoin_W=" << ((W->flags & FlowBlock::f_interior_gotoin) != 0)
            << "|dead_S=" << ((S->flags & FlowBlock::f_dead) != 0)
            << "|parent_S=" << names.parent(S)
            << "|w_out=" << edgeList(W,true,names)
            << "|w_in=" << edgeList(W,false,names)
            << "|consistent_W=" << edgesConsistent(W)
            << "|consistent_X=" << edgesConsistent(X)
            << "|consistent_Y=" << edgesConsistent(Y)
            << std::endl;
}

// Case 4: self edge inside the consumed set stays a component-internal edge
// and is never inherited by the composite.
void caseSelfEdgeInternal()
{
  BlockGraph g;
  FlowBlock *A = g.newBlock();
  FlowBlock *B = g.newBlock();
  FlowBlock *C = g.newBlock();
  setIndex(A,0); setIndex(B,1); setIndex(C,2);

  addLabeledEdge(g,A,A,0x0);	// self loop within the component set
  addLabeledEdge(g,A,B,0x0);
  addLabeledEdge(g,B,C,0x7);

  Names names;
  names.add(A,"A"); names.add(B,"B"); names.add(C,"C");

  std::vector<FlowBlock *> nodes;
  nodes.push_back(A);
  nodes.push_back(B);
  FlowBlock *W = g.newBlockList(nodes);
  names.add(W,"W");

  std::cout << "case=self_edge_internal|a_in=" << edgeList(A,false,names)
            << "|a_out=" << edgeList(A,true,names)
            << "|w_in=" << edgeList(W,false,names)
            << "|w_out=" << edgeList(W,true,names)
            << "|dead_A=" << ((A->flags & FlowBlock::f_dead) != 0)
            << "|parent_A=" << names.parent(A)
            << "|consistent_A=" << edgesConsistent(A)
            << "|consistent_W=" << edgesConsistent(W)
            << std::endl;
}

} // namespace

int main(void)
{
  std::cout << "schema=1|fixture=BLOCKSTRUCT-IDENTIFY-BOUNDARY-0001"
               "|oracle=e40ed13014025f82488b1f8f7bca566894ac376b"
               "|overall=MISMATCH|covered_projection=MATCH" << std::endl;
  caseCatBasic();
  caseParallelDedup();
  caseFlagPropagation();
  caseSelfEdgeInternal();
  return 0;
}
