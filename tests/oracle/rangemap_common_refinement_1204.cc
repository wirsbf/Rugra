/*
 * Locked Ghidra 12.0.4 rangemap<> oracle for
 * RANGEMAP-COMMON-REFINEMENT-0001.
 *
 * This fixture exercises the template directly.  The observable is the
 * record identity sequence produced by the public iterators, so duplicate
 * visits expose the common-refinement partitions without inspecting private
 * AddrRange state.
 */

#include "rangemap.hh"

#include <iostream>
#include <sstream>
#include <string>

namespace {

using namespace ghidra;
using std::string;

class TestRecord {
public:
  class Subsort {
    int value;
  public:
    Subsort(void) : value(0) {}
    explicit Subsort(int val) : value(val) {}
    explicit Subsort(bool latest) : value(latest ? 1000000 : 0) {}
    bool operator<(const Subsort &other) const { return value < other.value; }
  };

  struct InitData {
    string name;
    int subsort;
    InitData(const string &nm, int sub) : name(nm), subsort(sub) {}
  };

  typedef unsigned long long linetype;
  typedef Subsort subsorttype;
  typedef InitData inittype;

private:
  string name;
  linetype first;
  linetype last;
  Subsort subsort;

public:
  TestRecord(const InitData &data, linetype a, linetype b)
    : name(data.name), first(a), last(b), subsort(data.subsort) {}
  linetype getFirst(void) const { return first; }
  linetype getLast(void) const { return last; }
  Subsort getSubsort(void) const { return subsort; }
  const string &getName(void) const { return name; }
};

typedef rangemap<TestRecord> TestMap;

string names(TestMap::const_iterator iter, TestMap::const_iterator end)
{
  std::ostringstream out;
  bool first = true;
  while (iter != end) {
    if (!first) out << ',';
    first = false;
    out << (*iter).getName();
    ++iter;
  }
  return out.str();
}

string listNames(const TestMap &map)
{
  std::ostringstream out;
  bool first = true;
  for (std::list<TestRecord>::const_iterator iter = map.begin_list();
       iter != map.end_list(); ++iter) {
    if (!first) out << ',';
    first = false;
    out << iter->getName();
  }
  return out.str();
}

void dumpFind(const string &label, const TestMap &map,
              TestRecord::linetype point)
{
  std::pair<TestMap::const_iterator, TestMap::const_iterator> result =
      map.find(point);
  std::cout << "case=" << label << "|find=" << point
            << "|records=" << names(result.first, result.second) << '\n';
}

void dumpFindSubsort(const string &label, const TestMap &map,
                     TestRecord::linetype point, int low, int high)
{
  std::pair<TestMap::const_iterator, TestMap::const_iterator> result =
      map.find(point, TestRecord::Subsort(low), TestRecord::Subsort(high));
  std::cout << "case=" << label << "|find_sub=" << point << ':' << low
            << ':' << high << "|records="
            << names(result.first, result.second) << '\n';
}

void dumpWalk(const string &label, const TestMap &map)
{
  std::cout << "case=" << label << "|walk="
            << names(map.begin(), map.end()) << "|list=" << listNames(map)
            << '\n';
}

void dumpOverlap(const string &label, const TestMap &map,
                 TestRecord::linetype point, TestRecord::linetype end)
{
  TestMap::const_iterator iter = map.find_overlap(point, end);
  std::cout << "case=" << label << "|overlap=" << point << ':' << end
            << "|record=";
  if (iter == map.end()) std::cout << "null";
  else std::cout << (*iter).getName();
  std::cout << '\n';
}

void dumpCursor(const string &label, const TestMap &map,
                TestMap::const_iterator cursor)
{
  std::cout << "case=" << label << "|cursor=";
  if (cursor == map.end()) std::cout << "end";
  else std::cout << (*cursor).getName();
  std::cout << '\n';
}

void equalRangeCases(void)
{
  TestMap map;
  map.insert(TestRecord::InitData("eq_a", 5), 10, 20);
  dumpWalk("equal_after_a", map);
  map.insert(TestRecord::InitData("eq_b", 5), 10, 20);
  dumpWalk("equal_after_b", map);
  map.insert(TestRecord::InitData("sub_hi", 9), 10, 20);
  dumpWalk("equal_after_hi", map);
  map.insert(TestRecord::InitData("sub_lo", 1), 10, 20);
  dumpWalk("equal_after_lo", map);
  dumpFind("equal_range", map, 15);
  dumpFindSubsort("equal_subsort_window", map, 15, 5, 5);
  dumpWalk("equal_ordered_walk", map);
}

void wideNarrowCases(void)
{
  TestMap wideFirst;
  wideFirst.insert(TestRecord::InitData("wide", 5), 100, 140);
  wideFirst.insert(TestRecord::InitData("narrow", 2), 110, 120);
  dumpFind("wide_first_left", wideFirst, 105);
  dumpFind("wide_first_middle", wideFirst, 115);
  dumpFind("wide_first_right", wideFirst, 130);
  dumpWalk("wide_first_walk", wideFirst);

  TestMap narrowFirst;
  narrowFirst.insert(TestRecord::InitData("narrow", 2), 110, 120);
  narrowFirst.insert(TestRecord::InitData("wide", 5), 100, 140);
  dumpFind("narrow_first_left", narrowFirst, 105);
  dumpFind("narrow_first_middle", narrowFirst, 115);
  dumpFind("narrow_first_right", narrowFirst, 130);
  dumpWalk("narrow_first_walk", narrowFirst);
}

void splitEraseCases(void)
{
  TestMap map;
  map.insert(TestRecord::InitData("outer", 5), 200, 240);
  std::list<TestRecord>::iterator inner = map.insert(
      TestRecord::InitData("inner", 3), 210, 230);
  std::list<TestRecord>::iterator right = map.insert(
      TestRecord::InitData("right", 7), 220, 250);
  dumpWalk("split_before_erase", map);
  dumpFind("split_three_way", map, 225);

  map.erase(inner);
  dumpWalk("erase_inner_zip_left", map);
  dumpFind("erase_inner_middle", map, 215);
  dumpFind("erase_inner_overlap", map, 225);

  map.erase(right);
  dumpWalk("erase_right_zip_both", map);
  dumpFind("erase_right_outer", map, 225);
}

void overlapAndRangeWalkCases(void)
{
  TestMap map;
  map.insert(TestRecord::InitData("left", 4), 300, 305);
  map.insert(TestRecord::InitData("right_hi", 8), 310, 320);
  map.insert(TestRecord::InitData("right_lo", 2), 310, 315);
  dumpOverlap("gap_hit", map, 306, 312);
  dumpOverlap("gap_miss", map, 306, 309);
  dumpOverlap("inside_order", map, 312, 312);
  std::cout << "case=bounded_walk|range=304:316|records="
            << names(map.find_begin(304), map.find_end(316)) << '\n';
}

void equivalentSplitCases(void)
{
  TestMap map;
  map.insert(TestRecord::InitData("same_a", 5), 400, 440);
  std::list<TestRecord>::iterator sameB = map.insert(
      TestRecord::InitData("same_b", 5), 400, 440);
  std::list<TestRecord>::iterator cut = map.insert(
      TestRecord::InitData("cut", 5), 410, 420);
  dumpWalk("equivalent_split", map);
  dumpFind("equivalent_split_middle", map, 415);
  map.erase(cut);
  dumpWalk("equivalent_erase_cut", map);
  map.erase(sameB);
  dumpWalk("equivalent_erase_peer", map);
}

void stableCursorCases(void)
{
  TestMap before;
  before.insert(TestRecord::InitData("A", 5), 100, 110);
  TestMap::const_iterator beforeCursor = before.find_begin(100);
  dumpCursor("cursor_insert_before_initial", before, beforeCursor);
  before.insert(TestRecord::InitData("B", 5), 50, 60);
  dumpCursor("cursor_insert_before_after", before, beforeCursor);
  before.erase(beforeCursor);
  dumpWalk("cursor_insert_before_erase", before);

  TestMap after;
  after.insert(TestRecord::InitData("A", 5), 100, 110);
  TestMap::const_iterator afterCursor = after.find_begin(100);
  after.insert(TestRecord::InitData("C", 5), 150, 160);
  dumpCursor("cursor_insert_after", after, afterCursor);
  after.erase(afterCursor);
  dumpWalk("cursor_insert_after_erase", after);

  TestMap equivalent;
  equivalent.insert(TestRecord::InitData("eq_a", 5), 10, 20);
  TestMap::const_iterator equivalentCursor = equivalent.find_begin(15);
  equivalent.insert(TestRecord::InitData("eq_b", 5), 10, 20);
  dumpCursor("cursor_equivalent_after", equivalent, equivalentCursor);
  equivalent.erase(equivalentCursor);
  dumpWalk("cursor_equivalent_erase", equivalent);

  TestMap split;
  split.insert(TestRecord::InitData("wide", 5), 100, 140);
  TestMap::const_iterator splitCursor = split.find_begin(120);
  split.insert(TestRecord::InitData("narrow", 2), 110, 120);
  dumpCursor("cursor_unzip_after", split, splitCursor);
  split.erase(splitCursor);
  dumpWalk("cursor_unzip_erase", split);

  TestMap endMap;
  TestMap::const_iterator oldEnd = endMap.end();
  endMap.insert(TestRecord::InitData("only", 5), 1, 2);
  std::cout << "case=cursor_end_insert|same="
            << (oldEnd == endMap.end() ? 1 : 0) << '\n';
}

void cursorInvalidationMatrix(void)
{
  TestMap map;
  map.insert(TestRecord::InitData("outer", 5), 200, 240);
  std::list<TestRecord>::iterator innerRecord = map.insert(
      TestRecord::InitData("inner", 3), 210, 230);
  TestMap::const_iterator leftOuter = map.find_begin(205);
  std::pair<TestMap::const_iterator, TestMap::const_iterator> middle =
      map.find(220);
  TestMap::const_iterator innerMiddle = middle.first;
  TestMap::const_iterator middleOuter = innerMiddle;
  ++middleOuter;
  TestMap::const_iterator rightOuter = map.find_begin(235);
  TestMap::const_iterator oldEnd = map.end();

  std::cout << "case=cursor_matrix_before|left=" << (*leftOuter).getName()
            << "|inner=" << (*innerMiddle).getName()
            << "|middle=" << (*middleOuter).getName()
            << "|right=" << (*rightOuter).getName() << '\n';
  map.erase(innerRecord);
  // std::multiset::erase invalidates only erased elements.  erase(inner)
  // removes innerMiddle directly; zip(209) erases leftOuter; zip(230)
  // erases middleOuter; rightOuter is only extended in place and survives.
  std::cout << "case=cursor_matrix_after|left=invalid|inner=invalid"
            << "|middle=invalid|right=" << (*rightOuter).getName()
            << "|end_same=" << (oldEnd == map.end() ? 1 : 0) << '\n';
  map.erase(rightOuter);
  dumpWalk("cursor_matrix_right_erase", map);
}

} // anonymous namespace

int main(void)
{
  equalRangeCases();
  wideNarrowCases();
  splitEraseCases();
  overlapAndRangeWalkCases();
  equivalentSplitCases();
  stableCursorCases();
  cursorInvalidationMatrix();
  return 0;
}
