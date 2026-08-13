/*
 * SCOPE-CAT0-0001: locked Ghidra 12.0.4 ScopeInternal category oracle.
 *
 * This directly exercises getCategorySize(), getCategorySymbol(), and
 * setCategory().  TrackingSymbol also makes ScopeInternal's name-tree
 * ownership observable: category vectors hold non-owning pointers and a
 * symbol is destroyed exactly once by removeSymbol() or Scope destruction.
 */
#include "architecture.hh"
#include "database.hh"
#include "libdecomp.hh"
#include "type.hh"

#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

using namespace ghidra;
using std::map;
using std::string;
using std::vector;

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
  void printMessage(const string &) const override {}
};

class TrackingSymbol final : public Symbol {
public:
  static int4 destroyed;

  TrackingSymbol(Scope *scope,const string &name,Datatype *type)
    : Symbol(scope,name,type) {}

  ~TrackingSymbol(void) override { destroyed += 1; }
};

int4 TrackingSymbol::destroyed = 0;

class FixtureScope final : public ScopeInternal {
public:
  FixtureScope(uint8 id,const string &name,Architecture *architecture)
    : ScopeInternal(id,name,architecture) {}

  TrackingSymbol *addTracked(const string &name,Datatype *type) {
    TrackingSymbol *symbol = new TrackingSymbol(this,name,type);
    addSymbolInternal(symbol);
    return symbol;
  }

  int4 categoryOuterSize(void) const { return category.size(); }
};

struct Aliases {
  map<string,TrackingSymbol *> byName;

  void add(const string &name,TrackingSymbol *symbol) { byName[name] = symbol; }
  void erase(const string &name) { byName[name] = (TrackingSymbol *)0; }

  string label(Symbol *symbol) const {
    if (symbol == (Symbol *)0) return "-";
    for(map<string,TrackingSymbol *>::const_iterator iter=byName.begin();
        iter!=byName.end();++iter) {
      if (iter->second == symbol) return iter->first;
    }
    return "!foreign";
  }
};

void writeSlots(const FixtureScope &scope,const Aliases &aliases,int4 category)
{
  std::cout << '[';
  int4 size = scope.getCategorySize(category);
  for(int4 index=0;index<size;++index) {
    if (index != 0) std::cout << ',';
    std::cout << aliases.label(scope.getCategorySymbol(category,index));
  }
  std::cout << ']';
}

void writeSymbols(const Aliases &aliases)
{
  std::cout << '[';
  bool first = true;
  for(map<string,TrackingSymbol *>::const_iterator iter=aliases.byName.begin();
      iter!=aliases.byName.end();++iter) {
    TrackingSymbol *symbol = iter->second;
    if (symbol == (TrackingSymbol *)0) continue;
    if (!first) std::cout << ',';
    std::cout << iter->first << ':' << symbol->getCategory()
              << '/' << symbol->getCategoryIndex();
    first = false;
  }
  std::cout << ']';
}

void writeOwned(const FixtureScope &scope,const Aliases &aliases)
{
  std::cout << '[';
  bool first = true;
  for(map<string,TrackingSymbol *>::const_iterator iter=aliases.byName.begin();
      iter!=aliases.byName.end();++iter) {
    vector<Symbol *> result;
    scope.findByName(iter->first,result);
    if (!first) std::cout << ',';
    std::cout << iter->first << ':' << result.size();
    first = false;
  }
  std::cout << ']';
}

void snapshot(const string &stage,const FixtureScope &scope,const Aliases &aliases)
{
  std::cout << "stage=" << stage
            << " outer=" << scope.categoryOuterSize()
            << " sizes=[" << scope.getCategorySize(-1)
            << ',' << scope.getCategorySize(0)
            << ',' << scope.getCategorySize(1)
            << ',' << scope.getCategorySize(2)
            << ',' << scope.getCategorySize(3)
            << ',' << scope.getCategorySize(99) << "] cat0=";
  writeSlots(scope,aliases,0);
  std::cout << " cat1=";
  writeSlots(scope,aliases,1);
  std::cout << " cat2=";
  writeSlots(scope,aliases,2);
  std::cout << " invalid=["
            << (scope.getCategorySymbol(-1,0) == (Symbol *)0) << ','
            << (scope.getCategorySymbol(0,-1) == (Symbol *)0) << ','
            << (scope.getCategorySymbol(99,0) == (Symbol *)0) << ','
            << (scope.getCategorySymbol(0,999) == (Symbol *)0) << "] symbols=";
  writeSymbols(aliases);
  std::cout << " owned=";
  writeOwned(scope,aliases);
  std::cout << " destroyed=" << TrackingSymbol::destroyed << '\n';
}

} // namespace

int main(void)
{
  Aliases aliases;
  vector<string> specPaths;
  startDecompilerLibrary(specPaths);

  {
    FixtureArchitecture architecture;
    TypeBase integerType(4,TYPE_INT,"fixture_i32");
    FixtureScope scope(0x1234,"fixture",&architecture);
    TrackingSymbol *a = scope.addTracked("a",&integerType);
    TrackingSymbol *b = scope.addTracked("b",&integerType);
    TrackingSymbol *c = scope.addTracked("c",&integerType);
    TrackingSymbol *d = scope.addTracked("d",&integerType);
    TrackingSymbol *e = scope.addTracked("e",&integerType);
    TrackingSymbol *f = scope.addTracked("f",&integerType);
    aliases.add("a",a);
    aliases.add("b",b);
    aliases.add("c",c);
    aliases.add("d",d);
    aliases.add("e",e);
    aliases.add("f",f);

    snapshot("initial",scope,aliases);

    scope.setCategory(a,Symbol::function_parameter,2);
    scope.setCategory(b,Symbol::function_parameter,0);
    scope.setCategory(c,Symbol::function_parameter,5);
    snapshot("cat0_holes",scope,aliases);
    std::cout << "identity=cat0:" << (scope.getCategorySymbol(0,2) == a)
              << (scope.getCategorySymbol(0,0) == b)
              << (scope.getCategorySymbol(0,5) == c) << '\n';

    scope.setCategory(d,Symbol::union_facet,99);
    scope.setCategory(e,Symbol::union_facet,0);
    snapshot("cat2_gap",scope,aliases);
    scope.setCategory(f,Symbol::equate,77);
    snapshot("higher_append",scope,aliases);

    scope.setCategory(a,Symbol::union_facet,123);
    snapshot("move_a_to_cat2",scope,aliases);

    scope.setCategory(d,Symbol::union_facet,999);
    snapshot("reappend_d_cat2",scope,aliases);

    scope.setCategory(e,Symbol::no_category,444);
    snapshot("uncategorize_e",scope,aliases);

    scope.setCategory(a,Symbol::function_parameter,1);
    snapshot("move_a_to_cat0",scope,aliases);

    scope.setCategory(b,Symbol::function_parameter,4);
    snapshot("move_b_within_cat0",scope,aliases);

    scope.removeSymbol(c);
    aliases.erase("c");
    snapshot("delete_c",scope,aliases);

    scope.removeSymbol(b);
    aliases.erase("b");
    snapshot("delete_b",scope,aliases);

    scope.setCategory(a,Symbol::no_category,-2);
    snapshot("uncategorize_a",scope,aliases);

    scope.removeSymbol(d);
    aliases.erase("d");
    scope.setCategory(f,Symbol::no_category,7);
    snapshot("empty_all_tables",scope,aliases);

    scope.setCategory(e,Symbol::function_parameter,1);
    scope.setCategory(f,Symbol::function_parameter,65537);
    snapshot("cat0_replace_wrapped_index",scope,aliases);
    std::cout << "identity=replace:"
              << (scope.getCategorySymbol(0,1) == f)
              << (scope.getCategorySymbol(0,1) == e) << '\n';

    scope.setCategory(f,Symbol::no_category,7);
    snapshot("replacement_removed",scope,aliases);
  }

  std::cout << "stage=scope_drop destroyed=" << TrackingSymbol::destroyed << '\n';
  shutdownDecompilerLibrary();
  return 0;
}
