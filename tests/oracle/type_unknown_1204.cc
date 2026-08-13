/*
 * TYPE-UNKNOWN-0001: locked Ghidra 12.0.4 TypeFactory unknown-base oracle.
 */
#include "bfd_arch.hh"
#include "libdecomp.hh"
#include "type.hh"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ghidra;

void writeString(ostream &out,const string &value)
{
  out << '"';
  for(size_t i=0;i<value.size();++i) {
    unsigned char ch = static_cast<unsigned char>(value[i]);
    if (ch == '"' || ch == '\\') out << '\\' << static_cast<char>(ch);
    else if (ch == '\n') out << "\\n";
    else out << static_cast<char>(ch);
  }
  out << '"';
}

void writeType(ostream &out,int4 requestedSize,Datatype *type)
{
  string metatype;
  metatype2string(type->getMetatype(),metatype);
  out << "{\"requested_size\":" << requestedSize
      << ",\"size\":" << type->getSize()
      << ",\"metatype\":";
  writeString(out,metatype);
  out << ",\"name\":";
  writeString(out,type->getName());
  out << ",\"id\":" << type->getId()
      << ",\"flags\":" << type->getInheritable()
      << '}';
}

void writeAnonymousUnknownOrder(ostream &out,TypeFactory *factory)
{
  vector<Datatype *> ordered;
  factory->dependentOrder(ordered);
  bool first = true;
  out << '[';
  for(size_t i=0;i<ordered.size();++i) {
    Datatype *type = ordered[i];
    if (type->getMetatype() != TYPE_UNKNOWN || !type->getName().empty())
      continue;
    if (!first) out << ',';
    out << type->getSize();
    first = false;
  }
  out << ']';
}

void runFixture(const string &specDirectory,const string &binary)
{
  vector<string> specPaths;
  specPaths.push_back(specDirectory);
  startDecompilerLibrary(specPaths);
  BfdArchitecture architecture(binary,"default",&std::cerr);
  DocumentStorage store;
  architecture.init(store);

  TypeFactory *factory = architecture.types;
  if (factory == (TypeFactory *)0)
    throw std::runtime_error("architecture has no TypeFactory");

  const int4 sizes[] = { 8, 1, 4, 2, 3, 5, 6, 7 };
  vector<Datatype *> first;
  std::cout << "{\"schema\":1,\"fixture\":\"TYPE-UNKNOWN-0001\",\"types\":[";
  for(size_t i=0;i<sizeof(sizes)/sizeof(sizes[0]);++i) {
    if (i != 0) std::cout << ',';
    Datatype *type = factory->getBase(sizes[i],TYPE_UNKNOWN);
    first.push_back(type);
    writeType(std::cout,sizes[i],type);
  }
  std::cout << "],\"identity\":{\"repeat\":[";
  for(size_t i=0;i<first.size();++i) {
    if (i != 0) std::cout << ',';
    std::cout << (first[i] == factory->getBase(sizes[i],TYPE_UNKNOWN));
  }
  std::cout << "],\"different_size\":[";
  for(size_t i=1;i<first.size();++i) {
    if (i != 1) std::cout << ',';
    std::cout << (first[0] == first[i]);
  }
  std::cout << "]},\"named\":";

  Datatype *named = factory->getBase(3,TYPE_UNKNOWN,"fixture_unknown3");
  writeType(std::cout,3,named);
  std::cout << ",\"named_repeat\":"
            << (named == factory->getBase(3,TYPE_UNKNOWN,"fixture_unknown3"));
  std::cout << ",\"collision_error\":";
  try {
    (void)factory->getBase(4,TYPE_UNKNOWN,"fixture_unknown3");
    writeString(std::cout,"NONE");
  }
  catch(const LowlevelError &err) {
    writeString(std::cout,err.explain);
  }

  std::cout << ",\"anonymous_order_before_clear\":";
  writeAnonymousUnknownOrder(std::cout,factory);

  factory->clearNoncore();
  std::cout << ",\"anonymous_order_after_clear\":";
  writeAnonymousUnknownOrder(std::cout,factory);
  Datatype *afterClear = factory->getBase(3,TYPE_UNKNOWN);
  std::cout << ",\"clear_identity\":{\"new_repeat\":"
            << (afterClear == factory->getBase(3,TYPE_UNKNOWN))
            << "},\"anonymous_order_after_recreate\":";
  writeAnonymousUnknownOrder(std::cout,factory);
  std::cout << "}\n";
}

} // namespace

int main(int argc,char **argv)
{
  try {
    if (argc != 3)
      throw std::invalid_argument("usage: type_unknown_1204 SPEC_DIRECTORY BINARY");
    runFixture(argv[1],argv[2]);
    return 0;
  }
  catch(const ghidra::LowlevelError &err) {
    std::cerr << "LowlevelError: " << err.explain << '\n';
  }
  catch(const std::exception &err) {
    std::cerr << "std::exception: " << err.what() << '\n';
  }
  return 1;
}
