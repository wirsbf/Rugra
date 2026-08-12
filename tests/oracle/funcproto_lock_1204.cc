#include <iostream>

#include "fspec.hh"

using namespace ghidra;

static void dump(const char *label, FuncProto &proto) {
  std::cout << label
            << ":input=" << proto.isInputLocked()
            << ",output=" << proto.isOutputLocked()
            << ",model=" << proto.isModelLocked()
            << ",params=" << proto.numParams() << '\n';
}

int main() {
  TypeVoid void_type;
  FuncProto proto;
  proto.setInternal(nullptr, &void_type);
  dump("fresh", proto);

  proto.setInputLock(true);
  dump("input_locked", proto);
  proto.clearUnlockedInput();
  dump("clear_unlocked", proto);

  FuncProto copied;
  copied.copy(proto);
  dump("copied", copied);
  copied.clearInput();
  dump("clear_input", copied);

  FuncProto output;
  output.setInternal(nullptr, &void_type);
  output.setOutputLock(true);
  dump("output_locked", output);
  output.setOutputLock(false);
  dump("output_unlocked", output);
  return 0;
}
