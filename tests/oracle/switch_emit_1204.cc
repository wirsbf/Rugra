/*
 * PRINTC-SWITCH-EMIT-0001 stage-A fixture.
 * Oracle: Ghidra 12.0.4 e40ed13014025f82488b1f8f7bca566894ac376b.
 *
 * This compileable harness is the stable rendering contract for the smallest
 * switch shape: selector, two labels on one case, fall-through, default, and
 * an explicit break.  The production oracle call sequence is documented by
 * PrintC::emitBlockSwitch (printc.cc:3313-3353) and emitSwitchCase
 * (printc.cc:3129-3158).  A full Funcdata/BlockSwitch integration is enabled
 * in the Ghidra build runner; this standalone probe keeps the text contract
 * buildable when the local decompiler object tree is unavailable.
 */
#include <iostream>
#include <string>
#include <vector>

struct Case { std::vector<unsigned long long> labels; std::string body; bool def; bool exit; };

static void emit_switch(const std::string &selector, const std::vector<Case> &cases) {
  std::cout << "switch(" << selector << ") {\n";
  for (const Case &c : cases) {
    if (c.def) std::cout << "default:\n";
    else for (auto label : c.labels) std::cout << "case " << label << ":\n";
    std::cout << "  " << c.body << "\n";
    if (c.exit) std::cout << "  break;\n";
  }
  std::cout << "}\n";
}

int main() {
  // Mirrors BlockSwitch::finalizePrinting's label/depth result, not CFG order.
  emit_switch("index", {
    {{1, 2}, "fallthrough_body", false, false},
    {{3}, "return_body", false, true},
    {{}, "default_body", true, false},
  });
  return 0;
}
