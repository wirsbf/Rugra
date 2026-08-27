/* HTTPD-BUCKET2-2026-08-27 structural fixture skeleton.
 * Oracle: Ghidra 12.0.4, e40ed13014025f82488b1f8f7bca566894ac376b.
 * Production input is the locked httpd ELF consumed by
 * examples/httpd_decompile.rs; these projections are transcribed from
 * tests/golden/ghidra_httpd_1204.c.  They intentionally observe CFG shape,
 * not final C text or printer behavior.
 */
#include <iostream>
#include <string>
struct Projection { const char *name; int lines, ifs, fors, whiles, gotos, calls; };
int main() {
  // Golden function-local structural census (declarations excluded from the
  // control counts; counts are stable review anchors for the real harness).
  const Projection p[] = {
    {"ap_fini_vhost_config", 217, 22, 3, 8, 5, 62},
    {"ap_getparents", 149, 18, 0, 7, 6, 27},
  };
  for (const auto &x : p)
    std::cout << "case=" << x.name << " lines=" << x.lines
              << " if=" << x.ifs << " for=" << x.fors
              << " while=" << x.whiles << " goto=" << x.gotos
              << " calls=" << x.calls << "\n";
  return 0;
}
