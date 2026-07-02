# Ghidra headless postScript: decompile all functions, write C to a file.
# @category Examples
# @runtime Jython
#
# Usage as a Ghidra postScript:
#   analyzeHeadless <proj> <name> -import <binary> \
#       -scriptPath tools -postScript ghidra_decompile_all.py <out_file> \
#       -deleteProject
#
# The first script argument (getScriptArgs()[0]) is the output file path.
# Writing directly to a file (instead of print() to stdout) keeps C output
# from interleaving with Ghidra's own INFO log lines — the root cause of
# the old "strip first 124 lines" manual step and the trailing-INFO noise
# that contaminated tests/golden/ghidra_curl.c (11.3.2 era).

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

out_path = None
args = getScriptArgs()
if args and len(args) > 0:
    out_path = args[0]

if not out_path:
    # Fall back to stdout only if no arg given (legacy behavior).
    print("ERROR: no output file argument supplied")
    print("Usage: -postScript ghidra_decompile_all.py <out_file>")
    raise SystemExit(1)

decomp = DecompInterface()
decomp.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

f = open(out_path, "w")
try:
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)
    n_ok = 0
    n_fail = 0
    for func in funcs:
        name = func.getName()
        entry = func.getEntryPoint()
        results = decomp.decompileFunction(func, 30, monitor)
        if results and results.decompileCompleted():
            c_code = results.getDecompiledFunction().getC()
            f.write("/* ---- 0x%x: %s (%d bytes) ---- */\n" % (
                entry.getOffset(), name, func.getBody().getNumAddresses()))
            f.write(c_code)
            f.write("\n")
            n_ok += 1
        else:
            f.write("/* ---- 0x%x: %s FAILED ---- */\n" % (entry.getOffset(), name))
            n_fail += 1
    f.flush()
finally:
    f.close()
    decomp.dispose()

# A single clean summary line to stdout (host driver parses this).
print("GHIDRA_DECOMP_DONE ok=%d fail=%d out=%s" % (n_ok, n_fail, out_path))
