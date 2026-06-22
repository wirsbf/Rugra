# Ghidra headless script: decompile all functions and print C output.
# @category Examples
# @runtime Jython

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

decomp = DecompInterface()
decomp.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)
for func in funcs:
    name = func.getName()
    entry = func.getEntryPoint()
    results = decomp.decompileFunction(func, 30, monitor)
    if results and results.decompileCompleted():
        c_code = results.getDecompiledFunction().getC()
        print("/* ---- 0x%x: %s (%d bytes) ---- */" % (entry.getOffset(), name, func.getBody().getNumAddresses()))
        print(c_code)
    else:
        print("/* ---- 0x%x: %s FAILED ---- */" % (entry.getOffset(), name))

decomp.dispose()
