// Dump post-analysis P-code IR for a function. Ghidra 12.x compatible.
// @category Rugra
// @author rugra

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;

public class DumpPcodeIR extends GhidraScript {

    private String spaceName(int t) {
        switch (t) {
            case AddressSpace.TYPE_RAM: return "ram";
            case AddressSpace.TYPE_REGISTER: return "reg";
            case AddressSpace.TYPE_UNIQUE: return "u";
            case AddressSpace.TYPE_CONSTANT: return "const";
            case AddressSpace.TYPE_CODE: return "code";
            default: return String.valueOf(t);
        }
    }

    private String fmtVn(Varnode vn) {
        Address a = vn.getAddress();
        AddressSpace sp = a.getAddressSpace();
        StringBuilder s = new StringBuilder();
        s.append(spaceName(sp.getType())).append("@0x")
         .append(Long.toHexString(a.getOffset())).append("#").append(vn.getSize());
        if (vn.isInput()) s.append("[in]");
        if (vn.isConstant()) s.append("[c]");
        return s.toString();
    }

    @Override
    public void run() throws Exception {
        String funcName = null;
        String[] args = getScriptArgs();
        if (args.length > 0) funcName = args[0];

        Function func = null;
        if (funcName != null) {
            FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
            while (fi.hasNext()) {
                Function f = fi.next();
                if (f.getName().equals(funcName)) { func = f; break; }
            }
        }
        if (func == null) {
            println("Function '" + funcName + "' not found");
            return;
        }

        println("==== Ghidra IR dump: " + func.getName() + " @ 0x" +
                Long.toHexString(func.getEntryPoint().getOffset()) + " ====");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults res = decomp.decompileFunction(func, 120, monitor);
        if (!res.decompileCompleted()) {
            println("Decompile failed: " + res.getErrorMessage());
            decomp.dispose();
            return;
        }
        HighFunction hf = res.getHighFunction();
        java.util.Iterator<PcodeOpAST> it = hf.getPcodeOps();
        Address curBB = null;
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            PcodeBlock blk = op.getParent();
            Address bb = blk != null ? blk.getStart() : op.getSeqnum().getTarget();
            if (curBB == null || !curBB.equals(bb)) {
                curBB = bb;
                println("");
                println("BB 0x" + Long.toHexString(bb.getOffset()) + ":");
            }
            StringBuilder line = new StringBuilder();
            line.append("  [0x")
                .append(Long.toHexString(op.getSeqnum().getTarget().getOffset()))
                .append("] ").append(String.format("%-14s", Integer.toString(op.getOpcode())));
            Varnode out = op.getOutput();
            if (out != null) line.append("  out=").append(fmtVn(out));
            for (int i = 0; i < op.getNumInputs(); i++) {
                Varnode in = op.getInput(i);
                if (in == null) continue;
                line.append("  in").append(i).append("=").append(fmtVn(in));
            }
            println(line.toString());
        }
        decomp.dispose();
    }
}
