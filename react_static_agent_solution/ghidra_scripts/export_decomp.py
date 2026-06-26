# Ghidra headless script. It exports a small decompilation summary as jsonl.
# Usage from analyzeHeadless:
#   -postScript export_decomp.py /path/to/decomp.jsonl

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0] if len(args) > 0 else "decomp.jsonl"

monitor = ConsoleTaskMonitor()
iface = DecompInterface()
iface.openProgram(currentProgram)
fm = currentProgram.getFunctionManager()

with open(out_path, "w") as fp:
    for f in fm.getFunctions(True):
        item = {
            "name": f.getName(),
            "entry": str(f.getEntryPoint()),
            "decomp": ""
        }
        try:
            res = iface.decompileFunction(f, 30, monitor)
            if res is not None and res.decompileCompleted():
                item["decomp"] = res.getDecompiledFunction().getC()
        except Exception as e:
            item["decomp_error"] = str(e)
        fp.write(json.dumps(item) + "\n")
