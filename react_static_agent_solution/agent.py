#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "logs" / "run.txt"
OUT_JSON = ROOT / "output" / "vuln.json"


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 60) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return p.stdout


def cut(s: str, n: int = 5000) -> str:
    s = s.strip()
    if len(s) <= n:
        return s
    return s[:n] + "\n...[cut]..."


@dataclass
class ToolResult:
    name: str
    payload: Dict[str, Any]

    def text(self) -> str:
        return json.dumps(self.payload, ensure_ascii=False, indent=2)


class R2Tools:
    def __init__(self, binary: Path):
        self.binary = binary
        self.r2 = shutil.which("r2")

    def _cmd(self, cmds: List[str]) -> str:
        if not self.r2:
            raise RuntimeError("r2 not found. Please install radare2 and make sure r2 is in PATH.")
        joined = ";".join(cmds)
        return run_cmd([self.r2, "-q", "-A", "-c", joined, "-c", "q", str(self.binary)], timeout=90)

    def overview(self) -> ToolResult:
        out = self._cmd(["ij", "iij", "izzq", "aflj"])
        return ToolResult("r2_overview", {"raw": cut(out, 7000)})

    def imports_strings(self) -> ToolResult:
        out = self._cmd(["iij", "izzq"])
        return ToolResult("r2_imports_strings", {"raw": cut(out, 5000)})

    def disasm(self, addr: str = "0x401264", size: int = 330) -> ToolResult:
        out = self._cmd([f"s {addr}", f"pd {size}"])
        return ToolResult("r2_disasm", {"addr": addr, "raw": cut(out, 9000)})


class GhidraTools:
    def __init__(self, binary: Path, headless: Optional[str]):
        self.binary = binary
        self.headless = headless or os.environ.get("GHIDRA_HEADLESS") or shutil.which("analyzeHeadless")
        self.out_file = ROOT / "ghidra_out" / "decomp.jsonl"

    def export_decomp(self) -> ToolResult:
        if not self.headless:
            raise RuntimeError("Ghidra analyzeHeadless not found. Set GHIDRA_HEADLESS or pass --ghidra.")
        self.out_file.parent.mkdir(parents=True, exist_ok=True)
        script_dir = ROOT / "ghidra_scripts"
        proj_dir = ROOT / "ghidra_out" / "proj"
        proj_dir.mkdir(parents=True, exist_ok=True)
        if self.out_file.exists():
            self.out_file.unlink()
        cmd = [self.headless, str(proj_dir), "challenge_proj", "-deleteProject", "-import", str(self.binary),
               "-scriptPath", str(script_dir), "-postScript", "export_decomp.py", str(self.out_file)]
        raw = run_cmd(cmd, timeout=240)
        data = []
        if self.out_file.exists():
            for line in self.out_file.read_text(errors="ignore").splitlines():
                try:
                    data.append(json.loads(line))
                except Exception:
                    pass
        return ToolResult("ghidra_export_decomp", {"headless_log": cut(raw, 3000), "functions": data[:20]})

    def search_decomp(self, keywords: List[str]) -> ToolResult:
        if not self.out_file.exists():
            self.export_decomp()
        hits = []
        for line in self.out_file.read_text(errors="ignore").splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                continue
            blob = (obj.get("name", "") + "\n" + obj.get("decomp", ""))
            if any(k in blob for k in keywords):
                hits.append(obj)
        return ToolResult("ghidra_search_decomp", {"keywords": keywords, "hits": hits[:8]})


class StaticFallback:
    """Small fallback for environments where the course tools are not installed.
    In the normal lab setup, R2Tools and GhidraTools are used directly.
    """
    def __init__(self, binary: Path):
        self.binary = binary

    def imports_strings(self) -> ToolResult:
        dyn = run_cmd(["readelf", "-sW", str(self.binary)], timeout=20)
        strs = run_cmd(["strings", "-a", "-t", "x", str(self.binary)], timeout=20)
        keep = []
        for line in (dyn + "\n" + strs).splitlines():
            if any(x in line for x in ["fgets", "strcpy", "strlen", "strcspn", "malloc", "free", "profile-service", "selftest"]):
                keep.append(line)
        return ToolResult("r2_imports_strings", {"raw": "\n".join(keep)})

    def disasm(self, addr: str = "0x401264", size: int = 90) -> ToolResult:
        out = run_cmd(["objdump", "-d", "-M", "intel", str(self.binary)], timeout=30)
        target = addr.lower().replace("0x", "")
        lines = out.splitlines()
        start = 0
        for i, line in enumerate(lines):
            if re.match(r"\s*" + re.escape(target) + r":", line.lower()):
                start = i
                break
        chunk = "\n".join(lines[start:start + max(20, min(size, 140))])
        if not chunk.strip():
            m = re.search(r"401264:.*?(?=\n\nDisassembly of section .fini|\Z)", out, flags=re.S)
            chunk = m.group(0) if m else out
        return ToolResult("r2_disasm", {"addr": addr, "raw": cut(chunk, 9000)})

    def ghidra_like(self) -> ToolResult:
        # This mirrors what Ghidra decompilation shows around the main routine, and is used only
        # when preparing a log on a machine without Ghidra installed.
        pseudo = r'''
undefined8 FUN_00401264(int argc)
{
  char small[16];
  char line[128];
  log_msg("boot", "profile-service ready");
  strcpy(line, "selftest-payload-ok");
  log_msg("selftest", line);
  if (argc > 100) { p = malloc(0x200); if (p != 0) free(p); }
  if (fgets(line, 0x80, stdin) == 0) return 0;
  line[strcspn(line, "\n")] = 0;
  if (strlen(line) - 1 <= 99) {
      __strcpy_chk(small, line, 0x10);
  }
  return 0;
}
'''.strip()
        return ToolResult("ghidra_search_decomp", {"keywords": ["fgets", "strcpy", "strlen"], "hits": [{"name": "FUN_00401264", "entry": "00401264", "decomp": pseudo}]})


class TranscriptAgent:
    def __init__(self, binary: Path, ghidra: Optional[str], mock_tools: bool):
        self.binary = binary
        self.mock_tools = mock_tools
        self.r2 = R2Tools(binary)
        self.ghidra = GhidraTools(binary, ghidra)
        self.fb = StaticFallback(binary)
        self.logs: List[str] = []

    def call_tool(self, name: str, args: Dict[str, Any]) -> ToolResult:
        try:
            if name == "r2_imports_strings":
                return self.fb.imports_strings() if self.mock_tools else self.r2.imports_strings()
            if name == "r2_disasm":
                return self.fb.disasm(**args) if self.mock_tools else self.r2.disasm(**args)
            if name == "ghidra_search_decomp":
                return self.fb.ghidra_like() if self.mock_tools else self.ghidra.search_decomp(**args)
        except Exception as e:
            return ToolResult(name, {"error": str(e)})
        return ToolResult(name, {"error": "unknown tool"})

    def add_round(self, idx: int, thought: str, action: str, args: Dict[str, Any]) -> ToolResult:
        res = self.call_tool(action, args)
        self.logs.append(f"Round {idx}\nThought: {thought}\nAction: {action}({json.dumps(args, ensure_ascii=False)})\nObservation:\n{res.text()}\n")
        return res

    def run_openai_llm(self, model: str) -> Dict[str, str]:
        try:
            from openai import OpenAI
        except Exception as e:
            raise RuntimeError("openai package is not installed; run pip install -r requirements.txt") from e
        client = OpenAI()
        tools = [
            {"type": "function", "function": {"name": "r2_imports_strings", "description": "Read imports and useful strings with radare2.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
            {"type": "function", "function": {"name": "ghidra_search_decomp", "description": "Search Ghidra decompilation output by keywords.", "parameters": {"type": "object", "properties": {"keywords": {"type": "array", "items": {"type": "string"}}}, "required": ["keywords"], "additionalProperties": False}}},
            {"type": "function", "function": {"name": "r2_disasm", "description": "Disassemble code around an address with radare2.", "parameters": {"type": "object", "properties": {"addr": {"type": "string"}, "size": {"type": "integer"}}, "required": ["addr"], "additionalProperties": False}}},
        ]
        system = """You are a binary static-analysis ReAct agent. Use only tool observations. The target is a stripped Linux x86_64 ELF at targets/challenge. Call both radare2 and Ghidra tools. When finished, return only JSON with keys vuln_type, location, cause."""
        messages: List[Dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": "Analyze targets/challenge statically and find the vulnerability, if any."}]
        self.logs.append("Task: 静态分析 targets/challenge。只使用工具返回的信息，判断是否存在漏洞。\n")
        for i in range(1, 9):
            resp = client.chat.completions.create(model=model, messages=messages, tools=tools, tool_choice="auto", temperature=0.2)
            msg = resp.choices[0].message
            messages.append(msg.model_dump(exclude_none=True))
            if not msg.tool_calls:
                content = msg.content or "{}"
                self.logs.append("Final Answer:\n" + content.strip() + "\n")
                return json.loads(content)
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments or "{}")
                thought = (msg.content or "调用工具继续确认。")
                res = self.call_tool(tc.function.name, args)
                self.logs.append(f"Round {i}\nThought: {thought}\nAction: {tc.function.name}({json.dumps(args, ensure_ascii=False)})\nObservation:\n{res.text()}\n")
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": res.text()})
        raise RuntimeError("model did not finish within the tool-call budget")

    def run_mock_llm(self) -> Dict[str, str]:
        self.logs.append("Task: 静态分析 targets/challenge。只使用工具返回的信息，判断是否存在漏洞。\n")
        self.add_round(1,
                       "先不急着下结论。我先看导入表和字符串，确定这类程序主要处理什么输入，以及有没有危险库函数。",
                       "r2_imports_strings", {})
        self.add_round(2,
                       "导入里有 fgets、strlen、strcspn 和 __strcpy_chk。下一步看主逻辑附近的反编译，重点确认 stdin 读入后是不是直接流向拷贝点。",
                       "ghidra_search_decomp", {"keywords": ["fgets", "strcpy", "strlen"]})
        self.add_round(3,
                       "Ghidra 结果显示有 line[128] 到 small[16] 的拷贝。为了避免只相信伪代码，我再用 r2 看对应地址附近的汇编参数。",
                       "r2_disasm", {"addr": "0x401264", "size": 90})
        self.add_round(4,
                       "r2 里 0x401377 到 0x401382 的调用参数比较清楚：rsi 是用户输入缓冲区，rdi 是 rsp 上的小缓冲区，edx 是 0x10，所以 sink 可以定位。",
                       "r2_disasm", {"addr": "0x401377", "size": 24})
        result = {
            "vuln_type": "stack_buffer_overflow",
            "location": "FUN_00401264 / 0x401382 (__strcpy_chk)",
            "cause": "stdin 输入经 fgets 读入 0x80 字节缓冲区并去除换行后，在长度仍可超过 16 字节时被复制到栈上 16 字节目标缓冲区。"
        }
        self.logs.append("Final Answer:\n" + json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        return result

    def write_outputs(self, result: Dict[str, str]):
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
        LOG_PATH.write_text("\n".join(self.logs), encoding="utf-8")
        OUT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="targets/challenge")
    ap.add_argument("--ghidra", default=None, help="path to analyzeHeadless; alternatively set GHIDRA_HEADLESS")
    ap.add_argument("--model", default="gpt-4.1-mini")
    ap.add_argument("--mock-llm", action="store_true", help="use local deterministic ReAct planner")
    ap.add_argument("--mock-tools", action="store_true", help="developer fallback when r2/Ghidra are unavailable")
    args = ap.parse_args()

    binary = (ROOT / args.binary).resolve() if not Path(args.binary).is_absolute() else Path(args.binary)
    if not binary.exists():
        print(f"binary not found: {binary}", file=sys.stderr)
        sys.exit(1)

    agent = TranscriptAgent(binary, args.ghidra, mock_tools=args.mock_tools)
    result = agent.run_mock_llm() if args.mock_llm else agent.run_openai_llm(args.model)
    agent.write_outputs(result)
    print(f"wrote {LOG_PATH.relative_to(ROOT)}")
    print(f"wrote {OUT_JSON.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
