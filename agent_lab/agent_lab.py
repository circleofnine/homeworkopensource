#!/usr/bin/env python3
"""
ReAct + angr automatic reverse-analysis demo.

Usage:
  gcc -O0 -g -no-pie crackme.c -o crackme
  python agent_lab.py --binary ./crackme --mock-llm

With a real tool-calling LLM:
  export OPENAI_API_KEY=...
  python agent_lab.py --binary ./crackme --model gpt-4.1-mini
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def require_angr():
    """Import angr lazily so --help and documentation can be used before installing dependencies."""
    try:
        import angr  # type: ignore
        import claripy  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "angr/claripy is not installed. Please run: pip install -r requirements.txt"
        ) from exc
    return angr, claripy


def compile_target(source: str, output: str, cc: str = "gcc") -> None:
    """Compile crackme.c into an executable. -no-pie makes addresses more stable."""
    cmd = [cc, "-O0", "-g", "-no-pie", source, "-o", output]
    print(f"[compile] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


@dataclass
class ToolResult:
    name: str
    ok: bool
    observation: str


class AngrToolBox:
    """A small stateful toolbox exposed to the ReAct agent."""

    def __init__(self, binary_path: str, input_len: int = 4):
        self.binary_path = os.path.abspath(binary_path)
        self.input_len = input_len
        self.angr = None
        self.claripy = None
        self.project = None
        self.state = None
        self.simgr = None
        self.sym_chars = None
        self.stdin_ast = None
        self.found_state = None
        self.total_steps = 0

    # ------------------------- internal helpers -------------------------
    def _ensure_project(self):
        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(
                f"Binary not found: {self.binary_path}. Compile first, e.g. gcc -O0 -g -no-pie crackme.c -o crackme"
            )
        if self.project is None:
            self.angr, self.claripy = require_angr()
            self.project = self.angr.Project(self.binary_path, auto_load_libs=False)
        return self.project

    def _reset_symbolic_state(self):
        project = self._ensure_project()
        claripy = self.claripy
        assert claripy is not None

        # scanf("%9s") stops at whitespace. Four symbolic printable bytes + newline are enough,
        # because the target only checks input[0..3] and requires strlen(input) >= 4.
        self.sym_chars = [claripy.BVS(f"password_{i}", 8) for i in range(self.input_len)]
        newline = claripy.BVV(ord("\n"), 8)
        stdin = claripy.Concat(*(self.sym_chars + [newline]))
        self.stdin_ast = claripy.Concat(*self.sym_chars)

        self.state = project.factory.full_init_state(args=[self.binary_path], stdin=stdin)
        for ch in self.sym_chars:
            self.state.solver.add(ch >= 0x21)  # printable and non-space
            self.state.solver.add(ch <= 0x7E)
            self.state.solver.add(ch != 0x20)

        self.simgr = project.factory.simulation_manager(self.state)
        self.found_state = None
        self.total_steps = 0

    def _ensure_simgr(self):
        if self.simgr is None:
            self._reset_symbolic_state()
        return self.simgr

    @staticmethod
    def _stdout(state) -> bytes:
        try:
            return state.posix.dumps(1)
        except Exception:
            return b""

    def _is_success(self, state) -> bool:
        return b"Success!" in self._stdout(state)

    def _is_bad(self, state, avoid_wrong: bool = True, avoid_trap: bool = True) -> bool:
        out = self._stdout(state)
        if avoid_trap and b"trapped" in out:
            return True
        if avoid_trap and b"Oops" in out:
            return True
        if avoid_wrong and b"Wrong password!" in out:
            return True
        return False

    def _prune_active_states(self, avoid_wrong: bool = True, avoid_trap: bool = True) -> int:
        assert self.simgr is not None
        if "avoid" not in self.simgr.stashes:
            self.simgr.stashes["avoid"] = []
        kept = []
        pruned = 0
        for st in list(self.simgr.active):
            if self._is_bad(st, avoid_wrong=avoid_wrong, avoid_trap=avoid_trap):
                self.simgr.stashes["avoid"].append(st)
                pruned += 1
            else:
                kept.append(st)
        self.simgr.stashes["active"] = kept
        return pruned

    def _stash_counts(self) -> Dict[str, int]:
        assert self.simgr is not None
        return {name: len(states) for name, states in self.simgr.stashes.items() if states}

    def _sample_outputs(self, limit: int = 3) -> List[str]:
        assert self.simgr is not None
        samples: List[str] = []
        for stash_name in ["active", "found", "avoid", "deadended"]:
            for st in self.simgr.stashes.get(stash_name, [])[:limit]:
                out = self._stdout(st).decode(errors="replace")
                if out and out not in samples:
                    samples.append(f"{stash_name}: {out.strip()}")
                if len(samples) >= limit:
                    return samples
        return samples

    # ------------------------- ReAct-callable tools -------------------------
    def inspect_binary(self) -> str:
        """Inspect symbols and useful strings from the binary."""
        project = self._ensure_project()
        symbols = {}
        for name in ["main", "check_password", "gadget_trap"]:
            sym = project.loader.find_symbol(name)
            symbols[name] = hex(sym.rebased_addr) if sym is not None else None

        data = Path(self.binary_path).read_bytes()
        ascii_strings = []
        for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
            s = m.group(0).decode(errors="replace")
            if any(k in s for k in ["Success", "Wrong", "Oops", "Enter", "trapped"]):
                ascii_strings.append(s)
        ascii_strings = sorted(set(ascii_strings))

        obs = {
            "binary": self.binary_path,
            "entry": hex(project.entry),
            "symbols": symbols,
            "interesting_strings": ascii_strings,
            "hint": "Success string is the find condition; Wrong/Oops/trapped strings should be avoided.",
        }
        return json.dumps(obs, ensure_ascii=False, indent=2)

    def controlled_explore(self, max_steps: int = 20, avoid_wrong: bool = True, avoid_trap: bool = True) -> str:
        """Run bounded symbolic execution and prune states that already printed failure/trap messages."""
        simgr = self._ensure_simgr()
        pruned_total = 0
        found_this_round = 0

        for _ in range(max_steps):
            # Check before stepping so we do not accidentally step a success/trap state forever.
            found = [st for st in simgr.active if self._is_success(st)]
            if found:
                if "found" not in simgr.stashes:
                    simgr.stashes["found"] = []
                simgr.stashes["found"].extend(found)
                simgr.stashes["active"] = [st for st in simgr.active if st not in found]
                self.found_state = found[0]
                found_this_round += len(found)
                break

            pruned_total += self._prune_active_states(avoid_wrong=avoid_wrong, avoid_trap=avoid_trap)
            if not simgr.active:
                break
            simgr.step()
            self.total_steps += 1

        pruned_total += self._prune_active_states(avoid_wrong=avoid_wrong, avoid_trap=avoid_trap)
        obs = {
            "tool": "controlled_explore",
            "steps_this_call": max_steps,
            "total_steps": self.total_steps,
            "found_this_round": found_this_round,
            "pruned_bad_states": pruned_total,
            "stashes": self._stash_counts(),
            "sample_outputs": self._sample_outputs(),
            "next_suggestion": "If no success state is found, run explore_to_success with the same avoid policy.",
        }
        return json.dumps(obs, ensure_ascii=False, indent=2)

    def explore_to_success(self, max_steps: int = 200, avoid_wrong: bool = True, avoid_trap: bool = True) -> str:
        """Continue symbolic execution until stdout contains Success!, avoiding failure/trap states."""
        simgr = self._ensure_simgr()
        found_at: Optional[int] = None
        pruned_total = 0

        for local_step in range(max_steps):
            found = [st for st in simgr.active if self._is_success(st)]
            if found:
                if "found" not in simgr.stashes:
                    simgr.stashes["found"] = []
                simgr.stashes["found"].extend(found)
                simgr.stashes["active"] = [st for st in simgr.active if st not in found]
                self.found_state = found[0]
                found_at = self.total_steps
                break

            pruned_total += self._prune_active_states(avoid_wrong=avoid_wrong, avoid_trap=avoid_trap)
            if not simgr.active:
                break
            simgr.step()
            self.total_steps += 1

        pruned_total += self._prune_active_states(avoid_wrong=avoid_wrong, avoid_trap=avoid_trap)
        success = self.found_state is not None
        obs = {
            "tool": "explore_to_success",
            "success_state_found": success,
            "found_at_total_step": found_at,
            "pruned_bad_states": pruned_total,
            "stashes": self._stash_counts(),
            "sample_outputs": self._sample_outputs(),
            "next_suggestion": "Call solve_input to concretize stdin." if success else "Increase max_steps or inspect avoid constraints.",
        }
        return json.dumps(obs, ensure_ascii=False, indent=2)

    def solve_input(self) -> str:
        """Concretize the symbolic stdin bytes from the stored success state."""
        if self.found_state is None:
            # Some users may call solve_input after simgr put a state in found but self.found_state was not set.
            simgr = self._ensure_simgr()
            if simgr.stashes.get("found"):
                self.found_state = simgr.stashes["found"][0]
            else:
                raise RuntimeError("No success state has been found yet. Call explore_to_success first.")

        assert self.stdin_ast is not None
        raw = self.found_state.solver.eval(self.stdin_ast, cast_to=bytes)
        password = raw.decode(errors="replace")
        stdout = self._stdout(self.found_state).decode(errors="replace")
        obs = {
            "tool": "solve_input",
            "password": password,
            "stdin_repr": repr((password + "\n").encode()),
            "success_stdout": stdout.strip(),
            "manual_check": f"echo {password!r} | {self.binary_path}",
        }
        return json.dumps(obs, ensure_ascii=False, indent=2)

    def verify_input(self, password: str) -> str:
        """Run the real binary once with the solved input for a concrete verification."""
        completed = subprocess.run(
            [self.binary_path],
            input=(password + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
        obs = {
            "tool": "verify_input",
            "password": password,
            "returncode": completed.returncode,
            "stdout": completed.stdout.decode(errors="replace").strip(),
            "stderr": completed.stderr.decode(errors="replace").strip(),
        }
        return json.dumps(obs, ensure_ascii=False, indent=2)


TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "inspect_binary",
            "description": "Inspect symbols and useful strings in the target binary.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "controlled_explore",
            "description": "Run bounded symbolic execution and prune states that print failure/trap messages.",
            "parameters": {
                "type": "object",
                "properties": {
                    "max_steps": {"type": "integer", "description": "Maximum angr steps in this call.", "default": 20},
                    "avoid_wrong": {"type": "boolean", "default": True},
                    "avoid_trap": {"type": "boolean", "default": True},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explore_to_success",
            "description": "Continue symbolic execution until stdout contains Success!, avoiding Wrong/Oops/trapped paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "max_steps": {"type": "integer", "description": "Maximum angr steps in this call.", "default": 200},
                    "avoid_wrong": {"type": "boolean", "default": True},
                    "avoid_trap": {"type": "boolean", "default": True},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "solve_input",
            "description": "Solve concrete stdin from the previously found success state.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_input",
            "description": "Run the concrete binary with a candidate password.",
            "parameters": {
                "type": "object",
                "properties": {"password": {"type": "string"}},
                "required": ["password"],
                "additionalProperties": False,
            },
        },
    },
]


def dispatch_tool(toolbox: AngrToolBox, name: str, args: Dict[str, Any]) -> ToolResult:
    mapping: Dict[str, Callable[..., str]] = {
        "inspect_binary": toolbox.inspect_binary,
        "controlled_explore": toolbox.controlled_explore,
        "explore_to_success": toolbox.explore_to_success,
        "solve_input": toolbox.solve_input,
        "verify_input": toolbox.verify_input,
    }
    if name not in mapping:
        return ToolResult(name=name, ok=False, observation=f"Unknown tool: {name}")
    try:
        observation = mapping[name](**args)
        return ToolResult(name=name, ok=True, observation=observation)
    except Exception as exc:
        return ToolResult(name=name, ok=False, observation=f"ERROR: {type(exc).__name__}: {exc}")


SYSTEM_PROMPT = """You are a ReAct reverse-analysis agent.
Goal: find a stdin password that makes the crackme print "Success!".
Constraints: prefer paths related to Success!, avoid paths printing Wrong password, Oops, trapped, or entering a dead loop.
At each round, give only one concise Thought sentence, then call exactly one tool.
After solve_input succeeds, optionally verify the result and then stop.
"""


MOCK_PLAN: List[Tuple[str, str, Dict[str, Any]]] = [
    (
        "先检查二进制符号和字符串，确定 find/avoid 条件。",
        "inspect_binary",
        {},
    ),
    (
        "根据字符串线索，先做小步受控探索，并剪枝 Wrong/Oops/trapped 路径。",
        "controlled_explore",
        {"max_steps": 25, "avoid_wrong": True, "avoid_trap": True},
    ),
    (
        "受控探索尚未显式求解输入，继续以 Success! 为目标搜索成功状态。",
        "explore_to_success",
        {"max_steps": 200, "avoid_wrong": True, "avoid_trap": True},
    ),
    (
        "已经到达成功状态，现在从符号 stdin 中求解具体输入。",
        "solve_input",
        {},
    ),
]


def run_mock(toolbox: AngrToolBox) -> None:
    print("===== ReAct run: mock LLM mode =====")
    print(f"System goal: {SYSTEM_PROMPT.strip()}\n")
    for i, (thought, action, args) in enumerate(MOCK_PLAN, start=1):
        print(f"--- Round {i} ---")
        print(f"Thought: {thought}")
        print(f"Action: {action}({json.dumps(args, ensure_ascii=False)})")
        result = dispatch_tool(toolbox, action, args)
        print(f"Observation: {result.observation}\n")
        if action == "solve_input" and result.ok:
            try:
                obs = json.loads(result.observation)
                password = obs.get("password")
                if password:
                    print("--- Round 5 ---")
                    print("Thought: 用真实二进制再验证一次，确认该输入确实触发 Success!。")
                    v_args = {"password": password}
                    print(f"Action: verify_input({json.dumps(v_args, ensure_ascii=False)})")
                    verify = dispatch_tool(toolbox, "verify_input", v_args)
                    print(f"Observation: {verify.observation}\n")
            except Exception:
                pass
            break


def run_openai(toolbox: AngrToolBox, model: str, max_rounds: int) -> None:
    try:
        from openai import OpenAI  # type: ignore
    except ImportError as exc:
        raise RuntimeError("openai is not installed. Please run: pip install -r requirements.txt") from exc

    client = OpenAI()
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Please solve this crackme using the available angr tools."},
    ]

    print("===== ReAct run: OpenAI tool-calling mode =====")
    for i in range(1, max_rounds + 1):
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",
            temperature=0,
        )
        msg = resp.choices[0].message
        thought = msg.content or ""
        print(f"--- Round {i} ---")
        print(f"Thought: {thought.strip()}")

        # Keep the assistant message in the transcript for the next model call.
        messages.append(msg.model_dump(exclude_none=True))

        tool_calls = msg.tool_calls or []
        if not tool_calls:
            print("Action: <none>")
            print("Observation: model did not call a tool; stopping.")
            break

        for tc in tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            print(f"Action: {name}({json.dumps(args, ensure_ascii=False)})")
            result = dispatch_tool(toolbox, name, args)
            print(f"Observation: {result.observation}\n")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": name,
                    "content": result.observation,
                }
            )
            if name == "solve_input" and result.ok:
                return


def main() -> None:
    parser = argparse.ArgumentParser(description="ReAct + angr crackme solver")
    parser.add_argument("--binary", default="./crackme", help="Path to compiled target binary")
    parser.add_argument("--source", default="./crackme.c", help="Path to crackme.c")
    parser.add_argument("--compile", action="store_true", help="Compile crackme.c before running")
    parser.add_argument("--cc", default="gcc", help="C compiler")
    parser.add_argument("--input-len", type=int, default=4, help="Number of symbolic stdin bytes before newline")
    parser.add_argument("--mock-llm", action="store_true", help="Use a deterministic mock ReAct planner instead of an API LLM")
    parser.add_argument("--model", default="gpt-4.1-mini", help="OpenAI model name for tool-calling mode")
    parser.add_argument("--max-rounds", type=int, default=6, help="Maximum LLM rounds in tool-calling mode")
    args = parser.parse_args()

    if args.compile:
        compile_target(args.source, args.binary, cc=args.cc)

    toolbox = AngrToolBox(binary_path=args.binary, input_len=args.input_len)
    if args.mock_llm:
        run_mock(toolbox)
    else:
        run_openai(toolbox, model=args.model, max_rounds=args.max_rounds)


if __name__ == "__main__":
    main()
