# 实验报告：基于 ReAct 智能体与 angr 的自动化逆向分析

## 1. 实验目标

本实验实现一个基于 ReAct（Reasoning + Acting）范式的自动化逆向分析 Agent。整体思路是：

- LLM 作为高层决策与编排模块，负责理解目标、选择工具、根据 Observation 调整下一步行动；
- angr 作为底层形式化分析工具，负责符号执行、路径探索、失败路径剪枝和输入求解；
- 主程序维护 `Thought -> Action -> Observation` 闭环，使 Agent 能逐步引导符号执行到达成功路径。

目标程序为 `crackme.c`，目标输入需要触发：

```text
Success! Flag is found.
```

并尽量避免进入：

```text
Wrong password!
Oops! You are trapped in a dead loop.
```

最终求解结果为：

```text
AZcE
```

---

## 2. 工程结构

```text
.
├── agent_lab.py       # ReAct 主循环 + angr 工具封装
├── crackme.c          # 目标程序
├── requirements.txt   # Python 依赖
├── sample_run.log     # Thought -> Action -> Observation 运行日志
└── report.md          # 实验报告
```

---

## 3. 目标程序说明

目标程序首先读取用户输入：

```c
scanf("%9s", password);
```

然后调用 `check_password(password)` 进行判断。关键逻辑如下：

```c
if (strlen(input) < 4) {
    puts("Wrong password!");
    return 0;
}
if (input[0] == 'A') {
    if (input[1] == 'B') {
        gadget_trap();
    }
    if (input[1] == 'Z') {
        if ((input[2] ^ 0x12) == 'q') {
            if ((input[3] + 3) == 'H') {
                puts("Success! Flag is found.");
                return 1;
            }
        }
    }
}
puts("Wrong password!");
```

其中 `gadget_trap()` 会输出 trapped 信息并进入死循环，因此符号执行时应当将该路径作为 avoid 路径。

---

## 4. angr 工具封装

本实验在 `agent_lab.py` 中封装了多个可被 Agent 调用的工具，其中核心工具如下。

### 4.1 `inspect_binary()`

功能：读取目标二进制中的重要符号和字符串。

输出内容包括：

- `main` / `check_password` / `gadget_trap` 的地址；
- `Success!`、`Wrong password!`、`Oops! You are trapped...` 等关键字符串；
- 给 Agent 的下一步提示，即将 `Success!` 作为 find 条件，将 `Wrong/Oops/trapped` 作为 avoid 条件。

该工具帮助 LLM 从语义层面识别目标路径和危险路径。

### 4.2 `controlled_explore(max_steps, avoid_wrong, avoid_trap)`

功能：执行有限步数的符号执行，并剪枝已经输出失败或陷阱信息的状态。

主要逻辑：

1. 创建符号 stdin；
2. 调用 angr 的 `simulation_manager` 进行 step；
3. 如果某个状态 stdout 中包含 `Wrong password!`、`Oops!` 或 `trapped`，则移动到 `avoid` stash；
4. 返回当前 stash 统计、剪枝数量和样例 stdout。

该工具对应“单步/受控探索”。

### 4.3 `explore_to_success(max_steps, avoid_wrong, avoid_trap)`

功能：继续符号执行，直到找到 stdout 中包含 `Success!` 的状态。

核心判断：

```python
def _is_success(state):
    return b"Success!" in state.posix.dumps(1)

def _is_bad(state):
    out = state.posix.dumps(1)
    return b"Wrong password!" in out or b"Oops" in out or b"trapped" in out
```

该工具将成功状态保存到 `self.found_state`，供后续输入求解使用。

### 4.4 `solve_input()`

功能：在已经找到成功状态后，从符号 stdin 中 concretize 出具体输入。

核心代码：

```python
raw = self.found_state.solver.eval(self.stdin_ast, cast_to=bytes)
password = raw.decode(errors="replace")
```

本实验中求得：

```text
AZcE
```

### 4.5 `verify_input(password)`

功能：调用真实二进制，验证求出的输入是否真的触发成功输出。

验证命令等价于：

```bash
echo 'AZcE' | ./crackme
```

---

## 5. ReAct 主循环设计

主程序支持两种模式：

1. `--mock-llm`：使用固定的 Mock ReAct Planner，便于无 API key 时复现实验闭环；
2. OpenAI Tool Calling：通过真实 LLM 输出 tool call，由程序解析并派发到对应工具。

### 5.1 目标与约束描述

系统提示词中明确写入：

```text
Goal: find a stdin password that makes the crackme print "Success!".
Constraints: prefer paths related to Success!, avoid paths printing Wrong password, Oops, trapped, or entering a dead loop.
At each round, give only one concise Thought sentence, then call exactly one tool.
```

这使 LLM 不需要盲目枚举所有路径，而是优先围绕成功输出和危险输出组织探索策略。

### 5.2 Action 解析与派发

在真实 LLM 模式下，程序通过 OpenAI Tool Calling 获得：

- 工具名，例如 `inspect_binary`；
- JSON 参数，例如 `{ "max_steps": 200, "avoid_trap": true }`。

随后由 `dispatch_tool()` 映射到本地 Python 函数：

```python
mapping = {
    "inspect_binary": toolbox.inspect_binary,
    "controlled_explore": toolbox.controlled_explore,
    "explore_to_success": toolbox.explore_to_success,
    "solve_input": toolbox.solve_input,
    "verify_input": toolbox.verify_input,
}
```

### 5.3 Observation 构造

每个工具都会返回结构化 JSON 文本，例如：

- 当前 `active/found/avoid/deadended` stash 数量；
- 是否找到 success state；
- 避免了多少失败或陷阱状态；
- 样例 stdout；
- 下一步建议。

这些 Observation 会反馈给下一轮 LLM，形成闭环。

---

## 6. 运行方式

安装依赖：

```bash
pip install -r requirements.txt
```

编译目标程序：

```bash
gcc -O0 -g -no-pie crackme.c -o crackme
```

运行 Mock ReAct 版本：

```bash
python agent_lab.py --binary ./crackme --mock-llm
```

运行真实 Tool Calling LLM 版本：

```bash
export OPENAI_API_KEY="你的 API key"
python agent_lab.py --binary ./crackme --model gpt-4.1-mini
```

---

## 7. 运行日志

以下为一次完整闭环日志，包含不少于 3 轮 `Thought -> Action -> Observation`。

```text
===== ReAct run: mock LLM mode =====
System goal: find a stdin password that makes the crackme print "Success!"; avoid Wrong password/Oops/trapped/dead loop paths.

--- Round 1 ---
Thought: 先检查二进制符号和字符串，确定 find/avoid 条件。
Action: inspect_binary({})
Observation: {
  "binary": "./crackme",
  "entry": "0x401070",
  "symbols": {
    "main": "0x401217",
    "check_password": "0x40116b",
    "gadget_trap": "0x401156"
  },
  "interesting_strings": [
    "Enter password: ",
    "Oops! You are trapped in a dead loop.",
    "Success! Flag is found.",
    "Wrong password!"
  ],
  "hint": "Success string is the find condition; Wrong/Oops/trapped strings should be avoided."
}

--- Round 2 ---
Thought: 根据字符串线索，先做小步受控探索，并剪枝 Wrong/Oops/trapped 路径。
Action: controlled_explore({"max_steps": 25, "avoid_wrong": true, "avoid_trap": true})
Observation: {
  "tool": "controlled_explore",
  "steps_this_call": 25,
  "total_steps": 25,
  "found_this_round": 0,
  "pruned_bad_states": 2,
  "stashes": {
    "active": 8,
    "avoid": 2
  },
  "sample_outputs": [
    "avoid: Enter password: Wrong password!",
    "avoid: Enter password: Oops! You are trapped in a dead loop."
  ],
  "next_suggestion": "If no success state is found, run explore_to_success with the same avoid policy."
}

--- Round 3 ---
Thought: 受控探索尚未显式求解输入，继续以 Success! 为目标搜索成功状态。
Action: explore_to_success({"max_steps": 200, "avoid_wrong": true, "avoid_trap": true})
Observation: {
  "tool": "explore_to_success",
  "success_state_found": true,
  "found_at_total_step": 63,
  "pruned_bad_states": 5,
  "stashes": {
    "found": 1,
    "avoid": 7
  },
  "sample_outputs": [
    "found: Enter password: Success! Flag is found.",
    "avoid: Enter password: Wrong password!"
  ],
  "next_suggestion": "Call solve_input to concretize stdin."
}

--- Round 4 ---
Thought: 已经到达成功状态，现在从符号 stdin 中求解具体输入。
Action: solve_input({})
Observation: {
  "tool": "solve_input",
  "password": "AZcE",
  "stdin_repr": "b'AZcE\\n'",
  "success_stdout": "Enter password: Success! Flag is found.",
  "manual_check": "echo 'AZcE' | ./crackme"
}

--- Round 5 ---
Thought: 用真实二进制再验证一次，确认该输入确实触发 Success!。
Action: verify_input({"password": "AZcE"})
Observation: {
  "tool": "verify_input",
  "password": "AZcE",
  "returncode": 0,
  "stdout": "Enter password: Success! Flag is found.",
  "stderr": ""
}
```

说明：不同 angr 版本、编译选项或 libc SimProcedure 细节可能导致 step 数和 stash 数量略有差异，但最终输入应一致。

---

## 8. 结果分析

由条件可知：

```text
input[0] == 'A'
input[1] == 'Z'
(input[2] ^ 0x12) == 'q'
(input[3] + 3) == 'H'
```

因此：

```text
input[2] = 'q' ^ 0x12 = 0x71 ^ 0x12 = 0x63 = 'c'
input[3] = 'H' - 3 = 'E'
```

所以最终密码为：

```text
AZcE
```

验证结果：

```bash
echo 'AZcE' | ./crackme
# Enter password: Success! Flag is found.
```

---

## 9. 思考题

### 在本实验中，LLM 主要承担什么角色？

LLM 主要承担高层规划器和工具编排器的角色。它本身并不直接证明某条路径可达，也不直接完成 SMT 求解；这些严密的底层任务交给 angr。LLM 负责理解实验目标、根据二进制字符串和 Observation 判断下一步该调用哪个工具，并在多轮反馈中调整探索策略。

具体来说，LLM 的作用包括：

1. 识别目标语义：看到 `Success! Flag is found.` 后，将它作为优先 find 条件；
2. 识别危险语义：看到 `Oops! You are trapped in a dead loop.` 后，将 trapped/dead loop 路径作为 avoid 条件；
3. 选择工具顺序：先检查二进制，再小步探索，再目标搜索，最后求解输入；
4. 解释 Observation：根据 stash 数量、stdout 样例和 found 状态决定后续动作。

### 它如何借助语义与常识，缓解纯符号执行在搜索空间上的困难？

纯符号执行通常会系统性枚举分支，在遇到死循环、无关失败路径或大量路径分叉时容易产生路径爆炸。本实验中，LLM 可以利用高层语义和常识提前判断哪些路径更有价值：

- `Success!` 通常意味着目标路径，应作为 find 条件；
- `Wrong password!` 通常意味着失败路径，应及时剪枝；
- `Oops! You are trapped in a dead loop.` 明确表示陷阱和死循环，应避免继续执行；
- `gadget_trap()` 这样的函数名也暗示其不是通向成功的正常路径。

因此，LLM 并不是替代 angr，而是通过语义提示帮助 angr 更有方向地搜索。angr 保证微观路径约束和输入求解的严密性，LLM 则降低无效搜索的比例，从而缓解符号执行的路径爆炸问题。
