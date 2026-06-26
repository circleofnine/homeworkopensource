# ReAct + angr 自动化逆向分析实验

本工程实现一个简单的 ReAct 智能体：LLM 负责规划与工具选择，angr 负责符号执行、路径搜索和输入求解。目标是求解 `crackme.c` 中能触发 `Success! Flag is found.` 的输入。

## 文件结构

```text
.
├── agent_lab.py       # ReAct 主循环 + angr 工具封装
├── crackme.c          # 目标程序
├── requirements.txt   # Python 依赖
├── sample_run.log     # 不少于 3 轮的 Thought -> Action -> Observation 示例日志
└── report.md          # 实验报告草稿
```

## 环境安装

建议使用 Python 3.10 或 3.11。`angr` 对 Python 版本和二进制分析依赖较敏感，如果安装失败，优先新建干净虚拟环境。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

## 编译目标程序

```bash
gcc -O0 -g -no-pie crackme.c -o crackme
```

`-no-pie` 不是必须，但可以让符号地址更稳定，方便报告和日志对齐。

## 运行方式一：Mock ReAct 演示模式

该模式不需要 API key，但仍会调用同一套 angr 工具，适合生成可复现实验日志。

```bash
python agent_lab.py --binary ./crackme --mock-llm
```

也可以让脚本先编译再运行：

```bash
python agent_lab.py --compile --source ./crackme.c --binary ./crackme --mock-llm
```

## 运行方式二：真实 Tool Calling LLM

```bash
export OPENAI_API_KEY="你的 API key"
python agent_lab.py --binary ./crackme --model gpt-4.1-mini
```

## 预期结果

最终求得输入：

```text
AZcE
```

验证：

```bash
echo 'AZcE' | ./crackme
# Enter password: Success! Flag is found.
```

## Git 提交参考

```bash
git init
git add .
git commit -m "finish react angr reverse lab"
git remote add origin <你的仓库地址>
git push -u origin main
```
