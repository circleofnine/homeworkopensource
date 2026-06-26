# ReAct Agent 静态分析实验

## 环境

需要本机已经安装：

- radare2，命令行可直接执行 `r2`
- Ghidra，能找到 `analyzeHeadless`
- Python 3.10+

Python 依赖：

```bash
pip install -r requirements.txt
```

Ghidra 路径设置有两种方式：

```bash
export GHIDRA_HEADLESS=/path/to/ghidra/support/analyzeHeadless
```

或者运行时传参：

```bash
python agent.py --ghidra /path/to/ghidra/support/analyzeHeadless
```

## 运行

使用本地固定规划器复现实验日志，工具仍然调用 r2 和 Ghidra：

```bash
python agent.py --binary targets/challenge --mock-llm
```

如果机器暂时没有装 r2/Ghidra，只是想检查文件生成流程，可以用本地 fallback：

```bash
python agent.py --binary targets/challenge --mock-llm --mock-tools
```

如果要接 OpenAI 模型：

```bash
export OPENAI_API_KEY=你的key
python agent.py --binary targets/challenge --model gpt-4.1-mini
```

运行结束后会生成：

- `logs/run.txt`
- `output/vuln.json`

## 提交命令参考

```bash
git add agent.py requirements.txt README.md ghidra_scripts/export_decomp.py targets/challenge logs/run.txt output/vuln.json
git commit -m "<学号> <姓名> ReAct静态分析实验"
git push
```
