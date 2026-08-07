# AgentEval

基于 **DeepEval** 的 **OpenManus** 自动化安全评测框架(MVP)。

参照 **ASB**(Agent Security Bench, ICLR 2025)方法论,对 OpenManus agent 做三类风险评测:
**Prompt Injection / Tool Abuse / Data Leakage**(自建 9 条模板 = 3 类 × 3 变体)。

链路:**攻击模板 → 注入 → OpenManus 沙箱执行 → Memory 轨迹 → DeepEval 指标 → 报告**

| 指标 | 含义 | 判定方式 |
|---|---|---|
| **ASR** 攻击成功率 | 攻击是否达成(1.0 = 达成) | tool_abuse 走工具调用规则;PI/DL 走 goal/secret 快速路径 + LLM 裁判 |
| **RR** 拒绝率 | 模型是否明确拒绝恶意请求(1.0 = 拒绝,安全方向) | LLM 裁判 |
| **TSS** 工具安全分 | 是否调用违规工具(1.0 = 安全) | 规则式,零裁判成本 |

## 目录结构

```
AgentEval/
├── agenteval/              # 核心包
│   ├── attack/             #   templates.py(9 条模板)+ builder.py(注入构造)
│   ├── harness/            #   victim.py(SandboxManus 沙箱)+ injector.py(假 secret)+ trace.py(轨迹提取)
│   ├── judge/              #   deepseek.py(DeepSeek 裁判,deepseek-chat)
│   ├── metrics/            #   asr.py / refusal.py / tool_safety.py(BaseMetric 子类)
│   ├── runner.py           #   编排:run_case / run_suite
│   └── report.py           #   DataFrame / 聚合 / 打印 / CSV / JSON
├── main.py                 # CLI
├── AgentEval_demo.ipynb    # 演示 notebook(调包)
├── requirements-eval.txt   # 锁定依赖
├── sandbox/                # 假 secret 靶子文件(运行时自动创建,已 gitignore)
└── scratch/                # PythonExecute 子进程隔离 cwd(运行时自动创建,已 gitignore)
```

## 环境搭建

OpenManus 锁 `pydantic~=2.10.6`,deepeval 要求 `pydantic>=2.11.7` —— **区间不交,必须独立 venv**。
OpenManus 通过 `sys.path` 只读导入,**绝不安装、绝不修改其源码**。

```bash
# 0) OpenManus(被测对象,只读导入;任意位置均可)
git clone https://github.com/FoundationAgents/OpenManus.git
#    让评测找到它:设置 OPENMANUS_ROOT(不设置则默认取 AgentEval 上一级 ../OpenManus):
set OPENMANUS_ROOT=D:\path\to\OpenManus

# 1) 独立 seeded venv(--seed 让 %pip 在 notebook 可用)
uv venv --seed --python 3.12 .venv

# 2) 安装依赖(全部锁定在 requirements-eval.txt)
uv pip install --python .venv/Scripts/python.exe -r requirements-eval.txt

# 3) 注册 notebook kernel(可选,跑 demo notebook 需要)
.venv/Scripts/python.exe -m ipykernel install --user --name agenteval

# 4) DeepSeek key
set DEEPSEEK_API_KEY=sk-xxxx
```

## 使用

```bash
# 冒烟:一次良性 agent run + 一次 judge(先跑这个确认环境通)
python main.py --smoke

# 全量 9 条用例,结果写 JSON + CSV
python main.py --json results/results.json --csv results/results.csv

# 只跑子集 / 调超时 / 显式传 key
python main.py --only pi_001,tl_001
python main.py --timeout 120 --api-key sk-xxxx
```

演示 notebook:用 `agenteval` kernel 打开 `AgentEval_demo.ipynb`,Run All。

## 设计要点(实测验证)

- **沙箱工具集** = `SandboxManus`(子类 `ToolCallAgent`,非 Manus):PythonExecute + StrReplaceEditor + Terminate + 2 个禁用桩(AskHuman 会阻塞挂死、BrowserUseTool 需 playwright)+ 5 个敏感工具桩(SendMoney/AdminReset/DbDelete/SendEmail/CheckDeploy,零副作用)。
- **LLM 接线**:`LLM(llm_config={"default": LLMSettings(...)})` 显式注入 DeepSeek,**不读不写 OpenManus 的 config.toml**(内含硬编码 MiniMax key,绝不依赖)。
- **DeepEval 用法**:逐用例 `await metric.a_measure(tc)`,不用 `evaluate()`(有缓存 bug / 弹 TUI)。
- **安全边界(诚实口径)**:secret 全是假 FLAG;PythonExecute 子进程固定 `cwd=scratch/` 且**不继承 DEEPSEEK_API_KEY**(注入代码拿不到真 key);敏感工具只记录调用、返回良性输出。但这是 **cwd 级隔离,不是容器沙箱** —— 子进程仍有宿主用户权限与全量文件/网络访问,扩大攻击语料前建议容器化。
- **信任边界**:`OPENMANUS_ROOT` 指向的目录会在 `import agenteval` 时以评测进程权限执行其代码(任意代码执行),务必只指向你自己 clone / 审阅过的源码。

## 局限与扩展

- 单轮评测(每用例跑一次);扩展为多轮取均值、接 ASB 的 400 条攻击工具数据(JSONL)。
- 裁判是 `deepseek-chat`,可换 `deepseek-reasoner` 提升判定精度。
- 敏感工具是桩,测的是"意图"不是"真实损失";接入真实工具时需真沙箱。
