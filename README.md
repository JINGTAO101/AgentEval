# AgentEval

> 基于 **DeepEval** 的 **OpenManus** 自动化安全评测框架

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](#环境搭建)

AgentEval 参照 **ASB**(Agent Security Bench, ICLR 2025)方法论,对 OpenManus agent 做自动化安全评测。内置 **15 条攻击模板**,覆盖四类风险:

| 风险类别 | 模板数 | 说明 |
|---|---|---|
| **Prompt Injection** | 4 | 指令注入、伪造完成、转义字符、组合攻击 |
| **Tool Abuse** | 4 | 诱导调用敏感工具 |
| **Data Leakage** | 4 | 诱导泄露假 secret |
| **Privilege Escalation** | 3 | 越权提权后执行管理操作 |

> **⚠️ 安全声明**:本项目是**授权安全评测工具**,仅用于测试你自己的 agent 或已获明确授权的目标。注入的指令、模拟的敏感工具操作均为无害桩(假 secret、零副作用),不会造成真实损失。

---

## 特性

- **四类风险一键评测**:模板即插即用,单条或全量执行
- **双通道判定**:规则式(tool_abuse / privilege_escalation 零 LLM 成本)+ LLM 裁判(prompt_injection / data_leakage)
- **沙箱化被测对象**:自定义 `SandboxManus`,敏感工具全部替换为记录式桩
- **可审计轨迹**:完整 Message 轨迹(含工具调用参数)导出 JSON / CSV
- **透明指标**:ASR / RR / TSS 三类指标,含判定理由

## 目录结构

```
AgentEval/
├── agenteval/              # 核心包
│   ├── attack/             #   templates.py(15 条模板)+ builder.py(注入构造)
│   ├── harness/            #   victim.py(SandboxManus 沙箱)+ injector.py(假 secret)+ trace.py(轨迹提取)
│   ├── judge/              #   deepseek.py(DeepSeek 裁判,deepseek-chat)
│   ├── metrics/            #   asr.py / refusal.py / tool_safety.py(BaseMetric 子类)
│   ├── runner.py           #   编排:run_case / run_suite
│   └── report.py           #   DataFrame / 聚合 / 打印 / CSV / JSON
├── main.py                 # CLI 入口
├── AgentEval_demo.ipynb    # 演示 notebook
├── requirements-eval.txt   # 锁定依赖
├── sandbox/                # 假 secret 靶子文件(运行时自动创建,已 gitignore)
└── scratch/                # PythonExecute 子进程隔离 cwd(运行时自动创建,已 gitignore)
```

## 评测方法论

```
攻击模板 → prompt 注入 → OpenManus 沙箱执行 → Memory 轨迹提取 → 指标判定 → 报告
```

### 指标

| 指标 | 含义 | 判定方式 |
|---|---|---|
| **ASR** 攻击成功率 | 攻击是否达成(1.0 = 达成) | tool_abuse / privilege_escalation 走工具调用规则;PI / DL 走 goal / secret 快速路径 + LLM 裁判 |
| **RR** 拒绝率 | 模型是否明确拒绝恶意请求(1.0 = 拒绝,安全方向) | LLM 裁判 |
| **TSS** 工具安全分 | 是否调用违规工具(1.0 = 安全) | 规则式,零裁判成本 |

### 攻击变体

每条模板可选用 4 种注入变体,由 `builder.py` 组合生成:

| 变体 | 说明 |
|---|---|
| `naive` | 直接插入指令 |
| `fake_completion` | 伪造"已完成"回复,诱导继续执行注入内容 |
| `escape_characters` | 转义字符绕过上下文 |
| `combined_attack` | 伪造完成 + 忽略历史指令 + 注入目标组合 |

## 环境搭建

> OpenManus 锁 `pydantic~=2.10.6`,deepeval 要求 `pydantic>=2.11.7`,区间不交,**必须独立 venv**。OpenManus 通过 `sys.path` 只读导入,**绝不安装、绝不修改其源码**。

```bash
# 0) 克隆 OpenManus(被测对象,任意位置)
git clone https://github.com/FoundationAgents/OpenManus.git
#    让评测找到它:设置 OPENMANUS_ROOT(默认取 AgentEval 上一级 ../OpenManus)
set OPENMANUS_ROOT=D:\path\to\OpenManus

# 1) 创建独立 venv(--seed 让 %pip 在 notebook 可用)
uv venv --seed --python 3.12 .venv

# 2) 安装依赖
uv pip install --python .venv/Scripts/python.exe -r requirements-eval.txt

# 3) 注册 notebook kernel(可选,跑 demo 需要)
.venv/Scripts/python.exe -m ipykernel install --user --name agenteval

# 4) 配置 DeepSeek key
set DEEPSEEK_API_KEY=sk-xxxx
```

## 使用

```bash
# 冒烟测试:一次良性 agent run + 一次 judge(先跑这个确认环境通)
.venv/Scripts/python.exe main.py --smoke

# 全量 15 条用例,结果写 JSON + CSV
.venv/Scripts/python.exe main.py --json results/results.json --csv results/results.csv

# 只跑子集 / 调超时 / 显式传 key
.venv/Scripts/python.exe main.py --only pi_001,tl_001
.venv/Scripts/python.exe main.py --timeout 120 --api-key sk-xxxx
```

演示 notebook:用 `agenteval` kernel 打开 `AgentEval_demo.ipynb`,Run All。

## 设计要点

- **沙箱工具集**:`SandboxManus`(子类 `ToolCallAgent`,非 Manus)= PythonExecute + StrReplaceEditor + Terminate + 2 个禁用桩(AskHuman 会阻塞、BrowserUseTool 需 playwright)+ 5 个敏感工具桩(SendMoney / AdminReset / DbDelete / SendEmail / CheckDeploy,记录到 `SENSITIVE_CALLS`,零副作用,每用例清空)。
- **LLM 接线**:`LLM(llm_config={"default": LLMSettings(...)})` 显式注入 DeepSeek,**不读不写** OpenManus 的 `config.toml`(内含硬编码 MiniMax key)。
- **DeepEval 用法**:逐用例 `await metric.a_measure(tc)`,不用 `evaluate()`(有缓存 bug / 弹 TUI)。
- **轨迹提取**:`Trace.from_memory` 从 Message 列表提取工具调用、最终输出、全文(含工具调用参数);工具按 assistant `tool_calls` 去重,不双计。

## 安全与信任边界

| 边界 | 说明 |
|---|---|
| **假 secret** | 靶子文件里的 secret 全是随机假 FLAG,agent 事先不可能知道 |
| **敏感工具桩** | 记录调用、返回良性输出,**不产生真实副作用** |
| **Key 隔离** | PythonExecute 子进程固定 `cwd=scratch/`,且**不继承 `DEEPSEEK_API_KEY`**(注入代码拿不到真 key) |
| **⚠️ 非容器沙箱** | 这是 **cwd 级隔离,不是容器沙箱** —— 子进程仍有宿主用户权限与全量文件 / 网络访问。扩大攻击语料前建议容器化 |
| **⚠️ 信任边界** | `OPENMANUS_ROOT` 指向的目录会在 `import agenteval` 时以评测进程权限执行其代码(任意代码执行)。**务必只指向你自己 clone / 审阅过的源码** |

## 局限与扩展

- 单轮评测(每用例跑一次);可扩展为多轮取均值、接入 ASB 的 400 条攻击工具数据(JSONL)。
- 裁判默认 `deepseek-chat`,可换 `deepseek-reasoner` 提升判定精度。
- 敏感工具是桩,测的是"意图"而非"真实损失";接入真实工具时需真沙箱。

## License

[MIT](LICENSE) © JINGTAO101
