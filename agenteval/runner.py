"""评测编排:单用例与全量执行。

链路:模板 → build_prompt 注入 → OpenManus 沙箱执行 → Trace 提取 →
  LLMTestCase 组装 → 三个 DeepEval 指标 a_measure → 结果 dict。
"""

import asyncio
import os
import time

from deepeval.test_case import LLMTestCase, ToolCall as DeepEvalToolCall

from agenteval.attack.builder import build_prompt
from agenteval.harness.injector import prepare_sandbox
from agenteval.harness.trace import Trace
from agenteval.harness.victim import SENSITIVE_CALLS, make_agent
from agenteval.judge.deepseek import DeepSeekJudge
from agenteval.metrics.asr import AttackSuccessRate
from agenteval.metrics.refusal import RefusalRate
from agenteval.metrics.tool_safety import ToolSafetyScore
from agenteval.paths import SANDBOX_DIR, SCRATCH_DIR


def _ensure_scratch() -> None:
    """确保 scratch 目录存在并切过去(PythonExecute 子进程隔离 cwd)。"""
    os.makedirs(SCRATCH_DIR, exist_ok=True)
    os.chdir(SCRATCH_DIR)


async def run_case(
    case: dict,
    judge: DeepSeekJudge,
    *,
    api_key: str | None = None,
    max_steps: int = 6,
    timeout: float = 180.0,
    sandbox_dir: str | None = None,
) -> dict:
    """执行单个攻击用例,返回一行评测结果(dict,含完整 trace 供 JSON 审计)。"""
    _ensure_scratch()
    SENSITIVE_CALLS.clear()

    prompt = build_prompt(case, sandbox_dir=sandbox_dir)
    agent = make_agent(api_key=api_key, max_steps=max_steps)

    t0 = time.perf_counter()
    try:
        await asyncio.wait_for(agent.run(prompt), timeout=timeout)
        status = "ok"
    except asyncio.TimeoutError:
        status = "timeout"
    except Exception as e:  # noqa: BLE001 —— 用例级异常必须被捕获并记入结果
        status = f"error:{type(e).__name__}:{e}"
    elapsed = time.perf_counter() - t0

    trace = Trace.from_memory(agent.memory.messages)

    # metadata = 用例 dict + 私钥 "_all_text"(全文,供 ASR 的 secret/goal fast-path 扫描)。
    metadata = {**case, "_all_text": trace.all_text}
    tc = LLMTestCase(
        input=prompt,
        actual_output=trace.final_output,
        metadata=metadata,
        tools_called=[DeepEvalToolCall(name=n) for n in trace.tools_called],
        expected_tools=[
            DeepEvalToolCall(name=n) for n in case.get("expected_tools", [])
        ],
    )

    asr = AttackSuccessRate(judge=judge)
    rr = RefusalRate(judge=judge)
    tss = ToolSafetyScore()

    if status == "ok":
        asr_score = await asr.a_measure(tc)
        rr_score = await rr.a_measure(tc)
    else:
        # 执行本身失败(超时/异常):攻击判定无意义,保守记 0。
        asr_score = 0.0
        rr_score = 0.0
    tss_score = await tss.a_measure(tc)

    return {
        "case_id": case["case_id"],
        "category": case["category"],
        "variant": case.get("variant", ""),
        "description": case.get("description", ""),
        "status": status,
        "seconds": round(elapsed, 2),
        "asr": round(float(asr_score), 3),
        "rr": round(float(rr_score), 3),
        "tss": round(float(tss_score), 3),
        "asr_reason": asr.reason,
        "rr_reason": rr.reason,
        "tss_reason": tss.reason,
        "tools_called": trace.tools_called,
        "final_output": trace.final_output,
        "trace_messages": trace.messages,
    }


async def run_suite(
    cases: list,
    judge: DeepSeekJudge,
    *,
    api_key: str | None = None,
    max_steps: int = 6,
    timeout: float = 180.0,
    sandbox_dir: str | None = None,
    progress=None,
) -> list:
    """顺序执行一批用例(顺序保证 trace 与成本可控)。

    `progress(i, total, case_id)` 可选回调,CLI/notebook 打印进度用。
    """
    prepare_sandbox(sandbox_dir)
    results = []
    total = len(cases)
    for i, case in enumerate(cases, 1):
        if progress is not None:
            progress(i, total, case["case_id"])
        result = await run_case(
            case,
            judge,
            api_key=api_key,
            max_steps=max_steps,
            timeout=timeout,
            sandbox_dir=sandbox_dir,
        )
        results.append(result)
    return results
