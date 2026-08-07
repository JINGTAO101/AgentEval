#!/usr/bin/env python3
"""AgentEval CLI —— OpenManus 安全评测(MVP)。

用法:
  python main.py --smoke                          # 冒烟:一次良性 agent run + 一次 judge
  python main.py --json results/results.json      # 跑全部 9 条用例
  python main.py --only pi_001,tl_001             # 跑子集
  python main.py --timeout 120 --api-key sk-...   # 调超时 / 显式给 key

key 缺省读环境变量 DEEPSEEK_API_KEY。
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import agenteval  # noqa: E402 —— 包自身会注入 OpenManus 路径并 import deepeval
from agenteval.attack.templates import get_cases  # noqa: E402
from agenteval.judge.deepseek import DeepSeekJudge  # noqa: E402
from agenteval.report import (  # noqa: E402
    aggregate,
    make_dataframe,
    print_report,
    save_results,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AgentEval — OpenManus 安全评测(MVP)")
    p.add_argument("--smoke", action="store_true", help="只跑冒烟:一次良性 agent run + 一次 judge 调用")
    p.add_argument("--only", type=str, default="", help="逗号分隔的 case_id 子集,如 pi_001,tl_001")
    p.add_argument("--json", type=str, default="results/results.json", help="JSON 结果输出路径(相对项目根)")
    p.add_argument("--csv", type=str, default="", help="CSV 明细输出路径(相对项目根),默认不输出")
    p.add_argument("--timeout", type=float, default=180.0, help="每用例 agent 执行超时(秒)")
    p.add_argument("--max-steps", type=int, default=6, help="每用例 agent 最大步数")
    p.add_argument("--api-key", type=str, default=None, help="DeepSeek API key(缺省读 env DEEPSEEK_API_KEY)")
    return p.parse_args()


async def smoke(api_key: str | None) -> None:
    """冒烟:被测路径(agent.run)+ 裁判路径(a_ask)各验一次。"""
    from agenteval.harness.victim import make_agent

    print("[smoke] 被测路径:良性 agent run ...")
    agent = make_agent(api_key=api_key)
    out = await asyncio.wait_for(agent.run("Reply exactly: SMOKE_OK"), timeout=120)
    assert "SMOKE_OK" in out, f"agent 未回复 SMOKE_OK,实际:{out!r}"
    print(f"[smoke] agent OK -> {out!r}  (memory 步数={len(agent.memory.messages)})")

    print("[smoke] 裁判路径:DeepSeek judge ...")
    judge = DeepSeekJudge(api_key=api_key)
    ans = await judge.a_ask("Answer with a single token YES or NO: is 2+2=4?")
    assert ans.upper() in ("YES", "NO"), f"judge 未返回 YES/NO,实际:{ans!r}"
    print(f"[smoke] judge OK -> {ans}")
    print("SMOKE PASSED")


async def run_eval(args: argparse.Namespace) -> None:
    cases = get_cases(only=args.only.split(",") if args.only else None)
    print(f"[eval] {len(cases)} 条用例:{', '.join(c['case_id'] for c in cases)}")
    judge = DeepSeekJudge(api_key=args.api_key)

    def _progress(i, total, cid):
        print(f"  [{i}/{total}] {cid} ...", flush=True)

    results = await agenteval.run_suite(
        cases,
        judge,
        api_key=args.api_key,
        max_steps=args.max_steps,
        timeout=args.timeout,
        progress=_progress,
    )

    df = make_dataframe(results)
    agg = aggregate(df)
    print_report(df, agg)

    saved = save_results(results, json_path=args.json, csv_path=args.csv or None)
    print(f"[eval] 已保存:{saved}")


def main() -> None:
    args = parse_args()
    if not (args.api_key or os.environ.get("DEEPSEEK_API_KEY")):
        raise SystemExit(
            "未提供 DeepSeek API key:用 --api-key 传入或设置环境变量 DEEPSEEK_API_KEY"
        )
    if args.smoke:
        asyncio.run(smoke(args.api_key))
    else:
        asyncio.run(run_eval(args))


if __name__ == "__main__":
    main()
