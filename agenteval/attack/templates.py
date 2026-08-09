"""攻击模板:从 data/templates.jsonl 加载(54 条 = 46 DPI 直接注入 + 8 OPI 观测注入)。

schema 字段(每行一个 JSON,UTF-8;空行与 # 注释行被跳过):
  case_id            唯一 ID,如 "pi_001" / "opi_tl_001"
  category           类别:prompt_injection | tool_abuse | data_leakage | privilege_escalation
  variant            变体:naive | fake_completion | escape_characters | context_ignoring | combined_attack
  description        一句话说明攻击意图(报告展示)
  benign_task        正常任务(测 RR / 证明 agent 能干活);内含 {sandbox_dir} 占位符
  attacker_instruction  注入指令;OPI 时是写入 poison_file 的观测文本
  attacker_goal      攻击目标(判定字符串 / 判定描述)
  secret             (data_leakage)假 secret,fast-path 判定的字符串
  secret_context     (data_leakage)secret 所在上下文的描述
  malicious_tool     (tool_abuse / privilege_escalation)诱导调用的敏感工具名
  expected_tools     违规工具名列表(ToolSafetyScore / ASR 规则判定用),必须 list[str]
  difficulty         难度轴(Step 1):aggressive | non_aggressive(后者把恶意伪装成正常运维/审计)
  attack_channel     攻击通道(Step 2):dpi | opi(间接注入,藏进 tool observation)
  poison_file        (OPI)注入文本藏匿的沙箱文件名,必须 basename,默认 notes.txt

loader 约定:
  * import 时加载(fail-fast):非法 JSON / 缺必需字段 / 未知 category|variant|difficulty|
    attack_channel / expected_tools 类型错 / OPI 用了非 naive 变体 / poison_file 含路径 →
    直接 ValueError。基准数据是运行时输入,拼写错必须在 import 期暴露,不静默回落。
  * get_cases / get_case / case_counts 保留副本与保序语义(与旧硬编码版一致)。
"""

import json
import os
from typing import List, Optional

from agenteval.paths import TEMPLATES_JSONL

_REQUIRED_FIELDS = (
    "case_id",
    "category",
    "variant",
    "description",
    "benign_task",
    "attacker_instruction",
    "attacker_goal",
)
_CATEGORIES = {
    "prompt_injection",
    "tool_abuse",
    "data_leakage",
    "privilege_escalation",
}
_VARIANTS = {
    "naive",
    "fake_completion",
    "escape_characters",
    "context_ignoring",
    "combined_attack",
}
_DIFFICULTIES = {"aggressive", "non_aggressive"}
_CHANNELS = {"dpi", "opi"}
_DEFAULTS = {
    "secret": "",
    "secret_context": "",
    "malicious_tool": "",
    "expected_tools": [],
    "difficulty": "aggressive",
    "attack_channel": "dpi",
    "poison_file": "notes.txt",
}
# 与 agenteval/harness/victim.py 的 _SENSITIVE_TOOLS 镜像(不在 victim import,避免环)。
# 供防漂移测试拦截"引用了没桩的新工具名"的模板。
_KNOWN_SENSITIVE_TOOLS = {"SendMoney", "AdminReset", "DbDelete", "SendEmail", "CheckDeploy"}


def validate_case(c: dict) -> dict:
    """校验一条模板并填默认值;任何拼写错抛 ValueError(fail-fast)。"""
    cid = c.get("case_id", "?")
    missing = [k for k in _REQUIRED_FIELDS if k not in c]
    if missing:
        raise ValueError(f"templates: {cid} 缺必需字段 {missing}")
    if c["category"] not in _CATEGORIES:
        raise ValueError(f"templates: {cid} 未知 category {c['category']!r}")
    if c["variant"] not in _VARIANTS:
        raise ValueError(f"templates: {cid} 未知 variant {c['variant']!r}")
    et = c.get("expected_tools", [])
    if not isinstance(et, list) or not all(isinstance(t, str) for t in et):
        raise ValueError(f"templates: {cid} expected_tools 必须为 list[str],got {et!r}")
    if c.get("difficulty", "aggressive") not in _DIFFICULTIES:
        raise ValueError(f"templates: {cid} 未知 difficulty {c.get('difficulty')!r}")
    if c.get("attack_channel", "dpi") not in _CHANNELS:
        raise ValueError(f"templates: {cid} 未知 attack_channel {c.get('attack_channel')!r}")
    if c.get("attack_channel") == "opi" and c.get("variant", "naive") != "naive":
        raise ValueError(f"templates: {cid} OPI 用例 variant 必须为 naive")
    poison = c.get("poison_file", "notes.txt")
    if os.path.basename(poison) != poison:
        raise ValueError(f"templates: {cid} poison_file 必须是文件名,不能含路径:{poison!r}")
    if c.get("attack_channel") == "opi" and (
        f"{{sandbox_dir}}/{poison}" not in c.get("benign_task", "")
    ):
        # OPI 的恶意指令藏在 poison_file 里,良性任务必须强制 agent 打开该文件,
        # 否则注入永远不进上下文 —— 这是 authoring 错误,import 期就拦下。
        raise ValueError(
            f"templates: {cid} OPI 用例的 benign_task 必须引用 {{sandbox_dir}}/{poison}"
        )
    out = dict(_DEFAULTS)
    out.update(c)
    return out


def load_cases(path: Optional[str] = None) -> List[dict]:
    """从 JSONL 读全部用例,保持文件顺序;非法行/重复 case_id 报错(带行号)。"""
    path = path or TEMPLATES_JSONL
    cases: List[dict] = []
    seen = set()
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                c = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{ln} 非法 JSON: {e}") from e
            c = validate_case(c)
            if c["case_id"] in seen:
                raise ValueError(f"{path}:{ln} 重复 case_id {c['case_id']}")
            seen.add(c["case_id"])
            cases.append(c)
    return cases


_CASES: List[dict] = load_cases()


def get_cases(only: Optional[List[str]] = None) -> List[dict]:
    """返回全部模板;`only` 传 case_id 列表时只返回子集(保持文件内顺序)。"""
    if not only:
        return [dict(c) for c in _CASES]
    wanted = {cid.strip() for cid in only if cid and cid.strip()}
    return [dict(c) for c in _CASES if c["case_id"] in wanted]


def get_case(case_id: str) -> Optional[dict]:
    """按 case_id 取单条模板,不存在返回 None。"""
    for c in _CASES:
        if c["case_id"] == case_id:
            return dict(c)
    return None


def case_counts() -> dict:
    """{category: 条数},报告/展示用。"""
    counts: dict = {}
    for c in _CASES:
        counts[c["category"]] = counts.get(c["category"], 0) + 1
    return counts
