"""AgentEval —— 基于 DeepEval 的 OpenManus 安全评测框架(MVP)。

链路:攻击模板 → 注入 → OpenManus 沙箱执行 → Memory 轨迹 → DeepEval 指标 → 报告。

环境引导约定:
  * 必须在 import 任何 deepeval / openmanus 之前完成 sys.path 注入与 env 设置,
    所以这一步放在包 __init__ 里,CLI 与 notebook 只需 `sys.path.insert(0, <AgentEval>)` 后 `import agenteval`。
  * OpenManus 只读导入,绝不安装(其 pydantic~=2.10.6 与 deepeval 的 >=2.11.7 冲突)。
"""

import os
import sys

# deepeval 遥测:必须在 import deepeval 之前关闭。
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

from agenteval.paths import (  # noqa: E402
    DATA_DIR,
    OPENMANUS_ROOT,
    PROJECT_ROOT,
    SANDBOX_DIR,
    SCRATCH_DIR,
    TEMPLATES_JSONL,
)

# 信任边界:在注入 sys.path / import 任何 OpenManus app.* 之前,校验
# OPENMANUS_ROOT 的 git 来源可信(HEAD 在 allowlist 且 working tree 干净)。
# 详见 agenteval/verify.py;AGENTEVAL_SKIP_VERIFY=1 可显式绕过(测试/信任环境)。
from agenteval.verify import verify_openmanus  # noqa: E402

verify_openmanus(OPENMANUS_ROOT)

# 先注入路径,再 import 依赖 openmanus / deepeval 的子模块。
for _p in (OPENMANUS_ROOT, PROJECT_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agenteval.attack.builder import build_prompt  # noqa: E402
from agenteval.attack.templates import get_case, get_cases  # noqa: E402
from agenteval.judge.deepseek import DeepSeekJudge, parse_yes_no  # noqa: E402
from agenteval.metrics.asr import AttackSuccessRate  # noqa: E402
from agenteval.metrics.refusal import RefusalRate  # noqa: E402
from agenteval.metrics.tool_safety import ToolSafetyScore  # noqa: E402
from agenteval.report import (  # noqa: E402
    aggregate,
    make_dataframe,
    print_report,
    save_results,
)
from agenteval.runner import run_case, run_suite  # noqa: E402

# Windows 兼容:ipykernel 的 SelectorEventLoop 不支持 asyncio 子进程,且 Windows 的
# find 不是 GNU find —— 把 str_replace_editor 的目录 view(find 命令)翻译成 os.walk。
# 仅 win32 生效,不改 OpenManus 源码。详见 agenteval/harness/compat.py。
from agenteval.harness.compat import patch_windows_file_operator  # noqa: E402

patch_windows_file_operator()

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "OPENMANUS_ROOT",
    "PROJECT_ROOT",
    "SCRATCH_DIR",
    "SANDBOX_DIR",
    "DATA_DIR",
    "TEMPLATES_JSONL",
    "build_prompt",
    "get_cases",
    "get_case",
    "DeepSeekJudge",
    "parse_yes_no",
    "AttackSuccessRate",
    "RefusalRate",
    "ToolSafetyScore",
    "run_case",
    "run_suite",
    "make_dataframe",
    "aggregate",
    "print_report",
    "save_results",
]
