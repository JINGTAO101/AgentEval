"""OPENMANUS_ROOT 来源校验:确保被测的 OpenManus 源码可信。

信任边界语义(见 README「安全与信任边界」):
  `import agenteval` 会把 OPENMANUS_ROOT 插进 sys.path 并 `from app.* import`,
  import 即执行其代码。所以必须在任何 OpenManus 代码执行之前,校验:

    1. OPENMANUS_ROOT 是一个 git 仓库。
    2. HEAD commit 在可信提交列表里(审阅过的源码)。
    3. working tree 干净(本地未被未审阅的改动篡改)。

绕过(显式、信任环境才用,见 README):
  AGENTEVAL_SKIP_VERIFY=1  完全跳过(测试 / CI 用)。
  AGENTEVAL_ALLOW_DIRTY=1  允许 dirty working tree(本地有审阅过的定制改动)。
  AGENTEVAL_ALLOW_COMMIT=<sha[,sha...]>  追加可信 commit(临时,不落库)。

自包含模块:只用 stdlib(subprocess / os),不 import agenteval 其它模块,
所以可以被独立单测,不触发包 __init__。
"""

import os
import subprocess
from typing import Iterable, Optional, Set

# 可信提交列表文件(仓库内,每行一个完整 sha;空行与 # 注释忽略)。
_TRUSTED_COMMITS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trusted_openmanus_commits.txt")

_SKIP_ENV = "AGENTEVAL_SKIP_VERIFY"
_DIRTY_ENV = "AGENTEVAL_ALLOW_DIRTY"
_ALLOW_COMMIT_ENV = "AGENTEVAL_ALLOW_COMMIT"


def _env_dict(env: Optional[dict]) -> dict:
    """统一取环境变量来源(测试可传假 env,默认读 os.environ)。"""
    return os.environ if env is None else env


def _git(root: str, *args: str) -> subprocess.CompletedProcess:
    """在 root 里跑 git 命令;超时 / 异常由调用方处理。"""
    return subprocess.run(
        ["git", "-C", root, *args],
        capture_output=True,
        text=True,
        timeout=15,
        encoding="utf-8",
        errors="replace",
    )


def trusted_commits(env: Optional[dict] = None) -> Set[str]:
    """可信 commit 集合 = 文件(trusted_openmanus_commits.txt)+ 环境变量追加。"""
    commits: Set[str] = set()
    try:
        with open(_TRUSTED_COMMITS_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    commits.add(line)
    except OSError:
        pass  # 文件缺失视为空列表,仅靠 env 追加

    env_dict = _env_dict(env)
    extra = env_dict.get(_ALLOW_COMMIT_ENV, "")
    for sha in extra.split(","):
        sha = sha.strip()
        if sha:
            commits.add(sha)
    return commits


def verify_openmanus(root: str, env: Optional[dict] = None) -> None:
    """校验 OPENMANUS_ROOT 来源可信;不通过抛 RuntimeError(信息含修复步骤)。

    Args:
        root: OPENMANUS_ROOT 绝对路径。
        env: 可选环境变量 dict(测试注入用);默认 os.environ。
    """
    env_dict = _env_dict(env)

    # 显式跳过:测试 / 完全信任的环境。
    if env_dict.get(_SKIP_ENV) == "1":
        return

    # 1. 是 git 仓库?
    head = _git(root, "rev-parse", "HEAD")
    if head.returncode != 0:
        raise RuntimeError(
            f"OPENMANUS_ROOT 不是 git 仓库: {root}\n"
            "来源校验要求被测 OpenManus 是一个 git clone(这样才能核对提交)。\n"
            "修复:重新 clone 一份,或设 AGENTEVAL_SKIP_VERIFY=1 显式绕过。"
        )

    # 2. HEAD 在可信提交列表?
    head_sha = head.stdout.strip()
    if head_sha not in trusted_commits(env_dict):
        raise RuntimeError(
            f"OPENMANUS_ROOT HEAD ({head_sha[:12]}) 不在可信提交列表。\n"
            "这是信任边界:import 时会以评测进程权限执行该目录的代码。\n"
            f"修复:确认已审阅该源码后,把完整 sha 加入\n"
            f"    agenteval/trusted_openmanus_commits.txt\n"
            f"或临时设:AGENTEVAL_ALLOW_COMMIT={head_sha}"
        )

    # 3. working tree 干净(被审阅的提交未被本地篡改)?
    status = _git(root, "status", "--porcelain")
    dirty = [ln for ln in status.stdout.splitlines() if ln.strip()]
    if dirty and env_dict.get(_DIRTY_ENV) != "1":
        preview = ", ".join(dirty[:5])
        raise RuntimeError(
            f"OPENMANUS_ROOT working tree 有 {len(dirty)} 个未提交改动,要求干净。\n"
            f"改动:{preview}\n"
            "若这些是审阅过的本地定制,设 AGENTEVAL_ALLOW_DIRTY=1 放行;\n"
            "否则先还原,确保被测代码与被审阅的提交一致。"
        )
