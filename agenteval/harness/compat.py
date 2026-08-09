"""Windows 兼容层(仅 win32 生效)。

背景:OpenManus 的 `LocalFileOperator.run_command` 用 `asyncio.create_subprocess_shell`
执行 shell 命令,而:
  * ipykernel 在 Windows 上用 SelectorEventLoop —— 该 loop 不支持子进程,调用即抛
    `NotImplementedError`(OpenManus file_operators.py:73)。
  * 即便绕过 loop 限制,Windows 的 `find` 是文本搜索工具(C:\\Windows\\System32\\find.exe),
    不是 GNU find,`str_replace_editor` 的目录 view 参数语义全错。

本模块在 Windows 上把 OpenManus 生成的 `find <path> -maxdepth <N> ...` 目录列出命令
翻译成纯 Python `os.walk` 实现(语义等价:GNU `-maxdepth N` 含 0..N 层、`-not -path '*/\\.*'`
排除隐藏项),其余命令回退到 `asyncio.to_thread(subprocess.run)` —— 线程里跑同步子进程,
与旧版 `SandboxPythonExecute` 同款,在 notebook 里可靠。

只做运行时 monkeypatch,不修改 OpenManus 源码;非 win32 直接 no-op。
"""

import asyncio
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# OpenManus str_replace_editor._view_directory 生成的命令形如:
#   find <path> -maxdepth 2 -not -path '*/\.*'
# 用宽松匹配:只要以 `find <path> -maxdepth <N>` 开头就按目录列出翻译。
_FIND_RE = re.compile(r"^find\s+(.+?)\s+-maxdepth\s+(\d+)(?:\s+|$)")


def _find_listing(start: str, maxdepth: int, timeout: float = 120.0) -> str:
    """GNU `find <start> -maxdepth <maxdepth> -not -path '*/\\.*'` 的等价目录列出。

    输出:每行一个路径(目录 + 非隐藏文件),深度 0..maxdepth,隐藏项排除。
    """
    deadline = time.monotonic() + timeout
    root = Path(start)
    lines: list[str] = []
    start_depth = len(root.parts)

    def _depth(path: Path) -> int:
        return len(path.parts) - start_depth

    for current, dirs, files in os.walk(root):
        if time.monotonic() > deadline:
            raise TimeoutError(f"Directory listing for '{start}' timed out")
        depth = _depth(Path(current))
        # 隐藏目录不进遍历;深度到顶则不再下钻。
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        if depth <= maxdepth:
            lines.append(str(current))
        if depth >= maxdepth:
            dirs[:] = []
            continue
        for name in files:
            if not name.startswith("."):
                lines.append(os.path.join(current, name))
    return "\n".join(lines) + ("\n" if lines else "")


async def _compat_run_command(
    self, cmd: str, timeout: float = 120.0
) -> tuple[int, str, str]:
    """替换 LocalFileOperator.run_command:find 目录列出 → os.walk,其余 → 线程子进程。"""
    m = _FIND_RE.match(cmd.strip())
    if m:
        try:
            listing = await asyncio.to_thread(
                _find_listing, m.group(1).strip(), int(m.group(2)), timeout
            )
        except TimeoutError as exc:
            return 1, "", str(exc)
        return 0, listing, ""
    try:
        proc = await asyncio.to_thread(
            subprocess.run,
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return 1, "", f"Command '{cmd}' timed out after {timeout} seconds"
    return proc.returncode or 0, proc.stdout or "", proc.stderr or ""


def patch_windows_file_operator() -> None:
    """把 LocalFileOperator.run_command 换成 Windows 兼容版。非 win32 或已补丁则跳过。"""
    if sys.platform != "win32":
        return
    from app.tool.file_operators import LocalFileOperator

    if getattr(LocalFileOperator, "_agenteval_compat_patched", False):
        return
    LocalFileOperator.run_command = _compat_run_command
    LocalFileOperator._agenteval_compat_patched = True
