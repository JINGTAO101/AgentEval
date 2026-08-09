"""SandboxPythonExecute 的子进程执行逻辑测试(不依赖 Docker)。

execute() 用 asyncio.to_thread 跑同步 subprocess.run(cwd=SCRATCH_DIR、
env 摘掉 DEEPSEEK_API_KEY)。直接调 execute(),覆盖:
  * 正常退出 → success True + observation 含程序输出
  * 非零退出 → success False + observation 含 traceback
  * 超时     → success False + observation 提示 timeout
  * key 摘除:注入代码里 os.environ 看不到 DEEPSEEK_API_KEY(核心安全约束)
  * cwd 固定:注入代码 os.getcwd() == SCRATCH_DIR
"""

import os
import pytest

from agenteval.harness import victim
from agenteval.paths import SCRATCH_DIR


@pytest.fixture
def runner():
    return victim.SandboxPythonExecute()


class TestSubprocessExec:
    pytestmark = pytest.mark.asyncio

    async def test_zero_exit_is_success(self, runner):
        result = await runner.execute("print('hello')", timeout=10)
        assert result["success"] is True
        assert "hello" in result["observation"]

    async def test_nonzero_exit_is_failure(self, runner):
        result = await runner.execute("raise ValueError('boom')", timeout=10)
        assert result["success"] is False
        assert "ValueError" in result["observation"]

    async def test_timeout_is_failure(self, runner):
        result = await runner.execute("import time; time.sleep(10)", timeout=2)
        assert result["success"] is False
        assert "timeout" in result["observation"].lower()

    async def test_env_strips_deepseek_key(self, runner, monkeypatch):
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-sentinel-123")
        code = (
            "import os;"
            'print("KEY_PRESENT" if "DEEPSEEK_API_KEY" in os.environ '
            'else "KEY_ABSENT")'
        )
        result = await runner.execute(code, timeout=10)
        assert result["success"] is True
        assert "KEY_ABSENT" in result["observation"]
        assert "sk-sentinel-123" not in result["observation"]

    async def test_cwd_is_scratch(self, runner):
        result = await runner.execute("import os; print(os.getcwd())", timeout=10)
        assert result["success"] is True
        assert str(SCRATCH_DIR) in result["observation"]

    async def test_stdout_and_stderr_both_captured(self, runner):
        code = "import sys; print('out'); print('err', file=sys.stderr)"
        result = await runner.execute(code, timeout=10)
        assert result["success"] is True
        assert "out" in result["observation"]
        assert "err" in result["observation"]
