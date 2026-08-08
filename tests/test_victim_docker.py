"""SandboxPythonExecute 的 Docker 容器执行逻辑(fake DockerSandbox,不碰真实 Docker)。

关键:测试直接 import agenteval.harness.victim 并替换模块级 DockerSandbox 引用,
不需要 Docker daemon。execute() 内部的懒连接(`async with DockerSandbox(...)`)
在 fake 下走通 —— 覆盖正常/非零退出/超时/Docker 不可用四种路径。

配置方式:fake 用类属性做默认行为(execute 时才实例化),测试在 execute 前
改类属性,新实例动态读取 —— 避免"实例还没创建就取不到"的时序问题。
"""

import pytest

from agenteval.harness import victim
from agenteval.harness.victim import SandboxPythonExecute, _parse_rc, _strip_rc

# async def test 需要 pytest-asyncio(插件已装,项目无 pytest.ini)。
# mark 放在 async 测试类内部;同步的 TestHelpers 不标,避免误触发 warning。


class FakeDockerSandbox:
    """假 DockerSandbox。行为全部走类属性(默认),实例只记录被调用详情。"""

    output = "ok\n__RC:0\n"
    raise_on_enter = None
    raise_on_run = None

    def __init__(self, config=None, volume_bindings=None):
        self.config = config
        self.volume_bindings = volume_bindings
        self.called_commands = []

    async def __aenter__(self):
        if self.raise_on_enter:
            raise self.raise_on_enter
        return self

    async def __aexit__(self, *exc):
        return False

    async def run_command(self, cmd, timeout=None):
        if self.raise_on_run:
            raise self.raise_on_run
        self.called_commands.append((cmd, timeout))
        return self.output


@pytest.fixture
def fake_docker(monkeypatch):
    """把 victim.DockerSandbox 替换为 FakeDockerSandbox,返回 (类, 实例记录)。"""
    # 重置类属性默认值,避免上个测试的修改泄漏到下个测试。
    FakeDockerSandbox.output = "ok\n__RC:0\n"
    FakeDockerSandbox.raise_on_enter = None
    FakeDockerSandbox.raise_on_run = None

    instances = []

    def _factory(config=None, volume_bindings=None):
        box = FakeDockerSandbox(config=config, volume_bindings=volume_bindings)
        instances.append(box)
        return box

    monkeypatch.setattr(victim, "DockerSandbox", _factory)
    return FakeDockerSandbox, instances


def _box_after(fake_docker):
    _, instances = fake_docker
    assert instances, "execute() 应已构造 DockerSandbox"
    return instances[-1]


class TestSuccess:
    pytestmark = pytest.mark.asyncio

    async def test_zero_exit_is_success(self, fake_docker):
        FakeDockerSandbox.output = "hello world\n__RC:0\n"
        result = await SandboxPythonExecute().execute("print('hi')", timeout=7)
        assert result["success"] is True
        assert "hello world" in result["observation"]
        assert "__RC:" not in result["observation"]

    async def test_passes_sandbox_settings_and_binds(self, fake_docker):
        await SandboxPythonExecute().execute("pass", timeout=7)
        box = _box_after(fake_docker)
        assert box.config.network_enabled is False
        assert "/scratch" in box.volume_bindings.values()
        assert "/sandbox" in box.volume_bindings.values()

    async def test_command_uses_base64_exec_and_rc_marker(self, fake_docker):
        await SandboxPythonExecute().execute("print('x')", timeout=7)
        box = _box_after(fake_docker)
        cmd, timeout = box.called_commands[0]
        assert "python3 -c" in cmd
        assert "__RC:$?" in cmd
        assert "cd /scratch" in cmd
        assert timeout == 7


class TestFailure:
    pytestmark = pytest.mark.asyncio

    async def test_nonzero_exit_is_failure(self, fake_docker):
        FakeDockerSandbox.output = "traceback...\n__RC:1\n"
        result = await SandboxPythonExecute().execute("raise", timeout=7)
        assert result["success"] is False
        assert "traceback" in result["observation"]

    async def test_timeout_is_failure(self, fake_docker):
        from app.sandbox.core.exceptions import SandboxTimeoutError

        FakeDockerSandbox.raise_on_run = SandboxTimeoutError("timed out")
        result = await SandboxPythonExecute().execute("pass", timeout=7)
        assert result["success"] is False
        assert "timeout" in result["observation"].lower()

    async def test_docker_unavailable_is_failure(self, fake_docker):
        FakeDockerSandbox.raise_on_enter = RuntimeError(
            "Cannot connect to the Docker daemon"
        )
        result = await SandboxPythonExecute().execute("pass", timeout=7)
        assert result["success"] is False
        assert "Docker sandbox error" in result["observation"]


class TestHelpers:
    def test_parse_rc_takes_last(self):
        assert _parse_rc("a\n__RC:0\n__RC:1\n") == 1
        assert _parse_rc("no marker") == 0
        assert _parse_rc("__RC:abc\n") == 0

    def test_strip_rc_removes_marker_lines(self):
        assert _strip_rc("line1\n__RC:0\nline3\n") == "line1\nline3"
        # 程序真实输出里恰好以 __RC: 开头的行(非哨兵值)会被剥离 —— 这是已知取舍
        assert _strip_rc("__RC:not-a-marker\n") == ""
