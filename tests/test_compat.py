"""Windows 兼容层测试:find → os.walk 目录列出 + run_command 翻译。

注意:测试机就是 Windows,`import agenteval` 已触发 patch_windows_file_operator(),
所以 `LocalFileOperator.run_command` 已被替换 —— 这里直接验证替换后的行为。

关键断言:目录 view 的 `find` 命令在 SelectorEventLoop 上不再抛 NotImplementedError,
而是返回 os.walk 生成的目录列表(含子目录/文件、排除隐藏项、遵守 maxdepth)。
"""

import pytest

from agenteval.harness.compat import _FIND_RE, _find_listing, patch_windows_file_operator


def _make_tree(root) -> None:
    """造一个含隐藏项和多层目录的样例树。"""
    (root / "notes.txt").write_text("hi", encoding="utf-8")
    (root / "sub" / "deep").mkdir(parents=True, exist_ok=True)
    (root / "sub" / "deep" / "x.py").write_text("", encoding="utf-8")
    (root / ".hidden").write_text("", encoding="utf-8")
    (root / "sub" / ".gitkeep").write_text("", encoding="utf-8")


class TestFindListing:
    def test_lists_dirs_to_maxdepth(self, tmp_path):
        # maxdepth=2:GNU 语义覆盖深度 0..2 —— root/sub/deep 可见,x.py(深度3)不可见
        _make_tree(tmp_path)
        out = _find_listing(str(tmp_path), 2)
        assert str(tmp_path) in out
        assert str(tmp_path / "sub") in out
        assert str(tmp_path / "sub" / "deep") in out
        assert str(tmp_path / "sub" / "deep" / "x.py") not in out

    def test_deeper_maxdepth_reveals_deep_files(self, tmp_path):
        # maxdepth=3:深度3的 x.py 出现
        _make_tree(tmp_path)
        out = _find_listing(str(tmp_path), 3)
        assert str(tmp_path / "sub" / "deep" / "x.py") in out

    def test_excludes_hidden_entries(self, tmp_path):
        _make_tree(tmp_path)
        out = _find_listing(str(tmp_path), 2)
        assert ".hidden" not in out
        assert ".gitkeep" not in out

    def test_maxdepth1_hides_depth2_dir(self, tmp_path):
        # maxdepth=1:可见 root/sub,深度2的 deep 与 x.py 均不可见;深度1的 notes.txt 可见
        _make_tree(tmp_path)
        out = _find_listing(str(tmp_path), 1)
        assert str(tmp_path / "sub") in out
        assert str(tmp_path / "sub" / "deep") not in out
        assert str(tmp_path / "sub" / "deep" / "x.py") not in out
        assert str(tmp_path / "notes.txt") in out

    def test_missing_path_returns_empty(self, tmp_path):
        out = _find_listing(str(tmp_path / "nope"), 2)
        assert out == ""

    def test_find_regex_matches_openmanus_command(self, tmp_path):
        cmd = f"find {tmp_path} -maxdepth 2 " + r"-not -path '*/\.*'"
        m = _FIND_RE.match(cmd.strip())
        assert m is not None
        assert m.group(2) == "2"


class TestPatchedRunCommand:
    """替换后的 LocalFileOperator.run_command 在 Windows loop 上不应抛 NotImplementedError。"""

    pytestmark = pytest.mark.asyncio

    async def test_directory_find_returns_listing(self, tmp_path):
        from app.tool.file_operators import LocalFileOperator

        _make_tree(tmp_path)
        cmd = f"find {tmp_path} -maxdepth 2 " + r"-not -path '*/\.*'"
        rc, stdout, stderr = await LocalFileOperator().run_command(cmd, timeout=10)
        assert rc == 0
        assert not stderr
        assert str(tmp_path / "sub") in stdout
        assert str(tmp_path / "sub" / "deep") in stdout

    async def test_non_find_command_falls_back_to_thread_subprocess(self, tmp_path):
        from app.tool.file_operators import LocalFileOperator

        target = tmp_path / "probe.txt"
        target.write_text("hello", encoding="utf-8")
        # Windows 用 type;跨平台判断下 --shell 能跑的最小命令。用 python 保证两端都行。
        cmd = f"python -c \"print(open(r'{target}', encoding='utf-8').read())\""
        rc, stdout, stderr = await LocalFileOperator().run_command(cmd, timeout=30)
        assert rc == 0
        assert "hello" in stdout


def test_patch_is_idempotent(monkeypatch):
    """重复调用不重复打补丁(有 guard 属性)。"""
    monkeypatch.setattr("sys.platform", "win32")
    from app.tool.file_operators import LocalFileOperator

    before = LocalFileOperator.run_command
    patch_windows_file_operator()
    patch_windows_file_operator()
    assert LocalFileOperator.run_command is before
    assert LocalFileOperator._agenteval_compat_patched is True
