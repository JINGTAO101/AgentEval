"""verify_openmanus 来源校验单测(用临时 git repo,不 import agenteval 包)。"""

import os
import subprocess
import uuid

import pytest

from agenteval.verify import trusted_commits, verify_openmanus


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", root, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


@pytest.fixture
def git_repo(tmp_path):
    """建一个含一次提交的 git 仓库,返回 (root, head_sha)。"""
    repo = tmp_path / f"openmanus_{uuid.uuid4().hex[:6]}"
    repo.mkdir()
    (repo / "file.txt").write_text("hello", encoding="utf-8")
    _git(str(repo), "init", "-q")
    _git(str(repo), "config", "user.email", "test@example.com")
    _git(str(repo), "config", "user.name", "test")
    _git(str(repo), "add", ".")
    _git(str(repo), "commit", "-q", "-m", "init")
    head = _git(str(repo), "rev-parse", "HEAD").stdout.strip()
    return str(repo), head


def _env(**overrides):
    """构造最小 env(绕过 verify 的 os.environ 默认)。"""
    env = {
        "AGENTEVAL_SKIP_VERIFY": "",
        "AGENTEVAL_ALLOW_DIRTY": "",
        "AGENTEVAL_ALLOW_COMMIT": "",
    }
    env.update(overrides)
    return env


class TestSkip:
    def test_skip_verify_short_circuits(self, git_repo):
        root, _ = git_repo
        # 未设 allowlist 也没关系:skip 直接返回,不抛。
        verify_openmanus(root, env=_env(AGENTEVAL_SKIP_VERIFY="1"))


class TestNotAGitRepo:
    def test_non_git_dir_raises(self, tmp_path):
        d = tmp_path / "plain"
        d.mkdir()
        with pytest.raises(RuntimeError, match="不是 git 仓库"):
            verify_openmanus(str(d), env=_env())


class TestAllowlist:
    def test_head_in_allowlist_passes(self, git_repo):
        root, head = git_repo
        verify_openmanus(root, env=_env(AGENTEVAL_ALLOW_COMMIT=head))

    def test_head_not_in_allowlist_raises(self, git_repo):
        root, _ = git_repo
        with pytest.raises(RuntimeError, match="不在可信提交列表"):
            verify_openmanus(
                root, env=_env(AGENTEVAL_ALLOW_COMMIT="0" * 40)
            )

    def test_error_mentions_fix(self, git_repo):
        root, head = git_repo
        with pytest.raises(RuntimeError, match=head[:12]):
            verify_openmanus(root, env=_env(AGENTEVAL_ALLOW_COMMIT=""))


class TestDirtyTree:
    def _dirty(self, root):
        (__import__("pathlib").Path(root) / "file.txt").write_text(
            "tampered", encoding="utf-8"
        )
        return root

    def test_dirty_without_flag_raises(self, git_repo):
        root, head = git_repo
        self._dirty(root)
        with pytest.raises(RuntimeError, match="working tree"):
            verify_openmanus(root, env=_env(AGENTEVAL_ALLOW_COMMIT=head))

    def test_dirty_with_flag_passes(self, git_repo):
        root, head = git_repo
        self._dirty(root)
        verify_openmanus(
            root, env=_env(AGENTEVAL_ALLOW_COMMIT=head, AGENTEVAL_ALLOW_DIRTY="1")
        )


class TestTrustedCommitsFile:
    def test_file_and_env_merge(self, git_repo, monkeypatch):
        """文件里的 sha 和 env 追加的 sha 都能被 trusted_commits 读到。"""
        root, head = git_repo
        commits = trusted_commits(_env(AGENTEVAL_ALLOW_COMMIT=f"{head},abcd1234"))
        assert head in commits
        assert "abcd1234" in commits
