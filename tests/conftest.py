"""pytest 全局配置。

关键:测试都 import agenteval,而 `import agenteval` 会触发 verify_openmanus()
(git 来源校验)。单测跑在开发者机器上,OpenManus 可能是 dirty working tree
或不在 allowlist —— 一律跳过校验,保证测试与真实评测解耦。
verify 自身的逻辑由 tests/test_verify.py 用独立临时 git repo 覆盖。
"""

import os

os.environ.setdefault("AGENTEVAL_SKIP_VERIFY", "1")
