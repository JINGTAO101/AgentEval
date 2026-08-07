"""AgentEval 路径常量(自包含模块,不 import 任何依赖)。"""

import os

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
# 包根 = 本文件所在目录的上一级(仓库克隆位置)。
PROJECT_ROOT = os.path.dirname(_PACKAGE_DIR)

# 被测 agent 源码根(只读,通过 sys.path 直接 import,不安装、不修改)。
# 解析顺序:环境变量 OPENMANUS_ROOT > 默认同级目录(AgentEval 的上一级 ../OpenManus)。
# 未找到时报错并给出指引,避免把机器耦合路径硬编码进仓库。
_DEFAULT_OPENMANUS_ROOT = os.path.join(os.path.dirname(PROJECT_ROOT), "OpenManus")
OPENMANUS_ROOT = os.path.abspath(
    os.environ.get("OPENMANUS_ROOT") or _DEFAULT_OPENMANUS_ROOT
)
if not os.path.isdir(OPENMANUS_ROOT):
    raise RuntimeError(
        f"找不到 OpenManus 源码目录: {OPENMANUS_ROOT}\n"
        "请先 clone OpenManus 到任意位置,再设置环境变量 OPENMANUS_ROOT 指向它:\n"
        "  PowerShell : $env:OPENMANUS_ROOT = 'C:\\path\\to\\OpenManus'\n"
        "  CMD        : set OPENMANUS_ROOT=C:\\path\\to\\OpenManus\n"
        "  bash       : export OPENMANUS_ROOT=/path/to/OpenManus"
    )

# PythonExecute 子进程的固定工作目录(隔离默认 cwd,降低相对路径写宿主目录的风险;
# 注意:非完整沙箱,子进程仍有宿主用户权限,详见 README「安全边界」)。
SCRATCH_DIR = os.path.join(PROJECT_ROOT, "scratch")

# 假 secret 文件目录(Data Leakage 用例的靶子)。
SANDBOX_DIR = os.path.join(PROJECT_ROOT, "sandbox")
