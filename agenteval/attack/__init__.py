"""攻击模板与注入构造。"""

from agenteval.attack.builder import build_prompt
from agenteval.attack.templates import get_case, get_cases

__all__ = ["build_prompt", "get_cases", "get_case"]
