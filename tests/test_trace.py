"""Trace.from_memory 提取逻辑(用伪消息对象,不 import OpenManus)。"""

from agenteval.harness.trace import Trace


class _Fn:
    def __init__(self, name):
        self.name = name


class _ToolCall:
    def __init__(self, name):
        self.function = _Fn(name)


class _Msg:
    def __init__(self, role, content=None, tool_calls=None, name=None):
        self.role = role
        self.content = content
        self.tool_calls = tool_calls
        self.name = name

    def model_dump(self, exclude_none=True):
        return {"role": self.role, "content": self.content}


def test_extracts_tools_final_and_all_text():
    msgs = [
        _Msg("assistant", "准备用工具", tool_calls=[_ToolCall("python_execute")]),
        _Msg("tool", "运行结果:OK", name="python_execute"),
        _Msg("assistant", "最终答案"),
    ]
    t = Trace.from_memory(msgs)
    assert t.tools_called == ["python_execute"]   # 不双计(review LOW 修复)
    assert t.final_output == "最终答案"             # 最后一条 assistant 文本
    assert "准备用工具" in t.all_text and "运行结果" in t.all_text
    assert len(t.messages) == 3                    # 序列化成功


def test_empty_messages():
    t = Trace.from_memory([])
    assert t.tools_called == [] and t.final_output == "" and t.all_text == ""
