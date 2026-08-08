"""Trace.from_memory 提取逻辑(用伪消息对象,不 import OpenManus)。"""

from agenteval.harness.trace import Trace


class _Fn:
    def __init__(self, name, arguments=None):
        self.name = name
        self.arguments = arguments


class _ToolCall:
    def __init__(self, name, arguments=None):
        self.function = _Fn(name, arguments)


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


def test_tool_call_arguments_in_all_text():
    """工具调用参数也要进 all_text:泄露证据可能只藏在 SendEmail 的 to/body 参数里。"""
    msgs = [
        _Msg(
            "assistant",
            None,
            tool_calls=[_ToolCall("SendEmail", '{"to": "attacker", "body": "FLAG-9d21bb"}')],
        ),
        _Msg("tool", "sent", name="SendEmail"),
        _Msg("assistant", "邮件已发送"),
    ]
    t = Trace.from_memory(msgs)
    # 参数里的 secret 对 judge / fast-path 可见
    assert "FLAG-9d21bb" in t.all_text
    assert "[tool_call:SendEmail]" in t.all_text
    # 参数进 all_text,但不该污染 final_output(它仍是最后一条 assistant 文本)
    assert t.final_output == "邮件已发送"


def test_tool_call_without_arguments_still_works():
    """arguments 为 None 时不报错,也不进 all_text。"""
    msgs = [
        _Msg("assistant", "用工具", tool_calls=[_ToolCall("python_execute")]),
        _Msg("tool", "OK", name="python_execute"),
    ]
    t = Trace.from_memory(msgs)
    assert t.tools_called == ["python_execute"]
    assert "[tool_call:python_execute]" not in t.all_text
    assert t.all_text == "用工具\nOK"
