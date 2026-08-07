"""轨迹提取:从 OpenManus Memory 提取评测需要的结构化数据。

OpenManus Message 结构(已核对 app/schema.py):
  role / content / tool_calls(Optional[List[ToolCall(function: Function(name, arguments))]])
  / name(tool 消息) / tool_call_id
"""

from dataclasses import dataclass, field
from typing import Any, List


@dataclass
class Trace:
    """一次用例执行的完整轨迹。"""

    messages: List[dict]
    tools_called: List[str]
    final_output: str
    all_text: str
    step_count: int

    @classmethod
    def from_memory(cls, messages) -> "Trace":
        """从 OpenManus `agent.memory.messages` 提取。

        * tools_called:assistant 消息里 tool_calls 的 function.name(tool 结果消息的 name
          与之重复,不再追加,避免每次工具调用被计两次)。
        * final_output:最后一条 assistant 文本(agent.run() 的返回值是 step 日志,
          不是最终答案,所以必须从这里取)。
        * all_text:所有消息 content 拼接,供 secret fast-path / judge 全文参考。
        """
        tools: List[str] = []
        final_output = ""
        contents: List[str] = []
        for msg in messages:
            # assistant 消息的 tool_calls(唯一事实来源;tool 结果消息的 name 会重复)
            tcs = getattr(msg, "tool_calls", None)
            if tcs:
                for tc in tcs:
                    fn = getattr(tc, "function", None)
                    if fn is not None and getattr(fn, "name", None):
                        tools.append(fn.name)
            # content
            content = getattr(msg, "content", None)
            if content:
                contents.append(str(content))
                if getattr(msg, "role", None) == "assistant":
                    final_output = str(content)

        # 序列化消息到 dict(供 JSON 报告),失败时回退到字符串。
        serialized: List[dict] = []
        for m in messages:
            if hasattr(m, "model_dump"):
                try:
                    serialized.append(m.model_dump(exclude_none=True))
                    continue
                except Exception:
                    pass
            serialized.append({"raw": str(m)})

        return cls(
            messages=serialized,
            tools_called=tools,
            final_output=final_output or "",
            all_text="\n".join(contents),
            step_count=len(messages),
        )
