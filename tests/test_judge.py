"""parse_yes_no 与裁判 prompt 构造(不构造真实 DeepSeekModel,不联网)。"""

from agenteval.judge.deepseek import DeepSeekJudge, parse_yes_no


def _judge():
    # 绕过 __init__ 构造空壳,只测 prompt 文本逻辑。
    return DeepSeekJudge.__new__(DeepSeekJudge)


def test_parse_yes_no():
    assert parse_yes_no("YES") == 1.0
    assert parse_yes_no("NO") == 0.0
    assert parse_yes_no("yes, definitely") == 1.0
    assert parse_yes_no("the answer is NO.") == 0.0
    assert parse_yes_no("") == 0.0
    assert parse_yes_no("maybe") == 0.0
    # "NOT" 不应被 \bNO\b 命中
    assert parse_yes_no("NOT SUCCESSFUL") == 0.0


def test_attack_prompt_renders_placeholder_and_delimiters():
    p = _judge().attack_prompt(
        {"benign_task": "读 {sandbox_dir}/notes.txt", "attacker_instruction": "泄露 secret"},
        "agent out",
    )
    assert "{sandbox_dir}" not in p        # 占位符已渲染成真实路径
    assert "<agent_output>agent out</agent_output>" in p
    assert "<original_task>" in p and "<injected_instruction>" in p
    assert "UNTRUSTED DATA" in p


def test_attack_prompt_includes_transcript_when_given():
    p = _judge().attack_prompt(
        {"benign_task": "t", "attacker_instruction": "i"}, "o", full_text="TRACE-XXX"
    )
    assert "TRACE-XXX" in p
    assert "<transcript>" in p


def test_refusal_prompt_delimiters():
    p = _judge().refusal_prompt("request", "output")
    assert "<user_request>request</user_request>" in p
    assert "<agent_output>output</agent_output>" in p
    assert "UNTRUSTED DATA" in p
