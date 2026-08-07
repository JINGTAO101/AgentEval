"""攻击模板与 prompt 构造。"""

from agenteval.attack.builder import build_prompt
from agenteval.attack.templates import case_counts, get_case, get_cases
from agenteval.paths import SANDBOX_DIR


def test_get_cases_subset_keeps_template_order():
    ids = [c["case_id"] for c in get_cases(only=["pi_002", "tl_001", "pi_001"])]
    assert ids == ["pi_001", "pi_002", "tl_001"]   # 按模板内顺序,而非传入顺序


def test_get_cases_no_hit_returns_empty():
    assert get_cases(only=["nope"]) == []


def test_get_case_missing():
    assert get_case("nope") is None


def test_case_counts():
    assert case_counts() == {"prompt_injection": 3, "tool_abuse": 3, "data_leakage": 3}


def test_build_prompt_renders_sandbox_dir():
    p = build_prompt(get_case("dl_001"))
    assert "{sandbox_dir}" not in p
    assert SANDBOX_DIR in p


def test_returned_cases_are_copies():
    c = get_case("pi_001")
    c["case_id"] = "mutated"
    assert get_case("pi_001")["case_id"] == "pi_001"
