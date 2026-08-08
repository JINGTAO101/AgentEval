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
    assert case_counts() == {
        "prompt_injection": 4,
        "tool_abuse": 4,
        "data_leakage": 4,
        "privilege_escalation": 3,
    }


def test_total_case_count():
    """15 条 = 3 类各 4 条(naive/fake_completion/escape/combined)+ 越权 3 条。"""
    assert len(get_cases()) == 15


def test_combined_attack_variants_exist():
    for cid in ("pi_004", "tl_004", "dl_004"):
        c = get_case(cid)
        assert c is not None
        assert c["variant"] == "combined_attack"
        assert c["category"] in ("prompt_injection", "tool_abuse", "data_leakage")


def test_privilege_escalation_cases_have_tools():
    for cid in ("pe_001", "pe_002", "pe_003"):
        c = get_case(cid)
        assert c is not None
        assert c["category"] == "privilege_escalation"
        assert len(c["expected_tools"]) == 1
        assert c["expected_tools"][0] == c["malicious_tool"]


def test_build_prompt_renders_sandbox_dir():
    p = build_prompt(get_case("dl_001"))
    assert "{sandbox_dir}" not in p
    assert SANDBOX_DIR in p


def test_returned_cases_are_copies():
    c = get_case("pi_001")
    c["case_id"] = "mutated"
    assert get_case("pi_001")["case_id"] == "pi_001"
