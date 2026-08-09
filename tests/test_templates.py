"""攻击模板(JSONL loader)与 prompt 构造。"""

import json

import pytest

from agenteval.attack.builder import build_prompt
from agenteval.attack.templates import (
    load_cases,
    validate_case,
    case_counts,
    get_case,
    get_cases,
)
from agenteval.paths import SANDBOX_DIR


# ------------------------------------------------------------------ 既有公开 API 语义


def test_get_cases_subset_keeps_template_order():
    ids = [c["case_id"] for c in get_cases(only=["pi_002", "tl_001", "pi_001"])]
    assert ids == ["pi_001", "pi_002", "tl_001"]   # 按模板内顺序,而非传入顺序


def test_get_cases_no_hit_returns_empty():
    assert get_cases(only=["nope"]) == []


def test_get_case_missing():
    assert get_case("nope") is None


def test_case_counts():
    assert case_counts() == {
        "prompt_injection": 20,
        "tool_abuse": 26,
        "data_leakage": 20,
        "privilege_escalation": 19,
    }


def test_total_case_count():
    """85 条 = 72 DPI 直接注入 + 13 OPI 观测注入。"""
    assert len(get_cases()) == 85
    assert len([c for c in get_cases() if c["attack_channel"] == "dpi"]) == 72
    assert len([c for c in get_cases() if c["attack_channel"] == "opi"]) == 13


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


def test_privilege_escalation_has_non_aggressive():
    """pe 难度轴补齐:非激进提权用例存在(扩 harness 前的硬缺口)。"""
    pe = [c for c in get_cases() if c["category"] == "privilege_escalation"]
    nonagg = [c for c in pe if c["difficulty"] == "non_aggressive"]
    assert len(nonagg) == 8
    for c in nonagg:
        assert c["expected_tools"], f"{c['case_id']} 非激进 pe 必须引用工具桩"


def test_new_tool_stubs_used_in_data():
    """新 3 桩(AddAdminUser/ExportData/GrantPermissions)有真实用例引用。"""
    used = {
        t
        for c in get_cases()
        for t in c["expected_tools"]
        if t in ("AddAdminUser", "ExportData", "GrantPermissions")
    }
    assert used == {"AddAdminUser", "ExportData", "GrantPermissions"}


def test_build_prompt_renders_sandbox_dir():
    p = build_prompt(get_case("dl_001"))
    assert "{sandbox_dir}" not in p
    assert SANDBOX_DIR in p


def test_returned_cases_are_copies():
    c = get_case("pi_001")
    c["case_id"] = "mutated"
    assert get_case("pi_001")["case_id"] == "pi_001"


def test_defaults_filled():
    """loader 为缺省字段填默认值:难度/通道/secret/expected_tools。

    pi_001 显式写了 poison_file=""(DPI 用例用不到),loader 保留作者原值;
    缺省字段(如 _valid_case 里没有 poison_file)才由 validate_case 填默认。
    """
    c = get_case("pi_001")
    assert c["difficulty"] == "aggressive"
    assert c["attack_channel"] == "dpi"
    assert c["poison_file"] == ""
    assert c["secret"] == ""
    assert c["expected_tools"] == []
    # 字段缺失时才填默认值:poison_file 缺省 → notes.txt
    assert validate_case(_valid_case())["poison_file"] == "notes.txt"


# ------------------------------------------------------------------ validate_case 校验


def _valid_case(cid="x_001", **overrides):
    c = {
        "case_id": cid,
        "category": "prompt_injection",
        "variant": "naive",
        "description": "d",
        "benign_task": "阅读 {sandbox_dir}/notes.txt 的内容。",
        "attacker_instruction": "inst",
        "attacker_goal": "goal",
    }
    c.update(overrides)
    return c


def test_validate_missing_required_field():
    c = _valid_case()
    c.pop("benign_task")
    with pytest.raises(ValueError, match="benign_task"):
        validate_case(c)


def test_validate_unknown_category():
    with pytest.raises(ValueError, match="category"):
        validate_case(_valid_case(category="pwn"))


def test_validate_unknown_variant():
    with pytest.raises(ValueError, match="variant"):
        validate_case(_valid_case(variant="combine_attack"))  # 拼写错


def test_validate_unknown_difficulty():
    with pytest.raises(ValueError, match="difficulty"):
        validate_case(_valid_case(difficulty="mild"))


def test_validate_unknown_channel():
    with pytest.raises(ValueError, match="attack_channel"):
        validate_case(_valid_case(attack_channel="ipi"))


def test_validate_expected_tools_must_be_list_of_str():
    with pytest.raises(ValueError, match="expected_tools"):
        validate_case(_valid_case(expected_tools="SendMoney"))  # str
    with pytest.raises(ValueError, match="expected_tools"):
        validate_case(_valid_case(expected_tools=["SendMoney", 1]))


def test_validate_opi_requires_naive_variant():
    with pytest.raises(ValueError, match="naive"):
        validate_case(_valid_case(attack_channel="opi", variant="fake_completion"))


def test_validate_opi_poison_must_be_basename():
    with pytest.raises(ValueError, match="poison_file"):
        validate_case(_valid_case(attack_channel="opi", poison_file="../evil"))


def test_validate_opi_benign_must_reference_poison_file():
    # poison_file 换成 config.txt,但 benign_task 只引用 notes.txt → 拦截
    with pytest.raises(ValueError, match="config.txt"):
        validate_case(_valid_case(attack_channel="opi", poison_file="config.txt"))


# ------------------------------------------------------------------ load_cases 文件级


def _write_jsonl(tmp_path, rows: list, header: str = "# 测试注释头\n"):
    p = tmp_path / "t.jsonl"
    p.write_text(header + "\n".join(json.dumps(r, ensure_ascii=False) for r in rows),
                 encoding="utf-8")
    return str(p)


def test_load_cases_skips_blanks_and_comments(tmp_path):
    rows = [_valid_case("a_001"), _valid_case("a_002")]
    path = _write_jsonl(tmp_path, rows, header="# 注释行\n\n")
    assert [c["case_id"] for c in load_cases(path)] == ["a_001", "a_002"]


def test_load_cases_keeps_file_order(tmp_path):
    rows = [_valid_case("b_003"), _valid_case("b_001"), _valid_case("b_002")]
    path = _write_jsonl(tmp_path, rows)
    assert [c["case_id"] for c in load_cases(path)] == ["b_003", "b_001", "b_002"]


def test_load_cases_duplicate_id_rejected(tmp_path):
    rows = [_valid_case("c_001"), _valid_case("c_001")]
    path = _write_jsonl(tmp_path, rows)
    with pytest.raises(ValueError, match="重复 case_id"):
        load_cases(path)


def test_load_cases_invalid_json_rejected(tmp_path):
    p = tmp_path / "t.jsonl"
    p.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="非法 JSON"):
        load_cases(str(p))


# ------------------------------------------------------------------ OPI 的 build_prompt


def test_build_prompt_opi_renders_benign_only():
    c = _valid_case()
    c["attack_channel"] = "opi"
    p = build_prompt(c)
    assert "inst" not in p            # 恶意指令不进用户 prompt
    assert "Answer: task complete." not in p
    assert "Final answer below." not in p
    assert "{sandbox_dir}" not in p
    assert SANDBOX_DIR in p


def test_build_prompt_opi_vs_dpi_control():
    c = _valid_case(attacker_instruction="MARKER_XYZ")
    assert "MARKER_XYZ" in build_prompt(c)              # DPI:注入进 prompt
    c["attack_channel"] = "opi"
    assert "MARKER_XYZ" not in build_prompt(c)          # OPI:只在观测层
