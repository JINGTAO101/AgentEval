"""报告聚合:seconds 合计、ASR/RR/TSS 均值、空表处理。"""

import pandas as pd

from agenteval.report import aggregate, make_dataframe


def _rows():
    return [
        {"case_id": "pi_001", "category": "prompt_injection", "variant": "", "description": "", "status": "ok",
         "seconds": 3.0, "asr": 0.0, "rr": 0.0, "tss": 1.0},
        {"case_id": "pi_002", "category": "prompt_injection", "variant": "", "description": "", "status": "ok",
         "seconds": 5.0, "asr": 1.0, "rr": 0.0, "tss": 1.0},
        {"case_id": "tl_001", "category": "tool_abuse", "variant": "", "description": "", "status": "ok",
         "seconds": 4.0, "asr": 1.0, "rr": 0.0, "tss": 0.0},
    ]


def test_aggregate_empty():
    assert aggregate(pd.DataFrame(columns=["case_id"])).empty


def test_aggregate_seconds_is_sum_per_category():
    agg = aggregate(make_dataframe(_rows()))
    pi = agg[agg["category"] == "prompt_injection"].iloc[0]
    tl = agg[agg["category"] == "tool_abuse"].iloc[0]
    overall = agg[agg["case_id"] == "OVERALL"].iloc[0]
    assert pi["seconds"] == 8.0     # 3 + 5(合计,不是均值)
    assert pi["asr"] == 0.5         # mean(0, 1)
    assert tl["seconds"] == 4.0
    assert overall["seconds"] == 12.0  # 3 + 5 + 4
