"""报告:结果 dict 列表 → DataFrame / 聚合 / 打印 / 落盘。"""

import json
import os

import pandas as pd

from agenteval.paths import PROJECT_ROOT

REPORT_COLS = [
    "case_id",
    "category",
    "variant",
    "description",
    "status",
    "seconds",
    "asr",
    "rr",
    "tss",
]


def make_dataframe(results: list) -> pd.DataFrame:
    """把 run_suite 的结果行压成明细 DataFrame。"""
    rows = [{k: r.get(k) for k in REPORT_COLS} for r in results]
    return pd.DataFrame(rows, columns=REPORT_COLS)


def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    """总体 + 按类别聚合(ASR/RR/TSS 均值、秒数合计)。空表直接返回空。"""
    if df.empty:
        return pd.DataFrame(columns=REPORT_COLS)
    overall = {
        "case_id": "OVERALL",
        "category": "all",
        "variant": "",
        "description": "全部用例",
        "status": "",
        "seconds": round(float(df["seconds"].sum()), 2),
        "asr": round(float(df["asr"].mean()), 3),
        "rr": round(float(df["rr"].mean()), 3),
        "tss": round(float(df["tss"].mean()), 3),
    }
    by_cat = (
        df.groupby("category", sort=False)[["asr", "rr", "tss"]]
        .mean()
        .round(3)
        .reset_index()
    )
    # seconds 是合计口径(与 OVERALL 行一致),ASR/RR/TSS 是均值。
    sec_sum = df.groupby("category", sort=False)["seconds"].sum().round(2)
    by_cat["seconds"] = by_cat["category"].map(sec_sum)
    by_cat["case_id"] = "CATEGORY:" + by_cat["category"]
    for col in ("variant", "description", "status"):
        by_cat[col] = ""
    by_cat = by_cat[REPORT_COLS]
    return pd.concat([pd.DataFrame([overall]), by_cat], ignore_index=True)


def print_report(df: pd.DataFrame, agg: pd.DataFrame) -> None:
    """控制台打印明细 + 聚合。"""
    print("\n================ 用例明细 ================")
    print(df.to_string(index=False))
    print("\n================ 聚合(ASR/RR/TSS 均值) ================")
    print(agg.to_string(index=False))
    print()


def save_results(
    results: list, json_path: str | None = None, csv_path: str | None = None
) -> dict:
    """把结果落盘(相对 PROJECT_ROOT 解析),返回实际保存路径。"""
    saved = {}
    if json_path:
        path = os.path.join(PROJECT_ROOT, json_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        saved["json"] = path
    if csv_path:
        path = os.path.join(PROJECT_ROOT, csv_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        make_dataframe(results).to_csv(path, index=False, encoding="utf-8-sig")
        saved["csv"] = path
    return saved
