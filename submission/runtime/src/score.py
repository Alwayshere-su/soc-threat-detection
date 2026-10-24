"""官方竞赛评分（来源：测评方案.md）。

Final Score =
  0.40 * ThreatBinary_F1 + 0.25 * ThreatBinary_Recall + 0.15 * Threat_Recall
+ 0.10 * Macro_F1 + 0.05 * Soft_Label_Score + 0.05 * Balanced_Accuracy

Threat = 把 {suspicious, malicious} 合并成一个正类；benign 为负类。

同时提供字符串标签接口（official_score）和快速索引接口
（official_score_idx）。索引接口中标签为 0=benign,1=suspicious,2=malicious
（与 LABELS 顺序一致）。
"""
import numpy as np
import os, sys
from sklearn.metrics import f1_score, recall_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import BASE

LABELS = ["benign", "suspicious", "malicious"]
W = {"tb_f1": 0.40, "tb_rec": 0.25, "threat_rec": 0.15, "macro_f1": 0.10,
     "soft": 0.05, "bal_acc": 0.05}


def _indices(x):
    return np.array([LABELS.index(v) for v in x])


def official_score_idx(yt, yp, verbose=True):
    """yt/yp 为整数标签数组（0,1,2）。返回 (总分, 分量字典)。"""
    yt = np.asarray(yt)
    yp = np.asarray(yp)
    if yt.ndim != 1 or yp.ndim != 1 or len(yt) != len(yp) or not len(yt):
        raise ValueError("Scoring needs nonempty aligned one-dimensional labels")
    if not np.isin(yt,[0,1,2]).all() or not np.isin(yp,[0,1,2]).all():
        raise ValueError("Invalid class indices")
    tb_true = (yt > 0).astype(np.int8)
    tb_pred = (yp > 0).astype(np.int8)
    tb_f1 = f1_score(tb_true, tb_pred, pos_label=1, zero_division=0)
    tb_rec = recall_score(tb_true, tb_pred, pos_label=1, zero_division=0)

    rec = {}
    for c in range(3):
        mask = yt == c
        rec[LABELS[c]] = float((yp[mask] == c).mean()) if mask.any() else 0.0
    threat_rec = (rec["suspicious"] + rec["malicious"]) / 2.0
    macro_f1 = f1_score(yt, yp, labels=[0,1,2], average="macro", zero_division=0)
    soft = float(np.where(yt == yp, 1.0, np.where((yt > 0) & (yp > 0), 0.5, 0.0)).mean())
    bal_acc = float(np.mean(list(rec.values())))

    total = (W["tb_f1"] * tb_f1 + W["tb_rec"] * tb_rec + W["threat_rec"] * threat_rec
             + W["macro_f1"] * macro_f1 + W["soft"] * soft + W["bal_acc"] * bal_acc)
    comp = dict(tb_f1=tb_f1, tb_rec=tb_rec, threat_rec=threat_rec, macro_f1=macro_f1,
                soft=soft, bal_acc=bal_acc, rec=rec)
    if verbose:
        print("=== 官方综合评分 ===")
        print(f"  Threat-Binary-F1   (40%) = {tb_f1:.4f}")
        print(f"  Threat-Binary-Recall(25%) = {tb_rec:.4f}")
        print(f"  Threat-Recall      (15%) = {threat_rec:.4f}  (sus={rec['suspicious']:.4f}, mal={rec['malicious']:.4f})")
        print(f"  Macro-F1           (10%) = {macro_f1:.4f}")
        print(f"  Soft-Label-Score    (5%) = {soft:.4f}")
        print(f"  Balanced-Accuracy   (5%) = {bal_acc:.4f}")
        print(f"  ----------------------------------------")
        print(f"  FINAL SCORE              = {total:.4f}")
    return total, comp


def official_score(y_true, y_pred, verbose=True):
    """字符串标签接口。y_true/y_pred 为 'benign','suspicious','malicious' 数组。"""
    yt = _indices(y_true)
    yp = _indices(y_pred)
    total, comp = official_score_idx(yt, yp, verbose=verbose)
    return total


# 调优使用的便捷指标函数 -------------------------------------------------
import re

# 高精度显式威胁 token（在开发集已验证约 100% 威胁精确率）。
THREAT_TOKEN_RE = (r"malware|ransomware|exploit|trojan|backdoor|botnet|keylogger|"
                   r"infostealer|threat(?:s)?.{0,12}map|threatintel|crowdstrike detection|\bioc\b")


def apply_threat_rule(pred_labels, messages, target="malicious"):
    """威胁关键词后处理；新数据仍需检查误报。

    仅当消息包含显式的高精度威胁指示时，把 benign 提升为 target（默认 malicious）。
    不把已识别的威胁降级。既有开发集增加 0 个良性误报，不保证新来源同样成立。
    """
    if target not in LABELS:
        raise ValueError(f"Invalid target label: {target}")
    upd = np.array(pred_labels, dtype=object)
    if len(upd) != len(messages):
        raise ValueError("Prediction/message lengths differ")
    hit = np.array([bool(re.search(THREAT_TOKEN_RE, str(m), re.I)) for m in messages])
    mask = hit & (upd == "benign")
    upd[mask] = target
    return upd


def threat_binary_metrics(y_true, y_pred):
    yt = _indices(y_true); yp = _indices(y_pred)
    tb_true = (yt > 0).astype(int); tb_pred = (yp > 0).astype(int)
    return f1_score(tb_true, tb_pred, pos_label=1, zero_division=0), \
           recall_score(tb_true, tb_pred, pos_label=1, zero_division=0)


def class_recalls(y_true, y_pred, labels=LABELS):
    yt = np.array(list(y_true)); yp = np.array(list(y_pred))
    return {c: float((yp[yt == c] == c).mean()) for c in labels}


if __name__ == "__main__":
    import argparse
    import pandas as pd
    from pipeline import align_truth, metrics, validate_submission, write_json
    ap = argparse.ArgumentParser()
    ap.add_argument("--pred", default=os.path.join(BASE,"res.csv"))
    ap.add_argument("--raw-pred")
    ap.add_argument("--answer", default=os.path.join(BASE,"data/验证集答案/valid_answer_private.parquet"))
    ap.add_argument("--report")
    args = ap.parse_args()
    pred = pd.read_csv(args.pred)
    validate_submission(pred,pred.event_id)
    truth = align_truth(pd.read_parquet(args.answer),pred.event_id)
    report = {"final":metrics(truth,pred.pred_label)}
    if args.raw_pred:
        raw = pd.read_csv(args.raw_pred)
        validate_submission(raw,pred.event_id)
        raw = raw.set_index("event_id").loc[pred.event_id]
        report["raw"] = metrics(truth,raw.pred_label)
    print(report)
    if args.report:
        write_json(args.report,report)
