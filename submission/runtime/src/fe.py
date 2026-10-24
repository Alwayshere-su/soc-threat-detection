"""面向 SOC 威胁检测的特征工程。

从脱敏/伪匿名的安全日志字段中构造人工特征，重点利用 `message_sanitized`
文本以及结构化列。

数据被高度匿名化（CRED-<num>、ORG-<num>、USER-<num> 令牌替换敏感值），
因此我们依赖 *结构性* 信号：消息族、端口、协议、区域、动作、令牌组成，以及类别字段。
"""

import re
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# 预编译正则
# ---------------------------------------------------------------------------
RE_DSPORT = re.compile(r"(?:dport|dst_port|destination[-_ ]?port)\s*=\s*(\d+)", re.I)
RE_SSPORT = re.compile(r"(?:sport|src_port|source[-_ ]?port)\s*=\s*(\d+)", re.I)
RE_PORT = re.compile(r"\bport\s+(\d+)\b", re.I)
RE_PROTO = re.compile(r"\bprotocol\s*=\s*(\w+)", re.I)
RE_DSTPROTO = re.compile(r"\b(?:proto|protocol)\s+(\w+)", re.I)  # 防火墙风格 "Deny tcp"
RE_ACTION = re.compile(r"\b(deny|permit|accept(?:ed)?|reject|failed|failure|blocked|drop(?:ped)?|allow(?:ed)?)\b", re.I)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_CEF = re.compile(r"\bCEF:(\d)\|")
_EVENT_TAG = r"(?:EventID|(?:USER|ORG|HOST)-\d+(?:-\d+)*ID)"
RE_WINEVENT_PORTABLE = re.compile(
    rf"<{_EVENT_TAG}(?:\s[^>]*)?>\s*(\d+)\s*</{_EVENT_TAG}>", re.I)
FEATURE_VERSIONS = ("portable_v1",)
RE_ZONE = re.compile(r"\b(outside|inside|dmz|d?m[z]\w*|external|internal|guest|trust|untrust)\b", re.I)

# CRED- / ORG- / USER- 令牌计数器。注意匿名化的端口会以
# *port=CRED-123* 或 *port=5CRED-456*（保留前导数字）的形式出现。
RE_CRED = re.compile(r"CRED-\d+")
RE_ORG = re.compile(r"ORG-\d+")
RE_USER = re.compile(r"USER-\d+")

_ACTIONS = {"deny", "permit", "accept", "accepted", "reject", "failed", "failure",
            "blocked", "drop", "dropped", "allow", "allowed"}


def _safe_int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return -1


def extract_basic_features(df: pd.DataFrame, feature_version="portable_v1") -> pd.DataFrame:
    """无需复杂字符串处理的向量化特征。"""
    out = pd.DataFrame(index=df.index)

    msg = df["message_sanitized"].fillna("").astype(str)
    pl = df["pipeline"].fillna("").astype(str)

    # --- 类别字段（原始字符串；LightGBM 之后可按 category 处理）---
    out["pipeline"] = pl
    out["product_name"] = df["product_name"].fillna("").astype(str)
    out["vendor_name"] = df["vendor_name"].fillna("").astype(str)

    # --- 匿名令牌组成 ---
    out["n_cred"] = msg.str.count(r"CRED-\d+")
    out["n_org"] = msg.str.count(r"ORG-\d+")
    out["n_user"] = msg.str.count(r"USER-\d+")
    out["msg_len"] = msg.str.len()
    out["msg_words"] = msg.str.split().str.len().fillna(0)

    # --- 消息族标志（二进制）---
    fl = msg.str.lower()
    out["is_netflow"] = fl.str.contains("flows src=").astype(np.int8)
    out["is_firewall"] = fl.str.contains(r"\bdeny\b|\bpermit\b").astype(np.int8)
    out["is_windows_xml"] = fl.str.contains("xmlns=").astype(np.int8)
    out["is_elk_json"] = fl.str.contains("winlogbeat").astype(np.int8)
    out["is_aws"] = (df["pipeline"] == "aws_cloudtrail").astype(np.int8)
    out["is_cef"] = fl.str.contains("cef:").astype(np.int8)
    out["is_sshd"] = fl.str.contains("sshd").astype(np.int8)
    out["is_cmd"] = fl.str.contains(r"\bcmd\b").astype(np.int8)
    out["is_cloudtrail"] = fl.str.contains("cloudtrail").astype(np.int8)

    # --- 动作（one/few-hot）---
    action_first = fl.str.extract(r"\b(deny|permit|accept(?:ed)?|reject|failed|failure|blocked|drop(?:ped)?|allow(?:ed)?)\b", expand=False)
    out["action"] = action_first.fillna("none")
    for a in sorted(_ACTIONS):
        out[f"act_{a}"] = (action_first == a).astype(np.int8)

    # --- 数值 / 端口 ---
    out["n_ips"] = msg.str.count(RE_IP.pattern)
    out["dport"] = msg.str.extract(RE_DSPORT, expand=False).map(_safe_int)
    out["sport"] = msg.str.extract(RE_SSPORT, expand=False).map(_safe_int)
    out["port_generic"] = msg.str.extract(RE_PORT, expand=False).map(_safe_int)
    out["protocol"] = msg.str.extract(RE_PROTO, expand=False).fillna(
        msg.str.extract(RE_DSTPROTO, expand=False)
    ).fillna("")
    out["protocol"] = out["protocol"].str.lower()
    # 通用端口兜底（防火墙风格 "Deny tcp ... /56450"）
    out["port_any"] = out[["dport", "sport", "port_generic"]].max(axis=1)

    # --- 区域存在性 ---
    for z in ["outside", "inside", "dmz", "external", "internal"]:
        out[f"zone_{z}"] = fl.str.contains(z).astype(np.int8)

    # --- windows 事件 ID ---
    if feature_version not in FEATURE_VERSIONS:
        raise ValueError(f"Unknown feature version: {feature_version}")
    we = msg.str.extract(RE_WINEVENT_PORTABLE, expand=False).map(_safe_int)
    out["win_event_id"] = we
    out["has_win_event"] = (we > 0).astype(np.int8)

    # --- 跨源威胁 / 行为信号令牌 -------------------
    # 这些是稳定、非匿名的关键词，出现在许多产品族中，
    # 且对数据集特有的匿名化鲁棒。
    # 风险指示（预测非良性）：
    kw_risk = {
        "blocked": r"\bblocked\b|\bblock\b",
        "detection": r"\bdetect\w*\b",                        # EDR "Detection" 流向
        "denied_result": r"result[= ]+deni|\bdenied\b",
        "no_response": r"no_response|no response",
        "auth_failure": r"auth_failure|auth_failed|failed (?:password|logon|login|auth)|invalid (?:password|passcode|user)|invalid_passcode|access denied",
        "failed": r"\bfailed\b|\bfail\b|failure",
        "anomaly": r"anomal|suspicious|malicious|threat|attack|exploit|malware|ransom|intrusion",
        "bruteforce": r"brute|many failed|repeated failed",
        "filehash": r"filehash|sha256|md5",
        "filepath": r"filepath",
    }
    # 良性标记（在 artifact / 云 / 认证日志中预测良性）：
    kw_benign = {
        "asset_inventory": r"asset_inventory",
        "auth_success": r"auth_success|result[= ]+success|\bsuccess\b",
        "dirinfo": r"displayname|jobtitle|\bmail\b",
        "permitted": r"\bpermit(?:ted)?\b|\bacc[e]?pt(?:ed)?\b|\ballow(?:ed)?\b",
    }
    for name, pat in kw_risk.items():
        out[f"r_{name}"] = fl.str.contains(pat).astype(np.int8)
    for name, pat in kw_benign.items():
        out[f"b_{name}"] = fl.str.contains(pat).astype(np.int8)

    # --- src_ip / dst_ip 信号 ---
    for col in ["src_ip", "dst_ip", "src_host", "dst_host", "username"]:
        v = df[col]
        out[f"{col}_filled"] = (~v.isna() & (v.astype(str).str.strip() != "")).astype(np.int8)

    return out


def build_features(df: pd.DataFrame, feature_version="portable_v1") -> pd.DataFrame:
    f = extract_basic_features(df, feature_version=feature_version)
    return f


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path:
        df = pd.read_parquet(path)
        f = build_features(df)
        print(f.shape)
        for c in f.columns:
            if f[c].dtype.kind in "iuf":
                print(f"{c:20s} nunique={f[c].nunique():7d}  mean={f[c].mean():.4f}  null={f[c].isna().sum()}")
