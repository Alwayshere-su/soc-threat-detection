"""Shared encoding, prediction, ID validation and evaluation contracts."""
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score

LABELS = ["benign", "suspicious", "malicious"]
CAT_COLS = ["pipeline", "product_name", "vendor_name", "action", "protocol"]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")


def fit_categories(frame):
    return {c: sorted(frame[c].fillna("").astype(str).unique().tolist())
            for c in CAT_COLS if c in frame}


def encode_features(frame, cats, columns=None):
    """Reuse an immutable training vocabulary; unseen values explicitly map to -1."""
    result = frame.copy()
    for c in CAT_COLS:
        if c in result:
            if c not in cats:
                raise ValueError(f"Missing training vocabulary: {c}")
            mapping = {value: i for i, value in enumerate(cats[c])}
            result[c] = result[c].fillna("").astype(str).map(mapping).fillna(-1)
    if columns is not None:
        missing = set(columns) - set(result.columns)
        if missing:
            raise ValueError(f"Missing model features: {sorted(missing)}")
        result = result.loc[:, columns]
    return result.astype(np.float32)


def predict_probabilities(model, features, n_jobs=8):
    X = encode_features(features, model["cats"], model["common_cols"])
    models = model.get("models") or [model["clf"]]
    prob = np.zeros((len(X), len(LABELS)), dtype=np.float64)
    for clf in models:
        clf.set_params(n_jobs=n_jobs)
        if list(clf.classes_) != [0, 1, 2]:
            raise ValueError("Model class order must be [0, 1, 2]")
        prob += clf.predict_proba(X) / len(models)
    return prob * np.asarray(model.get("coef", [1.0, 1.0, 1.0]))


def validate_ids(ids, name="input"):
    ids = pd.Series(ids, copy=False)
    if ids.isna().any() or not ids.map(lambda v: isinstance(v, str) and bool(v.strip())).all():
        raise ValueError(f"{name}: event_id must be a nonempty string")
    if not ids.is_unique:
        raise ValueError(f"{name}: duplicate event_id")


def validate_submission(result, input_ids):
    if list(result.columns) != ["event_id", "pred_label"]:
        raise ValueError("Submission columns must be event_id,pred_label")
    validate_ids(input_ids, "input")
    validate_ids(result.event_id, "prediction")
    if not result.pred_label.isin(LABELS).all():
        raise ValueError("Prediction contains missing or invalid labels")
    expected = pd.Index(input_ids)
    actual = pd.Index(result.event_id)
    if len(actual) != len(expected) or not actual.isin(expected).all():
        raise ValueError("Prediction IDs must exactly match input IDs")


def align_truth(answer, ids):
    if not {"event_id", "label_binary"}.issubset(answer.columns):
        raise ValueError("Answer needs event_id,label_binary")
    validate_ids(answer.event_id, "answer")
    validate_ids(ids)
    if len(answer) != len(ids) or not pd.Index(ids).isin(answer.event_id).all():
        raise ValueError("Answer IDs must exactly match input IDs")
    truth = answer.set_index("event_id").loc[list(ids), "label_binary"]
    if not truth.isin(LABELS).all():
        raise ValueError("Answer contains missing or invalid labels")
    return truth.to_numpy()


def metrics(truth, prediction):
    from score import official_score_idx
    mapping = {label: i for i, label in enumerate(LABELS)}
    yt = pd.Series(truth).map(mapping).to_numpy()
    yp = pd.Series(prediction).map(mapping).to_numpy()
    if pd.isna(yt).any() or pd.isna(yp).any() or len(yt) != len(yp) or not len(yt):
        raise ValueError("Evaluation needs nonempty, aligned, valid labels")
    total, components = official_score_idx(yt, yp, verbose=False)
    return {"rows": len(yt), "errors": int((yt != yp).sum()),
            "accuracy": float(accuracy_score(yt, yp)),
            "macro_f1": float(f1_score(yt, yp, labels=[0, 1, 2], average="macro", zero_division=0)),
            "final_score": float(total), "components": components,
            "label_order": LABELS, "confusion_matrix": confusion_matrix(yt, yp, labels=[0, 1, 2]).tolist()}


def atomic_csv(frame, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    frame.to_csv(temporary, index=False)
    temporary.replace(path)
