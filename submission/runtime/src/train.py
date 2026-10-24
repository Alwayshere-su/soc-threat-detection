"""Single-model entry point and compatibility helpers for diagnostic scripts."""
import numpy as np
import pandas as pd
from pipeline import LABELS as LBL, CAT_COLS, encode_features, fit_categories
from sklearn.metrics import accuracy_score, classification_report, f1_score, roc_auc_score

def load_xy(feats_path, cats=None):
    frame = pd.read_parquet(feats_path)
    if cats is None:
        cats = fit_categories(frame)
    label = frame["label_binary"].map(dict(zip(LBL,range(3)))).to_numpy() if "label_binary" in frame else None
    if label is not None and pd.isna(label).any():
        raise ValueError("Invalid training label")
    features = frame.drop(columns=[c for c in ["event_id","label_binary"] if c in frame])
    return encode_features(features,cats),label,cats

def evaluate(y_true_idx, y_pred_idx, y_prob, prefix=""):
    print(f"{prefix} acc={accuracy_score(y_true_idx,y_pred_idx):.6f} macro_f1={f1_score(y_true_idx,y_pred_idx,average='macro'):.6f}")
    print(classification_report(y_true_idx,y_pred_idx,labels=[0,1,2],target_names=LBL,digits=6))
    print(f"macro_auc={roc_auc_score(y_true_idx,y_prob,multi_class='ovr',average='macro'):.6f}")
    return f1_score(y_true_idx,y_pred_idx,average="macro")

def main():
    from training import run
    run(ensemble=False)

if __name__ == "__main__":
    main()
