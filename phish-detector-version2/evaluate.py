#!/usr/bin/env python3
# Minimal evaluate.py — accuracy + confusion matrix; optional Excel/CSV export

import os, argparse, csv
from dataclasses import dataclass
from typing import Iterable, List, Tuple
from rules import classify_email, load_config_to_rules


@dataclass(frozen=True)
class EmailSample:
    """Container for a single email sample used during evaluation."""
    sender: str
    subject: str
    body: str
    label: int  # 1 = phishing, 0 = ham
    path: str


def read_text(p: str) -> str:
    """Read a text file, replacing undecodable bytes."""
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_email(raw: str) -> Tuple[str, str, str]:
    """Very simple parser: first line as subject, rest as body; mock sender."""
    lines = raw.splitlines()
    subject = lines[0] if lines else ""
    sender  = "unknown@example.com"
    body    = raw
    return sender, subject, body


def load_dataset(root: str) -> List[EmailSample]:
    """Load dataset folders and return a flat list of EmailSample."""
    samples: List[EmailSample] = []
    for d, lab in (("easy_ham", 0), ("hard_ham", 0), ("spam_2", 1)):
        folder = os.path.join(root, d)
        if not os.path.isdir(folder):
            continue
        for fn in os.listdir(folder):
            fp = os.path.join(folder, fn)
            if not os.path.isfile(fp):
                continue
            s, sub, b = parse_email(read_text(fp))
            samples.append(EmailSample(s, sub, b, lab, fp))
    if not samples:
        raise RuntimeError(f"No emails found under '{root}'. Expected easy_ham/, hard_ham/, spam_2/")
    return samples


def main() -> None:
    ap = argparse.ArgumentParser(description="Evaluate rule-based phishing detector.")
    ap.add_argument("--data-dir", default="dataset", help="Folder with easy_ham/, hard_ham/, spam_2/")
    ap.add_argument("--out", default="", help="Optional output (.xlsx or .csv).")
    args = ap.parse_args()

    load_config_to_rules()  # share config with the app

    samples = load_dataset(args.data_dir)
    y_true: List[int] = []
    y_pred: List[int] = []
    rows: List[dict] = []

    for smp in samples:
        label, score = classify_email(smp.sender, smp.subject, smp.body)
        y_true.append(smp.label)
        y_pred.append(1 if label == "Phishing" else 0)
        if args.out:
            rows.append({
                "path": smp.path,
                "true_label": "phish" if smp.label == 1 else "ham",
                "pred_label": label,
                "score": f"{float(score):.2f}",
                "subject_preview": smp.subject[:120].replace("\n", " ")
            })

    # Confusion matrix (pos = phishing)
    TP = FP = FN = TN = 0
    for t, p in zip(y_true, y_pred):
        if   t == 1 and p == 1: TP += 1
        elif t == 0 and p == 1: FP += 1
        elif t == 1 and p == 0: FN += 1
        else:                   TN += 1

    total = TP + FP + FN + TN
    accuracy = (TP + TN) / total if total else 0.0

    print("\n=== Evaluation Report ===")
    print(f"Dataset: {args.data_dir}  |  Total: {total} (ham={TN+FP}, phish={TP+FN})")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Confusion Matrix  TP={TP}  FP={FP}  FN={FN}  TN={TN}")

    if not args.out:
        return

    base, ext = os.path.splitext(args.out)
    ext = ext.lower()
    summary = {
        "TP": TP, "FP": FP, "FN": FN, "TN": TN, "total": total,
        "accuracy": round(accuracy, 4),
    }

    if ext == ".xlsx":
        try:
            from openpyxl import Workbook
        except ImportError:
            print("[ERR] openpyxl not installed. Install with: pip install openpyxl")
            return
        wb = Workbook()
        ws = wb.active; ws.title = "summary"
        ws.append(["metric", "value"])
        for k, v in summary.items():
            ws.append([k, v])
        # Each email on its own sheet
        for i, r in enumerate(rows, start=1):
            sh = wb.create_sheet(f"email_{i:04d}")
            sh.append(["field", "value"])
            for k in ["path", "true_label", "pred_label", "score", "subject_preview"]:
                sh.append([k, r[k]])
        wb.save(args.out)
        print(f"[OK] Excel written to: {args.out}  (summary + {len(rows)} email sheets)")
    else:
        # CSV: predictions to <base>.csv and summary to <base>_summary.csv
        pred_csv = base + ".csv"
        sum_csv  = base + "_summary.csv"
        with open(pred_csv, "w", newline="", encoding="utf-8") as f:
            fieldnames = list(rows[0].keys()) if rows else [
                "path", "true_label", "pred_label", "score", "subject_preview"
            ]
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader(); w.writerows(rows)
        with open(sum_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(summary.keys()))
            w.writeheader(); w.writerow(summary)
        print(f"[OK] CSV written to: {pred_csv} and {sum_csv}")


if __name__ == "__main__":
    main()
