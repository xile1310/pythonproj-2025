#!/usr/bin/env python3
# Minimal evaluate.py — accuracy + confusion matrix; optional Excel/CSV export

import os, argparse, csv
from rules import classify_email, load_config_to_rules

def read_text(p):
        # Open the file at path in read mode r
        # Encode text files using utf-8
        # If invalid errors are found, replace them instead of raising an error
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        # Read the entire content of the file
        # And return it as a string
        return f.read()


def parse_email(raw):
    # Split raw email text into sender, subject, body
    lines = raw.splitlines()
    # Here we assume the first line is the subject
    # If not set it to an empty string 
    subject = lines[0] if lines else ""
    # Set sender to a placeholder since it's not extracted from raw text
    sender  = "unknown@example.com"
    # Treat raw text as email body
    body    = raw
    # Return sender, subject, and body
    return sender, subject, body

def load_dataset(root):
    # Create empty list to hold all sample emails
    # Each sample is a tuple of (sender, subject, body, label, path)
    samples = []  # (sender, subject, body, label, path)
    # Loop over dataset folders and assign them labels
    # "easy_ham" and "hard_ham" are labeled as 0 (ham)
    # "spam_2" is labeled as 1 (phishing)
    for d, lab in (("easy_ham",0), ("hard_ham",0), ("spam_2",1)):
        folder = os.path.join(root, d) # path to the folder
        if not os.path.isdir(folder): continue # skip this is the folder does not exist
        #Iterate over all files in the folder
        for fn in os.listdir(folder):
            fp = os.path.join(folder, fn) # Full file path
            if not os.path.isfile(fp): continue #Skip it if it's not a file
            # Read email file and parse it into sender, subject, and body
            s, sub, b = parse_email(read_text(fp))
            # Append parsed email with its label and file path
            samples.append((s, sub, b, lab, fp))
            # If no emails found in the folder, raise an error
    if not samples:
        raise RuntimeError(f"No emails found under '{root}'. Expected easy_ham/, hard_ham/, spam_2/")
    # Return the list of samples
    return samples

def main():
    # Create argument parser for command-line options
    ap = argparse.ArgumentParser(description="Evaluate rule-based phishing detector.")
    # Add argument for dataset folder location
    # Default is "dataset"
    ap.add_argument("--data-dir", default="dataset", help="Folder with easy_ham/, hard_ham/, spam_2/")
    # Add optional argument for output file (.xlsx or .csv)
    ap.add_argument("--out", default="", help="Optional output (.xlsx or .csv).")
    # Parse command-line arguments
    args = ap.parse_args()
    # Loads detection rules from configuration
    load_config_to_rules()  # share config with the app
    # Load dataset emails & labels from given folder
    samples = load_dataset(args.data_dir)
    # Prepare lists to hold true labels, predicted labels, and output rows
    y_true, y_pred, rows = [], [], []
    # Process every email sample
    for sender, subject, body, gold, path in samples:
        # Run the email using the classifier, then get prdicted label and score
        label, score = classify_email(sender, subject, body)
        # 0 = ham, 1= phishing
        y_true.append(gold)
        # Save predicted label as 1 if its "Phishing" otherwise label as 0
        y_pred.append(1 if label == "Phishing" else 0)
        # If output file is requested, store results in rows
        if args.out:
            rows.append({
                "path": path,                                      # email file path
                "true_label": "phish" if gold==1 else "ham",       # truth label
                "pred_label": label,                               # predicted label
                "score": f"{float(score):.2f}",                    # prediction score (2d.p)
                "subject_preview": subject[:120].replace("\n"," ") #subject line preview limited to 120 chars 
            })

    # Confusion matrix (pos = phishing)
    TP = FP = FN = TN = 0
    for t, p in zip(y_true, y_pred):
        if   t==1 and p==1: TP+=1
        elif t==0 and p==1: FP+=1
        elif t==1 and p==0: FN+=1
        else:               TN+=1

    total = TP+FP+FN+TN
    accuracy  = (TP+TN)/total if total else 0.0

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
        "accuracy": round(accuracy,4),
    }

    if ext == ".xlsx":
        try:
            from openpyxl import Workbook
        except ImportError:
            print("[ERR] openpyxl not installed. Install with: pip install openpyxl")
            return
        wb = Workbook()
        ws = wb.active; ws.title = "summary"
        ws.append(["metric","value"])
        for k,v in summary.items(): ws.append([k,v])
        # Each email on its own sheet
        for i, r in enumerate(rows, start=1):
            sh = wb.create_sheet(f"email_{i:04d}")
            sh.append(["field","value"])
            for k in ["path","true_label","pred_label","score","subject_preview"]:
                sh.append([k, r[k]])
        wb.save(args.out)
        print(f"[OK] Excel written to: {args.out}  (summary + {len(rows)} email sheets)")
    else:
        # CSV: predictions to <base>.csv and summary to <base>_summary.csv
        pred_csv = base + ".csv"
        sum_csv  = base + "_summary.csv"
        with open(pred_csv, "w", newline="", encoding="utf-8") as f:
            fieldnames = list(rows[0].keys()) if rows else \
                ["path","true_label","pred_label","score","subject_preview"]
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader(); w.writerows(rows)
        with open(sum_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(summary.keys()))
            w.writeheader(); w.writerow(summary)
        print(f"[OK] CSV written to: {pred_csv} and {sum_csv}")

if __name__ == "__main__":
    main()
