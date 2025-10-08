#!/usr/bin/env python3
# Minimal evaluate.py — accuracy + confusion matrix; optional Excel export

import os, argparse
import rules
def read_text(p):
    """Read a text file as UTF-8, replacing invalid sequences.

    Args:
        p: Path to a text file.

    Returns:
        Full file contents as a single string.
    """
        # Open the file at path in read mode r
        # Encode text files using utf-8
        # If invalid errors are found, replace them instead of raising an error
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        # Read the entire content of the file
        # And return it as a string
        return f.read()


def parse_email(raw):
    """Parse naive email fields from raw text.

    Splits lines to obtain a faux subject and sets a placeholder sender.

    Args:
        raw: Raw email text.

    Returns:
        Tuple (sender, subject, body).
    """
    # Split raw email text into sender, subject, body
    lines = raw.splitlines()
    # Here we assume the first line is the subject
    # If not set it to an empty string 
    subject = lines[0] if lines else ""
    # Try to extract sender from a From: header; fallback to placeholder
    sender  = next((ln.split(":",1)[1].strip().split()[-1].strip("<>\"')(") for ln in lines if ln.lower().startswith("from:") and "@" in ln), "unknown@example.com")
    # Treat raw text as email body
    body    = raw
    # Return sender, subject, and body
    return sender, subject, body

def load_dataset(root):
    """Load dataset samples from labeled folders.

    Expects subdirectories: easy_ham/, hard_ham/, spam_2/.

    Args:
        root: Path to dataset directory.

    Returns:
        List of tuples (sender, subject, body, label, path).

    Raises:
        RuntimeError: If no samples are found under the root.
    """
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
    """Evaluate the rule-based classifier and optionally export results.

    Parses command-line options, loads rules and dataset, computes accuracy
    and confusion matrix, and optionally writes detailed outputs to Excel.
    """
    # Create argument parser for command-line options
    ap = argparse.ArgumentParser(description="Evaluate rule-based phishing detector.")
    # Add argument for dataset folder location
    # Default is "dataset"
    ap.add_argument("--data-dir", default="dataset", help="Folder with easy_ham/, hard_ham/, spam_2/")
    # Add optional argument for output file (.xlsx)
    ap.add_argument("-out", default="", help="Optional output (.xlsx).")
    # Parse command-line arguments
    args = ap.parse_args()
    # Loads detection rules from configuration
    rules.load_config_to_rules()  # share config with the app
    # Load dataset emails & labels from given folder
    samples = load_dataset(args.data_dir)
    # Prepare lists to hold true labels, predicted labels, and output rows
    y_true, y_pred, rows = [], [], []
    # Process every email sample
    for sender, subject, body, gold, path in samples:
        # Run the email using the classifier, then get prdicted label and score
        label, score = rules.classify_email(sender, subject, body)
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
    # Initialise all 4 variables to zero
    # TP = True Positive, FP = False Positive
    # FN = False Negative, TN = True Negative
    TP = FP = FN = TN = 0

    # Loop over true(y_true) and predicted(y_pred) labels to populate confusion matrix
    for t, p in zip(y_true, y_pred):
        if   t==1 and p==1: TP+=1 # If model correctly predict phishing email as phishing, increase TP by 1 (true positive)
        elif t==0 and p==1: FP+=1 # If model incorrectly predict ham email as phishing, increase FP by 1 (false positive)
        elif t==1 and p==0: FN+=1 # If model incorrectly predict phishing email as ham, increase FN by 1 (false negative)
        else:               TN+=1 # If model correctly predict ham email as ham, increase TN by 1 (true negative)

    # Calculate total number of samples
    total = TP+FP+FN+TN
    # Calculate accuracy correct predictions / total samples
    # If total is zero (to avoid division by zero), set accuracy to 0.
    accuracy  = (TP+TN)/total if total else 0.0

    print("\n=== Evaluation Report ===")
    print(f"Dataset: {args.data_dir}  |  Total: {total} (ham={TN+FP}, phish={TP+FN})") # Print dataset location, total number of samples, how many ham vs phishing
    print(f"Accuracy : {accuracy:.4f}") # Print accuracy score (correct prediction/total), to 4 decimal places
    print(f"Confusion Matrix  TP={TP}  FP={FP}  FN={FN}  TN={TN}") # Print full cnfusion matrix

    # If no output file is specified, exit here
    if not args.out:
        return
    
    # Prepare output file paths and summary statistics

    # Split output file path into base and ext
    base, _ = os.path.splitext(args.out) # Get base and extension of output file path
    args.out = base + ".xlsx"
    ext = ".xlsx"

    # Convert extension to lowercase for consistency
    ext = ext.lower()

    # Create a summary dictionary with evaluation results
    summary = {
        "TP": TP, "FP": FP, "FN": FN, "TN": TN, "total": total,
        "accuracy": round(accuracy,4), # Round accuracy to 4 decimal places
    }

    #Add results to excel
    if ext == ".xlsx":
        try:
            from openpyxl import Workbook # Try to import openpyxl for Excel 
        except ImportError:
            print("[ERR] openpyxl not installed. Install with: pip install openpyxl") # If openpyxl is not installed, print error message and stop
            return
        
         # Create a new Excel workbook and add summary sheet
        wb = Workbook()
        ws = wb.active; ws.title = "summary"

        # Add confusion metrix summary 
        ws.append(["metric","value"])
        for k,v in summary.items(): ws.append([k,v])

        # Write all email predictions into a single sheet named "predictions"
        ws_pred = wb.create_sheet("predictions")
        headers = ["path", "true_label", "pred_label", "score", "subject_preview"] #headers for the prediction sheet
        ws_pred.append(headers)
        for r in rows:
            ws_pred.append([r.get(h, "") for h in headers])

        # Save excel
        wb.save(args.out)
        print(f"[OK] Excel written to: {args.out}  (summary + predictions sheet {len(rows)} rows)")

if __name__ == "__main__":
    main()
