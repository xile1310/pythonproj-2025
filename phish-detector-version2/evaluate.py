#!/usr/bin/env python3
# Minimal evaluate.py — accuracy + confusion matrix; optional Excel export

import os, argparse
from email.parser import BytesParser
from email.message import EmailMessage
import newrules
def read_text(p):
    """Read text file as UTF-8, replacing invalid sequences."""
        # Open the file at path in read mode r
        # Encode text files using utf-8
        # If invalid errors are found, replace them instead of raising an error
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        # Read the entire content of the file
        # And return it as a string
        return f.read()


def parse_email(raw):
    """Parse email fields using BytesParser for improved accuracy."""
    try:
        # Convert string to bytes for BytesParser
        raw_bytes = raw.encode('utf-8', errors='replace')
        
        # Parse email using BytesParser
        parser = BytesParser()
        msg = parser.parsebytes(raw_bytes)
        
        # Extract sender from From header
        sender = "unknown@example.com"  # default fallback
        if 'From' in msg:
            from_header = msg['From']
            if from_header:
                # Extract email address from "Name <email@domain.com>" format
                if '<' in from_header and '>' in from_header:
                    # Extract email from angle brackets
                    start = from_header.find('<') + 1
                    end = from_header.find('>')
                    sender = from_header[start:end].strip()
                elif '@' in from_header:
                    # If no angle brackets, use the whole string if it contains @
                    sender = from_header.strip()
        
        # Extract subject
        subject = msg.get('Subject', '').strip() if msg.get('Subject') else ""
        
        # Extract body content
        body = ""
        if msg.is_multipart():
            # Handle multipart messages
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode('utf-8', errors='replace')
        else:
            # Handle single part messages
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode('utf-8', errors='replace')
        
        # If no body found, use the raw content as fallback
        if not body.strip():
            body = raw
        
        return sender, subject, body
        
    except Exception as e:
        # Fallback to original parsing if BytesParser fails
        lines = raw.splitlines()
        subject = lines[0] if lines else ""
        sender = next((ln.split(":",1)[1].strip().split()[-1].strip("<>\"')(") for ln in lines if ln.lower().startswith("from:") and "@" in ln), "unknown@example.com")
        body = raw
        return sender, subject, body

def load_dataset(root):
    """Load email dataset from directory structure."""
    samples = []  # (sender, subject, body, label, path)
    
    # Define possible folder structures
    dataset_structures = [
        # Original dataset structure (dataset)
        [("easy_ham", 0), ("hard_ham", 0), ("spam_2", 1)],
        # dataset2 and dataset3 structure
        [("ham", 0), ("spam", 1)]
    ]
    
    # Try each dataset structure
    for structure in dataset_structures:
        has_valid_folders = False
        for d, lab in structure:
            folder = os.path.join(root, d)
            if os.path.isdir(folder):
                has_valid_folders = True
                for fn in os.listdir(folder):
                    fp = os.path.join(folder, fn)
                    if not os.path.isfile(fp):
                        continue
                    s, sub, b = parse_email(read_text(fp))
                    samples.append((s, sub, b, lab, fp))
        
        # If we found valid folders in this structure, we can stop checking
        if has_valid_folders:
            break
    
    # If no samples were found at all, raise an error
    if not samples:
        raise RuntimeError(f"No emails found under '{root}'. Expected either:\n"
                         f"1. easy_ham/, hard_ham/, spam_2/ (dataset)\n"
                         f"2. ham/, spam/ (dataset2 or dataset3)")
    # Return the list of samples
    return samples


def main():
    """Evaluate the rule-based classifier and optionally export results.

    Parses command-line options, loads newrules and dataset, computes accuracy
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
    newrules.load_config_to_rules()  # share config with the app
    # Load dataset emails & labels from given folder
    samples = load_dataset(args.data_dir)
    # Prepare lists to hold true labels, predicted labels, and output rows
    y_true, y_pred, rows = [], [], []
    # Process every email sample
    for sender, subject, body, gold, path in samples:
        # Run the email using the classifier, then get prdicted label and score
        label, score = newrules.classify_email(sender, subject, body)
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
