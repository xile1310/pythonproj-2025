from typing import Dict  # Dict type hint
from utils import parse_email_like_text  # parsing helpers
from rules import run_all_rules  # rule runner

def analyze_email_text(raw_text: str) -> Dict[str, object]:
    parsed = parse_email_like_text(raw_text)  # parse headers/body
    results = run_all_rules(parsed)  # execute all rules
    return results  # return aggregated results
