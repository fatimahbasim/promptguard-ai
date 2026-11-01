
import re
import json
import argparse
from dataclasses import dataclass, asdict
from typing import List


@dataclass
class Finding:
    category: str
    severity: str
    matched_text: str
    explanation: str


PATTERNS = {
    "instruction_override": [
        r"ignore (all )?(previous|prior) instructions",
        r"disregard (all )?(previous|prior) instructions",
        r"override (the )?system prompt",
        r"forget (all )?(previous|prior) instructions",
        r"ignore the rules",
    ],
    "system_prompt_extraction": [
        r"reveal (the )?(hidden )?system prompt",
        r"show me (the )?(hidden )?system prompt",
        r"print (the )?(hidden )?system prompt",
        r"repeat (the )?(full )?system prompt",
        r"what are your (hidden )?instructions",
    ],
    "data_exfiltration": [
        r"send (all )?(the )?(private|secret|confidential) data",
        r"reveal (all )?(the )?(private|secret|confidential) data",
        r"output (all )?(the )?(api keys|passwords|secrets)",
        r"leak (the )?(database|credentials|secrets)",
        r"exfiltrate",
    ],
    "role_manipulation": [
        r"you are now (a |an )?(different|new|unrestricted)",
        r"pretend to be (a |an )?(different|new)",
        r"act as (an? )?(unrestricted|unfiltered)",
        r"developer mode",
        r"jailbreak",
    ],
}

SEVERITY = {
    "instruction_override": "high",
    "system_prompt_extraction": "high",
    "data_exfiltration": "critical",
    "role_manipulation": "medium",
}

WEIGHTS = {
    "instruction_override": 20,
    "system_prompt_extraction": 30,
    "data_exfiltration": 40,
    "role_manipulation": 15,
}


def scan_prompt(text: str) -> dict:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Input must be a non-empty string.")

    findings: List[Finding] = []

    for category, patterns in PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        category=category,
                        severity=SEVERITY[category],
                        matched_text=match.group(0),
                        explanation=(
                            f"Detected a pattern associated with {category.replace('_', ' ')}."
                        ),
                    )
                )
                break

    score = min(
        100,
        sum(WEIGHTS[item.category] for item in findings)
    )

    if score >= 60:
        risk_level = "CRITICAL"
    elif score >= 30:
        risk_level = "HIGH"
    elif score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "findings_count": len(findings),
        "findings": [asdict(item) for item in findings],
        "disclaimer": (
            "This is a rule-based security scanner. "
            "It identifies known suspicious text patterns and may produce "
            "false positives or miss new attack techniques. "
            "It does not prove that a prompt is safe."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="PromptGuard AI - Explainable prompt injection scanner"
    )
    parser.add_argument(
        "prompt",
        nargs="?",
        help="Text prompt to scan"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    args = parser.parse_args()

    if not args.prompt:
        parser.error("Please provide a prompt to scan.")

    try:
        result = scan_prompt(args.prompt)

        if args.json:
            print(json.dumps(result, indent=2))
            return

        print("\n=== PROMPTGUARD AI ===")
        print(f"Risk score: {result['risk_score']}/100")
        print(f"Risk level: {result['risk_level']}")
        print(f"Findings: {result['findings_count']}")

        for item in result["findings"]:
            print(f"\n[{item['severity'].upper()}] {item['category']}")
            print(f"Matched text: {item['matched_text']}")
            print(f"Explanation: {item['explanation']}")

        if not result["findings"]:
            print("\nNo known suspicious patterns detected.")

        print(f"\nNote: {result['disclaimer']}")

    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
  
