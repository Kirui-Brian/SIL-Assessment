"""Rule-based detectors for PHI/PII, secrets and prompt injection.

Regex is the fast first layer (sub-millisecond, deterministic, easy to audit). A Presidio/NER layer can be
added for free-text names and addresses, at the cost of latency and false positives.
Findings never carry the matched text, only the category and span, so logs cannot become a second leak.
"""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    kind: str       # e.g. KE_NATIONAL_ID
    group: str      # phi | pii | secret | injection | exfil
    start: int
    end: int


_I = re.IGNORECASE
DATA_RULES: list[tuple[str, str, re.Pattern]] = [
    # Kenyan identifiers and clinical context
    ("KE_NATIONAL_ID", "phi", re.compile(r"\b(?:national\s*id|id\s*(?:no|number|#)?)\s*[:#-]?\s*\d{7,8}\b", _I)),
    ("KE_PHONE",       "pii", re.compile(r"(?<!\d)(?:\+254|254|0)[17]\d{8}(?!\d)")),
    ("KRA_PIN",        "pii", re.compile(r"\b[AP]\d{9}[A-Z]\b")),
    ("SHA_NHIF_NO",    "phi", re.compile(r"\b(?:SHA|NHIF)\s*(?:no\.?|number|#)?\s*[:#-]?\s*\d{6,12}\b", _I)),
    ("MRN",            "phi", re.compile(r"\bMRN\s*[:#-]?\s*[A-Z0-9-]{4,}\b", _I)),
    ("DOB",            "phi", re.compile(r"\b(?:dob|date\s+of\s+birth)\s*[:-]?\s*\d{1,4}[/-]\d{1,2}[/-]\d{1,4}\b", _I)),
    ("PATIENT_NAME",   "phi", re.compile(r"\bpatient(?:\s+name)?\s*[:-]\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+")),
    ("EMAIL",          "pii", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    # Secrets
    ("DB_CONN_STRING", "secret", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/]+:[^\s@/]+@\S+", _I)),
    ("AWS_ACCESS_KEY", "secret", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("PRIVATE_KEY",    "secret", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT",            "secret", re.compile(r"\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}\b")),
    ("GITHUB_TOKEN",   "secret", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("API_KEY_ASSIGN", "secret", re.compile(r"\b(?:api[_-]?key|secret|token|passwd|password)\s*[=:]\s*['\"]?[A-Za-z0-9_\-/+=]{12,}", _I)),
    ("SK_KEY",         "secret", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
]

INJECTION_RULES: list[tuple[str, float, re.Pattern]] = [
    ("IGNORE_PREVIOUS",   0.8, re.compile(r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,30}\b(?:instructions?|rules?|prompts?|guidelines?)\b", _I)),
    ("REVEAL_SYSTEM",     0.7, re.compile(r"\b(?:reveal|print|show|repeat|output)\b[^.\n]{0,40}\b(?:system|hidden|initial)\s+(?:prompt|instructions?|message)\b", _I)),
    ("ROLE_HIJACK",       0.5, re.compile(r"\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are))\b[^.\n]{0,40}\b(?:dan|unrestricted|jailbroken|developer\s+mode|no\s+restrictions)\b", _I)),
    ("CHAT_TEMPLATE",     0.6, re.compile(r"(?:<\|im_start\|>|<\|system\|>|\[INST\]|###\s*system\s*:)", _I)),
    ("EXFIL_INSTRUCTION", 0.7, re.compile(r"\b(?:send|post|forward|upload|exfiltrate|append)\b[^.\n]{0,60}\b(?:to|at)\s+https?://", _I)),
    ("ENCODED_PAYLOAD",   0.4, re.compile(r"\b(?:decode|base64)\b[^.\n]{0,40}[A-Za-z0-9+/]{60,}={0,2}", _I)),
]

_IMG_OR_LINK = re.compile(r"!?\[[^\]]*\]\((https?://[^)\s]+)[^)]*\)")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def scan_data(text: str) -> list[Finding]:
    out = [Finding(k, g, m.start(), m.end()) for k, g, rx in DATA_RULES for m in rx.finditer(text)]
    for m in re.finditer(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            out.append(Finding("CARD_NUMBER", "pii", m.start(), m.end()))
    return out


def injection_score(text: str) -> tuple[float, list[str]]:
    hits = [(name, w) for name, w, rx in INJECTION_RULES if rx.search(text)]
    return min(1.0, sum(w for _, w in hits)), [n for n, _ in hits]


def redact(text: str, findings: list[Finding]) -> str:
    # Replace right to left so earlier offsets stay valid; overlapping spans are merged.
    spans = sorted({(f.start, f.end, f.kind) for f in findings}, reverse=True)
    last_start = None
    for start, end, kind in spans:
        if last_start is not None and end > last_start:
            end = last_start
            if end <= start:
                continue
        text = text[:start] + f"[REDACTED:{kind}]" + text[end:]
        last_start = start
    return text


def strip_untrusted_links(text: str, allow_domains: set[str]) -> tuple[str, int]:
    """Markdown images/links to non-allow-listed hosts are a classic exfiltration channel."""
    removed = 0

    def repl(m: re.Match) -> str:
        nonlocal removed
        host = re.sub(r"^https?://([^/:?#]+).*$", r"\1", m.group(1)).lower()
        if any(host == d or host.endswith("." + d) for d in allow_domains):
            return m.group(0)
        removed += 1
        return "[link removed by policy]"

    return _IMG_OR_LINK.sub(repl, text), removed
