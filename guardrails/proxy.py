"""OpenAI-compatible guardrail proxy. Teams call this; only this service holds the provider key and egress route.

Inbound:  auth -> model allow-list -> size cap -> secrets/PHI/PII block -> injection score block
Outbound: PII/PHI redaction -> secret strip -> untrusted link/image strip -> tool_call allow-list
Logs:     JSON audit lines with categories and counts only, never prompt or response text.
"""
import hashlib, hmac, json, logging, os, sys, time, uuid
import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from detectors import injection_score, redact, scan_data, strip_untrusted_links

app = FastAPI(title="AI guardrail proxy", docs_url=None, redoc_url=None)
log = logging.getLogger("llm_guard")
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")

API_KEYS = {k.strip() for k in os.getenv("PROXY_API_KEYS", "").split(",") if k.strip()}
ALLOWED_MODELS = {m.strip() for m in os.getenv("ALLOWED_MODELS", "gpt-enterprise").split(",")}
LINK_ALLOW = {d.strip() for d in os.getenv("OUTPUT_LINK_ALLOWLIST", "").split(",") if d.strip()}
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "")
UPSTREAM_KEY = os.getenv("UPSTREAM_API_KEY", "")
MAX_INPUT_CHARS = int(os.getenv("MAX_INPUT_CHARS", "32000"))
INJECTION_BLOCK_AT = float(os.getenv("INJECTION_BLOCK_AT", "0.7"))
ALLOWED_TOOLS = {t for t in os.getenv("ALLOWED_TOOLS", "").split(",") if t}


def audit(**fields):
    log.info(json.dumps({"ts": time.time(), "svc": "llm_guard", **fields}))


def _text_parts(messages: list[dict]) -> list[str]:
    parts = []
    for m in messages:
        c = m.get("content")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):                      # multimodal style content parts
            parts += [p.get("text", "") for p in c if isinstance(p, dict) and p.get("type") == "text"]
    return parts


async def call_upstream(payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(UPSTREAM_URL, json=payload, headers={"Authorization": f"Bearer {UPSTREAM_KEY}"})
        r.raise_for_status()
        return r.json()


def _blocked(rid: str, who: str, reason: str, categories: list[str], status: int = 400):
    audit(event="blocked", request_id=rid, caller=who, reason=reason, categories=sorted(set(categories)))
    return JSONResponse(status_code=status, content={"error": {"code": "guardrail_blocked", "reason": reason,
                        "categories": sorted(set(categories)), "request_id": rid}})


def require_api_key(authorization: str | None = Header(default=None)) -> str:
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not any(hmac.compare_digest(token, k) for k in API_KEYS):
        raise HTTPException(401, "invalid api key")
    return hashlib.sha256(token.encode()).hexdigest()[:8]           # pseudonymous caller id for logs


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/v1/chat/completions")
async def chat(payload: dict, caller: str = Depends(require_api_key)):
    rid = str(uuid.uuid4())

    if payload.get("model") not in ALLOWED_MODELS:
        return _blocked(rid, caller, "model_not_allowed", [])
    if payload.get("stream"):
        return _blocked(rid, caller, "streaming_disabled", [])        # chunk-window scanning is a documented next step
    messages = payload.get("messages") or []
    texts = _text_parts(messages)
    if sum(len(t) for t in texts) > MAX_INPUT_CHARS:
        return _blocked(rid, caller, "input_too_large", [])

    joined = "\n".join(texts)
    data_hits = scan_data(joined)
    if data_hits:
        return _blocked(rid, caller, "sensitive_data_in_prompt", [f.group.upper() + ":" + f.kind for f in data_hits])
    score, names = injection_score(joined)
    if score >= INJECTION_BLOCK_AT:
        return _blocked(rid, caller, "prompt_injection_suspected", names)

    safe_payload = {k: payload[k] for k in ("model", "messages", "temperature", "max_tokens") if k in payload}
    try:
        upstream = await call_upstream(safe_payload)
    except Exception as exc:
        audit(event="upstream_error", request_id=rid, caller=caller, error=type(exc).__name__)
        return JSONResponse(status_code=502, content={"error": {"code": "upstream_unavailable", "request_id": rid}})

    redactions, links_removed, tools_dropped, inj_in_output = 0, 0, 0, []
    for choice in upstream.get("choices", []):
        msg = choice.get("message", {})
        text = msg.get("content") or ""
        hits = scan_data(text)
        redactions += len(hits)
        text = redact(text, hits)
        text, n = strip_untrusted_links(text, LINK_ALLOW)
        links_removed += n
        _, names = injection_score(text)                               # indirect injection echoed in output
        inj_in_output += names
        msg["content"] = text
        calls = msg.get("tool_calls") or []
        kept = [c for c in calls if c.get("function", {}).get("name") in ALLOWED_TOOLS]
        tools_dropped += len(calls) - len(kept)
        if calls:
            msg["tool_calls"] = kept
    audit(event="allowed", request_id=rid, caller=caller, model=payload.get("model"), output_redactions=redactions,
          links_removed=links_removed, tools_dropped=tools_dropped, output_injection_markers=sorted(set(inj_in_output)))
    upstream["guardrail"] = {"request_id": rid, "redactions": redactions, "links_removed": links_removed}
    return upstream
