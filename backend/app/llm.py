import json
import logging
import re

from openai import OpenAI

from . import config

logger = logging.getLogger("sentinelai.llm")

_client = None
_client_checked = False


def get_client():
    global _client, _client_checked
    if not _client_checked:
        _client_checked = True
        if config.OPENROUTER_API_KEY:
            _client = OpenAI(base_url=config.OPENROUTER_BASE_URL, api_key=config.OPENROUTER_API_KEY)
    return _client


def _extract_json(text: str) -> dict:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    else:
        brace = re.search(r"\{.*\}", text, re.DOTALL)
        if brace:
            text = brace.group(0)
    try:
        return json.loads(text)
    except Exception:
        logger.warning("LLM response was not valid JSON, wrapping as raw text")
        return {"raw": text}


def ask_json(system: str, user: str, *, max_tokens: int = 900, temperature: float = 0.4) -> dict:
    """Call an OpenRouter-hosted model and parse a JSON object out of the reply.

    Tries each model in config.OPENROUTER_FALLBACK_MODELS in order (free-tier
    models share upstream rate-limit pools and occasionally 429). Raises
    RuntimeError if no API key is configured or every model fails, so callers
    can fall back to deterministic content and keep the pipeline alive.
    """
    client = get_client()
    if client is None:
        raise RuntimeError("OPENROUTER_API_KEY is not configured")

    last_error: Exception | None = None
    for model in config.OPENROUTER_FALLBACK_MODELS:
        try:
            resp = client.chat.completions.create(
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
                extra_headers={
                    "HTTP-Referer": "https://github.com/nainanishourya/SentinalAI",
                    "X-Title": "SentinalAI SOC",
                },
                messages=[
                    {"role": "system", "content": system + "\nAlways respond with a single valid JSON object. No prose outside the JSON."},
                    {"role": "user", "content": user},
                ],
            )
            text = resp.choices[0].message.content or "{}"
            result = _extract_json(text)
            result["_model_used"] = model
            return result
        except Exception as exc:
            logger.warning("model %s failed: %s", model, exc)
            last_error = exc
            continue

    raise RuntimeError(f"all OpenRouter models failed: {last_error}")
