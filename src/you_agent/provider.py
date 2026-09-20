"""OpenAI-compatible REST adapter (VyceAI / DeepSeek). No native package dependencies."""
import json
import re
import urllib.error
import urllib.request


class ProviderError(RuntimeError):
    pass


class Provider:
    def __init__(self, key, model="deepseek-v4-flash", base="https://vyceai.com/v1", timeout=90):
        if not key:
            raise ProviderError("YOU_API_KEY is missing. Set it locally in your shell.")
        if not re.fullmatch(r"[a-zA-Z0-9._:/-]+", model):
            raise ProviderError("Invalid model ID.")
        base = (base or "").rstrip("/")
        if not (base.startswith("https://") and " " not in base):
            raise ProviderError("YOU_API_BASE must be an https URL.")
        self.key, self.model, self.base, self.timeout = key, model, base, timeout

    def generate(self, messages, system, tools=None):
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}] + list(messages),
            "max_tokens": 4096,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        req = urllib.request.Request(
            self.base + "/chat/completions",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer " + self.key,
                # Cloudflare on vyceai.com blocks Python-urllib's default User-Agent (error 1010).
                "User-Agent": "You-Termux-Agent/0.2 (+https://github.com/markoza99/You)",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ProviderError("API response exceeded size limit.")
            data = json.loads(raw)
        except urllib.error.HTTPError as exc:
            try:
                err_body = exc.read(500).decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            if exc.code == 403 and ("1010" in err_body or "cloudflare" in err_body.lower()):
                raise ProviderError(
                    "HTTP 403 from Cloudflare (error 1010): the request was blocked before the API. "
                    "This is not an invalid-key error."
                ) from None
            messages_map = {
                400: "Invalid request or unsupported model feature.",
                401: "Authentication failed.",
                403: "Access denied (HTTP 403). Check the API key, model access, and whether Cloudflare blocked the request.",
                404: "Model or endpoint unavailable; check YOU_MODEL and YOU_API_BASE.",
                429: "Rate limit (HTTP 429). Wait and retry. This is not necessarily a billing failure.",
            }
            raise ProviderError(messages_map.get(exc.code, "API service error (HTTP %s)." % exc.code)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ProviderError("Network request failed or timed out; no tool was retried.") from None
        except (ValueError, TypeError):
            raise ProviderError("Invalid JSON response from the API.") from None
        choices = data.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            raise ProviderError("API returned no usable choices.")
        message = choices[0].get("message")
        if not isinstance(message, dict) or message.get("role") not in (None, "assistant"):
            raise ProviderError("API returned no usable assistant message.")
        finish = choices[0].get("finish_reason")
        tool_calls = message.get("tool_calls") or []
        if finish not in (None, "stop", "tool_calls"):
            raise ProviderError("API response was incomplete; refusing partial tool calls.")
        if not tool_calls and not (message.get("content") or "").strip():
            raise ProviderError("API returned neither visible text nor tool calls.")
        usage = data.get("usage") or {}
        total = usage.get("total_tokens", 0)
        return message, {"totalTokenCount": int(total or 0), "usage": usage}


# Backward-compatible name used by older tests/docs.
Gemini = Provider
