"""Small standard-library REST adapter; no native package dependencies."""
import json
import re
import urllib.error
import urllib.request


class ProviderError(RuntimeError):
    pass


class Gemini:
    def __init__(self, key, model="gemini-3.6-flash", timeout=45):
        if not key:
            raise ProviderError("GEMINI_API_KEY is missing. Set it locally in your shell.")
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", model):
            raise ProviderError("Invalid model ID.")
        self.key, self.model, self.timeout = key, model, timeout

    def generate(self, contents, system, tools=None):
        body = {"contents": contents, "systemInstruction": {"parts": [{"text": system}]},
                "generationConfig": {"maxOutputTokens": 4096}}
        if tools:
            body["tools"] = [{"functionDeclarations": tools}]
        req = urllib.request.Request(
            "https://generativelanguage.googleapis.com/v1beta/models/" + self.model + ":generateContent",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "x-goog-api-key": self.key})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ProviderError("API response exceeded size limit.")
            data = json.loads(raw)
        except urllib.error.HTTPError as exc:
            messages = {400: "Invalid request or unsupported model feature.",
                        401: "Authentication failed.", 403: "API key or model access denied.",
                        404: "Model unavailable; check YOU_MODEL and account access.",
                        429: "Quota/rate limit reached; wait or check billing."}
            raise ProviderError(messages.get(exc.code, "Gemini service error (HTTP %s)." % exc.code)) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ProviderError("Network request failed or timed out; no tool was retried.") from None
        except (ValueError, TypeError):
            raise ProviderError("Invalid JSON response from Gemini.") from None
        candidates = data.get("candidates", [])
        if not candidates or not candidates[0].get("content", {}).get("parts"):
            raise ProviderError("Gemini returned no usable content (possibly blocked).")
        if candidates[0].get("finishReason") not in (None, "STOP"):
            raise ProviderError("Gemini response was incomplete; refusing partial tool calls.")
        # Return original content so thought signatures and function IDs survive round trips.
        return candidates[0]["content"], data.get("usageMetadata", {})
