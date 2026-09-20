# Implementation status — v0.2.0

## Delivered

- Default provider is VyceAI (`https://vyceai.com/v1`) with model `deepseek-v4-flash`.
- OpenAI-compatible chat/completions adapter, Bearer auth, tool_calls loop.
- `YOU_API_KEY` (also accepts `VYCEAI_API_KEY`; `GEMINI_API_KEY` is a leftover fallback).
- Same workspace tools, approvals, redaction, and offline tests as v0.1.
- HTTP 429 message no longer tells the user to check billing first.

## Not yet verified

- Live DeepSeek tool-calling on a real Termux device with a VyceAI free key.
- VyceAI free-tier rate limits and credit remaining.
- Whether `deepseek-v4-flash` reliably uses tools instead of inventing results.

## Security boundaries

Workspace restrictions apply to built-in file tools only. Approved Python is arbitrary Termux-user code. Built-in reads upload workspace content to VyceAI. Avoid secrets in the workspace.
