---
name: privacy-filter-gateway
description: Knowledge for agents operating behind a privacy-filter reversible redaction gateway. The gateway automatically replaces PII and secrets in user messages with typed placeholders (e.g. [邮箱_0], [电话_0], [密钥_0]) before they reach the agent, and restores them in the agent's responses. Use this skill whenever you notice placeholder tokens like [邮箱_N], [电话_N], [身份证_N], [银行卡_N], [IP_N], or [密钥_N] in the conversation, or when the system prompt indicates a privacy gateway is active.
---

# Privacy-Filter Gateway — Agent Operating Guide

You are running behind a **reversible redaction gateway** ([privacy-filter](https://github.com/Tritium0041/privacy-filter)). The gateway has already sanitised the user's message before it reached you. This skill tells you what the placeholders mean, how to handle them correctly, and what the gateway does automatically so you don't duplicate its work.

---

## Placeholder Reference

Every placeholder follows the pattern `[TYPE_N]` where `TYPE` is the entity category and `N` is a zero-based index that is unique **per type per request**.

| Placeholder | Entity type | Example original value |
|---|---|---|
| `[邮箱_N]` | Email address | `alice@example.com` |
| `[电话_N]` | Phone number | `13900001111` |
| `[身份证_N]` | Chinese national ID | `110101199001011234` |
| `[银行卡_N]` | Bank card number (Luhn-checked) | `6222021234567890` |
| `[IP_N]` | IPv4 address | `192.168.1.1` |
| `[密钥_N]` | Secret / credential / API key / password | `sk-abc123...` |

Key properties:

- **Same value → same placeholder**: if the user mentions the same email twice, both occurrences become `[邮箱_0]`.
- **Different values of the same type → different indexes**: two distinct emails become `[邮箱_0]` and `[邮箱_1]`.
- **Placeholders are opaque to you**: you never see the original value; treat each placeholder as a stable, unique identifier for that piece of data within this request.

---

## What the Gateway Does Automatically

You do **not** need to call any restore API yourself. The gateway handles the full round-trip transparently:

1. **Inbound (user → you)**: Detects PII/secrets in the request body and replaces them with `[TYPE_N]` placeholders. Certain structural fields (IDs, session tokens, tool-call IDs) are intentionally left untouched.
2. **Outbound (you → user)**: Scans your response for any `[TYPE_N]` placeholder and substitutes the original value back before the user sees it.
3. **Streaming**: For SSE / streaming responses, the gateway restores placeholders in each `*.delta` event as the stream flows, including across chunk boundaries.

The user **always receives the real values**; you are the only party that sees placeholders.

---

## How to Handle Placeholders

### Pass them through unchanged

Refer to placeholders directly in your reasoning and in tool-call arguments. Do not attempt to guess, reconstruct, or substitute the original value.

```json
{ "to": "[邮箱_0]", "subject": "Your order confirmation" }
```

The gateway restores `[邮箱_0]` → `alice@example.com` in your response before it reaches the user or any downstream consumer.

> **Note on protected fields**: Structural fields that carry request/session identity — such as `call_id`, `tool_call_id`, `session_id`, `thread_id`, `response_id` — are never redacted by the gateway. Only user-supplied content fields (message text, `input`, `content`, `prompt`, function arguments, etc.) are subject to redaction.

### Use placeholders as stable identifiers for comparison

Two placeholders of the same type with different indexes refer to different original values:

- `[邮箱_0]` ≠ `[邮箱_1]` → two distinct email addresses
- `[邮箱_0]` = `[邮箱_0]` → the same email address, even if it appears multiple times

### Acknowledge by echoing the placeholder

If you need to confirm or reference a specific value, echo the placeholder token directly. The gateway will restore it to the original value before the user sees it:

> "I'll send the receipt to [邮箱_0]."

The user will read: "I'll send the receipt to alice@example.com."

### Never attempt to infer or reconstruct original values

Do not attempt to guess or reconstruct the original value from context. Do not ask the user to repeat information that has already been redacted. The gateway's session store is ephemeral (default TTL: 5 minutes) and the mapping is never exposed to you.

---

## Edge Cases

| Situation | Correct behaviour |
|---|---|
| A placeholder appears in a tool result / function output | Treat it as a stable identifier; pass it through; the gateway restores it in your final response. |
| The user asks "what is my email?" | Echo the placeholder: "Your email is [邮箱_0]." The gateway restores it to the real value before the user sees the response. |
| A placeholder appears in a code snippet the user wants you to edit | Preserve it verbatim; do not replace it with a dummy value. |
| Session expires mid-conversation | The gateway returns the placeholder unreplaced to the user. If the user reports seeing `[邮箱_0]` in the output, the session has likely expired; ask them to retry the request. |
| No placeholders in the message | The gateway found no PII/secrets; proceed normally. |
| You receive `[密钥_0]` in a tool result | A secret was detected in the tool's output. Treat it as a redacted credential; do not log or echo it. |
