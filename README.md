# Heimdall

Lightweight, zero-dependency LLM guardrails for Node.js. Three layers of defense:

- **Content moderation** — OpenAI Moderation API (free, no token cost)
- **Secret detection** — AWS keys, GitHub tokens, credit cards, SSNs, JWT tokens, and more
- **Prompt injection detection** — Jailbreak attempts, system prompt extraction, role overrides

All checks fail open. No API key is required — without one, the moderation layer silently skips.

## Install

```bash
npm install @fundr/heimdall
```

## Usage

```ts
import { configure, checkInput, checkOutput } from '@fundr/heimdall';

configure({
  moderationApiKey: process.env.OPENAI_API_KEY, // optional
  logger: console, // optional — pass any object with a .warn() method
});

// Before sending a user message to your LLM
const inputResult = await heimdall.checkInput(userMessage);
if (inputResult.blocked) {
  return res.status(422).json({ error: inputResult.reason });
}

// After receiving a response from your LLM
const outputResult = await heimdall.checkOutput(aiResponse);
if (outputResult.blocked) {
  aiResponse = outputResult.reason; // replace with safe fallback
}
```

## API

### `configure(config)`

Set up Heimdall before use.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `moderationApiKey` | `string` | `undefined` | OpenAI API key for moderation. Checks skip without it. |
| `logger` | `{ warn: Function }` | `undefined` | Optional logger. Receives `(message, data)` on blocked content. |

### `checkInput(text)`

Run all three guard layers against user input. Returns `{ blocked: boolean, reason?: string }`.

Checks: moderation → secrets → injection. First match blocks.

### `checkOutput(text)`

Run moderation and secret checks against LLM output. Returns `{ blocked: boolean, reason?: string }`.

Prompt injection is skipped on output — it only makes sense for user input.

## Layers

### Content Moderation

Uses the [OpenAI Moderation API](https://platform.openai.com/docs/guides/moderation) to detect hate speech, threats, violence, self-harm, and sexual content across 11 categories. Free — no token cost. Requires `moderationApiKey` to be configured.

### Secret Detection

Regex-based detection of credentials and sensitive data in LLM inputs and outputs:

- AWS access keys and secret keys
- GitHub personal access tokens
- OpenAI API keys
- Credit card numbers (Luhn-validated)
- US Social Security Numbers
- Private key headers (RSA, DSA, EC, OpenSSH, PGP)
- JWT tokens
- Generic API key patterns in context (e.g., `api_key: abc123…`)

### Prompt Injection

Regex-based detection of jailbreak and manipulation attempts:

- "Ignore your instructions", "forget everything", "override"
- "You are DAN", "act as unrestricted", "roleplay as evil"
- System prompt extraction ("reveal your system prompt")
- Role overrides, delimiter attacks, developer/god mode
- Token/safety bypass attempts

## Design

- **Zero runtime dependencies.** Only TypeScript as a dev dependency.
- **Fails open.** If the moderation API is unreachable, checks skip rather than blocking legitimate traffic.
- **No PII redaction of business data.** Names, emails, and phone numbers are not flagged — Heimdall is designed for applications where users legitimately work with contact data.
- **Optional logging.** Pass a logger to `configure()` if you want visibility into blocked content.

## License

MIT
