# Heimdall

Lightweight, zero-dependency LLM guardrails for Node.js. Three layers:

- **Content moderation** :  OpenAI Moderation API (free, no token cost)
- **Secret detection** :  credentials, card numbers, SSNs, JWTs, and more
- **Prompt injection detection** :  instruction overrides, jailbreaks, delimiter attacks

Nothing here is a guarantee. Every rule is a heuristic, and the false-positive
and false-negative rates are a choice you make with `blockAt`. See
[Rules and confidence](#rules-and-confidence).

## Status

> **Early and reference-grade. Not a security control.**
>
> Heimdall is an early-stage, single-maintainer project. The rules are regular
> expressions tuned against a small sample of real documents; they have not been
> battle-tested against adversarial input, and the moderation layer is only as
> good as the endpoint behind it.
>
> Treat this as a **reference implementation and a starting point**. Read the
> rules, tune them for your domain, and pin your own tests before you rely on it.
> It stops naive and careless input. It will not stop a determined attacker, and
> it should never be the only thing standing between a model and something that
> matters.

## Install

Not published to npm yet. Install from GitHub:

```bash
npm install github:041Agency/heimdall
```

The `prepare` script builds the package on install, so TypeScript is fetched and
the `dist/` output is produced for you.

## Usage

```ts
import { configure, checkInput, checkOutput } from '@fundr/heimdall';

configure({
  moderationApiKey: process.env.OPENAI_API_KEY, // optional; moderation is skipped without it
  messages: { input: 'Sorry, I cannot process that message.' }, // your words, not ours
  onFinding: (finding) => auditLog.write(finding), // report everything, blocked or not
});

const input = await checkInput(userMessage);
if (input.blocked) {
  return res.status(422).json({ error: input.reason, findings: input.findings });
}

const output = await checkOutput(aiResponse);
if (output.blocked) {
  aiResponse = output.reason;
}
```

### Report instead of refuse

A guardrails library has no business deciding what your product says. Every
finding is returned, blocked or not, so you can surface it in your own voice
rather than refusing:

```ts
configure({ layers: { moderation: false }, nonBlockingCategories: ['personal-data'] });

const { findings } = await checkInput(uploadedDocument);
for (const finding of findings.filter((f) => f.category === 'personal-data')) {
  warn(`This document looks like it contains a ${finding.guard}. Remove it before we store it?`);
}
```

## API

### `configure(config)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `moderationApiKey` | `string` | `undefined` | OpenAI API key for moderation. The layer is skipped without it. |
| `logger` | `{ warn: Function }` | `undefined` | Receives `(message, data)` whenever a guard fires. Never receives the scanned text. |
| `layers` | `{ moderation?, secrets?, injection? }` | all on | Switch individual layers off. |
| `blockAt` | `'high' \| 'medium'` | `'high'` | Lowest confidence that blocks. `'medium'` trades false positives for recall. |
| `nonBlockingCategories` | `SecretCategory[]` | `['personal-data']` | Reported, never blocking. A document is not refused for containing its owner's SSN. |
| `messages` | `{ input?, output? }` | generic fallbacks | Copy returned in `reason` when something blocks. |
| `onFinding` | `(finding) => void` | `undefined` | Called for every finding. This is the report-only hook. |

### `checkInput(text)` / `checkOutput(text)`

Async. `checkInput` runs every enabled layer; `checkOutput` runs moderation and
secrets only, because injection detection is meaningless on model output. Both
return:

```ts
interface HeimdallResult {
  blocked: boolean;
  reason?: string;      // the caller's message, only when blocked
  findings: Finding[];  // everything found, always
}
```

### `checkInputFast(text)`

Synchronous. Secrets and injection only, no network. Use it on the hot path and
run `checkInputModeration` in parallel if you want both.

### `checkInputModeration(text)`

The moderation layer on its own. Resolves immediately when the layer is off.

### `inspect(text)`

Report-only convenience: runs every enabled input layer and returns
`Finding[]` without deciding anything.

### Layer functions

`checkSecrets(text, opts?)`, `checkInjection(text, opts?)`, and
`checkModeration(text, apiKey?)` are exported for direct use. `opts.minConfidence`
defaults to `'medium'`, so they report everything they find.

## Concepts

### Findings

One thing a guard found. Findings never contain the matched text:

```ts
interface Finding {
  layer: 'moderation' | 'secrets' | 'injection';
  guard: string;                          // "GitHub Token", "Ignore instructions"
  confidence: 'high' | 'medium';
  category?: 'credential' | 'personal-data';
  reason: string;                         // short and safe to expose
}
```

### Confidence

`high` is reserved for patterns that are essentially never legitimate in
ordinary business text. `medium` is for heuristics with real-world false
positives: they are reported, but they do not block unless you set
`blockAt: 'medium'`.

The split exists because a naive rule set blocks real documents. A penetration
testing advert that says *"ability to bypass restrictions and safety filters"*,
or a developer advert that mentions custom elements such as `<user>`, look like
attacks to a loose pattern and are perfectly ordinary text. Those are reported at
medium confidence rather than refused.

### Categories

Secret findings are split because callers act on them differently. A leaked API
key is an incident; a document containing its owner's own social security number
is something to tell them about. Credentials block by default, personal data is
reported by default, and `nonBlockingCategories` decides which is which.

## Rules and confidence

### Prompt injection

| Rule | Confidence |
|------|------------|
| Ignore instructions (`ignore all previous instructions`) | high |
| Forget / reset instructions | high |
| Jailbreak persona (`act as DAN`) | high |
| System prompt extraction | high |
| Role override (`from now on you are`) | high |
| Prompt delimiter attack (chat-template tokens: `<\|im_start\|>`, `[INST]`, `<<SYS>>`) | high |
| Prompt delimiter attack (paired tags: `<system>...</system>`) | medium |
| Stray system tag (`</system>`) | medium |
| Developer / debug / admin / god mode | medium |
| Token/safety bypass | medium |

Two rules deliberately require more than a keyword:

- The instruction-override rules ignore a phrase followed by a preposition.
  *"ignore all instructions **from** the vendor"* describes a document;
  *"ignore all previous instructions"* instructs a model.
- The bypass rule requires the safeguard to follow the verb directly, so
  *"bypass restrictions and safety filters"* is not a match while
  *"bypass safety filters"* is.

### Secrets

| Rule | Category | Confidence |
|------|----------|------------|
| AWS access key | credential | high |
| GitHub token | credential | high |
| OpenAI API key | credential | high |
| Private key header | credential | high |
| JWT token | credential | high |
| Credit card number | personal-data | high (Luhn-checked) |
| US Social Security Number | personal-data | high |
| AWS secret key (any two 40-character blobs) | credential | medium |
| Generic API key in context (`api_key: ...`) | credential | medium |

The two medium rules are loose on purpose. Any two 40-character alphanumeric
blobs look like a secret, and technical documents legitimately carry hashes and
fingerprints, so they are reported rather than blocked.

## What Heimdall is not

- **Not a relevance or ranking signal.** Moderation reports harm categories:
  hate, harassment, self-harm, sexual content, violence. Those carry no
  information about whether a document is good, relevant, or a scam. A ghost job
  and a dream job both return `flagged: false`.
- **Not a redactor.** Heimdall tells you what it found. It does not remove or
  rewrite anything.
- **Not a PII scrubbing service for business data.** Names, emails, and phone
  numbers are not flagged. It is designed for applications where users
  legitimately work with contact data. Card numbers and SSNs are flagged because
  they are rarely legitimate in a document.
- **Not a sandbox.** Prompt injection detection is lexical. The real defence is
  architectural: do not put untrusted text in a position where it can trigger
  destructive tool calls, and validate every tool call you accept.

## Design

- **Zero runtime dependencies.** Only TypeScript as a dev dependency.
- **Fails open.** If the moderation API is unreachable, the check is skipped
  rather than blocking legitimate traffic.
- **No content in logs.** The logger receives the rule, layer, confidence, and
  category. Never the text, and never a preview of it.
- **Caller-owned copy.** The default refusal messages are fallbacks. Set
  `messages` and the wording is yours.

## Development

```bash
npm install
npm test        # builds, then runs the suite with node --test
```

The suite pins the false-positive cases specifically: ordinary CV text, ordinary
job-posting prose, and the loose heuristics that must not block.

## License

MIT
