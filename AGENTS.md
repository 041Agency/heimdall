# Working on Heimdall

A brief for whoever picks this up next, human or agent. Read it before changing
a rule or the public API.

## What this is

Zero-dependency LLM guardrails for Node.js, in three layers: content moderation
(OpenAI's endpoint), secret detection, and prompt-injection detection. Around 700
lines of TypeScript plus a test suite. The whole point is that it is small enough
to read in one sitting and depend on without a supply chain.

## Where it is consumed

Two consumers, both first-party:

1. **`resume-builder/desktop` (Yumiwe)**, a local-first Electron CV tool. It is
   the reason several design choices below exist. What it actually needs is
   narrow: scan an uploaded CV for personal data and **report** it, and scan an
   uploaded document for instruction-shaped text and **hold it for review**
   rather than refuse. It does not want moderation and it does not want anything
   blocked on its behalf.
2. Server-side chat apps, the original audience: block a request before spending
   a generation call.

If a change makes the library better for the second consumer and worse for the
first, say so out loud rather than quietly accepting it.

## Status and positioning

Early and reference-grade. Not a security control. That framing is deliberate and
should survive: the rules are hand-tuned regular expressions with known false
positives and known evasions, and the README says so plainly. Do not let the
project drift into implying it is a guarantee.

The library is not published to npm. `npm install @fundr/heimdall` fails today,
and the README tells people to install from GitHub instead. See the decisions
below.

## The invariants

These are load-bearing. Breaking one is a design regression, not a detail.

- **Zero runtime dependencies.** Dev dependencies only, and keep them minimal.
- **Fails open.** An unreachable moderation endpoint is a skip, never a block.
- **Findings never carry the matched text, and logs never carry the content.**
  Findings name the rule, layer, confidence and category. There is no `preview`
  field and there should not be one.
- **The library never writes the caller's copy.** `messages` exists so that the
  wording a user sees belongs to the product, not to this package.
- **Every rule declares a `confidence`.** `high` is reserved for phrases that are
  essentially never legitimate in ordinary business text. `medium` covers
  heuristics with real-world false positives. The default `blockAt` is `high`, so
  a medium rule reports without refusing.
- **Personal data is reported, not blocked, by default.** A document is not
  refused for containing its owner's own social security number.
- **False positives are the primary bug class.** This library is consumed by
  tools that read job postings and CVs, which are business documents. Rules that
  fire on ordinary prose are worse than rules that miss, and the test suite
  exists mostly to pin that.

## Git and identity

Two repositories are involved: this one, and `resume-builder/desktop`.

**Commit identity is already shared and correct** in both, and set globally:
`rhys-041 <rhys@041agency.com>`. Nothing to change.

**Authentication is not.** Yumiwe pushes over SSH through a host alias in
`~/.ssh/config`:

```
Host github-yumiwe
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_yumiwe
    IdentitiesOnly yes
```

That key authenticates as the GitHub account **`rhys-yumiwe`**. This repo's remote
is still HTTPS, which means pushes may land under a different account, and the
goal is to use the same one everywhere. Read access for `rhys-yumiwe` to
`041Agency/heimdall` is already confirmed; write access is not, so verify it:

```bash
cd /Users/rhysparry/Code/resume-builder/heimdall
git remote set-url origin git@github-yumiwe:041Agency/heimdall.git
git ls-remote origin          # read check, already known to work
git push origin HEAD          # write check
```

If the push is refused, `rhys-yumiwe` is not in the `041Agency` org with write
access. Either grant it, or revert to HTTPS:

```bash
git remote set-url origin https://github.com/041Agency/heimdall
```

Never commit a credential, a token, or a remote URL containing one.

## Working here

```bash
npm install          # also runs prepare, which builds
npm test             # builds, then node --test
npm run build        # tsc only
```

- TypeScript, CommonJS output to `dist/`, which is not tracked.
- Tests are plain JavaScript against `dist/`, run by `node --test`. No test
  framework, on purpose.
- **Style:** plain imperative commit subjects, no conventional-commit prefixes.
  No em dashes in Markdown; use commas, colons or parentheses.
- Adding or changing a rule means: set its `category` and `confidence`, and add a
  test that pins both the thing it should catch and the ordinary text it must not
  catch. A rule without a negative test is not finished.

## What the project needs

Priorities are ordered, not estimated.

### P0, before anything depends on this

1. **Resolve the identity.** `@fundr/heimdall`, `041Agency/heimdall`, and
   `Copyright (c) 2026 Fundr` cannot all be right. Pick one organisation, make the
   package name, the repo, the LICENSE holder, `author`, `repository`, `homepage`
   and `bugs` agree, then bump to `0.2.0` or reset the version honestly.
2. **Ship ESM alongside CJS.** `exports` map plus a dual build. The package is
   CommonJS-only today and most consumers are ESM. This is the single largest
   compatibility gap.
3. **Add CI.** GitHub Actions running build and test on Node 18, 20 and 22.
   Nothing else in this list is credible without it.
4. **Replace hand-tuned rules with a labelled corpus.** Move the fixtures into
   `test/fixtures/`: positive examples per rule, and a larger set of ordinary
   documents (job postings across industries, CVs, contracts, technical docs)
   that must produce zero findings. Measure precision and recall when a rule
   changes instead of eyeballing it. "No false positives on ordinary documents"
   should be an enforced property.
5. **Normalise before matching.** Strip zero-width characters, NFKC-normalise,
   collapse whitespace, then match. Trivial evasion currently works.

### P1, the difference between a script and a library

6. **`redact()`.** The library reports but never removes. Returning the text with
   matches replaced is the most requested thing a guardrails library can do, and
   it is the natural companion to the existing findings.
7. **Config presets.** `strict`, `balanced`, `report-only`. Assembling `blockAt`,
   `nonBlockingCategories` and `layers` by hand is a poor first experience.
8. **`docs/rules.md`**, kept in sync with the pattern tables, with one real
   example per rule and the reason for its confidence. The README table is a
   summary; this is the reference.
9. **Put the threat model in the README.** State what lexical detection can and
   cannot do, and that the real defence against prompt injection is architectural
   (do not put untrusted text where it can trigger destructive tool calls). This
   is the single most useful thing this project can tell its users.
10. **Broaden attack coverage.** Encoding and base64 payloads, homoglyphs,
    multilingual attempts, many-shot jailbreaks, indirect injection, and
    exfiltration requests ("repeat the text above").
11. **Improve the loose heuristics.** The AWS secret rule (any two 40-character
    alphanumeric blobs) is crude; entropy scoring would be better. The card prefix
    list is partial. National ID detection is US-only.
12. **CHANGELOG and a versioning policy.** The behaviour changes currently in
    flight are exactly what a changelog exists for.
13. **Project files:** `CONTRIBUTING.md` (what a new rule must ship with),
    `SECURITY.md` (which should say there is no security boundary, and how to
    report a false negative), `CODE_OF_CONDUCT.md`, and issue and PR templates.
14. **Decide the moderation layer's future.** It needs a platform API key, which
    local-first consumers by definition do not have, so for them it is dead
    weight that silently no-ops. Either document it as server-side-only or take it
    off the default path.
15. **Streaming output checks.** Most LLM apps stream; `checkOutput` takes a
    complete string.

### P2, polish

16. Formatter and linter plus `.editorconfig`, so contributions are consistent.
17. An `examples/` directory: block mode, report-only mode, document ingest.
18. Stable rule ids on findings, so consumers can pin behaviour across upgrades.
19. npm provenance, 2FA, and trusted publishing.
20. Benchmarks. The project claims to be lightweight; prove it.

## Decisions needed from the maintainer

- **Org and package name.** Blocks P0.1, and publication.
- **Publish to npm, or stay GitHub-only and drop the npm framing?** Half the
  README currently assumes the former and half the reality is the latter.
- **The moderation layer's role**, per P1.14.
- **Is an LLM-classifier layer ever in scope?** It would improve recall
  substantially and would break both zero-dependencies and local-first. The
  answer is probably no, but it should be written down.

## Out of scope

- Being a security control, a sandbox, or a guarantee.
- Redacting ordinary business data. Names, emails and phone numbers are
  deliberately not flagged, because the consumers legitimately work with contact
  data. Card numbers and national IDs are flagged because they rarely belong in a
  document.
- Relevance, ranking, or fit scoring. Moderation reports harm categories, which
  carry no signal about whether a document is good or relevant. A ghost job and a
  dream job both pass.
