import { atLeast, type Confidence, type Finding, type SecretCategory } from './config';

interface SecretPattern {
  name: string;
  regex: RegExp;
  category: SecretCategory;
  confidence: Confidence;
  /** Extra check applied to each raw match, e.g. Luhn for card numbers. */
  validate?: (match: string) => boolean;
  /** How many matches must appear before the rule fires. Default 1. */
  minMatches?: number;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'AWS Access Key',
    regex: /\bAKIA[0-9A-Z]{16}\b/,
    category: 'credential',
    confidence: 'high',
  },
  {
    // Any two 40-character alphanumeric blobs look like an AWS secret, so this
    // one is a heuristic: technical documents legitimately carry hashes and
    // fingerprints. Reported, never blocking by default.
    name: 'AWS Secret Key',
    regex: /\b(?<![A-Za-z0-9/+])[A-Za-z0-9+/]{40}(?![A-Za-z0-9/+])\b/,
    category: 'credential',
    confidence: 'medium',
    minMatches: 2,
  },
  {
    name: 'GitHub Token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/,
    category: 'credential',
    confidence: 'high',
  },
  {
    name: 'OpenAI API Key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/,
    category: 'credential',
    confidence: 'high',
  },
  {
    // The word "token" or "secret" followed by a long value is suggestive, not
    // proof. Never blocking on its own.
    name: 'Generic API key in context',
    regex: /\b(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['"]?[A-Za-z0-9_\-+=]{20,}['"]?/i,
    category: 'credential',
    confidence: 'medium',
  },
  {
    name: 'Private key header',
    regex: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----/,
    category: 'credential',
    confidence: 'high',
  },
  {
    name: 'JWT token',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    category: 'credential',
    confidence: 'high',
  },
  {
    name: 'Credit card number',
    regex: /\b(?:\d[ -]*?){13,19}\b/,
    category: 'personal-data',
    confidence: 'high',
    validate: isLikelyCreditCard,
  },
  {
    // Note: 3-2-4 digits, so ordinary North American numbers (3-3-4) do not
    // collide. Verified in the test suite.
    name: 'US Social Security Number',
    regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/,
    category: 'personal-data',
    confidence: 'high',
  },
];

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function isLikelyCreditCard(match: string): boolean {
  const digits = match.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  const prefixes = ['4', '5', '34', '37', '6011', '65', '35', '62', '22'];
  if (!prefixes.some((p) => digits.startsWith(p))) return false;
  return luhnCheck(digits);
}

export interface SecretsCheckResult {
  flagged: boolean;
  reason?: string;
  findings: Finding[];
}

/** Every match of a pattern, regardless of its flags. */
function matchAll(text: string, regex: RegExp): string[] {
  const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
  return Array.from(text.matchAll(new RegExp(regex.source, flags)), (m) => m[0]);
}

export function checkSecrets(
  text: string,
  opts?: { minConfidence?: Confidence },
): SecretsCheckResult {
  const min = opts?.minConfidence ?? 'medium';
  const findings: Finding[] = [];

  for (const pattern of SECRET_PATTERNS) {
    if (!atLeast(pattern.confidence, min)) continue;

    const matches = matchAll(text, pattern.regex);
    if (matches.length < (pattern.minMatches ?? 1)) continue;

    const hits = pattern.validate ? matches.filter(pattern.validate) : matches;
    if (hits.length === 0) continue;

    findings.push({
      layer: 'secrets',
      guard: pattern.name,
      confidence: pattern.confidence,
      category: pattern.category,
      reason: `Possible ${pattern.name}${hits.length > 1 ? ` (${hits.length} matches)` : ''}`,
    });
  }

  if (findings.length === 0) return { flagged: false, findings: [] };

  return {
    flagged: true,
    reason: `Detected potential secrets: ${findings.map((f) => f.guard).join(', ')}`,
    findings,
  };
}
