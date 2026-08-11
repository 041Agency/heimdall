const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  {
    name: 'AWS Access Key',
    regex: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    name: 'AWS Secret Key',
    regex: /\b(?<![A-Za-z0-9/+])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])\b/,
  },
  {
    name: 'GitHub Token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/,
  },
  {
    name: 'OpenAI API Key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/,
  },
  {
    name: 'Generic API Key in context',
    regex: /\b(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['"]?[A-Za-z0-9_\-+=]{20,}['"]?/i,
  },
  {
    name: 'Credit Card Number',
    regex: /\b(?:\d[ -]*?){13,19}\b/,
  },
  {
    name: 'US Social Security Number',
    regex: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/,
  },
  {
    name: 'Private Key Header',
    regex: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----/,
  },
  {
    name: 'JWT Token',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
];

const CC_LUHN_THRESHOLD = 0.5;

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
  const hasPrefix = prefixes.some((p) => digits.startsWith(p));
  if (!hasPrefix) return false;
  return luhnCheck(digits);
}

export interface SecretsCheckResult {
  flagged: boolean;
  reason?: string;
}

export function checkSecrets(text: string): SecretsCheckResult {
  const found: string[] = [];

  for (const pattern of SECRET_PATTERNS) {
    const match = pattern.regex.exec(text);
    if (!match) continue;

    if (pattern.name === 'Credit Card Number') {
      const matches = text.match(new RegExp(pattern.regex.source, 'g')) ?? [];
      const ccCount = matches.filter((m) => isLikelyCreditCard(m)).length;
      if (ccCount > 0) {
        found.push(`${pattern.name} (${ccCount})`);
      }
    } else if (pattern.name === 'AWS Secret Key') {
      const matchCount = (text.match(new RegExp(pattern.regex.source, 'g')) ?? []).length;
      if (matchCount >= 2) {
        found.push(`${pattern.name}`);
      }
    } else {
      found.push(pattern.name);
    }
  }

  if (found.length === 0) {
    return { flagged: false };
  }

  return {
    flagged: true,
    reason: `Detected potential secrets: ${found.join(', ')}`,
  };
}
