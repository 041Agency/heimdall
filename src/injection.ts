import { atLeast, type Confidence, type Finding } from './config';

interface InjectionPattern {
  name: string;
  regex: RegExp;
  confidence: Confidence;
}

/**
 * A phrase followed by a preposition is ordinarily describing a document, not
 * instructing a model: "ignore the instructions *from* the vendor" is fine,
 * "ignore all previous instructions" is not. Every instruction-override rule
 * uses this to avoid flagging ordinary business prose.
 */
const NOT_A_REFERENCE = String.raw`(?!\s+(?:from|by|of|in|issued|provided|given|sent|that|which))`;

const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    name: 'Ignore instructions',
    confidence: 'high',
    regex: new RegExp(
      String.raw`\bignore\s+(?:all\s+|any\s+)?(?:your\s+|the\s+)?(?:previous\s+|prior\s+|above\s+|earlier\s+|preceding\s+)?(?:instructions?|prompts?|rules?|guidelines?|system\s+(?:prompt|message))\b` +
        NOT_A_REFERENCE,
      'i',
    ),
  },
  {
    name: 'Forget / reset instructions',
    confidence: 'high',
    regex: new RegExp(
      String.raw`\b(?:forget|disregard|override|overwrite)\s+(?:everything|all|your|the\s+above)\s+(?:instructions?|prompts?|rules?|training|guidelines?)\b` +
        NOT_A_REFERENCE,
      'i',
    ),
  },
  {
    name: 'Jailbreak persona',
    confidence: 'high',
    regex:
      /\b(?:you\s+are|you're|act\s+as|pretend\s+to\s+be|roleplay\s+as|become)\s+(?:now\s+)?(?:DAN|jailbreak|unrestricted|unfiltered|evil|malicious|dark)\b/i,
  },
  {
    name: 'System prompt extraction',
    confidence: 'high',
    regex:
      /\b(?:print|show|reveal|display|output|tell\s+me|what\s+is|what's)\s+(?:your\s+)?(?:system\s+prompt|system\s+message|base\s+prompt|initial\s+prompt|hidden\s+prompt|base\s+instructions)\b/i,
  },
  {
    name: 'Role override',
    confidence: 'high',
    regex: /\bfrom\s+now\s+on\s+you\s+are\b/i,
  },
  {
    // "Your new role is ..." is ordinary onboarding language in a job posting.
    name: 'Role override (weak)',
    confidence: 'medium',
    regex: /\b(?:your\s+new\s+role\s+is|you\s+must\s+now\s+always)\b/i,
  },
  {
    // Chat-template control tokens. These have no ordinary textual use.
    name: 'Prompt delimiter attack',
    confidence: 'high',
    regex: /<\s*\|\s*(?:im_start|im_end|system|user|assistant|endoftext)\s*\|\s*>|\[\/?INST\]|<<\/?SYS>>/i,
  },
  {
    // A paired tag is a strong signal, but an AI-vendor posting may legitimately
    // quote one as an example, so it is reported rather than blocked by default.
    // A bare `<user>`/`<system>` custom element in a developer posting is not a
    // match at all: the closing tag is required.
    name: 'Prompt delimiter attack (paired tags)',
    confidence: 'medium',
    regex: /<(system|instructions?|prompt|persona|assistant|user)>[\s\S]*?<\/\1>/i,
  },
  {
    name: 'Stray system tag',
    confidence: 'medium',
    regex: /<\/(system|instructions?|prompt|persona|assistant)>/i,
  },
  {
    // "debug mode" and "admin mode" appear in ordinary technical documentation.
    name: 'Developer mode',
    confidence: 'medium',
    regex: /\b(?:developer\s*mode|dev\s*mode|debug\s*mode|admin\s*mode|god\s*mode)\b/i,
  },
  {
    // Requires the safeguard to follow the verb directly, so a security-engineering
    // posting ("bypass restrictions and safety filters in hardened systems") is not
    // a match, while "bypass safety filters" is. Reported, not blocked by default:
    // red-teaming and safety work discuss this legitimately.
    name: 'Token/safety bypass',
    confidence: 'medium',
    regex:
      /\b(?:bypass|circumvent|disable|turn\s+off)\s+(?:the\s+|your\s+|all\s+)?(?:guardrails?\b|(?:safety|content|moderation)(?:\s+(?:filters?|checks?|guardrails?|restrictions?|limitations?))?\b)/i,
  },
];

export interface InjectionCheckResult {
  flagged: boolean;
  reason?: string;
  findings: Finding[];
}

export function checkInjection(
  text: string,
  opts?: { minConfidence?: Confidence },
): InjectionCheckResult {
  const min = opts?.minConfidence ?? 'medium';
  const findings: Finding[] = [];

  for (const pattern of INJECTION_PATTERNS) {
    if (!atLeast(pattern.confidence, min)) continue;
    if (!pattern.regex.test(text)) continue;

    findings.push({
      layer: 'injection',
      guard: pattern.name,
      confidence: pattern.confidence,
      reason: `Possible prompt injection: ${pattern.name}`,
    });
  }

  if (findings.length === 0) return { flagged: false, findings: [] };

  return {
    flagged: true,
    reason: `Detected possible prompt injection: ${findings.map((f) => f.guard).join(', ')}`,
    findings,
  };
}
