"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkInjection = checkInjection;
const INJECTION_PATTERNS = [
    {
        name: 'Ignore instructions',
        regex: /\bignore\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|prompts?|rules?|guidelines?|system\s+(prompt|message))\b/i,
    },
    {
        name: 'Forget / reset instructions',
        regex: /\b(forget|disregard|override|overwrite)\s+(everything|all|your)\s+(instructions?|prompts?|rules?|training)\b/i,
    },
    {
        name: 'Jailbreak persona',
        regex: /\b(you\s+are|you're|act\s+as|pretend\s+to\s+be|roleplay\s+as|become)\s+(now\s+)?(DAN|jailbreak|unrestricted|unfiltered|evil|malicious|dark)\b/i,
    },
    {
        name: 'System prompt extraction',
        regex: /\b(print|show|reveal|display|output|tell\s+me|what\s+is|what's)\s+(your\s+)?(system\s+prompt|system\s+message|base\s+prompt|initial\s+prompt|hidden\s+prompt|base\s+instructions)\b/i,
    },
    {
        name: 'Role override',
        regex: /\b(from\s+now\s+on\s+you\s+are|your\s+new\s+role\s+is|you\s+must\s+now\s+(always\s*)?)\b/i,
    },
    {
        name: 'Prompt delimiter attack',
        regex: /<\/?(system|instruction|prompt|rule|persona|user|assistant)>/i,
    },
    {
        name: 'Developer mode',
        regex: /\b(developer\s*mode|dev\s*mode|debug\s*mode|admin\s*mode|god\s*mode)\b/i,
    },
    {
        name: 'Token/safety bypass',
        regex: /\b(bypass|circumvent|disable|turn\s*off)\s+(safety|filter|guardrail|moderation|content\s+filter|restrictions?|limitations?)\b/i,
    },
];
function checkInjection(text) {
    const found = [];
    for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(text)) {
            found.push(pattern.name);
        }
    }
    if (found.length === 0) {
        return { flagged: false };
    }
    return {
        flagged: true,
        reason: `Detected possible prompt injection: ${found.join(', ')}`,
    };
}
//# sourceMappingURL=injection.js.map