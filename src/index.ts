import {
  configure,
  getConfig,
  isBlocking,
  layerEnabled,
  type Finding,
  type HeimdallResult,
} from './config';
import { checkModeration } from './moderation';
import { checkSecrets } from './secrets';
import { checkInjection } from './injection';

export type {
  Confidence,
  Finding,
  GuardLayer,
  HeimdallConfig,
  HeimdallLogger,
  HeimdallResult,
  SecretCategory,
} from './config';
export { checkModeration } from './moderation';
export { checkSecrets } from './secrets';
export { checkInjection } from './injection';

/**
 * Fallbacks used only when the caller has not set `messages`. Prefer setting
 * your own: the wording a user sees belongs to your product, not this library.
 */
const DEFAULT_INPUT_MESSAGE =
  "I'm not able to help with that message. Could you rephrase what you're looking for?";

const DEFAULT_OUTPUT_MESSAGE =
  "I'm unable to respond to that request. Could you try asking in a different way?";

/**
 * Report every finding to the caller, then decide. The log carries the rule and
 * its confidence but never any of the scanned text.
 */
function decide(
  stage: 'input' | 'output',
  findings: Finding[],
  fallback: string,
): HeimdallResult {
  const cfg = getConfig();

  for (const finding of findings) {
    cfg.onFinding?.(finding);
    cfg.logger?.warn(`[heimdall] ${stage} guard fired`, {
      layer: finding.layer,
      guard: finding.guard,
      confidence: finding.confidence,
      category: finding.category,
    });
  }

  if (!findings.some(isBlocking)) return { blocked: false, findings };

  const message =
    stage === 'output' ? cfg.messages?.output ?? fallback : cfg.messages?.input ?? fallback;
  return { blocked: true, reason: message, findings };
}

/**
 * Synchronous input check: secrets and injection only, no network. Use this on
 * the hot path and run `checkInputModeration` in parallel if you want both.
 */
export function checkInputFast(text: string): HeimdallResult {
  const findings: Finding[] = [];
  if (layerEnabled('secrets')) findings.push(...checkSecrets(text).findings);
  if (layerEnabled('injection')) findings.push(...checkInjection(text).findings);
  return decide('input', findings, DEFAULT_INPUT_MESSAGE);
}

/** The moderation layer on its own. Resolves immediately when it is disabled. */
export async function checkInputModeration(text: string): Promise<HeimdallResult> {
  if (!layerEnabled('moderation')) return { blocked: false, findings: [] };
  const result = await checkModeration(text, getConfig().moderationApiKey);
  return decide('input', result.findings, DEFAULT_INPUT_MESSAGE);
}

/** Every enabled input layer. Moderation runs concurrently with the regexes. */
export async function checkInput(text: string): Promise<HeimdallResult> {
  const cfg = getConfig();

  const [moderation, secrets, injection] = await Promise.all([
    layerEnabled('moderation')
      ? checkModeration(text, cfg.moderationApiKey)
      : Promise.resolve({ findings: [] as Finding[] }),
    Promise.resolve(layerEnabled('secrets') ? checkSecrets(text).findings : []),
    Promise.resolve(layerEnabled('injection') ? checkInjection(text).findings : []),
  ]);

  return decide(
    'input',
    [...moderation.findings, ...secrets, ...injection],
    DEFAULT_INPUT_MESSAGE,
  );
}

/** Output check: moderation and secrets. Injection only makes sense on input. */
export async function checkOutput(text: string): Promise<HeimdallResult> {
  const cfg = getConfig();

  const [moderation, secrets] = await Promise.all([
    layerEnabled('moderation')
      ? checkModeration(text, cfg.moderationApiKey)
      : Promise.resolve({ findings: [] as Finding[] }),
    Promise.resolve(layerEnabled('secrets') ? checkSecrets(text).findings : []),
  ]);

  return decide('output', [...moderation.findings, ...secrets], DEFAULT_OUTPUT_MESSAGE);
}

/**
 * Report-only. Runs every enabled input layer and returns the findings without
 * deciding anything. This is the entry point for apps that surface findings
 * themselves instead of refusing.
 */
export async function inspect(text: string): Promise<Finding[]> {
  return (await checkInput(text)).findings;
}

export { configure };
