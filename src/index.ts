import { configure, getConfig, HeimdallConfig, HeimdallLogger, HeimdallResult } from './config';
import { checkModeration } from './moderation';
import { checkSecrets } from './secrets';
import { checkInjection } from './injection';

export type { HeimdallConfig, HeimdallLogger, HeimdallResult };

const INPUT_REFUSAL =
  "I'm not able to help with that message. Is there something fund-related I can assist with?";

const OUTPUT_REFUSAL =
  "I'm here to help with your Fundr workflows. Could you rephrase what you're looking for?";

function log(cfg: HeimdallConfig, stage: string, guardType: string, reason?: string, preview?: string): void {
  cfg.logger?.warn('[heimdall] ' + stage + ' blocked', {
    guardType,
    reason,
    preview,
  });
}

export function checkInputFast(text: string): HeimdallResult {
  const cfg = getConfig();

  const secretsResult = checkSecrets(text);
  const injectionResult = checkInjection(text);

  const blocked = secretsResult.flagged
    ? { type: 'secrets' as const, reason: secretsResult.reason }
    : injectionResult.flagged
      ? { type: 'injection' as const, reason: injectionResult.reason }
      : null;

  if (blocked) {
    log(cfg, 'input', blocked.type, blocked.reason, text.slice(0, 200));
    return { blocked: true, reason: INPUT_REFUSAL };
  }

  return { blocked: false };
}

export async function checkInputModeration(text: string): Promise<HeimdallResult> {
  const cfg = getConfig();

  const modResult = await checkModeration(text, cfg.moderationApiKey)
    .catch(() => ({ flagged: false, reason: undefined }));

  if (modResult.flagged) {
    log(cfg, 'input', 'moderation', modResult.reason, text.slice(0, 200));
    return { blocked: true, reason: INPUT_REFUSAL };
  }

  return { blocked: false };
}

export async function checkInput(text: string): Promise<HeimdallResult> {
  const cfg = getConfig();
  const apiKey = cfg.moderationApiKey;

  const [modResult, secretsResult, injectionResult] = await Promise.all([
    checkModeration(text, apiKey).catch(() => ({ flagged: false, reason: undefined })),
    Promise.resolve(checkSecrets(text)),
    Promise.resolve(checkInjection(text)),
  ]);

  const blocked = modResult.flagged
    ? { type: 'moderation' as const, reason: modResult.reason }
    : secretsResult.flagged
      ? { type: 'secrets' as const, reason: secretsResult.reason }
      : injectionResult.flagged
        ? { type: 'injection' as const, reason: injectionResult.reason }
        : null;

  if (blocked) {
    log(cfg, 'input', blocked.type, blocked.reason, text.slice(0, 200));
    return { blocked: true, reason: INPUT_REFUSAL };
  }

  return { blocked: false };
}

export async function checkOutput(text: string): Promise<HeimdallResult> {
  const cfg = getConfig();
  const apiKey = cfg.moderationApiKey;

  const [modResult, secretsResult] = await Promise.all([
    checkModeration(text, apiKey).catch(() => ({ flagged: false, reason: undefined })),
    Promise.resolve(checkSecrets(text)),
  ]);

  const blocked = modResult.flagged
    ? { type: 'moderation' as const, reason: modResult.reason }
    : secretsResult.flagged
      ? { type: 'secrets' as const, reason: secretsResult.reason }
      : null;

  if (blocked) {
    log(cfg, 'output', blocked.type, blocked.reason, text.slice(0, 200));
    return { blocked: true, reason: OUTPUT_REFUSAL };
  }

  return { blocked: false };
}

export { configure };
