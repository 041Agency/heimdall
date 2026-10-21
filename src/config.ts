/**
 * How sure a rule is that it has found something.
 *
 * `high` is reserved for phrases and patterns that are essentially never
 * legitimate in ordinary business text. `medium` is for heuristics that are
 * right most of the time but have real-world false positives, so they are
 * reported but do not block unless the caller opts in.
 */
export type Confidence = 'high' | 'medium';

/**
 * Secrets are split into two groups because callers act on them differently.
 * A leaked API key is an incident; a document containing the owner's own social
 * security number is a thing to tell them about, not a reason to refuse.
 */
export type SecretCategory = 'credential' | 'personal-data';

export type GuardLayer = 'moderation' | 'secrets' | 'injection';

/** One thing a guard found. Never contains any of the scanned text. */
export interface Finding {
  layer: GuardLayer;
  /** The rule that fired, e.g. `GitHub Token` or `Ignore instructions`. */
  guard: string;
  confidence: Confidence;
  /** Set on secret findings. */
  category?: SecretCategory;
  /** Short, safe description. Contains no content from the scanned text. */
  reason: string;
}

export interface HeimdallLogger {
  warn: (msg: string, data?: Record<string, unknown>) => void;
}

export interface HeimdallConfig {
  /** OpenAI API key for the moderation layer. Without it, moderation is skipped. */
  moderationApiKey?: string;
  /** Optional logger. Receives `(message, data)` whenever a guard fires. */
  logger?: HeimdallLogger;
  /** Turn individual layers off. Absent means on. */
  layers?: Partial<Record<GuardLayer, boolean>>;
  /**
   * Lowest confidence that blocks. `'medium'` blocks on heuristics too, which
   * trades false positives for recall. Default: `'high'`.
   */
  blockAt?: Confidence;
  /**
   * Categories that are reported through `findings`/`onFinding` but never block.
   * Default: `['personal-data']` — a document is not refused because it contains
   * the user's own social security number.
   */
  nonBlockingCategories?: SecretCategory[];
  /**
   * Copy returned in `reason` when input or output is blocked. Callers own this:
   * a guardrails library has no business deciding what your product says.
   */
  messages?: { input?: string; output?: string };
  /**
   * Called for every finding, blocked or not. This is the hook for report-only
   * mode: leave the layers on and act on findings yourself.
   */
  onFinding?: (finding: Finding) => void;
}

export interface HeimdallResult {
  blocked: boolean;
  /** The caller-facing message when blocked. */
  reason?: string;
  /** Everything the guards found, whether or not it blocked. */
  findings: Finding[];
}

const CONFIDENCE_RANK: Record<Confidence, number> = { high: 2, medium: 1 };

export function atLeast(actual: Confidence, minimum: Confidence): boolean {
  return CONFIDENCE_RANK[actual] >= CONFIDENCE_RANK[minimum];
}

let config: HeimdallConfig = {};

export function configure(cfg: HeimdallConfig): void {
  config = cfg;
}

export function getConfig(): HeimdallConfig {
  return config;
}

export function layerEnabled(layer: GuardLayer): boolean {
  return config.layers?.[layer] !== false;
}

/** Should this finding stop the request, given the current config? */
export function isBlocking(finding: Finding): boolean {
  if (!atLeast(finding.confidence, config.blockAt ?? 'high')) return false;
  const exempt = config.nonBlockingCategories ?? ['personal-data'];
  return !(finding.category !== undefined && exempt.includes(finding.category));
}
