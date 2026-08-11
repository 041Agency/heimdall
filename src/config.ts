export interface HeimdallLogger {
  warn: (msg: string, data?: Record<string, unknown>) => void;
}

export interface HeimdallConfig {
  moderationApiKey?: string;
  logger?: HeimdallLogger;
}

export interface HeimdallResult {
  blocked: boolean;
  reason?: string;
}

let config: HeimdallConfig = {};

export function configure(cfg: HeimdallConfig): void {
  config = cfg;
}

export function getConfig(): HeimdallConfig {
  return config;
}
