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
export declare function configure(cfg: HeimdallConfig): void;
export declare function getConfig(): HeimdallConfig;
//# sourceMappingURL=config.d.ts.map