export interface ModerationCheckResult {
    flagged: boolean;
    reason?: string;
}
export declare function checkModeration(text: string, apiKey?: string): Promise<ModerationCheckResult>;
//# sourceMappingURL=moderation.d.ts.map