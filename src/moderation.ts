import type { Finding } from './config';

const MODERATION_URL = 'https://api.openai.com/v1/moderations';

const HARMFUL_CATEGORIES = [
  'hate',
  'hate/threatening',
  'harassment',
  'harassment/threatening',
  'self-harm',
  'self-harm/intent',
  'self-harm/instructions',
  'sexual',
  'sexual/minors',
  'violence',
  'violence/graphic',
] as const;

interface ModerationResponse {
  flagged: boolean;
  categories: Record<string, boolean>;
}

export interface ModerationCheckResult {
  flagged: boolean;
  reason?: string;
  findings: Finding[];
}

/**
 * OpenAI's moderation endpoint. It is free (no token cost) but requires a
 * platform API key; without one the layer is skipped and reports nothing.
 * Fails open: a network error is not a block.
 *
 * Note the categories are harm categories aimed at user-generated chat. They
 * carry no signal about whether a document is relevant or good, so this layer
 * is not a fit-ranking tool.
 */
export async function checkModeration(
  text: string,
  apiKey?: string,
): Promise<ModerationCheckResult> {
  if (!apiKey) return { flagged: false, findings: [] };

  try {
    const res = await fetch(MODERATION_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ input: text }),
    });

    if (!res.ok) return { flagged: false, findings: [] };

    const data = (await res.json()) as { results: ModerationResponse[] };
    const result = data.results?.[0];
    if (!result?.flagged) return { flagged: false, findings: [] };

    const triggered = HARMFUL_CATEGORIES.filter((cat) => result.categories[cat]);
    if (triggered.length === 0) return { flagged: false, findings: [] };

    const reason = `Content flagged for: ${triggered.join(', ')}`;
    return {
      flagged: true,
      reason,
      findings: [
        {
          layer: 'moderation',
          guard: 'OpenAI moderation',
          confidence: 'high',
          reason,
        },
      ],
    };
  } catch {
    return { flagged: false, findings: [] };
  }
}
