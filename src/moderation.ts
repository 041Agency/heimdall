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

interface ModerationResult {
  flagged: boolean;
  categories: Record<string, boolean>;
}

export interface ModerationCheckResult {
  flagged: boolean;
  reason?: string;
}

export async function checkModeration(text: string, apiKey?: string): Promise<ModerationCheckResult> {
  if (!apiKey) {
    return { flagged: false };
  }

  try {
    const res = await fetch(MODERATION_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ input: text }),
    });

    if (!res.ok) {
      return { flagged: false };
    }

    const data = (await res.json()) as { results: ModerationResult[] };
    const result = data.results?.[0];
    if (!result?.flagged) {
      return { flagged: false };
    }

    const triggered = HARMFUL_CATEGORIES.filter((cat) => result.categories[cat]);
    if (triggered.length === 0) {
      return { flagged: false };
    }

    return {
      flagged: true,
      reason: `Content flagged for: ${triggered.join(', ')}`,
    };
  } catch {
    return { flagged: false };
  }
}
