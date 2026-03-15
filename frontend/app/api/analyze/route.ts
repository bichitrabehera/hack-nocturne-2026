import OpenAI from "openai";
import { z } from "zod";

export const runtime = "nodejs";

const OPENAI_API_KEY =
  process.env.OPENAI_API_KEY || process.env.BACKEND_OPENAI_API_KEY || "";
const client = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// ─── Zod Schemas ──────────────────────────────────────────────────────────────

const AttackTypeSchema = z.enum([
  "phishing",
  "drainer",
  "prize",
  "malware",
  "unknown",
]);

/** What we accept from the request body */
const RequestSchema = z.object({
  url: z
    .string()
    .describe("The URL to analyze for potential scams")
    .min(1, "url cannot be empty")
    .max(2048, "url too long")
    .trim()
    .transform((val) => (val.startsWith("http") ? val : `https://${val}`))
    .refine(
      (val) => {
        try {
          new URL(val);
          return true;
        } catch {
          return false;
        }
      },
      { message: "url is not a valid URL" },
    ),
});

/** What the OpenAI model must return — validated before we trust it */
const AIResponseSchema = z.object({
  attackType: AttackTypeSchema.catch("unknown"),
  riskScore: z.number().min(0).max(100).catch(0),
  confidence: z.number().min(0).max(100).catch(0),
  indicators: z.array(z.string().max(200)).max(10).catch([]),
});

/** The shape every caller receives — success or error, always consistent */
const SuccessResponseSchema = z.object({
  ok: z.literal(true),
  attackType: AttackTypeSchema,
  riskScore: z.number().int().min(0).max(100),
  confidence: z.number().int().min(0).max(100),
  indicators: z.array(z.string()),
  source: z.enum(["ai", "heuristic", "fallback"]),
  url: z.string().url(),
  domain: z.string(),
  analysedAt: z.string().datetime(),
});

const ErrorResponseSchema = z.object({
  ok: z.literal(false),
  error: z.string(),
  code: z.enum([
    "MISSING_URL",
    "INVALID_URL",
    "URL_TOO_LONG",
    "ANALYSIS_FAILED",
    "INTERNAL_ERROR",
  ]),
});

// Union — anything coming out of this route matches one of these two shapes
export type ApiResponse =
  | z.infer<typeof SuccessResponseSchema>
  | z.infer<typeof ErrorResponseSchema>;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function clamp(n: number, min = 0, max = 100) {
  return Math.round(Math.max(min, Math.min(max, n)));
}

function errorResponse(
  code: z.infer<typeof ErrorResponseSchema>["code"],
  message: string,
  status: number,
) {
  const body = ErrorResponseSchema.parse({
    ok: false,
    error: message,
    code,
  });
  return Response.json(body, { status });
}

// ─── Signal extraction ────────────────────────────────────────────────────────

interface Signals {
  domain: string;
  length: number;
  rootLabel: string;
  keywords: string[];
  highRiskKeywords: string[];
  patterns: {
    hasIPPattern: boolean;
    hasShortDomain: boolean;
    hasManyDashes: boolean;
    hasSuspiciousTLD: boolean;
    hasTyposquatHint: boolean;
    hasCryptoBaitDomainTerms: boolean;
  };
  riskFactors: string[];
}

const BRAND_REFERENCES = [
  "metamask",
  "trustwallet",
  "coinbase",
  "binance",
  "uniswap",
  "opensea",
  "phantom",
  "ledger",
  "google",
  "microsoft",
  "apple",
];

function getRootLabel(domain: string): string {
  return domain
    .toLowerCase()
    .replace(/^www\./, "")
    .split(".")[0]
    .replace(/[^a-z0-9-]/g, "");
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () =>
    new Array<number>(n + 1).fill(0),
  );

  for (let i = 0; i <= m; i += 1) dp[i][0] = i;
  for (let j = 0; j <= n; j += 1) dp[0][j] = j;

  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }
  return dp[m][n];
}

function hasTyposquatHint(rootLabel: string): boolean {
  if (!rootLabel) return false;

  const nearBrand = BRAND_REFERENCES.some((brand) => {
    if (rootLabel === brand) return false;
    const distance = levenshtein(rootLabel, brand);
    return distance > 0 && distance <= 2;
  });

  const repeatedTail = /([a-z0-9])\1$/.test(rootLabel);
  const appendedVariant = BRAND_REFERENCES.some(
    (brand) =>
      rootLabel.includes(brand) &&
      rootLabel !== brand &&
      Math.abs(rootLabel.length - brand.length) <= 4,
  );

  return nearBrand || (appendedVariant && repeatedTail);
}

function extractSignals(url: string): Signals | null {
  try {
    const u = new URL(url);
    const domain = u.hostname;
    const rootLabel = getRootLabel(domain);
    const path = u.pathname.toLowerCase();
    const query = u.search.toLowerCase();

    const suspiciousKeywords = [
      "airdrop",
      "reward",
      "bonus",
      "claim",
      "verify",
      "wallet",
      "defi",
      "crypto",
      "login",
      "secure",
      "update",
      "connect",
      "mint",
      "approve",
      "stake",
      "swap",
      "drain",
      "private",
      "seed",
      "phrase",
      "mnemonic",
      "keystore",
      "metamask",
      "trustwallet",
    ];
    const highRiskKeywords = [
      "private-key",
      "seed-phrase",
      "mnemonic",
      "approve-all",
      "drain",
      "steal",
      "hack",
      "malware",
      "virus",
    ];

    const inDomain = suspiciousKeywords.filter((k) =>
      domain.toLowerCase().includes(k),
    );
    const inPath = suspiciousKeywords.filter((k) => path.includes(k));
    const inQuery = suspiciousKeywords.filter((k) => query.includes(k));
    const highRisk = highRiskKeywords.filter((k) =>
      url.toLowerCase().includes(k),
    );

    const hasIPPattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain);
    const hasShortDomain = domain.replace(/^www\./, "").length < 8;
    const hasManyDashes = (domain.match(/-/g) ?? []).length > 2;
    const hasSuspiciousTLD =
      /\.(tk|ml|ga|cf|gq|xyz|top|click|cyou|ru|pw)$/i.test(domain);
    const typoHint = hasTyposquatHint(rootLabel);
    const hasCryptoBaitDomainTerms =
      /(airdrop|claim|bonus|reward|wallet|defi|swap|stake|mint)/i.test(
        rootLabel,
      );

    return {
      domain,
      length: url.length,
      rootLabel,
      keywords: [...new Set([...inDomain, ...inPath, ...inQuery])],
      highRiskKeywords: highRisk,
      patterns: {
        hasIPPattern,
        hasShortDomain,
        hasManyDashes,
        hasSuspiciousTLD,
        hasTyposquatHint: typoHint,
        hasCryptoBaitDomainTerms,
      },
      riskFactors: [
        ...(highRisk.length ? ["high_risk_keywords"] : []),
        ...(hasIPPattern ? ["ip_address"] : []),
        ...(hasShortDomain ? ["short_domain"] : []),
        ...(hasManyDashes ? ["excessive_dashes"] : []),
        ...(hasSuspiciousTLD ? ["suspicious_tld"] : []),
        ...(typoHint ? ["typosquat_hint"] : []),
        ...(hasCryptoBaitDomainTerms ? ["crypto_bait_domain_terms"] : []),
      ],
    };
  } catch {
    return null;
  }
}

// ─── Heuristic analysis ───────────────────────────────────────────────────────

interface HeuristicResult {
  attackType: z.infer<typeof AttackTypeSchema>;
  riskScore: number;
  confidence: number;
  indicators: string[];
}

interface PageSignals {
  finalUrl: string;
  title: string;
  formsCount: number;
  linksCount: number;
  externalDomainCount: number;
  hasPasswordField: boolean;
  hasCredentialPrompt: boolean;
  hasWalletConnectPrompt: boolean;
  hasSeedPhrasePrompt: boolean;
  hasUrgencyPrompt: boolean;
  textSnippet: string;
}

function stripHtml(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

async function fetchPageSignals(
  url: string,
  baseDomain: string,
): Promise<PageSignals | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": "Mozilla/5.0 ScamShield-Analyzer" },
      cache: "no-store",
    });

    const html = await response.text();
    const text = stripHtml(html);
    const textSnippet = text.slice(0, 1400);

    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = (titleMatch?.[1] || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 120);

    const formsCount = (html.match(/<form\b/gi) || []).length;
    const links = [...html.matchAll(/href=["']([^"']+)["']/gi)].map(
      (m) => m[1],
    );
    const absoluteDomains = links
      .map((link) => {
        try {
          return new URL(link, response.url).hostname
            .toLowerCase()
            .replace(/^www\./, "");
        } catch {
          return "";
        }
      })
      .filter(Boolean);

    const externalDomainCount = new Set(
      absoluteDomains.filter((d) => d && d !== baseDomain),
    ).size;

    const lower = `${title}\n${textSnippet}`.toLowerCase();
    const hasPasswordField = /type=["']password["']/i.test(html);
    const hasCredentialPrompt =
      /(log ?in|sign ?in|verify account|password|2fa|recovery code|confirm account)/i.test(
        lower,
      ) || hasPasswordField;
    const hasWalletConnectPrompt =
      /(connect wallet|walletconnect|approve|token allowance|sign message|enable wallet)/i.test(
        lower,
      );
    const hasSeedPhrasePrompt =
      /(seed phrase|mnemonic|private key|recovery phrase|12 words|24 words|import wallet)/i.test(
        lower,
      );
    const hasUrgencyPrompt =
      /(limited time|expires|countdown|hurry|urgent|claim now|only today|pool amount)/i.test(
        lower,
      );

    return {
      finalUrl: response.url,
      title,
      formsCount,
      linksCount: links.length,
      externalDomainCount,
      hasPasswordField,
      hasCredentialPrompt,
      hasWalletConnectPrompt,
      hasSeedPhrasePrompt,
      hasUrgencyPrompt,
      textSnippet,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function getQuickAnalysis(
  signals: Signals,
  pageSignals: PageSignals | null,
): HeuristicResult {
  let risk = 0;
  const indicators: string[] = [];

  if (signals.patterns.hasIPPattern) {
    risk += 25;
    indicators.push("IP address used as hostname");
  }
  if (signals.patterns.hasSuspiciousTLD) {
    risk += 15;
    indicators.push("Suspicious top-level domain");
  }
  if (signals.patterns.hasShortDomain) {
    risk += 10;
    indicators.push("Unusually short domain");
  }
  if (signals.patterns.hasManyDashes) {
    risk += 10;
    indicators.push("Excessive hyphens in domain");
  }
  if (signals.patterns.hasTyposquatHint) {
    risk += 22;
    indicators.push("Typosquatting / lookalike domain pattern");
  }
  if (signals.patterns.hasCryptoBaitDomainTerms) {
    risk += 12;
    indicators.push("Crypto bait terms embedded in domain");
  }
  if (signals.highRiskKeywords.length) {
    risk += 30;
    indicators.push(
      "High-risk keywords: " + signals.highRiskKeywords.slice(0, 3).join(", "),
    );
  }

  const phishingKW = [
    "login",
    "secure",
    "verify",
    "account",
    "metamask",
    "wallet",
  ];
  const drainerKW = ["approve", "connect", "drain", "mint", "stake", "swap"];
  const prizeKW = ["airdrop", "reward", "bonus", "claim", "giveaway"];
  const malwareKW = ["download", "update", "install", "virus", "malware"];

  const hasPhishing = signals.keywords.some((k) => phishingKW.includes(k));
  const hasDrainer = signals.keywords.some((k) => drainerKW.includes(k));
  const hasPrize = signals.keywords.some((k) => prizeKW.includes(k));
  const hasMalware = signals.keywords.some((k) => malwareKW.includes(k));

  let attackType: z.infer<typeof AttackTypeSchema> = "unknown";

  if (hasDrainer) {
    attackType = "drainer";
    risk += 25;
    indicators.push("Wallet drain indicators");
  } else if (hasPhishing) {
    attackType = "phishing";
    risk += 20;
    indicators.push("Credential phishing indicators");
  } else if (hasPrize) {
    attackType = "prize";
    risk += 15;
    indicators.push("Fake reward/prize indicators");
  } else if (hasMalware) {
    attackType = "malware";
    risk += 20;
    indicators.push("Malware distribution indicators");
  }

  if (pageSignals) {
    if (pageSignals.formsCount > 0) {
      risk += 8;
      indicators.push(`HTML forms present (${pageSignals.formsCount})`);
    }
    if (pageSignals.externalDomainCount >= 2) {
      risk += 8;
      indicators.push(
        `Multiple external domains (${pageSignals.externalDomainCount})`,
      );
    }
    if (pageSignals.hasSeedPhrasePrompt) {
      risk += 40;
      indicators.push("Seed phrase / private key prompt detected");
      if (attackType === "unknown") attackType = "phishing";
    }
    if (pageSignals.hasCredentialPrompt) {
      risk += 26;
      indicators.push("Credential/login prompt detected");
      if (attackType === "unknown") attackType = "phishing";
    }
    if (pageSignals.hasWalletConnectPrompt) {
      risk += 24;
      indicators.push("Wallet connect / approval prompt detected");
      if (attackType === "unknown") attackType = "drainer";
    }
    if (pageSignals.hasUrgencyPrompt) {
      risk += 12;
      indicators.push("Urgency language detected");
    }
  }

  const confidenceBoost =
    (signals.patterns.hasTyposquatHint ? 15 : 0) +
    (signals.patterns.hasCryptoBaitDomainTerms ? 10 : 0) +
    (pageSignals?.hasCredentialPrompt ? 12 : 0) +
    (pageSignals?.hasWalletConnectPrompt ? 12 : 0) +
    (pageSignals?.hasSeedPhrasePrompt ? 18 : 0);

  return {
    attackType,
    riskScore: clamp(risk),
    confidence: clamp(50 + signals.keywords.length * 5 + confidenceBoost),
    indicators: indicators.slice(0, 5),
  };
}

function calibrateAnalysisResult(
  merged: z.infer<typeof SuccessResponseSchema>,
  heuristic: HeuristicResult,
  pageSignals: PageSignals | null,
): z.infer<typeof SuccessResponseSchema> {
  let attackType = merged.attackType;
  let riskScore = merged.riskScore;
  let confidence = merged.confidence;
  const indicators = [...merged.indicators];

  if (pageSignals?.hasSeedPhrasePrompt) {
    riskScore = Math.max(riskScore, 75);
    confidence = Math.max(confidence, 75);
    if (attackType === "unknown") attackType = "phishing";
  }
  if (pageSignals?.hasCredentialPrompt) {
    riskScore = Math.max(riskScore, 60);
    confidence = Math.max(confidence, 68);
    if (attackType === "unknown") attackType = "phishing";
  }
  if (pageSignals?.hasWalletConnectPrompt && pageSignals?.hasUrgencyPrompt) {
    riskScore = Math.max(riskScore, 58);
    confidence = Math.max(confidence, 65);
    if (attackType === "unknown") attackType = "drainer";
  }

  // Always enforce heuristic as a floor — AI cannot score lower than heuristic
  riskScore = Math.max(riskScore, heuristic.riskScore);
  confidence = Math.max(confidence, heuristic.confidence);

  // Only allow AI "unknown" to override heuristic if heuristic is also uncertain
  if (
    attackType === "unknown" &&
    heuristic.attackType !== "unknown" &&
    heuristic.riskScore >= 25 // lowered threshold: trust heuristic attack type sooner
  ) {
    attackType = heuristic.attackType;
  }

  if (pageSignals && pageSignals.finalUrl !== merged.url) {
    indicators.push(`Resolved final URL: ${pageSignals.finalUrl}`);
  }

  return {
    ...merged,
    attackType,
    riskScore: clamp(riskScore),
    confidence: clamp(confidence),
    indicators: [...new Set(indicators)].slice(0, 8),
  };
}

// ─── Discord alert ────────────────────────────────────────────────────────────

async function sendDiscordAlert(
  url: string,
  result: HeuristicResult,
): Promise<void> {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl || result.riskScore < 70) return;

  const color =
    result.riskScore >= 85
      ? 0xff0000
      : result.riskScore >= 70
        ? 0xff6600
        : 0xffff00;

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "ScamShield Bot",
        embeds: [
          {
            title: "⚡ High-Risk Scam Detected",
            color,
            fields: [
              { name: "URL", value: url.slice(0, 100), inline: false },
              { name: "Type", value: result.attackType, inline: true },
              { name: "Risk", value: `${result.riskScore}/100`, inline: true },
              {
                name: "Confidence",
                value: `${result.confidence}%`,
                inline: true,
              },
              {
                name: "Indicators",
                value: result.indicators.slice(0, 3).join("\n") || "—",
                inline: false,
              },
            ],
            timestamp: new Date().toISOString(),
            footer: { text: "ScamShield Real-time Alert" },
          },
        ],
      }),
    });
  } catch (err) {
    console.error("[Discord] alert failed:", err);
    // Never throw — Discord failure must not affect the API response
  }
}

// ─── Route handler ────────────────────────────────────────────────────────────

export async function POST(req: Request): Promise<Response> {
  // 1. Parse + validate request body
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return errorResponse("MISSING_URL", "Request body must be valid JSON", 400);
  }

  const parsed = RequestSchema.safeParse(body);
  if (!parsed.success) {
    const firstError = parsed.error.issues[0];
    const code =
      firstError.path[0] === "url" && firstError.message.includes("required")
        ? "MISSING_URL"
        : firstError.message.includes("valid URL")
          ? "INVALID_URL"
          : firstError.message.includes("too long")
            ? "URL_TOO_LONG"
            : "INVALID_URL";
    return errorResponse(code, firstError.message, 400);
  }

  const { url } = parsed.data;

  // 2. Extract signals — always works if URL parsed
  const signals = extractSignals(url);
  if (!signals) {
    return errorResponse(
      "ANALYSIS_FAILED",
      "Could not extract signals from URL",
      422,
    );
  }

  const domain = signals.domain;
  const analysedAt = new Date().toISOString();
  const pageSignals = await fetchPageSignals(url, domain);
  const heuristic = getQuickAnalysis(signals, pageSignals);

  try {
    if (!client) {
      throw new Error("OPENAI_API_KEY is not configured");
    }

    // FIX 1: Removed `heuristicResult` from AI input entirely.
    // Passing the heuristic to the model caused it to anchor on (and sometimes
    // contradict or blindly echo) those values rather than reasoning from raw signals.
    // The heuristic is applied as a hard floor in the merge step instead.
    //
    // FIX 2: Replaced vague scoring "guidance" with deterministic RULES the model
    // must follow. LLMs treat soft guidance as optional; explicit IF/THEN rules
    // produce consistent, reproducible scoring.
    const completion = await client.chat.completions.create({
      model: "gpt-4o-mini",
      temperature: 0.1,
      max_tokens: 320,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: `You are a cybersecurity scam detection engine. Analyze the URL signals provided and return a JSON risk assessment.

CLASSIFICATION RULES (apply in order, first match wins):
- If hasSeedPhrasePrompt OR highRiskKW contains "mnemonic"/"seed-phrase"/"private-key" → attackType="phishing", riskScore >= 80
- If hasWalletConnectPrompt AND (hasUrgencyPrompt OR hasCryptoBaitDomainTerms) → attackType="drainer", riskScore >= 65
- If hasWalletConnectPrompt → attackType="drainer", riskScore >= 50
- If hasCredentialPrompt AND (hasTyposquatHint OR hasSuspiciousTLD) → attackType="phishing", riskScore >= 60
- If hasCredentialPrompt → attackType="phishing", riskScore >= 45
- If suspiciousKW contains any of [airdrop,reward,bonus,claim] AND (hasSuspiciousTLD OR hasCryptoBaitDomainTerms) → attackType="prize", riskScore >= 50
- If suspiciousKW contains any of [airdrop,reward,bonus,claim] → attackType="prize", riskScore >= 35
- If suspiciousKW contains any of [approve,drain,mint,stake,swap] → attackType="drainer", riskScore >= 40
- If suspiciousKW contains any of [login,verify,secure,metamask,wallet] → attackType="phishing", riskScore >= 35
- If hasSuspiciousTLD AND hasTyposquatHint → riskScore += 30 on top of any matched rule above
- If hasSuspiciousTLD AND hasCryptoBaitDomainTerms → riskScore += 20 on top of any matched rule above
- If hasIPPattern → riskScore += 25
- If hasManyDashes → riskScore += 10
- Only use attackType="unknown" if NO rule above matched at all

CONFIDENCE RULES:
- Start confidence at 50
- +15 if hasTyposquatHint
- +12 if hasCredentialPrompt
- +12 if hasWalletConnectPrompt
- +18 if hasSeedPhrasePrompt
- +10 if hasCryptoBaitDomainTerms
- +5 per suspicious keyword (max +25)

Return ONLY a JSON object — no prose, no markdown.
Schema: { attackType, riskScore (0-100 integer), confidence (0-100 integer), indicators: string[] (max 5 items, each a concise human-readable reason) }`,
        },
        {
          role: "user",
          // FIX 1 applied here: heuristicResult removed from this payload
          content: JSON.stringify({
            url,
            domain,
            rootLabel: signals.rootLabel,
            urlLength: signals.length,
            suspiciousKW: signals.keywords,
            highRiskKW: signals.highRiskKeywords,
            patterns: signals.patterns,
            riskFactors: signals.riskFactors,
            pageSignals: pageSignals
              ? {
                  // FIX 3: Send only boolean page signals to AI, not raw text snippets.
                  // The textSnippet was bloating the context and sometimes confusing
                  // the model with benign-looking page copy from legitimately risky pages.
                  title: pageSignals.title,
                  formsCount: pageSignals.formsCount,
                  externalDomainCount: pageSignals.externalDomainCount,
                  hasPasswordField: pageSignals.hasPasswordField,
                  hasCredentialPrompt: pageSignals.hasCredentialPrompt,
                  hasWalletConnectPrompt: pageSignals.hasWalletConnectPrompt,
                  hasSeedPhrasePrompt: pageSignals.hasSeedPhrasePrompt,
                  hasUrgencyPrompt: pageSignals.hasUrgencyPrompt,
                }
              : null,
          }),
        },
      ],
    });

    // 4. Validate the AI response with Zod — never trust raw JSON from a model
    const rawAI = JSON.parse(completion.choices[0].message.content ?? "{}");
    const aiParsed = AIResponseSchema.safeParse(rawAI);

    // If AI returned garbage, fall back to heuristic (never fail the request)
    const ai = aiParsed.success ? aiParsed.data : heuristic;

    // FIX 4: Attack type resolution — prefer AI when it's specific, but never
    // let AI "unknown" silently discard a heuristic that found something concrete.
    const resolvedAttackType: z.infer<typeof AttackTypeSchema> =
      ai.attackType !== "unknown"
        ? ai.attackType
        : heuristic.attackType !== "unknown"
          ? heuristic.attackType
          : "unknown";

    const merged: z.infer<typeof SuccessResponseSchema> = {
      ok: true,
      source: aiParsed.success ? "ai" : "heuristic",
      url,
      domain,
      analysedAt,
      attackType: resolvedAttackType,
      // Heuristic is always the floor — AI cannot produce a lower risk score
      riskScore: clamp(Math.max(heuristic.riskScore, ai.riskScore)),
      confidence: clamp(Math.max(heuristic.confidence, ai.confidence)),
      indicators: [
        ...new Set([...heuristic.indicators, ...ai.indicators]),
      ].slice(0, 8),
    };

    const calibrated = calibrateAnalysisResult(merged, heuristic, pageSignals);

    void sendDiscordAlert(url, calibrated);
    return Response.json(SuccessResponseSchema.parse(calibrated));
  } catch (err) {
    // 5. OpenAI failed entirely — return heuristic as fallback, never 500
    console.error("[OpenAI] analysis failed:", err);
    const fallback: z.infer<typeof SuccessResponseSchema> = {
      ok: true,
      source: "fallback",
      url,
      domain,
      analysedAt,
      ...heuristic,
      indicators: [
        ...heuristic.indicators,
        "OpenAI unavailable, using heuristic fallback",
      ].slice(0, 8),
    };
    return Response.json(SuccessResponseSchema.parse(fallback));
  }
}
