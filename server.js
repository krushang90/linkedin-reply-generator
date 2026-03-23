import "dotenv/config";
import express from "express";
import session from "express-session";
import Anthropic from "@anthropic-ai/sdk";
import path from "path";
import { fileURLToPath } from "url";
import { createHash, createDecipheriv, scryptSync } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Decrypt ENCRYPTED_API_KEY if present, otherwise fall back to ANTHROPIC_API_KEY
function resolveApiKey() {
  const encrypted = process.env.ENCRYPTED_API_KEY;
  const encKey = process.env.ENCRYPTION_KEY;

  if (encrypted && encKey) {
    const parts = encrypted.split(":");
    if (parts.length !== 4) throw new Error("ENCRYPTED_API_KEY format invalid");
    const [saltHex, ivHex, authTagHex, dataHex] = parts;
    const key = scryptSync(encKey, Buffer.from(saltHex, "hex"), 32);
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));
    return decipher.update(dataHex, "hex", "utf8") + decipher.final("utf8");
  }

  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  throw new Error("No API key found. Set ENCRYPTED_API_KEY + ENCRYPTION_KEY, or ANTHROPIC_API_KEY.");
}

const client = new Anthropic({ apiKey: resolveApiKey() });

// Hash helper — passwords are stored as SHA-256 hex in .env
function sha256(str) {
  return createHash("sha256").update(str).digest("hex");
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_this_secret_in_env",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", maxAge: 8 * 60 * 60 * 1000 }, // 8h
  })
);

// Auth middleware — protects every route except /login and /logout
function requireAuth(req, res, next) {
  if (req.session.authenticated) return next();
  if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Unauthorised" });
  res.redirect("/login");
}

// Login page
app.get("/login", (req, res) => {
  if (req.session.authenticated) return res.redirect("/");
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Login submit
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const validUser = process.env.ADMIN_USERNAME || "admin";
  const validHash = process.env.ADMIN_PASSWORD_HASH;

  if (!validHash) {
    return res.status(500).send("ADMIN_PASSWORD_HASH not set in .env");
  }

  if (username === validUser && sha256(password) === validHash) {
    req.session.authenticated = true;
    return res.redirect("/");
  }

  res.redirect("/login?error=1");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// Protect all routes below this point
app.use(requireAuth);

app.use(express.static(path.join(__dirname, "public")));

const COMPANY_PROFILES = {
  yashvi_global: {
    name: "Yashvi Global",
    website: "yashviglobal.com",
    description: `Yashvi Global is a full-service digital agency offering 360° digital marketing and software development.
Services include:
- Digital Marketing: SEO, social media marketing, paid ads (Google/Meta), content marketing, email marketing, performance marketing
- Software Development: ERP systems, CRM solutions, custom web development
- Tech Stack: PHP and open-source technologies
- Approach: Data-driven, results-focused, tailored strategies
- Goal: Lead generation and business growth for clients`,
  },
  yashvi_konnect: {
    name: "Yashvi Konnect",
    website: "yashvikonnect.com",
    description: `Yashvi Konnect is a specialized digital agency exclusively serving e-commerce businesses.
Services include:
- E-commerce marketing: Paid ads (Google Shopping, Meta), conversion rate optimization, retargeting
- E-commerce SEO: Product page optimization, category SEO, technical SEO
- E-commerce growth: Email/SMS marketing, marketplace management, analytics
- Platform expertise: Shopify, WooCommerce, Magento, OpenCart
- Goal: Revenue growth and lead generation specifically for e-commerce brands`,
  },
};

const TONE_INSTRUCTIONS = `
You are responding from a personal LinkedIn profile on behalf of the company.
Tone guidelines:
- Warm, friendly, and conversational (not salesy or pushy)
- Sound like a real person, not a corporate bot
- Natural and approachable, the way you'd talk to someone you just met at a networking event
- Never use em dashes (do not use the -- or the actual em dash character)
- Don't use buzzwords like "synergy", "leverage", "holistic"
- Avoid emojis unless absolutely natural in context
`;

const REPLY_TYPE_INSTRUCTIONS = {
  comment: `You are writing a public comment reply on a LinkedIn post.
Keep it short and punchy (1 to 3 sentences max). It's visible to everyone so keep it friendly and on-point.
End with a light CTA like a question or an invite to connect or chat. Do not start with "Hi [name]".`,

  dm: `You are writing a LinkedIn Direct Message (DM).
This is a private, one-on-one conversation — be warm, direct, and confident.
Start with a proper greeting like "Hi [First Name]," or "Hey [First Name],".
Keep it to 3 to 5 sentences. Acknowledge what they said or why you're reaching out from a position of confidence — you're not pitching, you're starting a peer conversation. Never use phrases that sound desperate or like you're chasing work (e.g. "this is our bread and butter", "we'd love to help", "we can do this for you"). End with a soft CTA like a relevant question or an offer to chat.`,

  email: `You are writing a follow-up email.
Format it as a proper email with:
- Subject: (a short, natural subject line)
- A friendly greeting (e.g. "Hey [First Name]," or "Hi [First Name],")
- 2 to 3 short paragraphs: acknowledge them, show relevance, soft CTA
- A warm sign-off (e.g. "Cheers," or "Looking forward to connecting,") followed by the sender's name placeholder [Your Name]
Keep the tone friendly and human, not stiff or corporate.`,
};

app.post("/api/generate", async (req, res) => {
  const { comment, company, context, replyType } = req.body;

  if (!comment || !company) {
    return res.status(400).json({ error: "comment and company are required" });
  }

  const profile = COMPANY_PROFILES[company];
  if (!profile) {
    return res.status(400).json({ error: "invalid company" });
  }

  const type = replyType && REPLY_TYPE_INSTRUCTIONS[replyType] ? replyType : "comment";
  const replyTypeInstructions = REPLY_TYPE_INSTRUCTIONS[type];

  const systemPrompt = `You are a reply generator for ${profile.name}.

Company Profile:
${profile.description}

${TONE_INSTRUCTIONS}

${replyTypeInstructions}

Your job: Generate a thoughtful, engaging reply that:
1. Acknowledges what they said
2. Subtly reinforces ${profile.name}'s value/expertise
3. Moves the conversation forward toward a potential business relationship
4. Feels like it came from a real person, not a marketing team`;

  const replyTypeLabel = { comment: "LinkedIn post comment", dm: "LinkedIn DM", email: "email" }[type];

  const userMessage = `Message or post to reply to:
"${comment}"${context ? `\n\nAdditional context about this person or conversation:\n${context}` : ""}

Generate a natural ${replyTypeLabel} reply.`;

  try {
    const stream = client.messages.stream({
      model: "claude-opus-4-6",
      max_tokens: 512,
      system: [
        {
          type: "text",
          text: systemPrompt,
          cache_control: { type: "ephemeral", ttl: "1h" },
        },
      ],
      messages: [{ role: "user", content: userMessage }],
    });

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    for await (const event of stream) {
      if (
        event.type === "content_block_delta" &&
        event.delta.type === "text_delta"
      ) {
        res.write(`data: ${JSON.stringify({ text: event.delta.text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (error) {
    let message = "Something went wrong. Please try again.";
    let status = 500;
    if (error instanceof Anthropic.AuthenticationError) { message = "Invalid API key. Set ANTHROPIC_API_KEY."; status = 401; }
    else if (error instanceof Anthropic.RateLimitError) { message = "Rate limited. Please try again shortly."; status = 429; }

    if (res.headersSent) {
      res.write(`data: ${JSON.stringify({ error: message })}\n\n`);
      res.end();
    } else {
      res.status(status).json({ error: message });
    }
  }
});

// 404 handler for API routes
app.use("/api/*path", (req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

// Global error handler — returns JSON for API routes so clients never see HTML error pages
app.use((err, req, res, next) => {
  console.error(err);
  if (req.path.startsWith("/api/")) {
    res.status(500).json({ error: "Internal server error." });
  } else {
    res.status(500).send("Internal server error.");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`LinkedIn Response Generator running at http://localhost:${PORT}`);
});
