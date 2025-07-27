import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import crypto from "crypto";

// Setup Redis rate limiter
const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(1, "60 s"),
  analytics: true,
});

// Get client IP
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded?.split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip || 'unknown';
}

// Verify signature
function verifySignature(hwid, timestamp, signature, secret) {
  const raw = hwid + timestamp + secret;
  const expected = crypto.createHash("sha256").update(raw).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Client-Key");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ message: "Method not allowed" });

  const clientIP = getClientIP(req);
  const expectedClientKey = process.env.CLIENT_KEY;
  const sharedSecret = process.env.SHARED_SECRET;

  const providedKey = req.headers["x-client-key"];
  if (!providedKey || providedKey !== expectedClientKey) {
    return res.status(403).json({ message: "Forbidden - invalid client key" });
  }

  const body = req.body;

  if (!body || typeof body !== "object") {
    return res.status(400).json({ message: "Invalid body" });
  }

  const { userId, username, hwid, timestamp, signature, content } = body;

  if (
    !userId || !username || !hwid || !timestamp || !signature || !content ||
    typeof userId !== "number" || typeof username !== "string"
  ) {
    return res.status(400).json({ message: "Missing or invalid fields" });
  }

  // Check timestamp freshness
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(timestamp - now) > 30) {
    return res.status(400).json({ message: "Timestamp out of sync" });
  }

  // Check signature
  if (!verifySignature(hwid, timestamp.toString(), signature, sharedSecret)) {
    return res.status(401).json({ message: "Invalid signature" });
  }

  // Rate limit by HWID + IP
  const identifier = `ip:${clientIP}:hwid:${hwid}`;
  const { success, reset, remaining, limit } = await ratelimit.limit(identifier);
  if (!success) {
    return res.status(429).json({
      message: "Rate limit exceeded",
      resetTime: new Date(reset),
      retryAfter: Math.round((reset - Date.now()) / 1000),
      limit,
      remaining
    });
  }

  // Forward to Discord
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return res.status(500).json({ message: "Webhook not configured" });

  const payload = {
    content: `[${username} | ${userId}] ${content}`
  };

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "Roblox-Webhook-Relay"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errText = await response.text();
      return res.status(500).json({ message: "Discord error", details: errText });
    }

    return res.status(200).json({ message: "Sent successfully", remaining, reset: new Date(reset) });
  } catch (err) {
    return res.status(500).json({ message: "Error forwarding to Discord", error: err.message });
  }
}
