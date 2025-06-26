import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Create a rate limiter that allows 1 request per 60 seconds
const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(1, "1 s"),
  analytics: true, // Optional: enable analytics
});

// Helper function to get client IP
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['x-real-ip'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         'unknown';
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  // Get client IP for rate limiting
  const clientIP = getClientIP(req);
  const identifier = `webhook:${clientIP}`;
  
  try {
    // Check rate limit
    const { success, limit, reset, remaining } = await ratelimit.limit(identifier);
    
    if (!success) {
      return res.status(429).json({ 
        message: 'Rate limit exceeded. Please wait before sending another message.',
        limit,
        remaining,
        resetTime: new Date(reset),
        retryAfter: Math.round((reset - Date.now()) / 1000)
      });
    }

    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookUrl) {
      return res.status(500).json({ message: 'Webhook URL not configured' });
    }

    const body = req.body;
    
    // Basic validation
    if (!body.content && !body.embeds?.length) {
      return res.status(400).json({ message: 'Message content is required' });
    }
    
    if (body.content && body.content.length > 2000) {
      return res.status(400).json({ message: 'Message too long (max 2000 characters)' });
    }
    
    // Forward to Discord
    const discordResponse = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!discordResponse.ok) {
      const text = await discordResponse.text();
      return res.status(500).json({ message: 'Discord webhook failed', details: text });
    }

    return res.status(200).json({ 
      message: 'Message sent to Discord',
      rateLimit: {
        limit,
        remaining: remaining - 1,
        resetTime: new Date(reset)
      }
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}
