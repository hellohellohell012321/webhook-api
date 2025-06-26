import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// Create a rate limiter that allows 1 request per 60 seconds
const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(1, "60 s"), // Fixed: was "1 s"
  analytics: true,
});

// Helper function to get client IP
function getClientIP(req) {
  // Handle both comma-separated and single IP cases
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  
  return req.headers['x-real-ip'] || 
         req.connection?.remoteAddress || 
         req.socket?.remoteAddress ||
         req.ip ||
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

    // Check for webhook URL
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookUrl) {
      console.error('DISCORD_WEBHOOK_URL environment variable not set');
      return res.status(500).json({ message: 'Webhook URL not configured' });
    }

    const body = req.body;
    
    // Enhanced validation
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ message: 'Invalid request body' });
    }
    
    if (!body.content && !body.embeds?.length) {
      return res.status(400).json({ message: 'Message content or embeds required' });
    }
    
    if (body.content && body.content.length > 2000) {
      return res.status(400).json({ message: 'Message too long (max 2000 characters)' });
    }

    // Validate embeds if present
    if (body.embeds) {
      if (!Array.isArray(body.embeds)) {
        return res.status(400).json({ message: 'Embeds must be an array' });
      }
      if (body.embeds.length > 10) {
        return res.status(400).json({ message: 'Too many embeds (max 10)' });
      }
    }
    
    // Log the attempt (helpful for debugging)
    console.log(`Sending webhook from IP: ${clientIP}`);
    
    // Forward to Discord with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    try {
      const discordResponse = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'User-Agent': 'Discord-Webhook-Proxy'
        },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (!discordResponse.ok) {
        const errorText = await discordResponse.text();
        console.error('Discord webhook error:', {
          status: discordResponse.status,
          statusText: discordResponse.statusText,
          body: errorText
        });
        
        return res.status(discordResponse.status).json({ 
          message: 'Discord webhook failed', 
          details: errorText,
          status: discordResponse.status
        });
      }

      // Success response
      return res.status(200).json({ 
        message: 'Message sent to Discord successfully',
        rateLimit: {
          limit,
          remaining: remaining - 1,
          resetTime: new Date(reset)
        }
      });
      
    } catch (fetchError) {
      clearTimeout(timeoutId);
      
      if (fetchError.name === 'AbortError') {
        return res.status(408).json({ message: 'Request timeout - Discord webhook took too long' });
      }
      
      throw fetchError; // Re-throw to be caught by outer catch
    }
    
  } catch (error) {
    console.error('Webhook handler error:', error);
    
    // Don't expose internal error details in production
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    return res.status(500).json({ 
      message: 'Internal server error',
      ...(isDevelopment && { details: error.message })
    });
  }
}
