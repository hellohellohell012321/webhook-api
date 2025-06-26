export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'kys' });
  }

  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  if (!webhookUrl) {
    return res.status(500).json({ message: 'Webhook URL not configured' });
  }

  try {
    // Receive full body including content, embeds, etc.
    const body = req.body;

    // Forward exactly what was received to Discord
    const discordResponse = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!discordResponse.ok) {
      const text = await discordResponse.text();
      return res.status(500).json({ message: 'Discord webhook failed', details: text });
    }

    return res.status(200).json({ message: 'Message sent to Discord' });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
}
