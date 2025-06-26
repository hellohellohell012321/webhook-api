export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  const { content } = req.body;

  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  if (!content || !webhookUrl) {
    return res.status(400).json({ message: 'Missing content or webhook URL' });
  }

  try {
    const discordRes = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });

    if (!discordRes.ok) throw new Error('Failed to send Discord message');

    res.status(200).json({ message: 'Message sent to Discord' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
}
