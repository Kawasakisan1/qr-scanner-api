export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST required' });
  
  const { urlToCheck } = req.body;
  const API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;
  const apiEndpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

  const requestBody = {
    client: { clientId: "qr-secure", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: urlToCheck }]
    }
  };

  try {
    const response = await fetch(apiEndpoint, {
      method: 'POST',
      body: JSON.stringify(requestBody),
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await response.json();
    res.status(200).json({ isSafe: data.matches ? false : true });
  } catch (error) {
    res.status(500).json({ isSafe: null });
  }
}
