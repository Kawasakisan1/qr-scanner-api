export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST required' });
  
  const { urlToCheck } = req.body;
  const API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;
  const apiEndpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

  const requestBody = {
    client: { clientId: "qr-secure", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
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
    
    // Si hay matches, enviamos el primer tipo de amenaza encontrado
    if (data.matches && data.matches.length > 0) {
      res.status(200).json({ isSafe: false, type: data.matches[0].threatType });
    } else {
      res.status(200).json({ isSafe: true });
    }
  } catch (error) {
    res.status(500).json({ isSafe: null });
  }
}
