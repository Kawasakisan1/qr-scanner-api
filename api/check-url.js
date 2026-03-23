export default async function handler(req, res) {
  // 1. Configurar CORS para permitir que tu sitio de InfinityFree consulte esta API
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*'); // Permite peticiones de cualquier sitio
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Manejar la petición "preflight" de los navegadores
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

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
    
    // Si hay 'matches', es que Google encontró una amenaza (No es seguro)
    res.status(200).json({ isSafe: data.matches ? false : true });
  } catch (error) {
    res.status(500).json({ isSafe: null, error: error.message });
  }
}
