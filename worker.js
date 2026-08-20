/* ═══════════════════════════════════════════════════════════
   AgriMap — Proxy OAuth Sentinel Hub (Cloudflare Worker)
   Les credentials sont stockés en variables d'environnement :
   SH_CLIENT_ID et SH_CLIENT_SECRET (jamais dans le code)
   ═══════════════════════════════════════════════════════════ */

const ALLOWED_ORIGINS = [
  'https://yabou33.github.io',
  'http://localhost:5500',      // Live Server local (optionnel)
  'http://127.0.0.1:5500'
];

// Cache du token en mémoire (partagé entre requêtes du même isolate)
let cachedToken = null;
let tokenExpiry = 0;

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

    const corsHeaders = {
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin'
    };

    // Préflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: corsHeaders });
    }

    // Refuser les origines inconnues
    if (!ALLOWED_ORIGINS.includes(origin)) {
      return new Response(JSON.stringify({ error: 'Origin non autorisée' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    try {
      // Token encore valide en cache → on le renvoie directement
      if (cachedToken && Date.now() < tokenExpiry) {
        return new Response(JSON.stringify({
          access_token: cachedToken,
          expires_in: Math.floor((tokenExpiry - Date.now()) / 1000)
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Sinon, on demande un nouveau token à Sentinel Hub
      const r = await fetch('https://services.sentinel-hub.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: env.SH_CLIENT_ID,
          client_secret: env.SH_CLIENT_SECRET
        })
      });

      if (!r.ok) {
        const txt = await r.text();
        return new Response(JSON.stringify({ error: 'Auth Sentinel Hub échouée', status: r.status, detail: txt }), {
          status: 502,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      const d = await r.json();
      cachedToken = d.access_token;
      tokenExpiry = Date.now() + (d.expires_in - 120) * 1000; // marge de 2 min

      return new Response(JSON.stringify({
        access_token: d.access_token,
        expires_in: d.expires_in
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });

    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  }
};
