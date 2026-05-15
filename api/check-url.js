const tls = require('tls');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const urlParam = req.query.url || (req.body && req.body.url);
  if (!urlParam) return res.status(400).json({ error: 'URL krävs' });

  let urlStr = String(urlParam).trim();
  if (!/^https?:\/\//i.test(urlStr)) urlStr = 'https://' + urlStr;

  let parsed;
  try { parsed = new URL(urlStr); }
  catch { return res.status(400).json({ error: 'Ogiltig URL' }); }

  const blockedHost = /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|localhost$|0\.0\.0\.0|169\.254\.)/i;
  if (blockedHost.test(parsed.hostname)) {
    return res.status(400).json({ error: 'Privata/lokala adresser är blockerade' });
  }

  const port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);

  const result = {
    input: parsed.href,
    hostname: parsed.hostname,
    protocol: parsed.protocol.replace(':', ''),
    port,
    timestamp: new Date().toISOString(),
  };

  const [headersRes, certRes, whoisRes] = await Promise.allSettled([
    fetchHeaders(parsed.href),
    parsed.protocol === 'https:' ? getCertInfo(parsed.hostname, port) : Promise.resolve(null),
    getDomainAge(parsed.hostname),
  ]);

  result.fetch = headersRes.status === 'fulfilled' ? headersRes.value : { error: String(headersRes.reason && headersRes.reason.message || headersRes.reason) };
  result.cert = certRes.status === 'fulfilled' ? certRes.value : { error: String(certRes.reason && certRes.reason.message || certRes.reason) };
  result.whois = whoisRes.status === 'fulfilled' ? whoisRes.value : { error: 'whois-uppslag misslyckades' };
  result.typosquat = checkTyposquat(parsed.hostname);

  res.status(200).json(result);
};

async function fetchHeaders(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'Sakerkoll/1.0 (+https://sakerkoll.vercel.app)' },
    });
    return {
      status: response.status,
      finalUrl: response.url,
      redirected: response.redirected,
      hsts: response.headers.get('strict-transport-security'),
      csp: response.headers.get('content-security-policy'),
      xFrame: response.headers.get('x-frame-options'),
      xContent: response.headers.get('x-content-type-options'),
      referrer: response.headers.get('referrer-policy'),
      permissions: response.headers.get('permissions-policy'),
      server: response.headers.get('server'),
      poweredBy: response.headers.get('x-powered-by'),
    };
  } finally {
    clearTimeout(timer);
  }
}

function getCertInfo(host, port) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (v, isError) => {
      if (settled) return;
      settled = true;
      try { socket.end(); } catch {}
      isError ? reject(v) : resolve(v);
    };
    const socket = tls.connect({
      host, port, servername: host,
      rejectUnauthorized: false,
      timeout: 6000,
    }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const daysLeft = cert.valid_to
        ? Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000)
        : null;
      done({
        valid: authorized,
        authError: authError ? String(authError) : null,
        protocol,
        cipher: cipher ? cipher.name : null,
        subject: (cert.subject && cert.subject.CN) || null,
        issuer: (cert.issuer && cert.issuer.CN) || null,
        validFrom: cert.valid_from || null,
        validTo: cert.valid_to || null,
        daysLeft,
        san: cert.subjectaltname || null,
      }, false);
    });
    socket.on('error', (e) => done(e, true));
    socket.on('timeout', () => { try { socket.destroy(); } catch {} done(new Error('timeout'), true); });
  });
}

async function getDomainAge(hostname) {
  const apex = getApexDomain(hostname);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const response = await fetch(`https://rdap.org/domain/${apex}`, {
      signal: controller.signal,
      headers: { 'Accept': 'application/rdap+json' },
    });
    if (!response.ok) return { apex, error: `rdap ${response.status}` };
    const data = await response.json();
    const events = Array.isArray(data.events) ? data.events : [];
    const reg = events.find(e => e.eventAction === 'registration');
    const exp = events.find(e => e.eventAction === 'expiration');
    const updated = events.find(e => e.eventAction === 'last changed' || e.eventAction === 'last update of RDAP database');
    const regDate = reg && reg.eventDate ? new Date(reg.eventDate) : null;
    const ageDays = regDate ? Math.floor((Date.now() - regDate.getTime()) / 86400000) : null;
    return {
      apex,
      registered: regDate ? regDate.toISOString().slice(0, 10) : null,
      expires: exp && exp.eventDate ? exp.eventDate.slice(0, 10) : null,
      updated: updated && updated.eventDate ? updated.eventDate.slice(0, 10) : null,
      ageDays,
      ageYears: ageDays != null ? (ageDays / 365).toFixed(1) : null,
      registrar: data.entities && data.entities.find(e => Array.isArray(e.roles) && e.roles.includes('registrar'))?.vcardArray?.[1]?.find(x => x[0] === 'fn')?.[3] || null,
    };
  } finally {
    clearTimeout(timer);
  }
}

function getApexDomain(host) {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const twoPartTlds = new Set(['co.uk','com.au','co.jp','com.br','co.nz','co.za','com.sg','co.in']);
  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTlds.has(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

function checkTyposquat(hostname) {
  const hasPunycode = hostname.includes('xn--');
  const hasMixedScripts = /[\u0400-\u04FF\u0370-\u03FF\u0530-\u058F\u0600-\u06FF]/.test(hostname);
  const excessiveSubdomains = hostname.split('.').length > 4;

  const commonDomains = [
    'google.com','facebook.com','instagram.com','amazon.com','paypal.com',
    'microsoft.com','apple.com','netflix.com','spotify.com','twitter.com','x.com',
    'youtube.com','linkedin.com','github.com','discord.com','whatsapp.com',
    'swedbank.se','nordea.se','handelsbanken.se','seb.se','skatteverket.se',
    'bankid.com','klarna.com','blocket.se','tradera.se','ica.se','coop.se',
    'postnord.se','svt.se','aftonbladet.se','dn.se','expressen.se','1177.se',
    'forsakringskassan.se','arbetsformedlingen.se','csn.se'
  ];

  const apex = getApexDomain(hostname);
  const similar = [];
  for (const d of commonDomains) {
    if (d === apex) continue;
    const dist = levenshtein(apex, d);
    if (dist > 0 && dist <= 2) similar.push({ target: d, distance: dist });
  }

  return { apex, hasPunycode, hasMixedScripts, excessiveSubdomains, similarTo: similar.slice(0, 5) };
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}
