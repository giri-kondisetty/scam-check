const URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"')\]]+|(?:[a-z0-9-]+\.)+(?:[a-z]{2,24})(?:\/[^\s<>"')\]]*)?)/gi;

const BARE_TLDS = new Set([
  'com', 'net', 'org', 'info', 'biz', 'co', 'io', 'me', 'app', 'xyz', 'top', 'online', 'site', 'shop',
  'club', 'live', 'vip', 'icu', 'link', 'click', 'cc', 'ly', 'gd', 'uk', 'us', 'in', 'au', 'ca', 'de',
  'fr', 'es', 'it', 'nl', 'br', 'mx', 'jp', 'cn', 'ru', 'ph', 'sg', 'my', 'id', 'ng', 'za', 'nz', 'gov', 'edu',
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'ow.ly', 'rb.gy', 'rebrand.ly',
  'shorturl.at', 'tiny.cc', 's.id', 'buff.ly', 't.ly', 'lnkd.in',
]);

const TWO_LEVEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au', 'gov.au', 'co.in', 'gov.in',
  'co.nz', 'co.za', 'com.br', 'com.mx', 'co.jp', 'com.sg', 'com.ph', 'com.my', 'co.id', 'com.ng',
]);

const BRANDS = {
  paypal: ['paypal.com'],
  amazon: ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.ca', 'amazon.com.au'],
  apple: ['apple.com', 'icloud.com'],
  icloud: ['icloud.com', 'apple.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com'],
  usps: ['usps.com'],
  fedex: ['fedex.com'],
  dhl: ['dhl.com', 'dhl.de'],
  royalmail: ['royalmail.com'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com'],
  hsbc: ['hsbc.com', 'hsbc.co.uk'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com'],
};

export function registrableDomain(host) {
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const lastTwo = labels.slice(-2).join('.');
  return TWO_LEVEL_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

export function refang(text) {
  return text
    .replace(/\s*[\[({]\s*(?:\.|dot)\s*[\])}]\s*/gi, '.')
    .replace(/\bh(?:xx|\*\*)p(s?)(?=:|\[)/gi, 'http$1')
    .replace(/\[:\]/g, ':')
    .replace(/\[\/\]/g, '/');
}

export function extractLinks(input) {
  const text = refang(input);
  const links = [];
  const seen = new Set();
  for (const match of text.matchAll(URL_RE)) {
    let raw = match[0].replace(/[.,;:!?]+$/, '');
    const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
    let url;
    try {
      url = new URL(withScheme);
    } catch {
      continue;
    }
    const host = url.hostname.toLowerCase().replace(/^www\./, '');
    const named = /^(https?:\/\/|www\.)/i.test(raw);
    if (!named && !BARE_TLDS.has(host.split('.').pop())) continue;
    if (!host.includes('.') || seen.has(host + url.pathname)) continue;
    seen.add(host + url.pathname);
    links.push({ raw, host, url, explicitScheme: /^https?:\/\//i.test(raw) });
  }
  return links;
}

export function linkSignals(link) {
  const found = [];
  const { host, url, raw, explicitScheme } = link;
  const add = (id, weight, title, detail) => found.push({ id, weight, title, detail, link: raw });

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    add('ip-address', 3, 'The link goes to a bare number address', 'Real organisations use a name, not a raw address like 192.0.2.1.');
  }
  if (host.split('.').some((l) => l.startsWith('xn--')) || /[^\x00-\x7f]/.test(raw)) {
    add('lookalike-characters', 3, 'The link uses look-alike characters', 'Letters from other alphabets are used to imitate a real site name.');
  }
  if (url.username || /@/.test(url.href.split('/')[2] || '')) {
    add('hidden-destination', 3, 'The link hides where it really goes', 'Everything before an @ in a link is ignored; the real site comes after it.');
  }
  if (SHORTENERS.has(host)) {
    add('shortened', 1, 'The link is shortened', 'A shortened link hides the real site until you open it.');
  }
  if (explicitScheme && url.protocol === 'http:') {
    add('not-encrypted', 1, 'The link is not encrypted', 'Sites that handle logins or payments use https.');
  }
  const registrable = registrableDomain(host);
  const compact = host.replace(/[-.]/g, '');
  for (const [brand, official] of Object.entries(BRANDS)) {
    if (compact.includes(brand) && !official.includes(registrable)) {
      add('impersonates-brand', 3, `The link imitates ${brand}`, `It contains "${brand}" but the site is really ${registrable}.`);
      break;
    }
  }
  if ((host.match(/-/g) || []).length >= 3 || host.split('.').length >= 5) {
    add('odd-address', 1, 'The link has an unusual address', 'Long addresses with many dashes or dots are common on fake sites.');
  }
  return found;
}
