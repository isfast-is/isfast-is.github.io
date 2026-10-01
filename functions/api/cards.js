// Pages Function: returns only the cards the logged-in user may open.
// Identity comes from the Cloudflare Access JWT (verified against the team's public keys).
// Visibility comes from the Access policies themselves (read live via the API, cached 60 s)
// plus EXTRA_ALLOW for links that are not behind Access (Apps Script dashboards etc.).
// Env (Pages project settings): CF_ACCOUNT_ID, CF_API_TOKEN (secret), ACCESS_AUD, TEAM_DOMAIN,
// PASSPHRASES (secret JSON {url: pass}), EXTRA_ALLOW (JSON {url: [emails|@domains]}), ADMINS (comma list).

const b64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0));

async function verifyJwt(token, teamDomain, aud) {
  const [h, p, sig] = token.split('.');
  if (!h || !p || !sig) throw new Error('bad jwt');
  const header = JSON.parse(new TextDecoder().decode(b64url(h)));
  const payload = JSON.parse(new TextDecoder().decode(b64url(p)));
  const certs = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`, { cf: { cacheTtl: 3600 } }).then(r => r.json());
  const jwk = (certs.keys || []).find(k => k.kid === header.kid);
  if (!jwk) throw new Error('unknown kid');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64url(sig), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) throw new Error('bad signature');
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('expired');
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (aud && !auds.includes(aud)) throw new Error('wrong aud');
  return payload;
}

let appCache = { at: 0, apps: [] };
async function loadApps(env) {
  if (Date.now() - appCache.at < 60000 && appCache.apps.length) return appCache.apps;
  const apps = [];
  for (let page = 1; page <= 5; page++) {
    const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/access/apps?page=${page}`,
      { headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` } }).then(r => r.json());
    const batch = r.result || [];
    apps.push(...batch);
    if (batch.length < 10) break;
  }
  appCache = { at: Date.now(), apps };
  return apps;
}

function ruleAllows(rule, email) {
  if (rule.email) return rule.email.email.toLowerCase() === email;
  if (rule.email_domain) return email.endsWith('@' + rule.email_domain.domain.toLowerCase());
  if (rule.everyone) return true;
  return false;
}
function policyAllows(policy, email) {
  if (policy.decision !== 'allow') return false;
  if ((policy.exclude || []).some(r => ruleAllows(r, email))) return false;
  if ((policy.require || []).length && !(policy.require || []).every(r => ruleAllows(r, email))) return false;
  return (policy.include || []).some(r => ruleAllows(r, email));
}
function matchApp(apps, url) {
  let u; try { u = new URL(url); } catch (e) { return null; }
  const host = u.host.toLowerCase(), path = u.pathname.replace(/\/+$/, '') || '/';
  let best = null, bestLen = -1;
  for (const a of apps) {
    for (const d of (a.self_hosted_domains && a.self_hosted_domains.length ? a.self_hosted_domains : [a.domain])) {
      const [dh, ...rest] = d.toLowerCase().split('/');
      const dp = '/' + rest.join('/').replace(/\/+$/, '');
      const hostOk = dh === host || (dh.startsWith('*.') && host.endsWith(dh.slice(1)));
      const pathOk = dp === '/' || path === dp || path.startsWith(dp + '/');
      if (hostOk && pathOk && dp.length > bestLen) { best = a; bestLen = dp.length; }
    }
  }
  return best;
}
function extraAllows(list, email) {
  return (list || []).some(x => x.startsWith('@') ? email.endsWith(x.toLowerCase()) : x.toLowerCase() === email);
}

export async function onRequestGet({ request, env }) {
  const token = request.headers.get('Cf-Access-Jwt-Assertion') || '';
  let email;
  try { email = (await verifyJwt(token, env.TEAM_DOMAIN, env.ACCESS_AUD)).email?.toLowerCase(); }
  catch (e) { return new Response(JSON.stringify({ error: 'unauthenticated' }), { status: 401, headers: { 'content-type': 'application/json' } }); }
  if (!email) return new Response(JSON.stringify({ error: 'no email' }), { status: 401 });

  const admins = (env.ADMINS || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
  const asParam = new URL(request.url).searchParams.get('as');
  const viewer = (asParam && admins.includes(email)) ? asParam.toLowerCase() : email;

  const [apps, cards] = await Promise.all([loadApps(env), env.ASSETS.fetch(new URL('/cards.json', request.url)).then(r => r.json())]);
  const passes = env.PASSPHRASES ? JSON.parse(env.PASSPHRASES) : {};
  const extra = env.EXTRA_ALLOW ? JSON.parse(env.EXTRA_ALLOW) : {};

  const out = { updated: cards.updated, viewer, email, isAdmin: admins.includes(email), sections: [] };
  for (const s of cards.sections) {
    const links = [];
    for (const l of s.links) {
      const app = matchApp(apps, l.url);
      let allowed;
      if (app) allowed = (app.policies || []).some(p => policyAllows(p, viewer));
      else if (extra[l.url]) allowed = extraAllows(extra[l.url], viewer);
      else allowed = true; // open links with no rule
      if (!allowed) continue;
      const c = { ...l };
      if (passes[l.url]) c.pass = passes[l.url];
      links.push(c);
    }
    if (links.length) out.sections.push({ title: s.title, emoji: s.emoji, links });
  }
  return new Response(JSON.stringify(out), { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
}
