// Shared helpers for the Pages Functions: Access JWT verification + Cloudflare API client.
// Env (Pages project settings): CF_ACCOUNT_ID, CF_API_TOKEN (secret), ACCESS_AUD, TEAM_DOMAIN, ADMINS,
// PASSPHRASES (secret JSON {url: pass}), EXTRA_ALLOW (JSON {url: [emails|@domains]}).

const b64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0));

export async function verifyJwt(token, teamDomain, aud) {
  const [h, p, sig] = (token || '').split('.');
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

export async function identify(request, env) {
  const token = request.headers.get('Cf-Access-Jwt-Assertion') || '';
  const email = (await verifyJwt(token, env.TEAM_DOMAIN, env.ACCESS_AUD)).email?.toLowerCase();
  if (!email) throw new Error('no email');
  const admins = (env.ADMINS || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
  return { email, isAdmin: admins.includes(email), admins };
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
}

export async function cfApi(env, method, path, body) {
  const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}${path}`, {
    method, headers: { Authorization: `Bearer ${env.CF_API_TOKEN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({ success: false, errors: [{ message: `HTTP ${r.status}` }] }));
  if (!j.success) throw new Error((j.errors || []).map(e => e.message).join('; ') || `HTTP ${r.status}`);
  return j.result;
}

let appCache = { at: 0, apps: [] };
export async function loadApps(env, fresh = false) {
  if (!fresh && Date.now() - appCache.at < 60000 && appCache.apps.length) return appCache.apps;
  const apps = [];
  for (let page = 1; page <= 10; page++) {
    const batch = (await cfApi(env, 'GET', `/access/apps?page=${page}&per_page=50`)) || [];
    apps.push(...batch);
    if (batch.length < 50) break;
  }
  appCache = { at: Date.now(), apps };
  return apps;
}
export function invalidateApps() { appCache = { at: 0, apps: [] }; }

export function ruleAllows(rule, email) {
  if (rule.email) return rule.email.email.toLowerCase() === email;
  if (rule.email_domain) return email.endsWith('@' + rule.email_domain.domain.toLowerCase());
  if (rule.everyone) return true;
  return false;
}
export function policyAllows(policy, email) {
  if (policy.decision !== 'allow') return false;
  if ((policy.exclude || []).some(r => ruleAllows(r, email))) return false;
  if ((policy.require || []).length && !(policy.require || []).every(r => ruleAllows(r, email))) return false;
  return (policy.include || []).some(r => ruleAllows(r, email));
}
export function appDomains(a) {
  return (a.self_hosted_domains && a.self_hosted_domains.length ? a.self_hosted_domains : [a.domain]).filter(Boolean);
}
export function matchApp(apps, url) {
  let u; try { u = new URL(url); } catch (e) { return null; }
  const host = u.host.toLowerCase(), path = u.pathname.replace(/\/+$/, '') || '/';
  let best = null, bestLen = -1;
  for (const a of apps) {
    for (const d of appDomains(a)) {
      const [dh, ...rest] = d.toLowerCase().split('/');
      const dp = '/' + rest.join('/').replace(/\/+$/, '');
      const hostOk = dh === host || (dh.startsWith('*.') && host.endsWith(dh.slice(1)));
      const pathOk = dp === '/' || path === dp || path.startsWith(dp + '/');
      if (hostOk && pathOk && dp.length > bestLen) { best = a; bestLen = dp.length; }
    }
  }
  return best;
}
export function extraAllows(list, email) {
  return (list || []).some(x => x.startsWith('@') ? email.endsWith(x.toLowerCase()) : x.toLowerCase() === email);
}

// ---- landing settings (hidden cards etc.) stored as the plain-text env var LANDING_SETTINGS on the Pages project.
// Read live via the API (not from env, which is frozen at deploy time) so admin changes apply at once.
let settingsCache = { at: 0, data: null };
const projectName = env => env.PAGES_PROJECT || 'thoroddsen';
export async function loadSettings(env, fresh = false) {
  if (!fresh && settingsCache.data && Date.now() - settingsCache.at < 5000) return settingsCache.data;
  let data = { hidden: [] };
  try {
    const p = await cfApi(env, 'GET', `/pages/projects/${projectName(env)}`);
    const v = p?.deployment_configs?.production?.env_vars?.LANDING_SETTINGS?.value;
    if (v) data = { hidden: [], ...JSON.parse(v) };
  } catch (e) { /* keep defaults */ }
  settingsCache = { at: Date.now(), data };
  return data;
}
export async function saveSettings(env, data) {
  const v = { value: JSON.stringify(data), type: 'plain_text' };
  await cfApi(env, 'PATCH', `/pages/projects/${projectName(env)}`, { deployment_configs: { production: { env_vars: { LANDING_SETTINGS: v } }, preview: { env_vars: { LANDING_SETTINGS: v } } } });
  settingsCache = { at: Date.now(), data };
  return data;
}
