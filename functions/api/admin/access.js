// Admin-only access management. Source of truth = the Cloudflare Access policies themselves.
//   GET  /api/admin/access            -> { sites:[{appId, name, domains, policyId, include:[...]}], people:[...], cards:[...] }
//   POST /api/admin/access            -> { action:'set', appId, include:[ 'a@b.is' | '@domain.is', ... ] }
//                                        { action:'lock', url, name, include:[...] }   (create an Access app for an open site)
//                                        { action:'unlock', appId }                    (delete the app -> site becomes open)
// Every call is checked against the Access JWT; only ADMINS get through. The owner (first ADMINS entry)
// is always kept in every include list so nobody can lock the admin out.
import { identify, json, cfApi, loadApps, invalidateApps, appDomains, loadSettings, saveSettings } from '../../../lib/access.js';

const ownerOf = who => who.admins[0];
const toRule = v => v.startsWith('@') ? { email_domain: { domain: v.slice(1) } } : { email: { email: v } };
const fromRule = r => r.email ? r.email.email.toLowerCase() : r.email_domain ? '@' + r.email_domain.domain.toLowerCase() : r.everyone ? '*' : null;
const clean = (list, owner) => {
  const out = [owner];
  for (const raw of list || []) {
    const v = String(raw).trim().toLowerCase();
    if (!v || out.includes(v)) continue;
    if (/^@[a-z0-9.-]+\.[a-z]{2,}$/.test(v) || /^[^@\s]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(v)) out.push(v);
  }
  return out;
};

async function snapshot(request, env) {
  const apps = await loadApps(env, true);
  const sites = apps.map(a => {
    const pol = (a.policies || [])[0];
    return { appId: a.id, name: a.name, domains: appDomains(a), aud: a.aud, policyId: pol ? pol.id : null,
      include: pol ? (pol.include || []).map(fromRule).filter(Boolean) : [], policyCount: (a.policies || []).length };
  }).sort((x, y) => x.name.localeCompare(y.name, 'is'));
  const people = [...new Set(sites.flatMap(s => s.include))].sort();
  const cards = await env.ASSETS.fetch(new URL('/cards.json', request.url)).then(r => r.json());
  const flat = cards.sections.flatMap(s => s.links.map(l => ({ name: l.name, url: l.url, section: s.title, ext: l.ext || null })));
  const settings = await loadSettings(env, true);
  return { sites, people, cards: flat, hidden: settings.hidden || [] };
}

export async function onRequestGet({ request, env }) {
  let who;
  try { who = await identify(request, env); } catch (e) { return json({ error: 'unauthenticated' }, 401); }
  if (!who.isAdmin) return json({ error: 'forbidden' }, 403);
  try { return json(await snapshot(request, env)); } catch (e) { return json({ error: e.message }, 500); }
}

export async function onRequestPost({ request, env }) {
  let who;
  try { who = await identify(request, env); } catch (e) { return json({ error: 'unauthenticated' }, 401); }
  if (!who.isAdmin) return json({ error: 'forbidden' }, 403);
  let body; try { body = await request.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
  const owner = ownerOf(who);
  try {
    if (body.action === 'set') {
      const include = clean(body.include, owner).map(toRule);
      const apps = await loadApps(env, true);
      const app = apps.find(a => a.id === body.appId);
      if (!app) return json({ error: 'app not found' }, 404);
      const pol = (app.policies || [])[0];
      const payload = { name: 'Aðgangur', decision: 'allow', include, precedence: 1 };
      if (pol) await cfApi(env, 'PUT', `/access/apps/${app.id}/policies/${pol.id}`, payload);
      else await cfApi(env, 'POST', `/access/apps/${app.id}/policies`, payload);
    } else if (body.action === 'lock') {
      const u = new URL(body.url);
      const host = u.host.toLowerCase();
      const domains = [host];
      if (host.endsWith('.pages.dev')) domains.push('*.' + host);
      // Reuse the identity-provider setup of an existing app (the token has no IdP-read permission).
      const ref = (await loadApps(env)).find(x => (x.allowed_idps || []).length) || {};
      const idps = ref.allowed_idps || [];
      const app = await cfApi(env, 'POST', '/access/apps', {
        name: body.name || host, domain: host, type: 'self_hosted', self_hosted_domains: domains,
        session_duration: '720h', auto_redirect_to_identity: idps.length === 1, allowed_idps: idps, app_launcher_visible: false,
      });
      await cfApi(env, 'POST', `/access/apps/${app.id}/policies`, { name: 'Aðgangur', decision: 'allow', include: clean(body.include, owner).map(toRule), precedence: 1 });
    } else if (body.action === 'unlock') {
      const apps = await loadApps(env, true);
      const app = apps.find(a => a.id === body.appId);
      if (!app) return json({ error: 'app not found' }, 404);
      if (appDomains(app).some(d => d.split('/')[0] === new URL(request.url).host)) return json({ error: 'Ekki hægt að opna lendingarsíðuna sjálfa.' }, 400);
      await cfApi(env, 'DELETE', `/access/apps/${app.id}`);
    } else if (body.action === 'visibility') {
      const s = await loadSettings(env, true); const set = new Set(s.hidden || []);
      body.show ? set.delete(body.url) : set.add(body.url);
      await saveSettings(env, { ...s, hidden: [...set] });
      return json(await snapshot(request, env));
    } else return json({ error: 'unknown action' }, 400);
    invalidateApps();
    return json(await snapshot(request, env));
  } catch (e) { return json({ error: e.message }, 500); }
}
