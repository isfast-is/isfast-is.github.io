// GET /api/cards[?as=email] — the cards the logged-in user may open (admins can view as someone else).
import { identify, json, loadApps, policyAllows, matchApp, extraAllows, loadSettings } from '../../lib/access.js';

export async function onRequestGet({ request, env }) {
  let who;
  try { who = await identify(request, env); } catch (e) { return json({ error: 'unauthenticated' }, 401); }
  const asParam = new URL(request.url).searchParams.get('as');
  const viewer = (asParam && who.isAdmin) ? asParam.toLowerCase() : who.email;

  const [apps, cards, settings] = await Promise.all([loadApps(env), env.ASSETS.fetch(new URL('/cards.json', request.url)).then(r => r.json()), loadSettings(env, new URL(request.url).searchParams.has('fresh'))]);
  const hidden = new Set(settings.hidden || []);
  const passes = env.PASSPHRASES ? JSON.parse(env.PASSPHRASES) : {};
  const extra = env.EXTRA_ALLOW ? JSON.parse(env.EXTRA_ALLOW) : {};

  const out = { updated: cards.updated, viewer, email: who.email, isAdmin: who.isAdmin, sections: [] };
  for (const s of cards.sections) {
    const links = [];
    for (const l of s.links) {
      if (hidden.has(l.url)) continue; // hidden by the admin (Birta-hak)
      const app = matchApp(apps, l.url);
      let allowed, gate;
      if (app) { allowed = (app.policies || []).some(p => policyAllows(p, viewer)); gate = 'access'; }
      else if (extra[l.url]) { allowed = extraAllows(extra[l.url], viewer); gate = 'list'; }
      else if (l.open) { allowed = true; gate = 'open'; }
      else { allowed = who.isAdmin; gate = 'admin'; } // links outside Access (Apps Script, Tailscale, other accounts): owner only
      if (!allowed) continue;
      const c = { ...l, gate };
      if (passes[l.url]) c.pass = passes[l.url];
      links.push(c);
    }
    if (links.length) out.sections.push({ title: s.title, emoji: s.emoji, links });
  }
  return json(out);
}
