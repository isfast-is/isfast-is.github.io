# isfast-is.github.io → isfast.pages.dev

Lendingarsíða Ísfast-teymisins, hýst á Cloudflare Pages á bak við Cloudflare Access
(Google-innskráning fyrir @isfast.is, annars netfang + kóði í pósti).

- `index.html` – síðan. Sækir `/api/cards` og birtir aðeins spjöld sem innskráður notandi hefur
  aðgang að. Stjórnendur (ADMINS) fá flipann **Aðgangsstýring**: eftir síðu (merki fyrir hvern
  aðila, vistast strax) og eftir aðila (gátlisti + Vista), Birta-hak, Opna/Læsa, Afrita boð.
- `functions/api/cards.js` – staðfestir Access-JWT, les Access-reglurnar gegnum API (60 s), síar
  `cards.json`. Spjöld utan Access: EXTRA_ALLOW (JSON url→[netföng]) eða `open:true`, annars
  aðeins stjórnendur.
- `functions/api/admin/access.js` – stjórnendaaðgerðir: set/lock/unlock/visibility.
- `lib/access.js` – sameiginlegur kóði (sami og á gunnar-star.github.io).
- `cards.json` – nöfn, lýsingar, slóðir (ekkert trúnaðarefni). `projects.json`/`.passphrases.json` staðbundið.

Pages-breytur (verkefni `isfast`): CF_ACCOUNT_ID, CF_API_TOKEN (secret), ACCESS_AUD, TEAM_DOMAIN,
ADMINS, PASSPHRASES (secret), EXTRA_ALLOW, PAGES_PROJECT=isfast, LANDING_SETTINGS (falin spjöld).
