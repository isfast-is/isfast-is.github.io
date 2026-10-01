# isfast-is.github.io → isfast.pages.dev

Lendingarsíða Ísfast-teymisins, hýst á Cloudflare Pages á bak við Cloudflare Access.

- `index.html` – síðan. Sækir `/api/cards` og birtir aðeins spjöld sem innskráður notandi hefur aðgang að.
- `functions/api/cards.js` – Pages Function. Staðfestir Access-JWT notandans, les Access-reglurnar
  gegnum Cloudflare API (vistað í 60 s) og síar `cards.json` eftir þeim. Aðgangsorð og aukareglur
  fyrir síður utan Access koma úr umhverfisbreytum verkefnisins, aldrei úr repóinu.
- `cards.json` – nöfn, lýsingar og slóðir spjaldanna (ekkert trúnaðarefni).
- `projects.json`, `.passphrases.json` – staðbundið, gitignored.

Stjórnandi (ADMINS) getur skoðað síðuna „eins og“ annar notandi með `?as=netfang`.
