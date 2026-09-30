# isfast-is.github.io

Lendingarsíða Ísfast-teymisins: allar verkefnasíður, mælaborð og kynningar á einum stað.

**Lifandi: https://isfast-is.github.io/** (læst með aðgangsorði teymisins)

## Hvernig þetta virkar

Kyrrstæð GitHub Pages-síða, ekkert byggingarskref. Listinn yfir síður er **dulkóðaður**:

- `index.html` – síðan. Biður um aðgangsorð einu sinni á hverju tæki (geymt í localStorage),
  afkóðar í vafranum (PBKDF2 → AES-256-GCM með WebCrypto) og teiknar spjöldin.
  „Læsa þessu tæki“ í fæti gleymir aðgangsorðinu.
- `projects.enc` – dulkóðaði listinn (eina gagnaskráin sem er birt)
- `encrypt.py` – dulkóðar aftur eftir breytingar
- `projects.json`, `.passphrase` – **aðeins staðbundið, gitignored** (vinnueintak á Mac mini:
  `~/repos/isfast-is.github.io/`)

## Að bæta við eða fjarlægja síðu

1. Breyta `projects.json` (sections → `links`: `{ "name", "desc", "url", "pass" | "login": true | "open": true }`)
2. `python3 encrypt.py`
3. Commit + push `projects.enc` – Pages birtir breytinguna á um það bil mínútu

## Að skipta um aðgangsorð

`python3 encrypt.py "nýtt-aðgangsorð"` (uppfærir líka `.passphrase`), síðan push.

## Öryggislíkan

GitHub Pages-síður eru alltaf opinberlega *afgreiddar*; repo-ið er opið því isfast-is er
ókeypis org (Pages krefst opins repo-s). Trúnaðurinn liggur í dulkóðuninni: sá sem ekki hefur
aðgangsorðið sér aðeins læsiskjá. Síðan er `noindex`.
