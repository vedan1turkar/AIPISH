# Third-party notices

**Project licence:** none is specified. This repository has no LICENSE file, so no licence to the AIPISH
code is granted by this document. The notices below cover third-party software, data and services that
AIPISH uses.

**How this list was made (2026-11-22).** Licences were read from installed package metadata, not from memory:

- Python: `importlib.metadata` (`License-Expression`, else the `License ::` classifiers, else `License`) in a
  clean virtualenv built from `backend/requirements*.txt` with `backend/constraints.txt`.
- npm: the `license` field of each package's `package.json` after `npm ci`, plus the `license` fields in
  `frontend/package-lock.json`.

Only **direct** dependencies are listed by name. Transitive dependencies are counted below; run the same
commands to list them. Check each upstream licence yourself before redistributing anything.

## Backend (Python, `backend/requirements*.txt`)

| Package | Version | Licence (from metadata) | Used for |
|---|---|---|---|
| fastapi | 0.143.0 | MIT | API framework |
| uvicorn | 0.54.0 | BSD-3-Clause | ASGI server |
| pydantic | 2.14.0 | MIT | Schemas |
| pydantic-settings | 2.15.0 | MIT | Settings |
| python-dotenv | 1.2.4 | BSD-3-Clause | `.env` loading |
| SQLAlchemy | 2.1.4 | MIT | ORM |
| python-multipart | 0.0.32 | Apache-2.0 | File uploads |
| httpx | 0.28.1 | BSD (classifier) | Outbound HTTP |
| PyJWT | 2.15.1 | MIT | JWT tokens |
| reportlab | 5.0.1 | BSD (classifier) | PDF reports |
| dnspython | 2.9.0 | ISC | DNS lookups |
| dkimpy | 1.1.8 | "BSD-like" (`License` field); classifier "DFSG approved" | DKIM verification |
| pyspf | 2.0.14 | Python Software Foundation License (classifier) | SPF verification |
| networkx | 3.7 | BSD-3-Clause | Correlation graph |
| psycopg | 3.3.9 | LGPL-3.0-only | PostgreSQL driver (unmodified, used as a library) |
| Jinja2 | 3.1.6 | BSD (classifier) | HTML report and alert e-mail templates |
| mail-parser | 4.10.0 | Apache-2.0 | Informational parser cross-check |

Optional ML stack (`backend/requirements-ml.txt`):

| Package | Version | Licence (from metadata) |
|---|---|---|
| numpy | 2.5.5 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| scikit-learn | 1.9.1 | BSD-3-Clause |
| xgboost | 3.4.1 | Apache-2.0 |
| torch (CPU build) | 2.15.0 | Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND ISC AND MIT AND Zlib |
| transformers | 4.57.6 | Apache (classifier) |
| safetensors | 0.8.0 | Apache (classifier) |
| shap | 0.54.1 | MIT (classifier) |

Test-only (`backend/requirements-dev.txt`): pytest 9.1.1 (MIT), pytest-socket 0.8.1 (MIT), respx 0.23.1 (BSD).

Installed totals in the clean virtualenvs: 75 distributions with the ML stack, 47 without it (including pip).

## Frontend (npm, `frontend/package.json`)

Runtime dependencies (bundled into the web image):

| Package | Version | Licence |
|---|---|---|
| react, react-dom | 18.3.1 | MIT |
| cytoscape | 3.34.3 | MIT |
| leaflet | 1.9.4 | BSD-2-Clause |
| plotly.js-basic-dist-min | 4.3.0 | MIT |
| topojson-client | 3.1.0 | ISC |
| world-atlas | 2.0.2 | ISC |
| @fontsource/ibm-plex-sans | 5.3.0 | OFL-1.1 |
| @fontsource/ibm-plex-mono | 5.3.0 | OFL-1.1 |

Development dependencies (not shipped): vite 5.4.21, vitest 2.1.9, typescript 5.9.3 (Apache-2.0),
eslint 10.12.0, typescript-eslint 8.71.1, @eslint/js 10.0.1, @vitejs/plugin-react 4.7.0, tailwindcss
3.4.19, postcss 8.5.29, autoprefixer 10.6.1, jsdom 25.0.1, @testing-library/react 16.1.0,
@testing-library/dom 10.4.0, globals 17.13.0, @types/* (all MIT unless noted), and axe-core 4.10.2
(MPL-2.0).

`package-lock.json` licence counts over all 383 locked packages: MIT 327, ISC 19, Apache-2.0 19,
BSD-2-Clause 9, BSD-3-Clause 3, OFL-1.1 2, MIT-0 1, MPL-2.0 1, CC-BY-4.0 1, BlueOak-1.0.0 1.

## Fonts

IBM Plex Sans and IBM Plex Mono, via `@fontsource`, SIL Open Font License 1.1. Bundled and served
from the app itself; no font CDN is used.

## Map outline data

`world-atlas` 2.0.2 `countries-110m` (ISC), derived from [Natural Earth](https://www.naturalearthdata.com)
data, which is in the public domain. Bundled; the map loads no tiles and makes no external requests. The
in-app attribution is `MAP_ATTRIBUTION` in `frontend/src/components/geo/labels.ts`.

## MITRE ATT&CK

Technique IDs, names and tactics are taken from MITRE ATT&CK Enterprise 20.1
(`backend/app/attack/data/techniques.json`, with source URL and bundle SHA-256).
© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE
Corporation, under the ATT&CK Terms of Use
(https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

## Training data (not redistributed)

From [data/DATA_CARD.md](data/DATA_CARD.md) §2; raw mail is kept only locally under `data/raw/` and is not in
this repository.

| Source | Terms as stated by the provider | In this repository |
|---|---|---|
| Nazario phishing corpus | CC BY 4.0, attribution required | Not committed (contains live phishing URLs) |
| SpamAssassin public corpus (ham only) | No licence granted; copyright stays with senders | Not committed |
| Enron email dataset (CMU, 2015-05-07) | No formal licence; research resource; respect privacy | Not committed (personal correspondence) |
| Synthetic AIPISH templates | Project-generated (`backend/app/ml/dataset/synthetic.py`) | Generated from code |

Required attribution: *Jose Nazario, Phishing Corpus, https://monkey.org/~jose/phishing/, licensed
CC BY 4.0.* Changes: messages normalised, masked, deduplicated and relabelled as described in the data card.

Trained model files (`models/`) are derived from these sources and are not committed.

## Models and runtimes not bundled

- **DistilRoBERTa** (`distilroberta-base`) is the base of the fine-tuned transformer component. The fine-tuned
  weights live in `models/` (gitignored) and are mounted read-only into the container; check the upstream model
  licence before redistributing them.
- **Ollama and the `mistral` model** run on the host, outside this repository and outside the images.

## External services (used only when configured)

| Service | Plan used | Notes |
|---|---|---|
| VirusTotal | Public API | Non-commercial use only; 4 requests/minute; GET lookups only (no uploads) |
| AbuseIPDB | Free | Rate-limit headers observed in the live run |
| Shodan | Free | Host lookups worked on the free plan in the live run |
| IPinfo | Free | No privacy fields on the free plan |
| Tor Project bulk exit list | Public | Downloaded list; membership checked locally |
| ip-api.com | Free endpoint (`ENRICH_IPGEO_BASE`) | Upload-time IP geo enrichment; check the provider's current terms |
| MISP, MaxMind GeoIP2 | — | Not configured |

Every provider call needs per-analysis consent (except upload-time DNS/RDAP/ip-api enrichment, which can be
switched off with `ENRICH_ENABLE_*` or `APP_ENV=offline`) and sends bare indicators only. The project is
non-commercial university coursework; follow each provider's current terms.
