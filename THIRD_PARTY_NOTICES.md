# Third-Party Notices

OpenCred is licensed under the [MIT License](./LICENSE). It bundles or depends
on the following third-party material, each of which remains under its own
license. This file collects the attributions that those licenses require.

## Bundled fonts (SIL Open Font License 1.1)

The desktop app (`apps/desktop/src/renderer/assets/fonts/`) and the PDF
packaging engine (`packages/packaging/src/fonts/`, also embedded in
`packages/packaging/src/font-data.ts`) bundle these typefaces, all under the
[SIL Open Font License 1.1](https://openfontlicense.org/):

- **Geist / Geist Mono** — Copyright (c) 2023 Vercel, in collaboration with
  basement.studio. License text: `Geist-OFL.txt` alongside the font files.
- **IBM Plex Mono** — Copyright (c) 2017 IBM Corp. License text:
  `IBMPlexMono-OFL.txt` alongside the font files.
- **Instrument Serif** — Copyright (c) 2022 The Instrument Serif Project
  Authors. License text: `InstrumentSerif-OFL.txt` alongside the font files.

The OFL license texts are retained next to the fonts as the license requires.

## Bundled JSON-LD contexts (`packages/vc-core/src/contexts/`)

To avoid fetching remote documents at runtime (a supply-chain risk), OpenCred
bundles these context documents verbatim:

- **W3C Verifiable Credentials v2.0 context** (`credentials-v2.json`) and
  **W3C Data Integrity v1 context** (`data-integrity-v1.json`) — © W3C,
  distributed under the [W3C Software and Document License](https://www.w3.org/copyright/software-license/).
- **W3C CCG Traceability Vocabulary context** (`traceability-v1.json`, also
  embedded in `packages/vc-core/src/context-data.ts`) — © W3C Credentials
  Community Group, W3C Community Final Specification Agreement.
- **1EdTech Open Badges v3 context** (`external/open-badges-v3.json`) —
  © 1EdTech Consortium, distributed under the 1EdTech royalty-free
  specification license.
- The remaining files under `external/` (electricity, functional-identity,
  immunization, business-entity, employment-offer-letter, insurance-policy,
  prescription, test-result) are OpenCred-authored or sourced from the MIT-licensed
  [opencred-vc-schemas](https://github.com/nfh-trust-labs/opencred-vc-schemas)
  repository.

## Bundled schemas (`packages/schema-engine/`)

The schema registry (`schema-data.ts`, `generated-registry.ts`) embeds schema
and context documents whose upstream provenance and license are declared
per-entry in the registry metadata. Upstream sources include the W3C CCG
Traceability Vocabulary (W3C license), the Decentralized Identity Foundation
(Apache-2.0), 1EdTech Open Badges (1EdTech royalty-free specification
license), and OpenCred's own MIT-licensed schemas.

## Dependency license notes

All production dependencies are under permissive licenses (MIT, ISC,
Apache-2.0, BSD, BlueOak). Two notes:

- **`@mosip/pixelpass`** ≥0.3 is licensed under **MPL-2.0** (file-level
  copyleft). OpenCred uses it unmodified as an npm dependency; the MPL-covered
  source is available from [its upstream repository](https://github.com/mosip/pixelpass).
- **`node-forge`** is dual-licensed `(BSD-3-Clause OR GPL-2.0)`; OpenCred
  elects the **BSD-3-Clause** license.

The complete license text of every dependency ships in its package under
`node_modules/` and is declared in each package's metadata.
