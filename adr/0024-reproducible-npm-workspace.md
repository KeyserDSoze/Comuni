# ADR 0024 — Lockfile npm unico alla radice e installazione deterministica del workspace

- Stato: Accepted come riproducibilità della risoluzione npm (issue #30; epica #5)
- Data: 2026-11-15
- Dipendenze: ADR 0001, 0010, 0020, 0023 e issue #29, #30
- Riferimenti: [npm ci](https://docs.npmjs.com/cli/v10/commands/npm-ci), [npm workspaces](https://docs.npmjs.com/cli/v10/using-npm/workspaces), [package-lock v3](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json).

## Problema

Il frontend usa un workspace npm radice, ma senza `package-lock.json` la risoluzione di versioni transitive cambiava a ogni `npm install`. Il Dockerfile installava inoltre il `src/frontend/package.json` fuori dal workspace root: due build dello stesso commit avrebbero potuto utilizzare alberi differenti, invalidando le conclusioni della CI SCA e rendendo difficile un rollback affidabile.

## Decisione

1. **Una sola sorgente della risoluzione:** `package-lock.json` npm v3, generato automaticamente da npm 10 / Node.js 22 sulla **root** e revisionato insieme ai manifest; contiene `packages[""]`, `packages["src/frontend"]`, il link `node_modules/@comuni/frontend` e gli hash SHA-512 per i tarball. Vietare lockfile secondari in `src/frontend`; niente modifiche manuali dei pin.
2. **Installazioni fail-closed:** per CI React/Playwright e build Docker, `npm ci --no-audit --no-fund` dalla root. Un disallineamento dei due `package.json` col lockfile deve bloccare la build, senza rigenerazione silenziosa. L'audit SCA usa `npm ci --ignore-scripts --no-audit --no-fund`, poi `npm audit --omit=dev --audit-level=high` secondo ADR 0023.
3. **Un solo bundle e un solo frontend:** il Dockerfile copia prima i manifest e lockfile per il layer npm, poi i sorgenti React, compila con `npm run build --workspace @comuni/frontend` e copia `src/frontend/dist` in `wwwroot` dell'unica API .NET.
4. **Manutenzione:** aggiornare intenzionalmente manifest e lockfile con `npm install --package-lock-only --ignore-scripts` sulla root, review del grafo e dei campi `resolved`/`integrity`, `npm ci` + build + Playwright prima del commit. Nessun `npm audit fix` automatico. TDD RED su `main`; lock generato da un runner npm nel workflow temporaneo #30, **rimosso** nella configurazione finale, poi GREEN e CI sullo SHA finale.

## Compromessi e rischi residui

Il lockfile blocca versioni/integrity del **grafo npm**, non tutti i byte dell'immagine Docker o dell'output compilato: base image, Node/npm runtime, dipendenze di sistema, lifecycle script e artefatti esterni rimangono input variabili. L'installazione usata per compilare può invocare lifecycle script di dipendenze; l'audit SCA separato li disabilita, ma ciò non ne certifica l'innocuità. Nessun servizio o database aggiuntivo; prove Azure reali, SBOM/provenance, policy sugli alert CodeQL e scansione immagini restano nelle epiche #5/#6.
