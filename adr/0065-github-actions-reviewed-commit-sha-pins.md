# ADR 0065 — Pin SHA reviewati per tutte le action GitHub di CI e release

- **Data:** 2026-11-16
- **Stato:** Accepted per CI/deploy workflows; un pin non equivale a provenienza firmata del runner o a verifica delle immagini base.
- **Issue:** #76, sotto #65/#6, in continuità con ADR 0057–0064.
- **Riferimenti:** [GitHub — security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions), [GitHub API — Git refs](https://docs.github.com/en/rest/git/refs#get-a-reference), [GitHub API — Git tags](https://docs.github.com/en/rest/git/tags#get-a-tag), [Docker image digest pinning](https://docs.docker.com/build/building/best-practices/).

## Contesto e minaccia

La pipeline di release manuale `.github/workflows/deploy.yml` usa OIDC federato verso due principal Azure, crea il contenuto pubblicato in ACR, firma attestazioni SLSA/SPDX, verifica il digest candidato, controlla CVE, blocca tag/manifest e prepara un piano Terraform. Una action di terze parti non fissata a un **commit Git esatto** può cambiare quando il publisher sposta un tag `@v2`/`@v3`/`@v4`, anche quando il codice della piattaforma e il commit `GITHUB_SHA` sono invariati. In particolare, un `checkout`, un `azure/login`, un installer tool, un action di attestazione o il setup Terraform compromesso potrebbe ottenere token OIDC, manipolare l'immagine o falsare il gate.

Lo stesso problema tocca `.github/workflows/ci.yml`: senza action pin, una CI verde sul commit applicativo non garantisce che il programma eseguito dal runner sia rimasto identico durante l'intero intervallo. Prima della #76 Trivy e `actions/attest` erano già pinnate, ma checkout/setup-dotnet/setup-node/CodeQL/Terraform/Azure Login usavano tag mobili.

## Decisione

1. **Pinnare ogni proprietà `uses:` dei due soli workflow del repository** al **commit Git completo di 40 caratteri esadecimali lowercase**, non al nome di tag, a un tag annotato non dereferenziato, a uno SHA abbreviato o a un Docker tag.
2. Risolvere le action tramite **API ufficiale GitHub** `GET /repos/<owner>/<repo>/git/ref/tags/<major>`, controllare se `object.type` è `commit` oppure `tag`; in quest'ultimo caso utilizzare **`GET /repos/<owner>/<repo>/git/tags/<sha>` e il `object.sha` del commit finale**, non lo SHA dell'oggetto annotated tag. Commit ufficiali verificati il 16/11/2026:

| Action | Major di riferimento | Commit fissato |
|---|---|---|
| `actions/checkout` | `v4` | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/setup-dotnet` | `v4` | `67a3573c9a986a3f9c594539f4ab511d57bb3ce9` |
| `actions/setup-node` | `v4` | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
| `hashicorp/setup-terraform` | `v3` | `b9cd54a3c349d3f38e8881555d616ced269862dd` |
| `azure/login` | `v2`, annotated | `7184910d9eb2b1c5e48f7073824a90609bb9b6d6` |
| `github/codeql-action/init`, `analyze` | `v4`, annotated | `33d7b85da1a04171e211befe2c739303b9a4c066` |
| `aquasecurity/setup-trivy` | `v0.3.1`, già pinnata | `81e514348e19b6112ce2a7e3ecbafe19c1e1f567` |
| `actions/attest` | `v4`, già pinnata | `1e69f48acb82d1966a394da916b4c1698aa569d6` |

3. **Conservare** il commento di versione `# vX` accanto al digest per agevolare la manutenzione; il commento non influenza il codice risolto e non deve essere usato come criterio di autorizzazione.
4. Aggiungere `tests/infra/test_github_action_sha_pins.py`, eseguito dal job Terraform/Python, che accetta solo queste coppie **action repository + commit**, richiede anche il numero previsto di istanze in **entrambi** i workflow (14 CI, 8 deploy), impedisce di rimuovere silenziosamente passaggi critici, rifiuta reference `@main`, `@v4`, SHA corta, repository diverso, `docker://`, `./local`, action inserita senza review e commit diverso. Tutte le stringhe `uses:` devono essere trovate nei workflow; un nuovo package/major/commit richiede aggiornamento esplicito dell'allowlist, ADR, revisione e CI completa.
5. Non modificare job o permission, né `id-token:write`, payload attestation, OIDC, Trivy, Key Vault, RLS, Dockerfile o traffico ACA. Il pin cambia **solo il ref eseguibile** delle action e il testo dei vecchi test che controllavano la tag `azure/login@v2`. I criteri della #76 sono soddisfatti solo con test RED→GREEN e **CI 7/7 sul medesimo SHA finale di `main`**.

## Aggiornamento controllato e residui

Per aggiornare in futuro un'action, ottenere la **release/tags ufficiale** dell'autore, verificare il commit e, dove disponibile, i provenance/signatures; se è un tag annotato, risolvere l'oggetto `tag` fino al **commit**, rivedere changelog e permessi, modificare contemporaneamente i due `uses:` necessari e la allowlist e ripetere suite infrastrutturali, CodeQL, xUnit/PostgreSQL, Playwright e Docker. Non aggiornare solo il commento `# v4` lasciando il SHA invariato e non eseguire un upgrade silente di terze parti.

Il pin GitHub Action **non sostituisce** le protezioni del runner/branch GitHub Environment, non impedisce al publisher di cancellare un commit o rilasciare un nuovo CVE, non garantisce la sicurezza dei tool scaricati dinamicamente dalle action, né della base image `mcr.microsoft.com/dotnet/sdk:10.0`, `node:22-alpine`, `mcr.microsoft.com/dotnet/aspnet:10.0` ancora basate su tag mobili nel `Dockerfile`. Questi digest e la policy di aggiornamento/rebuild richiedono una sotto-issue della #65. Nessuna prova Azure reale o `terraform apply` è stata eseguita; #74/#72/#70/#65/#6 restano aperte per il go-live.
