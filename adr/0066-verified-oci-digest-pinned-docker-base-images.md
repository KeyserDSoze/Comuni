# ADR 0066 — Pin per digest OCI verificato delle tre immagini base Docker (linux/amd64)

- Data: **2026-11-16**
- Stato: **Accepted per pipeline e build CI**, nessuna verifica Azure ACA live.
- Scope: issue #77, sotto #65/#6 e ADR 0065; l'API .NET10, la SPA React e PostgreSQL rimangono una sola soluzione.
- Fonti: [Docker — pinning base images](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions), [Docker — inspect OCI manifest index](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/), [Microsoft .NET container images](https://learn.microsoft.com/en-us/dotnet/core/docker/container-images), [Docker Official Node images](https://hub.docker.com/_/node).

## Rischio e decisione

L'immagine finale dell'API+SPA viene già pubblicata per digest OCI ACR e protetta da attestazioni/doppio lock (ADR 0056–0064). Tuttavia il Dockerfile usava `FROM mcr.microsoft.com/dotnet/sdk:10.0`, `FROM node:22-alpine` e `FROM mcr.microsoft.com/dotnet/aspnet:10.0` **senza digest**: una promozione del tag MCR/Docker Hub poteva cambiare i contenuti della build senza cambiare GitHub SHA. La #76 ha pinnato le Action GitHub, ma non i tre FROM.

**Decisione:** conservare i tag human-readable, ma vincolare l'effettiva selezione delle basi con `:tag@sha256:<digest-index>` in ogni FROM. Il digest è quello dell'**indice/manifest list OCI multiarch** ottenuto da registry fonte, non il digest di un'immagine amd64 preso a caso dal portale. Imporre `--platform linux/amd64` in **entrambi** i build `ci.yml` e `deploy.yml`, selezionando il child manifest ammesso dalla manifest list. Il Dockerfile continua ad avere tre stage `backend`, `frontend` e runtime, nessun `ARG BASE_IMAGE`, tag di altri registry o input per sovrascrivere una base.

## Evidenza digest verificata al registry, 16/11/2026

Per evitare di inventare hash o confondere digest di tag, indice e manifest per architettura, il test RED e un probe **temporaneo in sola lettura** nel job Terraform GitHub Actions hanno invocato `docker buildx imagetools inspect "$image"` su ognuna delle tre source. Run [43911157458](https://github.com/KeyserDSoze/Comuni/actions/runs/43911157458), job Terraform, step `Inspect exact upstream base OCI index digests for SHA approval` con output completo della sezione di intestazione e child `linux/amd64`:

| Source tag (human-readable) | Digest dell'indice multiarch approvato | Manifest child `linux/amd64` osservato |
|---|---|---|
| `mcr.microsoft.com/dotnet/sdk:10.0` | `sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb` | `sha256:ddbaedfc8b774389d91a511af08b77296f2c7a8d15d86f6214d2a87166933625` |
| `node:22-alpine` (`docker.io/library/node`) | `sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a` | `sha256:12f54cafa58d0e96554ae05871e29663ff7241836377dc9a7916449b8adb062c` |
| `mcr.microsoft.com/dotnet/aspnet:10.0` | `sha256:bfd912c83295ce66d4b706ebb8541b9f14259b0e76fbb88b2751f58ce2399d2e` | `sha256:05acd0ca475e2130832bab441d28a7dd31041129bad28eac7928151fd73cd2c5` |

Il digest dell'**indice** è quello pinnato nel FROM; i digest child sono registrati per distinguere in modo non ambiguo la piattaforma. Node ha anche alcuni manifest `unknown/unknown` destinati ad attestazioni: non usarli come manifest applicativo `linux/amd64`. I digest pubblicati nei portali web possono essere storici o cambiare tra crawl: per questa approvazione fanno fede gli hash completi riletti direttamente dai registri nel runner CI; il probe temporaneo è stato rimosso dopo la raccolta, per evitare future dipendenze dal tag mobile.

## TDD e controlli di regressione

- RED su `main` in `tests/infra/test_immutable_docker_base_digests.py`: ogni FROM deve corrispondere a **esattamente una** delle tre source + digest lowercase 64-hex su allowlist e a stage previsto; rifiuta tag mobili, digest abbreviati/case-insensitive, registry/repository/versione diversi, input `ARG` o `ONBUILD` non autorizzati, stage in più e piattaforma build dinamica/non esplicita. La suite richiede SHA approvati, inizialmente vuoti, e `--platform linux/amd64` per entrambi i workflow.
- GREEN: tre `FROM ...@sha256:<index>` vincolati in Dockerfile; pinned hash hardcoded nei test e build-path della CI e di deploy fissati a amd64, senza alterare il resto della pipeline.
- Oltre ai Python test dell'infrastruttura, il job `Combined container image` deve effettivamente eseguire `docker build --platform linux/amd64 -t comuni:ci .` con tutte e tre le basi approvate; tutti i **7 job CI** sull'esatto SHA finale di `main` devono essere verdi per chiudere #77.

## Procedura controllata di aggiornamento

1. Alla pubblicazione di una patch .NET/Node/Alpine, o davanti a CVE e advisory, rivedere la nuova release ufficiale, l'architettura e gli attributi di supporto; eseguire da un runner autorizzato `docker buildx imagetools inspect mcr.microsoft.com/dotnet/sdk:10.0`, `.../aspnet:10.0` e `node:22-alpine`, recuperando **l'indice completo** e la presenza di `linux/amd64`. Se non è possibile verificare il digest alla fonte, **non** inventarne uno e non sostituire il pin con un tag mobile.
2. Registrare sorgente, data, commit del Dockerfile, digest indice/child, motivo aggiornamento e validazione advisory; aggiornare **insieme** Dockerfile, allowlist test e questo ADR (nuova ADR per cambi architetturali), e rieseguire xUnit/PostgreSQL, React/Playwright, Terraform/Python, CodeQL, SCA e **build Docker reale**.
3. Il rilascio Azure, quando autorizzato dall'owner, continua a verificare il digest **dell'immagine finale** `comuni@sha256:...`, Trivy/SBOM e firma attestazioni prima di Terraform e staged 0% traffic. Se il build fallisce con un'immagine base pinnata, interrompere: niente fallback `docker build --pull` con FROM non revisionate.
4. Rollback non equivale a riutilizzare una tag modificabile: usare la revisione ACA stable esistente e/o il digest immutabile già approvato, senza sbloccare i tag/manifest ACR e senza bypassare i gate di sicurezza.

## Limiti

Pinning dell'indice + build CI su `linux/amd64` riducono la deriva dei contenuti, **non** attestano che il registro non sia compromesso, né certificano CVE zero, firme/attestazioni delle immagini upstream o la riproducibilità bit-a-bit della build finale. Non è stata eseguita una promozione Azure reale, `terraform apply`, lettura/modifica Key Vault, assegnazione IAM o smoke test ACA. La parent #65 resta aperta per trusted builder, attestazioni base/runner e prove Azure; #74/#72/#70/#6/#49 rimangono aperte per FIC, RBAC e interoperabilità dei lock in cloud.
