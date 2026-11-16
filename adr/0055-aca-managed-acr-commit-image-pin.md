# ADR 0055 — Immagine candidata ACA vincolata al commit e all'ACR managed prima di Terraform apply

- Stato: Accepted per il solo **gate offline del piano Terraform**; non costituisce attestazione di provenienza o immutabilità dell'immagine.
- Data: 2026-11-16.
- Issue: #63 (sotto #5/#6/#49), dopo ADR 0046, 0053 e 0054.
- Riferimenti: [Terraform JSON plan format](https://developer.hashicorp.com/terraform/internals/json-format), [Azure Container Registry overview](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-intro), [Azure Container Apps revisions](https://learn.microsoft.com/en-us/azure/container-apps/revisions), [Docker image digests](https://docs.docker.com/dhi/core-concepts/digests/).

## Minaccia

Il workflow manuale GitHub Actions costruisce e invia `<ACR_LOGIN_SERVER>/comuni:<GITHUB_SHA>` e fa `terraform apply` di un piano approvato da `scripts/azure/check-staged-rollout-plan.py`. Il gate, prima di #63, controllava PostgreSQL/RLS, OIDC Production, ambiente, segreti, identity UAI e stable 100% / candidate 0%, ma **non** `template.container[0].image`. Un piano manomesso poteva distribuire una revisione candidata con immagine arbitraria; essendo la candidata raggiungibile tramite label, la verifica post-apply dell'immagine sarebbe arrivata **dopo l'avvio** del codice malevolo con accesso ai riferimenti Key Vault del SQL runtime e della firma tenant.

Il container registry indicato nella sola sezione app-scoped `registry.server` non è una fonte di fiducia sufficiente: deve coincidere con l'ACR previsto in `planned_values.root_module.resources` della risorsa Terraform managed.

## Decisione

1. Il workflow passa il vero `GITHUB_SHA` automatico del run a `check-staged-rollout-plan.py --source-commit-sha "$GITHUB_SHA"` nello **stesso** comando che legge la pipe privata del piano. Il flag è obbligatorio. Non viene derivato dall'image URI, da `TF_VAR_image` o da un campo del piano Terraform. Accettare solo **40 caratteri esadecimali minuscoli** e una revisione candidata `r<primi12hex>`, in linea con il workflow. Un valore non canonico o uno SHA differente fallisce chiuso.
2. Da `planned_values.root_module.resources` il gate richiede **esattamente una** risorsa `azurerm_container_registry.main` con tipo `azurerm_container_registry`, `name` lowercase alfanumerico (5–50 caratteri) e `login_server == name + ".azurecr.io"`. Se manca, è ambigua, sconosciuta o fuori dal dominio ACR approvato, lo staging fallisce chiuso; non ripiegare su un registry da utente o variabile release. Un eventuale login server con formato differente richiede valutazione/ADR separata, senza allentare il vincolo in automatico.
3. Il registry app-scoped **già installato** deve rimanere identico (ADR 0053) e il suo `server` deve coincidere con il registro managed del piano. L'unico container candidate ha `image` **esattamente** `<managed_login_server>/comuni:<approved_40hex_SHA>`. Nessun `latest`, host alternativo, repo/path differenti, tag multipli, digest concatenato, prefisso schema URL o placeholder `null` è valido. La verifica avviene prima di `terraform apply`.
4. Test avversariali sintetici RED in `tests/infra/test_aca_candidate_image_preapply.py`, fixture `test_staged_rollout.py` estesa a registry+immagine e nuovi flag SHA in tutti i test che usano il gate. GREEN non modifica la topologia Azure né inserisce nuovi secret. ADR 0053/0054 e controlli 100% stable/0% candidate rimangono obbligatori. La CI di definizione done richiede tutti i sette job sullo stesso commit finale `main`.

## Limiti e risposte operative

Il tag `comuni:<SHA>` è un **nome**, non un'identità crittografica del contenuto. Un principal con permesso `push`/retag in ACR può sostituire i layer con lo stesso tag e superare questa verifica di piano. L'ACR managed va protetto con RBAC/provenance e pipeline immutabile; un successivo incremento può vincolare la release a un digest `sha256` verificato dal registry dopo la build/push, e aggiungere attestazione/SBOM e firma. **Non** dichiarare supply chain attestata o zero-downtime.

Il JSON Terraform è soltanto una delle fonti di metadati: runner, `GITHUB_SHA`, credenziali CI, stato GitHub Environment/ACR, container image digest e l'integrità della remote state richiedono controlli separati. Non sono stati eseguiti `terraform apply` live, letture di secret, autenticazioni OIDC reali o test Azure di isolamento cross-tenant. Le epiche #5/#6/#49 restano aperte.
