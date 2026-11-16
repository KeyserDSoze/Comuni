# ADR 0059 — Lock ACR indipendente per tag e manifest OCI della candidata

- **Data:** 2026-11-16
- **Stato:** Accepted per la pipeline e i test offline; **non** verificato su un ACR Azure reale.
- **Issue:** #68 (sotto #65, #5, #6), dopo ADR 0056, 0057 e 0058.
- **Specifiche Microsoft ufficiali:** [Lock container image in Azure Container Registry](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-image-lock), [Azure ACR RBAC/ABAC permissions](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-abac-repository-permissions), [ACR image push troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/azure/azure-container-registry/troubleshoot-push-error-operation-disallowed-timeout).

## Problema

Il job di staging #64 riceve il digest del **proprio** Docker push e lo riconfronta con il registro gestito; #66/#67 aggiungono attestazioni firmate di provenienza SLSA e SPDX/CVE gate. Prima di questa decisione, il tag `comuni:<GITHUB_SHA>` e il manifest `comuni@sha256:<digest>` rimanevano **scrivibili e cancellabili**, nonostante il solo deploy per digest riducesse il rischio di sostituzione tag.

La documentazione Microsoft precisa che gli attributi mutabili del **tag e del manifest sono distinti**: proteggere il tag non protegge il manifest, e viceversa. Un update a livello di intera repository `comuni` impedirebbe anche i futuri push e renderebbe difficile il rollback: non è accettabile.

## Decisione

1. Il workflow `.github/workflows/deploy.yml` richiama `scripts/azure/lock-approved-image.py` **immediatamente dopo** il digest approvato da `resolve-pushed-image-digest.py` e **prima** di Trivy, attestazioni SLSA/SPDX e `terraform plan/apply`. Gli argomenti provengono dal runner GitHub protetto, non dal Terraform plan: `--source-commit-sha "$GITHUB_SHA"`, `--candidate-image-digest "$CANDIDATE_IMAGE_DIGEST"`, `--image "$TF_VAR_image"`, nome e host ACR da GitHub Environment.
2. Convalidare: `GITHUB_SHA` esattamente 40 hex lowercase, registry `[a-z0-9]{5,50}` e `<name>.azurecr.io`, digest `sha256:` + 64 hex lowercase, URI esatta `<managedACR>/comuni@<approved_digest>`. Interrogare il **digest attualmente collegato al tag** con `az acr manifest show-metadata --registry <registry> --name comuni:<GITHUB_SHA> --query digest --output tsv --only-show-errors`: se diverso dal receipt del push approvato o mancante, **nessuna mutazione ACR**.
3. Solo dopo la verifica, impostare **su entrambi i riferimenti** gli attributi `writeEnabled=false`, `deleteEnabled=false`: `az acr repository update --name <registry> --image comuni:<GITHUB_SHA> ...` e `az acr repository update --name <registry> --image comuni@sha256:<digest> ...`. Non usare `--repository comuni`, `--delete-enabled true` o `--write-enabled true` nell'automazione di rilascio.
4. Dopo gli aggiornamenti, ricontrollare lo stesso `comuni:<GITHUB_SHA>` e leggere `changeableAttributes` con `az acr repository show --name ... --image ... --query changeableAttributes --output json` **separatamente per tag e manifest**. Ogni oggetto deve avere **booleani JSON** `writeEnabled:false`, `deleteEnabled:false` e `readEnabled:true`. Un errore di az, metadata mancanti/ambigui o un lock non persistito bloccano il rilascio.
5. La CLI non scrive il contenuto del registry, l'URI digest, le credenziali o i dettagli dei comandi nei log; stdout/stderr di Azure vengono sempre catturati. La verifica è **fail closed** senza fallback, senza auto-unlock e senza proteggere tutta la repository. Se lo step si interrompe a metà, il tag e/o manifest possono restare parzialmente bloccati: occorre **change review dell'owner** prima di eventuali sblocchi. Riavviare lo stesso commit può fallire per tag già bloccato: usare un nuovo commit approvato, non sbloccare automaticamente.
6. **Nessuna modifica al ruolo della Container App.** Il registry Terraform esistente è Basic, `admin_enabled=false`; l'unica UAI ACA dispone del ruolo `AcrPull` (read-only, non `AcrPush`). Il principal separato del workflow che esegue `docker push`/lock deve avere i permessi ACR strettamente necessari, da configurare e verificare in ambiente live tramite Azure IAM. **Non** convertire automaticamente il registry da RBAC a `rbac-abac`: secondo Microsoft i ruoli legacy `AcrPull/AcrPush` **non** sono rispettati in quella modalità e la migrazione può interrompere il pull della stable. La migrazione deve essere approvata, preparare ruoli ABAC equivalenti e verificare i pull senza downtime.
7. RED `tests/infra/test_aca_acr_tag_manifest_lock.py` con fake `az` che registra gli argomenti, validazione del digest prima e dopo, fault injection su tutte le sei chiamate e read-back dei due attributi. GREEN script + workflow. CI 7/7 sullo **stesso SHA main** è condizione per chiudere la #68.

## Garanzie ed esclusioni

Il lock ACR impedisce modifiche/cancellazioni accidentali e attacchi da principal con soli permessi ordinari, ma **non** impedisce a un amministratore con poteri di aggiornamento metadata di sbloccare, né a `acr purge --include-locked` di rimuovere un oggetto dopo lo sblocco. Un principal compromesso durante il push potrebbe creare contenuto malevolo **prima** del lock: restano necessarie le attestazioni #66/#67 e un builder affidabile. Il digest OCI è sempre il punto di selezione del rollout.

La pipeline non aggiunge ruoli `AcrPush` alla UAI dell'app né aggiorna automaticamente il tenant Azure; `Azure Container Apps` resta sulla stessa API con la stessa SPA, i controlli segreti/RLS/OIDC e split stable100%/candidate0% restano invariati.

**Non è stato eseguito alcun accesso Azure live in questa implementazione.** Gli effettivi diritti della federated identity, la sintassi della CLI nel tenant, un eventuale ruolo ABAC, il risultato di una vera lock/unlock e gli smoke del rollout devono essere verificati in ambiente approvato; #65/#5/#6/#49 rimangono aperte.
