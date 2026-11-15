# ADR 0017 — Staging di revisioni Azure Container Apps a traffico zero

- Stato: Accepted come **guardrail di staging**, non come rollout zero-downtime validato
- Data: 2026-11-15
- Issue: #23, sotto-issue delle #19 e #6; architettura ADR 0003 e ADR 0014–0016
- Fonti: [Microsoft Learn — Container Apps revisions](https://learn.microsoft.com/en-us/azure/container-apps/revisions), [provider Terraform azurerm_container_app](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_app)

## Problema

La prima versione del deploy Terraform aveva `revision_mode=Single` e il traffico indirizzato al 100% alla latest: anche con Key Vault pin versione, il rilascio di un template con nuovo `Security__TenantProofKeyId` avrebbe esposto automaticamente utenti all'API non ancora verificata. Le secret di ACA sono application-scoped; aggiornare in-place `tenant-proof-key` potrebbe rompere vecchie revisioni con HMAC legacy.

## Decisione

Passare la stessa **unica** Container App a `revision_mode=Multiple`. Il Terraform richiede `stable_revision_suffix` già esistente, `stable_tenant_proof_secret_version` pinned, `candidate_revision_suffix` univoco derivato dal commit, `tenant_proof_secret_version` pinned candidata e `tenant_proof_key_id`. La stable riceve 100% di traffico e la latest candidata 0%, senza trasferimento automatico. `min_replicas=1` per rendere la candidata disponibile per future verifiche, con costo da valutare.

Le secret ACA sono distinte: `tenant-proof-key` rimane associata alla vecchia versione immutabile, `tp-<primi 16 caratteri hex della versione>` (**19 caratteri**, URI Key Vault pinned con full 32hex) viene creata per la candidata e il nuovo template usa solo quest'ultima. La configurazione HMAC stable rimane invariante. Non rimuovere la secret precedente durante la fase di stage.

Il GitHub Environment contiene anche `STABLE_REVISION_SUFFIX` e `STABLE_TENANT_PROOF_SECRET_VERSION`; entrambe le versioni vengono verificate tramite preflight Key Vault metadata-only. Il workflow produce un piano Terraform, poi invia il risultato di `terraform show -json` **via pipe** al gate `scripts/azure/check-staged-rollout-plan.py`, che non mostra né conserva lo stato, ma confronta la secret stable prima/dopo, vincola il riferimento della nuova secret/ID e il routing a 100/0, rifiuta create/delete/replacement della Container App, impedisce mutazioni/rimozioni di secret application-scoped esistenti e blocca qualunque azione di distruzione di altre risorse. Soltanto dopo la verifica si procede all'apply.

## Alternative scartate

- Single revision + readiness: Microsoft dichiara readiness prima dello switch, ma **non prova il pairing della chiave RLS e del verifier PostgreSQL**, e il traffico si sposterebbe automaticamente.
- Multiple + latest=100: permette multi-revisione ma non preserva il 100% sulla stable finché il collaudo applicativo non autorizza la promozione.
- Sostituire la stessa secret `tenant-proof-key` application-scoped: può influire sulle revisioni ancora attive e non consente rollback isolato.
- Far stampare `terraform show -json` nei log del job: esporrebbe state e credenziali; si preferisce pipe con soli esiti generici.
- Creare un servizio o DB separato per la candidata: viola la configurazione architetturale e richiede gestione aggiuntiva.

## Limiti / obblighi successivi

Questo incremento **non** è un orchestratore blue-green completo. Lo stage non garantisce che il suffisso stable corrisponda a una revisione Azure esistente e sana; il gate opera su JSON sintetico in CI e richiede collaudo su piano reale prima dell'apply. Una prima infrastruttura senza revisione stable deve seguire un percorso separato. Il workflow non automatizza una label/URL di test sicura, il pairing ID/chiave/DB, il controllo di readiness, la promozione di traffico, il rollback, il grace/retire delle chiavi precedenti o la pulizia di secret usate da revisioni attive. L'assenza di cleanup automatico è una **scelta fail-closed**: nuove iterazioni non possono cancellare segreti di cui non sia stata approvata la dismissione. È necessario un workflow autorizzato che includa la verifica Azure in VNet, audit, allarmi, test di concorrenza e rollback: #19/#6. Non dichiarare go-live/compliance o zero-downtime con i soli test CI.

## Evoluzione successiva — ADR 0018

L'ADR 0018 aggiunge una verifica **post-apply** live dei metadati e del traffico effettivo, da usare prima di qualunque smoke test e promozione. Non introduce una procedura di promozione/rollback né una prova di pairing crittografico tra Key Vault e PostgreSQL.

## Evoluzione ADR 0033 — Nomi candidate compatibili con ACA

Microsoft documenta il limite di **20 caratteri** per le chiavi secret ACA. L'originale `tenant-proof-key-v<32hex>` non è un nome distribuibile in modo affidabile; ADR 0033 e #39 lo sostituiscono nel Terraform, nel plan gate e nel verifier live con `tp-<16hex>` (19 caratteri). Il **full URI versionato** continua a usare esattamente 32hex, e la secret stable `tenant-proof-key` resta immutata. Collisioni del prefisso non provocano sovrascritture: il plan gate preserva l'URI preesistente e fallisce. Questa evoluzione è verificata offline, non con un deploy Azure reale.
