# ADR 0016 — Pinning di una versione Key Vault per il signer RLS

- Stato: Accepted — incremento testato in CI (#22), **non** rollout Azure
- Data: 2026-11-15
- Dipende da ADR 0013, 0014 (versioned RLS proofs) e 0015 (secret fuori Terraform)
- Documentazione ufficiale: https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets e https://learn.microsoft.com/en-us/cli/azure/keyvault/secret?view=azure-cli-latest

## Problema

Con URI `https://vault.vault.azure.net/secrets/tenant-proof-key` Azure Container Apps segue la **versione latest** del secret, la recupera periodicamente e può riavviare le revisioni attive. Il cambio del materiale HMAC senza sincronizzare `Security__TenantProofKeyId` e la tabella verificatore `platform.tenant_proof_keys` produce errori API o transazioni RLS negate. Il supporto SQL per grace/revoke (#20) non risolve da solo questa race di rilascio.

## Decisione

- Terraform richiede `tenant_proof_secret_version` (32 hex, senza default) e forma il riferimento `<Key Vault URI>/secrets/tenant-proof-key/<version>`. È **metadata**, non segreto; `var.tenant_proof_key` continua a non esistere e non c'è data source che legga il valore.
- Il GitHub Environment `production` fornisce `TENANT_PROOF_SECRET_VERSION`, associato ad approvazione e al `TENANT_PROOF_KEY_ID` usato dal signer RLS. Il versionless non è più ammesso in questo percorso.
- Preflight in `scripts/azure/check-tenant-proof-secret.sh`: controlla sintassi input, enumera i **metadati delle versioni** con `az keyvault secret list-versions` e valuta `attributes.enabled` sulla **versione esatta** tramite URI. La richiesta list-versions non restituisce valori e richiede secrets/list: non si chiama `az keyvault secret show` o un endpoint che recupera il segreto.
- In caso di ID mancante/invalido, fallimento Azure CLI, versione disabilitata o non trovata, lo script fallisce. Test senza Azure con `az` simulata e contratti Terraform/Actions su `main`.
- L'API continua a ricevere il valore con il riferimento Key Vault risolto dalla propria managed identity. Nessun cambiamento a PostgreSQL, policy RLS, single API/React/database.

## Conseguenze e limiti

Un'ulteriore versione Key Vault non modifica in automatico la versione pin applicativa: l'operatore deve aggiornare deliberatamente la coppia **(key ID, secret version)** ed eseguire un rilascio. Questo mitiga la race da refresh latest, ma non garantisce pairing crittografico: il preflight non può usare o conoscere la chiave per confrontarla col DB. Occorre smoke test sull'API, autorizzazioni e logging prudenti prima e dopo la distribuzione.

La Container App esistente usa **`revision_mode = "Single"`**, quindi non si deve promettere una rotazione zero-downtime o rollout con due revisioni/traffic shifting. Anche la propagazione dei riferimenti ai segreti e il bootstrap Azure in VNet non sono stati verificati. #19/#6 restano aperte per multi-revision staged rollout/rollback, validazione key ID/key material, key rotation/secret storage e test Azure live. Le vecchie copie Terraform State possono ancora esporre segreti e devono essere gestite separatamente.

## Evoluzione — ADR 0017

L'ADR 0017 aggiunge la conservazione del **nome e della versione della secret stable** durante lo staging di una nuova revisione 0% con **secret app-scoped distinta**, perché l'aggiornamento di una secret esistente sarebbe visibile anche alle revisioni precedenti. L'ADR 0016 descrive il pinning versione della singola secret prima di questa evoluzione.
