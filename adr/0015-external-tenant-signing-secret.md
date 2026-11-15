# ADR 0015 — Chiave tenant HMAC esterna a Terraform e preflight Key Vault

- Stato: Accepted, limitatamente alla gestione dello state e al preflight (#21)
- Data: 2026-11-15
- Riferimenti: ADR 0003, 0011, 0013, 0014; issue #19, #21, #6
- Requisiti: Terraform >= 1.9, provider azurerm 4.x

## Contesto

La slice #18 aveva introdotto una Key Vault secret `tenant-proof-key` con `value = var.tenant_proof_key`. Anche se il valore era marcato `sensitive`, restava conservato nello **state Terraform**, inclusi i vecchi snapshot versionati. La #20 ha implementato il verifier PostgreSQL multi-key con grace/revoca, ma un rollout non può basarsi su una secret creata da un semplice Terraform apply.

## Decisione

- **No secret HMAC via Terraform.** Si elimina la variabile `tenant_proof_key`, il relativo `TF_VAR_tenant_proof_key` GitHub e la risorsa `azurerm_key_vault_secret.tenant_proof_key`; l'API continua a leggere `Security__TenantProofKey` tramite secret reference di Azure Container Apps.
- Il riferimento è un URI **versionless** `<Key Vault URI>secrets/tenant-proof-key`, costruito da metadati della risorsa Vault. Non si usa una data source che recuperi il valore nello state.
- Per installazioni esistenti il blocco Terraform `removed { from = azurerm_key_vault_secret.tenant_proof_key lifecycle { destroy = false } }` smette di tracciare il secret **senza eliminarlo**. Verificare sempre il plan prima dell'apply, in caso contrario fermarsi.
- Il workflow Azure fa un check preliminare con `az keyvault secret show --query attributes.enabled -o tsv`, non legge/visualizza `value`; se il Vault/secret è mancante, disabilitato o non accessibile, si blocca prima del plan. Ciò richiede che il Vault e il secret siano pre-provisionati: bootstrap iniziale separato e autorizzato, #6.
- I test CI verificano i confini del codice Terraform/workflow e un `az` simulato, **non** sostituiscono un test Azure. Non si modifica l'identità dell'API né il database unico.

## Conseguenze, alternative e rischi

Le future versioni dello state non devono più ricevere **questa** chiave HMAC dal Terraform. Le copie **storiche** dello state possono ancora contenerla: limitare accessi, approvare retention/cleanup e **ruotare** il vecchio key ID mediante la procedura #19. Altre credenziali PostgreSQL rimangono nello state e richiedono un ulteriore incremento di gestione.

Il preflight controlla `enabled`, **non** verifica valore corretto, expiry, pairing con `Security__TenantProofKeyId` e tabella `platform.tenant_proof_keys`, né l'effettivo aggiornamento di tutte le repliche. L'URI versionless da solo non garantisce rollout atomico o zero-downtime: manca coordinamento DB/Key Vault/revision app, test di carico, allarmi, rollback su Azure (#19 e #6). È intenzionalmente vietato eseguire rotazioni cieche.

Il provisioning segreti in PostgreSQL attraverso `psql` può essere visibile nei log o diagnostic events secondo le impostazioni del server: non assumere trasporto invisibile. Serve una procedura/log redaction verificata, privilegi minimi, gestione Key Vault autorizzata e secret rotation sicura. Non c'è verifica live Azure, privacy compliance o garanzia di produzione.
