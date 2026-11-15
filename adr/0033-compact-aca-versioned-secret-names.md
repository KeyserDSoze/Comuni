# ADR 0033 — Chiavi delle secret versionate ACA entro 20 caratteri, URI Key Vault completo

- Stato: Accepted come correzione offline di compatibilità Azure per #39; rollout/rotazione live non autorizzati.
- Data: 2026-11-15.
- Dipendenze: ADR 0014–0019, 0031–0032, issue #5/#6/#19/#38/#39.
- Specifica ufficiale: [Microsoft Azure CLI — az containerapp secret](https://learn.microsoft.com/en-us/cli/azure/containerapp/secret?view=azure-cli-latest) (le chiavi `--secrets` non possono eccedere **20 caratteri**); [Container Apps — gestione secret e Key Vault](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets) (secret app-scoped e URI versionati).

## Problema

L'ADR 0017 aveva scelto per la candidata HMAC il nome ACA `tenant-proof-key-v<32-hex-version>` (fino a 51 caratteri) mantenendo `tenant-proof-key` per la stable. Terraform e i test offline non imponevano il limite di **20 caratteri** dei nomi ACA. Il plan JSON e il verificador live erano coerenti **tra loro**, ma questo non dimostrava che Azure accettasse la creazione. Durante #38 il nuovo inventario globale ha ricevuto un nome compatto (`pi-<16 hex>`), evidenziando la stessa lacuna nello staging HMAC già esistente.

## Decisione

1. **Secret app-scoped con nome breve, versione verificata tramite URI completo.** La candidata HMAC usa `tp-<primi 16 hex della versione Key Vault>`: 19 caratteri, caratteri consentiti. Il riferimento Key Vault è sempre `https://<vault>.vault.azure.net/secrets/tenant-proof-key/<32 hex>` **completo e immutabile**. `Security__TenantProofKey` punta solo alla secret `tp-...`; `Security__TenantProofKeyId` resta l'ID approvato per il verificatore RLS in PostgreSQL.
2. **Stable preservata.** La secret storica `tenant-proof-key` e il suo URI versione stabile approvata rimangono invariati, così come l'unico ACA/React/.NET/PostgreSQL, l'identità gestita, il pinning HMAC `stable_tenant_proof_secret_version`, i label e traffico **100% stable / 0% candidata**. Nessuna chiave HMAC viene letta, firmata o trasferita tramite Terraform.
3. **Gates aggiornati in tre punti indipendenti.** Terraform `infra/main.tf`, `check-staged-rollout-plan.py` e la verifica **post-apply** `verify-staged-revisions.py` calcolano esattamente lo stesso nome dal prefisso di versione. Il plan gate confronta inoltre il **full URI** e conserva tutte le secret esistenti. Test Python con piani sintetici provano la lunghezza, il nome corretto, l'URI completo, il mancato spostamento del traffico, secret candidate sbagliate, versioni alterate e il verificatore revision live simulato.
4. **Collisione di prefissi: fail closed.** Due versioni distinte possono condividere i primi 16 caratteri (64-bit namespace). Se una secret `tp-<prefix>` è già presente con URI versione diversa, **non si deve sostituire** la vecchia secret application-scoped: il gate esistente confronta tutti gli URI prima/dopo e rifiuta l'update. Serve una nuova procedura approvata, eventualmente un nome compatto alternativo con proprietà di unicità verificabili, senza riutilizzare una chiave in uso.
5. **Versioni legacy.** Eventuali secret con vecchio nome lungo già presenti in un'app preesistente non vengono rimosse automaticamente né rinominate in-place. Se il piano tenterà di eliminarle, il gate fallisce. Una migrazione di secret di revisioni esistenti va gestita come change separato con inventario delle referenze stable, non come refactor non presidiato.
6. **TDD.** RED aggiornando test di staging e revisione simulata prima del codice; GREEN modificando solo la generazione del nome nei tre punti; gate completo CI xUnit/PostgreSQL, React/Playwright, Terraform e test infrastrutturali, NuGet/npm, CodeQL e Docker. Nessuna dipendenza runtime aggiuntiva.

## Alternative respinte e limiti

- Troncare la **versione nell'URI Key Vault**, usare URI versionless/latest o derivare la secret dal valore della chiave: non è sicuro, introduce race o leak.
- Riutilizzare `tenant-proof-key` come nome della candidata: muterebbe una secret application-scoped della stable durante lo staging.
- Assumere che `terraform validate` o la CI con CLI Azure simulata dimostrino una deployability live: non verificano API ARM, Key Vault o approvazione reale.

La correzione elimina un nome manifestamente fuori limite ma **non prova** che lo stage Azure sia riuscito o che la rotazione HMAC sia senza interruzioni. L'attivazione in VNet privata, il pairing della chiave con PostgreSQL, i secret KV e il go-live restano nell'epica #19/#6; il nuovo inventario globale #38 è ancora off per default e richiede approvazioni indipendenti.
