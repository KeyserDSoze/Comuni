# ADR 0041 — Firma tenant RLS con key ID versionato obbligatorio in Production

- Stato: Accepted per startup API e contratto di staging, **non** per la rotazione Azure live.
- Data: 2026-11-16.
- Issue: #47, sotto #19/#5/#6.
- Dipendenze: ADR 0013–0017, ADR 0040.
- Fonti: [ASP.NET Core configuration](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/), [Terraform variable validation](https://developer.hashicorp.com/terraform/language/values/variables), [PostgreSQL RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

## Problema

Il verifier HMAC RLS riconosce sia la prova `tenantGuid|expiry|nonce|MAC` (legacy) sia la prova a cinque campi con key ID autenticato. Questo è utile per i vecchi processi in una finestra di rotazione, ma la configurazione API precedente consentiva anche a una **nuova** revisione Production di firmare in formato legacy quando `Security:TenantProofKeyId` mancava. Il Terraform `tenant_proof_key_id` aveva inoltre un default vuoto, pur referenziando una versione esplicita di Key Vault. Ciò rendeva possibile uno stage che appariva versionato ma emetteva ancora prove legacy.

## Decisione

1. **Boundary applicativo.** `TenantProofSigningSettings.Read(IConfiguration, environmentName)` crea il signer prima della registrazione dei servizi e delle richieste al DB. Solo `Development` e `Testing` possono usare il formato legacy a quattro campi per demo e test. In `Production`, `Staging` e qualunque altro ambiente hosted, un key ID assente, whitespace o esattamente `legacy` produce `InvalidOperationException` allo startup, senza loggare il secret. Il `TenantProofSigner` già esistente continua a validare pattern ASCII del key ID e minimo 32 byte di chiave. Non è introdotto alcun bypass via flag frontend, token JWT o request.
2. **Boundary di configurazione Terraform.** `tenant_proof_key_id` è obbligatorio, non nullable e senza default, con pattern di 1–32 caratteri minuscoli ASCII e `legacy` esplicitamente vietato. Il GitHub Environment approvato fornisce `TENANT_PROOF_KEY_ID` senza alcun fallback. Il valore HMAC resta fuori da Terraform, e Key Vault mantiene il riferimento a versione esatta. Questi due metadati non dimostrano crittograficamente il pairing col verifier SQL.
3. **Compatibilità nella verifica SQL.** La funzione `platform.verified_tenant_id()` **continua a verificare** le proof legacy delle revisioni stable autorizzate durante grace. Non viene aggiornato lo schema né ritirata automaticamente la chiave `legacy`. La nuova API **non può firmare** senza versione. La stable esistente non viene sostituita automaticamente: candidate revision 0% fino a smoke e approval, poi eventuale promozione solo con consenso umano e piano di rollback (#19/#6).
4. **Rollout e rollback:** prima di stage serve installare come DB owner la nuova chiave ID+materiale, con autorizzazione e audit esterni, predisporre una nuova versione Key Vault e verificarne la corrispondenza con smoke RLS a due tenant sintetici. Se il nuovo processo fallisce l'avvio perché mancano configurazioni, **non** ricadere in legacy: mantenere la stable al 100% e la candidata al 0%, senza ritirare vecchie chiavi. La grace e la revoca delle vecchie key richiedono il procedimento owner-only #46 dopo aver verificato tutte le repliche.
5. **TDD:** RED xUnit per ID assente/legacy in ambiente hosted e regressione Terraform Python, GREEN gate startup + Terraform senza default; tutti i job CI devono essere verdi sulla HEAD prima della chiusura #47.

## Alternative e limiti

Consentire temporaneamente `legacy` in Production tramite un flag sarebbe un bypass permanente difficile da revisionare ed è rifiutato. Eliminare la verifica legacy immediatamente dal DB romperebbe vecchie revisioni durante la finestra di migrazione e pertanto è rifiutato. Il controllo non garantisce che i byte del secret Key Vault coincidano con PostgreSQL, che tutte le revisioni siano drenate o che il runtime di produzione sia stato testato su Azure; #19, #5 e #6 restano aperte.
