# ADR 0040 — Ritiro RLS HMAC protetto da una chiave sostitutiva attiva

- Stato: Accepted come **guardia SQL per runner owner offline**, non garanzia Azure di zero-downtime.
- Data: 2026-11-16
- Issue: #46, sotto #19/#5, dipende da #6.
- Fonti: [PostgreSQL 17 LOCK](https://www.postgresql.org/docs/17/sql-lock.html), [explicit locking](https://www.postgresql.org/docs/17/explicit-locking.html), ADR 0014–0017 e 0034.

## Problema

Il ritiro originale `scripts/postgres/retire-tenant-proof-key.sql` poteva revocare una versione HMAC senza richiedere un successore. Anche dopo uno stage multi-key corretto, due operatori che ritirassero due versioni una contro l'altra potrebbero terminare con nessuna delle due valida, bloccando la RLS comunale. La verifica di un deploy Azure **non** può essere ottenuta soltanto con metadati di Key Vault o con il controllo su tabella.

## Decisione

1. Il comando di retirement owner richiede `TENANT_PROOF_RETIRE_KEY_ID`, `TENANT_PROOF_GRACE_SECONDS` (0–3600), e il **nuovo** `TENANT_PROOF_REPLACEMENT_KEY_ID` con la stessa allowlist ASCII del key ID, distinto dal target. Non richiede mai la chiave segreta, non stampa ID/materiale e non amplia GRANT. Non introdurre il controllo su tenant API/SPA.
2. In **un'unica transazione** PostgreSQL la procedura ottiene `LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE` con timeout e valida il target esistente e il successore: `revoked_at IS NULL`, `not_before <= clock_timestamp()`, e `valid_until > clock_timestamp() + grace_seconds + 300s`. Il margine 300 secondi copre il massimo orizzonte della proof ammesso da `verified_tenant_id()`; il signer oggi usa 180 secondi. Questo limita i ritiri senza alternativa e i ritiri reciproci, ma **non** dimostra che il successore sia il signer in uso in ogni replica.
3. `UPDATE` accorcia `valid_until` con `least()` e valorizza `revoked_at` soltanto se grace=0, preservando il valore già impostato. Retry non estendono né riabilitano. Qualunque errore, timeout o input non valido fallisce chiuso senza persistenza. Revoca e guardia restano accessibili solo al proprietario SQL, non al runtime. `SHARE ROW EXCLUSIVE` è self-conflicting e confligge con `ROW EXCLUSIVE` degli scrittori: si evita il double-retire in letture concorrenti, mantenendo SELECT ordinarie del verifier.
4. La CI con PostgreSQL 17 passa explicitamente `TENANT_PROOF_REPLACEMENT_KEY_ID=legacy` per il **solo** scenario di rotazione sintetica, eseguendo prima il provisioning legacy; non è un flag da impostare in production senza uno stage verificato. Test RED/GREEN xUnit invocano `psql`, usano tenant sintetici e verificano RLS prima/dopo, rollback su input invalido, ruoli, idempotenza e due ritiri concorrenti.
5. **Limitazione deliberate/break-glass:** un DB owner/superuser può ancora bypassare ogni script; una chiave sostitutiva sana **nel DB** non garantisce che la revisione candidata usi la versione Key Vault corretta, che tutte le repliche precedenti siano drenate o che il clock sia sincronizzato. La revoca di emergenza dell'**ultima** chiave non può usare lo script ordinario: richiede incident/change indipendente con approvazione, audit esterno, verifica dell'impatto e SQL owner eccezionale tracciato. Niente automatismo di ritiro dalla CI/release Azure. #19 e #6 restano aperte fino al test reale di stage/rollback in VNet.

## Alternative scartate

Un controllo non transazionale di `COUNT(*)` chiavi attive sarebbe vulnerabile al race del ritiro reciproco. Permettere `force=true` nello script ordinario aggirerebbe la guardia senza un processo di emergency review. Fidarsi dei soli metadati Key Vault non prova l'effettivo materiale HMAC in PostgreSQL. L'opzione scelta mantiene una sola API, un solo frontend e un solo PostgreSQL.

## Evoluzione trasporto input (#103 / ADR 0087)

Questa ADR descrive le invarianti originarie della guardia (successore active per grace+300 secondi, lock SHARE ROW EXCLUSIVE, update monotono, retry e concorrenza). Dopo #103 il trasporto **non** interpola più `:'retire_id'`, `:'replacement_id'`, `:'grace_secs'` in SQL: i tre metadati owner-only transitano tramite `\\copy` client-side statico da `stream-private-input.py retire-tenant-proof` con allowlist, TEMP `ON COMMIT DROP` e `current_setting` transaction-local. La validazione di formato ora si svolge **dentro** la stessa transazione, prima del lock; in caso di errore `psql ON_ERROR_STOP` chiude e PostgreSQL annulla TEMP/GUC e qualsiasi scrittura, senza alterare la guardia.

I metadati ID e grace restano sensibili e **base64(JSON) è reversibile**: il test PostgreSQL17 verifica solo il testo degli statement sotto `log_statement=all` e non copre payload COPY, estensioni pgAudit, Azure/SIEM, backup o retention. Nessun permesso in più al runtime, né prova di rollout effettivo o autorizzazione alla rotazione di chiavi reali. #19/#86/#49/#92 restano aperte.
