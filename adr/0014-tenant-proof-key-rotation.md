# ADR 0014 — Verifica RLS multi-key e rotazione in fasi (slice #20)

- Stato: Accepted come primitiva applicativa/DB; rollout Azure ancora **non verificato** (#19/#6)
- Data: 2026-11-15
- Dipendenze: ADR 0013 e #18
- Fonti ufficiali: [PostgreSQL 17 RLS](https://www.postgresql.org/docs/17/ddl-rowsecurity.html), [SECURITY DEFINER](https://www.postgresql.org/docs/17/sql-createfunction.html), [pgcrypto](https://www.postgresql.org/docs/17/pgcrypto.html)

## Problema

Un solo segreto condiviso tra API e DB rende impossibile sostituire la chiave senza interrompere richieste servite da repliche che non hanno ancora ricevuto il nuovo segreto. La rotazione deve permettere alla vecchia chiave di continuare a funzionare **solo** per un periodo controllato, mentre un'altra versione viene installata e verificata. Il ruolo `comuni_app_runtime` non deve poter scegliere arbitrariamente un'altra organization, vedere la chiave, ripristinare chiavi revocate né firmare prove tramite SQL.

## Decisione

La migration `202611150007_VersionedTenantProofKeys` aggiunge la tabella owner-only `platform.tenant_proof_keys`, con:
- `key_id` allowlist ASCII minuscola (max 32 caratteri)
- `signing_key` (almeno 32 byte)
- `not_before`, `valid_until`, `revoked_at`

Il verifier `platform.verified_tenant_id()` resta `SECURITY DEFINER` con search_path controllato. Valida regex, timestamp della proof (fino a 300 secondi futuri), finestra di validità e stato di revoca, poi calcola l'HMAC della **versione specificata**, senza fallback. Prove con ID alterato, chiave scaduta o revocata ritornano `NULL` (RLS fail-closed). Le cinque RLS esistenti continuano a invocare questa funzione senza esporre una routine SQL di firma.

Nuovo payload: `keyId|organizationGuidN|expiryUnix|nonceGuidN|hmacSha256`; il key ID è incluso nel testo firmato. Vecchio payload: `organizationGuidN|expiryUnix|nonceGuidN|hmacSha256`, ammesso *soltanto* quando il record `legacy` non è ritirato. La migrazione importa l'eventuale vecchio segreto nella tabella nuova, preservando l'accesso delle repliche precedenti. **Il supporto legacy non va mantenuto indefinitamente:** un operatore autorizzato ne deve pianificare il ritiro.

La configurazione API `Security:TenantProofKeyId` (vuota = legacy) determina la versione emessa; `Security:TenantProofKey` resta un segreto. Gli script SQL owner-only `stage-tenant-proof-key.sql` e `retire-tenant-proof-key.sql` controllano validità, idempotenza e revoca; stage non sovrascrive né riattiva ID già ritirati, retire può soltanto **accorciare** la validità e, con grace 0, revocare immediatamente. Bootstrap legacy separato da rotation.

## Ordine operativo di massima (da verificare in Azure)

1. Eseguire migration con owner, preservando `legacy`; verificare le repliche vecchie sotto RLS.
2. Stagiare una nuova `TENANT_PROOF_KEY_ID` e secret tramite runner **privato**, con accessi owner controllati.
3. Pubblicare versione applicativa/Key Vault con la stessa coppia ID/secret; verificare tutte le repliche e chiamate multi-organization.
4. Impostare un grace `valid_until` sul vecchio ID che copra latenza, vecchie repliche e TTL di 3 minuti.
5. Revocare/accertare expirazione del vecchio ID soltanto quando nessuna replica lo usa; verificare che la vecchia proof sia negata.

**Non automatizzare il passo 5 sulla sola base della CI**. Il workflow Azure attuale non possiede un migration runner privato né un coordinatore di rollout, e Terraform contiene ancora il secret in State. #19 deve realizzare validazione di concorrenza/rollback, Key Vault, backup, non-log delle proof e approvazioni. Il downgrade della migration è volutamente proibito: ripristinare il verifier single-key riabiliterebbe un segreto revocato.

## Threat model e residui

Il runtime SQL resta privo di SELECT/UPDATE sulla tabella delle chiavi, non può creare nuovi MAC per altri tenant e le proof sono sempre transaction-local. Una proof valida carpita può essere ripetuta fino alla scadenza **o prima della revoca**, un'API compromessa può creare prove, l'owner/superuser bypassa RLS. Il confronto HMAC in plpgsql non è dichiarato constant-time. La finestra di grace, la sincronizzazione dell'orologio e le transazioni lunghe sono rischi operativi da verificare. Questo incremento **non** certifica sicurezza su Azure né conformità GDPR/AgID.

## Evoluzione — ADR 0040 / issue #46

Il percorso di ritiro ordinario richiede ora un **ID sostitutivo esplicito** e una guardia transazionale serializzata (chiave sana per tutta grace+300 s). Il comportamento precedente che consentiva di revocare l'ultimo ID senza verificare il successore è stato eliminato dal runner owner-only. Si mantiene l'eccezione soltanto tramite processo *break-glass* separato, fuori dallo script ordinario; il verificatore RLS e la semantica delle proof restano invariati. Il controllo DB non sostituisce smoke live su Key Vault/API, approvazioni, backup o test Azure, quindi #19 rimane aperta.
