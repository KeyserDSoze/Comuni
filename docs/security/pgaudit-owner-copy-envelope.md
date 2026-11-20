# Runbook — payload completo delle procedure owner-only e logging PostgreSQL

**Applicabilità:** gate sintetico #124 / ADR 0108, 12 script owner-only non-SCRAM inventariati in `docs/security/owner-only-psql-private-input-inventory.json`. Non è una procedura approvata per dati reali.

## Principio

Il producer `stream-private-input.py` crea un record `base64(JSON)` contenente più valori privati. **Base64 non è cifratura.** Il test SQL e il client devono preservare la registrazione dei metadati amministrativi, senza rendere visibile il record intero in log di PostgreSQL, pgAudit o output di `psql`. Guardare soltanto ogni `iss`, `sub`, change ticket o chiave singolarmente è insufficiente: l'intera riga codificata può eludere la ricerca per stringa individuale.

Il runner CI conserva temporaneamente soltanto input **sintetici**, il nome di ciascuno dei 12 script e l'output client combinato stdout/stderr. Dopo tutte le operazioni (anche le fallite), ricostruisce il record come lo codifica esattamente l'helper, lo ricerca nel log server completo e nell'output client e restituisce solo un esito booleano tramite diagnostica costante. L'esito GREEN richiede anche che **tutti e 12** gli script siano effettivamente invocati, non soltanto dichiarati.

## Policy invarianti

Il profilo delle dodici procedure non-SCRAM mantiene `pgaudit.log=role,ddl,write,function`, `log_statement=all`, error logging attivo e `pgaudit.log_parameter=off` **limitatamente alla visibilità dei valori**, con preflight prima del COPY. I due provisioner SQL/SCRAM seguono la differente policy di redazione `ROLE/DDL` di ADR 0076/0098/0107; non sostituirla indiscriminatamente. La fixture non deve pubblicare stdout/stderr grezzo, Docker logs, payload, verifier, signing key, derivati o frammenti.

## Verifica necessaria prima di un ambiente autorizzato

Verificare con owner DBA e responsabili Security/Privacy: configurazione effettiva PostgreSQL Azure, pgAuditLogToFile, parameter logging, errore/context, collectors/SQL proxy, agent APM, destinazioni SIEM e retention, accessi privilegiati, TLS VerifyFull, gestione secret Key Vault, approvazioni e rollback. Usare esclusivamente canary e ambiente per cui esiste un mandato; una fuga in qualunque destinazione va trattata come un blocco, non disabilitando audit per ottenere un verde. **Non dichiarare conformità o protezione dei log di produzione in base alla sola CI locale.** Dipendenze aperte #86/#92/#89/#19.
