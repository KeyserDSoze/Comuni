# Inventario dei canali PostgreSQL owner-only

L'[ADR 0088](../../adr/0088-owner-only-psql-copy-global-inventory.md) definisce la guardia generale sulla sicurezza dei comandi `psql` privati. Il manifest [`owner-only-psql-private-input-inventory.json`](owner-only-psql-private-input-inventory.json) elenca **14 script**, ciascuno con una sola operazione locale allowlisted, una categoria di rischio, la relativa issue e solo i **nomi** degli input (mai valori o password).

## Modificare o aggiungere una procedura

Scrivere prima il test RED (`tests/infra/test_owner_psql_copy_inventory.py` e il relativo xUnit/PostgreSQL17), aggiornare il manifest e l'allowlist esatta `INPUTS` dell'helper, preservare ownership, audit, lock, transazioni, idempotenza e divieto al runtime. Ogni procedura usa una sola `\\copy` statica lato client, TEMP `ON COMMIT DROP`, `BEGIN` e `ON_ERROR_STOP`; non usare `psql :'value'` o `\\echo :value`. Le nuove procedure `\\getenv` non inventariate fanno fallire la CI Terraform/Python.

Questa è una verifica **statica**, non dimostra assenza di PII in COPY, TEMP, proxy, errori, pgAudit/Azure/SIEM, backup o retention. Base64(JSON) è reversibile e non crittografia. Sono ancora richiesti runner trusted, CA/hostname PostgreSQL VerifyFull, approvazione di change, MFA/IdP e review Privacy/Security; **#86 resta aperta** per le prove in ambiente reale.

## Profilo pgAudit per i due script con identità OIDC (#116 / ADR 0100)

Il canale COPY da solo **non impedisce** che pgAudit registri variabili PL/pgSQL passate come parametri nei DML. Nei test reali con `pgaudit.log_parameter=on` è stato rilevato un canary sintetico. `register-organization.sql` e `bootstrap-initial-admin.sql` ora rifiutano questo profilo **prima del COPY**. Per la sola verifica offline, lo script psql usa `pgaudit.log_parameter=off` con `pgaudit.log=role,ddl,write,function` e logging degli statement ancora attivo: i metadati delle operazioni rimangono visibili. Non impostare `pgaudit.log=none`. Questo vincolo NON copre automaticamente gli altri 12 script, pgAudit Azure, proxy, errori, SIEM o payload COPY; l'uso reale resta vietato fino a review Security/Privacy #86/#92 e approvazione IdP #84.

## Estensione #117 — activation ed enrollment Admin (ADR 0101)

Dopo `register-organization.sql` e `bootstrap-initial-admin.sql`, anche `activate-organization.sql` ed `enroll-additional-admin.sql` rifiutano `pgaudit.log_parameter=on` **prima della COPY client-side** con errore costante, mantenendo gli eventi FUNCTION/WRITE/DDL/ROLE e le statement PostgreSQL nel test sintetico. La fixture PostgreSQL17/pgAudit reale esercita l'intero lifecycle di questi quattro script con canary sintetici OIDC/Comune/reviewer/ticket e rifiuto del profilo unsafe senza echo. Nessuna nuova operazione è stata aggiunta all'inventory v1 (14 script). Non dedurre che gli altri dieci script siano protetti, che base64 cripta i dati o che i log e gli accessi Azure/SIEM siano stati validati: #86/#92/#84 rimangono bloccanti per l'uso reale.
