# Inventario dei canali PostgreSQL owner-only

L'[ADR 0088](../../adr/0088-owner-only-psql-copy-global-inventory.md) definisce la guardia generale sulla sicurezza dei comandi `psql` privati. Il manifest [`owner-only-psql-private-input-inventory.json`](owner-only-psql-private-input-inventory.json) elenca **14 script**, ciascuno con una sola operazione locale allowlisted, una categoria di rischio, la relativa issue e solo i **nomi** degli input (mai valori o password).

## Modificare o aggiungere una procedura

Scrivere prima il test RED (`tests/infra/test_owner_psql_copy_inventory.py` e il relativo xUnit/PostgreSQL17), aggiornare il manifest e l'allowlist esatta `INPUTS` dell'helper, preservare ownership, audit, lock, transazioni, idempotenza e divieto al runtime. Ogni procedura usa una sola `\\copy` statica lato client, TEMP `ON COMMIT DROP`, `BEGIN` e `ON_ERROR_STOP`; non usare `psql :'value'` o `\\echo :value`. Le nuove procedure `\\getenv` non inventariate fanno fallire la CI Terraform/Python.

Questa è una verifica **statica**, non dimostra assenza di PII in COPY, TEMP, proxy, errori, pgAudit/Azure/SIEM, backup o retention. Base64(JSON) è reversibile e non crittografia. Sono ancora richiesti runner trusted, CA/hostname PostgreSQL VerifyFull, approvazione di change, MFA/IdP e review Privacy/Security; **#86 resta aperta** per le prove in ambiente reale.
