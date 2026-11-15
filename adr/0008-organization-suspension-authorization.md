# ADR 0008 — Sospensione organization applicata nelle policy API

- Stato: Accepted
- Data: 2026-11-15
- Issue: #14 (sotto-incremento di #3 e #5)

## Contesto

Una membership attiva non è sufficiente per concedere l'accesso a un Comune sospeso. Il JWT rimane valido fino alla scadenza e i feature flag di un modulo non interrompono ogni endpoint di lettura/scrittura. Prima della console Superadmin serve un blocco globale fail-closed nel layer di autorizzazione.

## Decisione

Aggiungiamo `platform.organizations.is_suspended` (boolean, not null, default false), con migrazione retrocompatibile e metodi DDD `Suspend`/`Reactivate` sull'entità. La policy `OrganizationRoleHandler` consulta PostgreSQL ad **ogni richiesta protetta** e procede alla verifica delle membership soltanto se la organization esiste ed è **non sospesa**. Questo vale per `Read`, `Write` e le nuove policy che riutilizzano lo stesso requisito.

La colonna non è modificabile da endpoint pubblici in questa slice. La futura API di lifecycle e la console Superadmin richiedono autorizzazioni platform, audit e transizioni di stato esplicite (#3 e #10). Liveness/readiness restano endpoint operativi anonimi per il monitoraggio tecnico.

## Conseguenze

- Un JWT valido con membership Admin non autorizza attività su organization sospese: 403.
- Nessun cambio forzato della configurazione dei moduli; la sospensione prevale su ogni feature flag.
- Query PostgreSQL aggiuntiva per ogni autorizzazione protetta, senza cache di stati potenzialmente revocati.
- `is_suspended` è un blocco preliminare e **non** realizza l'intero lifecycle `created/active/suspended`, l'operazione amministrativa di sospensione o la gestione di sessioni OIDC.
- Il controllo è nell'API; non sostituisce PostgreSQL RLS, privilegi minimi, controllo accessi all'archivio e ulteriori gate di sicurezza (#5).
