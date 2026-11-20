# TDD catalogo Core e flag fail-closed (#128)

## RED prima del codice

- Commit test [`8826fe8`](https://github.com/KeyserDSoze/Comuni/commit/8826fe876ae9a6627168b5edec2e674b2a97e30b), [Actions 44811608046](https://github.com/KeyserDSoze/Comuni/actions/runs/44811608046): 375 test API precedenti passati, **3 nuovi test API falliti** su endpoint catalogo e flag estraneo; Playwright: **1 nuovo test fallito** perché Archivio non compare come Pianificato.
- `tests/backend/Comuni.Api.Tests/ModuleCatalogApiTests.cs` usa real PostgreSQL17. Crea due Comuni sintetici con membership Admin/Reader/Officer. Inserisce nel Comune A `platform.organization_modules(archive,true)` **solo via owner test fixture**, oltre al flag protocol. Verifica GET catalog 12 key, 11 planned no dependences/configuration, Protocollo per-tenant, 401 anonimo/403 Reader/Officer/JWT role-forged, PUT future=404, niente audit, GET context e GET legacy ignorano archive, Comune B immutato.
- `tests/frontend/admin-modules.spec.ts` verifica area Admin, toggle Protocollo e status planned di Archivio senza pulsante e senza menu. Le altre fixture Admin audit/membership devono rispondere al nuovo endpoint per testare la UI senza errori di rete simulati.

## Gate GREEN

CI su uno **stesso SHA finale HEAD main**: xUnit unit/backend/PostgreSQL17 con SQL login limitato e test RLS già previsti, real pgAudit SCRAM/COPY e file sink, React build e Playwright, Terraform/Python, CodeQL C#/TS, NuGet/npm audit, immagine Docker. **7/7 success** prima della chiusura. Nessun mock browser equivale a prova di autorizzazione: l'API esercita la policy `Admin` e il database SQL reale, il frontend riflette soltanto metadati server.

## Limiti

Il catalogo non implementa domini planned, non presume dipendenze interdominio, non comprova conservazione/ANPR/tributi a norma. La riga `archive=true` è unicamente un test di fault injection su database disposable; non eseguire su Comuni reali. OIDC, Azure, Superadmin e revisione GDPR/AgID rimangono gate separati.
