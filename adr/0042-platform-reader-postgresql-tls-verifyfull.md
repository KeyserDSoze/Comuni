# ADR 0042 — Identità TLS PostgreSQL verificata per l'inventario globale Superadmin

- Stato: Accepted per la **validazione all'avvio** del reader SQL globale opt-in, non per rollout Azure.
- Data: 2026-11-16.
- Issue: #48, sotto #38/#5/#6.
- Dipendenze: ADR 0031–0034 e 0041.
- Documenti tecnici: [Npgsql SSL modes](https://www.npgsql.org/doc/api/Npgsql.SslMode.html), [Npgsql connection string security](https://www.npgsql.org/doc/connection-string-parameters), [Microsoft Learn — Azure PostgreSQL TLS](https://learn.microsoft.com/en-us/azure/postgresql/security/security-tls-how-to-connect), [Microsoft Learn — certificate rotation/troubleshooting](https://learn.microsoft.com/en-us/azure/postgresql/security/security-tls-troubleshoot).

## Problema

Il login `comuni_platform_reader` può leggere un inventario **cross-organization** di metadati, benché non le tabelle comunali. Anche con feature opt-in, la precedente guardia accettava `SSL Mode=Require` (cifra, ma non implica validazione dell'identità TLS) e `VerifyCA` (non verifica il nome host). Un endpoint PostgreSQL non attendibile/MITM potrebbe intercettare autenticazione e metadati. Il valore del secret arriva da Key Vault tramite l'unica API, ma il trasporto SQL deve verificare il peer indipendentemente dal vault.

## Decisione

1. **Boundary hosted:** se l'inventario è **ON** e l'environment non è `Development`/`Testing`, `PlatformInventorySettings.Read` accetta soltanto `SslMode.VerifyFull` e `TrustServerCertificate == false`. È richiesto il certificato server verificabile dalla CA, con identità DNS corrispondente all'host della connessione. Sono rifiutati `Disable`, `Prefer`, `Require`, `VerifyCA` e il bypass della validazione, compresi gli input che combinano `VerifyFull` con `Trust Server Certificate=true`. Le verifiche già presenti su `OIDC`, username reader esclusivo, stesso database/host/porta e password non vuota restano in vigore. Errori non riportano password né connection string.
2. **Compatibilità di test, non bypass prod:** i test xUnit PostgreSQL 17 e gli ambienti locali usano `Development`/`Testing` e non devono possedere PKI/TLS reali; rimangono invariati. In Production/Staging l'abilitazione del flag **fallisce al bootstrap** se il secret `ConnectionStrings:PlatformRead` non è stato preparato con VerifyFull e CA attendibile; non disabilita automaticamente il controllo. La feature è OFF per default e non viene attivata da questa modifica.
3. **Preparazione Azure:** predisporre esternamente il valore della stringa reader in Key Vault con FQDN PostgreSQL completo e modalità VerifyFull, e gestire un trust store appropriato nel container. Non usare IP/alias DNS la cui identità non combaci con il certificato, non inserire certificati/chiavi private nel repository, non pin-are certificati leaf/intermedi soggetti a rotazione; verificare CA/rinnovi con un test live e rollback approvato. L'URI versionato Key Vault e le release candidate ACA già previste da ADR 0032 restano i soli riferimenti Terraform, mai il valore della credenziale.
4. **TDD:** RED xUnit `PlatformInventoryTlsSettingsTests` e contratto infra `test_platform_inventory_tls.py` richiedono matrice di SSL modes, bypass negato, un reader valido, OIDC/SQL identity invariati e modalità locale. GREEN modifica minimamente il guard esistente. CI completa 7/7 prima di chiudere la sotto-issue.
5. **Confini non risolti:** il percorso normale `ConnectionStrings:Default` della singola API usa attualmente `SSL Mode=Require` tramite un secret gestito da Terraform. Questo gate **non lo modifica**: cambiare il valore della secret app-scoped `postgres-connection` potrebbe influire sulle revisioni stable, e necessita un piano di deploy, aggiornamento della connessione e test distinti su #5/#6. Non è verificata una connessione Azure reale né la corrispondenza della password SQL limitata, dell'IdP/MFA o l'assenza di PII.

## Alternative rifiutate

- `SSL Mode=Require`: cifratura senza validazione robusta della controparte, insufficiente per letture cross-Comune.
- `VerifyCA` o `Trust Server Certificate=true`: rischi di DNS spoof o disattivazione della verifica.
- Imporre VerifyFull ai test CI senza PKI: interferisce con il test dell'isolamento tenant locale e non aggiunge prova di Azure.
- Modificare nello stesso commit il secret runtime preesistente: introdurrebbe una mutazione globale/stable non approvata fuori dallo scope dell'inventario.
