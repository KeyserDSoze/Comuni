# Deployment Azure

**Una sola piattaforma su Azure.** ADR 0003 sceglie Azure Container Apps (singola app API + SPA), PostgreSQL Flexible Server privato, Blob Storage privato, ACR, Key Vault, Managed Identity e Log Analytics. Tutto l'inventario infrastrutturale è in `infra/`.

## Prerequisiti (fuori dal repository)
- Subscription, permessi Azure per Resource Groups, RBAC e creazione risorse; OIDC federato GitHub → Azure.
- Storage Account e container per backend Terraform remoti **creati prima** del primo `terraform init`; accesso Blob Data Contributor per l'identità del deploy. Lo stato contiene segreti sensibili: RBAC e auditing obbligatori.
- Nome ACR univoco e immagine già pubblicata prima del primo `terraform apply` completo. Inizializzare ACR come bootstrap separato oppure usare un'immagine validata preesistente.
- GitHub Environment `production` con approval, secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `POSTGRES_ADMIN_PASSWORD` (solo owner/migrazioni) e `POSTGRES_RUNTIME_PASSWORD` (login `comuni_app_runtime`); vars `OIDC_AUTHORITY`, `OIDC_AUDIENCE`, `AZURE_PREFIX`, `AZURE_LOCATION`, `ACR_NAME`, `ACR_LOGIN_SERVER`, `TF_STATE_RESOURCE_GROUP`, `TF_STATE_STORAGE_ACCOUNT`, `TF_STATE_CONTAINER`, `TF_STATE_KEY`.
- Il principal deploy deve poter fare ACR push, gestire il Key Vault (Secrets Officer), e creare container Blob Storage.

## Iterazione
1. Test e build passano nella workflow `CI` su main.
2. Le **migrazioni versionate** sono eseguite in modo controllato da un runner con connettività alla subnet PostgreSQL, con account owner. **Dopo le migrazioni**, provisionare o ruotare `comuni_app_runtime` con `scripts/postgres/provision-runtime-role.sql` (variabile ambientale `RUNTIME_DB_PASSWORD`) prima di aggiornare l'immagine. L'applicazione Azure **non riceve** la password owner. La pipeline iniziale **non** applica migrazioni o provisioning via rete privata, pertanto è un **gate manuale** obbligatorio e manca ancora un job di migrazione automatizzato: #6.
3. Avviare manualmente `Deploy to Azure` in GitHub Actions: login OIDC, build immutabile `comuni:<commit>`, push ACR, plan + apply Terraform sullo stato remoto.
4. Verificare health liveness/readiness, /openapi/v1.json, tenancy, ruoli e log applicativi. Test di restore e alert sono gate operativi prima di dati reali.

## Sicurezza e costi da verificare
- L'isolamento tenant è a livello di applicazione, con filtro EF. Valutare RLS per difesa ulteriore.
- Password dell'owner **e del runtime** sono ancora presenti (sensibili) nel Terraform State; limitare rigorosamente RBAC e auditing sul backend remoto. La password owner serve solo alla risorsa server, **mai alla connessione dell'app**. Prima del rollout reale, effettuare il bootstrap del ruolo e ruotare qualsiasi password amministrativa precedentemente consegnata al runtime. Valutare autenticazione Entra per Postgres prima di dati reali.
- La connessione DB è privata nella VNet, nessuna porta PostgreSQL pubblica. Web app ha ingresso HTTPS pubblico.
- Key Vault usa RBAC e purge protection; Container Apps ha identity user-assigned, ACR admin disabilitato.
- `Authentication__Mode=Oidc`, `Authentication__Authority` HTTPS e `Authentication__Audience` sono obbligatori per l'API in Production; **non** configurare `Jwt__SigningKey` in Azure. Il login frontend non è ancora realizzato e il provider reale va autorizzato/provisionato prima del go-live.
- Blob Storage è predisposto, ma il modulo documentale non è ancora implementato.
- Controllare consumo di Container Apps, database, Log Analytics, storage e costi networking.
- Fase successiva: login e federazione OIDC con IdP reale, audit completo, retention, backup provati, GDPR DPIA, gestione dati personali, rotazione chiavi, integrazioni AgID e compliance. Non usare il prototipo per protocollazione legale.

## Limiter e reverse proxy Azure (ADR 0010)

Il rate limiter ASP.NET Core è **per replica Container Apps** e non protegge dagli attacchi DDoS distribuiti; in ambienti con `max_replicas > 1` i contatori non sono condivisi. Prima di aprire il servizio a utenti reali pianificare rate limiting all'edge, WAF, metriche 429, test di carico e soglie calibrate sui carichi dei Comuni. Il client IP dietro proxy non è automaticamente quello originale: **non** abilitare globalmente il trust in `X-Forwarded-For` senza elenco preciso di proxy fidati. Valutare un IP limiter basato sul proxy solo dopo convalida della catena di inoltro.

L'API usa header browser di protezione e cache no-store, mentre HTTPS pubblico è terminato da Azure Container Apps. Verificare sul dominio pubblico HTTPS obbligatorio, HSTS e redirect a livello frontiera; **non** configurare inoltri HTTP arbitrari in Kestrel e non dichiarare HSTS verificato fino al deploy reale.

## Provisioning dell'account PostgreSQL applicativo (#16)

**Migrazione e provisioning sono due fasi distinte.** Esempio (su runner con accesso alla VNet privata, connessione TLS al PostgreSQL Flexible Server e `psql` installato; valori ambiente letti da un sistema segreti, non scritti in shell history):

```bash
# 1. Configurare ConnectionStrings__Default con credenziale schema-owner,
#    poi eseguire migrazioni EF fuori dal runtime applicativo:
bash scripts/migrate.sh

# 2. Il provisioning legge RUNTIME_DB_PASSWORD direttamente dall'ambiente
#    ed è idempotente; PGPASSWORD autentica l'owner presso PostgreSQL.
psql "host=<private-pg-host> port=5432 dbname=comuni user=<schema-owner> sslmode=require" \
  -v ON_ERROR_STOP=1 -f scripts/postgres/provision-runtime-role.sql

# 3. Aggiornare Terraform dopo aver configurato POSTGRES_RUNTIME_PASSWORD
#    e verificato l'accesso con la nuova utenza.
```

L'utenza fissa `comuni_app_runtime` riceve solo `USAGE` schema, SELECT tabelle del Core e Protocollo, INSERT su `protocol.records` e `platform.audit_events`, UPDATE esclusivo della colonna `enabled` in `platform.organization_modules`. Nessuna modifica di utenti, organizzazioni, audit esistenti, nessuna creazione tabelle né accesso alla history di EF. **Nessun GRANT automatico alle tabelle future**: ogni migrazione che aggiunge domini deve ampliare esplicitamente la allowlist con review e test. L'account non deve appartenere a ruoli proprietari/amministrativi.

La CI su PostgreSQL 17 esegue lo stesso script **due volte** dopo le migrazioni, verifica il login separato e gli accessi negati/consentiti con xUnit. In locale Docker Compose resta intenzionalmente configurato con account privilegiato per la migrazione automatica in Development; **non** riusare questo schema o le password dimostrative su Azure.

**Limitazione critica:** questo riduce i privilegi DDL e amministrativi, ma NON è isolamento row-level tra Comuni: l'account condiviso può leggere le righe tenant-owned in SQL diretto finché non viene adottato un contesto PostgreSQL trusted con RLS fail-closed. Valutazione di `SET LOCAL` e pooling, enforcement e test raw SQL restano nella #5.

## Tenant RLS — ordine migrazioni e connessioni (#17)

La migration `202611150005_TenantRowLevelSecurity` abilita RLS su cinque tabelle tenant-owned. Applicarla **con ruolo owner** prima di eseguire nuovamente `scripts/postgres/provision-runtime-role.sql` e prima di promuovere la nuova API. L'API in produzione deve usare **soltanto** `comuni_app_runtime` non owner: l'owner/superuser bypassa RLS. Testare con il login runtime e due organization distinte la lettura senza contesto (0), `SET LOCAL` transaction-local, rollback/commit con connessioni riusate e POST con audit. Le policy SQL non richiedono un nuovo database o servizio Azure.

**Gate di go-live:** la RLS basata su custom GUC PostgreSQL non resiste a SQL arbitrario sotto lo stesso login: un attaccante che possa eseguire `set_config` potrebbe cambiare organization. Definire il threat model e il binding non falsificabile prima di dati reali; #5 resta aperta. Il job privato Azure per migrare/provisionare continua a mancare (#6). Test di connessioni pooled sotto carico e rollout blue/green da verificare in Azure.
