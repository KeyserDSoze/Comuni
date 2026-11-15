# Deployment Azure

**Una sola piattaforma su Azure.** ADR 0003 sceglie Azure Container Apps (singola app API + SPA), PostgreSQL Flexible Server privato, Blob Storage privato, ACR, Key Vault, Managed Identity e Log Analytics. Tutto l'inventario infrastrutturale è in `infra/`.

## Prerequisiti (fuori dal repository)
- Subscription, permessi Azure per Resource Groups, RBAC e creazione risorse; OIDC federato GitHub → Azure.
- Storage Account e container per backend Terraform remoti **creati prima** del primo `terraform init`; accesso Blob Data Contributor per l'identità del deploy. Lo stato contiene segreti sensibili: RBAC e auditing obbligatori.
- Nome ACR univoco e immagine già pubblicata prima del primo `terraform apply` completo. Inizializzare ACR come bootstrap separato oppure usare un'immagine validata preesistente.
- GitHub Environment `production` con approval, secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `POSTGRES_ADMIN_PASSWORD`; vars `OIDC_AUTHORITY`, `OIDC_AUDIENCE`, `AZURE_PREFIX`, `AZURE_LOCATION`, `ACR_NAME`, `ACR_LOGIN_SERVER`, `TF_STATE_RESOURCE_GROUP`, `TF_STATE_STORAGE_ACCOUNT`, `TF_STATE_CONTAINER`, `TF_STATE_KEY`.
- Il principal deploy deve poter fare ACR push, gestire il Key Vault (Secrets Officer), e creare container Blob Storage.

## Iterazione
1. Test e build passano nella workflow `CI` su main.
2. Le **migrazioni versionate** sono eseguite in modo controllato da un runner con connettività alla subnet PostgreSQL. La pipeline iniziale **non** applica le migrazioni all'avvio in Production; predisporre un task in rete privata prima del primo go-live.
3. Avviare manualmente `Deploy to Azure` in GitHub Actions: login OIDC, build immutabile `comuni:<commit>`, push ACR, plan + apply Terraform sullo stato remoto.
4. Verificare health liveness/readiness, /openapi/v1.json, tenancy, ruoli e log applicativi. Test di restore e alert sono gate operativi prima di dati reali.

## Sicurezza e costi da verificare
- L'isolamento tenant è a livello di applicazione, con filtro EF. Valutare RLS per difesa ulteriore.
- Password Postgres è presente (sensibile) in Terraform State. Valutare autenticazione Entra per Postgres prima di dati reali.
- La connessione DB è privata nella VNet, nessuna porta PostgreSQL pubblica. Web app ha ingresso HTTPS pubblico.
- Key Vault usa RBAC e purge protection; Container Apps ha identity user-assigned, ACR admin disabilitato.
- `Authentication__Mode=Oidc`, `Authentication__Authority` HTTPS e `Authentication__Audience` sono obbligatori per l'API in Production; **non** configurare `Jwt__SigningKey` in Azure. Il login frontend non è ancora realizzato e il provider reale va autorizzato/provisionato prima del go-live.
- Blob Storage è predisposto, ma il modulo documentale non è ancora implementato.
- Controllare consumo di Container Apps, database, Log Analytics, storage e costi networking.
- Fase successiva: login e federazione OIDC con IdP reale, audit completo, retention, backup provati, GDPR DPIA, gestione dati personali, rotazione chiavi, integrazioni AgID e compliance. Non usare il prototipo per protocollazione legale.

## Limiter e reverse proxy Azure (ADR 0010)

Il rate limiter ASP.NET Core è **per replica Container Apps** e non protegge dagli attacchi DDoS distribuiti; in ambienti con `max_replicas > 1` i contatori non sono condivisi. Prima di aprire il servizio a utenti reali pianificare rate limiting all'edge, WAF, metriche 429, test di carico e soglie calibrate sui carichi dei Comuni. Il client IP dietro proxy non è automaticamente quello originale: **non** abilitare globalmente il trust in `X-Forwarded-For` senza elenco preciso di proxy fidati. Valutare un IP limiter basato sul proxy solo dopo convalida della catena di inoltro.

L'API usa header browser di protezione e cache no-store, mentre HTTPS pubblico è terminato da Azure Container Apps. Verificare sul dominio pubblico HTTPS obbligatorio, HSTS e redirect a livello frontiera; **non** configurare inoltri HTTP arbitrari in Kestrel e non dichiarare HSTS verificato fino al deploy reale.
