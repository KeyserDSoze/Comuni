# Deployment Azure

**Una sola piattaforma su Azure.** ADR 0003 sceglie Azure Container Apps (singola app API + SPA), PostgreSQL Flexible Server privato, Blob Storage privato, ACR, Key Vault, Managed Identity e Log Analytics. Tutto l'inventario infrastrutturale è in `infra/`.

## Prerequisiti (fuori dal repository)
- Subscription, permessi Azure per Resource Groups, RBAC e creazione risorse; OIDC federato GitHub → Azure.
- Storage Account e container per backend Terraform remoti **creati prima** del primo `terraform init`; accesso Blob Data Contributor per l'identità del deploy. Lo stato contiene segreti sensibili: RBAC e auditing obbligatori.
- Nome ACR univoco e immagine già pubblicata prima del primo `terraform apply` completo. Inizializzare ACR come bootstrap separato oppure usare un'immagine validata preesistente.
- GitHub Environment `production` con approval, secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `POSTGRES_ADMIN_PASSWORD` (solo owner/migrazioni), `POSTGRES_RUNTIME_PASSWORD` (login `comuni_app_runtime`) ; vars `OIDC_AUTHORITY`, `OIDC_AUDIENCE`, `AZURE_PREFIX`, `AZURE_LOCATION`, `ACR_NAME`, `ACR_LOGIN_SERVER`, `TF_STATE_RESOURCE_GROUP`, `TF_STATE_STORAGE_ACCOUNT`, `TF_STATE_CONTAINER`, `TF_STATE_KEY`.
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

## Attivazione e rotazione delle prove tenant firmate (#18)

L'API di produzione ora **fallisce all'avvio** se `Security:TenantProofKey` manca o ha meno di 32 byte UTF-8. Il segreto è referenziato con URI versionless da Azure Container Apps ma **è creato esternamente a Terraform**, fuori da `TF_VAR_*` e non attraverso il workflow di deploy. Gli state snapshot Terraform delle revisioni precedenti potrebbero ancora includerne il valore: vedi ADR 0015. Questo valore deve corrispondere alla chiave memorizzata sotto ruolo owner in PostgreSQL.

1. Prima di `CREATE EXTENSION pgcrypto`, Terraform deve abilitare l'estensione nel Flexible Server (`azure.extensions=PGCRYPTO`). Il workflow di deploy attuale non garantisce l'ordine di bootstrap della rete privata: #6 resta bloccante.
2. Con ruolo owner in VNet privata, eseguire le migrazioni EF fino a `202611150006_SignedTenantRlsProof`.
3. Sullo **stesso database**, con `TENANT_PROOF_KEY` popolato da secret store (non da comando stampato a video) eseguire `psql -v ON_ERROR_STOP=1 -f scripts/postgres/provision-tenant-proof.sql`; se manca la chiave, lo script rifiuta l'operazione. Eseguire nuovamente `scripts/postgres/provision-runtime-role.sql` per il GRANT EXECUTE della funzione al ruolo runtime.
4. Attivare la versione dell'API che usa la medesima chiave e verificare in smoke test la lettura A/B, RLS senza proof, spoof con proof invalida, audit transazionale e riuso connessioni.

**Rotazione:** scrivere una nuova chiave DB mentre è attiva la vecchia app provoca richieste non autorizzate; fare rolling update del segreto senza protocollo di doppia chiave non è zero-downtime. Richiede una procedura versionata e testata (issue #18/#6) prima del go-live. **Mai** distribuire la chiave in source, tfvars, browser o log; usare secret store e TLS. Prove attuali sono su PostgreSQL 17 in CI, non su Azure reale.

## Stage/grace/revoke delle versioni RLS (ADR 0014 / issue #20)

Questa procedura stabilisce l'ordine **tecnico**, non è ancora un runbook Azure verificato. Richiede un runner con `psql` e connessione privata TLS da un'identità schema-owner. Esclude il login runtime e non deve stampare i segreti.

1. Eseguire migration `202611150007_VersionedTenantProofKeys` prima di aggiornare le API. La chiave precedente viene importata sotto l'ID `legacy`; verificare che le API esistenti continuino ad accedere ai soli tenant autorizzati.
2. Generare fuori dal repository una nuova chiave random da almeno 32 byte e assegnare un ID univoco (es. `rotate_2026_11`). Popolare `TENANT_PROOF_KEY_ID` e `TENANT_PROOF_KEY` con il secret store autorizzato, poi eseguire `psql ... -f scripts/postgres/stage-tenant-proof-key.sql` come owner. Lo script non sovrascrive o riattiva gli ID esistenti: se fallisce, **non** proseguire il rollout.
3. Distribuire la nuova configurazione API `Security__TenantProofKeyId` e `Security__TenantProofKey` da Key Vault con approvazione. Anche la variabile Terraform `tenant_proof_key_id` e GitHub Environment `TENANT_PROOF_KEY_ID` devono coincidere. Verificare ogni replica ed endpoint API, con monitoraggio di 403/5xx e accessi RLS.
4. Solo dopo la verifica del rollout, scegliere un grace in secondi (da 0 a 3600), più lungo della vita delle proof residue (3 minuti), e fornire `TENANT_PROOF_RETIRE_KEY_ID=legacy`, `TENANT_PROOF_GRACE_SECONDS=...`; eseguire `psql ... -f scripts/postgres/retire-tenant-proof-key.sql`. Lo script **accorcia soltanto** la finestra e con `0` revoca subito. Un ID scaduto/revocato non può essere riattivato dagli script.
5. Verificare con test di negazione che la vecchia proof ritorni zero righe e quella nuova conservi il proprio tenant. Non includere mai proof/secret nei log. In caso di problemi **prima della revoca**, rollback dell'app alla precedente versione mentre la chiave legacy è ancora valida. **Dopo la revoca**, rollback richiede un nuovo key ID/staging e un deployment coordinato; non reinstallare ciecamente il verifier legacy.

**Gap P0 #19/#6:** runner Azure privato, doppia revisione attiva, provisioning esterno Key Vault, test carico multi-replica e connessioni pooled, controllo del clock skew, allarmi e rollback devono essere realizzati e collaudati prima di qualunque produzione reale. ADR 0015 riduce l'esposizione della chiave HMAC nel **nuovo** Terraform State ma non cancella le revisioni precedenti.

## Key Vault RLS fuori da Terraform State — ADR 0015, issue #21

**Il secret `tenant-proof-key` deve esistere ed essere abilitato prima del deploy.** La configurazione Terraform non contiene più `var.tenant_proof_key` né gestisce `azurerm_key_vault_secret.tenant_proof_key`. Container Apps riceve il riferimento versionless `https://<vault>.vault.azure.net/secrets/tenant-proof-key`; i valori restano in Key Vault e nella tabella owner-only di PostgreSQL, non nei nuovi `terraform plan`/state relativi a questo secret. Lo stato continua a contenere **altre** credenziali sensibili (password PostgreSQL), che richiedono gestione separata.

### Procedura sicura per un'installazione preesistente

1. Prima di qualunque `terraform apply`, ottenere backup protetto dello state e approvazione change management. Lo state precedente **contiene** il segreto HMAC, anche nei vecchi snapshot/blob versionati: limitare accessi e retention, predisporre rotazione a nuovo key ID; questo cambio non rimuove copie storiche.
2. Con la nuova configurazione eseguire `terraform plan` e verificare l'azione `removed` con `destroy = false`. **Il secret non deve essere distrutto, svuotato né ricreato**. Se compare un'azione destroy, fermarsi; non eseguire `apply`. L'azione di state removal si completa con l'applicazione controllata.
3. Il secret deve rimanere accessibile alla managed identity della Container App come `Key Vault Secrets User`. L'identità del workflow di deploy deve disporre solo dei permessi necessari per verificare i metadati; idealmente separare chi effettua stage/rotazione da chi distribuisce l'app.
4. La pipeline GitHub Action esegue `scripts/azure/check-tenant-proof-secret.sh <nome-vault>` **prima della build e del plan**: legge solamente `attributes.enabled` via Azure CLI. Mancante, non abilitato o inaccessibile causa errore e blocca il deploy; lo script non legge o stampa la chiave.
5. Il preflight verifica **solo disponibilità e stato enabled**. Non prova corrispondenza con la chiave PostgreSQL, key ID, validità temporale, propagazione del secret nelle repliche o revoca. Convalidare con smoke test sotto account runtime per ogni revisione prima di terminare il grace period.

### Bootstrap iniziale e rotazione

Sul **primo** ambiente Azure, il Key Vault non esiste prima dell'infrastruttura: il preflight rende volutamente impossibile un deploy applicativo tutto in un solo passo. Eseguire una fase infrastrutturale approvata di bootstrap della VNet, del vault, delle identity e dei role assignment (ancora da automatizzare nella #6), creare il secret con una procedura esterna autorizzata di Key Vault e solo dopo distribuire l'app. Il workflow attuale non implementa questo bootstrap; nessuna subscription o secret reale è stata modificata.

Per passare da ID `legacy` a `rotate_...`: **prima** migrare DB e installare l'ID e la nuova chiave con `stage-tenant-proof-key.sql` via connessione owner/VNet; **poi** predisporre in Key Vault la versione del secret consumata dal nuovo signer; eseguire deployment controllato, verificare su tutte le repliche il pairing **key ID/valore** e la presenza di prove valide, e soltanto dopo impostare grace/revoca del vecchio ID. **Attenzione:** usare un unico nome di secret versionless con cambio del valore e contemporanea modifica dell'ID applicativo non garantisce sincronizzazione atomica fra le revisioni: il refresh del riferimento e le variabili di ambiente potrebbero aggiornarsi in momenti diversi. Non effettuare rotazioni produttive automatiche senza slot/versione per revisione, smoke test e rollback verificati (#19/#6).

Il segreto viene trasferito anche al server PostgreSQL per lo stage. La `psql -f` e il logging dei parametri/statements PostgreSQL richiedono una **valutazione esplicita**: non assumere che non compaia in `log_statement`, audit, log di provisioning o altri sistemi. Mai mettere il valore in comandi di shell registrati, in `tfvars`, nei log o nei commenti GitHub. L'uso di secret store e trasporto parametrizzato/log redaction sono da rendere operativi in #19. La chiave precedentemente gestita da Terraform deve essere ruotata; gestione e distruzione verificata di vecchie copie dello state è un intervento separato.
