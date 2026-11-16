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

**Il secret `tenant-proof-key` deve esistere ed essere abilitato prima del deploy.** La configurazione Terraform non contiene più `var.tenant_proof_key` né gestisce `azurerm_key_vault_secret.tenant_proof_key`. Nel disegno iniziale #21, Container Apps riceveva un riferimento versionless; **l'ADR 0016/#22 lo sostituisce** con un riferimento fissato a una versione esatta, ad esempio `https://<vault>.vault.azure.net/secrets/tenant-proof-key/<32-hex-version>`; i valori restano in Key Vault e nella tabella owner-only di PostgreSQL, non nei nuovi `terraform plan`/state relativi a questo secret. Lo stato continua a contenere **altre** credenziali sensibili (password PostgreSQL), che richiedono gestione separata.

### Procedura sicura per un'installazione preesistente

1. Prima di qualunque `terraform apply`, ottenere backup protetto dello state e approvazione change management. Lo state precedente **contiene** il segreto HMAC, anche nei vecchi snapshot/blob versionati: limitare accessi e retention, predisporre rotazione a nuovo key ID; questo cambio non rimuove copie storiche.
2. Con la nuova configurazione eseguire `terraform plan` e verificare l'azione `removed` con `destroy = false`. **Il secret non deve essere distrutto, svuotato né ricreato**. Se compare un'azione destroy, fermarsi; non eseguire `apply`. L'azione di state removal si completa con l'applicazione controllata.
3. Il secret deve rimanere accessibile alla managed identity della Container App come `Key Vault Secrets User`. L'identità del workflow di deploy deve disporre solo dei permessi necessari per verificare i metadati; idealmente separare chi effettua stage/rotazione da chi distribuisce l'app.
4. La pipeline GitHub Action esegue `scripts/azure/check-tenant-proof-secret.sh <nome-vault> <32-hex-version>` **prima della build e del plan**: con `az keyvault secret list-versions` controlla soltanto i metadati della versione esatta (ID + `attributes.enabled`) senza scaricarne il valore. Mancante, non abilitato o inaccessibile causa errore e blocca il deploy.
5. Il preflight verifica **solo disponibilità e stato enabled**. Non prova corrispondenza con la chiave PostgreSQL, key ID, validità temporale, propagazione del secret nelle repliche o revoca. Convalidare con smoke test sotto account runtime per ogni revisione prima di terminare il grace period.

### Bootstrap iniziale e rotazione

Sul **primo** ambiente Azure, il Key Vault non esiste prima dell'infrastruttura: il preflight rende volutamente impossibile un deploy applicativo tutto in un solo passo. Eseguire una fase infrastrutturale approvata di bootstrap della VNet, del vault, delle identity e dei role assignment (ancora da automatizzare nella #6), creare il secret con una procedura esterna autorizzata di Key Vault e solo dopo distribuire l'app. Il workflow attuale non implementa questo bootstrap; nessuna subscription o secret reale è stata modificata.

Per passare da ID `legacy` a `rotate_...`: **prima** migrare DB e installare l'ID e la nuova chiave con `stage-tenant-proof-key.sql` via connessione owner/VNet; **poi** predisporre in Key Vault la versione del secret consumata dal nuovo signer; eseguire deployment controllato, verificare su tutte le repliche il pairing **key ID/valore** e la presenza di prove valide, e soltanto dopo impostare grace/revoca del vecchio ID. **Attenzione:** usare un unico nome di secret versionless con cambio del valore e contemporanea modifica dell'ID applicativo non garantisce sincronizzazione atomica fra le revisioni: il refresh del riferimento e le variabili di ambiente potrebbero aggiornarsi in momenti diversi. Non effettuare rotazioni produttive automatiche senza slot/versione per revisione, smoke test e rollback verificati (#19/#6).

Il segreto viene trasferito anche al server PostgreSQL per lo stage. La `psql -f` e il logging dei parametri/statements PostgreSQL richiedono una **valutazione esplicita**: non assumere che non compaia in `log_statement`, audit, log di provisioning o altri sistemi. Mai mettere il valore in comandi di shell registrati, in `tfvars`, nei log o nei commenti GitHub. L'uso di secret store e trasporto parametrizzato/log redaction sono da rendere operativi in #19. La chiave precedentemente gestita da Terraform deve essere ruotata; gestione e distruzione verificata di vecchie copie dello state è un intervento separato.

## Pinned Key Vault secret version per rilascio (ADR 0016, issue #22)

Il riferimento **versionless** era rischioso per HMAC RLS: Azure Container Apps può aggiornare una secret alla nuova versione entro 30 minuti e riavviare le revisioni che la usano, indipendentemente dal valore di `Security__TenantProofKeyId`. L'API non deve usare una chiave diversa da quella già registrata come ID firmatario in PostgreSQL. Ora Terraform richiede la variabile **non segreta** `tenant_proof_secret_version`, obbligatoriamente 32 caratteri esadecimali, e produce una Key Vault URI **versionata** `https://<vault>.vault.azure.net/secrets/tenant-proof-key/<version>`. Non viene acquisito il valore della chiave. Questa modifica richiede **configurazione esplicita**; senza versione valida la validazione Terraform/deploy fallisce chiusa.

Il GitHub Environment protetto `production` deve definire **`TENANT_PROOF_SECRET_VERSION`** (versione 32 hex) insieme a `TENANT_PROOF_KEY_ID` (ID logico PostgreSQL). Sono due identificativi diversi: il primo sceglie il *materiale segreto immutabile* in Azure Key Vault, il secondo indica la *chiave verificabile* in `platform.tenant_proof_keys`. La procedura dell'operatore deve registrare in change request la corrispondenza **Key ID ↔ versione Key Vault** senza copiare il segreto nei ticket/log/TF state. Il preflight esegue:

```bash
bash scripts/azure/check-tenant-proof-secret.sh "<nome-vault>" "<32-hex-version>"
```

La CLI usa **`az keyvault secret list-versions`**: questa operazione restituisce metadata/identificativi, **non i valori dei segreti**, e richiede il permesso `secrets/list`. Un filtro JMESPath seleziona esattamente l'URI versionato e ne verifica `attributes.enabled`, senza ripiegare sulla versione più recente. Il job di deploy non deve ricevere permessi di lettura del valore HMAC per il preflight; la **managed identity** Container Apps ha separatamente il permesso di risolvere il riferimento per eseguire l'applicazione.

Ordine vincolante per qualunque rotazione futura, **da provare ancora in Azure**: stage ID/chiave in PostgreSQL tramite runner owner in VNet → creare una *nuova versione* del secret esistente in Key Vault con procedura autorizzata → annotare nuova versione e ID nel GitHub Environment protetto → review del Terraform plan con URI **versionata** → pubblicare revisione e testarne il signer sul DB RLS → verificare vecchia e nuova con grace → dismettere la versione precedente soltanto quando nessuna replica ne dipende. Il rollback **prima della revoca** ripristina vecchio ID e **vecchia versione specifica**; dopo revoca serve nuovo staging, non riattivare chiavi ritirate. La versione usata sul primo deploy di questa modifica va fissata all'attuale secret **prima** di un apply.

**Limiti:** il preflight non dimostra che Key Vault e DB abbiano lo stesso HMAC, che Container Apps abbia effettivamente caricato la versione, che OIDC/RLS funzioni in Azure o che le vecchie repliche siano scariche. La configurazione attuale ha `revision_mode = "Single"`: il pin evita l'aggiornamento automatico di una versione, **non** implementa rollout multi-revisione, smoke test per replica, controllo del traffico o zero-downtime. La #19 e la #6 restano bloccanti. Vecchi Terraform State possono contenere chiavi storiche; rimane obbligatorio proteggerli e ruotare le chiavi esposte.

## Staging Azure Container Apps senza spostamento automatico del traffico — ADR 0017 / #23

**Scopo:** preparare una revisione candidata della sola app API+React, mantenendo il traffico pubblico **100% sulla revisione stabile, 0% sulla nuova**. Il Terraform corrente usa `revision_mode = "Multiple"` con due pesi espliciti. Per verificare la candidata senza doverle instradare traffico pubblico è necessario un accesso controllato alla revisione (ad esempio etichetta di revisione configurata/approvata, endpoint protetto o operazione interna); **il workflow non automatizza ancora questo smoke test né la promozione**.

### Prerequisiti obbligatori prima di azionare il workflow

1. **Deve esistere già un'app con una revisione stabile** in Azure e la versione HMAC `tenant-proof-key` usata dalla revisione deve essere **pin-ata** e corretta. Il workflow di staging rifiuta esplicitamente la creazione della Container App o l'assenza del suo stato precedente. Il **primo bootstrap** non si completa con questa pipeline: serve un procedimento infrastrutturale separato e approvato (#6), incluse migrazioni nella VNet.
2. Nell'Environment GitHub `production` impostare `STABLE_REVISION_SUFFIX` (suffisso reale della revisione attiva, consultabile via `az containerapp revision list`), `STABLE_TENANT_PROOF_SECRET_VERSION` (32 hex, **versione che usa già la stable**), `TENANT_PROOF_SECRET_VERSION` (32 hex, versione Key Vault della candidata) e `TENANT_PROOF_KEY_ID` (ID logico verificabile in PostgreSQL). Non inserire mai il valore HMAC in variabili Terraform.
3. Prima dello stage installare il nuovo key ID e il materiale HMAC **via processo owner in rete privata** in `platform.tenant_proof_keys` (ADR 0014), ed essere certi che entrambe le versioni Key Vault siano abilitate. Il workflow testa solo i metadati delle due versioni; non può attestare il contenuto DB.
4. Il commit GitHub deve essere immutabile: la candidata riceve il suffix `r<prime-12-cifre-del-GITHUB_SHA>` (un altro SHA se occorre creare una revisione diversa). La prima conversione Single → Multiple va approvata con review del piano Terraform e verifica della revisione stabile.

### Meccanismo di sicurezza dello stage

- Le **secret ACA sono application-scoped**, quindi la revisione stabile mantiene la secret già in uso `tenant-proof-key` puntata alla sua **versione storica immutabile**. La candidata riceve una **nuova secret dal nome diverso** `tp-<primi 16 caratteri hex della versione>` (nome ACA da 19 caratteri; URI Key Vault full 32hex) e il nuovo template riferisce esclusivamente quella. Il suo `Security__TenantProofKeyId` usa l'ID staged.
- La candidata ha `min_replicas = 1` (costo e capacità da valutare), `revision_suffix` univoco e **0% di traffico pubblico**; la revisione stabile nominata ha **100%**.
- Prima dell'apply il workflow produce un piano e invia `terraform show -json deploy.tfplan` **direttamente** al gate Python `scripts/azure/check-staged-rollout-plan.py` tramite pipe; questo JSON può contenere password e altri valori sensibili: **non salvarlo, non stamparlo, non allegarlo a GitHub Issues**. Il gate verifica, senza mostrare lo state: Container App preesistente, azione update (mai create/delete/replacement), tutte le secret preesistenti conservate con stessi riferimenti, nuova secret/versione e variabili candidate coerenti, stable 100% / latest 0%; vieta azioni di distruzione su qualunque risorsa del piano.
- Il gate non verifica l'effettiva presenza/attività della `STABLE_REVISION_SUFFIX` in Azure: l'operatore deve controllarla prima del plan/apply. Un suffix errato dovrebbe impedire il routing previsto oppure provocare fallimento dell'apply; non considerarlo un controllo live.
- **Non fare l'apply se il piano prevede la rimozione di una secret versionata appartenente a una revisione ancora attiva**: il gate rifiuta l'operazione. Successivi staging devono conservare i vecchi riferimenti finché non si conferma che le relative revisioni siano dismesse; la pulizia e l'orchestrazione ripetuta rimangono da realizzare (#19).

### Verifica, promozione e rollback

Dopo lo stage, verificare che la stable continui a servire il 100%, che la candidata sia provisioned/healthy, che la nuova secret e il key ID corrispondano davvero al verifier PostgreSQL, e testare con account/organization autorizzati l'accesso API, la RLS e l'audit transazionale **su una revisione candidata raggiunta con un canale di smoke test controllato**. **La pipeline attuale non lo fa e non promuove automaticamente**; la procedura futura deve aggiungere un'azione di traffico approvata e un rollback a 100% stable. Evitare di applicare di nuovo il Terraform con stable suffix vecchio dopo un'eventuale promozione manuale: il piano potrebbe riportare il 100% al valore dichiarato nello state. Non revocare la vecchia chiave prima di confermare che tutte le repliche dipendenti siano dismesse e siano scadute le proof.

**Limiti di questo incremento:** non c'è test Azure reale, controllo live di suffix/traffic, green/blue smoke, approvazione promozione, policy WAF/edge, schedulazione di migrazioni private, rollback collaudato o zero-downtime dimostrato. #19 e #6 rimangono aperte; non usare dati personali in produzione.

## Post-stage gate sulle revisioni ACA (ADR 0018 / #24)

Il workflow manuale `Deploy to Azure`, **dopo l'apply** di uno stage 100% stabile / 0% candidata, esegue ora `scripts/azure/verify-staged-revisions.py` (solo letture). La verifica è obbligatoria per considerare lo stage riuscito; se fallisce il workflow termina con errore **senza spostare traffico o revocare chiavi**. La candidata può risultare già creata in Azure quando la verifica fallisce: un operatore deve ispezionarla e risolvere il problema; non tentare una promozione automatica né ripetere apply senza esaminare il piano.

Lo script invoca `az containerapp show` per controllare `Multiple`, `az containerapp revision list` per lo stato delle revisioni e `az containerapp ingress traffic show` per i pesi effettivi. Per la revisione stabile e la candidata richiede `active=true`, `healthState=Healthy`, `provisioningState=Provisioned`, `runningState=Running`, almeno una replica in esecuzione. Sulla candidata confronta **esattamente** l'immagine immutabile `<acr>/comuni:<GITHUB_SHA>`, `Security__TenantProofKeyId` e il riferimento `Security__TenantProofKey` con `tp-<16hex>` previsto. Il traffico deve essere composto **esclusivamente** da stable 100% e latest 0%. Nessuna terza destinazione, nessun passaggio a latest. Il nome della revisione segue `<container-app-name>-<revision-suffix>` secondo Microsoft Learn.

L'esecuzione usa un numero massimo di tentativi con intervallo limitato (default 12 x 10 secondi tra tentativi) per tollerare l'eventuale consistenza dell'API di Azure dopo il deploy. Gli input sono validati (nome app, gruppo risorse, SHA immagine, revision suffix, key ID e versione Key Vault). Gli output raw della CLI sono catturati **in memoria** e non compaiono nei log GitHub: potrebbero contenere metadati di configurazione e secret references. La CLI non usa comandi di mutazione del traffico.

Comando per uso manuale dell'operatore (senza valori segreti):

```bash
python3 scripts/azure/verify-staged-revisions.py \
  --app '<prefix>-app' --resource-group '<prefix>-rg' \
  --stable-revision '<suffix-stable-approvato>' \
  --candidate-revision 'r<12-cifre-sha>' \
  --expected-image '<acr>.azurecr.io/comuni:<40-hex-commit>' \
  --candidate-key-id '<key-id-stage-in-postgresql>' \
  --candidate-secret-version '<32-hex-versione-key-vault>'
```

**Gate NON sufficienti al go-live:** un esito verde del controllo metadati non equivale a smoke HTTP del backend, né certifica che la chiave HMAC sia uguale a quella nel database (la managed identity può avere un secret configurato ma errato); verificare tramite accesso controllato alla candidata (URL di revisione/label con policy adeguate), autenticazione OIDC e RLS reali su **almeno due Comuni**, auditing e errori/timeout. L'endpoint `/health/ready` controlla la readiness applicativa, non prova la firma RLS. La promozione del traffico e il rollback con approvazioni restano attività distinte e **non** sono implementate (#19/#6). Non dichiarare zero downtime: nessun deployment Azure reale o test di carico effettuato.

## Etichetta immutabile e smoke OIDC/RLS su candidata (ADR 0019 / #25)

Lo stage ACA mantiene **100% del traffico ordinario** sulla revisione stabile e **0% sulla candidata**. Ora la regola `ingress.traffic_weight` della *latest* a peso 0 assegna anche `label = candidate_revision_suffix` (ad esempio `r123456789abc`). Azure Container Apps rende l'etichetta raggiungibile a un **FQDN dedicato** senza modificare le percentuali della root app: `https://<app>---<rsha12>.<environment-default-domain>`. Il gate Terraform plan e il controllo live post-stage verificano che questa label sia associata *solo* alla candidata latest. Fonti ufficiali: [Azure revisions e label](https://learn.microsoft.com/en-us/azure/container-apps/revisions), [domini per label](https://learn.microsoft.com/en-us/azure/container-apps/connect-apps).

**Attenzione:** una label con FQDN esterno è una nuova superficie di accesso, **non un endpoint privato** né un controllo di autorizzazione. La protezione della PWA/asset pubblici e degli endpoint health rimane da valutare, mentre le API tenant continuano a richiedere JWT OIDC valido e membership effettiva. Prima del collaudo con dati di qualunque tipo devono essere approvati ingress restrictions/WAF e misure di controllo dell'accesso. Per ora usare **soltanto due Comuni di test sintetici** e nessun dato personale reale.

### Procedura del test manuale (quando un IdP reale sarà disponibile)

1. Con operatore autorizzato, verificare tramite `scripts/azure/verify-staged-revisions.py` che la revisione candidata sia **Healthy**, etichettata col suffix immutabile e ancora a 0%, e che la stable sia al 100%. Verificare l'esatta coppia *app / revision label / environment default domain* in Azure, non dedurla da una URL proposta da un client.
2. Preparare due organization sintetiche **A e B distinte**, protocollo abilitato per entrambe, membership `Reader` attiva per due identità test reali. Precaricare tramite procedimento autorizzato **un marker sintetico univoco in ciascun Comune** (subject di Protocollo in lista degli ultimi 100), senza nomi o dati personali. Il verificatore HTTP è **read-only**: non genera nuovi atti e non scrive dati né eventi audit.
3. Ottenere dall'IdP approvato **due access token OIDC distinti e di breve vita** che riportino gli organization ID attesi, poi iniettarli **solo** nelle variabili ambiente protette `COMUNI_SMOKE_OIDC_TOKEN_A` e `COMUNI_SMOKE_OIDC_TOKEN_B` del runner dell'operatore. Non salvarli in repository, GitHub Actions secrets permanenti, shell history, artifact, file di log o argomenti CLI; non abilitare `set -x`. Al momento il progetto non implementa il login IdP frontend (#2), perciò questa fase **non è automatizzabile con sicurezza in CI**.
4. Dal runner con DNS e connettività controllati verso l'endpoint ACA approvato, eseguire (tutti i parametri seguenti tranne i token sono **metadati non segreti**):

```bash
python3 scripts/azure/smoke-candidate-oidc.py \
  --candidate-url "https://${APP_NAME}---${REVISION_SUFFIX}.${APP_ENV_DOMAIN}" \
  --app "$APP_NAME" --revision-label "$REVISION_SUFFIX" \
  --environment-domain "$APP_ENV_DOMAIN" \
  --org-a "$TEST_ORG_A" --org-b "$TEST_ORG_B" \
  --marker-a "$TEST_SENTINEL_A" --marker-b "$TEST_SENTINEL_B"
```

`APP_ENV_DOMAIN` è il *default domain* verificato dell'Environment ACA (ad esempio `envid.region.azurecontainerapps.io`) **approvato** dall'operatore; lo script richiede esattamente `<app>---<label>.<domain>`. I due token sono letti **soltanto dall'ambiente del processo**, non dalla CLI. Il client Python verifica TLS con la CA del sistema, rifiuta redirect, proxy, host diversi, porte non standard e richieste HTTP non HTTPS; usa un timeout per richiesta e non stampa contenuti ricevuti né token.

5. Lo smoke esegue solo sei `GET`: `/health/ready` (200), `/api/v1/context` anonimo (401), e per ogni tenant A/B `/api/v1/context` (200 con organization ID corretto, ruolo DB attivo e modulo protocollo) e `/api/v1/protocol/records` (200 con **il proprio marker e senza quello dell'altro Comune**). Errori 401/403 inattesi, 429, dati incoerenti, fixture mancante o contenuti invalidi causano fallimento. Se il modulo è disabilitato o il marker è fuori dagli ultimi 100, **fallire è corretto**: correggere il test fixture, non disabilitare i controlli.
6. Distruggere i token effimeri dal runner dopo il test, leggere i risultati sanitizzati e ripetere il controllo read-only di routing; non promuovere alcuna revisione automaticamente. Per la successiva fase di approvazione/promozione e rollback, aprire un incremento separato (#19/#6).

**Limiti espliciti:** la CI simula trasporto HTTPS e CLI Azure, **non prova un URL Azure reale né l'ottenimento di access token OIDC reali**. Due sentinel visibili nel GET permettono di verificare **un caso concreto** di separazione per tenant, ma non esauriscono threat modeling RLS, audit, altri moduli, concorrenza o privati Azure. La label da sola non protegge l'accesso e non attesta la corrispondenza fisica del valore Key Vault con PostgreSQL: il test API autentico è necessario proprio per verificarne l'uso nella richiesta. Nessun deployment/protocollo ufficiale verificato.

## Gate di migrazione OIDC membership prima del login (ADR 0022)

La migration `202611150009_MembershipIdentityIssuer` è additiva ma **non** converte dati legacy. Sotto `Oidc` le membership con `identity_issuer=NULL` sono **non autorizzate**. Prima di cambiare Authority/issuer, pianificare provisioning con change approval e identità verificate in IdP; assicurare almeno un Admin collegato per ciascun Comune mediante workflow owner controllato e audit esterno. La differenza tra issuer del discovery token e issuer memorizzato è case-sensitive. Se esiste un record legacy/conflicting, la API ritorna 409 e non trasferisce autorizzazioni. Re-eseguire dopo migrazione `scripts/postgres/provision-runtime-role.sql` per il nuovo grant INSERT(identity_issuer) senza concedere UPDATE. Validare con il client HTTP OIDC e con due tenant sintetici, non con dati PA reali.

**Nessun provisioning su Azure o IdP è stato eseguito** in questa implementazione e nessun script automatico di backfill viene incluso. Attivare OIDC prematuramente causa intenzionalmente 403 per le membership non verificate.

## Bootstrap controllato del primo Admin OIDC (ADR 0025 / #31)

Questo runbook si applica **soltanto** a un Comune già creato, attivo, privo di qualunque membership Admin. Non crea organization, IdP, sessioni, credenziali o token e non può trasferire una riga Admin legacy. Non è idoneo per un ambiente contenente dati reali senza verifiche di sicurezza, accessi e autorizzazioni.

**Gate umano indispensabile, fuori dallo script:** identificare legalmente l'operatore responsabile, ottenere change ticket approvato da reviewer indipendente, verificare attraverso il provider OIDC reale e la sua discovery HTTPS l'issuer canonico `iss`, la sua audience API, la validità di un access token firmato e il `sub` esatto/case-sensitive dell'utente da nominare. Verificare la titolarità del Comune e che quella persona debba effettivamente ricevere Admin. Non dedurre il `sub` da email, nome, codice fiscale o un altro provider. Il ticket deve registrare approvatore, responsabile owner del database, data e piano di incident handling; lo script non può verificarne l'autenticità.

**Prerequisiti:** migrazioni PostgreSQL fino al binding `identity_issuer` (ADR 0022), database creato su subnet privata, schema owner distinto da `comuni_app_runtime`, client psql e TLS, connessione owner e materiale sensibile fornito **solo** da un vault/runner autorizzato. Esaminare in read-only `platform.organizations` e `platform.organization_memberships` per ID/stato/ruoli; qualunque Admin preesistente richiede un processo distinto, **non** questo bootstrap. Preparare nell'ambiente protetto le cinque variabili richieste (non inserirne i valori in comandi, log, issue, `tfvars`, shell history o GitHub Actions):

- `COMUNI_BOOTSTRAP_ORGANIZATION_ID`: UUID del Comune approvato.
- `COMUNI_BOOTSTRAP_IDENTITY_ISSUER`: `iss` OIDC HTTPS esatto, già verificato.
- `COMUNI_BOOTSTRAP_SUBJECT`: `sub` verificato per quell'issuer.
- `COMUNI_BOOTSTRAP_CHANGE_TICKET`: riferimento change approvato, senza dati personali.
- `COMUNI_BOOTSTRAP_APPROVER`: alias del revisore esterno (non verifica crittografica).

Con queste variabili già presenti nel runner, eseguire **senza** `set -x`, `psql -a` o `psql -e` e senza password nella CLI:

```bash
psql "host=<pg-host-privato> port=5432 dbname=comuni user=<schema-owner> sslmode=require" \
  -X -q -v ON_ERROR_STOP=1 -f scripts/postgres/bootstrap-initial-admin.sql
```

`PGPASSWORD`/connessione devono arrivare dal secret store dell'operatore, non essere scritti nella shell history. Un exit non-zero blocca tutto; **non** ignorarlo. Il comando è serializzato dalla row lock organization, crea un solo Admin e un evento di audit atomico, e un identico retry non aggiunge audit. Non è consentito eseguirlo con `comuni_app_runtime`. In caso di successo, in una sessione owner autorizzata **separata** verificare che vi sia esattamente un Admin attivo con issuer e subject previsti, un evento `platform.membership.admin.initialized` con correlation `bootstrap:<ticket>`, e provare un access token di test OIDC breve: accesso al proprio tenant consentito, a un altro tenant e con issuer errato negato. Non riportare token o subject in log operativi.

**Errore, incident, rollback:** non disabilitare i controlli, non modificare a mano `identity_issuer` per un errore o migrare automaticamente Admin legacy. Conservare l'audit, bloccare login/release, aprire un change owner separato con approvazione per remediation e ripetere la verifica IdP. Non viene eseguito alcun accesso reale da questa repository e non è garantita conformità PA.


## Creazione owner-only di un nuovo Comune (ADR 0026 / #32)

L'onboarding tecnico `scripts/postgres/provision-organization.sql` crea una **organization mai esistita** in PostgreSQL, il flag `protocol` inizialmente **disabilitato** e un evento append-only `platform.organization.created` nella stessa transazione. Non crea alcun utente, membership, IdP, organizzazione di secondo livello o applicazione. L'organization è memorizzata con `is_suspended=FALSE`, ma **tutte le API tenant richiedono membership backend attiva** e restano 403 fino al bootstrap separato del primo Admin (#31). Il Protocollo resta 403 fino all'abilitazione consapevole dall'Admin.

**Prerequisiti obbligatori esterni, non verificabili dallo script:** confermare l'identità dell'ente e l'autorizzazione della piattaforma a gestirlo, decidere e approvare un UUID univoco, sottoporre un change ticket a un **revisore indipendente**, verificare l'ambiente, il principio di least privilege e le conseguenze sul trattamento dati. Non usare l'ambiente live con dati PA reali prima delle verifiche formali. Database PostgreSQL migrato (incluse audit e RLS), runner privato con accesso alla subnet DB e ruolo proprietario delle tabelle platform (non `comuni_app_runtime`), TLS e credenziali del vault.

Preparare nel runner, **senza stampare valori in command line/history o issue**, queste quattro variabili:
- `COMUNI_PROVISION_ORGANIZATION_ID`: UUID non nullo del Comune approvato.
- `COMUNI_PROVISION_ORGANIZATION_NAME`: denominazione 1–200 caratteri, senza spazi esterni o caratteri di controllo.
- `COMUNI_PROVISION_CHANGE_TICKET`: riferimento change approvato (senza dati personali).
- `COMUNI_PROVISION_APPROVER`: alias reviewer esterno. Non equivale a una firma digitale o approvazione autenticata dall'app.

Eseguire con variabili già in environment, senza `set -x`, `psql -a` o `psql -e`:
```bash
psql "host=<pg-host-privato> port=5432 dbname=comuni user=<schema-owner> sslmode=require" \
  -X -q -v ON_ERROR_STOP=1 -f scripts/postgres/provision-organization.sql
```
Le credenziali `PGPASSWORD` arrivano dal vault/runner protetto, non da GitHub o argomenti CLI. **Exit non zero = stop immediato**: non ritentare con UUID/nome diversi senza nuovo change. Un retry con **stesso UUID/nome** è no-op soltanto quando la riga ha audit di provisioning coerente e la feature `protocol` esiste; non riattiva un Comune sospeso, né cambia moduli o utenti già gestiti. Il lock advisory per UUID serializza chiamate concorrenti. In caso di UUID già usato con nome diverso o riga legacy senza audit, aprire un incident/change: non usare UPDATE correttivi automatici.

**Verifica post-esecuzione (owner, read-only e senza esportare dati personali):** esattamente una organization con nome/ID attesi, nessuna membership, riga `protocol.enabled=FALSE`, evento unico `platform.organization.created` con `resource_id=organization_id` e correlation `bootstrap:<ticket>`; token sintetico privo di membership deve ricevere 403 su `/api/v1/context`. Completare separatamente ADR 0025 / #31 per il primo Admin con issuer+sub verificati dal provider; quindi attivare manualmente i moduli dall'Admin usando API già protette. Nessun deploy, utenti reali o approvazione sono stati effettuati in questa CI.


## Lifecycle del Comune: sospensione e riattivazione owner-only (#33 / ADR 0027)

Il Core già rifiuta **ogni nuova richiesta protetta** (Read/Write/Administration/Protocollo) quando `platform.organizations.is_suspended=TRUE`, anche con token JWT già emesso e membership Admin ancora attiva. Lo script `scripts/postgres/set-organization-suspension.sql` esegue `suspend` oppure `reactivate` solo per un Comune esistente: la transizione e l'audit sono atomici e idempotenti. Non elimina record, non cambia membership né i flag di modulo e **non** revoca sessioni OIDC dell'IdP o annulla richieste già in esecuzione.

**Controlli operatore esterni, obbligatori:** accertare con un secondo responsabile autorizzato l'identità del Comune, l'effettiva titolarità dell'azione, una motivazione documentata e un change ticket approvato, con piano incident/rollback. Non lasciare che un Admin comunale sospenda altri tenant, né usare un endpoint API o un account SQL runtime. Connettersi da runner di gestione autorizzato nella rete privata PostgreSQL, con credenziali owner per `platform.organizations` e `platform.audit_events` (niente account `comuni_app_runtime`), TLS e secret store. Un'esecuzione non verifica automaticamente l'approvazione esterna.

Preparare nel runner approvato, senza mostrare i valori su CLI/history/log, cinque variabili d'ambiente:
- `COMUNI_LIFECYCLE_ORGANIZATION_ID`: UUID del Comune già presente.
- `COMUNI_LIFECYCLE_ACTION`: esattamente `suspend` oppure `reactivate`.
- `COMUNI_LIFECYCLE_CHANGE_TICKET`: identificativo di change sanitizzato senza dati personali.
- `COMUNI_LIFECYCLE_APPROVER`: alias di un revisore indipendente (non è una prova firmata).
- `COMUNI_LIFECYCLE_REASON_CODE`: codice di motivazione non personale come `security-incident`; la spiegazione e l'approvazione autentica restano nel change esterno.

Con ambiente già preparato e password prelevata da vault, eseguire **senza** `set -x`, `psql -a` o `psql -e`:

```bash
psql "host=<pg-host-privato> port=5432 dbname=comuni user=<schema-owner> sslmode=require" \
  -X -q -v ON_ERROR_STOP=1 -f scripts/postgres/set-organization-suspension.sql
```

Un codice di uscita non zero blocca la procedura: non ignorare errori con `|| true`. Verificare in una sessione owner read-only lo stato atteso e **un solo evento** di tipo `platform.organization.suspended` oppure `platform.organization.reactivated` per una transizione effettiva, con `resource_id=organization_id`, `actor_subject=db-owner:<owner>` e `correlation_id=lifecycle:<ticket>`. Il retry nello stato raggiunto è no-op (non genera ulteriori eventi), e la row lock evita due modifiche concorrenti indistinguibili. Non scrivere informazioni personali, motivazioni dettagliate o password nei log. Verificare su test tenant che la sospensione dia 403 per context, Admin e Protocollo; un diverso Comune deve restare 200. Riattivare solo dopo nuovo change/approvazione e verifica di config, appartenenze, safety e dell'IdP: la riattivazione restituisce accesso **solo** alle membership già attive e ai moduli già abilitati.

**Limiti:** lo script non contiene firma o controllo crittografico del change, non arresta automaticamente transazioni già iniziate e non disabilita access/refresh token del provider. Per incident response attivo occorre un piano infrastrutturale e identitario ulteriore. Nessun deploy Azure live o trattamento dati reali è stato eseguito in questa slice.


## Prerequisiti platform-only Superadmin (ADR 0028 / #34)

La migration additiva `202611150010_PlatformOperatorIdentityBoundary` crea `platform.platform_operators` **vuota** (PK `identity_issuer, subject`, `is_active` false) e la funzione booleana `platform.is_active_platform_operator(text,text)` con `SECURITY DEFINER`. Va applicata con il **migration/schema owner** prima di avviare il nuovo backend; dopo le migrazioni rieseguire **`scripts/postgres/provision-runtime-role.sql`** per concedere solo EXECUTE della funzione al ruolo runtime, non SELECT/UPDATE/INSERT sulla tabella. Non inserire seed operatori in Azure o in SQL condiviso: **l'onboarding con verifica IdP, approval esterna e audit della nomina non è ancora implementato**. L'assenza di operatori attivi deve produrre 403, non attivare un fallback di sviluppo.

L'API espone per ora solo `GET /api/v1/platform/session` che risponde al proprio stato con `role=Superadmin`, senza accesso alle organizzazioni o privilegio di impersonificazione. È obbligatorio un JWT OIDC verificato senza il claim `organization_id`; il medesimo token non dà accesso alle API comunali. La validazione è stata testata contro un IdP RSA **simulato**: nessuna registrazione IdP live, policy MFA o token audience dedicata sono state convalidate. Prima di realizzare azioni cross-organization occorrono threat model, approvazione Superadmin, session management, RBAC/audit e test RLS/Azure.


## Enrollment e revoca owner-only operatori Superadmin (#35 / ADR 0029)

La migration `202611150011_PlatformOperatorGlobalAudit` aggiunge un UUID pseudonimo `operator_id` a `platform.platform_operators` e una tabella `platform.platform_operator_audit_events` **senza organization_id**. Ogni evento globale contiene solo actor proprietario DB, azione, tipo risorsa, UUID casuale stabile, riferimento al ticket e timestamp. Trigger PostgreSQL rifiutano UPDATE/DELETE/TRUNCATE. Non c'è una API di assegnazione del ruolo Superadmin; la tabella resta priva di operatori reali per default. Dopo migrazioni rieseguire `scripts/postgres/provision-runtime-role.sql`: `comuni_app_runtime` non ottiene SELECT/INSERT/UPDATE/DELETE su roster e audit globale, soltanto il predicato booleano dell'ADR 0028.

**Gate obbligatorio non automatizzato.** Prima di qualsiasi esecuzione in un ambiente con operatori veri: verificare responsabilità piattaforma, incarico nominale autorizzato, account presso IdP **affidabile** e `iss` HTTPS + `sub` esatti (non email/nome), OIDC discovery e audience API, MFA applicata al provider, identità del richiedente, secondo approvatore **indipendente**, change ticket distinto per ogni variazione e piano incident/recovery. Registrare evidenze nel change esterno senza inserirle nel repository; un valore impostato nelle variabili non prova l'approvazione. Non eseguire questo strumento in Azure live prima della verifica di accessi e network sicuro: il repository non ha ancora collegato IdP, Azure o un workflow di approvazione reali.

Nel runner privato con accesso PostgreSQL/TLS, owner di `platform.platform_operators` e `platform.platform_operator_audit_events`, predisporre dal vault cinque variabili senza stampare dati nel log/shell history:

- `COMUNI_PLATFORM_OPERATOR_IDENTITY_ISSUER`: `iss` esatto, formato HTTPS canonico verificato presso l'IdP.
- `COMUNI_PLATFORM_OPERATOR_SUBJECT`: `sub` esatto del candidato, case-sensitive e verificato.
- `COMUNI_PLATFORM_OPERATOR_ACTION`: `enroll` (prima concessione o riattivazione approvata) oppure `revoke`.
- `COMUNI_PLATFORM_OPERATOR_CHANGE_TICKET`: change approvato **nuovo per ogni effettiva transizione**, senza PII.
- `COMUNI_PLATFORM_OPERATOR_APPROVER`: alias di un secondo approvatore esterno (non un'autenticazione crittografica).

Con environment già preparato dal runner, senza `set -x`, `psql -a`, `psql -e` né password in argomenti CLI:

```bash
psql "host=<pg-host-privato> port=5432 dbname=comuni user=<schema-owner> sslmode=require" \
  -X -q -v ON_ERROR_STOP=1 -f scripts/postgres/manage-platform-operator.sql
```

Il codice di uscita non zero interrompe l'operazione. `revoke` su operatore inesistente, `iss`/subject/action o approvazioni malformati e un ticket riutilizzato per cambiare stato falliscono senza modifiche. Il primo `enroll` crea il record `is_active=TRUE`; il `revoke` lo disabilita, un successivo `enroll` **con nuovo change** lo riattiva. Nessun retry dello stato già raggiunto crea altri audit. La transazione serializzata con lock advisory `iss+sub` + row lock assicura audit e modifica atomici.

**Verifica post-change:** in sessione owner autorizzata e senza esportare identità, confermare un solo record corrispondente alla coppia `iss+sub`, stato attivo atteso e **esattamente un** evento aggiuntivo per transizione (`platform.operator.enrolled/revoked/reactivated`) con `resource_id=operator_id` e `correlation_id=operator:<ticket>`; la tabella globale non contiene issuer, sub o organizzazioni fittizie. Su IdP di test, un token OIDC privo di `organization_id` ottiene 200 da `/api/v1/platform/session` solo se attivo, poi 403 dopo revoca, senza accesso a `/api/v1/context`. L'IdP reale potrebbe mantenere token esistenti: la revoca DB blocca soltanto le **nuove richieste autorizzate**, non revoca le sessioni provider né interrompe le richieste in corso.

**Incident:** su sospetto account compromesso, sospendere accessi IdP secondo procedura esterna; documentare l'incidente, usare il comando `revoke` con ticket indipendente e conservare il log SQL. Non correggere audit esistenti via UPDATE/DELETE, disabilitare trigger o attribuire la revoca a un Comune. Non dichiarare retention normativa, immutabilità contro superuser o conformità GDPR/AgID.


## Inventario globale Superadmin con login PostgreSQL separato (#37 / ADR 0031)

Questa funzione è **disabilitata per default**: `PlatformInventory:Enabled=false`, e la configurazione Terraform/Azure attuale non ha ancora un collegamento live con il secondo account. **Non abilitare in Azure con dati reali** finché segreti, approvazioni, rete privata e revisione sicurezza non saranno verificati. In locale/CI la funzionalità è collaudata con PostgreSQL 17 e issuer RS256/JWKS simulato. Non cambiare le regole di tenant RLS/chiavi HMAC o concedere SELECT della vista a `comuni_app_runtime`.

**Ordine obbligatorio e separazione dei compiti** per un runner privato autorizzato PostgreSQL (nessun valore sensibile nel repository, CLI, output Actions o Terraform state):
1. Migrare con **schema owner** fino a `202611150012_PlatformOrganizationInventory`. La migration definisce `platform.platform_organization_inventory` (soli UUID, denominazione, sospensione, booleano Protocollo) e funzione `platform.active_platform_operator_id(text,text)` invocabile soltanto dal nuovo principal. La vista è una proiezione deliberatamente globale in owner-context, ma **non** accessibile al login comunale.
2. Dal secret store iniettarne il valore in `PLATFORM_READ_DB_PASSWORD` (minimo 32 caratteri; diverso dalle credenziali owner e runtime). Eseguire da runner su rete privata e TLS, **senza** `set -x`, `psql -a` o `psql -e`:
   ```bash
   psql "host=<private-pg-host> port=5432 dbname=comuni user=<schema-owner> sslmode=require" \
     -X -q -v ON_ERROR_STOP=1 -f scripts/postgres/provision-platform-read-role.sql
   ```
   Il provisioning è idempotente e rifiuta un ruolo già membro di altri ruoli o con privilegi superuser/CREATEROLE/BYPASSRLS. Verificare esplicitamente username `comuni_platform_reader`, USAGE schema `platform`, SELECT **solo** vista, EXECUTE funzione di audit actor, INSERT **solo colonne audit**, e divieto di leggere tabelle base/membership/documenti. Il principal `comuni_app_runtime` deve continuare a non poter leggere la vista né invocare il resolver; un test SQL diretto deve ricevere 42501.
3. Configurare il backend con `PlatformInventory__Enabled=true` e `ConnectionStrings__PlatformRead` dalla **Key Vault reference o secret store runtime** verso lo **stesso host/porta/database** di `ConnectionStrings__Default`, ma con username `comuni_platform_reader`. In ambiente Production è obbligatorio SSL `Require` o più rigoroso. **Non** mettere questi valori nel React, `tfvars`, `TF_VAR_*`, comandi shell, log o GitHub Secrets non autorizzati. Validazione fail-fast se flag attivo e connection assente, credenziali coincidenti con Default, username diverso o database differente. Se il flag manca/disabilitato, la rotta resta 503 anche per un Superadmin valido.
4. Verifica di sicurezza su tenant sintetici: login OIDC platform firmato, `GET /api/v1/platform/organizations?limit=2` restituisce solo metadata e `nextCursor`, crea un nuovo evento `platform.organizations.listed` nell'audit globale; un Admin Comune/JWT role falsificato resta 403, un utente anonimo 401. Revocando la membership platform, la **richiesta successiva** restituisce 403, senza nuovi audit. Verificare il ciclo completo con 2+ Comuni e recuperare il report dei privilegi SQL. Una rotta 200 non abilita né impersonificazione né mutazioni. Le azioni di sospensione/attivazione restano nei processi owner-only ADR 0025–0027.
5. Prima della promozione Azure: validare separatamente deployment del secret in Key Vault, isolamento del login e delle subnet, scadenza/rotazione del secret, metriche e allarmi per consultazioni anomale, retention/tamper evidence dell'audit fuori dal DB owner, threat model aggiornato e test con IdP/MFA reali. **Nessuno di questi test live è incluso nella CI**; #5/#6/#10 restano aperte.

**Rollback operativo:** disattivare `PlatformInventory__Enabled` e non condividere il connection string. Il rollback della vista/role e dell'audit globale non è automatico; non cancellare audit. Un operatore autorizzato deve coordinare eventuale revoca della credenziale in Key Vault e PostgreSQL, con incident/change approvato e trail fuori dal sistema.


## #38 — Staging opt-in dell'inventario Superadmin da Key Vault (ADR 0032)

**Non è stato effettuato alcun deployment Azure reale.** La feature resta **spenta per default** in Terraform e nell'API. Questa fase aggiunge soltanto un percorso approvabile e verificabile, su una **unica Container App API+React** e un **unico PostgreSQL**. L'accesso globale ai metadati espone un blast radius diverso dalla normale RLS; non eseguire la candidata con dati reali senza processo di approvazione, rete privata e IdP live.

**Prerequisiti manuali obbligatori (runner privato owner-reviewed, fuori GitHub Actions di deploy):** dopo migration `202611150012_PlatformOrganizationInventory`, provisionare `comuni_platform_reader` sullo **stesso** database del runtime comunale con `PLATFORM_READ_DB_PASSWORD` fornita dalla cassaforte esterna. Mai usare la password dell'owner o `comuni_app_runtime`, `set -x`, `psql -e`, output in chiaro o parametri password in shell. Dal runner VNet privata con TLS PostgreSQL, eseguire:

```bash
psql "host=<private-postgres-fqdn> port=5432 dbname=comuni user=<schema-owner> sslmode=verify-full" \
  -X -q -v ON_ERROR_STOP=1 -f scripts/postgres/provision-platform-read-role.sql
psql "host=<private-postgres-fqdn> port=5432 dbname=comuni user=<schema-owner> sslmode=verify-full" \
  -X -q -v ON_ERROR_STOP=1 -f scripts/postgres/verify-platform-read-role.sql
```

La CA PostgreSQL deve essere attendibile dal runner (e configurata in modo appropriato). Il **verificatore è una transazione READ ONLY** e termina in errore se role, RLS boundary, vista a quattro campi, permissione audit per colonna, grant futuri, ownership, membership SQL o accessi protocollo non rispettano la allowlist. La CI esegue lo stesso controllo su PostgreSQL 17 dopo il provisioning e prima degli xUnit. Il runner live deve registrare l'esito nel change approvato, non nei log contenenti identità.

L'operatore autorizzato carica **all'esterno di Terraform** nel Key Vault **`platform-inventory-connection`** un valore Npgsql completo riferito a **host FQDN privato, porta 5432, database `comuni`, username `comuni_platform_reader`, password separata e TLS almeno Require** (preferire `VerifyFull` con CA appropriata). Non specificare il valore in `TF_VAR_*`, `tfvars`, GitHub Actions `env`, `az ... --value`, shell history, console o repository. Il mezzo per scrivere il valore in Key Vault richiede una procedura privata approvata che non mostri segreti in argomenti, output o log; **non è automatizzato da questa release**. Richiedere un identificatore versione esatto **32 hex**, abilitato, e la managed identity ACA già autorizzata `Key Vault Secrets User`. L'approvazione deve attestare che la connessione punta proprio al ruolo limitato; il preflight metadata-only non può verificarne il contenuto.

Per lo staging con approvazione GitHub Environment `production`, aggiungere la **sola versione metadata** nella variabile di ambiente GitHub **`PLATFORM_INVENTORY_SECRET_VERSION`**. Aprire manualmente `Deploy to Azure` e selezionare `enable_platform_inventory=true` soltanto se l'approvazione e i prerequisiti esterni sono completati. Senza selezione è `false`, nessun `ConnectionStrings__PlatformRead` entra nella candidata. Il workflow verifica `scripts/azure/check-platform-inventory-secret.sh` via `az keyvault secret list-versions` sulla **versione precisa** prima del plan; la scelta `true` con secret assente, versione malformata o disabled interrompe il deploy. Il gate `check-staged-rollout-plan.py` in pipe (mai stampare il plan JSON) controlla la secret app-scoped `pi-<primi 16 caratteri hex della versione>` (19 caratteri; URI Key Vault versione completa), la reference `ConnectionStrings__PlatformRead`, `PlatformInventory__Enabled=true`, il medesimo Key Vault dello signer e il mantenimento di **tutte** le secret già presenti. In ogni caso il traffico **resta al 100% sulla stable e 0% sulla candidata**, che ha label di test immutabile per commit; non è promozione automatica.

**Gates obbligatori prima di qualsiasi promozione live:** verificatore SQL come owner dopo migrazione, autorizzazione OIDC/MFA reale a tre token di test (operatore platform + due utenti di Comuni **sintetici**), chiamate API /platform/session e inventario paginate con audit globale pseudonimo, prova 403 per utenti comunali, rollback/monitoring, verifica metadati ACA/traffic/health della candidata tramite gli script dell'ADR 0018–0019, allarmi e review privacy. Non inserire token o documenti reali nel repository. Lo script `smoke-candidate-oidc.py` esistente verifica due tenant RLS ma **non** dimostra da solo l'autorizzazione cross-tenant dell'inventario: il test live di quest'ultimo resta un gate umano aggiuntivo.

**Backout:** prima della promozione, **non promuovere** la candidata e lasciare 100% alla stable; revocare l'accesso IdP/sessioni secondo processo esterno e avviare un change di disattivazione/rotazione del ruolo, senza cancellare eventi audit. Le secret ACA sono *application-scoped*: il gate **rifiuta** un plan che rimuove o cambia una secret usata da revisioni precedenti. Dopo una promozione live, tornare semplicemente a `enable_platform_inventory=false` potrebbe proporne la rimozione ed essere bloccato; conservare la versione stable con una procedura/versione Terraform dedicata e change approvato prima della rotazione. La gestione di questo scenario e i test Azure live restano aperti; **non** dichiarare zero downtime.

**Compatibilità naming ACA (#38/#39, ADR 0032–0033):** l'Azure CLI documenta massimo 20 caratteri per le chiavi secret. L'inventario usa `pi-<16hex>` (19 caratteri) e il signer RLS candidato usa `tp-<16hex>` (19 caratteri), mantenendo l'URI Key Vault **con versione esatta 32hex**. Eventuali collisioni dei prefissi vengono respinte dal plan gate senza sovrascrivere una secret application-scoped. Questo risolve il blocco di naming nel codice, **non** dimostra il successo di un deployment Azure reale né una rotazione HMAC senza interruzioni.


## #40 — Smoke manuale Superadmin OIDC dell'inventario sulla candidata 0% (ADR 0034)

Il tool `scripts/azure/smoke-candidate-platform.py` è **soltanto read-only** ed eseguibile da un operatore in runner privato, **non** dalla GitHub Action di `terraform apply`. Prima di invocarlo servono migrazioni/provisioning role owner approvati (#38), una Key Vault secret reference verificata, candidacy ACA `stable=100% / candidate=0%`, URL label e FQDN confrontati ai metadati Azure tramite `scripts/azure/verify-staged-revisions.py` e **tre** access token OIDC temporanei emessi da un IdP approvato: uno per Comune sintetico A, uno per Comune sintetico B e uno per una identità platform **senza organization claim**, già attiva nel roster Superadmin. **I token non si salvano nel repository, non si passano come argomenti o in issue/log e non vanno mantenuti come GitHub Secret permanente.** Devono essere iniettati da un runner privato autorizzato tramite `COMUNI_SMOKE_OIDC_TOKEN_A`, `COMUNI_SMOKE_OIDC_TOKEN_B` e `COMUNI_SMOKE_OIDC_TOKEN_PLATFORM`, con shell tracing disattivato.

Con environment e token già predisposti in modo riservato e senza stampare valori:

```bash
python3 scripts/azure/smoke-candidate-platform.py \
  --candidate-url "https://<approved-app>---<rcommitsha12>.<approved-env-domain>" \
  --app "<approved-app>" \
  --revision-label "<rcommitsha12>" \
  --environment-domain "<approved-env-domain>.azurecontainerapps.io" \
  --org-a "<uuid-comune-sintetico-a>" \
  --org-b "<uuid-comune-sintetico-b>"
```

Il tool impone URL HTTPS canonico della **sola** label candidata, TLS CA, assenza redirect/proxy, tempo e risposta limitati. `GET /health/ready` deve essere pronto. `GET /api/v1/platform/session` deve restituire **401 anonimo, 403 ai due token comunali e 200 esattamente `{"role":"Superadmin"}`** all'operatore platform. Il token piattaforma deve ricevere **403** da `/api/v1/context`. L'inventario globale deve essere **401 anonimo, 403 per entrambi i Comuni e 200 per il solo token platform**. Il paging `limit=2` verifica esclusivamente i campi `id,name,isSuspended,protocolEnabled`, UUID ordinati senza ripetizioni, cursor coerente e la presenza dei due UUID di test. Si ferma dopo **20 pagine / 40 record al massimo**: è pensato per un **dataset sintetico controllato**, non per enumerare tutti i Comuni di produzione. Non stampa righe, nomi, token, UUID o errori di HTTP verbatim.

La suite **separata** `smoke-candidate-oidc.py` (#25) con due marker Protocollo sintetici resta obbligatoria per testare la RLS tenant, mentre lo smoke #40 verifica la separazione Superadmin. Dopo un successo, un operatore deve **verificare autonomamente** nel DB owner-read-only che ogni pagina restituita abbia audit globale pseudonimo e che la revoca owner-only del soggetto **di test** comporti 403 alla richiesta successiva. Lo smoke non modifica DB né ripristina la membership e non può attestare autonomamente un processo di approvazione o MFA reale. Il cambio di stato/revoca deve avere ticket, seconda approvazione e ripristino documentato (ADR 0029).

In caso di esito negativo **non** trasferire traffico alla candidata né riutilizzare token; verificare l'incidente e sospendere l'attivazione della #38. Non dichiarare lo staging Azure testato perché i test CI usano un opener HTTP simulato, non Key Vault o token veri.


## #41 — Abilitazione della lettura audit comunale a privilegi minimi (ADR 0035)

Dopo le migrazioni PostgreSQL, il **runner owner privato** già usato per provisionare `comuni_app_runtime` deve eseguire nuovamente `scripts/postgres/provision-runtime-role.sql` sullo stesso database e sulle stesse tabelle, utilizzando `RUNTIME_DB_PASSWORD` dal vault esterno. Non eseguire come runtime, non salvare password in GitHub issue/log/terraform tfvars o nell'app React. L'operazione revoca tutti i grant e riapplica la allowlist idempotente; aggiunge solamente `GRANT SELECT (id,organization_id,action,resource_type,occurred_at) ON platform.audit_events TO comuni_app_runtime`. Non concede SELECT a livello di tabella o su `actor_subject`, `resource_id`, `correlation_id`. Il runtime continua a non poter modificare/cancellare audit e non riceve accesso al roster o audit globale platform.

Il gate **PostgreSQL 17 della CI** provisiona il ruolo dopo la migration e verifica con l'account ristretto le cinque colonne leggibili e il blocco 42501 delle tre colonne riservate, insieme al fatto che senza signed tenant proof un SELECT non restituisce righe. La nuova API è protetta server-side da Admin membership attiva e **organization non sospesa**; il rollout deve verificare anche la segregazione con due Comuni sintetici e token Admin/Reader fittizi prima dei dati reali. La PWA può visualizzare il metadata audit senza un nuovo servizio o configurazione/Key Vault secret aggiuntivo.

**Rollback:** rimuovere dal provisioning owner la nuova grant SELECT per colonne e revocare queste colonne dal ruolo nel normale change management, poi disabilitare/ritirare endpoint/UI tramite un deployment approvato; non cancellare né riscrivere eventi esistenti. L'operazione è disgiunta dalla #38 (inventario global platform off per default) e non attiva accesso cross-tenant. Non sono stati eseguiti rollout Azure reali in questa sessione.

## #42 — Tracciamento atomico delle consultazioni audit comunali (ADR 0036)

La route `GET /api/v1/admin/audit` già presente (#41) ora scrive un evento `platform.audit.consulted` per ogni richiesta Admin **riuscita**. Non sono necessarie nuove migrazioni, nuove GRANT, secret, Container Apps, DB, ruoli o Terraform variables. È però obbligatorio che nell'ambiente di destinazione siano già stati eseguiti migrations e **`scripts/postgres/provision-runtime-role.sql`** della #41, con `comuni_app_runtime` dotato di SELECT limitato a cinque colonne e INSERT append-only su `platform.audit_events`. Non eseguire l'app con la connessione del migration owner.

Prima del rollout in un ambiente autorizzato, verificare con Comuni **sintetici** che ogni GET 200 aggiunga un solo evento `platform.audit.consulted` al proprio tenant con sub e correlation attendibili; 400/401/403 non devono scriverne. Verificare che senza tenant proof HMAC o senza transaction la lettura+INSERT non avvenga, che con rollback non restino eventi, che non compaia mai l'evento della richiesta corrente nella sua risposta e che il successivo GET possa mostrarlo. Testare anche la consultazione con Protocollo disabilitato; non deve dipendere dalle feature del dominio. Osservare volume di eventi generati da ricarichi UI (una consultazione per GET effettivo). Documentare eventuale controllo di abuso prima dell'ambiente live.

**Rollback:** un deploy precedente con la route read-only non crea eventi di consultazione, ma non elimina gli eventi append-only già persistiti. Nessuna riscrittura retroattiva, modifica DBA o azzeramento dell'audit. Nessuna verifica Azure/IdP live è stata effettuata qui; gli obiettivi retention, tamper-evidence e backup/restore sono ancora aperti nelle epiche #4/#5.


## #43 — Registrazione iniziale di un nuovo Comune, owner-only e auditata (ADR 0037)

**Solo dopo le migrazioni** e la verifica esterna dell'identità istituzionale del Comune, del mandato, della change approvata, del ticket e di un reviewer indipendente, un runner **privato** con PostgreSQL owner/TLS adeguati può eseguire `scripts/postgres/register-organization.sql`. Non invocarlo dalla API, dalla PWA, da `comuni_app_runtime`, da una pipeline pubblica senza rete privata o come parte di un `terraform apply`. Variabili d'ambiente *solo nel runner autorizzato*:

- `COMUNI_REGISTER_ORGANIZATION_ID`: UUID scelto e registrato nel change, nel formato canonico.
- `COMUNI_REGISTER_ORGANIZATION_NAME`: denominazione istituzionale con 3–200 caratteri senza control/whitespace esterna; **non sostituisce il codice ISTAT** o la verifica ufficiale.
- `COMUNI_REGISTER_CHANGE_TICKET`: identificativo del change autorizzato, almeno 8 caratteri.
- `COMUNI_REGISTER_APPROVER`: riferimento all'approvatore indipendente verificato **fuori dal DB**.

Con variabili già configurate dal gestore segreti del runner, senza stampare valori o abilitare shell tracing:

```bash
psql "host=<private-postgres-fqdn> port=5432 dbname=comuni user=<schema-owner> sslmode=verify-full" \
  -X -q -v ON_ERROR_STOP=1 \
  -f scripts/postgres/register-organization.sql
```

Il processo deve abortire se **una** delle tre scritture fallisce: `platform.organizations` (`is_suspended=false`), `platform.organization_modules` (`protocol.enabled=false`) ed evento audit append-only `platform.organization.registered`. Il numero iniziale di membership è **zero**. Un identico replay è idempotente senza aggiornare il nome, la sospensione, i moduli o la membership; riuso UUID con altro nome/ticket e record preesistenti senza audit precedente vengono rifiutati. Non impostare `psql -a`/`-e` o `set -x`, non mettere denominazioni/ticket in issue o log pubblici.

**Passi separati post-registrazione:** approvare issuer/subject OIDC reali, eseguire lo script owner `bootstrap-initial-admin.sql` (#31) con ticket distinto, poi verificare con un token OIDC realmente valido che l'Admin può accedere **solo** al suo Comune e che il Protocollo rimane disabilitato fino alla decisione di attivazione del modulo. La CI verifica la sequenza solo con identità sintetiche e PostgreSQL disposable, non con IdP/Azure reali. In caso di errore non cancellare automaticamente la organization o il suo audit: intervenire tramite change approvato, conservando audit append-only; eventualmente sospendere con la procedura owner `set-organization-suspension.sql` (#33). Onboarding legale, modello `created/active/suspended`, UI di gestione Superadmin e richiesta adesione restano scope delle epiche #3/#10.


## #44 — Checklist creato → attivo → sospeso, migrazione 0013 e owner activation (ADR 0038)

**Ordine obbligatorio in ambiente autorizzato (non eseguito qui su Azure reale):** fermare i cambi di lifecycle durante l'upgrade; applicare **come owner su connessione privata TLS** la migration EF `202611150013_OrganizationActivationGate` prima di usare i nuovi script. La migration aggiunge `platform.organizations.is_activated BOOLEAN NOT NULL DEFAULT TRUE` e un CHECK che vieta pending+suspended; gli enti legacy restano attivi/sospesi come prima, senza permessi nuovi. Aggiorna la vista globale già concessa a `comuni_platform_reader` conservando quattro colonne e grant di sola lettura. Il nuovo binario API deve usare `IsOperationalAsync` che richiede **activated AND NOT suspended**; non applicare la nuova registrazione prima del binario/migration senza staging compatibile.

Dopo la migration: (1) verificare esternamente adesione/mandato e fare owner `register-organization.sql`, che crea `created` con `protocol=false`; (2) verificare l'issuer OIDC, il subject e l'approvazione a quattro occhi, eseguire owner `bootstrap-initial-admin.sql` (#31) per attribuire l'Admin senza accesso HTTP ancora; (3) verificare che il Protocollo resti off e nessun servizio sia abilitato, quindi su **un nuovo ticket approvato** eseguire owner `activate-organization.sql`. Impostare nella sessione privata del runner `COMUNI_ACTIVATE_ORGANIZATION_ID`, `COMUNI_ACTIVATE_CHANGE_TICKET`, `COMUNI_ACTIVATE_APPROVER` tramite processo controllato, mai nei log/chat/repository o negli argomenti shell. Eseguire senza tracing:

```bash
psql "host=<private-postgres-fqdn> port=5432 dbname=comuni user=<schema-owner> sslmode=verify-full" \
  -X -q -v ON_ERROR_STOP=1 \
  -f scripts/postgres/activate-organization.sql
```

L'activation convalida owner, ticket/reviewer formali, admin OIDC attivo e moduli spenti; aggiorna `is_activated=true` e scrive `platform.organization.activated` in modo atomico. Non concede membership, non abilita Protocollo e non imposta `is_suspended` a FALSE per un Comune già sospeso. Rifiuta richieste di attivazione su sospeso, non presente, non approvato o ancora privo di Admin verificabile. Il script `set-organization-suspension.sql` (#33) rifiuta pending per suspend/reactivate, mentre continua ad agire su active/suspended con audit.

**Gates prima dell'apertura al traffico reale:** test con due Comuni sintetici, token JWT validati dal provider OIDC autorizzato e Admin; accesso created=403, active con membership=200, Protocollo disabilitato=403, sospeso=403, recovery con ticket; verifica SQL owner read-only di stati e audit e del ruolo runtime senza UPDATE su organizations; candidate ACA 0% e rollback/monitoring #38 ancora obbligatori. Il boolean `isSuspended` dell'inventario indica “non operativo” e **non distingue** created e suspended; nella PWA è tradotto *Non operativo / Not operational*.

**Downgrade non automatico:** `Down` della migration 0013 solleva errore se sono presenti Comuni created. Eliminare la colonna senza gate trasformerebbe created in active; non eliminare/modificare righe per forzare il rollback e non disabilitare il constraint senza change. Prevedere ripristino della **stessa** versione API/migration sotto change owner approvato, senza rimuovere controlli di sicurezza. Nessun rollout Azure/IdP reale o workflow legale è stato verificato in questa sessione.

## #45 — Change inventory status e smoke candidata (ADR 0039)

Dopo `202611160001_PlatformLifecycleInventory` il verifier `scripts/postgres/verify-platform-read-role.sql` richiede **cinque** colonne esatte nella vista `platform.platform_organization_inventory` (`id,name,is_suspended,protocol_enabled,lifecycle_status`). Migrare come owner **prima** della candidata API e rieseguire provisioning idempotente + verifica READ ONLY del principal dedicato; non aggiungere GRANT al runtime comunale. La smoke candidata `smoke-candidate-platform.py` valida esattamente cinque campi e `created/active/suspended`, con il compat boolean coerente. Lo smoke resta read-only e non costituisce approvazione di onboarding.

**Compatibilità e rollback:** l'API v1 aggiunge `lifecycleStatus` ma `isSuspended` non cambia significato. Il bundle PWA pre-#45 valida rigidamente quattro chiavi e segnala l'inventario non disponibile: transizione ammessa solo con flag **OFF** finché la candidata unificata API+SPA e il controllo cache non sono approvati. Non esiste un consumer production verificato da preservare; prima di un rilascio valutare versionamento endpoint se esistono client esterni non aggiornabili. Il rollback operativo è spegnere `PlatformInventory__Enabled` tramite change; la migration Down ricrea la vecchia vista soltanto dopo `DROP VIEW RESTRICT` in transazione e ripristina il GRANT al principal ristretto se presente. Non forzare downgrade con dipendenze, non alterare `is_activated` di #44, non cancellare audit. Azure/IdP live e #38 restano non completati.

## #46 — Guardia sostitutiva obbligatoria per il ritiro chiavi tenant RLS (ADR 0040)

**Non utilizzare il vecchio comando senza il successore.** Il runner privato owner della tabella `platform.tenant_proof_keys` deve ricevere, oltre a `TENANT_PROOF_RETIRE_KEY_ID` e `TENANT_PROOF_GRACE_SECONDS` (0..3600), anche **`TENANT_PROOF_REPLACEMENT_KEY_ID`**: ID di una chiave già stagata e **diversa** da quella in uscita. Non passare la chiave HMAC stessa; il comando di retirement non necessita mai del materiale segreto. Es.: se il nuovo ID `rotate_2026_11` è stato installato, verificato ed è già usato sulla candidata autorizzata, impostarlo come sostitutivo quando si ritira `legacy`. Usare soltanto variabili ambiente del processo con gestione sicura da secret store/change system, senza `-v`, `set -x` o tracing del comando.

Lo script acquisisce `LOCK TABLE platform.tenant_proof_keys IN SHARE ROW EXCLUSIVE MODE` (con lock timeout) e **nella stessa transazione** controlla: esistenza del target, ID successore diverso, `revoked_at IS NULL`, `not_before <= clock_timestamp()`, `valid_until > clock_timestamp() + grace + 300s`. Se un requisito non vale, fa **ROLLBACK** e termina con errore generico, senza alterare scadenza o revoca. La finestra di 300 secondi copre il massimo TTL ammesso dal verifier (la proof emessa dal signer dura 180 s); **non** prova sincronizzazione di repliche o clock esterni. Con successore valido, `least(valid_until, now+grace)` continua ad accorciare soltanto e `revoked_at` rimane irreversibile anche ai retry. Due ritiro reciproci concorrenti non possono revocare entrambe le chiavi. Anche il runner deve verificare che la nuova coppia ID/versione Key Vault firmi realmente sul DB *prima* della retirement.

**Emergenza e limiti:** questa guardia protegge il percorso ordinario ma non impedisce un DBA di modificare manualmente la tabella o un incidente di compromissione; la revoca d'emergenza dell'ultima chiave non è supportata dallo script ordinario e richiede un change separato (incident response, identità/approvazione, audit esterno, previsione di outage) prima di SQL owner approvato. Non automatizzare il ritiro da CI, GitHub Actions o Terraform di produzione. #19/#6 rimangono aperte fino a osservabilità delle revisioni, reti private, IdP reali e rollback testato in Azure.
