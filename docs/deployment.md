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

- Le **secret ACA sono application-scoped**, quindi la revisione stabile mantiene la secret già in uso `tenant-proof-key` puntata alla sua **versione storica immutabile**. La candidata riceve una **nuova secret dal nome diverso** `tenant-proof-key-v<versione-32hex>` e il nuovo template riferisce esclusivamente quella. Il suo `Security__TenantProofKeyId` usa l'ID staged.
- La candidata ha `min_replicas = 1` (costo e capacità da valutare), `revision_suffix` univoco e **0% di traffico pubblico**; la revisione stabile nominata ha **100%**.
- Prima dell'apply il workflow produce un piano e invia `terraform show -json deploy.tfplan` **direttamente** al gate Python `scripts/azure/check-staged-rollout-plan.py` tramite pipe; questo JSON può contenere password e altri valori sensibili: **non salvarlo, non stamparlo, non allegarlo a GitHub Issues**. Il gate verifica, senza mostrare lo state: Container App preesistente, azione update (mai create/delete/replacement), tutte le secret preesistenti conservate con stessi riferimenti, nuova secret/versione e variabili candidate coerenti, stable 100% / latest 0%; vieta azioni di distruzione su qualunque risorsa del piano.
- Il gate non verifica l'effettiva presenza/attività della `STABLE_REVISION_SUFFIX` in Azure: l'operatore deve controllarla prima del plan/apply. Un suffix errato dovrebbe impedire il routing previsto oppure provocare fallimento dell'apply; non considerarlo un controllo live.
- **Non fare l'apply se il piano prevede la rimozione di una secret versionata appartenente a una revisione ancora attiva**: il gate rifiuta l'operazione. Successivi staging devono conservare i vecchi riferimenti finché non si conferma che le relative revisioni siano dismesse; la pulizia e l'orchestrazione ripetuta rimangono da realizzare (#19).

### Verifica, promozione e rollback

Dopo lo stage, verificare che la stable continui a servire il 100%, che la candidata sia provisioned/healthy, che la nuova secret e il key ID corrispondano davvero al verifier PostgreSQL, e testare con account/organization autorizzati l'accesso API, la RLS e l'audit transazionale **su una revisione candidata raggiunta con un canale di smoke test controllato**. **La pipeline attuale non lo fa e non promuove automaticamente**; la procedura futura deve aggiungere un'azione di traffico approvata e un rollback a 100% stable. Evitare di applicare di nuovo il Terraform con stable suffix vecchio dopo un'eventuale promozione manuale: il piano potrebbe riportare il 100% al valore dichiarato nello state. Non revocare la vecchia chiave prima di confermare che tutte le repliche dipendenti siano dismesse e siano scadute le proof.

**Limiti di questo incremento:** non c'è test Azure reale, controllo live di suffix/traffic, green/blue smoke, approvazione promozione, policy WAF/edge, schedulazione di migrazioni private, rollback collaudato o zero-downtime dimostrato. #19 e #6 rimangono aperte; non usare dati personali in produzione.

## Post-stage gate sulle revisioni ACA (ADR 0018 / #24)

Il workflow manuale `Deploy to Azure`, **dopo l'apply** di uno stage 100% stabile / 0% candidata, esegue ora `scripts/azure/verify-staged-revisions.py` (solo letture). La verifica è obbligatoria per considerare lo stage riuscito; se fallisce il workflow termina con errore **senza spostare traffico o revocare chiavi**. La candidata può risultare già creata in Azure quando la verifica fallisce: un operatore deve ispezionarla e risolvere il problema; non tentare una promozione automatica né ripetere apply senza esaminare il piano.

Lo script invoca `az containerapp show` per controllare `Multiple`, `az containerapp revision list` per lo stato delle revisioni e `az containerapp ingress traffic show` per i pesi effettivi. Per la revisione stabile e la candidata richiede `active=true`, `healthState=Healthy`, `provisioningState=Provisioned`, `runningState=Running`, almeno una replica in esecuzione. Sulla candidata confronta **esattamente** l'immagine immutabile `<acr>/comuni:<GITHUB_SHA>`, `Security__TenantProofKeyId` e il riferimento `Security__TenantProofKey` con `tenant-proof-key-v<32hex>` previsto. Il traffico deve essere composto **esclusivamente** da stable 100% e latest 0%. Nessuna terza destinazione, nessun passaggio a latest. Il nome della revisione segue `<container-app-name>-<revision-suffix>` secondo Microsoft Learn.

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
