# Sicurezza: baseline e gap obbligatori prima del go-live

## Baseline presente
- API con modalità di trust separate: `DevelopmentJwt` HS256 consentito **solo** in Development/Testing; in Production `Oidc` richiede Authority HTTPS, Audience, verifica firma asimmetrica RS256 tramite JWKS, issuer e lifetime. Non è consentito riutilizzare il segreto demo su Azure.
- Claim `organization_id` e `sub` esclusivamente dal token validato; autorizzazione contro membership attive **persistite in PostgreSQL** con ruoli `Admin`, `Officer`, `Reader`, indipendentemente dal claim `role` JWT.
- Policy API e controlli feature flag server side; filtri EF + guardia SaveChanges, e RLS PostgreSQL sulle cinque tabelle tenant-owned tramite contesto transaction-local (ADR 0012 / #17), sotto l'account runtime non owner.
- Sospensione organization (ADR 0008, #14): una organization assente o sospesa riceve 403 per tutte le API protette, anche con JWT valido e membership attiva; la policy legge PostgreSQL a ogni richiesta. Nessun endpoint di gestione della sospensione è attualmente esposto.
- Token demo nel browser solo in RAM, nessuna persistenza in localStorage. Seed utenti/membership solo in ambiente Development.
- Azure: database su subnet privata, Key Vault, RBAC, Managed Identity, ACR con admin disabilitato.
- CI: unit test DDD e test API con PostgreSQL reale per cross-organization; E2E Playwright per autorizzazioni UI.
- **Audit iniziale (#11):** creazione di metadati del Protocollo con evento `protocol.record.created` nella stessa transazione PostgreSQL; solo actor, organization, action, resource ID, correlation e timestamp; niente subject del documento. Trigger del DB bloccano UPDATE, DELETE e TRUNCATE (ma non un superuser). Nessuna API di lettura audit in questa slice.

## Non ancora implementato — blocchi per produzione reale
- Il backend può **validare** access token OIDC ma mancano ancora il provider effettivamente collegato, login frontend con authorization code/PKCE o BFF, flussi SPID/CIE, onboarding/provisioning delle memberships per Comune, revoca sessioni, MFA e test contro un provider reale. La revoca di membership **blocca nuove autorizzazioni** ma non revoca di per sé JWT esterni.
- Audit di **tutti** gli eventi amministrativi e consultazioni sensibili; consultazione autorizzata, retention, accesso least-privilege e tamper evidence indipendente dal DB. L'evento iniziale del Protocollo **non** rende il sistema audit-complete o tamper-proof.
- Lifecycle completo organization e sospensione/riattivazione amministrativa con audit (#3/#10): il flag di sospensione è al momento soltanto una barriera API; nessuna console Superadmin lo gestisce.
- Rate limiting, security headers, threat modeling, OWASP ASVS, scansioni SAST/SCA e gestione vulnerabilità continuativa.
- Test end-to-end completi su Azure, segreti/chiavi ruotati, backup/restore verificati, monitoraggio e alerting.
- Policy GDPR, ruoli titolare/responsabile, minimizzazione e cifratura dati, retention, DPIA ove dovuta.
- Protocollo a norma, documenti, segnatura, fascicolazione, conservazione, interoperabilità AgID.
- Verifica estesa del nuovo schema di **asserzioni tenant firmate** in #18 (e.g. key rotation, replay, performance, injection e privilegi di funzioni), account con identità gestita/Entra ove applicabile, RLS per nuovi domini e job di migrazione/provisioning privata Azure. La separazione least-privilege #16 e la prima RLS #17 non sono state verificate su Azure reale.
- Rete privata/endpoint Blob e Key Vault, firewall, WAF e policy aziendali da definire.

**Non trattare il modulo Protocollo demo come registro ufficiale né inserire dati personali reali.**

## Flusso amministrativo dei moduli — #13

Il ruolo `Admin` è conferito da una membership attiva e verificata lato backend tramite `OrganizationRoleRequirement`, non dal JWT. Solo l'organization autenticata può consultare/modificare la propria configurazione `protocol`; nessun override del tenant da route, header o body. Aggiornamento feature flag e audit sono transazionali, con esito immediato nelle verifiche backend. La UI filtra il menu ma non costituisce confine di sicurezza. Questa slice **non** abilita operazioni platform/Superadmin, né una gestione generalizzata di cataloghi e dipendenze: #3 e #10 rimangono aperte.

## Protezioni HTTP iniziali — issue #15

Le richieste `/api` sono limitate mediante il rate limiter **in memoria per replica** di ASP.NET Core con finestra fissa (default **120 richieste/60 secondi**), senza coda, 429 e `Retry-After`. Le richieste con JWT valido sono partizionate per coppia `organization_id` e `sub`; richieste anonime/non autenticate per IP della connessione **senza fidarsi di X-Forwarded-For**. Health check e asset PWA sono esclusi. Parametri `Security:ApiRateLimit:PermitLimit` (1–10000) e `Security:ApiRateLimit:WindowSeconds` (1–3600) hanno validazione fail-fast.

Risposte API incluse 401/403/429: `Cache-Control: no-store`, `Pragma: no-cache`. Tutte le risposte: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy` restrittiva, CSP con script/worker solo dalla stessa origine e `frame-ancestors 'none'`. La CSP consente ancora CSS inline (`style-src 'unsafe-inline'`) per compatibilità e richiede revisione con il frontend definitivo.

**Limiti obbligatori per il go-live:** con più repliche ACA la quota **non è globale**; istanze diverse non condividono contatori. Dietro reverse proxy l'IP visto da Kestrel potrebbe essere quello del proxy, con effetto di aggregazione sui client anonimi; non prendere mai `X-Forwarded-For` senza restringere i proxy fidati. Difesa DDoS, WAF, limiti edge, load test, proxy chain attendibile, HSTS e redirect HTTPS gestiti in frontiera richiedono configurazione/validazione Azure separata. Queste protezioni **non** risolvono PostgreSQL RLS e privilegi DB (resta aperta #5).

## Credenziali PostgreSQL e limiti del ruolo runtime — issue #16

Il provisioning SQL `scripts/postgres/provision-runtime-role.sql` definisce il login `comuni_app_runtime`, distinto dal proprietario degli schemi/migrazioni. **Il connection string dell'applicazione Azure** in Terraform ora usa questo login con password separata; `comuniadmin` è riservato al provisioning infrastrutturale e alle migrazioni eseguite da un operatore autorizzato. La CI usa realmente questo login PostgreSQL per verificare funzioni consentite e errori `42501` su operazioni privilegiate.

Il ruolo runtime può leggere solo le tabelle necessarie a organizzazione, flag, membership e Protocollo demo; può inserire metadati Protocollo e nuovi eventi Audit e aggiornare **solo** `organization_modules.enabled`. Non è owner di tabelle né membro di ruoli admin e non possiede GRANT di CREATE negli schemi. Non riceve GRANT automatici per i nuovi domini. Aggiornare esplicitamente il provisioning per ogni schema/dominio aggiunto.

**Evoluzione #18:** la RLS ora convalida una prova HMAC a scadenza breve generata dall'API, non la sola GUC `comuni.organization_id`. Modificare direttamente il vecchio setting non permette più di selezionare un altro Comune; il ruolo runtime non può leggere la chiave privata di verifica PostgreSQL. Restano rischi di furto/ripetizione di una prova valida, compromissione del processo API o della chiave, SQL injection con capacità aggiuntive, bypass DBA e nuove tabelle non protette. Il sistema **non è pronto per dati comunali reali** senza review e deployment verificati. Il provisioning in rete privata Azure, la gestione/rotazione dei segreti, l'isolamento delle connessioni Entra e backup/restore restano da verificare.

## Row-Level Security PostgreSQL iniziale — #17

La migrazione EF `202611150005_TenantRowLevelSecurity` abilita RLS con policy `USING`/`WITH CHECK` su `platform.organizations`, `platform.organization_modules`, `platform.organization_memberships`, `platform.audit_events` e `protocol.records`. Le policy confrontano id/organization_id con `NULLIF(current_setting('comuni.organization_id', true), '')::uuid` e negano l'accesso normale se il valore manca. La RLS vale per il ruolo SQL `comuni_app_runtime` **non owner e senza BYPASSRLS**; i proprietari e superuser la bypassano, quindi non usare mai la credenziale owner nel runtime.

Dopo `UseAuthentication`, il middleware per `/api` crea una transazione EF e imposta `set_config(..., true)` parametrizzato a partire dall'organization del JWT validato. La transazione copre policy di autorizzazione, query e scritture del repository, che riusano la transazione invece di crearne una annidata; viene chiusa o annullata al termine della richiesta. Non si imposta alcun tenant a livello di sessione: con il connection pooling Npgsql il contesto non deve sopravvivere a commit/rollback. Le richieste senza organizzazione valida rimangono senza contesto e non possono vedere tabelle RLS sotto il ruolo runtime.

**Threat model residuo:** la GUC PostgreSQL `comuni.organization_id` è impostabile mediante `set_config` dallo stesso ruolo applicativo. Se SQL non fidato raggiungesse la connessione, l'attaccante potrebbe cambiare il valore e leggere un'altra organization. Test RLS su query SQL dirette dimostrano il filtro con un contesto determinato, non attestano protezione contro l'iniezione di SQL. Prima del go-live valutare una fonte di contesto non falsificabile, role isolation più forte o approccio per-tenant, insieme a threat modeling e penetration test; #5 resta aperta.

## Prove di tenant firmate — ADR 0013 / #18

Il backend costruisce per ogni richiesta una prova `tenantGuidN|expiryUnix|nonceGuidN|hmacSha256`, valida per circa tre minuti, firmata con `Security:TenantProofKey` (minimo 32 byte). Il segreto resta nella configurazione sicura dell'API, **mai nel JWT o nel browser**. Tramite parametro PostgreSQL, `TenantDatabaseTransaction` salva la prova nella variabile **transaction-local** `comuni.tenant_assertion`. Una funzione PostgreSQL `platform.verified_tenant_id()` `SECURITY DEFINER` con search_path fisso legge la chiave dalla tabella **privata** `platform.tenant_proof_secret` e confronta HMAC e scadenza; le cinque policy RLS valutano solo il risultato verificato. Il ruolo `comuni_app_runtime` può soltanto eseguire la funzione, non leggere/modificare la chiave. La vecchia `comuni.organization_id` non è più utilizzata dalle policy.

**Confine di sicurezza:** la mera SQL injection sotto il ruolo runtime non può **creare una nuova prova valida per un diverso Comune** senza accesso alla chiave o a una prova altrui. Tuttavia un attaccante con controllo dell'API o accesso a un token validamente firmato per un altro Comune può riutilizzarlo fino alla scadenza; un owner/superuser bypassa RLS. L'implementazione non elimina tutte le classi di SQL injection o le vie di esfiltrazione dei dati. Il segreto condiviso in Key Vault e nel DB richiede provisioning sincronizzato e rotazione progettata; il Terraform State ne contiene una copia sensibile. Monitorare l'uso di funzioni SECURITY DEFINER, privilegi di CREATE, temp objects e versioni PostgreSQL/pgcrypto. Non esporre il valore di `comuni.tenant_assertion` nei log.

Le politiche RLS sono testate sul database PostgreSQL 17 di CI, **non** su Azure PostgreSQL Flexible Server; la nuova migration richiede l'estensione `pgcrypto` opportunamente consentita in Azure. La #5 continua per security review, pen-test, SAST, secret rotation/zero-downtime rollout, database roles e altri domini.

## Rotazione in fasi delle prove tenant — ADR 0014 / #20

La migration `202611150007_VersionedTenantProofKeys` introduce chiavi identificate da ID, finestra temporale e revoca owner-only. Il verifier RLS supporta un formato con key-id autenticato e quello legacy a quattro campi **solo finché `legacy` è autorizzata**; un vecchio MAC non può essere reinterpretato sotto un altro key-id. Test PostgreSQL sul ruolo runtime verificano grace, key revocation, firma manipolata e nessuna fuga fra tenant/pooled transactions.

L'app seleziona `Security:TenantProofKeyId` e `Security:TenantProofKey`; un ID non ancora installato o ritirato fallisce chiuso. Le operazioni di staging/retirement usano script separati con credenziali owner. **Il supporto al grace period NON significa che sia stato collaudato un rollout senza interruzione su Azure**; ADR 0015 sposta la chiave HMAC fuori dal Terraform State nuovo, ma le versioni storiche possono ancora contenerla e mancano il coordinamento di Key Vault, repliche e rollback (#19 e #6). Evitare rollback della migration verso verificatore single-key; negare l'accesso è preferibile a riattivare inconsapevolmente versioni revocate.

## Confine Terraform / gestione delle chiavi — #21

La chiave privata per firmare le asserzioni RLS **non viene più passata a Terraform**. Container Apps usa solo un URI versionless di un secret Key Vault predisposto fuori dal piano Terraform. Un `removed` block con `destroy=false` evita la cancellazione del secret già gestito dai vecchi state; **non** elimina valori segreti dagli snapshot storici. La CI esegue test contrattuali contro regressioni di questo confine e un preflight metadata-only con CLI Azure simulata.

Lo script preflight blocca il deploy quando il secret manca, è disabilitato o è inaccessibile. **Non certifica che il secret sia corretto**, aggiornato, non scaduto, installato in PostgreSQL o caricato da tutte le repliche. Lo state Terraform continua a contenere password DB e richiede isolamento. La #19 resta aperta per una rotazione multi-replica senza downtime, un bootstrap e secret transfer con logging protetto, test di carico/rollback e gestione dei segreti preesistenti.

## Riferimenti a versione specifica di Key Vault — #22

Il signer RLS Azure ora usa un **URI di una specifica versione** del secret `tenant-proof-key`, passato come metadata `tenant_proof_secret_version` (32 hex) da GitHub Environment. Il versionless usato originariamente in #21 poteva ottenere una nuova versione in background e riavviare revisioni attive prima che il key ID nel backend fosse aggiornato. Il preflight si basa su `az keyvault secret list-versions` (soli metadati e permesso secrets/list), filtrando l'ID esatto e `attributes.enabled`. Questi controlli **non** hanno accesso al valore HMAC e non devono poter vedere valori nel Terraform State.

Il pin impedisce l'adozione **automatica** della versione latest; non garantisce la corrispondenza tra chiave HMAC e ID Postgres, non impedisce replay di proof autentiche, non risolve la sincronizzazione delle revisioni del container o le chiavi storiche nello state. #19/#6 rimangono aperte.

## Nuova revisione senza promozione automatica — ADR 0017 / #23

Per limitare la race nella rotazione HMAC, Azure Container Apps usa in Terraform `Multiple` e conserva **100% traffico su `stable_revision_suffix`**; il nuovo template (revision suffix `r<sha12>`) ha **0%**. La secret application-scoped `tenant-proof-key` della stable conserva il riferimento versionato precedente; una secret distinta `tenant-proof-key-v<version>` è usata solo dal template candidato, senza modifica in-place del valore della stable. Il piano Terraform è sottoposto a gate fail-closed: vietate eliminazioni di altre risorse, sostituzione dell'app, mutazioni/rimozioni delle secret già presenti o auto-promozione latest. La fase richiede un deployment Azure già esistente; la prima installazione e i successivi rollout restano sotto un procedimento distinto (#6).

**Rischio residuo:** segreti ACA applicati all'intera app, etichette/revision direct URLs, disponibilità reale della stable, pairing key ID/Key Vault/DB, accessi al piano Terraform JSON, costi di replica calda, revisione autorizzata e modifica dei pesi dopo lo stage non sono verificati end-to-end. Nessuna garanzia zero downtime; #19/#6/#5 aperte.
