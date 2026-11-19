# ADR 0021 — Membership Reader/Officer amministrabili per Comune con RLS restrittiva e audit

- Stato: Accepted **come slice del Core**, senza IdP/provider reale (#27)
- Data: 2026-11-15
- Dipendenze: ADR 0002, 0005, 0006, 0009, 0011–0013, 0020 e issue #2/#3/#5/#10

## Problema

Il database e le API convalidano membership Admin/Officer/Reader, ma non esisteva un flusso Admin Comune per gestirle. In assenza di un provider OIDC registrato non è possibile creare utenti reali, ma è necessario un meccanismo per preprovisionare **solo** membership di soggetti IdP verificati offline e aggiornare l'autorizzazione immediatamente. Un `GRANT INSERT` generale avrebbe permesso a eventuale SQL injection di inserire un ruolo **Admin** sotto `comuni_app_runtime`, aggirando il controllo C#.

## Decisione

- **API unica:** `GET /api/v1/admin/memberships`, `PUT /api/v1/admin/memberships/{role}`; solo policy Admin persistita nel DB e organization dal JWT validato. PUT accetta solo `Reader` e `Officer`, `subject` OIDC esatto e boolean `enabled`. I nomi del ruolo Admin, Superadmin/ignoti sono rifiutati, e il Comune non è impostabile dal browser. GET mostra le membership Admin **solo in lettura**.
- **Business/Core:** service con whitelist e validazione conservativa del `sub`, case-sensitive, nessuna emissione JWT, nessuna creazione IdP. Attivazione/upsert, disattivazione senza cancellazione, idempotenza; `subject` non è cambiato, riusato o aggiustato silenziosamente.
- **Persistence:** `INSERT ON CONFLICT ... DO UPDATE` parametrizzato per attivazione e UPDATE parametrizzato per revoca; la PK composta impedisce duplicati concurrenti. Solo cambiamenti reali aggiungono `AuditEvent` nella **stessa transazione**. Il resourceId audit è deterministico SHA256(troncato) di tenant/ruolo/subject, con actor e correlation verificati; è pseudonimizzazione, non garanzia di anonimato. Audit non contiene mai il `sub` del target in chiaro.
- **Seconda barriera DB:** `comuni_app_runtime` riceve `INSERT` sulle colonne di `platform.organization_memberships` e `UPDATE(is_active)` soltanto; migrazione `202611150008_RuntimeMembershipRoleGuard` aggiunge policy **RESTRICTIVE INSERT/UPDATE** su `platform.organization_memberships` con `current_user <> 'comuni_app_runtime' OR role IN ('Reader','Officer')`. Poiché le policy tenant originali sono permissive, queste si applicano con AND. Un attore con SQL runtime non può inserire un Admin nemmeno con prova HMAC per il proprio tenant, mentre owner/migrazioni continuano a poter predisporre gli amministratori con procedura esplicitamente privilegiata.
- **Frontend unico:** schermata Amministrazione mostra l'elenco filtrato dal backend, form di assegnazione Reader/Officer e pulsanti attiva/disattiva. Non effettua operazioni di Admin role e non trasferisce override tenant.

## Compromessi / vincoli

- **Primo e ultimo Admin:** non si deve disattivare o sostituire dall'interfaccia generica. Il futuro flusso Superadmin/tenant-admin richiederà autorizzazione forte, serializzazione per evitare due revoche concorrenti, audit tracciato e verifiche operatore (#3/#10).
- Il `sub` inserito dall'Admin può essere inesistente o appartenere a un diverso issuer finché non esistono onboarding e verifica reale. Il backend **non** garantisce ancora binding `issuer+sub`, email claim verificati, federazione SPID/CIE, MFA o revoca di sessione esterna (#2). Proibire pre-provisioning con utenti reali non confermati.
- Il ruolo PostgreSQL runtime può ancora operare su Reader/Officer in caso di SQL injection/compromissione; la RLS evita il cross-tenant, non la compromissione del singolo tenant. Sicurezza generale, audit esterno, strumenti antivirus/log retention, backup e test Azure restano nella #5/#6.
- Il resourceId audit è riproducibile dal soggetto: non trattarlo come anonimizzato GDPR e definire retention/disclosure nel processo complessivo.
- Nessuna nuova applicazione, database o provider, niente SPID/CIE e nessuna garanzia di conformità PA o produzione pronta.

## Evoluzione ADR 0022

La gestione Reader/Officer da parte dell'Admin vincola ora le membership OIDC all'**issuer autenticato** dell'Admin. Il binding non è sovrascrivibile da body e non viene riassegnato automaticamente per righe con issuer NULL o diverso; un conflitto restituisce 409. Vedere ADR 0022 per runbook fail-closed di migrazione identità.

## Emendamento #110 / ADR 0093 — integrità semantica dell'audit Reader/Officer

La validazione dell'audit in `MembershipAdministrationRepository` ora verifica in modo fail-closed action, tipo risorsa, pseudonimo di `organization|role|sub|issuer` e contesto tenant prima di ogni SQL, in aggiunta a ruoli Reader/Officer, issuer OIDC e RLS già previsti. Il calcolo SHA256 originale è stato estratto in `MembershipAuditResourceIdentity` e condiviso fra Business e Persistence, senza cambiare gli ID emessi e senza aggiungere plaintext del target all'evento. Anche `ListAsync` nega in modo esplicito letture richieste per un Comune diverso dal contesto. Vedere ADR 0093 e test con login PostgreSQL runtime ristretto; non sostituisce la review della privacy, l'IdP reale o la protezione dell'audit contro owner DB.
