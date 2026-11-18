# ADR 0025 — Bootstrap iniziale di una membership Admin OIDC con solo schema owner

- Stato: Accepted come **strumento controllato offline**, senza provisioning di identità reale (issue #31)
- Data: 2026-11-15
- Dipendenze: ADR 0002, 0005, 0006, 0011–0014, 0020–0022; issue #2/#3/#4/#5/#10
- Fonte: [OpenID Connect Core 1.0 §5.7 — soggetto unico per issuer](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStabilityAndUniqueness)

## Problema

Nell'API già esistono controllo di membership OIDC per coppia esatta `iss`+`sub`, RLS tenant e gestione Admin solo per Reader/Officer. Il **primo** Admin di un Comune deve però essere creato da un processo separato, prima che esista un operatore autenticabile. Esporre una mutation API cross-tenant o inferire l'identità dalla email/issuer di default violerebbe il confine di fiducia. Un backfill automatico da `identity_issuer=NULL` sarebbe pericoloso.

## Decisione

- Per una organization **già esistente, attiva e senza alcuna riga Admin** il runner operatore privato esegue `scripts/postgres/bootstrap-initial-admin.sql` attraverso `psql -X -q -v ON_ERROR_STOP=1`, con il **login owner dello schema e delle tabelle audit/membership**. Non viene creato un endpoint HTTP, un provider OIDC, un token o una nuova app.
- Il tool richiede in environment: `COMUNI_BOOTSTRAP_ORGANIZATION_ID`, `COMUNI_BOOTSTRAP_IDENTITY_ISSUER`, `COMUNI_BOOTSTRAP_SUBJECT`, `COMUNI_BOOTSTRAP_CHANGE_TICKET`, `COMUNI_BOOTSTRAP_APPROVER`. Un operatore autorizzato deve prima attestare separatamente il `sub` **esatto** tramite IdP affidabile, `iss` HTTPS canonico, audience API, titolarità della persona, id del Comune e change approvato da revisore indipendente. Lo script può validare solo sintassi e presence dell'approvazione, **non può attestare che approvatore o identità siano reali**. Gli identificatori di identità sono case sensitive, senza fallback.
- Usa `SET LOCAL` all'interno di una transazione PostgreSQL; tutte le variabili psql sono **quoted literals** (`:'var'`) e mai SQL dinamico. Le guardie SQL rifiutano ruolo diverso dal proprietario, ID nullo/sconosciuto, org sospesa, issuer non HTTPS o di forma conservativa errata, sub con controlli/whitespace esterni, ticket e reviewer mancanti o non validi.
- Prima dell'inserimento acquisisce `SELECT ... FOR UPDATE` sulla riga dell'organization. Due provisioning concorrenti per lo stesso Comune sono serializzati. Se esiste una qualsiasi riga Admin (anche inattiva o legacy `identity_issuer=NULL`), il comando rifiuta il cambiamento. Solo un retry dell'**identica membership attiva, stesso issuer** restituisce no-op. Non è un modo per gestire il secondo Admin, trasferire issuer o ripristinare un account disattivato.
- La prima assegnazione e l'evento `platform.membership.admin.initialized` in `platform.audit_events` sono nella **stessa transazione**. Audit: organization, attore database `db-owner:<current_user>`, action, resource id pseudonimizzato, correlation `bootstrap:<ticket>`, tempo; non contiene subject/issuer in chiaro. Il riferimento al reviewer è controllato nel change ticket esterno e non viene spacciato per claim JWT verificato. I privilegi RLS runtime continuano a **negare** qualsiasi INSERT/UPDATE del ruolo Admin.
- Un rollback non può cancellare l'audit append-only e non è automatizzato: in caso di binding errato bloccare il go-live e aprire un nuovo change incident/owner con verifica dell'identità, preservando tracce.

## Limiti

Il comando non verifica OIDC discovery, possesso dell'account, MFA, approvazione realmente firmata, migrazioni IdP, revoca sessioni o compliance. Deve essere eseguito **solo** in un ambiente autorizzato con rete privata PostgreSQL, TLS e account owner segreto, dopo migrazioni EF e prima di abilitare il login. La CI testa con due organization sintetiche, psql e PostgreSQL 17: **nessun bootstrap production live è stato eseguito**. Un proprietario DB compromesso conserva ampi privilegi; servono controllo accessi e separation of duties esterni. I workflow Superadmin/gestione di altri Admin restano nella #3/#10 e l'IdP effettivo nella #2.

## Emendamento sul trasporto degli identificativi (#95 / ADR 0079)

La descrizione originaria dei `quoted literals` `psql :'var'` resta documentazione della **versione precedente**, non dell'implementazione corrente. Per ridurre la raccolta di issuer/sub nei log PostgreSQL delle statement, il bootstrap usa adesso `\\copy` locale e input da temp table secondo ADR 0079. I controlli schema owner, tenant, first Admin, audit append-only e idempotenza descritti sopra restano invariati. L'aggiornamento non autorizza procedure reali senza #84/#86 e verifica delle pipeline di logging.
