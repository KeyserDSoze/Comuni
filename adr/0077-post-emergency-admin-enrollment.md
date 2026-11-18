# ADR 0077 — Enrollment ordinario post-emergenza con audit accoppiato e riattivazione verificata

- Data: 2026-11-18.
- Stato: **Accepted per test sintetici offline, non autorizzato per l'uso in produzione** fino a verifiche #84, #86, IdP e approvazioni reali.
- Issue: #87; segue ADR 0069 (enrollment), 0071 (revoca ordinaria) e 0072 (emergency staging), senza modificare i loro confini operativi.
- Riferimenti: [PostgreSQL espliciti row-level locks](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS); [OpenID Connect issuer/subject](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStabilityAndUniqueness).

## Contesto e minacce

Il recovery offline #85 conserva il vecchio Admin compromesso come membership inattiva e registra due eventi append-only, `platform.membership.admin.emergency.revoked` (precedente issuer+subject) e `platform.membership.admin.emergency.staged` (nuovo issuer+subject), con la stessa correlazione `emergency:INC-...`. Dopo un change owner separato di riattivazione, #83 riconosceva soltanto l'audit di revoca *ordinaria*: un Comune legittimamente recuperato non poteva inserire il secondo Admin di continuità senza cancellare o riattivare identità storiche. Accettare ogni inactive Admin senza verificare la coppia aprirebbe invece un percorso di privilege grant basato su audit incompleto, duplicato o non riconducibile al nuovo Admin.

## Decisione

1. Estendere **solo** il percorso già owner-only offline `scripts/postgres/enroll-additional-admin.sql`. Il lock `SELECT ... FOR UPDATE` su `platform.organizations` e i controlli dello stato `is_activated=TRUE, is_suspended=FALSE` precedono la lettura del roster; niente nuova API, ruoli, grants, flag o frontend. Ogni Admin attivo deve avere issuer HTTPS ammissibile e deve esistere almeno un Admin attivo.
2. Per **ogni** Admin storico inattivo esigere issuer valido ed **esattamente un** audit di revoca per `md5(org|Admin|subject|issuer)::uuid`. La revoca ordinaria resta accettata solo con owner actor e correlazione `admin-revoke:<ticket>`. L'evento emergency revoked è ammissibile solo con actor `db-owner:...`, correlazione `emergency:INC-...`, **esattamente due** audit dell'incident nello stesso Comune e una coppia `emergency.staged` con resource hash di **un Admin OIDC attualmente attivo**, actor e `occurred_at` identici al revoke. L'identità compromessa non deve avere altre membership nello stesso Comune.
3. La **riattivazione è indipendente**: l'ultimo audit owner del ciclo sospensione/riattivazione deve essere `platform.organization.reactivated` per lo stesso Comune, con timestamp non precedente all'emergency revoke; il solo flag DB `is_suspended=FALSE` non basta. Un tenant ancora sospeso non può eseguire enrollment. Non si assume che l'audit dimostri la reale approvazione umana, ma solo la sua coerenza interna.
4. Verificare anche gli eventi emergency **orfani**, non raggiungibili dal roster: resource_type, formato correlazione, actor, conteggio due eventi e membro opposto con stesso actor/tempo; ogni revoked deve corrispondere a un Admin inattivo, ogni staged a un Admin attivo. Audit duplicati, eventi senza membro corrispondente o messaggi aggiuntivi con la stessa correlazione bloccano la transazione. Per prudenza un futuro turnover dell'Admin staged che rendesse il pair non più corrente richiederà un nuovo ADR/change; non introdurre automaticamente transitive trust.
5. Preservare la prevenzione del replay: nessuna concessione a un subject che esiste o ha un precedente audit di grant/revoke/stage per il binding; il ticket emergency non può essere riutilizzato come ticket di enrollment. Il retry esatto dell'enrollment ordinario resta no-op, mentre due tentativi simultanei con lo stesso ticket ma subject diversi non devono creare due Admin.
6. Nessun evento di audit viene modificato, cancellato o riattivato; lo script aggiunge solo la nuova membership e un `platform.membership.admin.added` transazionali. Il DB runtime resta privo dei privilegi di owner. Gli script non revocano sessioni IdP esterne e non effettuano identity proof.

## TDD e validazione

Il primo commit RED #87 aggiunge `PostEmergencyAdminEnrollmentTests.cs` con PostgreSQL 17, `psql`, token OIDC RS256 firmati localmente e due Comuni sintetici. Il RED ha dimostrato **2 fallimenti attesi su 340 test API**, pur con 338 già verdi: enrollment del secondo Admin dopo recovery e concorrenza su ticket. GREEN implementa i guard owner-only con casi negativi di audit duplicato/orfano, tenant sospeso, target esistente, riuso ticket emergency e runtime SQL. Playwright è regression gate: non serve una nuova UI per un'operazione *offline* senza route HTTP. Richiedere sempre l'ultima CI **7/7 verde sul medesimo SHA main** prima di chiudere #87; nessuna esecuzione locale o Azure live viene implicitamente dichiarata.

## Limiti di sicurezza e rilascio

Un `db-owner` compromesso può falsificare righe o audit e non è sostituito dalla verifica del workflow; hash issuer/sub sono pseudonimi, non anonimi. Prima di produzione: verificare realmente identità/MFA/revisori e incident approval (#84), eliminare rischi dei literal nei server log di issuer/subject nel *restante* percorso enrollment (#86), policy retention/audit (#4), configurazione pgAudit/Azure e autorizzazione esplicita dell'operatore. La #92 sul leak di verificatori SCRAM in configurazioni reali resta indipendente. In caso di dubbio sospendere il Comune e bloccare il change, non disabilitare i guard o ripristinare vecchie identità.

## Nota sul trasporto degli identificativi (#94, ADR 0078)

La politica di trust emergency/post-reattivazione di questo ADR è invariata. Il suo script owner-only di enrollment ora importa il binding issuer/sub tramite `\\copy` privato in TEMP table e non tramite `psql :'add_admin_*'`, per mitigare i literal nei log statement PostgreSQL. L'ADR 0078 documenta il perimetro dell'intervento e i limiti: non si assume protezione dei payload COPY in Azure/SIEM, né verifiche IdP o reviewer reali. Restano aperte #84 e #86.
