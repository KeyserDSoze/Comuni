# ADR 0030 — Area Superadmin read-only nella PWA unica, autorizzata via sessione OIDC platform

- Stato: Accepted come **prima schermata informativa** Superadmin, non console amministrativa completa (#36).
- Data: 2026-11-15.
- Dipendenze: ADR 0001/0004/0005/0007/0008/0020/0022/0028/0029; issue #2/#3/#5/#10/#34/#35/#36.
- Fonti: [OAuth Security BCP RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [Browser-Based Applications RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html), [WAI-ARIA APG Navigation](https://www.w3.org/WAI/ARIA/apg/patterns/).

## Problema

Le issue #34 e #35 hanno separato le identità piattaforma da Admin comunali sul backend/PostgreSQL, ma la React PWA assumeva che qualsiasi utente autenticato ricevesse il contesto `GET /api/v1/context` associato a `organization_id`. Un token OIDC platform correttamente **privo** di tenant viene quindi rifiutato dalle API comunali (403) e non accede neppure a una pagina informativa. Sarebbe pericoloso autorizzarlo attraverso un claim JWT `role=Superadmin`, consentire un `organization_id` nel client o esporre automaticamente una lista di Comuni.

## Decisione

1. Un **solo frontend React**, una API e PostgreSQL. La PWA rimane l'app esistente e riutilizza `Brand`, design system, navbar/sidebar, modalità chiara/scura e i18n italiano/inglese; **nessuna** applicazione o rotta backend aggiuntiva. La nuova vista è soltanto la sessione dell'operatore piattaforma: titolo, ruolo `Superadmin` verificato server-side e indicazione che i dati comunali/impersonificazione sono indisponibili.
2. Dopo l'**esistente** flusso browser OIDC Authorization Code + PKCE, lo stesso access token **solo in memoria React** viene inviato a `GET /api/v1/context` e, **solo in modalità OIDC**, a `GET /api/v1/platform/session`, senza decodificare JWT o inferire il ruolo da `role`, `groups`, email, URL, localStorage o variabili di configurazione client. Non si introduce un client secret o un secondo login.
3. Le risposte sono interpretate come **esclusive**: contesto comunale valido e nessuna sessione platform ⇒ area comunale; sessione platform esattamente `{"role":"Superadmin"}` e nessun contesto comunale ⇒ area informativa piattaforma; entrambe riuscite, entrambe rifiutate, una risposta con proprietà extra o ruolo diverso ⇒ **nessuna area autorizzata**. La risposta platform deve essere 200 e JSON con un solo campo. Il backend **resta l'unica fonte di autorizzazione**: una voce di menu non concede un privilegio né seleziona un Comune.
4. La vista piattaforma può usare il percorso client `/platform` in History API per navigazione/deep link, ma la sua esistenza **non** conferisce autenticazione. Un deep link anonimo mostra il login, e i token DevelopmentJwt non chiamano mai la sessione platform; l'app non carica dati cross-tenant neppure per operatori riconosciuti. Il backend `PlatformOperatorHandler` continua a richiedere JWT RS256 validato, `iss` + `sub` attivi e assenza di `organization_id`. Un normale Admin Comune non vede il link Superadmin.
5. La sessione platform viene ricontrollata con API prima della navigazione e alla ripresa del focus della finestra; al primo 401/403 o payload inatteso il client cancella immediatamente la vista/voce di menu. Il logout e la scadenza del token puliscono il contesto piattaforma, il token in RAM e l'eventuale percorso `/platform`. Una ricarica pagina **non** recupera il token: nuovo login OIDC obbligatorio. La revoca lato DB è **effettiva sulla richiesta backend successiva**, non equivale a invalidare i JWT presso l'IdP.
6. Le regressioni Playwright usano risposte OIDC e server **simulate**, con verifica PKCE esistente, ruoli fittizi/403, deep link anonimo/demo, 200 platform, 401, payload extra, esito ambiguo tenant+platform, revoca alla ripresa focus, logout, storage, localizzazione e tema. I test backend xUnit/PostgreSQL degli ADR 0028/0029 rimangono invariati ed essenziali: i mock frontend non provano la protezione server.

## Alternative considerate

- Un secondo portale per il Superadmin: **scartato**, romperebbe l'app unica e duplichererebbe sessioni e design.
- UI privilegiata basata sul claim JWT `role=Superadmin` o sul path `/platform`: **scartato** per escalation da token comunali, demo o URL manipolato.
- Memorizzare l'access token tra i reload: **scartato** per non estendere l'esposizione a XSS/storico browser. Valutare un BFF con cookie HttpOnly nella stessa API per operazioni PA sensibili prima della produzione (ADR 0020).
- Caricare l'elenco organizzazioni appena si entra nel Superadmin: **rinviato** per definire autorizzazione cross-tenant, SQL least privilege, privacy, minimizzazione e audit delle consultazioni. Nessuna nuova query agli enti è stata aggiunta.

## Limiti e rischi

Il percorso `/platform` è **solo UI**: non è un confine di sicurezza e non rende privata la stessa SPA. Il browser può ricevere token OIDC in memoria JS (XSS risk) e i test usano un provider fittizio, non Azure live o MFA reale. La verifica al focus/non al background non garantisce che una schermata già resa sparisca immediatamente se il DB cambia durante inattività; **la API protegge ogni richiesta**, e la schermata non contiene dati sensibili. Non sono disponibili console di gestione Comuni, utenti e impostazioni, audit consultazioni globali, impersonificazione né controllo di operazioni reali. L'area non dimostra conformità normativa. Le epiche #2/#3/#5/#10 rimangono aperte.
