# ADR 0010 — Rate limiting API e protezione delle risposte HTTP

- Stato: Accepted (vertical slice #15 della security epic #5)
- Data: 2026-11-15
- Relazione: ADR 0001, 0002, 0007, 0008, 0009
- Documentazione tecnica: https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit?view=aspnetcore-10.0 ; https://learn.microsoft.com/en-us/aspnet/core/security/enforcing-ssl?view=aspnetcore-10.0

## Contesto
L'API espone endpoint autenticati ma senza protezione automatica da richieste in burst e senza politica browser centralizzata. La piattaforma rimane un Modular Monolith con una sola API/React e PostgreSQL.

## Decisione
Usiamo esclusivamente **ASP.NET Core rate-limiting built-in**: finestra fissa con auto-replenishment, 120 permessi ogni 60 secondi, nessuna coda, risposta 429 con `Retry-After`. È attivo **solo per `/api`**. La partizione viene calcolata **dopo** `UseAuthentication` dal Principal JWT già validato (`organization_id` GUID e `sub`) e in mancanza di identità verificata dall'IP della connessione. Non si legge `X-Forwarded-For` o altri header scelti dal client come identità. Parametri `Security:ApiRateLimit:PermitLimit` e `Security:ApiRateLimit:WindowSeconds` sono controllati all'avvio.

Un middleware precedente applica su tutte le risposte anti-MIME-sniff, anti-frame, no-referrer, Permissions-Policy e Content-Security-Policy di stessa origine con supporto PWA; per `/api` aggiunge cache no-store. La CSP conserva temporaneamente `style-src 'unsafe-inline'` per compatibilità UI; nessun `unsafe-eval` o script-inline. Health e asset statici sono esenti dalla quota.

## Conseguenze / limitazioni e rischio residuo
- Quote **in memoria per replica**; restart azzera i contatori; non è un sistema distribuito o WAF anti-DDoS. Configurare edge rate-limits, telemetria/alert 429 e load test prima del go-live.
- IP anonimo visto dietro Azure Container Apps può essere quello del proxy: la policy può raggruppare più client. Non usare forwarded headers non verificati; configurare solo proxy noti con test di rete in un incremento futuro.
- Nessun HSTS/redirect HTTPS imposto sul traffico HTTP interno dell'app: terminazione TLS e relative intestazioni devono essere verificate alla frontiera Azure. Non è una validazione HTTPS reale.
- L'implementazione non cambia i ruoli, le policy e il backend tenant enforcement. RLS, privilegi DB minimi, secret scans e conformità sono scope separato, #5 resta aperta.
