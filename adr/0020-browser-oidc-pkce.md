# ADR 0020 — Client browser Authorization Code + PKCE S256 per l'API Comuni

- Stato: Accepted **come incremento tecnico** (#26 di #2), non accettazione di un IdP reale / produzione PA
- Data: 2026-11-15
- Integra ADR 0004 e 0007; mantiene l'API .NET 10, React unico e un database PostgreSQL.
- Fonti: [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html), [RFC 10017 — OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017.html).

## Contesto

L'API già valida JWT OIDC RS256/JWKS in Production e autorizza per `sub`/`organization_id` da membership DB, ma il frontend demo richiedeva di incollare un JWT. Questa interfaccia non costituisce un accesso reale ed è inaccettabile come fallback di produzione. Per usare un IdP reale occorre implementare almeno il flusso OAuth standard; la registrazione/provider e la valutazione di sessioni server-side restano in #2.

## Decisione

Il backend espone pubblicamente **solo metadati** con `GET /api/v1/auth/browser`: `mode` (DevelopmentJwt/Oidc), `enabled` e, se configurati, `issuer`, `clientId`, endpoint di autorizzazione/token, scope. In Demo il browser client è disattivato; in Production/Oidc senza i quattro parametri completi resta disabilitato e il form manuale scompare. Con valori parziali/insecure la configurazione **fallisce all'avvio**: niente client secret, endpoint HTTPS sullo stesso host dell'Authority JWT, scope `openid` e API delegato senza `offline_access`. Metadati non sensibili si possono distribuire via Terraform/GitHub Environment.

Il React usa un **public browser client**, senza client secret, con `response_type=code`, `code_challenge_method=S256` prodotto da `crypto.subtle.digest`, `state` random. La SPA verifica `state` e scadenza (5 minuti) attraverso sessionStorage, elimina la transazione prima di consumare il codice, scambia il codice direttamente via CORS sul token endpoint dell'IdP e usa solo `access_token` di tipo Bearer per l'API. `id_token`/refresh token non sono conservati. L'access token rimane nello stato RAM React, non in storage persistente; logout lo azzera (non revoca la sessione dell'IdP). La callback usa `window.location.origin + '/'` e cancella query code/state immediatamente al caricamento. Redirect URI esatta deve essere registrata nell'IdP. I token sono esclusivamente **input al backend JWT validation**, mai fonte di ruoli client-side o di tenant override.

## Alternative e trade-off

- **BFF con cookie HttpOnly nella stessa API (.NET 10)**: RFC 10017 considera questo pattern più resistente all'esfiltrazione degli access/refresh token dal browser. È preferibile a lungo termine per operazioni sensibili della PA; richiede session store, CSRF, cookie SameSite/Secure, token exchange server-side, protezione da session fixation e strategia di logout. Non implementato in questa slice. Prima del go-live rivalutare il pattern e prendere decisione formale.
- **SPA PKCE diretta** (scelta limitata): possibile con IdP che permette CORS e redirect esatti; non serve un secondo backend e non si distribuiscono segreti. Rischio XSS e token esposti a JS, sessioni perse al refresh e assenza di refresh token (nuovo login alla scadenza).
- **Implicit flow / Resource Owner Password Credentials / JWT demo produzione**: scartati per sicurezza e RFC 9700; nessuna modalità alternativa OAuth consente bypass autorizzativo.

## Rischi e follow-up

Il client non dispone ancora di un IdP reale. Non sono stati verificati in Azure `issuer`/audience di token esterni, callback, CORS, onboarding, flussi per utenti cittadini, SPID/CIE, MFA, revoca, federation e provider policy. Qualunque flusso reale deve emettere `organization_id` e `sub` attendibili e già registrati nel DB per Admin/Officer/Reader, con protocolli autorizzativi separati per Comune. Implementare BFF/safe session se il threat model del trattamento dati lo richiede e valutare SAST/OWASP ASVS prima della produzione. L'issue #2 rimane APERTA. CI TDD su Playwright, xUnit, PostgreSQL, Terraform e Docker non equivale a provider live conformance.
