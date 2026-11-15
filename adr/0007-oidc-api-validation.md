# ADR 0007 — Validazione OIDC in Production e JWT demo solo in sviluppo

- Stato: Accepted (slice #12 di #2)
- Data: 2026-11-15
- Sostituisce: modalità di autenticazione produzione temporanea descritta in ADR 0004
- Riferimenti ufficiali: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication?view=aspnetcore-10.0 ; https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.jwtbearer.jwtbeareroptions?view=aspnetcore-10.0

## Contesto
Una firma JWT HS256 shared-secret è utile soltanto per la vertical slice locale. In Production un trusted identity provider deve firmare access token con chiavi private che l'API non possiede; l'API ottiene le chiavi **pubbliche** tramite i metadati OIDC/JWKS.

## Decisione
`AuthenticationConfiguration` seleziona rigorosamente due modalità:

- `DevelopmentJwt`: disponibile solo in Development/Testing; validazione HS256 con secret >= 32 byte e issuer/audience locali.
- `Oidc`: obbligatoria in Production; richiede `Authentication:Authority` URL assoluto HTTPS senza credenziali/query/fragment e `Authentication:Audience`. Non ammette `Jwt:SigningKey` in Production. `JwtBearer` con metadata HTTPS, issuer/audience/lifetime/signature obbligatori e allowlist algoritmi `RS256`. Refresh JWKS su chiave non trovata.

I claim `sub` e `organization_id` provengono solo dal JWT già validato. La membership attiva (ruoli) viene verificata nel PostgreSQL, non nei claim di ruolo.

Azure Terraform/Container Apps usa esplicitamente `Authentication__Mode=Oidc`, `Authentication__Authority`, `Authentication__Audience`; la chiave HS256 è rimossa dal provisioning Production.

## Limiti / next steps
- Questa ADR **abilita la validazione dei token**, **non realizza il login**. Manca collegamento a issuer reale, emissione/ottenimento token tramite authorization code+PKCE/BFF, session management, MFA, logout, refresh e revoca. Il portale contiene ancora il campo tecnico JWT, esclusivamente demo.
- Un IdP reale deve emettere access token per l'audience dell'API e `organization_id` validato; valutare amministrazione tenant e provisioning senza demandare scelte tenant al browser. Non accettare un semplice ID token al posto dell'access token.
- Algoritmo limitato intenzionalmente a RS256. Supportare ES256/altre chiavi richiede un ADR e test aggiuntivi.
- Le prove automatiche usano firma RSA e JWKS locali senza servizi esterni. Per produzione servono IdP validato, test d'integrazione con provider vero, onboarding e criteri di compliance SPID/CIE da studiare separatamente.
- L'identità cittadino e quella operatore devono essere progettate con policy distinte, evitando impersonificazione senza audit.

L'epica #2 rimane aperta.
