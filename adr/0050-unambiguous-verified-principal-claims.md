# ADR 0050 — Unicità fail-closed dei claim JWT di identità municipal e platform

- Stato: Accepted per la semantica di `ClaimsPrincipal` nell'API, non certificazione di un IdP esterno.
- Data: 2026-11-16.
- Issue: #57 (sotto #5, #2 e #4); #49 resta in lavorazione Azure separata.
- ADR esistenti: 0002, 0005, 0011–0014, 0022, 0028, 0029, 0035, 0036.
- Riferimenti: [ASP.NET Core Claims-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/claims), [ASP.NET Core JWT bearer authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-jwt-bearer-authentication), [OIDC Core — issuer/subject pair](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStabilityAndUniqueness).

## Minaccia e problema

In un sistema multi-organization, l'API riceve dal JWT firmato un `organization_id`, `sub` e `iss`. Il backend usa la coppia `iss/sub` per la membership PostgreSQL, RLS firmata per la transaction tenant-scoped e un'identità separata tenantless per il Superadmin. La firma valida autentica l'origine del token ma non definisce in modo uniforme la selezione se **il principal ASP.NET Core ha più claim dello stesso tipo**. `FindFirst` era chiamato da sei punti indipendenti: un principal con claim identitari multipli avrebbe potuto essere interpretato in modo incoerente nei controlli d'accesso, firma RLS, audit e rate limit. Il doppio claim, anche con due valori identici, non è normalizzato automaticamente dal codice applicativo né deve essere usato come scorciatoia di selezione.

## Decisione

1. **Un unico interprete server-side:** `VerifiedPrincipalIdentity.TryMunicipal` accetta soltanto `ClaimsPrincipal` autenticato contenente esattamente **un** `organization_id` UUID non vuoto, un `sub` valido di 1–160 caratteri e un `iss` valido di 1–512 caratteri, senza whitespace esterno o control characters. Il confronto del valore `iss` è **esatto** nel membership store, senza normalizzazioni o rebind; un issuer legacy `DevelopmentJwt` non viene confuso con un issuer OIDC. In presenza di duplicate claims identici o discordanti, input vuoto, mancante o malformato, restituisce fail closed senza identificatore parziale.
2. **Identità piattaforma distinta:** `TryPlatform` accetta un solo `iss` e un solo `sub`, richiede assenza totale del claim `organization_id`. `PlatformOperatorHandler` continua a richiedere modalità OIDC, issuer HTTPS trusted e attestazione dal roster PostgreSQL separato. Non sono possibili `role=Superadmin` dal JWT o commistioni con una membership municipal.
3. **Stessi dati in tutte le fasi:** `OrganizationRoleHandler` nega prima di chiedere lo stato Comune/membership; `HttpCurrentOrganization` espone `Guid.Empty` per un principal ambiguo; `HttpCurrentActorContext` non registra un soggetto arbitrario; `ApiProtectionSettings.PartitionKey` usa IP reale, non un tenant dedotto; la request middleware non inizia la signed RLS transaction in assenza di identità univoca. `/api/v1/context` e `/api/v1/platform/organizations` riusano il controllo prima delle letture sensibili. La risposta non espone valori raw dei claim.
4. **Non cambia il confine di autenticazione:** JwtBearer mantiene verifica di firma, issuer, audience, scadenza, algoritmo consentito (RS256 in produzione) prima delle policy; l'helper non accetta token da header non validati né può essere chiamato dalla SPA per scegliere il Comune. In Demo/Testing i seed con un solo `iss` continuano a funzionare. Il validatore dei claim non prova che un parser JWT abbia preservato tutte le chiavi duplicate nel **JSON originale**: un futuro hardening a livello di token parser può richiedere un'altra slice con test su JWT serializzati e IdP.
5. **TDD:** prima xUnit RED con fake Directory/MembershipStore e PlatformOperatorStore, verificando zero query, contesti tenant/audit e partitioning su principal validi e duplicati; GREEN helper e wiring senza nuove migrazioni. Tutti i sette job CI della stessa HEAD `main` sono obbligatori prima di chiudere #57.
6. **Limiti:** nessuna integrazione IdP/OIDC reale, revoca live, prova Azure VNet/CA/TLS o completo sistema di impersonificazione/audit normativo. Le epiche #2/#4/#5 e #49 rimangono aperte. Nessun secondo frontend/API/DB, nessun nuovo grant SQL.

## Alternative scartate

- Scegliere primo/ultimo claim o deduplicare anche valori identici: introduce interpretazioni dipendenti dal parser e divergenze tra componenti.
- Affidarsi esclusivamente al token `role`, a un `organization_id` di query/header o a una store query senza check: aggira il perimetro multi-organization.
- Trattare un operatore tenantless come un Comune speciale: rischia perdita di isolamento e creazione di privilegi non previsti.
