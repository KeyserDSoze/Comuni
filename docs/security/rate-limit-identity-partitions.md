# Limiti API per identità OIDC composta — #127 / ADR 0111

Il limiter per-replica della singola API segue `UseAuthentication` e usa `VerifiedPrincipalIdentity`, **non** i claim ruolo, per individuare un soggetto con autenticazione già validata. I bucket sono:

- `tenant:<sha256>` per `(organization_id, iss, sub)`: issuer + subject sono entrambi case-sensitive e ogni Comune resta separato.
- `platform:<sha256>` per `(iss, sub)` **senza** alcun claim `organization_id`: l'identità piattaforma non eredita i privilegi del Comune e il limiter **non concede** il ruolo Superadmin. La relativa policy di backend consulta sempre la roster DB di operatori autorizzati.
- `ip:<peer>` per richieste anonime, token non autenticati e tuple ambigue/mancanti (inclusi claim duplicati identici, organizzazione malformata e solo ruolo `Superadmin`). `X-Forwarded-For` e header arbitrari sono ignorati fino all'introduzione di un proxy trusted verificato.

La serializzazione è esatta/case-sensitive, usa **prefissi di lunghezza** indipendenti dai delimitatori e un digest SHA-256 a 64 cifre per non conservare in chiaro issuer e subject nelle chiavi del limiter. **SHA-256 non rende anonimi gli identificativi**: chi conosce valori prevedibili può provare dizionari se una chiave viene esposta. Non includere mai i bucket interni in log, metriche ad alta cardinalità o response headers. La fingerprint non è mai usata per access control, audit actor o identità RLS.

L'API oggi valida un issuer OIDC configurato alla volta: multi-issuer simultaneo è un caso di regressione progettuale, non un'esperienza di federazione già fornita. Il limiter resta `120/60s` di default, memoria **per replica**, senza coda, per sole route `/api`. Non protegge da attacchi DDoS distribuiti, IP spoof attraverso proxy non configurati o operatori con JWT regolari multipli. Servono controlli edge, network, observability senza PII e test load/live autorizzati prima del go-live. Né Azure né PostgreSQL RLS cambiano. Vedere [tests](../testing/rate-limit-identity-partitions.md).
