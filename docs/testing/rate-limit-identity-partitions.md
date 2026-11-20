# Test TDD — rate-limit namespace issuer / Comune / piattaforma (#127)

`tests/backend/Comuni.Api.Tests/ApiProtectionTests.cs` contiene prove xUnit con `DefaultHttpContext` e principal sintetici per il parser `VerifiedPrincipalIdentity`. Sono indipendenti dal provider OIDC reale, dalle chiavi Key Vault e dalla rete Azure. In particolare:

1. **Stesso organization ID e sub, issuer distinti** => fingerprint/bucket diversi; stessi tre valori => quota stabile anche cambiando il peer IP o simulando un `X-Forwarded-For` forgiato; cambiando Comune => quota distinta.
2. **Identità platform tenantless** con `iss+sub` => namespace `platform` differente da anonimi, un altro subject, un altro issuer e dalla stessa identità a cui viene associato un Comune; il ruolo JWT non è una scorciatoia autorizzativa.
3. **Invalidità**: claim `iss`, `sub`, `organization_id` duplicati/ambigui, GUID non valido/zero, issuer o subject mancante e sola dichiarazione JWT `Superadmin` => fallback rigoroso alla quota `ip:<peer>`, indipendente da header client.
4. **Collisioni**: issuer/subject con caratteri `:` in posizioni diverse devono generare fingerprint distinte. Per le partizioni autenticate l'output ha lunghezza fissa, non riporta issuer/subject/tenant in chiaro.
5. Rimangono i test HTTP originali: quarta request anonima => **429**, `Retry-After`, headers di sicurezza/no-store, spoof `X-Forwarded-For` non influenza bucket; test xUnit/PostgreSQL, pgAudit, React/Playwright, Terraform/Python, CodeQL, NuGet/npm e build Docker sono gate CI.

RED [`2f35291`](https://github.com/KeyserDSoze/Comuni/commit/2f35291a62d2ba03c5059e5a88f16f5d0332b9b5), [Actions 44807542710](https://github.com/KeyserDSoze/Comuni/actions/runs/44807542710) => **373 test API verdi, 2 falliti attesi**: rate limit uguale per due issuer comunali e fallback IP per operatori tenantless. La fase GREEN implementa namespace separati e SHA256 su serializzazione senza collisioni; chiusura #127 **soltanto dopo 7/7 job success allo SHA finale HEAD `main`**. Non rappresenta una prova multi-issuer OIDC federato reale né una quota distribuita tra repliche.
