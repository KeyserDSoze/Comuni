# ADR 0054 — Fail closed per OIDC e nomi canonici nell'ambiente della candidata ACA

- Stato: Accepted **solo per il controllo offline del Terraform plan**, non per un provider OIDC reale.
- Data: 2026-11-16.
- Issue: #62; dipende dalle #2/#5/#6/#49 e dall'ADR 0053.
- Specifiche: [Azure Container Apps — environment variables](https://learn.microsoft.com/en-us/azure/container-apps/environment-variables); [ASP.NET Core — configuration keys](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/); [Configuration providers .NET](https://learn.microsoft.com/en-us/dotnet/core/extensions/configuration-providers).

## Problema e minaccia

Il workflow manuale di staging passa una candidata all'unica API .NET con secrets HMAC e SQL versionati, mentre la stable rimane al 100% del traffico. La candidata ha una **label pubblicabile raggiungibile direttamente** anche se riceve lo 0% del traffico ordinario. Il gate controllava il tenant HMAC, il DB e il split dei pesi ma non l'ambiente effettivo né la modalità di autenticazione della candidata; un piano alterato poteva lasciare `Authentication__Mode=DevelopmentJwt` o `ASPNETCORE_ENVIRONMENT=Development`.

Azure Container Apps documenta che, se una chiave di environment si ripete, **prevale l'ultima**. Le chiavi della Configuration API .NET sono invece case-insensitive e normalizzano `__` in `:`. Un piano poteva includere `ConnectionStrings__Default` valido per il controllo stringa esatta, seguito da `connectionstrings__default` o `ConnectionStrings:Default` con password in chiaro; analogamente per `Authentication__Mode`, authority, audience, HMAC e host PostgreSQL. `DOTNET_ENVIRONMENT` costituisce un ulteriore possibile selettore dell'ambiente .NET.

## Decisione

1. Dopo aver verificato l'unico container della candidata, `check-staged-rollout-plan.py` convalida **tutte** le `template.container.env` prima dei controlli preesistenti. Gli oggetti devono essere dizionari con `name` ASCII non vuoto composto solo da lettere, cifre e underscore, senza separatori `:`, spazi o caratteri speciali. Il nome canonico è `name.replace("__", ":").casefold()`; non sono consentiti **duplicati canonici**, a prescindere da tipo e valore.
2. La candidata deve avere esattamente `ASPNETCORE_ENVIRONMENT=Production` come valore normale (non `secret_name`), `Authentication__Mode=Oidc`, `Authentication__Authority` URL HTTPS assoluto con hostname, senza userinfo, query, fragment o whitespace, e `Authentication__Audience` esplicita e senza whitespace. `DOTNET_ENVIRONMENT` viene rifiutato del tutto nello staging, anche se il valore fosse Production, perché la pipeline ha già un singolo selettore.
3. Il controllo è **prima** di `terraform apply` sul medesimo piano binario sottoposto al gate. Le motivazioni di errore sono fisse, non riportano valori di issuer, password, token, claim o altri dati del piano. Nessun log del JSON sensibile.
4. I controlli HMAC, connessione PostgreSQL, ruolo reader opt-in, identity UAI, segreti ACA immutabili, single Container App e traffic split stable 100% / candidate 0% rimangono applicati. Non cambia Terraform, la scelta del provider, il frontend, i DB o i workflow di provisioning.
5. Test TDD RED `tests/infra/test_aca_candidate_oidc_env.py` con piani sintetici e segreti sentinel; fixture positiva in `test_staged_rollout.py` allineata a `infra/main.tf`. La CI richiede Terraform/Python, .NET/PostgreSQL, React/Playwright, CodeQL, dependency scans e Docker verdi sullo stesso SHA `main`.

## Non garantito / alternative scartate

- Il gate **non dimostra** che l'Authority HTTPS sia un identity provider approvato o che OIDC/JWKS, MFA, browser PKCE e revoche funzionino su Azure: ciò richiede la #2 e smoke con token di identità reali, più la #6. Non sostituisce il check al bootstrap lato API.
- La normalizzazione del plan protegge le variabili presenti nel template Terraform, **non** quelle iniettate da runtime, base image, sidecar o servizi esterni. Le immagini candidate e la supply chain richiedono validazione indipendente. Lo 0% del traffico non nasconde l'URL label.
- Non si è scelto di recuperare credenziali/secret Key Vault per verificare il piano (viola il boundary di confidenzialità), né di correggere automaticamente un piano ambiguo scegliendo la prima/ultima variabile.
- Nessun `terraform apply` o modifica di dati Azure. Le #49/#5/#6/#2 rimangono aperte.
