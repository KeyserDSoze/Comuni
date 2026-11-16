# ADR 0067 — Aggiornamento action GitHub Node24 con pin SHA verificati

- **Data:** 2026-11-16
- **Stato:** Accepted per codice CI e configurazione workflow; **login Azure OIDC live non eseguito**
- **Issue:** [#78](https://github.com/KeyserDSoze/Comuni/issues/78), estende ADR 0065 (#76), compatibilità del runner CI e release Azure; parent #65/#6/#70.
- **Fonti primarie:** [actions/checkout releases](https://github.com/actions/checkout/releases), [actions/setup-node releases](https://github.com/actions/setup-node/releases), [actions/setup-dotnet releases](https://github.com/actions/setup-dotnet/releases), [hashicorp/setup-terraform releases](https://github.com/hashicorp/setup-terraform/releases), [Azure/login releases](https://github.com/Azure/login/releases).

## Contesto e minaccia

L'ADR 0065 ha eliminato i tag GitHub Actions mobili e introdotto una allowlist di SHA di 40 caratteri. In più run CI GitHub ha emesso warning per action pinning a **runtime interno Node.js 20**, ormai deprecato, forzando l'esecuzione sotto Node24. I due warning iniziali citavano `actions/checkout@11d5960...` e `hashicorp/setup-terraform@b9cd54a...`, ma l'ispezione **dei file `action.yml` realmente presenti agli SHA pinnati** ha mostrato `using: node20` anche per `actions/setup-dotnet@67a3573...`, `actions/setup-node@49933ea...` e `Azure/login@7184910...`. Aggiornare soltanto i due componenti segnalati non avrebbe completato il controllo della supply chain.

Il **runtime JavaScript di una action**, dichiarato in `runs.using`, è diverso da `node-version: '22'` richiesto dalle operazioni npm dell'applicazione. L'upgrade del runtime delle action non comporta un cambio di Node per la compilazione della SPA, né della versione .NET10/Terraform del servizio.

## Decisione

Aggiornare tutti e cinque i componenti coinvolti a **release ufficiali che dichiarano `node24` nel loro `action.yml`**, usando esclusivamente SHA di **commit**, mai tag mobili o SHA dell'oggetto Git *annotated tag*.

| Action | Vecchio pin (node20) | Nuovo pin (node24) | Note |
|---|---|---|---|
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` (v4) | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` (v5) | 7 usi totali: 6 CI, 1 deploy |
| `hashicorp/setup-terraform` | `b9cd54a3c349d3f38e8881555d616ced269862dd` (v3) | `dfe3c3f87815947d99a8997f908cb6525fc44e9e` (v4) | 2 usi: CI e deploy |
| `actions/setup-dotnet` | `67a3573c9a986a3f9c594539f4ab511d57bb3ce9` (v4) | `26b0ec14cb23fa6904739307f278c14f94c95bf1` (v5) | 3 usi CI, conserva `dotnet-version: 10.0.x` |
| `actions/setup-node` | `49933ea5288caeca8642d1e84afbd3f7d6820020` (v4) | `a0853c24544627f65ddf259abe73b1d18a591444` (v5) | 2 usi CI, conserva `node-version: '22'` |
| `Azure/login` | `7184910d9eb2b1c5e48f7073824a90609bb9b6d6` (v2) | `a641126d1b8aa4d1fa005f4f92df94a3a4c4c906` (v3) | 3 login OIDC nel deploy; tag `v3` **annotato**, dereferenziato a commit |

I commit sono stati recuperati dalle Git refs ufficiali (endpoint `/repos/<owner>/<repo>/git/ref/tags/<major>`), e i file `action.yml` degli SHA specifici sono stati letti per verificare **`runs.using: node24`**. In particolare, `Azure/login@v3` punta all'oggetto tag `935127ca5bb3c4b02c9c2c10060028383878f33f`, che punta a sua volta al **commit** `a641126d1b8aa4d1fa005f4f92df94a3a4c4c906`: non usare il digest dell'oggetto tag come riferimento eseguibile.

## Contratti e comportamenti preservati

- `tests/infra/test_github_action_sha_pins.py` rifiuta le vecchie SHA e i ref `@vN`, impone per ciascuna action la nuova allowlist ufficiale, i conteggi nei due YAML e la presenza dei commenti `# v5/v4/v3`. `test_azure_oidc_session_handoff.py` verifica esplicitamente **tre login OIDC `Azure/login` v3**.
- Checkout continua a usare il GITHUB_TOKEN con `contents:read` in CI e deploy, senza autorizzazioni ampliate. La release richiede GitHub-hosted runners aggiornati (le action Node24 richiedono GitHub Actions runner >= 2.327.1); `ubuntu-latest` e `ubuntu-24.04` sono runners GitHub-hosted, non self-hosted.
- `hashicorp/setup-terraform@v4` preserva l'input `terraform_wrapper`, **default `true` come v3**, e il download/install Terraform. Il workflow mantiene `terraform fmt`, `init`, `validate` in CI e `init/plan/show/apply` con pre-plan security gate nel deploy. Non cambiare versioni providers, backend, state o gestione del tfplan.
- `Azure/login@v3` preserva gli input OIDC `client-id`, `tenant-id`, `subscription-id` e l'audience di default `api://AzureADTokenExchange`; il workflow continua ad attestare via `check-azure-oidc-session.py` la sessione CLI Azure **dopo ciascuno dei tre login**. Non modificare i principal FIC o concedere altri ruoli. Nessun token da input non approvato, nessun fallback con client secret.
- Il workflow conserva la sequenza infra read-only RBAC → build ACR con digest/lock/Trivy/SBOM/Sigstore → infra Terraform/Key Vault/rollout candidato 0%, come ADR 0061–0064. La CI conserva xUnit/PostgreSQL, React/Playwright, CodeQL, SCA e build Docker con basi digest-pinned.

## TDD e limiti di validazione

RED: suite allowlist aggiornata **prima dei YAML** ha richiesto i commit checkout v5 e Terraform v4, fallendo nel run [43915493531](https://github.com/KeyserDSoze/Comuni/actions/runs/43915493531). GREEN parziale: sostituzione dei due ref, [run 43915868402](https://github.com/KeyserDSoze/Comuni/actions/runs/43915868402) 7/7. Dopo l'ispezione di tutti i manifest, RED aggiuntivo ha imposto setup-dotnet v5, setup-node v5 e Azure Login v3 e ha fatto fallire i test nel run [43916452331](https://github.com/KeyserDSoze/Comuni/actions/runs/43916452331). GREEN totale aggiorna i due workflow e mantiene tutti i test di isolamento OIDC. **Chiudere #78 solo dopo CI finale 7/7 sulla stessa HEAD di `main`.**

**I test offline possono dimostrare la coerenza dei YAML e l'esecuzione GitHub-hosted della CI, ma la CI non esegue `deploy.yml` e non autentica i tre service principal Entra reali.** Il cambio major `Azure/login` nel deploy richiede un successivo test approvato dell'owner, incluso RBAC/FIC/Key Vault e rollback, prima di dichiarare una release Azure funzionante. #70/#72/#74/#65/#6 restano aperte per i controlli live, trusted runner e supply-chain; non è stato effettuato `terraform apply` né sono state lette le secret di produzione.
