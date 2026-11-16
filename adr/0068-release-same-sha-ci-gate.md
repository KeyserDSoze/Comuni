# ADR 0068 — Gate CI GitHub 7/7 vincolato al commit di release prima di Azure OIDC

- Data: 2026-11-16.
- Stato: Accepted per contratto e workflow; esecuzione reale di deploy Azure non effettuata.
- Issue: #79 (sotto #65/#6, coordinata con #70/#72/#74).
- Fonti: [GitHub REST — List workflow runs for a workflow](https://docs.github.com/en/rest/actions/workflow-runs#list-workflow-runs-for-a-workflow), [GitHub REST — List jobs for a workflow run](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run).

## Contesto

La CI esegue sette job su push main: backend .NET10 + PostgreSQL, React/Playwright, Terraform, dependency audit, CodeQL C#, CodeQL JavaScript/TypeScript e build Docker. Il rilascio Azure è un distinto workflow manuale con `workflow_dispatch`; il guard su repository/ref/event impediva dispatch da branch non approvati ma **non** richiedeva CI verde sullo SHA avviato. Un operatore avrebbe potuto autenticare service principal OIDC e pubblicare una candidata da un commit non verificato o con un job fallito/skipped, pur in presenza di CI verde su un altro SHA.

## Decisione

1. `.github/workflows/deploy.yml` concede al suo token effimero **solo il permesso aggiuntivo repository `actions: read`**, mantenendo `contents: read`, `id-token: write` e `attestations: write`. Il token è passato soltanto allo step di verifica, dopo il guard statale sul repository e prima del **primo** `azure/login`, del build/push e di ogni `terraform plan/apply`. Nessuna credenziale Azure è acquisita prima del gate.
2. `scripts/azure/check-release-ci.py` valida localmente `GITHUB_REPOSITORY=KeyserDSoze/Comuni`, `GITHUB_REF=refs/heads/main`, `GITHUB_EVENT_NAME=workflow_dispatch`, SHA esadecimale a 40 caratteri e token effimero presente. Interroga **solo** `https://api.github.com/repos/KeyserDSoze/Comuni/actions/workflows/ci.yml/runs`, filtrando `head_sha`, `branch=main` ed `event=push`. Non filtra `status=completed`: un run in corso **non** deve essere nascosto da un vecchio risultato verde. Richiede esattamente un run e confronta anche SHA, ref, nome, path, evento, stato e conclusione.
3. Il secondo GET su `.../actions/runs/<run_id>/jobs` impone i **sette nomi di job esatti**, senza duplicati o sconosciuti, tutti `completed/success`, con lo **stesso `run_id` e `head_sha`**. I job skipped o cancellati **non** equivalgono a successo. Una modifica intenzionale della matrice CI richiede modifica coordinata del contratto; si privilegia il fail-closed.
4. L'API base, la repository e il workflow sono costanti nel codice; soltanto il commit esadecimale e il run ID intero positivo compongono i path. Richieste HTTPS GET con `Authorization: Bearer` in header, timeout 20s, limite 1 MiB per risposta, nessun redirect, HTTP 200 obbligatorio, JSON senza proprietà duplicate; nessuna stampa di body, eccezioni HTTP, token, URL, tenant o SHA. Richieste non disponibili, risposte ambigue o inattese bloccano il deploy.
5. Il gate è **autonomo rispetto ai controlli OCI**: non indebolisce ACR, Key Vault, signed provenance, SBOM/CVE, PostgreSQL RLS, Terraform plan, stable100/candidate0 e relative separazioni OIDC.

## Verifiche e limiti

TDD: `tests/infra/test_release_ci_preflight.py` ha preceduto lo script (RED su `main`) e simula il contratto HTTPS con i casi positivi e negativi; la suite entra nel job `Terraform validate` (unittest offline). La verifica finale richiede CI reale 7/7 sullo SHA finale di `main`; non è una prova di deploy Azure live.

Il gate verifica lo stato GitHub **al momento della lettura**, non l'assenza di compromissioni del runner o delle credenziali CI, né la trustworthiness della pipeline stessa. `workflow_dispatch` resta manuale con approvazione dell'environment `production`. Se GitHub Actions API è indisponibile o modifica lo schema, il deploy è bloccato (non vi è bypass automatico). Non è stato eseguito alcun `terraform apply`, attribuito RBAC o modificato un registro ACR reale.
