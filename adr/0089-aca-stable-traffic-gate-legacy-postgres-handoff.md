# ADR 0089 — Handoff PostgreSQL legacy vincolato a ACA Multiple stable 100% / candidata 0%

- Data: 2026-11-18.
- Stato: **Accepted come gate di piano Terraform offline e sintetico**, non come garanzia di traffico o segreti live.
- Issue #106, dipendenze #49/#55/#6/#19; estende ADR 0048 e preserva ADR 0017–0019, 0043–0044.
- Riferimenti ufficiali: [Terraform JSON plan](https://developer.hashicorp.com/terraform/internals/json-format), [Azure Container Apps — revisions](https://learn.microsoft.com/en-us/azure/container-apps/revisions), [Traffic splitting](https://learn.microsoft.com/en-us/azure/container-apps/traffic-splitting).

## Rischio

Il validatore `scripts/azure/check-legacy-postgres-handoff-plan.py` aveva un requisito `azurerm_container_app.main = ["no-op"]` e `before==after`, ma **non ispezionava l'assetto di routing già in essere**. Un eventuale passaggio futuro del segreto legacy da Terraform a gestione esterna avrebbe quindi potuto superare la verifica di forma con ACA in `revision_mode=Single`, con una candidata già promossa, o con traffico distribuito accidentalmente. I controlli del gate staged-release sono distinti: un precedente stage sicuro non prova che la configurazione sia ancora tale al momento dell'handoff.

## Decisione

1. Conservare lo strumento indipendente e read-only, che accetta stdin `terraform show -json`, senza azioni Azure/Terraform, stampa del piano, secret, host o URI. Nessuna modifica a `infra/main.tf`, al workflow reale di deploy, alle risorse, al database, a Key Vault o ai ruoli.
2. Il validatore verifica **sul medesimo `before` del piano** (già uguale a `after`): `revision_mode == Multiple`, **un solo blocco `ingress`**, **esattamente due** elementi `traffic_weight`. Richiede una stabile esplicita `latest_revision is False`, `percentage` intero (non bool) **100**, `revision_suffix` valido e non vuoto. La candidata deve avere `latest_revision is True`, `percentage` intero **0**, nessun `revision_suffix` e `label` uguale al `template[0].revision_suffix` `r[a-z0-9]{12}`; questa suffix deve essere diversa dalla stabile e la label stabile non può essere la label candidata. Duplicati, target aggiuntivi, tipi inattesi, missing ingress/label/suffix, modalità single e percentuali 99/1 sono rifiutati.
3. Il piano resta vincolato alla **sola azione `["forget"]`** per `azurerm_key_vault_secret.postgres_connection`, `after=null`, con URI legacy immutato e `azurerm_container_app.main ["no-op"]`, secret precedente invariato, nuovo `pg-<16hex>` in Key Vault versionato e ambiente `ConnectionStrings__Default` legato alla candidata. Qualunque drift, modifiche negli output o ulteriori risorse non-no-op sono rifiutati. Nessuna rimozione Terraform o rotazione viene effettuata dallo script.
4. **TDD RED→GREEN su `main`**: test Python con fixture realistiche `ingress.traffic_weight` e cambi non distruttivi; 25 varianti di routing/stati non sicuri (anche `before==after`) e check su `before/after` divergenti; test di output che non svela sentinel. Commit RED `5e3c2e88` (fallimento Terraform/Python in CI run `44320402466`), GREEN `6f975ea3`; test di intera CI 7/7 sullo **SHA finale** prima della chiusura #106. Nessuna dipendenza extra Python.

## Limiti e operazioni autorizzative

Un piano Terraform validato mostra **solo una snapshot di metadata** e non dimostra che la stable riceva davvero il 100% o che la candidata sia ancora 0% **al momento dell'apply**; traffico, revoche, Key Vault versioni, secret bytes/CA, RLS e tutte le revisioni inattive vanno verificati con un preflight live autorizzato e approvazione indipendente. Lo script non verifica il possessore del secret né lo stato reale del backend Terraform e non può essere collegato automaticamente a `terraform apply`. Il piano può contenere password di produzione: leggerlo in stdin su runner privato, non caricarlo su issue/log, evitare pipe che stampano JSON. Questa misura non autorizza la rimozione della secret legacy, la rotazione del SQL login o il passaggio in produzione. L'epica #49 rimane aperta, come #6/#19/#5.
