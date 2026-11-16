# ADR 0046 — Solo aggiornamento della Container App nel piano Terraform per candidate 0%

- Stato: Accepted per **guardia offline di staging**, non per migrazione Azure reale né decommission dello state.
- Data: 2026-11-16.
- Issue: #53 (sotto #49/#5/#6, collegata a #19).
- Dipendenze: ADR 0017–0019, 0043–0045.
- Specifica ufficiale: [Terraform JSON plan format](https://developer.hashicorp.com/terraform/internals/json-format), [terraform plan](https://developer.hashicorp.com/terraform/cli/commands/plan), [Terraform state and sensitive values](https://developer.hashicorp.com/terraform/language/manage-sensitive-data).

## Contesto e rischio

Il workflow `deploy.yml` è un'azione manuale, protetta da GitHub Environment e OIDC, che esegue Terraform `plan` seguito dal gate `check-staged-rollout-plan.py` e dall'`apply` **dello stesso piano**, senza una seconda review. Lo scopo unico è creare/aggiornare una revisione candidata dell'**unica** Azure Container App tenendo la stable al 100% e la candidata allo 0%. Il gate precedente rifiutava ogni `delete` e ogni `update` della risorsa PostgreSQL e del vecchio Key Vault secret `postgres_connection`, ma permetteva **update e create di tutte le altre risorse**, comprese role assignment, rete, DNS, container registry, altri segreti o moduli.

Queste variazioni potrebbero raggiungere le stable o cambiare permessi, password o rotte *prima* di smoke/approvazioni, anche quando la diff della Container App è sicura. Il vecchio segreto runtime `postgres-connection` è **versionless** e contiene una password già salvata nello state Terraform storico: qualunque modifica non strettamente necessaria è particolarmente rischiosa.

## Decisione

1. **Allowlist di una singola mutazione:** il JSON di `terraform show -json deploy.tfplan` deve contenere esattamente una `resource_changes` per `azurerm_container_app.main`, con tipo `azurerm_container_app` e azione `["update"]`. Il validatore esistente controlla la modalità Multiple, l'immagine, il suffix, i secret app-scoped immutabili, l'FQDN managed, le connessioni non in chiaro, l'inventario opt-in, il traffico stable 100% / candidate 0%. Per **ogni altra** risorsa nel piano, sono ammesse **solo** le azioni `["no-op"]` e un indirizzo univoco e non vuoto. Non esiste una allowlist speciale per Key Vault, RBAC, database, rete, amministratori o credenziali. Mutazioni di un'altra Container App o letture di data source non vengono introdotte di nascosto in uno stage.
2. **Drift e output:** l'oggetto `resource_drift` di Terraform, se presente, deve essere una lista vuota; `output_changes`, se presente, può contenere soltanto blocchi `["no-op"]` senza mutazioni. Qualunque drift o change degli output richiede un'analisi separata prima dello stage. Lo schema delle actions viene verificato strettamente: nessuna `["read"]`, `["create"]`, `["update"]`, `["delete"]`, `["delete", "create"]`, `["create", "delete"]` su risorse extra e nessun `["forget"]` per `removed` state.
3. **Separation of duties:** un cambiamento intenzionale di infrastruttura, incluso un `removed { lifecycle { destroy=false } }` per la vecchia secret runtime o una nuova credenziale amministrativa, deve avere un piano, una review, una CI, un backup/assessment dello state e un'autorizzazione **separati**. Il workflow di candidate staging non fornisce un bypass. Non modificare la secret stable versionless o il password role in-place durante il rollout. Usare runner/identità private autorizzate, smoke a due tenant e backout prima di qualsiasi promozione.
4. **Confidenzialità:** `terraform show -json` e `deploy.tfplan` possono contenere credenziali anche quando i campi sono marcati `sensitive`. Il gate processa il piano in memoria/pipe e emette soltanto motivazioni statiche, **mai** indirizzi, valori o JSON del piano. I test sintetici verificano la mancata divulgazione del sentinel, e non ispezionano password reali.
5. **TDD e gate:** RED `tests/infra/test_aca_stage_immutable_infrastructure.py` dimostra l'attuale possibilità di modifiche extra e drift; GREEN restringe il validatore. L'intera CI di `main` (.NET 10 PostgreSQL, Playwright, Terraform/Python, CodeQL, audit dipendenze, immagine Docker) deve risultare 7/7 per dichiarare completata solo #53.

## Limiti ed eccezioni

Questa regola non riscrive `infra/main.tf`, non tocca password o state, non esegue `terraform apply` e non completa #49. Gli snapshot storici dello state possono ancora contenere credenziali runtime/admin e non vengono resi sicuri dai controlli JSON. Il piano potrebbe essere intenzionalmente bloccato per drift o data source letti durante un deploy legittimo: questa è una **condizione fail-closed**, non un invito a disabilitare i controlli. Prima del go-live servono review RBAC, Key Vault/IdP e VNet/CA reali, verifica RLS su due Comuni sintetici, stage stable 100% e candidate 0%, approval e rollback sicuro. Nessun ruolo per Comune o flag frontend può aggirare le verifiche backend.
