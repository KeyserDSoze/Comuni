# ADR 0049 — Lifecycle fail-closed del file Terraform plan sensibile nello staging ACA

- Stato: Accepted per il **workflow di staging**, non per sanificazione dello State o del runner.
- Data: 2026-11-16.
- Issue: #56 (sotto #49/#5/#6).
- Dipendenze: ADR 0017, 0043–0048.
- Documentazione: [Terraform plan — sensitive data in saved plan files](https://developer.hashicorp.com/terraform/cli/commands/plan), [Terraform show — JSON plan](https://developer.hashicorp.com/terraform/cli/commands/show), [GitHub Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

## Rischio

`.github/workflows/deploy.yml` prepara `infra/deploy.tfplan` con `terraform plan -out`, lo mostra in JSON al gate di staging e poi applica lo stesso piano binario. Il backend Terraform conserva ancora secret storici (incluso il valore di `azurerm_key_vault_secret.postgres_connection`) che possono essere copiati nel piano, anche se la CLI li maschera nel testo. Il file binario rimaneva nello spazio di lavoro del runner, anche in caso di errore di piano/gate/apply. L'avvio da un percorso preesistente o symlink potrebbe permettere riuso/sovrascrittura non autorizzata. La pipeline di stage è già protetta da un gate che permette unicamente un aggiornamento dell'unica Container App e mantiene 100% stable/0% candidata (ADR 0046); i suoi permessi e semantiche vanno preservati.

## Decisione

1. **Protezione prima del plan.** All'inizio dello step `Plan and stage candidate at zero traffic` eseguire `set -euo pipefail`, `umask 077`, registrare `trap 'rm -f -- infra/deploy.tfplan' EXIT`, quindi rifiutare se `infra/deploy.tfplan` esiste già (file o link simbolico). Solo allora eseguire `terraform -chdir=infra plan -input=false -out=deploy.tfplan`. Il nuovo file creato dal runner ha permessi privati (testato come 0600 con mock).
2. **Stesso piano, stessa politica.** La verifica resta la pipe `terraform -chdir=infra show -json deploy.tfplan | python3 scripts/azure/check-staged-rollout-plan.py` con tutti gli argomenti esistenti (Key Vault versions, RLS, host, inventory, stable/candidate 100/0). `pipefail` impone che un errore sia di show sia del gate impedisca `terraform -chdir=infra apply -input=false -auto-approve deploy.tfplan`. Il file piano non viene pubblicato come Artifact e non si stampa mai JSON di credenziali in stdout.
3. **Cleanup garantito dai normali exit shell, non dall'host.** Il trap viene registrato prima di qualsiasi scrittura e rimuove il file temporaneo sia dopo un apply riuscito sia dopo failure di plan/show/gate/apply, senza modificare altre risorse. Se è presente un symlink/stale file, il workflow fallisce prima del plan e rimuove il riferimento locale. Questo cleanup riduce la durata di persistenza, ma **non è un secure erase**: non annulla dati in memoria, log di altre operazioni, snapshot del disco, crash/SIGKILL o manomissione di un runner privilegiato. Gli operatori devono garantire ambiente runner controllato, cifratura del volume e policy di conservazione.
4. **TDD del vero script.** RED `tests/infra/test_sensitive_stage_plan_cleanup.py` estrae dal workflow lo shell `run: |` e lo esegue con comandi sintetici e sentinel password, coprendo successo, plan/show/gate/apply failure, permessi 0600, symlink/stale file, assenza di leak e nessun apply prima del gate. GREEN aggiorna solo il workflow. Richiesti tutti i 7 job CI dello SHA finale di `main` prima di chiudere #56.
5. **Limiti in produzione.** Nessun cambiamento a `infra/main.tf`, Key Vault, ACA stable o database; nessun apply Azure eseguito dallo sviluppo. Le password nello State Terraform e nei suoi backup storici non vengono rimosse. #54 e #55 forniscono verifiche read-only preliminari all'handoff owner-approved, ma la migrazione legacy, rotazione password e verify TLS/RLS/IdP reali restano nel P0 #49/#5/#6.

## Alternative respinte

- Salvare il piano come GitHub Artifact o nei log per audit: esposizione di secret e costo privacy/sicurezza non giustificati.
- Rieseguire `terraform plan` per l'apply anziché applicare lo stesso file controllato: rischio TOCTOU e modifica non revisionata.
- Sostituire il piano binario con output JSON come input dell'apply: non supportato da Terraform e non prova equivalenza.
- Dichiarare `rm -f` cancellazione sicura: non lo è; serve gestione runner e State indipendente.
