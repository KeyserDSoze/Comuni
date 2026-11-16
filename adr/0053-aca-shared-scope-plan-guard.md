# ADR 0053 — Staging ACA: blocco delle impostazioni applicative condivise

- Stato: Accepted per il **gate offline** del Terraform plan; nessuna verifica Azure live.
- Data: 2026-11-16.
- Issue: #61, sotto #49/#5/#6; estensione dell'ADR 0046.
- Riferimenti: [Microsoft Learn — revision vs application scope](https://learn.microsoft.com/en-us/azure/container-apps/revisions), [Microsoft Learn — app secrets e Key Vault identity](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets).

## Contesto e minaccia

La release `.github/workflows/deploy.yml` esegue `terraform apply` sulla base di un plan filtrato per un singolo UPDATE a `azurerm_container_app.main`. Un UPDATE di questa risorsa contiene tuttavia sia template per revisioni candidate sia impostazioni **app-scoped** condivise con tutte le revisioni esistenti. Il vecchio gate verificava traffico 100% stable/0% candidate, URI Key Vault dei segreti e pochi env; non rifiutava una modifica all'identity dell'app, al registry, all'ambiente o a ingress (eccetto `traffic_weight`). Confrontava anche soltanto l'URI dei secret già presenti, lasciando modificabili `identity` e altri campi con lo stesso URI.

Un secret Key Vault è app-scoped; una identità gestita sbagliata può alterare l'accesso alle credenziali già usate dalla stable. Il cambio di registry o ingress può alterare il confine d'esposizione pubblico e l'origine delle immagini al di fuori dell'unico rollout approvato. Non è sufficiente non spostare i pesi di traffico.

## Decisione

1. Il plan gate richiede nella configurazione **before** dell'app una sola identity di tipo `UserAssigned`, con un solo `identity_ids` non vuoto; l'intero blocco `identity` deve rimanere identico in **after**. Il ruolo/assegnazione reale richiede controlli Azure separati.
2. Il blocco `registry` esistente deve avere un unico registry con `server` non vuoto e `identity` uguale all'UAI autorizzato, e non può cambiare tra **before** e **after** (inclusi eventuali attributi ulteriori). Anche `container_app_environment_id` deve essere presente e identico.
3. L'unico blocco `ingress` deve mantenere invariati **tutti i campi diversi da `traffic_weight`**. Il gate preesistente continua a imporre stable 100%, candidate 0% e label immutabile: questa è l'unica mutazione autorizzata del routing. Inserire un nuovo campo ingress è una mutazione vietata, non una scorciatoia.
4. Ogni secret già esistente nel blocco `before.secret` deve essere identico nell'`after.secret`, non solo nello `key_vault_secret_id`. Ogni **nuovo** secret consentito dal release contract (`tp-`, `pg-` e, opzionalmente, `pi-`) deve usare esattamente l'UAI già installato nell'app. Continuano i gate per URI Key Vault con versione e per nome consentito.
5. Test Python TDD in `tests/infra/test_aca_shared_scope_guard.py`, con piani `terraform show -json` sintetici e credenziali sentinel; la fixture condivisa aggiorna il proprio schema con gli attributi realmente configurati da `infra/main.tf`. I test RED precedono la modifica del gate GREEN. Nessun valore del piano viene stampato dal validatore.

## Limiti e scelte escluse

- Questo è un confronto **offline** fra valori before/after del Terraform plan. Non verifica in ARM il comportamento di una stable né l'effettiva correttezza delle permission Key Vault/ACR, il trust TLS del DB o il contenuto di un secret.
- Non equivale a consentire modifiche arbitrarie al template della candidata (che richiede altri controlli e la verifica post-stage). Se un change legittimo necessita di cambiare UAI, registry, ingress non-traffic o ambiente, occorre una **release distinta, approvata e collaudata**, non aggirare il gate zero-traffic.
- Nessuna modifica all'infrastruttura Terraform o apply live. Lo storico `postgres-connection` versionless, le password nello State e la gestione completa del rollout restano aperti nelle #49/#5/#6. Non dichiarare zero-downtime né produzione pronta.
