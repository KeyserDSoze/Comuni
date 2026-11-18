# ADR 0091 — Verifica incrociata delle snapshot Terraform nell'handoff PostgreSQL legacy

- Data: 2026-11-18.
- Stato: **Accepted per gate read-only su piani Terraform sintetici**, non autorizza il passaggio di State.
- Issue #108, nel perimetro #49/#6; estende ADR 0048, ADR 0089 e ADR 0090.
- Riferimento ufficiale: [HashiCorp — JSON output format](https://developer.hashicorp.com/terraform/internals/json-format).

## Problema

Il gate `scripts/azure/check-legacy-postgres-handoff-plan.py` verifica il server PostgreSQL managed nel blocco `planned_values` e il non-cambio della Container App nel blocco `resource_changes`; questi due insiemi non erano però **correlati**. Un JSON incompleto o contraffatto poteva dichiarare in `planned_values` un PostgreSQL coerente e una ACA sicura altrove nei `resource_changes`, oppure includere una riga PostgreSQL `no-op` mancante. Per un handoff di stato owner-only queste incongruenze devono essere rifiutate, senza trattare l'apparente `no-op` come attestazione dell'ambiente reale.

## Decisione

1. Conservare l'accettazione di **un solo** `azurerm_key_vault_secret.postgres_connection ["forget"]`, senza cancellazione Azure, e delle altre risorse `["no-op"]` con `before==after`, senza drift e senza altre modifiche; mantenere gate ACA `Multiple`, stable 100% e candidata 0%, secret `pg-<16hex>` versionato e `RuntimePostgres__ExpectedHost` corrispondente al FQDN della risorsa PostgreSQL managed.
2. Esigere anche una riga `azurerm_postgresql_flexible_server.main` di tipo esatto `azurerm_postgresql_flexible_server` in `resource_changes`, azione unica `["no-op"]`, con `before.name` e `before.fqdn` uguali ai campi del valore `planned_values.root_module.resources` della stessa risorsa. Il loop generale già verifica che `before==after` e non esistano cambi distruttivi; non accettare un riferimento PostgreSQL visibile solo nella sezione planned.
3. Esigere che la stessa ACA managed `azurerm_container_app.main` compaia **una sola volta** anche in `planned_values` con tipo corretto. Confrontare con l'oggetto `resource_changes.change.before` la modalità `revision_mode`, `ingress.traffic_weight`, `target_port`, `external_enabled`, `template.revision_suffix`, `container.image` e le sole env `ConnectionStrings__Default`, `RuntimePostgres__ExpectedHost`, più i **riferimenti** Key Vault legacy e candidato già controllati. Non leggere né confrontare payload/password in chiaro, né imporre uguaglianza byte-for-byte di attributi calcolati, provider-only o redatti da Terraform.
4. Parsing fail-closed: riferimenti assenti, duplicati, tipi errati, snapshot discordanti, root module sconosciuta, nome/FQDN incoerenti, target/label/suffix non corrispondenti, secret ref alterati o campo richiesto nascosto/mancante **rifiutano** il piano. Non stampare valori del piano, URI, host, password, secret o eccezioni; output sintetico fisso. Nessun `terraform apply`, `state rm`, account Azure, modifica HCL, secret o ruolo.
5. **TDD su `main`**: commit RED `a4cb7d11` con fixture del piano contenente entrambe le risorse nei due blocchi e casi negativi per PG e ACA, run CI Terraform/Python `44326008161` con 17 fallimenti attesi per mismatch non intercettati; commit GREEN `ec0b40b4` limita il cambiamento al validatore Python, senza nuove dipendenze. La chiusura #108 richiede **sette job CI superati sul medesimo SHA finale** dopo questo ADR, i test e i runbook.

## Limiti

HashiCorp descrive `planned_values` come rappresentazione dell'**esito previsto** e `resource_changes` come descrizione delle modifiche; due blocchi coerenti non provano la correttezza dello State storico, l'attualità delle revisioni o l'autenticità del piano da un runner compromesso. Questa è validazione *offline*, non ispezione live di Azure Container Apps, Key Vault, CA/certificato TLS, ruolo SQL, RLS, backup o rollback. La mancata disponibilità di metadata richiesti provoca rifiuto, anche se il provider li omette. `#49`, `#6` e `#19` restano aperte per le verifiche operative e le approvazioni indipendenti. Nessun Comune, secret o endpoint reale è stato utilizzato.
