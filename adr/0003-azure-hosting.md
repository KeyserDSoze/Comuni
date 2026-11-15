# ADR 0003 — Azure Container Apps (primo deployment)

- Stato: Accepted
- Data: 2026-11-15

## Decisione
Deploy di una singola immagine con API .NET 10 e frontend statico su **Azure Container Apps**. Stato su PostgreSQL Flexible Server e documenti su Azure Blob Storage quando sarà disponibile il modulo documentale; segreti su Azure Key Vault, Managed Identity per accesso ai servizi e Azure Monitor/Log Analytics per osservabilità. Provisioning Terraform; GitHub Actions per CI e immagini. L'hosting in App Service resta alternativa solo attraverso un nuovo ADR.

## Motivazione
Un singolo container per l'applicazione riduce costi, CORS e problemi di routing. Non sono necessari broker, service bus, API gateway dedicati né Kubernetes per il bootstrap.

## Trade-off
Le migrazioni DB sono un'attività esplicita del deployment, non automatizzate per processi concorrenti in produzione. In ambienti reali servono database private networking, backup/restore testati, alert e policy organizzative.
