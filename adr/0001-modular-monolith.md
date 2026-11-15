# ADR 0001 — Modular Monolith con DDD multi-dominio

- Stato: Accepted
- Data: 2026-11-15

## Contesto
I Comuni condividono identità, navigazione, documenti e infrastruttura, ma i moduli applicativi devono evolvere senza accoppiamento.

## Decisione
Una sola API ASP.NET Core .NET 10 e una sola React SPA. `Domains` contiene modelli e invarianti, `Business` contratti e use case, `Infrastructures` gli adapter, `Applications/Api` la composition root e gli endpoint. Un PostgreSQL con separazione logica, inizialmente tramite tabelle con organization_id, moduli distinti per namespace/cartelle e policy per dominio. Nessuna comunicazione interprocesso per use case locali.

## Conseguenze
Deployment atomico e debug semplice; i confini modulari sono verificati mediante project references e test, con possibili schemi PostgreSQL per dominio in iterazioni successive. Evitare riferimenti circolari, orchestrazioni distribuite premature e repository genericissimi.
