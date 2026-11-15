# Mappa multi-dominio e priorità

L'immagine di riferimento mostra aree gestionali comunali, ma non costituisce specifica delle integrazioni, dei workflow o delle conformità legali. La piattaforma Comuni implementa per ora la **fondazione** e un modulo di **metadati Protocollo dimostrativo**.

| Bounded Context proposto | Modulo | Stato | Note |
| --- | --- | --- | --- |
| Organizations & Access | `platform` | Fondazione | Organization, membership e ruoli da PostgreSQL, moduli abilitati; OIDC e provisioning amministrativo utenti da progettare |
| Protocollo | `protocol` | Demo minima | Elenco/registrazione metadati; nessuna protocollazione legale |
| Archivio documentale | `documents` | Pianificato | Blob, versionamento, metadata, retention, audit, conservazione |
| Amministrativi | `administration` | Pianificato | Delibere, determine, ordinanze, contratti |
| Finanziario | `finance` | Pianificato | Contabilità, bilanci, inventario |
| Tributi | `taxes` | Pianificato | IMU, TARI, riscossioni |
| Utenze | `utilities` | Pianificato | Rette e gestione utenze |
| Demografico | `demographics` | Pianificato | Anagrafe, stato civile, elettorale; ANPR/ANSC previa analisi |
| Personale | `hr` | Pianificato | Presenze, gestione economica, giuridica |
| Polizia locale | `local-police` | Pianificato | Sanzioni, verbali, notifiche |
| Lavori pubblici | `public-works` | Pianificato | Progetti, iter e trasmissioni |
| Urbanistica ed edilizia | `building` | Pianificato | Pratiche, SUAP, SUE |
| Cimitero | `cemetery` | Pianificato | Concessioni, lampade votive |

## Sequenza orientativa

1. Hardening della fondazione: OIDC, membership per Comune, audit, gestione secrets, autorizzazioni granulari, test del deploy.
2. Archivio documentale con Blob Storage e policy di accesso, retention e registrazione audit.
3. Protocollo informatico conforme ai requisiti effettivamente applicabili, previo dominio e integrazioni documentali e di conservazione.
4. Primo dominio verticale completo (selezione funzionale mediante analisi con uno o più Comuni).
5. Estensioni incrementali e integrazioni PagoPA, PDND, SEND, ANPR, ANSC, SPID/CIE secondo necessità e requisiti verificati.

Ogni modulo futuro mantiene entità in `Domains/<Mod>`, use case in `Business/<Mod>`, adapter in `Infrastructures/<Mod>` e endpoint nella sola `Applications/Api`, con propri test e migrazioni EF versionate. Un modulo non abilitato deve essere invisibile in UI **e inaccessibile in API**.
