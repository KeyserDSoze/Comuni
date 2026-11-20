# Sicurezza del toggle concorrente di Protocollo (#129 / ADR 0113)

Due Admin del medesimo Comune possono inviare `PUT /api/v1/admin/modules/protocol` contemporaneamente. Una transazione SQL singola che salva flag e audit non basta a evitare due eventi se entrambi i writer leggono lo stesso valore **prima** di qualunque lock. Il repository ora prende un `SELECT ... FOR UPDATE` sulla **specifica riga `organization_id + module_key`** prima di valutare lo stato e di creare un evento.

Il lock si applica sotto la transazione RLS HMAC `SET LOCAL comuni.tenant_assertion`, con il login non-owner `comuni_app_runtime`. Gli identificativi sono parametri, non pezzi di SQL dinamico; il repository rifiuta prima del SQL un Comune non corrente, un modulo non installato e un audit semanticamente scorretto. Il secondo writer della stessa transizione torna `Unchanged` senza audit; il primo torna `Updated` con un solo `AuditEvent` nello stesso commit. Un lock per Comune **non** blocca inutilmente i moduli di un altro Comune. La mancanza della riga => `NotFound` (non auto-provisionare).

Non aggiungere grants owner, leggere dati altrui, registrare i JWT, chiavi HMAC o il nome applicativo/SQL dei test in log di produzione. Le modalità di auditing sono quelle già previste dal repository, da PostgreSQL pgAudit e dalla policy IAM dell'ambiente. Il cambio non modifica la semantica di `GET /admin/modules/catalog`: gli altri 11 servizi rimangono pianificati e non attivabili.

**Limiti:** i toggle antagonisti `enable` e `disable` rimangono ordinati dal lock (last writer wins), non è un lock pessimista esposto come precondizione HTTP o un controllo ETag. Un DB owner bypassa RLS e la disciplina applicativa; il SIEM, Azure PostgreSQL live, multi-replica ACA, concorrenza ad alto carico, retention/privacy e review security restano ancora da approvare. Vedere [test](../testing/module-toggle-concurrency.md).

## Lettura del ChangeTracker prima del lock (#131 / ADR 0115)

Il lock SQL della #129 serializza le scritture, ma **non invalida da solo** la cache di entità già materializzate da EF nello stesso `DbContext`. Il repository ora ricarica esplicitamente da PostgreSQL la riga tracciata con `Entry.ReloadAsync` **dopo** `FOR UPDATE` e prima del confronto `Enabled`. Questo impedisce che la copia locale obsoleta generi un altro audit per una transizione già committata. Il reload usa la stessa transazione, le stesse prove RLS e lo stesso login non-owner; la perdita di visibilità restituisce `NotFound` senza audit.

Questa correzione non rende atomico un diverso processo owner-only di sospensione con una richiesta HTTP già autorizzata, non abilita la gestione dei moduli `planned` e non prova l'immutabilità dell'audit rispetto al proprietario SQL. Vedere [test RED e GREEN](../testing/module-toggle-concurrency.md) e ADR 0115.
