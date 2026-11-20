# Core Platform — Catalogo servizi per Comune (#128)

## Contratto e confini

`GET /api/v1/admin/modules/catalog` (policy **Admin** verificata sul backend) restituisce una lista di metadati statici code-owned della stessa API .NET 10. Ogni item ha esattamente:

```json
{
  "key": "protocol",
  "name": "Protocollo",
  "status": "available",
  "enabled": true,
  "configurable": true,
  "dependsOn": []
}
```

L'esempio `enabled:true` vale **solo** per un Comune con riga `platform.organization_modules(protocol,true)`; lo stato viene dal database tenant-scoped, non dall'URL, header, JWT role o UI. Se la riga manca, `configurable=false`, `enabled=false`. Se lo stato è `planned`, `configurable=false`, `enabled=false` in ogni caso, anche se una riga owner con `enabled=true` esiste erroneamente. `dependsOn` è inizialmente vuoto: non anticipare relazioni normative o applicative non ancora implementate.

L'elenco ordinato delle 12 key riservate è: `administrative`, `archive`, `cemetery`, `demographics`, `finance`, `local-police`, `personnel`, `protocol`, `public-works`, `taxes`, `urban-planning`, `utilities`. Il Core non è disabilitabile. **Soltanto `protocol` è `available`**, ed è ancora un modulo **dimostrativo**, non un protocollo legalmente conforme; tutti gli altri sono pianificati e non hanno API o modello dati di dominio. Nome italiano canonico restituito dal backend, React localizza per key in italiano e inglese.

`GET /api/v1/admin/modules` e `PUT /api/v1/admin/modules/protocol` mantengono i contratti esistenti; il PUT deve effettuare audit transazionale soltanto se cambia il flag, sotto la RLS del Comune. `PUT` per domini planned ritorna 404, senza scritture. `GET /api/v1/context` e `IOrganizationModuleStore.IsEnabledAsync` filtrano sempre per moduli implementati: un futuro flag SQL `archive=true` non può diventare un servizio attivo, né renderlo raggiungibile dal frontend.

## Evoluzione controllata

Per promuovere un dominio da planned ad available: specifica funzionale e normativa verificata, issue e ADR, modello dati e migrazioni con RLS e privilegi minimi, test xUnit e Playwright RED→GREEN, enforcement backend delle autorizzazioni, migrazione/seed dei flag per Comune, dipendenze catalogate e configurazione del Superadmin approvata. La sola modifica della voce UI/DB non abilita una feature. Non esistono applicazioni o database per-modulo.

Il catalogo attuale non dimostra conformità CAD/AgID/GDPR o disponibilità di integrazioni ANPR/pagoPA/SEND. Superadmin e provider OIDC live sono indipendenti e restano incompleti (#10/#2). Nessun deploy Azure viene eseguito da questa modifica.


## Toggle concorrenti del modulo Protocollo — ADR 0113 / #129

La riga di configurazione di Protocollo è l'unico lock del toggle, acquisito con `SELECT ... FOR UPDATE` *nella transazione tenant corrente* prima di confrontare lo stato del flag. Due richieste con lo stesso target serializzano e generano un solo audit; il secondo writer riceve un no-op. La riga non esistente rimane `NotFound`; i 11 domini planned non possono essere attivati. Non è optimistic concurrency HTTP né risolve le richieste contraddittorie provenienti da client con stato stale. [Runbook](../security/module-toggle-concurrency.md).
