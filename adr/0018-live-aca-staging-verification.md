# ADR 0018 — Verifica live delle revisioni ACA dopo lo stage, senza promozione

- Stato: Accepted, limitatamente a un **gate di metadati di sola lettura** (#24)
- Data: 2026-11-15
- Dipendenze: ADR 0003, 0014–0017; issue padre #19, #6, #5
- Fonti ufficiali: [Azure CLI revision list](https://learn.microsoft.com/en-us/cli/azure/containerapp/revision), [Azure CLI ingress traffic show](https://learn.microsoft.com/en-us/cli/azure/containerapp/ingress/traffic), [ARM revision properties](https://learn.microsoft.com/en-us/rest/api/resource-manager/containerapps/container-apps-revisions/get-revision)

## Contesto

Con #23 la configurazione Terraform consente di creare una candidata con 0% del traffico e preservare la stable. Il piano verificato **prima dell'apply** non garantisce che la candidata sia effettivamente attiva, Healthy e coerente con la chiave RLS prevista, né che il traffico live rimanga a 100%/0% una volta completato il deployment. Serve un controllo operativo ulteriore **di sola lettura**, senza dare al workflow facoltà di promuovere una revisione non verificata.

## Decisione

Aggiungiamo `scripts/azure/verify-staged-revisions.py`, uno script Python che chiama Azure CLI con argomenti in vettori (mai shell interpolata) e cattura la risposta senza riportarla nei log:

- `az containerapp show --query properties.configuration.activeRevisionsMode` deve restituire `Multiple`.
- `az containerapp revision list` deve contenere una **e una sola** revisione stable e candidata con nomi esatti `<app>-<suffix>`; entrambe `active=true`, `healthState=Healthy`, `provisioningState=Provisioned`, `runningState=Running` e almeno una replica. Le altre revisioni possono esistere ma non devono ricevere traffico.
- Il container candidato deve indicare `<acr>/comuni:<40-hex-commit>` e valori `Security__TenantProofKeyId` e `Security__TenantProofKey` coerenti con gli input di release; il valore HMAC non è mai richiesto.
- `az containerapp ingress traffic show` deve presentare **solo** stable 100% e latest 0%. Non sono consentite regole aggiuntive, drift sui pesi o promozione automatica.
- Retry limitati per assorbire la consistenza eventuale dopo lo stage; se manca un requisito, il job fallisce in modalità fail-closed. Non esiste un comando di promozione o rollback nello script.

Il workflow `Deploy to Azure` invoca il gate **dopo** `terraform apply`, con suffix, SHA dell'immagine, ID logico e versione secret provenienti dal GitHub Environment protetto e dal commit. Un esito verde è un prerequisito necessario per le successive verifiche operative (autenticazione e RLS HTTP su revision URL), non sufficiente per approvare traffico utente.

## Limiti e rischi residui

La CI usa `az` simulata e non verifica Azure live. CLI extension e payload metadata in subscription reale vanno verificati prima del go-live; i metadata possono essere temporaneamente non disponibili dopo il provisioning. Se il gate fallisce dopo apply, la nuova revisione è forse già stata creata ma deve rimanere a 0%; non eseguiamo teardown/rollback distruttivo. Il monitoraggio di rollback e dei pesi live, l'accesso sicuro a candidate URL, i JWT/OIDC reali, la dimostrazione che il secret Key Vault corrisponda al verifier PostgreSQL, migrazioni in VNet, app secrets and pool saturation sono ancora da realizzare/validare in #19/#6. Nessuna promessa zero-downtime, sicurezza PA/GDPR o produzione reale.
