# ADR 0019 — Label immutabile per candidata ACA e smoke OIDC/RLS read-only

- Stato: Accepted come **tooling e guardrail testati offline** (#25); nessun test Azure live/IdP reale
- Data: 2026-11-15
- Correlazioni: ADR 0012–0018, issue #19/#6/#5/#2
- Fonti: [Azure revision labels](https://learn.microsoft.com/en-us/azure/container-apps/revisions), [Azure label FQDN](https://learn.microsoft.com/en-us/azure/container-apps/connect-apps), [Terraform Container App traffic_weight](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_app)

## Problema

La #23 crea una candidata a **0%** e la #24 verifica readiness e routing via metadata. Senza un URL di revisione distinto non è possibile verificare **autenticazione, autorizzazione e RLS sulla candidata** senza spostare traffico pubblico. Una mera prova su `/health/ready` non valida JWT, membership o signer HMAC PostgreSQL.

## Decisione

La regola `ingress.traffic_weight` latest a 0% riceve `label = var.candidate_revision_suffix`, suffix immutabile derivato dal commit `r<sha12>`. L'etichetta indirizza l'URL Azure `https://<app>---<label>.<environment default domain>` **solo** alla candidata, indipendentemente dal routing della root app. Il controllo Terraform plan e il verificatore live dell'ADR 0018 rifiutano label assente, diversa o applicata alla stable; il peso root resta 100% stable/0% candidata.

Per lo smoke implementiamo un tool **separato e read-only** `scripts/azure/smoke-candidate-oidc.py`. Un operatore in un runner controllato passa in memoria due access token OIDC reali e temporanei attraverso variabili ambiente non loggate, assieme agli UUID di due organization sintetiche e a due marker di protocollo pre-seminati. Il tool verifica l'URL HTTPS con app/label/**dominio dell'environment approvato**, TLS CA, assenza redirect e proxy, timeout e limite alla dimensione delle risposte. Non invia mai token verso host differenti, non stampa claim o contenuti e non invoca endpoint POST/PUT/DELETE.

Si richiedono: health ready 200; context anonimo 401; context con token A/B 200, UUID corretto, membership role e protocol enabled; GET Protocollo per entrambi 200, contenente il proprio marker sintetico e non quello dell'altro Comune. In CI si usano mock HTTP e fake metadata Azure, **non** credenziali/servizi reali. Il tool non viene agganciato automaticamente al deploy, perché al momento non esiste ancora un IdP approvato né onboarding reale (#2), e un GitHub Secret permanente contenente JWT a breve scadenza sarebbe un'architettura errata.

## Rischi residui e alternative

- La label con ingress esterno **non rende privata la candidata**. OIDC protegge le API tenant ma asset statici/health sono pubblici. Valutare restrizioni ingress/edge, antiflood e token management in un ambiente approvato prima di usare dati veri.
- L'URL label deve essere verificato con i metadati Azure da un operatore: accettare un dominio proposto da un client significherebbe rischiare esfiltrazione di JWT. Per questo il client richiede dominio ACA approvato e URL esatto, non accetta redirect e ignora i proxy di sistema. La disponibilità di un canary FQDN non attesta l'identità del server applicativo in assenza di verifica HTTPS e metadata gate.
- Il controllo dei marker in una lista **limitata agli ultimi 100** può fallire per fixture non visibile. Questo è voluto: fail closed. Non creare record ufficiali, dati personali o posizioni reali per un test.
- Il verifier PostgreSQL RLS e la validazione OIDC sono testati separatamente in CI; la nuova smoke rule è una verifica *funzionale limitata*, non una prova completa di segregazione per ogni tabella, attacco o dominio.
- Nessuna rotazione reale, promozione, rollback, confronto HMAC secret-DB con certificazione, SAST/SCA, compliance o zero downtime verificati. #19/#6/#5 restano aperte. La #25 è chiudibile solo per tooling/label offline con CI completa sul commit finale.
