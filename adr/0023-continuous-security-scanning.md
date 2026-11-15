# ADR 0023 — Continuous SCA/SAST security checks on main

- Stato: Accepted come quality gate CI offline/cloud GitHub (#29), non security certification
- Data: 2026-11-15
- Dipendenze: ADR 0001, 0002, 0010–0013, 0022; issue #5, #6, #19, #29
- Riferimenti: [NuGet auditing](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages), [npm audit](https://docs.npmjs.com/cli/npm-audit/), [GitHub CodeQL advanced configuration](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning).

## Problema

La CI di `main` verifica comportamento e isolamento ma non blocca la pubblicazione di commit con dipendenze vulnerabili conosciute. Una advisory può apparire senza un commit, quindi la scansione solo sui push non è sufficiente. I controlli non devono scaricare segreti Azure o usare un ambiente contenente dati comunali reali.

## Decisione

- Tutte le scansioni fanno parte dello **stesso workflow CI** con trigger `push main`, `workflow_dispatch` e `schedule` settimanale, senza accesso Azure/DB reale. Il job Docker dipende anche dai risultati SCA e CodeQL. Non usare `continue-on-error` né `|| true` nei gate.
- Il job `dependency-audit` usa `dotnet restore` con NuGet Audit abilitato esplicitamente, `NuGetAuditMode=all` e `NuGetAuditLevel=high` sui progetti API/integration e domain/unit. `NU1903` e `NU1904` sono errori, così come `NU1900` se le informazioni di vulnerabilità non sono recuperabili. Sono inclusi pacchetti transitivi e dipendenze di test per la sicurezza del toolchain CI.
- Nello stesso job npm installa le dipendenze del workspace frontend **senza eseguire script di lifecycle** per il solo audit; `npm audit --omit=dev --audit-level=high` blocca advisory high/critical della catena runtime React. Le dipendenze di sviluppo non sono comprese in questa soglia npm e richiedono triage/manual review; la build/test Playwright continua nel job frontend separato. Nessun `npm audit fix` automatico.
- CodeQL v4 analizza C# (build `.NET 10` esplicita) e JavaScript/TypeScript (nessuna build per estrazione); solo il job di analisi ha `security-events: write`. Gli alert sono pubblicati nella sezione GitHub Code scanning, ma **la presenza di un alert CodeQL non causa automaticamente failure**: serve triage e una policy di merge/deploy distinta per gravità degli alert.
- La pipeline rimane una sola API .NET 10, un frontend React e un PostgreSQL. Nessuna scansione introduce altri servizi applicativi, endpoint o gestisce segreti.

## Sicurezza operativa e limiti

Nessun audit è una prova che il codice sia sicuro: advisory sconosciute/0-day, misconfigurazioni Azure/Terraform, vulnerabilità in container base image, incident response, penetration test, SBOM e dipendenze npm dev rimangono responsabilità di controlli successivi nell'epica #5. La valutazione di `NuGetAudit` dipende dalla disponibilità del feed: il fallimento chiuso richiede un intervento per outage anziché il bypass del controllo. In caso di vulnerabilità high/critical creare issue con advisory (senza credenziali), assegnare remediation, documentare eccezioni con scadenza e autorizzazione esplicita; non disabilitare i gate nel workflow. Se CodeQL non può pubblicare per permessi repository, il job deve fallire.

Verificare tutti i job sul commit finale di `main` prima di chiudere #29. L'esecuzione in GitHub Actions non prova il deploy Azure o la conformità GDPR/AgID.
