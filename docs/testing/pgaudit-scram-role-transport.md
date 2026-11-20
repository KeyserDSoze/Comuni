# Test pgAudit SCRAM: envelope COPY e canali client (#123)

## Obiettivo

Prevenire regressioni in cui un verifier SCRAM compare in forma raw o reversibilmente codificata in server log `pgAudit`, statement/error context o stdout/stderr di `psql`. L'esempio `base64(JSON({"SCRAM_VERIFIER": ...}))` è **il formato esatto dell'helper**, non una codifica protettiva. Nessuna credenziale reale.

## Test-first e gate

- `python3 -m unittest discover -s tests/infra -p 'test_pgaudit*.py' -v` controlla il parser con canary deterministici, incluse forme dirette base64 e l'envelope JSON. In RED [8fd46ba](https://github.com/KeyserDSoze/Comuni/commit/8fd46ba4cfdd71d3a6bcae74d3aa30810ae6de95) il job Terraform/Python [44750344128](https://github.com/KeyserDSoze/Comuni/actions/runs/44750344128) ha registrato 2 failure del detector precedente e 7 error di interfaccia client assente.
- Il job backend esegue `docker build -f tests/postgres/pgaudit/Dockerfile ...` e `python3 tests/postgres/pgaudit/verify_role_audit.py` prima degli integration tests API; richiede Docker/psql/dotnet e un database Postgres 17 disposable configurato dallo script. La sola suite Python statica non sostituisce questo gate reale.
- La fixture crea i due login SCRAM, verifica CREATE/ALTER, login, verifier salato, transazione/rollback, utente runtime negato e catalogo; acquisisce output client senza stamparli e confronta tutte le varianti canary con il server log. Eventi ROLE redatti per ogni ruolo/azione, GRANT e COPY rimangono requisiti positivi.
- Una regressione deve produrre solo un'eccezione diagnostica generica, **mai** il valore, la riga raw o il payload. Non incollare in issue gli output client di errori o SQL log; riportare solo categoria, stato e commit/run ID.

## Criteri di chiusura

Solo dopo completamento di **sette job GitHub Actions verdi sullo stesso SHA HEAD main**, includendo backend/PostgreSQL17 pgAudit reale, unit test/infra, Playwright, CodeQL, SCA e build Docker. Il gate CI non verifica Azure PostgreSQL, collector/SIEM, logging configurato fuori container, DBA/Key Vault, retention o rotazione multi-replica: mantenere #92/#89/#19 aperte fino alle rispettive approvazioni e prove.
