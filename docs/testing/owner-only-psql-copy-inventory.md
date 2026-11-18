# TDD — inventario dei trasporti COPY owner-only (#105)

Il test offline `tests/infra/test_owner_psql_copy_inventory.py` è incluso nel job **Terraform validate**, comandato dalla root con `python3 -m unittest discover -s tests/infra -p 'test_*.py' -v`. Il RED è stato osservato nella run `44312536458` (manifest non ancora presente). Dopo GREEN manifest `03d5f448`, il job Terraform/Python di `44312793277` ha superato la verifica. La suite totale 7/7 va comunque confermata sullo SHA definitivo.

Copertura: mapping esatto dei 14 script/operazioni, parsing AST non eseguibile del dizionario `INPUTS`, whitelist env e classificazione, singolo comando COPY statico, TEMP e transazione, assenza literal/echo, controllo `\\getenv` per le dieci procedure che lo usano, discovery di script fuori inventario e due mutazioni malevole in memoria. Verificati anche limiti di valore/busta e errore client fisso.

**Non sostituisce** i test xUnit/PostgreSQL17 con server log reali, Playwright, SCA, CodeQL C#/JS o Docker. Non prova anonimizzazione o gestione Azure/pgaudit/SIEM né autorizza dati reali. Chiusura issue solo con 7/7 job green sullo stesso `main` HEAD.
