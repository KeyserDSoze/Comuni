# Gestione GitHub Issues — processo di sviluppo

**Fonte di verità:** [issue del repository](https://github.com/KeyserDSoze/Comuni/issues), non un elenco statico di status in questo documento.

## Rituale a ogni sessione di sviluppo
1. Recuperare l'ultima head `main`, le issue aperte/chiuse e il risultato della CI sull'ultima head.
2. Verificare blocchi e dipendenze, scegliere una issue di priorità adeguata ed evitare duplicati.
3. Creare un'issue prima di nuovo lavoro non già tracciato. Ogni issue include problema, scope, test, criteri di accettazione e dipendenze.
4. Scrivere prima i test RED su `main`, quindi codice GREEN e refactor. Inserire `#numero` nei messaggi commit e link nella issue.
5. Commentare stato e verifica. Chiudere con reason `completed` **soltanto** se criteri soddisfatti e tutti i job CI (incluso container) sono verdi per il commit verificato.
6. Altrimenti mantenere issue aperta, spiegando cosa manca e il prossimo passo; in caso di nuove scoperte aprire issue con link di dipendenza.
7. Non affermare di monitorare autonomamente il repository fra una sessione di ChatGPT e l'altra.

## Convenzioni
- Sviluppare **direttamente su `main`**; niente branch/PR per il normale flusso richiesto.
- Priorità: **P0** sicurezza/fondazione bloccante; **P1** infrastruttura/admin; **P2** domini funzionali/integrations.
- Non usare la chiusura per nascondere scope incompleto; separare lavoro distinto in nuove issue.
- La definizione di Done include xUnit, PostgreSQL, Playwright quando applicabile, test CI, ADR/docs aggiornati e verifica delle API di sicurezza.
