# ADR 0097 — Integrità canonica dei metadati AuditEvent

- Data: 2026-11-20.
- Stato: **Accepted come vincolo di dominio per nuovi eventi**, non attestazione di audit forense o conservazione.
- Issue: #114; epiche #4 e #5.
- ADR correlate: 0006 (audit transazionale), 0050 (principal verificato senza ambiguità), 0092–0094 (coerenza repository), 0095 e 0096 (consultazioni tracciate con attore server-owned).

## Contesto e minaccia

La factory `AuditEvent.Create`, condivisa da Protocollo, gestione moduli/membership e consultazione del registro, normalizzava implicitamente `actorSubject`, `action`, `resourceType` e `correlationId` con `Trim()`. L'identità `sub` già verificata dall'API doveva essere rappresentata esattamente nell'audit, non silenziosamente convertita in una stringa diversa; lo stesso vale per la correlazione. La factory accettava anche CR, LF, TAB e NUL all'interno del valore, consentendo metadati difficili da interpretare/esportare e potenzialmente confondibili con nuove righe in diagnostica o SIEM. Un audit senza alterazioni SQL può comunque essere inaccurato se i metadati subiscono trasformazioni non dichiarate.

## Decisione

1. `AuditEvent.Create` respinge per ogni stringa `actorSubject` (max 160), `action` (max 120), `resourceType` (max 100) e `correlationId` (max 128) l'input nullo/vuoto/whitespace, `value.Length > maxLength`, `value != value.Trim()` e qualunque `char.IsControl`. Il nome del parametro è mantenuto nell'eccezione di validazione. Non viene più eseguita alcuna trasformazione sul valore ammesso: si conserva la stringa originale (case e Unicode ordinari inclusi).
2. L'identità rimane di competenza dell'API: `VerifiedPrincipalIdentity.ValidSubject` già rifiuta controlli e whitespace esterno; la factory audit ora applica lo stesso criterio anche se un futuro use case non passasse per la route corrente. L'actor delle consultazioni continua a provenire da `ICurrentActorContext`; la factory non è un provider d'identità.
3. **TDD sulla CI reale:** RED commit `296619b400a047398736911db574c8726e7b47ce`, run `44715802992`, 14 casi xUnit falliti come previsto (`Assert.Throws() Failure: No exception was thrown`) e 33 unit passati. GREEN amplia i test per null/blank/oltre limite per ciascun campo, conserva la prova positiva Unicode/case-sensitive e aggiunge un probe nel test del repository con signed-RLS PostgreSQL runtime che deve rifiutare actor whitespace e correlation newline **prima** di attaccare un evento al ChangeTracker. La chiusura richiede 7/7 job CI verdi sul commit finale di main con codice e ADR.
4. Nessuna nuova migrazione PostgreSQL, colonna, permesso SQL, modifica frontend/endpoint, secret o intervento Azure; non aggiornare i dati storici esistenti e non tentare riparazioni silenziose dei valori pregressi. Le azioni valide oggi usano già identificatori canonici e correlation prodotte dal server.

## Limiti e valutazioni

`char.IsControl` non elimina tutti i caratteri Unicode di formato o le sequenze visivamente confondibili. Questa decisione garantisce soltanto rifiuto di controlli e whitespace esterno e assenza di `Trim` implicito: non è una strategia completa anti-spoofing Unicode, non impedisce input malevolo da un processo già compromesso e non sostituisce policy JWT/Admin, tenant proof HMAC, RLS o autorizzazioni PostgreSQL. L'owner/superuser può ancora alterare schema e log. Retention, catena di integrità, WORM, pgAudit/SIEM, impersonificazione Superadmin, protezione dati e certificazioni CAD/GDPR/AgID restano fuori scope e aperte nelle issue parent.
