# Strategia TDD e verifica

Il bootstrap è sviluppato in due incrementi registrati su `main`: specifiche/test iniziali (RED) e codice implementativo (GREEN/Refactor). Le dipendenze .NET e browser Playwright devono essere presenti per la verifica effettiva.

## Matrice minima
| Livello | Caso | Atteso |
| --- | --- | --- |
| Domain | subject vuoto | errore |
| Domain | creazione record | organization non vuota e invariant validi |
| Business | modulo non attivo | use case bloccato |
| Business | list | organization passata esplicitamente |
| API/PostgreSQL | JWT assente | 401 |
| API/PostgreSQL | Reader scrive | 403 |
| API/PostgreSQL | isolamento tra tenant | nessuna lettura incrociata |
| API/PostgreSQL | feature flag disabilitato | 403 |
| Domain | membership valida/invalida e disattivazione | invarianti rispettati |
| API/PostgreSQL | JWT Admin con membership Reader | scrittura 403, context ruolo Reader |
| API/PostgreSQL | membership assente o disattivata | 403 |
| API/PostgreSQL | subject solo nel tenant A usa token per tenant B | 403 |
| API/PostgreSQL | JWT Reader ma membership Officer | scrittura consentita dal ruolo DB |
| Frontend/E2E | menu per moduli | menu condizionale |
| Frontend/E2E | accesso Reader | niente azione di creazione |

## Esecuzione
`dotnet test tests/backend/Comuni.UnitTests` per test rapidi.
`TEST_DATABASE_CONNECTION="Host=localhost;Port=5432;Database=comuni_test;Username=comuni;Password=..." dotnet test tests/backend/Comuni.Api.Tests` per integration con PostgreSQL reale.
`npm install && npx playwright install --with-deps chromium && npm run build --workspace @comuni/frontend && npm run test:e2e --workspace @comuni/frontend`.
GitHub Actions ripete queste verifiche con PostgreSQL service.
