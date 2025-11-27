# IpanemaBox API

API for managing service and installation schedules, developed to organize appointments, avoid scheduling conflicts, and centralize access for the entire team.

## Requirements
- Go
- GNU Make
- Docker
- Docker compose
- ApiDog (for e2e tests)

## Setup
1. Install dependencies:
```bash
make install
```

2. Run DB migrations:
```bash
make migrate-up POSTGRES_PASSWORD={SECRET}
```

3. Start locally:
```bash
make dev
```

## API Doc
- **Swagger UI**: `http://localhost:8080/swagger/index.html`
- **OpenAPI JSON**: `http://localhost:8080/swagger/doc.json`

## Testing
```bash
make test
```

### E2E tests
- Import to ApiDog `docs/Ipanema Box.apidog.json`
- Start project locally
- Run scenario tests on ApiDog

## Monitoring
- **Health Check**: `GET /health`

## Next steps
- Set up an isolated test database environment with setup and teardown commands