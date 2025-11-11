# IpanemaBox API

API for managing service and installation schedules, developed to organize appointments, avoid scheduling conflicts, and centralize access for the entire team.

## Requirements
- Go
- GNU Make
- Docker
- Docker compose

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

## Monitoring
- **Health Check**: `GET /health`

## Next steps

Missing tests:
1. Application Layer (internal/auth/application/)
    - TestAuthServiceImpl_RefreshToken
2. Presentation Layer (internal/auth/presentation/)
    - TestAuthHandler_Logout
    - TestAuthHandler_RefreshToken
3. Middleware (internal/shared/presentation/middleware/)
    - auth_test.go
    - error_handler_test.go
4. E2E tests