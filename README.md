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
make migrate-up
```

3. Start locally:
```bash
make dev
```

## API Doc
- **Swagger UI**: `http://localhost:3000/api-docs`
- **OpenAPI JSON**: `http://localhost:3000/api-docs.json`

## Testing
```bash
make test
```

## Monitoring
- **Health Check**: `GET /health`
