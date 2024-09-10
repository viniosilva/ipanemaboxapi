# Ipanema Box API

Schedule, services and customers manager

## Tech Stack

- [Go](https://go.dev/)
- [Make](https://www.gnu.org/software/make/)
- [Project Layout](https://github.com/golang-standards/project-layout)

## Run Locally

Install dependencies

```bash
  make
```

Configure infrastructure

```bash
make infra/up
make db/migrate
```

Configure test infrastructure

```bash
make infra/test/up
make db/test/migrate
```

Start the server

```bash
  make dev
```


## Running Tests

To run tests, run the following command

```bash
  # unit tests
  make test

  # e2e tests
  make test/e2e
```

## Deployment

[UNDER CONSTRUCTION]

To deploy this project run

```bash
  make deploy
```
