# Ipanema Box API

Ipanema Box

## Requirements

- [go](https://tip.golang.org/doc/go1.20)
- [make](https://www.gnu.org/software/make/)
- [mockgen](https://github.com/golang/mock)
- [swaggo](https://github.com/swaggo/swag)
- [golang-migrate](https://github.com/golang-migrate/migrate/tree/master/cmd/migrate)

## Instalation

```bash
$ make
```

## Configuration

Create `.env` file with a password as:

```bash
MYSQL_PASSWORD=S3cRe1
```

## Setup

```bash
$ make infra/up
$ make db/migration/up
```

## Running

```bash
$ make run
```

See local API at http://localhost:3001/api/swagger/index.html

## Tests

```bash
$ make test/unit

$ make test/unit/cov

$ make test/integration
```
