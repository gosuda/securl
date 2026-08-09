# SecURL

SecURL is a self-hosted service for creating encrypted, protected links. The destination is encrypted in the browser, and the URL fragment needed to open it is never sent to the server. The server only keeps an opaque storage key and the encrypted envelope.

It works as a single Go service with the frontend embedded, so the default setup is intentionally small.

## Quick start

The quickest way to try SecURL is with Docker:

```sh
cp .env.example .env
docker build -t securl .
docker run --rm --stop-timeout 10 --env-file .env -p 8080:8080 securl
```

Open [http://localhost:8080](http://localhost:8080).

The example configuration uses in-memory storage. That is convenient for a first run, but every link is lost when the process stops. Switch to PostgreSQL or MariaDB before using SecURL for anything persistent.

## Run from source

You will need Go 1.26.5 and Node.js 24.

```sh
npm --prefix frontend ci
npm --prefix frontend run build
cp .env.example .env
go run ./cmd/securl
```

The frontend build is written to `internal/frontend/dist` and embedded into the Go binary.

## Configuration

The standalone command loads `.env` from the current working directory. Environment variables already set by the process take precedence.

Start with `.env.example`, then use the [configuration guide](docs/configuration.md) when you need persistent storage, a public deployment, an external frontend, Safe Browsing, or CAPTCHA. The guide includes the default, a working example, and the important constraints for every supported variable.

## Useful commands

```sh
# Check the configured listener. The server must already be running.
go run ./cmd/securl healthcheck

# Remove all links that were expired when the command started.
# This requires PostgreSQL or MariaDB.
go run ./cmd/securl cleanup
```

## Development checks

```sh
npm --prefix frontend run check
npm --prefix frontend run test:unit
npm --prefix frontend run test:e2e
go test -race ./...
```

Database contract tests are skipped unless `TEST_POSTGRES_URL` or `TEST_MARIADB_DSN` is set. Use disposable databases: those tests apply migrations and clear the `envelopes` table.

## License

SecURL is available under the terms in [LICENSE](LICENSE).
