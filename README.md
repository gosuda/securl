# SecURL: A Secure URL Shortener That Respects User Privacy

SecURL creates end-to-end encrypted protected links. The browser keeps the 11-character fragment ID and plaintext destination out of server requests; the server stores only an opaque 32-byte storage key and an immutable Protobuf envelope.

## Configuration

SecURL reads process environment variables and loads matching values from a `.env` file in the working directory. Existing process environment variables take precedence. Start from the checked-in example:

```sh
cp .env.example .env
```

Durations use Go duration syntax such as `3s`, `1m`, `24h`, or `720h`. Boolean values use `true` or `false`. Comma-separated origin values must be exact HTTP(S) origins containing only a scheme and host; paths, query strings, fragments, credentials, and wildcards are rejected. Default ports and internationalized hostnames are normalized before comparison.

### Server and storage

| Variable | Default | Description |
| --- | --- | --- |
| `SECURL_HTTP_ADDR` | `:8080` | Fallback TCP listen address used when `PORT` is unset. Use `127.0.0.1:8080` to bind only to loopback. |
| `PORT` | unset | PaaS-provided listen port. When present, overrides `SECURL_HTTP_ADDR` and activates `HOST`/`IP` discovery. |
| `HOST` | unset | Bind hostname or address used with `PORT`. Empty or unset produces `:PORT`. |
| `IP` | unset | Optional bind IP used with `PORT`. A valid IPv4 or IPv6 value overrides `HOST`; IPv6 is bracketed automatically. |
| `SECURL_PUBLIC_ORIGINS` | `http://localhost:8080` | Comma-separated first-party SecURL origins accepted by origin checks. Include every public origin that serves this instance. |
| `SECURL_STORE_BACKEND` | `memory` | Storage backend: `memory`, `postgres`, or `mariadb`. Memory storage is lost when the process exits. |
| `SECURL_POSTGRES_URL` | empty | PostgreSQL connection URL. Required when `SECURL_STORE_BACKEND=postgres`. |
| `SECURL_MARIADB_DSN` | empty | MariaDB DSN in go-sql-driver format, for example `securl:password@tcp(mariadb:3306)/securl`. Required when `SECURL_STORE_BACKEND=mariadb`. |
| `SECURL_FRONTEND_MODE` | `embedded` | Frontend mode: `embedded` serves the compiled frontend from the Go binary; `external` serves only the API. |
| `SECURL_CORS_ALLOWED_ORIGINS` | empty | Comma-separated external frontend origins allowed to call the API. Required in `external` mode. Credentials and wildcard origins are not supported. |
| `SECURL_MAX_ENVELOPE_BYTES` | `16384` | Maximum accepted serialized encrypted envelope size in bytes. Must be a positive integer. |
| `SECURL_ENABLE_HSTS` | `false` | Adds `Strict-Transport-Security: max-age=31536000`. Enable only when the public service is consistently available over HTTPS. |

Listen-address precedence follows [`github.com/lemon-mint/envaddr`](https://github.com/lemon-mint/envaddr): if `PORT` is present, SecURL listens on `[IP or HOST]:PORT`; a valid `IP` overrides `HOST`. If `PORT` is absent, `SECURL_HTTP_ADDR` is used, falling back to `:8080`. `PORT` controls only the local bind address—PaaS deployments must still set `SECURL_PUBLIC_ORIGINS` to their public HTTPS origin.

### Link lifetime and cleanup

| Variable | Default | Description |
| --- | --- | --- |
| `SECURL_ALLOWED_TTLS` | `1h,24h,168h,720h,forever` | Comma-separated TTL choices exposed to clients. Finite values must be whole-second durations from `1s` through `720h`. `forever` creates a link without an expiration time. |
| `SECURL_DEFAULT_TTL` | `168h` | Initially selected TTL. Must also appear in `SECURL_ALLOWED_TTLS`; `forever` is valid when allowed. |
| `SECURL_CLEANUP_INTERVAL` | `1m` | Interval between expired-envelope cleanup passes. Must be a positive duration. |
| `SECURL_CLEANUP_BATCH` | `500` | Maximum number of expired envelopes deleted per cleanup pass. Must be a positive 32-bit integer. Non-expiring envelopes are never selected for cleanup. |

`forever` is encoded as `ttl_seconds = 0`. The memory repository keeps no expiration timestamp, PostgreSQL stores `expires_at = NULL`, and API responses report `expires_at_unix = 0`. Burn-after-reading links are still deleted after their first protected retrieval regardless of TTL.

### Google Safe Browsing

| Variable | Default | Description |
| --- | --- | --- |
| `SECURL_SAFE_BROWSING_ENABLED` | `false` | Enables destination checks through the Google Safe Browsing v5 hash API. |
| `SECURL_SAFE_BROWSING_API_KEY` | empty | Google Safe Browsing API key. Required when Safe Browsing is enabled. |
| `SECURL_SAFE_BROWSING_TIMEOUT` | `3s` | Timeout for each upstream Safe Browsing request. Must be a positive duration. |
| `SECURL_SAFE_BROWSING_CACHE_ENTRIES` | `4096` | Maximum number of hash-prefix cache entries. Must be a positive integer. |

When Safe Browsing is disabled, protected links require an explicit user action before opening the destination. When it is enabled but the upstream check fails, the UI keeps the destination gated until the user explicitly chooses the unscanned path.

### CAPTCHA

| Variable | Default | Description |
| --- | --- | --- |
| `SECURL_CAPTCHA_PROVIDER` | `none` | CAPTCHA provider: `none`, `turnstile`, or `recaptcha`. |
| `SECURL_CAPTCHA_SITE_KEY` | empty | Public provider site key. Required when the provider is not `none`. |
| `SECURL_CAPTCHA_SECRET_KEY` | empty | Server-side provider secret. Required when the provider is not `none`. |
| `SECURL_CAPTCHA_WRAP_KEY` | empty | Canonical unpadded base64url encoding of exactly 32 random bytes. Required when the provider is not `none`; used to encrypt CAPTCHA release keys at rest. |
| `SECURL_CAPTCHA_ALLOWED_HOSTNAMES` | `localhost` | Comma-separated exact hostnames accepted from CAPTCHA verification responses. Use hostnames only, without schemes or paths. |

Generate a wrapping key with Node.js:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

All three CAPTCHA key variables are required together when `SECURL_CAPTCHA_PROVIDER` is `turnstile` or `recaptcha`.

### Frontend build and test variables

| Variable | Default | Description |
| --- | --- | --- |
| `PUBLIC_SECURL_API_BASE_URL` | empty | Build-time API base URL for an externally hosted frontend. Empty uses same-origin requests. A non-empty URL is also added to the generated Content Security Policy, so changing it requires rebuilding the frontend. |
| `TEST_POSTGRES_URL` | empty | PostgreSQL URL used only by PostgreSQL repository contract tests. Tests apply migrations and truncate the `envelopes` table; use a disposable database. Tests are skipped when unset. |
| `TEST_MARIADB_DSN` | empty | MariaDB DSN used only by MariaDB repository contract tests. Tests apply migrations and truncate the `envelopes` table; use a disposable database. Tests are skipped when unset. |

### Example profiles

Embedded in-memory development:

```env
SECURL_HTTP_ADDR=:8080
SECURL_PUBLIC_ORIGINS=http://localhost:8080
SECURL_STORE_BACKEND=memory
SECURL_FRONTEND_MODE=embedded
```

PaaS deployment with an injected port:

```env
HOST=0.0.0.0
PORT=8080
SECURL_PUBLIC_ORIGINS=https://securl.example
SECURL_STORE_BACKEND=postgres
SECURL_POSTGRES_URL=postgres://securl:password@postgres:5432/securl
```

PostgreSQL with non-expiring links enabled:

```env
SECURL_PUBLIC_ORIGINS=https://securl.example
SECURL_STORE_BACKEND=postgres
SECURL_POSTGRES_URL=postgres://securl:password@postgres:5432/securl
SECURL_ALLOWED_TTLS=1h,24h,168h,720h,forever
SECURL_DEFAULT_TTL=168h
SECURL_ENABLE_HSTS=true
```

MariaDB with forced `utf8mb4` storage:

```env
SECURL_PUBLIC_ORIGINS=https://securl.example
SECURL_STORE_BACKEND=mariadb
SECURL_MARIADB_DSN=securl:password@tcp(mariadb:3306)/securl
SECURL_ALLOWED_TTLS=1h,24h,168h,720h,forever
SECURL_DEFAULT_TTL=168h
SECURL_ENABLE_HSTS=true
```

External frontend with Cloudflare Turnstile:

```env
SECURL_FRONTEND_MODE=external
SECURL_PUBLIC_ORIGINS=https://securl.example
SECURL_CORS_ALLOWED_ORIGINS=https://links.example
SECURL_CAPTCHA_PROVIDER=turnstile
SECURL_CAPTCHA_SITE_KEY=your-site-key
SECURL_CAPTCHA_SECRET_KEY=your-secret-key
SECURL_CAPTCHA_WRAP_KEY=your-32-byte-base64url-key
SECURL_CAPTCHA_ALLOWED_HOSTNAMES=links.example
```

## PostgreSQL

Set `SECURL_STORE_BACKEND=postgres` and `SECURL_POSTGRES_URL` to a PostgreSQL connection URL. SecURL applies the single embedded PostgreSQL schema migration automatically at startup under a PostgreSQL advisory lock.

## MariaDB

Set `SECURL_STORE_BACKEND=mariadb` and `SECURL_MARIADB_DSN` to a go-sql-driver DSN. SecURL enables time parsing in UTC, forces the connection character set to `utf8mb4` with `utf8mb4_bin` collation, and creates every MariaDB table as InnoDB with `DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`. The single embedded MariaDB schema migration is serialized with `GET_LOCK` during startup.

## Container

```sh
docker build -t securl .
docker run --rm --env-file .env -p 8080:8080 securl
```

The final image is distroless, runs as `nonroot`, and contains one statically linked SecURL binary with the frontend embedded.

## External frontend mode

Build the static frontend with the API origin injected at build time, then deploy `internal/frontend/dist` separately:

```sh
PUBLIC_SECURL_API_BASE_URL=https://api.example.com npm --prefix frontend run build
```

Run the API with `SECURL_FRONTEND_MODE=external`, list every browser origin in `SECURL_PUBLIC_ORIGINS`, and list allowed cross-origin frontend origins in `SECURL_CORS_ALLOWED_ORIGINS`. Origins are normalized and matched exactly; wildcard and credentialed CORS are not supported.

See `.env.example` for all configuration keys.

## Verification

```sh
npm --prefix frontend run check
npm --prefix frontend run test:unit
npm --prefix frontend run test:e2e
go test -race ./...
```

PostgreSQL and MariaDB contract tests additionally use `TEST_POSTGRES_URL` and `TEST_MARIADB_DSN`, respectively.
