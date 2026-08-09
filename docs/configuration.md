# Configuration

SecURL is configured with environment variables. The standalone command also loads a `.env` file from its current working directory, which makes the checked-in example a good place to start:

```sh
cp .env.example .env
```

Values already present in the process environment win over values in `.env`. A variable that is present but empty is still considered configured; it does not fall back to the default.

The Go package does not load `.env` on its own. If SecURL is embedded in another process, that process is responsible for setting the environment before calling `securl.New`.

## Value formats

A few rules apply across the configuration:

- Durations use Go syntax: `3s`, `1m`, `24h`, `168h`, or `720h`.
- Booleans use values accepted by Go's `strconv.ParseBool`; `true` and `false` are the clearest choices.
- Lists are comma-separated. Spaces around entries are trimmed.
- Origins must contain only an `http` or `https` scheme and a host. Paths, query strings, fragments, credentials, and wildcards are rejected.
- Default ports are removed from origins, internationalized hostnames are converted to ASCII, and hostnames are compared case-insensitively.
- Secrets belong in a secret manager or injected process environment in production. Do not commit a filled `.env` file.

## Server and browser origins

| Variable | Default | Example | What it controls |
| --- | --- | --- | --- |
| `SECURL_HTTP_ADDR` | `:8080` | `127.0.0.1:8080` | Local listener used when `PORT` is absent. It accepts a TCP address or `unix:/absolute/path.sock`. Unix socket paths must be absolute, and the process must be able to write to the parent directory. |
| `SECURL_EXIT_ON_STDIN_EOF` | `false` | `true` | Stops the standalone command gracefully when stdin reaches EOF. This is meant for a parent process that owns a lifetime pipe. Leave it disabled for normal terminal and container use. |
| `PORT` | unset | `8080` | PaaS-style TCP port. When present, it overrides a TCP `SECURL_HTTP_ADDR` and enables `HOST` and `IP` lookup. An explicit Unix socket still wins. |
| `HOST` | unset | `0.0.0.0` | Bind host used with `PORT`. If it is empty or absent, SecURL listens on all interfaces as `:PORT`. It has no effect without `PORT`. |
| `IP` | unset | `2001:db8::10` | Optional bind IP used with `PORT`. A valid IPv4 or IPv6 address overrides `HOST`; IPv6 addresses are bracketed automatically. An invalid value is ignored and `HOST` is used. |
| `SECURL_PUBLIC_ORIGINS` | `http://localhost:8080` | `https://securl.example.com,https://alt.example.com` | First-party browser origins for this SecURL instance. Include every public origin from which users will send state-changing requests. This is the public URL, not necessarily the local bind address behind a reverse proxy. |
| `SECURL_FRONTEND_MODE` | `embedded` | `external` | `embedded` serves the compiled frontend from the Go binary. `external` serves the API without the frontend and requires `SECURL_CORS_ALLOWED_ORIGINS`. |
| `SECURL_CORS_ALLOWED_ORIGINS` | empty | `https://links.example.com` | Browser origins allowed to call the API cross-origin. Use this for a separately hosted frontend. Matches are exact; wildcard and credentialed origins are not supported. |
| `SECURL_ENABLE_HSTS` | `false` | `true` | Adds `Strict-Transport-Security: max-age=31536000` to responses. Enable it only when the public service is always reached over HTTPS. The header does not include `includeSubDomains` or `preload`. |

### Listener precedence

Listener selection follows these rules:

1. `SECURL_HTTP_ADDR=unix:/absolute/path.sock` always selects that Unix socket, even when `PORT` is present.
2. Otherwise, a present `PORT` selects `[IP or HOST]:PORT`. A valid `IP` wins over `HOST`.
3. Without `PORT`, SecURL uses `SECURL_HTTP_ADDR`.
4. Without either variable, SecURL listens on `:8080`.

The listener only controls where the process accepts traffic. If a reverse proxy exposes `https://securl.example.com` while SecURL listens on `127.0.0.1:8080`, set `SECURL_PUBLIC_ORIGINS=https://securl.example.com`.

## Storage and request limits

| Variable | Default | Example | What it controls |
| --- | --- | --- | --- |
| `SECURL_STORE_BACKEND` | `memory` | `postgres` | Storage implementation: `memory`, `postgres`, or `mariadb`. Memory storage is erased when the process exits. |
| `SECURL_POSTGRES_URL` | empty | `postgres://securl:password@postgres:5432/securl` | PostgreSQL or CockroachDB connection URL. It is required when `SECURL_STORE_BACKEND=postgres`. SecURL connects, checks the server version, and applies embedded migrations at startup. |
| `SECURL_MARIADB_DSN` | empty | `securl:password@tcp(mariadb:3306)/securl` | MariaDB DSN in `go-sql-driver/mysql` format. It is required when `SECURL_STORE_BACKEND=mariadb`. SecURL forces UTC time parsing, `utf8mb4`, and `utf8mb4_bin`. |
| `SECURL_MAX_ENVELOPE_BYTES` | `16384` | `32768` | Largest serialized encrypted envelope accepted by the API, in bytes. It must be a positive integer. Raising it allows larger encrypted metadata and ciphertext; lowering it may reject links produced by existing clients. |

### Database startup behavior

PostgreSQL uses a transaction-scoped advisory lock while applying migrations. CockroachDB is detected from `SELECT version()` and uses its compatible migration path automatically, including retries for serialization failures. No separate CockroachDB flag is needed.

MariaDB uses a connection-scoped `GET_LOCK` while applying its idempotent migration. Tables are created as InnoDB with `utf8mb4_bin` collation.

## Link lifetime and cleanup

| Variable | Default | Example | What it controls |
| --- | --- | --- | --- |
| `SECURL_ALLOWED_TTLS` | `1h,24h,168h,720h,forever` | `15m,1h,24h,forever` | TTL choices sent to the frontend and accepted by the create API. Finite values must be whole-second durations from `1s` through `720h`. `forever` creates a link without an expiration time. Duplicate entries are removed while preserving the first occurrence. |
| `SECURL_DEFAULT_TTL` | `168h` | `24h` | Initially selected TTL in the frontend. It must also appear in `SECURL_ALLOWED_TTLS`. `forever` is valid when it is included in the allowed list. |
| `SECURL_CLEANUP_INTERVAL` | `1m` | `30s` | Time between background cleanup passes. It must be a positive duration. A shorter interval removes expired rows sooner but wakes the database more often. |
| `SECURL_CLEANUP_BATCH` | `500` | `1000` | Maximum expired rows deleted in one cleanup pass. It must be a positive 32-bit integer. Larger batches reduce the number of passes but can hold database resources longer. |

`forever` is represented as a zero TTL. Persistent databases store no expiration time, and API responses report an expiration value of zero. Burn-after-reading links are still deleted after their first protected retrieval.

The one-shot cleanup command deletes every envelope that was already expired when the command began:

```sh
go run ./cmd/securl cleanup
```

It keeps processing `SECURL_CLEANUP_BATCH` rows at a time until the initial expired set is gone. The command requires PostgreSQL or MariaDB; it intentionally refuses the in-memory backend.

## Google Safe Browsing

| Variable | Default | Example | What it controls |
| --- | --- | --- | --- |
| `SECURL_SAFE_BROWSING_ENABLED` | `false` | `true` | Enables destination checks through the Google Safe Browsing v5 hash API. Enabling it requires `SECURL_SAFE_BROWSING_API_KEY`. |
| `SECURL_SAFE_BROWSING_API_KEY` | empty | `AIza...` | Server-side Google Safe Browsing API key. It is sent only to Google's API and should be injected as a secret. |
| `SECURL_SAFE_BROWSING_TIMEOUT` | `3s` | `5s` | Timeout for each upstream Safe Browsing request. It must be a positive duration. Keep it short enough that opening a protected link does not stall on an unhealthy dependency. |
| `SECURL_SAFE_BROWSING_CACHE_ENTRIES` | `4096` | `8192` | Maximum number of hash-prefix results kept in the in-memory LRU cache. It must be a positive integer. Cache expiration follows the duration returned by Google. |

When Safe Browsing is disabled, opening a destination always requires an explicit user action. If it is enabled but the upstream lookup fails, the destination remains gated and the user can explicitly choose the unscanned path.

## CAPTCHA

| Variable | Default | Example | What it controls |
| --- | --- | --- | --- |
| `SECURL_CAPTCHA_PROVIDER` | `none` | `turnstile` | CAPTCHA implementation: `none`, `turnstile`, or `recaptcha`. Any enabled provider requires the site, secret, and wrap keys below. |
| `SECURL_CREATE_CAPTCHA_REQUIRED` | `false` | `true` | Requires a successful CAPTCHA before the API accepts a newly created link. It cannot be enabled while the provider is `none`. Recipient CAPTCHA protection remains a separate per-link choice. |
| `SECURL_CAPTCHA_SITE_KEY` | empty | `your-turnstile-site-key` | Public provider key sent to the frontend through runtime configuration. It is required when a CAPTCHA provider is enabled. |
| `SECURL_CAPTCHA_SECRET_KEY` | empty | `your-turnstile-secret-key` | Private provider key used by the server to verify tokens. It is required when a CAPTCHA provider is enabled and must not be exposed to the frontend. |
| `SECURL_CAPTCHA_WRAP_KEY` | empty | `MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY` | Canonical, unpadded base64url encoding of exactly 32 bytes. SecURL uses it to encrypt per-link CAPTCHA release keys at rest. Keep it stable: replacing it makes existing CAPTCHA-protected links impossible to unwrap. The shown value is only a format example; generate a random key for real use. |
| `SECURL_CAPTCHA_ALLOWED_HOSTNAMES` | `localhost` | `links.example.com,www.example.com` | Exact hostnames accepted from provider verification responses. Use hostnames only, without a scheme, port, path, or wildcard. Entries are normalized and deduplicated at startup. |

Generate a wrapping key with Node.js:

```sh
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

All three key variables must be present when `SECURL_CAPTCHA_PROVIDER` is `turnstile` or `recaptcha`.

## Frontend build and test variables

These variables are not part of the running server configuration, but they are used by the frontend build, contract tests, or the Node launcher.

| Variable | Default | Example | What it controls |
| --- | --- | --- | --- |
| `PUBLIC_SECURL_API_BASE_URL` | empty | `https://api.example.com` | Build-time API base URL for an externally hosted frontend. Empty means same-origin requests. A non-empty absolute URL is also added to the generated Content Security Policy, so changing it requires rebuilding the frontend. |
| `TEST_POSTGRES_URL` | empty | `postgres://securl:password@localhost:5432/securl_test` | PostgreSQL URL used only by repository contract tests. Tests are skipped when it is unset. They apply migrations and clear the `envelopes` table, so use a disposable database. |
| `TEST_MARIADB_DSN` | empty | `securl:password@tcp(localhost:3306)/securl_test` | MariaDB DSN used only by repository contract tests. Tests are skipped when it is unset. They apply migrations and clear the `envelopes` table, so use a disposable database. |
| `SECURL_BINARY_PATH` | `cmd/securl/securl` | `./bin/securl` | Binary launched by `node cmd/securl/run.js`. The launcher exposes a public TCP port and forwards requests to the Go process over a temporary Unix socket. |

When `cmd/securl/run.js` is used, `PORT` controls the public proxy port and defaults to `3000`. The launcher overrides the Go process to use a temporary Unix socket and enables `SECURL_EXIT_ON_STDIN_EOF` so both processes share a lifecycle.

## Example profiles

### Local development

This is the default `.env.example` profile:

```env
SECURL_HTTP_ADDR=:8080
SECURL_PUBLIC_ORIGINS=http://localhost:8080
SECURL_STORE_BACKEND=memory
SECURL_FRONTEND_MODE=embedded
```

It requires no external services, but stored links disappear whenever SecURL stops.

### PostgreSQL behind a reverse proxy

```env
SECURL_HTTP_ADDR=127.0.0.1:8080
SECURL_PUBLIC_ORIGINS=https://securl.example.com
SECURL_STORE_BACKEND=postgres
SECURL_POSTGRES_URL=postgres://securl:password@postgres:5432/securl
SECURL_ENABLE_HSTS=true
```

The reverse proxy should terminate HTTPS and forward traffic to `127.0.0.1:8080`.

### PaaS with an injected port

```env
HOST=0.0.0.0
PORT=8080
SECURL_PUBLIC_ORIGINS=https://securl.example.com
SECURL_STORE_BACKEND=postgres
SECURL_POSTGRES_URL=postgres://securl:password@postgres:5432/securl
```

When the platform injects `PORT`, it takes precedence over a TCP `SECURL_HTTP_ADDR` from `.env`.

### MariaDB

```env
SECURL_PUBLIC_ORIGINS=https://securl.example.com
SECURL_STORE_BACKEND=mariadb
SECURL_MARIADB_DSN=securl:password@tcp(mariadb:3306)/securl
SECURL_ALLOWED_TTLS=1h,24h,168h,720h,forever
SECURL_DEFAULT_TTL=168h
SECURL_ENABLE_HSTS=true
```

### External frontend with Cloudflare Turnstile

Build the frontend with its API origin:

```sh
PUBLIC_SECURL_API_BASE_URL=https://api.example.com npm --prefix frontend run build
```

Run the API with the frontend origin allowed:

```env
SECURL_FRONTEND_MODE=external
SECURL_PUBLIC_ORIGINS=https://api.example.com
SECURL_CORS_ALLOWED_ORIGINS=https://links.example.com
SECURL_CAPTCHA_PROVIDER=turnstile
SECURL_CAPTCHA_SITE_KEY=your-turnstile-site-key
SECURL_CAPTCHA_SECRET_KEY=your-turnstile-secret-key
SECURL_CAPTCHA_WRAP_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY
SECURL_CREATE_CAPTCHA_REQUIRED=true
SECURL_CAPTCHA_ALLOWED_HOSTNAMES=links.example.com
```

The wrapping key above is only a valid-format example. Replace it with the output of the generation command before deploying.

## Container notes

The project Dockerfile builds the frontend, embeds it into a static Go binary, and runs that binary as a non-root user in a distroless image:

```sh
docker build -t securl .
docker run --rm --stop-timeout 10 --env-file .env -p 8080:8080 securl
```

The image includes a health check that runs `/securl healthcheck`. SecURL handles `SIGTERM` and uses an eight-second shutdown budget, which fits within the ten-second Docker stop timeout shown above.

## Embedding SecURL in another Go process

The root package loads configuration without opening the listener or storage. The host process owns the listener and passes it to `Application.Serve`:

```go
application, err := securl.New(logger)
if err != nil {
    return err
}

listener, err := net.Listen(application.ListenNetwork(), application.ListenAddress())
if err != nil {
    return err
}

if err := application.Serve(ctx, listener); err != nil {
    return err
}
```

To probe the listener that the host actually supplied, call `securl.CheckHealth` with `listener.Addr().Network()` and `listener.Addr().String()`.
