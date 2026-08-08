package migrations

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	advisoryLockID      int64 = 0x53656355524c
	cockroachMaxRetries       = 5
)

type databaseMode uint8

const (
	postgresMode databaseMode = iota
	cockroachMode
)

//go:embed *.sql
var migrationFiles embed.FS

func databaseModeFromVersion(version string) databaseMode {
	if strings.Contains(version, "CockroachDB") {
		return cockroachMode
	}
	return postgresMode
}

func detectDatabaseMode(ctx context.Context, pool *pgxpool.Pool) (databaseMode, error) {
	var version string
	if err := pool.QueryRow(ctx, "SELECT version()").Scan(&version); err != nil {
		return postgresMode, fmt.Errorf("detect database version: %w", err)
	}
	return databaseModeFromVersion(version), nil
}

func embeddedMigrationEntries() ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(migrationFiles, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	return entries, nil
}

// Apply detects CockroachDB from SELECT version(). PostgreSQL uses a
// transaction-scoped advisory lock. CockroachDB executes each idempotent SQL
// statement in its own implicit transaction because PostgreSQL advisory locks
// are unavailable and serializable statements may return SQLSTATE 40001.
func Apply(ctx context.Context, pool *pgxpool.Pool) error {
	mode, err := detectDatabaseMode(ctx, pool)
	if err != nil {
		return err
	}
	entries, err := embeddedMigrationEntries()
	if err != nil {
		return err
	}
	if mode == cockroachMode {
		return applyCockroach(ctx, pool, entries)
	}
	return applyPostgres(ctx, pool, entries)
}

func applyPostgres(ctx context.Context, pool *pgxpool.Pool, entries []fs.DirEntry) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migrations: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", advisoryLockID); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, `
CREATE TABLE IF NOT EXISTS securl_schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version := entry.Name()
		var applied bool
		if err := tx.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM securl_schema_migrations WHERE version = $1)",
			version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied {
			continue
		}
		migration, err := migrationFiles.ReadFile(version)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, string(migration)); err != nil {
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO securl_schema_migrations (version) VALUES ($1)",
			version,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func dollarQuoteTagAt(input string, index int) (string, bool) {
	if input[index] != '$' {
		return "", false
	}
	for end := index + 1; end < len(input); end++ {
		character := input[end]
		if character == '$' {
			return input[index : end+1], true
		}
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_') {
			return "", false
		}
	}
	return "", false
}

func splitMigrationStatements(input string) ([]string, error) {
	var statements []string
	start := 0
	singleQuoted := false
	doubleQuoted := false
	lineComment := false
	blockCommentDepth := 0
	dollarQuote := ""
	for index := 0; index < len(input); {
		switch {
		case dollarQuote != "":
			if strings.HasPrefix(input[index:], dollarQuote) {
				index += len(dollarQuote)
				dollarQuote = ""
			} else {
				index++
			}
		case lineComment:
			if input[index] == '\n' {
				lineComment = false
			}
			index++
		case blockCommentDepth > 0:
			if strings.HasPrefix(input[index:], "/*") {
				blockCommentDepth++
				index += 2
			} else if strings.HasPrefix(input[index:], "*/") {
				blockCommentDepth--
				index += 2
			} else {
				index++
			}
		case singleQuoted:
			if input[index] == '\\' && index+1 < len(input) {
				index += 2
			} else if input[index] == '\'' {
				if index+1 < len(input) && input[index+1] == '\'' {
					index += 2
				} else {
					singleQuoted = false
					index++
				}
			} else {
				index++
			}
		case doubleQuoted:
			if input[index] == '"' {
				if index+1 < len(input) && input[index+1] == '"' {
					index += 2
				} else {
					doubleQuoted = false
					index++
				}
			} else {
				index++
			}
		default:
			switch {
			case strings.HasPrefix(input[index:], "--"):
				lineComment = true
				index += 2
			case strings.HasPrefix(input[index:], "/*"):
				blockCommentDepth = 1
				index += 2
			case input[index] == '\'':
				singleQuoted = true
				index++
			case input[index] == '"':
				doubleQuoted = true
				index++
			case input[index] == '$':
				if tag, ok := dollarQuoteTagAt(input, index); ok {
					dollarQuote = tag
					index += len(tag)
				} else {
					index++
				}
			case input[index] == ';':
				if statement := strings.TrimSpace(input[start:index]); statement != "" {
					statements = append(statements, statement)
				}
				index++
				start = index
			default:
				index++
			}
		}
	}
	if singleQuoted || doubleQuoted || blockCommentDepth != 0 || dollarQuote != "" {
		return nil, errors.New("unterminated SQL construct")
	}
	if statement := strings.TrimSpace(input[start:]); statement != "" {
		statements = append(statements, statement)
	}
	return statements, nil
}

func applyCockroach(ctx context.Context, pool *pgxpool.Pool, entries []fs.DirEntry) error {
	if err := retryCockroach(ctx, func() error {
		_, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS securl_schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`)
		return err
	}); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version := entry.Name()
		var applied bool
		if err := retryCockroach(ctx, func() error {
			return pool.QueryRow(ctx,
				"SELECT EXISTS (SELECT 1 FROM securl_schema_migrations WHERE version = $1)",
				version,
			).Scan(&applied)
		}); err != nil {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if applied {
			continue
		}
		migration, err := migrationFiles.ReadFile(version)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		statements, err := splitMigrationStatements(string(migration))
		if err != nil {
			return fmt.Errorf("split migration %s: %w", version, err)
		}
		for index, statement := range statements {
			if err := retryCockroach(ctx, func() error {
				_, err := pool.Exec(ctx, statement)
				return err
			}); err != nil {
				return fmt.Errorf("apply migration %s statement %d: %w", version, index+1, err)
			}
		}
		if err := retryCockroach(ctx, func() error {
			_, err := pool.Exec(ctx, `
INSERT INTO securl_schema_migrations (version) VALUES ($1)
ON CONFLICT (version) DO NOTHING`, version)
			return err
		}); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	return nil
}

func retryCockroach(ctx context.Context, operation func() error) error {
	var lastErr error
	for attempt := range cockroachMaxRetries {
		lastErr = operation()
		if lastErr == nil || !isSerializationFailure(lastErr) {
			return lastErr
		}
		if attempt == cockroachMaxRetries-1 {
			break
		}
		delay := time.Duration(1<<attempt) * 10 * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("CockroachDB migration retries exhausted: %w", lastErr)
}

func isSerializationFailure(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "40001"
}
