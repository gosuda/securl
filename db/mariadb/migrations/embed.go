package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
)

const advisoryLockName = "securl_schema_migrations"

//go:embed *.sql
var migrationFiles embed.FS

// Apply runs every pending idempotent migration while holding a MariaDB
// connection-scoped advisory lock. MariaDB DDL commits implicitly, so each
// migration file must remain safe to retry until its version row is recorded.
func Apply(ctx context.Context, database *sql.DB) error {
	connection, err := database.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer connection.Close()

	var acquired sql.NullInt64
	if err := connection.QueryRowContext(ctx, "SELECT GET_LOCK(?, 30)", advisoryLockName).Scan(&acquired); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		return fmt.Errorf("lock migrations: advisory lock unavailable")
	}
	defer connection.ExecContext(context.WithoutCancel(ctx), "SELECT RELEASE_LOCK(?)", advisoryLockName)

	if _, err := connection.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS securl_schema_migrations (
    version VARCHAR(255) NOT NULL PRIMARY KEY,
    applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}

	entries, err := fs.ReadDir(migrationFiles, ".")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		version := entry.Name()
		var applied bool
		if err := connection.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM securl_schema_migrations WHERE version = ?)",
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
		if _, err := connection.ExecContext(ctx, string(migration)); err != nil {
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := connection.ExecContext(ctx,
			"INSERT INTO securl_schema_migrations (version) VALUES (?)",
			version,
		); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	return nil
}
