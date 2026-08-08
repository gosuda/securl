package migrations

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestDatabaseModeFromVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected databaseMode
	}{
		{
			name:     "CockroachDB CCL",
			version:  "CockroachDB CCL v26.2.5 (x86_64-pc-linux-gnu)",
			expected: cockroachMode,
		},
		{
			name:     "CockroachDB OSS",
			version:  "CockroachDB OSS v25.4.0",
			expected: cockroachMode,
		},
		{
			name:     "PostgreSQL",
			version:  "PostgreSQL 17.4 on aarch64-unknown-linux-gnu",
			expected: postgresMode,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := databaseModeFromVersion(test.version); actual != test.expected {
				t.Fatalf("mode=%d expected=%d", actual, test.expected)
			}
		})
	}
}

func TestSplitEmbeddedMigrationIntoImplicitTransactions(t *testing.T) {
	migration, err := migrationFiles.ReadFile("000001_create_envelopes.sql")
	if err != nil {
		t.Fatal(err)
	}
	statements, err := splitMigrationStatements(string(migration))
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 || !strings.HasPrefix(statements[0], "CREATE TABLE") ||
		!strings.HasPrefix(statements[1], "CREATE INDEX") {
		t.Fatalf("statements=%q", statements)
	}
}

func TestSplitMigrationPreservesQuotedAndCommentSemicolons(t *testing.T) {
	input := `CREATE TABLE example (value TEXT DEFAULT ';');
-- comment with ;
CREATE FUNCTION example_fn() RETURNS void AS $$
BEGIN
    PERFORM ';';
END
$$ LANGUAGE plpgsql;`
	statements, err := splitMigrationStatements(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != 2 || !strings.Contains(statements[1], "PERFORM ';'") {
		t.Fatalf("statements=%q", statements)
	}
}

func TestSplitMigrationRejectsUnterminatedSQL(t *testing.T) {
	if _, err := splitMigrationStatements("CREATE TABLE example (value TEXT DEFAULT 'unterminated)"); err == nil {
		t.Fatal("unterminated SQL was accepted")
	}
}

func TestRetryCockroachRetriesSerializationFailures(t *testing.T) {
	attempts := 0
	err := retryCockroach(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return fmt.Errorf("retry transaction: %w", &pgconn.PgError{Code: "40001"})
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}

func TestRetryCockroachStopsOnNonSerializationFailure(t *testing.T) {
	expected := errors.New("permanent failure")
	attempts := 0
	err := retryCockroach(context.Background(), func() error {
		attempts++
		return expected
	})
	if !errors.Is(err, expected) || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}
