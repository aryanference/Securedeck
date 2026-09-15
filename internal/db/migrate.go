package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Migrate runs all .up.sql files in the specified directory against the DB.
func Migrate(ctx context.Context, db DB, migrationsDir string, dialect string) error {
	// Create migration tracking table if it doesn't exist
	var createTableQuery string
	if dialect == "sqlite" {
		createTableQuery = `CREATE TABLE IF NOT EXISTS _migrations (
			id TEXT PRIMARY KEY,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`
	} else {
		createTableQuery = `CREATE TABLE IF NOT EXISTS _migrations (
			id TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ DEFAULT NOW()
		)`
	}

	_, err := db.ExecContext(ctx, createTableQuery)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("failed to read migrations dir: %w", err)
	}

	var upFiles []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".up.sql") {
			upFiles = append(upFiles, f.Name())
		}
	}
	sort.Strings(upFiles)

	for _, file := range upFiles {
		// Check if already applied
		var id string
		checkQuery := `SELECT id FROM _migrations WHERE id = $1`
		if dialect == "sqlite" {
			checkQuery = `SELECT id FROM _migrations WHERE id = ?`
		}
		
		err := db.QueryRowContext(ctx, checkQuery, file).Scan(&id)
		if err == nil {
			// Already applied
			continue
		}

		content, err := os.ReadFile(filepath.Join(migrationsDir, file))
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", file, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}

		// Note: executing multiple statements in one ExecContext might fail depending on the driver,
		// but pgx and modernc.org/sqlite generally support it if separated by semicolons.
		_, err = tx.ExecContext(ctx, string(content))
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute migration %s: %w", file, err)
		}

		insertQuery := `INSERT INTO _migrations (id) VALUES ($1)`
		if dialect == "sqlite" {
			insertQuery = `INSERT INTO _migrations (id) VALUES (?)`
		}
		_, err = tx.ExecContext(ctx, insertQuery, file)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %s: %w", file, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", file, err)
		}
	}

	return nil
}
