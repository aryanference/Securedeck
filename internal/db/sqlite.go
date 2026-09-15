package db

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type SQLiteDB struct {
	*sql.DB
}

func NewSQLiteDB(dsn string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite connection: %w", err)
	}
	
	// Enforce pragmas required by spec
	_, err = db.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
	if err != nil {
		return nil, fmt.Errorf("failed to set pragmas: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite: %w", err)
	}

	return &SQLiteDB{DB: db}, nil
}
