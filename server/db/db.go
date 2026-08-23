package db

import (
	"database/sql"
	_ "embed"
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed schema.sql
var schema string

var DB *sql.DB

// Peer auth against the current OS user matches Homebrew's default local
// Postgres setup, so this needs no password to run out of the box. Override
// with DATABASE_URL for anything else.
func defaultDSN() string {
	user := os.Getenv("USER")
	return fmt.Sprintf("postgres://%s@localhost:5432/logparseapp?sslmode=disable", user)
}

func Connect() error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = defaultDSN()
	}

	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	if err := conn.Ping(); err != nil {
		return err
	}

	DB = conn
	return nil
}

// Applied on every boot. Safe to re-run: see schema.sql for why it's one
// idempotent script rather than versioned migrations.
func ApplySchema() error {
	_, err := DB.Exec(schema)
	return err
}
