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

func ApplySchema() error {
	_, err := DB.Exec(schema)
	return err
}
