package postgres

import (
	"fmt"
	"time"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	"github.com/labib0x9/docpine/internal/config"
	_ "github.com/lib/pq"
)

func NewPostgresConn(cfg *config.PostgreSQL) *sqlx.DB {
	dbSource := newConnectionString(cfg)
	conn, err := sqlx.Connect("postgres", dbSource)
	if err != nil {
		panic(err)
	}
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(25)
	conn.SetConnMaxIdleTime(20 * time.Minute)
	return conn
}

func newConnectionString(cfg *config.PostgreSQL) string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		cfg.User,
		cfg.Pass,
		cfg.Addr,
		cfg.Port,
		cfg.DatabaseName,
		cfg.SslMode,
	)
}

func newSuperConnectionString(cfg *config.PostgreSQL) string {
	return fmt.Sprintf(
		"postgres://%s@%s:%s/%s?sslmode=%s",
		cfg.SuperUser,
		cfg.Addr,
		cfg.Port,
		cfg.SuperDatabase,
		cfg.SslMode,
	)
}

func NewPostgresSuperConn(cfg *config.PostgreSQL) *sqlx.DB {
	dbSource := newSuperConnectionString(cfg)
	conn, err := sqlx.Connect("postgres", dbSource)
	if err != nil {
		panic(err)
	}
	return conn
}
