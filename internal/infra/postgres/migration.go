package postgres

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/labib0x9/docpine/internal/config"
	"github.com/lib/pq"
)

func SetupDatabase(cnf *config.PostgreSQL) error {
	superDbConn := NewPostgresSuperConn(cnf)
	defer superDbConn.Close()

	userIdent := pq.QuoteIdentifier(cnf.User)
	dbIdent := pq.QuoteIdentifier(cnf.DatabaseName)
	escapedPass := strings.ReplaceAll(cnf.Pass, "'", "''")
	escapedUserLiteral := strings.ReplaceAll(cnf.User, "'", "''")

	_, err := superDbConn.Exec(fmt.Sprintf(`
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%s') THEN
				CREATE ROLE %s WITH LOGIN PASSWORD '%s';
			END IF;
		END
		$$;
	`, escapedUserLiteral, userIdent, escapedPass))
	if err != nil {
		return err
	}

	var exists bool
	err = superDbConn.QueryRow(
		`SELECT EXISTS(SELECT FROM pg_database WHERE datname = $1)`,
		cnf.DatabaseName,
	).Scan(&exists)
	if err != nil {
		return err
	}

	if !exists {
		_, err = superDbConn.Exec(fmt.Sprintf(
			`CREATE DATABASE %s OWNER %s`,
			dbIdent, userIdent,
		))
		if err != nil {
			return err
		}
	}

	_, err = superDbConn.Exec(fmt.Sprintf(
		`GRANT ALL PRIVILEGES ON DATABASE %s TO %s`,
		dbIdent, userIdent,
	))
	if err != nil {
		return err
	}

	targetSuperDSN := fmt.Sprintf(
		"postgres://%s@%s:%s/%s?sslmode=%s",
		cnf.SuperUser,
		cnf.Addr,
		cnf.Port,
		cnf.DatabaseName,
		cnf.SslMode,
	)
	if targetSuperDB, err := sql.Open("postgres", targetSuperDSN); err == nil {
		defer targetSuperDB.Close()
		_, _ = targetSuperDB.Exec(fmt.Sprintf(`
			ALTER DATABASE %[2]s OWNER TO %[1]s;
			ALTER SCHEMA public OWNER TO %[1]s;
			GRANT ALL ON SCHEMA public TO %[1]s;
			GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO %[1]s;
			GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO %[1]s;
			GRANT ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public TO %[1]s;
			CREATE EXTENSION IF NOT EXISTS pg_cron;
			GRANT USAGE ON SCHEMA cron TO %[1]s;
			GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA cron TO %[1]s;
			GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA cron TO %[1]s;
			GRANT ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA cron TO %[1]s;
		`, userIdent, dbIdent))
	}

	slog.Info("Database setup complete, run migration to create tables")

	return nil
}

func Run(cnf *config.PostgreSQL) error {
	dbSource := newConnectionString(cnf)

	appDB, err := sql.Open("postgres", dbSource)
	if err != nil {
		return err
	}
	defer appDB.Close()

	driver, err := postgres.WithInstance(appDB, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance("file://migrations", "postgres", driver)
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}

// step = 0, all
func Rollback(cnf *config.PostgreSQL, steps int) error {
	dbSource := newConnectionString(cnf)
	appDB, err := sql.Open("postgres", dbSource)
	if err != nil {
		return err
	}
	defer appDB.Close()

	driver, err := postgres.WithInstance(appDB, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance("file://migrations", "postgres", driver)
	if err != nil {
		return err
	}

	if steps == 0 {
		return m.Down()
	}
	return m.Steps(-steps)
}
