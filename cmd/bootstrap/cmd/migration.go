package cmd

import (
	"fmt"

	"github.com/labib0x9/docpine/internal/config"
	"github.com/labib0x9/docpine/internal/infra/postgres"
	"github.com/spf13/cobra"
)

var (
	all  bool
	up   bool
	down bool
)

var migrateCmd = &cobra.Command{
	Use:     "migration",
	Aliases: []string{"migrate"},
	Short:   "executes db migration",
	RunE:    dbSetupfunc,
}

func dbSetupfunc(cmd *cobra.Command, args []string) error {
	return setupDatabase()
}

func setupDatabase() error {
	cnf := config.GetConfig()
	switch {
	case all:
		{
			if err := postgres.SetupDatabase(cnf.PostgreSQL); err != nil {
				return err
			}
		}
		fallthrough
	case up:
		{
			if err := postgres.Run(cnf.PostgreSQL); err != nil {
				return err
			}
		}
	case down:
		{
			if err := postgres.Rollback(cnf.PostgreSQL, 0); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("No valid flag provided.")
	}
	return nil
}

func init() {
	migrateCmd.Flags().BoolVarP(&all, "all", "a", false, "create user, database and migration up")
	migrateCmd.Flags().BoolVarP(&up, "up", "u", false, "only migration up")
	migrateCmd.Flags().BoolVarP(&down, "down", "d", false, "only migration down all")
	rootCmd.AddCommand(migrateCmd)
}
