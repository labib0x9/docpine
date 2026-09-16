package cmd

import (
	"github.com/spf13/cobra"
)

var allCmd = &cobra.Command{
	Use:     "all",
	Aliases: []string{"all"},
	Short:   "initializes queue, minio and sql migration",
	RunE:    allSetup,
}

func allSetup(cmd *cobra.Command, args []string) error {
	all = true
	err := setupDatabase()
	if err != nil {
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(allCmd)
}
