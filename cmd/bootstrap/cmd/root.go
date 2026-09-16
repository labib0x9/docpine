package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "bootstrap is a cli to setup database migration, rabbitmq queue and minio event notifier",
	Long:  "",
	Run:   func(cmd *cobra.Command, args []string) {},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Oops. An error while executing bootstrap '%s'\n", err)
		os.Exit(1)
	}
}
