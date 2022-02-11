package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/testifysec/judge-k8s/cmd/options"
	"github.com/testifysec/witness/pkg/log"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "judge",
		Short: "A tool for judging artifacts",
		Long:  `A Kubernetes admission controller for judging attestations`,
	}

	ro.AddFlags(cmd)
	cmd.AddCommand(ServCmd())
	return cmd
}

func Execute() {
	if err := New().Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func preRoot(cmd *cobra.Command, ro *options.RootOptions) {
	logger := newLogger()
	log.SetLogger(logger)
	if err := logger.SetLevel(ro.LogLevel); err != nil {
		logger.l.Fatal(err)
	}

}
