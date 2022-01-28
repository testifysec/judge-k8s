package options

import "github.com/spf13/cobra"

type Interface interface {
	// AddFlags adds this options' flags to the cobra command.
	AddFlags(cmd *cobra.Command)
}

type RootOptions struct {
	LogLevel string
}

func (ro *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&ro.LogLevel, "log-level", "l", "info", "Level of logging to output (debug, info, warn, error)")
}

type ServeOptions struct {
	Port        int
	Cert        string
	Key         string
	PolicyFile  string
	RekorServer string
}

func (so *ServeOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().IntVarP(&so.Port, "port", "", 443, "Port to listen on")
	cmd.PersistentFlags().StringVarP(&so.Cert, "cert", "c", "", "Path to TLS certificate file")
	cmd.PersistentFlags().StringVarP(&so.Key, "key", "k", "k", "Path to TLS key file")
	cmd.PersistentFlags().StringVarP(&so.PolicyFile, "policy", "p", "", "Path to the policy file")
	cmd.PersistentFlags().StringVarP(&so.RekorServer, "rekor-server", "r", "http://rekor-server:8077", "Rekor server address")
}
