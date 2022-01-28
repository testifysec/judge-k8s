package cmd

import (
	"fmt"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"github.com/spf13/cobra"
	"github.com/testifysec/judge-k8s/cmd/options"
	"github.com/testifysec/judge-k8s/pkg/handlers"
)

func ServCmd() *cobra.Command {
	o := options.ServeOptions{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the server",
		Long:  `Start the server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServ(o)
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func runServ(o options.ServeOptions) error {
	e := echo.New()
	e.Logger.SetLevel(log.Level())
	e.POST("/", handlers.PostValidatingAdmission())
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
	}))

	err := e.StartTLS(fmt.Sprintf(":%d", o.Port), o.Cert, o.Key)
	if err != nil {
		return err
	}

	return nil
}
