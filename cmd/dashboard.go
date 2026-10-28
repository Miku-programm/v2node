package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wyx2685/v2node/dashboard"
)

var dashCfg dashboard.Config

var dashboardCommand = cobra.Command{
	Use:   "dashboard",
	Short: "Run probe log analysis dashboard (reads from ClickHouse)",
	Args:  cobra.NoArgs,
	Run: func(_ *cobra.Command, _ []string) {
		if dashCfg.CHPassword == "" {
			dashCfg.CHPassword = os.Getenv("V2NODE_CH_PASSWORD")
		}
		if dashCfg.AuthPassword == "" {
			dashCfg.AuthPassword = os.Getenv("V2NODE_DASH_PASSWORD")
		}
		s, err := dashboard.New(dashCfg)
		if err != nil {
			log.WithField("err", err).Error("Init dashboard failed")
			return
		}
		if err := s.Run(); err != nil {
			log.WithField("err", err).Error("Dashboard stopped")
		}
	},
}

func init() {
	f := dashboardCommand.Flags()
	f.StringVarP(&dashCfg.Listen, "listen", "l", "127.0.0.1:8088", "listen address")
	f.StringVar(&dashCfg.CHURL, "ch-url", "http://127.0.0.1:8123", "ClickHouse HTTP url")
	f.StringVar(&dashCfg.CHDatabase, "ch-db", "v2node", "ClickHouse database")
	f.StringVar(&dashCfg.CHTable, "ch-table", "probe_events", "ClickHouse table")
	f.StringVar(&dashCfg.CHUser, "ch-user", "default", "ClickHouse user (read-only recommended)")
	f.StringVar(&dashCfg.CHPassword, "ch-password", "", "ClickHouse password (or env V2NODE_CH_PASSWORD)")
	f.StringVar(&dashCfg.AuthUser, "auth-user", "", "dashboard basic auth user")
	f.StringVar(&dashCfg.AuthPassword, "auth-password", "", "dashboard basic auth password (or env V2NODE_DASH_PASSWORD)")
	f.BoolVar(&dashCfg.AllowRawSQL, "raw-sql", false, "allow running custom SELECT queries from the dashboard")
	command.AddCommand(&dashboardCommand)
}
