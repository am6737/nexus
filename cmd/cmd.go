package cmd

import (
	"github.com/urfave/cli/v2"
)

const VERSION = "v1.0.0"

var App = &cli.App{
	Name:    "nexus",
	Usage:   "nexus",
	Version: VERSION,
	Commands: []*cli.Command{
		{
			Name:  "run",
			Usage: "start nexus",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "config",
					Usage: "config file path",
					Value: "config.yaml",
				},
			},
			Action: run,
		},
		{
			Name:   "install",
			Usage:  "install nexus",
			Action: install,
		},
		{
			Name:   "uninstall",
			Usage:  "uninstall nexus",
			Action: uninstall,
		},
		{
			Name:  "start",
			Usage: "start nexus",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "config",
					Usage: "config file path",
					Value: "config.yaml",
				},
			},
			Action: start,
		},
		{
			Name:   "stop",
			Usage:  "stop nexus",
			Action: stop,
		},
		{
			Name:  "enroll",
			Usage: "enroll nexus",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  "code",
					Usage: "enrollment code",
				},
				&cli.StringFlag{
					Name:  "server",
					Usage: "server addr",
					Value: "43.229.28.27:7777",
				},
			},
			Action: enroll,
		},
	},
}
