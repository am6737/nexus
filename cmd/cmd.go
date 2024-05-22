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
					Value: "/Users/lms/Documents/biset/nexus/config.yaml",
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
			Name:   "start",
			Usage:  "start nexus",
			Action: start,
		},
		{
			Name:   "stop",
			Usage:  "stop nexus",
			Action: stop,
		},
		{
			Name:   "enroll",
			Usage:  "enroll nexus",
			Action: enroll,
		},
	},
}
