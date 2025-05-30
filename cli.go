package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/mgutz/ansi"
	"github.com/urfave/cli/v3"
)

func Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, ansi.Color(fmt.Sprintf(format, args...), "red+dbi")+"\n")
	os.Exit(1)
}

func Cli() {
	red := ansi.ColorFunc("red+dbi")
	cmd := &cli.Command{
		Name:                  "symbolon-core",
		Usage:                 "blah blah blah",
		EnableShellCompletion: true,
		Version:               "0.1.0",
		// Authors: []any{
		// 	"amarjay<abdmananjnr@gmail.com>",
		// },
		// Copyright:   "MIT License (MIT)",
		HideVersion: true,
		Suggest:     true,
		Description: "This is a CLI for Symbolon Core, a tool for managing containers and networks.",
		Commands: []*cli.Command{
			{
				Name:        "build",
				Usage:       "Build a container image",
				Description: "This command builds a container image from a script",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Running a container...[not implemented yet]")
					return nil
				},
			},
			{
				Name:        "run",
				Usage:       "Run a container",
				Description: "This command runs a container with the specified image and options.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Running a container...[not implemented yet]")
					return nil
				},
			},
			{
				Name:        "stop",
				Usage:       "Stop a running container",
				Description: "This command stops a running container by its ID or name.",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					fmt.Println("Stopping a container...[not implemented yet]")
					return nil
				},
			},
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable verbose output",
			},
			&cli.BoolFlag{
				Name:    "detach",
				Aliases: []string{"d"},
				Usage:   "Run the container in detached mode",
				Value:   false,
			},
		},
		Arguments: []cli.Argument{
			&cli.IntArg{
				Name:      "someint",
				UsageText: "some integer",
			},
			&cli.IntArg{
				Name: "_someint",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Bool("detach") {
				return cli.Exit(red("cannot run in detach mode"), 126)
			}
			fmt.Printf("We got %d", cmd.IntArg("someint"))
			return nil
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func main() {
	Cli()
}
