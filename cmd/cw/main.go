// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"fmt"
	"os"

	"github.com/frandustry/CryptoWrapper/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	root := cli.New(version, commit, date)
	if err := root.Execute(); err != nil {
		if exitErr, ok := err.(cli.ExitError); ok {
			fmt.Fprintln(os.Stderr, exitErr.Error())
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
