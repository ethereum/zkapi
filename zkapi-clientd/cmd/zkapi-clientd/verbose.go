package main

import (
	"errors"
	"flag"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
	"io"
)

func serveLogLevel(args []string) (activity.Level, error) {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.String("model", "", "model used for opening-balance recommendation")
	verbose := f.Bool("verbose", false, "")
	semi := f.Bool("semi-verbose", false, "")
	if err := f.Parse(args); err != nil {
		return activity.Normal, err
	}
	if *verbose && *semi {
		return activity.Normal, errors.New("choose --verbose or --semi-verbose, not both")
	}
	if *verbose {
		return activity.Verbose, nil
	}
	if *semi {
		return activity.SemiVerbose, nil
	}
	return activity.Normal, nil
}
