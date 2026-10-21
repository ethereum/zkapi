package main

import (
	"github.com/ethereum/zkapi/zkapi-clientd/internal/activity"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"testing"
)

func TestServeDiagnosticFlags(t *testing.T) {
	c, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args  []string
		level activity.Level
	}{
		{nil, activity.Normal}, {[]string{"--verbose"}, activity.Verbose}, {[]string{"--semi-verbose"}, activity.SemiVerbose},
	} {
		level, err := serveLogLevel(test.args)
		if err != nil || level != test.level {
			t.Fatal(level, err)
		}
		got, err := serveConfig(c, test.args)
		if err != nil || got != c {
			t.Fatal("logging changes wallet config", err)
		}
	}
	if _, err := serveConfig(c, []string{"--verbose", "--semi-verbose"}); err == nil {
		t.Fatal("ambiguous verbosity accepted")
	}
}
