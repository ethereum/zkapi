package main

import (
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func TestTorModeConfiguration(t *testing.T) {
	c, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	c.RelayURL = "tor://127.0.0.1:9050"
	if err := config.Validate(c); err != nil {
		t.Fatal(err)
	}
	if !zkConfig(c, nil).TorMode {
		t.Fatal("Tor mode not passed to inference client")
	}
	c.ZKAPI.ExternalCompanion = true
	if err := config.Validate(c); err == nil {
		t.Fatal("external companion bypasses managed Tor route")
	}
	c.RelayURL = "socks5://127.0.0.1:9050"
	if zkConfig(c, nil).TorMode {
		t.Fatal("plain SOCKS opted into conversation mode")
	}
}
