package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
)

func TestModelDisplayAndClear(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	c.DefaultModel = "provider/model"
	if err := config.Init(dir, c); err != nil {
		t.Fatal(err)
	}
	c, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runModels(context.Background(), dir, c, "set-model", nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), c.DefaultModel) {
		t.Fatal(out.String())
	}
	if err := runModels(context.Background(), dir, c, "set-model", []string{"--clear"}, &out); err != nil {
		t.Fatal(err)
	}
	next, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	expected := c
	expected.DefaultModel = ""
	if next != expected {
		t.Fatal("clearing model changed other configuration")
	}
}

func TestPrintModels(t *testing.T) {
	var out bytes.Buffer
	err := printModels(&out, []byte(`{"data":[{"id":"z/model","oa_request_limit_micro_usd":2000000},{"id":"a/model","oa_request_limit_micro_usd":1000000},{"id":"evil\nline","oa_request_limit_micro_usd":1}]}`), "a/model")
	if err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if strings.Index(s, "a/model") > strings.Index(s, "z/model") || !strings.Contains(s, "$1 [default]") || strings.Contains(s, "evil") {
		t.Fatal(s)
	}
}
