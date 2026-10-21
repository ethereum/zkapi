package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/rewriter"
)

func runRewriterConfig(dir string, c config.Config, args []string, out io.Writer) error {
	f := flag.NewFlagSet("set-rewriter", flag.ContinueOnError)
	f.SetOutput(out)
	endpoint := f.String("url", "", "OpenAI-compatible base URL (direct HTTPS; loopback HTTP allowed)")
	model := f.String("model", "", "rewriter model ID")
	keyEnv := f.String("api-key-env", "", "read API key from this environment variable and save privately; omitted means no key")
	notice := f.String("notice", "reasoning", "preview: reasoning, metadata, or off")
	clear := f.Bool("clear", false, "disable rewriter and remove its saved key")
	if err := f.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected set-rewriter arguments")
	}
	if len(args) == 0 {
		if !c.Rewriter.Enabled() {
			fmt.Fprintln(out, "Rewriter disabled.")
			return nil
		}
		// Never echo the endpoint (potential path secrets) or the API key.
		fmt.Fprintf(out, "Rewriter enabled; model=%s; API key configured=%t; notice=%s\n", c.Rewriter.Model, c.Rewriter.APIKey != "", c.Rewriter.Notice)
		return nil
	}
	next := c
	if *clear {
		if len(args) != 1 {
			return errors.New("use --clear alone")
		}
		next.Rewriter = rewriter.Config{}
	} else {
		key := ""
		if *keyEnv != "" {
			key = os.Getenv(*keyEnv)
			if key == "" {
				return errors.New("rewriter API key environment variable is empty")
			}
		}
		next.Rewriter = rewriter.Config{URL: *endpoint, Model: *model, APIKey: key, Notice: *notice}
		if !next.Rewriter.Enabled() {
			return errors.New("--url and --model are required")
		}
	}
	if err := config.Update(dir, c, next); err != nil {
		return err
	}
	if *clear {
		fmt.Fprintln(out, "Rewriter disabled.")
	} else {
		fmt.Fprintln(out, "Rewriter saved. WARNING: uncached user text goes directly to this service outside Tor/zkAPI. Target history reuses saved rewrites; cache misses rewrite historical user turns. Style normalization does not guarantee anonymity. Stop/restart serve to apply. No test request or payment sent.")
	}
	return nil
}
