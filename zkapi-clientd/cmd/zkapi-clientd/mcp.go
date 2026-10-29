package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/delegatemcp"
)

const mcpHelp = `Usage: zkapi-clientd [--config-dir DIR] mcp
Serve the Model Context Protocol on stdin/stdout for a local AI host.
Attaches to the zkapi-clientd serve daemon already running for the profile:
it never starts, funds or configures it. From the saved config it uses only
the connection settings and default model; it never loads or creates the
separate management credential. Tools: zkapi_delegate (paid, one independent completion per call;
requires Tor routing) and zkapi_list_models (free). See docs/MCP_DELEGATION.md.`

// runMCP serves until the host closes stdin or ctx ends. Only MCP frames are
// written to stdout; this command prints nothing else there.
func runMCP(ctx context.Context, dir string, args []string, transport mcp.Transport, help io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(help, mcpHelp)
		return nil
	}
	if len(args) != 0 {
		return errors.New("mcp accepts no arguments; use zkapi-clientd config to change settings")
	}
	access, err := config.ReadLocalAccess(dir)
	if err != nil {
		return fmt.Errorf("%w; mcp needs the profile of a configured daemon: pass the same --config-dir as zkapi-clientd serve", err)
	}
	server, err := delegatemcp.NewServer(delegatemcp.Options{Listen: access.Listen, APIKey: access.APIKey, DefaultModel: access.DefaultModel, Version: version})
	if err != nil {
		return err
	}
	if err := server.Run(ctx, transport); err != nil && ctx.Err() == nil {
		return errors.New("MCP session ended with a protocol or transport error")
	}
	return nil
}
