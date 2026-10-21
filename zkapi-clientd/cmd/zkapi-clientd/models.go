package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func runModels(ctx context.Context, dir string, c config.Config, command string, args []string, out io.Writer) error {
	if command == "set-model" && len(args) == 0 {
		if c.DefaultModel == "" {
			fmt.Fprintln(out, "No default model selected.")
		} else {
			fmt.Fprintf(out, "Default model: %s\n", c.DefaultModel)
		}
		return nil
	}
	if command == "set-model" && len(args) == 1 && args[0] == "--clear" {
		next := c
		next.DefaultModel = ""
		if err := config.Update(dir, c, next); err != nil {
			return err
		}
		fmt.Fprintln(out, "Default cleared; requests must specify a model. Serve uses the conservative funding recommendation.")
		return nil
	}
	if command == "list-models" && len(args) != 0 {
		return errors.New("usage: list-models")
	}
	if command == "set-model" && (len(args) != 1 || !config.ValidModelID(args[0])) {
		return errors.New("usage: set-model MODEL (or --clear)")
	}
	transport, err := relay.NewClient(c.RelayURL)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	client, err := zkapi.New(zkConfig(c, transport))
	if err != nil {
		return err
	}
	if command == "set-model" {
		budget, err := client.ModelRequestBudget(ctx, args[0])
		if err != nil {
			return modelSelectionError(args[0], err)
		}
		next := c
		next.DefaultModel = args[0]
		if err := config.Update(dir, c, next); err != nil {
			return err
		}
		fmt.Fprintf(out, "Default model: %s (per-query cap $%s).\nUsed for missing request models and serve funding recommendations; explicit request models take precedence.\n", args[0], setupUSD(budget))
		return nil
	}
	raw, err := client.PublicModels(ctx)
	if err != nil {
		return err
	}
	return printModels(out, raw, c.DefaultModel)
}

func modelSelectionError(model string, err error) error {
	var remote *zkapi.Error
	if errors.As(err, &remote) {
		switch remote.Code {
		case "model_not_found":
			return fmt.Errorf("model not found: %q; use the full provider/model ID (for example openai/gpt-6.1-sol-pro). Run zkapi-clientd list-models", model)
		case "model_budget_unavailable":
			return fmt.Errorf("model %q has no supported spending policy; select a model from zkapi-clientd list-models", model)
		}
	}
	return err
}

func printModels(out io.Writer, raw json.RawMessage, selected string) error {
	var catalog struct {
		Data []struct {
			ID     string `json:"id"`
			Budget uint64 `json:"oa_request_limit_micro_usd"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return errors.New("invalid model catalog")
	}
	sort.Slice(catalog.Data, func(i, j int) bool { return catalog.Data[i].ID < catalog.Data[j].ID })
	fmt.Fprintln(out, "MODEL  |  PER-QUERY CAP (USD)")
	for _, model := range catalog.Data {
		if !config.ValidModelID(model.ID) || model.Budget == 0 {
			continue
		}
		marker := ""
		if model.ID == selected {
			marker = " [default]"
		}
		fmt.Fprintf(out, "%s  |  $%s%s\n", model.ID, setupUSD(model.Budget), marker)
	}
	fmt.Fprintln(out, "Caps are authorization limits, not predicted charges. No payment or key acquisition performed.")
	return nil
}
