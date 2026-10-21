package main

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// Render every exported setting, including zero/disabled values, with explicit
// redactions. This is an inspection view, not an importable wallet backup.
func printSavedConfig(dir string, out io.Writer) error {
	if _, err := os.Lstat(filepath.Join(dir, "config.json")); err != nil {
		return errors.New("cannot read saved configuration; use config --setup to initialize a new profile, or restore the existing configuration")
	}
	c, err := config.Inspect(dir)
	if err != nil {
		return configurationRequired(err)
	}
	saved, err := config.LoadVaultProtocol(dir)
	if err != nil {
		return err
	}
	protocol := saved
	if protocol == "" {
		protocol = "concession"
	}
	values := allConfigFields(reflect.ValueOf(c))
	// Marshal omits disabled optional fields; include them for a complete view.
	values["default_model"] = c.DefaultModel
	values["org_url"] = c.OrgURL
	values["management_token"] = redactCredential(c.ManagementToken)
	values["api_key"] = redactCredential(c.APIKey)
	values["vault_protocol"] = protocol
	values["rewriter"] = map[string]any{"url": safeConfigURL(c.Rewriter.URL), "model": c.Rewriter.Model, "api_key": redactCredential(c.Rewriter.APIKey), "notice": c.Rewriter.Notice, "instruction": c.Rewriter.EffectiveInstruction(), "instruction_source": "default"}
	if c.Rewriter.Instruction != "" {
		values["rewriter"].(map[string]any)["instruction_source"] = "custom"
	}
	urls := strings.Fields(c.Cover.URLs)
	for i := range urls {
		urls[i] = safeConfigURL(urls[i])
	}
	values["cover"] = map[string]any{"rate": c.Cover.Rate, "concurrency": c.Cover.Concurrency, "urls": strings.Join(urls, " ")}
	for _, k := range []string{"org_url", "verifier_url", "relay_url"} {
		if v, ok := values[k].(string); ok {
			values[k] = safeConfigURL(v)
		}
	}
	wallet := values["zkapi"].(map[string]any)
	wallet["bridge_token"] = redactCredential(c.ZKAPI.BridgeToken)
	wallet["client_url"] = safeConfigURL(c.ZKAPI.ClientURL)
	wallet["binary"] = c.ZKAPI.Binary
	wallet["proof_setup_dir"] = c.ZKAPI.ProofSetupDir
	wallet["external_companion"] = c.ZKAPI.ExternalCompanion
	wallet["request_limit_micro_usd"] = c.ZKAPI.RequestLimitMicroUSD
	// Newer optional protocol fields already present are sanitized below.
	for k, v := range wallet {
		if strings.HasSuffix(k, "_url") {
			if s, ok := v.(string); ok {
				wallet[k] = safeConfigURL(s)
			}
		}
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(values)
}

// Include optional zero values without changing on-disk serialization. Preserve
// integer types rather than round-tripping through float64.
func allConfigFields(v reflect.Value) map[string]any {
	result := map[string]any{}
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" || name == "" {
			continue
		}
		value := v.Field(i)
		if value.Kind() == reflect.Struct {
			result[name] = allConfigFields(value)
		} else {
			result[name] = value.Interface()
		}
	}
	return result
}
func redactCredential(s string) string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}
func safeConfigURL(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "[redacted URL]"
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return u.Scheme + "://" + u.Host + "/[redacted]"
	}
	return s
}
