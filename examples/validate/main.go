package main

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/usetero/policy-go/backend/teroscan"
	"github.com/usetero/policy-go/policy"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	pflag.String("file", "", "path to policy JSON file")
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()

	file := viper.GetString("file")
	if file == "" && pflag.NArg() > 0 {
		file = pflag.Arg(0)
	}
	if file == "" {
		fmt.Fprintln(os.Stderr, "usage: validate --file <path>")
		os.Exit(1)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}

	var resp policyv1.SyncResponse
	if err := protojson.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "invalid policy JSON: %v\n", err)
		os.Exit(1)
	}

	if resp.ErrorMessage != "" {
		fmt.Fprintf(os.Stderr, "server error in policy file: %s\n", resp.ErrorMessage)
		os.Exit(1)
	}

	registry := policy.NewPolicyRegistry(policy.WithRegexBackend(teroscan.New()))
	handle, err := registry.Register(&staticProvider{policies: resp.Policies})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error compiling policies: %v\n", err)
		os.Exit(1)
	}
	defer handle.Unregister()

	stats := registry.CollectStats()
	failed := 0
	for _, s := range stats {
		for _, e := range s.Errors {
			fmt.Fprintf(os.Stderr, "FAIL %s: %s\n", s.PolicyID, e)
			failed++
		}
	}

	if failed > 0 {
		os.Exit(1)
	}

	fmt.Printf("OK: %d policies valid\n", len(resp.Policies))
}

type staticProvider struct {
	policies []*policyv1.Policy
}

func (p *staticProvider) Load() ([]*policyv1.Policy, error) { return p.policies, nil }
func (p *staticProvider) Subscribe(cb policy.PolicyCallback) error {
	cb(p.policies)
	return nil
}
func (p *staticProvider) SetStatsCollector(policy.StatsCollector) {}
