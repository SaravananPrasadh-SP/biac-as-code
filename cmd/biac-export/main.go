// biac-export exports SEP built-in access control (roles, grants, column masks,
// row filters, role assignments) into a compact, ID-free artifact for fast import.
//
// What is exported is declared in a plan (embedded/plan.json) and resolved
// against an OpenAPI spec (embedded/api.spec); both can be overridden.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"
)

//go:embed embedded/api.spec
var embeddedSpec []byte

//go:embed embedded/plan.json
var embeddedPlan []byte

const formatVersion = 2

type Artifact struct {
	Version    int            `json:"v"`
	ExportedAt string         `json:"exportedAt"`
	Source     string         `json:"source"`
	SpecVer    string         `json:"specVersion"`
	Order      []string       `json:"order"` // top-level resources in import order
	Resources  map[string]any `json:"resources"`
}

func main() {
	args := os.Args[1:]
	cmd := "export"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "export":
		err = runExport(args)
	case "validate":
		err = runValidate(args)
	case "spec-diff":
		err = runSpecDiff(args)
	case "import":
		err = runImport(args)
	case "convert":
		err = runConvert(args)
	default:
		err = fmt.Errorf("unknown command %q (export | import | convert | validate | spec-diff)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 32<<20))
}

func loadSpecPlan(specPath, planPath string) (*Spec, *Plan, error) {
	sb, pb := embeddedSpec, embeddedPlan
	var err error
	if specPath != "" {
		if sb, err = readLimited(specPath); err != nil {
			return nil, nil, err
		}
	}
	if planPath != "" {
		if pb, err = readLimited(planPath); err != nil {
			return nil, nil, err
		}
	}
	s, err := parseSpec(sb)
	if err != nil {
		return nil, nil, err
	}
	p, err := parsePlan(pb)
	if err != nil {
		return nil, nil, err
	}
	return s, p, nil
}

type multi map[string]map[string]bool // --select resource=a,b (repeatable)

func (m multi) String() string { return "" }
func (m multi) Set(v string) error {
	k, vals, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return fmt.Errorf("want resource=name1,name2")
	}
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	for _, n := range strings.Split(vals, ",") {
		if n = strings.TrimSpace(n); n != "" {
			m[k][n] = true
		}
	}
	return nil
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	sel := multi{}
	var (
		urlF  = fs.String("url", os.Getenv("STARBURST_URL"), "SEP base URL (env STARBURST_URL)")
		out   = fs.String("out", "biac-export.biac", "output file: .biac = binary (default), .json / .json.gz = JSON")
		spec  = fs.String("spec", "", "OpenAPI spec file (default: embedded)")
		plan  = fs.String("plan", "", "export plan file (default: embedded)")
		conc  = fs.Int("concurrency", 16, "max parallel API calls")
		ca    = fs.String("ca-cert", "", "extra PEM CA bundle")
		allow = fs.Bool("allow-http", false, "permit plain http (local testing only)")
		role  = fs.String("role", os.Getenv("STARBURST_ROLE"), "system role to activate, e.g. sysadmin; sent as X-Trino-Role: system=ROLE{role} (env STARBURST_ROLE)")
		debug = fs.Bool("debug", false, "also write a human-readable JSON copy next to the binary artifact (contains the same sensitive data)")
		to    = fs.Duration("timeout", 60*time.Second, "per-request timeout")
	)
	fs.Var(sel, "select", "limit a resource, e.g. --select roles=analyst,admin (repeatable)")
	fs.Parse(args)

	s, p, err := loadSpecPlan(*spec, *plan)
	if err != nil {
		return err
	}
	warns, skip, err := p.validate(s)
	if err != nil {
		return err
	}
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	// Secrets come from the environment only: never in shell history or `ps`.
	c, err := newClient(clientConfig{BaseURL: *urlF, Token: os.Getenv("STARBURST_TOKEN"),
		User: os.Getenv("STARBURST_USER"), Pass: os.Getenv("STARBURST_PASSWORD"),
		Role: *role, CACertFile: *ca, AllowHTTP: *allow, Timeout: *to})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, order, err := newEngine(c, s, p, skip, *conc, sel).Run(ctx)
	if err != nil {
		return err
	}
	art := &Artifact{Version: formatVersion, ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Source: c.base.Host, SpecVer: s.Version, Order: order, Resources: res}
	tree, err := normalize(art)
	if err != nil {
		return err
	}
	if err := writeArtifact(*out, tree); err != nil {
		return err
	}
	if *debug && !strings.HasSuffix(*out, ".json") && !strings.HasSuffix(*out, ".json.gz") {
		dbg := strings.TrimSuffix(*out, ".biac") + ".debug.json"
		if err := writeArtifact(dbg, tree); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "debug: wrote readable copy %s (same sensitivity as the artifact; delete after use)\n", dbg)
	}
	var sum []string
	for _, n := range order {
		sum = append(sum, fmt.Sprintf("%d %s", len(res[n].([]item)), n))
	}
	fmt.Fprintf(os.Stderr, "exported %s -> %s\n", strings.Join(sum, ", "), *out)
	return nil
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	spec := fs.String("spec", "", "OpenAPI spec file (default: embedded)")
	plan := fs.String("plan", "", "export plan file (default: embedded)")
	fs.Parse(args)
	s, p, err := loadSpecPlan(*spec, *plan)
	if err != nil {
		return err
	}
	warns, _, err := p.validate(s)
	for _, w := range warns {
		fmt.Println("warning:", w)
	}
	if err != nil {
		return err
	}
	fmt.Printf("plan OK against spec version %s (%d operations, %d resources)\n", s.Version, len(s.Ops), len(p.Resources))
	return nil
}

func runSpecDiff(args []string) error {
	fs := flag.NewFlagSet("spec-diff", flag.ExitOnError)
	plan := fs.String("plan", "", "export plan file (default: embedded)")
	fs.Parse(args)
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: spec-diff [--plan plan.json] OLD_SPEC NEW_SPEC")
	}
	var specs [2]*Spec
	for i := range specs {
		b, err := readLimited(fs.Arg(i))
		if err != nil {
			return err
		}
		if specs[i], err = parseSpec(b); err != nil {
			return fmt.Errorf("%s: %w", fs.Arg(i), err)
		}
	}
	_, p, err := loadSpecPlan("", *plan)
	if err != nil {
		return err
	}
	report, impacted := diffSpecs(specs[0], specs[1], p)
	fmt.Print(report)
	if impacted {
		os.Exit(2) // distinct code for CI
	}
	return nil
}

// writeArtifact picks the format from the extension: .json / .json.gz => JSON, else binary.
func writeArtifact(path string, tree any) (err error) {
	var data []byte
	switch {
	case strings.HasSuffix(path, ".json.gz"), strings.HasSuffix(path, ".json"):
		if data, err = json.Marshal(tree); err != nil {
			return err
		}
		if strings.HasSuffix(path, ".gz") {
			var zb bytes.Buffer
			zw := gzip.NewWriter(&zb)
			zw.Write(data)
			if err = zw.Close(); err != nil {
				return err
			}
			data = zb.Bytes()
		}
	default:
		if data, err = encodeBin(tree); err != nil {
			return err
		}
	}
	// 0600: the artifact contains access-policy detail. Write-then-rename: no partial file on failure.
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func runConvert(args []string) error {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: convert IN OUT   (OUT extension: .biac | .json | .json.gz)")
	}
	m, err := loadArtifact(fs.Arg(0))
	if err != nil {
		return err
	}
	return writeArtifact(fs.Arg(1), m)
}
