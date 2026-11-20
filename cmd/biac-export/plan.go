package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Plan declares WHAT to export. Adding a service = adding a Resource entry.
type Plan struct {
	Version   int        `json:"version"`
	Resources []Resource `json:"resources"`
}

type Resource struct {
	Name      string            `json:"name"`
	Op        string            `json:"op"`                  // operationId in the spec (must be a GET)
	Per       string            `json:"per,omitempty"`       // parent resource; one call per parent item
	Params    map[string]string `json:"params,omitempty"`    // path param -> parent field (dotted ok)
	IDField   string            `json:"idField,omitempty"`   // default "id"; used when others reference this resource
	SelectKey string            `json:"selectKey,omitempty"` // field matched by --select name=a,b
	Rewrite   []Rewrite         `json:"rewrite,omitempty"`   // replace cluster-specific IDs by names
	Drop      []string          `json:"drop,omitempty"`      // fields removed from the artifact
	Optional  bool              `json:"optional,omitempty"`  // skip if op absent from spec or 404 at runtime
}

// Rewrite replaces the ID at Field with Use-field of the From resource's item, stored at To.
type Rewrite struct {
	Field string `json:"field"`
	To    string `json:"to"`
	From  string `json:"from"`
	Use   string `json:"use"`
}

func parsePlan(data []byte) (*Plan, error) {
	var p Plan
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	return &p, nil
}

// validate checks the plan against the spec. It returns warnings and the set
// of optional resources to skip (operation missing from this spec version).
func (p *Plan) validate(s *Spec) (warns []string, skip map[string]bool, err error) {
	skip = map[string]bool{}
	seen := map[string]*Resource{}
	for i := range p.Resources {
		r := &p.Resources[i]
		if r.Name == "" || seen[r.Name] != nil {
			return nil, nil, fmt.Errorf("resource #%d: empty or duplicate name %q", i, r.Name)
		}
		op := s.Ops[r.Op]
		if op == nil {
			if r.Optional {
				warns = append(warns, fmt.Sprintf("%s: operation %q not in spec; skipped (optional)", r.Name, r.Op))
				skip[r.Name] = true
				seen[r.Name] = r
				continue
			}
			return nil, nil, fmt.Errorf("%s: operation %q not found in spec (removed or renamed? run spec-diff)", r.Name, r.Op)
		}
		if op.Method != "GET" {
			return nil, nil, fmt.Errorf("%s: %s is %s; export is read-only (GET only)", r.Name, r.Op, op.Method)
		}
		if strings.Contains(op.Path, "/internal/") {
			return nil, nil, fmt.Errorf("%s: %s is an internal endpoint; not allowed", r.Name, r.Op)
		}
		if r.Per != "" {
			par := seen[r.Per]
			if par == nil {
				return nil, nil, fmt.Errorf("%s: parent %q must be declared earlier", r.Name, r.Per)
			}
			if skip[r.Per] {
				skip[r.Name] = true
				seen[r.Name] = r
				continue
			}
		}
		pp := op.pathParams()
		for _, n := range pp {
			if r.Params[n] == "" {
				return nil, nil, fmt.Errorf("%s: path param {%s} of %s has no mapping in \"params\"", r.Name, n, op.Path)
			}
		}
		for n := range r.Params {
			if !op.hasParam(n, "path") {
				return nil, nil, fmt.Errorf("%s: params key %q is not a path param of %s", r.Name, n, op.Path)
			}
		}
		if r.Per == "" && len(pp) > 0 {
			return nil, nil, fmt.Errorf("%s: %s needs path params %v but has no \"per\" parent", r.Name, r.Op, pp)
		}
		for _, rw := range r.Rewrite {
			from := seen[rw.From]
			if from == nil || from.Per != "" {
				return nil, nil, fmt.Errorf("%s: rewrite from %q must be an earlier top-level resource", r.Name, rw.From)
			}
			if skip[rw.From] {
				return nil, nil, fmt.Errorf("%s: rewrite source %q was skipped", r.Name, rw.From)
			}
		}
		seen[r.Name] = r
	}
	return warns, skip, nil
}
