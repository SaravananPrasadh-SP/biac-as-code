package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Spec is a parsed OpenAPI 3 document, indexed by operationId.
type Spec struct {
	Version string
	Ops     map[string]*Operation
	doc     map[string]any
}

type Param struct {
	Name, In string
	Required bool
}

type Operation struct {
	ID, Method, Path string
	Params           []Param
	Resp             any // resolved 200 response schema (may be nil)
}

func parseSpec(data []byte) (*Spec, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("spec must be OpenAPI 3 in JSON: %w", err)
	}
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.") {
		return nil, fmt.Errorf("unsupported spec: openapi=%q (need 3.x)", v)
	}
	s := &Spec{doc: doc, Ops: map[string]*Operation{}}
	if info, ok := doc["info"].(map[string]any); ok {
		s.Version, _ = info["version"].(string)
	}
	paths, _ := doc["paths"].(map[string]any)
	for path, item := range paths {
		pi, ok := item.(map[string]any)
		if !ok {
			continue
		}
		shared := s.params(pi["parameters"])
		for method, o := range pi {
			op, ok := o.(map[string]any)
			if !ok || method == "parameters" {
				continue
			}
			id, _ := op["operationId"].(string)
			if id == "" {
				continue
			}
			if _, dup := s.Ops[id]; dup {
				return nil, fmt.Errorf("duplicate operationId %q", id)
			}
			s.Ops[id] = &Operation{ID: id, Method: strings.ToUpper(method), Path: path,
				Params: append(append([]Param{}, shared...), s.params(op["parameters"])...),
				Resp:   s.okSchema(op)}
		}
	}
	return s, nil
}

func (s *Spec) params(v any) []Param {
	var out []Param
	arr, _ := v.([]any)
	for _, p := range arr {
		m, _ := s.resolve(p).(map[string]any)
		if m == nil {
			continue
		}
		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		req, _ := m["required"].(bool)
		out = append(out, Param{name, in, req})
	}
	return out
}

func (s *Spec) okSchema(op map[string]any) any {
	resps, _ := op["responses"].(map[string]any)
	r, _ := s.resolve(resps["200"]).(map[string]any)
	content, _ := r["content"].(map[string]any)
	keys := make([]string, 0, len(content))
	for k := range content {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if m, ok := content[k].(map[string]any); ok && m["schema"] != nil {
			return s.resolve(m["schema"])
		}
	}
	return nil
}

// resolve follows local $ref pointers (bounded to avoid cycles).
func (s *Spec) resolve(n any) any {
	for i := 0; i < 16; i++ {
		m, ok := n.(map[string]any)
		if !ok {
			return n
		}
		ref, ok := m["$ref"].(string)
		if !ok || !strings.HasPrefix(ref, "#/") {
			return n
		}
		var cur any = s.doc
		for _, seg := range strings.Split(ref[2:], "/") {
			seg = strings.NewReplacer("~1", "/", "~0", "~").Replace(seg)
			cm, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = cm[seg]
		}
		n = cur
	}
	return nil
}

// pageShape reads the pagination envelope from the response schema:
// the array property holding items and the "next..." token property.
func (s *Spec) pageShape(op *Operation) (items, token string) {
	m, _ := op.Resp.(map[string]any)
	props, _ := m["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		pm, _ := s.resolve(props[k]).(map[string]any)
		switch t, _ := pm["type"].(string); {
		case t == "array" && (items == "" || k == "result"):
			items = k
		case t == "string" && strings.HasPrefix(k, "next"):
			token = k
		}
	}
	return
}

func (o *Operation) hasParam(name, in string) bool {
	for _, p := range o.Params {
		if p.Name == name && p.In == in {
			return true
		}
	}
	return false
}

func (o *Operation) pathParams() []string {
	var out []string
	for _, p := range o.Params {
		if p.In == "path" {
			out = append(out, p.Name)
		}
	}
	return out
}
