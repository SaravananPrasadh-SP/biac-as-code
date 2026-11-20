package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var mock = map[string]any{
	"/api/v1/biac/expressions/columnMask": []any{map[string]any{"id": 1, "name": "mask_ssn", "expression": "'***'"}},
	"/api/v1/biac/expressions/rowFilter":  []any{map[string]any{"id": 2, "name": "us_only", "expression": "country='US'"}},
	"/api/v1/biac/roles":                  []any{map[string]any{"id": 7, "name": "analyst"}, map[string]any{"id": 8, "name": "admin"}},
	"/api/v1/biac/roles/7/grants": []any{map[string]any{"id": 5, "effect": "APPLY_COLUMN_MASK", "action": "SELECT",
		"columnMaskExpressionId": 1, "entity": map[string]any{"category": "TABLES"}}},
	"/api/v1/biac/roles/7/locationGrants": []any{},
	"/api/v1/biac/roles/7/columnMasks":    []any{map[string]any{"id": 1, "expressionId": 1, "entity": map[string]any{"table": "t"}}},
	"/api/v1/biac/roles/7/rowFilters":     []any{map[string]any{"id": 1, "expressionId": 2, "entity": map[string]any{"table": "t"}}},
	"/api/v1/biac/roles/7/assignments": []any{
		map[string]any{"id": 1, "roleAdmin": true, "subject": map[string]any{"type": "USER", "username": "bob"}},
		map[string]any{"id": 2, "subject": map[string]any{"type": "ROLE", "roleId": 8}}},
}

func testEngine(t *testing.T, s *Spec, p *Plan, sel map[string]map[string]bool) (map[string]any, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := mock[r.URL.Path]
		if !ok {
			d = []any{} // other roles: empty
			if !strings.HasPrefix(r.URL.Path, "/api/v1/biac/roles/") {
				http.NotFound(w, r)
				return
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"result": d})
	}))
	t.Cleanup(srv.Close)
	c, err := newClient(clientConfig{BaseURL: srv.URL, User: "u", Pass: "p", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	_, skip, err := p.validate(s)
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := newEngine(c, s, p, skip, 4, sel).Run(context.Background())
	return res, err
}

func TestExportDefaultPlan(t *testing.T) {
	s, p, err := loadSpecPlan("", "")
	if err != nil {
		t.Fatal(err)
	}
	res, err := testEngine(t, s, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	got := string(b)
	for _, want := range []string{
		`"columnMaskExpression":"mask_ssn"`, // grant ID -> name
		`"expression":"us_only"`,            // row filter ID -> name
		`"role":"admin"`,                    // role subject ID -> name
		`"username":"bob"`, `"roleAdmin":true`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	for _, bad := range []string{`"id"`, `Id"`} {
		if strings.Contains(got, bad) {
			t.Errorf("cluster-specific ID leaked (%s): %s", bad, got)
		}
	}
	res, err = testEngine(t, s, p, map[string]map[string]bool{"roles": {"admin": true}})
	if err != nil || len(res["roles"].([]item)) != 1 {
		t.Fatalf("select failed: %v %v", res, err)
	}
	if _, err = testEngine(t, s, p, map[string]map[string]bool{"roles": {"nope": true}}); err == nil {
		t.Fatal("expected error for unknown --select")
	}
}

func TestValidateAndDiff(t *testing.T) {
	s, p, _ := loadSpecPlan("", "")
	if _, _, err := p.validate(s); err != nil {
		t.Fatal(err)
	}
	// Simulate a newer version that drops listRoleAssignments.
	var doc map[string]any
	json.Unmarshal(embeddedSpec, &doc)
	paths := doc["paths"].(map[string]any)
	delete(paths["/api/v1/biac/roles/{roleId}/assignments"].(map[string]any), "get")
	b, _ := json.Marshal(doc)
	s2, err := parseSpec(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.validate(s2); err == nil || !strings.Contains(err.Error(), "listRoleAssignments") {
		t.Fatalf("validate should fail clearly, got %v", err)
	}
	rep, impacted := diffSpecs(s, s2, p)
	if !impacted || !strings.Contains(rep, "USED BY PLAN") {
		t.Fatalf("diff should flag impact:\n%s", rep)
	}
	// Optional resources degrade gracefully.
	for i := range p.Resources {
		if p.Resources[i].Name == "assignments" {
			p.Resources[i].Optional = true
		}
	}
	warns, skip, err := p.validate(s2)
	if err != nil || len(warns) != 1 || !skip["assignments"] {
		t.Fatalf("optional skip failed: %v %v %v", warns, skip, err)
	}
}

func TestPlanRejectsUnsafe(t *testing.T) {
	s, _, _ := loadSpecPlan("", "")
	for name, js := range map[string]string{
		"non-GET":  `{"version":1,"resources":[{"name":"x","op":"createRole"}]}`,
		"internal": `{"version":1,"resources":[{"name":"x","op":"hasAccess"}]}`,
		"no-per":   `{"version":1,"resources":[{"name":"x","op":"listGrants"}]}`,
	} {
		p, err := parsePlan([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.validate(s); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func sampleTree(t testing.TB, roles int) map[string]any {
	t.Helper()
	var rs []any
	for i := 0; i < roles; i++ {
		rs = append(rs, map[string]any{
			"name": "role_" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('0'+i%10)),
			"grants": []any{
				map[string]any{"effect": "ALLOW", "action": "SELECT", "entity": map[string]any{
					"category": "TABLES", "catalog": "hive", "schema": "sales", "table": "t" + string(rune('a'+i%26)), "columns": []any{"c1", "c2"}}},
				map[string]any{"effect": "ALLOW", "action": "INSERT", "entity": map[string]any{
					"category": "TABLES", "catalog": "hive", "schema": "sales", "table": "t" + string(rune('a'+i%26))}},
			},
			"assignments": []any{map[string]any{"subject": map[string]any{"type": "USER", "username": "u"}, "roleAdmin": true}},
		})
	}
	tree, err := normalize(map[string]any{"v": 2, "big": int64(1) << 62, "neg": -5, "f": 1.5, "n": nil, "resources": map[string]any{"roles": rs}})
	if err != nil {
		t.Fatal(err)
	}
	return unNumber(tree).(map[string]any)
}

func TestBinRoundTrip(t *testing.T) {
	in := sampleTree(t, 50)
	enc, err := encodeBin(mustNum(t, in))
	if err != nil {
		t.Fatal(err)
	}
	enc2, _ := encodeBin(mustNum(t, in))
	if !bytes.Equal(enc, enc2) {
		t.Fatal("encoding is not deterministic")
	}
	out, err := decodeBin(enc)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(in)
	b, _ := json.Marshal(out)
	if !bytes.Equal(a, b) {
		t.Fatalf("round trip mismatch\n%s\n%s", a, b)
	}
}

func mustNum(t testing.TB, v any) any {
	t.Helper()
	n, err := normalize(v)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBinRejectsCorruption(t *testing.T) {
	enc, _ := encodeBin(mustNum(t, sampleTree(t, 5)))
	for i := 0; i < len(enc); i++ { // every truncation must error, never panic
		if _, err := decodeBin(enc[:i]); err == nil {
			t.Fatalf("truncation at %d accepted", i)
		}
	}
	for _, pos := range []int{0, 5, 10, len(enc) / 2, len(enc) - 40} { // bit flips
		c := append([]byte{}, enc...)
		c[pos] ^= 0x40
		if _, err := decodeBin(c); err == nil {
			t.Fatalf("bit flip at %d accepted", pos)
		}
	}
	// Valid checksum over hostile content (huge counts) must still fail safely.
	bad := append([]byte("BIAC\x01\x00"), 0xff, 0xff, 0xff, 0xff, 0x0f, 0x00)
	sum := sha256.Sum256(bad)
	if _, err := decodeBin(append(bad, sum[:]...)); err == nil {
		t.Fatal("hostile counts accepted")
	}
}

func TestLoadArtifactAllFormats(t *testing.T) {
	in := sampleTree(t, 10)
	dir := t.TempDir()
	want, _ := json.Marshal(in)
	for _, name := range []string{"a.biac", "a.json", "a.json.gz"} {
		p := dir + "/" + name
		if err := writeArtifact(p, mustNum(t, in)); err != nil {
			t.Fatal(err)
		}
		got, err := loadArtifact(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		g, _ := json.Marshal(got)
		if !bytes.Equal(g, want) {
			t.Fatalf("%s mismatch", name)
		}
	}
}

func BenchmarkLoad(b *testing.B) {
	in := mustNum(b, sampleTree(b, 5000))
	bin, _ := encodeBin(in)
	js, _ := json.Marshal(in)
	b.Logf("sizes: json=%d bin=%d", len(js), len(bin))
	b.Run("json", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var v any
			json.Unmarshal(js, &v)
		}
	})
	b.Run("bin", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			decodeBin(bin)
		}
	})
}

func TestRoleHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Trino-Role")
		w.Write([]byte(`{"result":[]}`))
	}))
	defer srv.Close()
	c, err := newClient(clientConfig{BaseURL: srv.URL, User: "u", Pass: "p", AllowHTTP: true, Role: "sysadmin"})
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := c.get(context.Background(), "/x", nil, &out); err != nil {
		t.Fatal(err)
	}
	if got != "system=ROLE{sysadmin}" {
		t.Fatalf("header = %q", got)
	}
	if _, err := newClient(clientConfig{BaseURL: srv.URL, User: "u", Pass: "p", AllowHTTP: true, Role: "a}\r\nX: y"}); err == nil {
		t.Fatal("hostile role accepted")
	}
}
