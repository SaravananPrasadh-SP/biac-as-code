package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeSEP is a tiny stateful in-memory BIAC API (reads + writes) for round-trip tests.
type fakeSEP struct {
	mu      sync.Mutex
	next    int
	exprs   map[string][]map[string]any // "columnMask"|"rowFilter"
	roles   []map[string]any
	child   map[string]map[string][]map[string]any // roleId -> kind -> items
	assign  []map[string]any                       // {id, roleId, st, sk, roleAdmin}
	writes  int                                    // every non-GET attempt
	changes int                                    // only requests that changed state
}

func newFake() *fakeSEP {
	return &fakeSEP{next: 100, exprs: map[string][]map[string]any{}, child: map[string]map[string][]map[string]any{}}
}

func (f *fakeSEP) id() int { f.next++; return f.next }

var reRole = regexp.MustCompile(`^/api/v1/biac/roles/(\d+)(?:/(grants|locationGrants|columnMasks|rowFilters|assignments)(?:/(\d+))?)?$`)
var reExpr = regexp.MustCompile(`^/api/v1/biac/expressions/(columnMask|rowFilter)(?:/(\d+))?$`)
var reSubj = regexp.MustCompile(`^/api/v1/biac/subjects/(users|groups|roles)/([^/]+)/assignments(?:/(\d+))?$`)

func (f *fakeSEP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]any
	if r.Body != nil && r.Method != "GET" && r.Method != "DELETE" {
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		dec.Decode(&body)
	}
	if r.Method != "GET" {
		f.writes++
	}
	reply := func(v any) { json.NewEncoder(w).Encode(v) }
	page := func(v []map[string]any) {
		if v == nil {
			v = []map[string]any{}
		}
		reply(map[string]any{"result": v})
	}
	p := r.URL.Path
	switch {
	case p == "/api/v1/biac/roles":
		if r.Method == "GET" {
			page(f.roles)
			return
		}
		for _, ro := range f.roles {
			if ro["name"] == body["name"] {
				http.Error(w, `{"message":"role already exists"}`, 409)
				return
			}
		}
		f.changes++
		role := map[string]any{"id": f.id(), "name": body["name"]}
		if d, ok := body["description"]; ok {
			role["description"] = d
		}
		f.roles = append(f.roles, role)
		f.child[fmt.Sprint(role["id"])] = map[string][]map[string]any{}
		reply(role)
	case reExpr.MatchString(p):
		m := reExpr.FindStringSubmatch(p)
		k := m[1]
		switch {
		case r.Method == "GET":
			page(f.exprs[k])
		case r.Method == "POST":
			for _, e := range f.exprs[k] {
				if e["name"] == body["name"] {
					http.Error(w, `{"message":"expression already exists"}`, 409)
					return
				}
			}
			f.changes++
			e := map[string]any{"id": f.id()}
			for a, b := range body {
				e[a] = b
			}
			f.exprs[k] = append(f.exprs[k], e)
			reply(e)
		case r.Method == "PUT":
			for _, e := range f.exprs[k] {
				if fmt.Sprint(e["id"]) == m[2] {
					f.changes++
					for a, b := range body {
						e[a] = b
					}
					reply(e)
					return
				}
			}
			http.NotFound(w, r)
		}
	case reRole.MatchString(p):
		m := reRole.FindStringSubmatch(p)
		rid, kind, cid := m[1], m[2], m[3]
		if kind == "" && r.Method == "PUT" {
			for _, ro := range f.roles {
				if fmt.Sprint(ro["id"]) == rid {
					f.changes++
					for a, b := range body {
						ro[a] = b
					}
					reply(ro)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		if kind == "locationGrants" {
			http.NotFound(w, r) // this fake cluster does not support them
			return
		}
		if kind == "assignments" {
			var out []map[string]any
			for _, a := range f.assign {
				if fmt.Sprint(a["roleId"]) == rid {
					sub := map[string]any{"type": a["st"]}
					switch a["st"] {
					case "USER":
						sub["username"] = a["sk"]
					case "GROUP":
						sub["groupName"] = a["sk"]
					case "ROLE":
						n, _ := strconv.Atoi(fmt.Sprint(a["sk"]))
						sub["roleId"] = json.Number(strconv.Itoa(n))
					}
					it := map[string]any{"id": a["id"], "subject": sub}
					if a["roleAdmin"] == true {
						it["roleAdmin"] = true
					}
					out = append(out, it)
				}
			}
			page(out)
			return
		}
		items := f.child[rid][kind]
		switch r.Method {
		case "GET":
			page(items)
		case "POST":
			f.changes++
			it := map[string]any{"id": f.id()}
			for a, b := range body {
				it[a] = b
			}
			f.child[rid][kind] = append(items, it)
			reply(it)
		case "DELETE":
			f.changes++
			var keep []map[string]any
			for _, it := range items {
				if fmt.Sprint(it["id"]) != cid {
					keep = append(keep, it)
				}
			}
			f.child[rid][kind] = keep
			w.WriteHeader(204)
		}
	case reSubj.MatchString(p):
		m := reSubj.FindStringSubmatch(p)
		st := map[string]string{"users": "USER", "groups": "GROUP", "roles": "ROLE"}[m[1]]
		f.changes++
		if r.Method == "POST" {
			a := map[string]any{"id": f.id(), "roleId": fmt.Sprint(body["roleId"]), "st": st, "sk": m[2]}
			if body["roleAdmin"] == true {
				a["roleAdmin"] = true
			}
			f.assign = append(f.assign, a)
			reply(map[string]any{"id": a["id"]})
		} else {
			var keep []map[string]any
			for _, a := range f.assign {
				if fmt.Sprint(a["id"]) != m[3] {
					keep = append(keep, a)
				}
			}
			f.assign = keep
			w.WriteHeader(204)
		}
	default:
		http.NotFound(w, r)
	}
}

// exportOf runs the real export engine against the fake and returns the artifact resources.
func exportOf(t *testing.T, f *fakeSEP) map[string]any {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, p, _ := loadSpecPlan("", "")
	c, _ := newClient(clientConfig{BaseURL: srv.URL, User: "u", Pass: "p", AllowHTTP: true})
	_, skip, _ := p.validate(s)
	res, _, err := newEngine(c, s, p, skip, 4, nil).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tree, _ := normalize(map[string]any{"resources": res})
	return unNumber(tree).(map[string]any)["resources"].(map[string]any)
}

// doImport runs a REAL import (writes) against the fake.
func doImport(t *testing.T, f *fakeSEP, res map[string]any, overwrite bool) *importer {
	t.Helper()
	return runTestImport(t, f, res, importOpts{Overwrite: overwrite, Conc: 4}, nil)
}

// doDry runs a snapshot-based dry-run/compare; the snapshot is a full export of the fake taken now.
func doDry(t *testing.T, f *fakeSEP, res map[string]any, overwrite, compare bool) *importer {
	t.Helper()
	return runTestImport(t, f, res, importOpts{Overwrite: overwrite, Dry: true, Compare: compare, Conc: 4}, exportOf(t, f))
}

func runTestImport(t *testing.T, f *fakeSEP, res map[string]any, o importOpts, snap map[string]any) *importer {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, p, _ := loadSpecPlan("", "")
	c, _ := newClient(clientConfig{BaseURL: srv.URL, User: "u", Pass: "p", AllowHTTP: true})
	m := newImporter(c, s, p, "fake", o, snap)
	if err := importArtifact(context.Background(), m, res, nil); err != nil {
		t.Fatalf("import: %v\nfails=%v", err, m.fails)
	}
	return m
}

func artifactFixture(t *testing.T) map[string]any {
	js := `{"columnMaskExpressions":[{"name":"mask_ssn","expression":"'***'"}],
	"rowFilterExpressions":[{"name":"us_only","expression":"country='US'","description":"d"}],
	"roles":[
	 {"name":"admin"},
	 {"name":"analyst","description":"read only","grants":[
	   {"effect":"ALLOW","action":"SELECT","entity":{"category":"TABLES","catalog":"hive","schema":"s","table":"t"}},
	   {"effect":"DENY","action":"DROP","entity":{"category":"TABLES","catalog":"hive"}},
	   {"effect":"APPLY_COLUMN_MASK","action":"SELECT","columnMaskExpression":"mask_ssn","entity":{"category":"TABLES","table":"t","columns":["ssn"]}}],
	  "columnMasks":[{"entity":{"category":"TABLES","table":"t","columns":["ssn"]},"expression":"mask_ssn"}],
	  "rowFilters":[{"entity":{"category":"TABLES","table":"t"},"expression":"us_only"}],
	  "assignments":[{"subject":{"type":"USER","username":"bob"},"roleAdmin":true},
	                 {"subject":{"type":"GROUP","groupName":"eng"}},
	                 {"subject":{"type":"ROLE","role":"admin"}}]}]}`
	var v any
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

// canonical, order-independent view for comparing two resource trees
func canonTree(v any) string {
	switch x := v.(type) {
	case []any:
		var parts []string
		for _, e := range x {
			parts = append(parts, canonTree(e))
		}
		sort.Strings(parts)
		return "[" + strings.Join(parts, ",") + "]"
	case []item:
		a := make([]any, len(x))
		for i := range x {
			a[i] = x[i]
		}
		return canonTree(a)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var parts []string
		for _, k := range keys {
			parts = append(parts, k+":"+canonTree(x[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func TestImportRoundTrip(t *testing.T) {
	art := artifactFixture(t)
	f := newFake()
	m := doImport(t, f, art, false)
	if m.counts["created roles"] != 2 || m.counts["created grants"] != 3 || m.counts["created assignments"] != 3 {
		t.Fatalf("counts: %v", m.counts)
	}
	got := exportOf(t, f)
	if canonTree(got) != canonTree(art) {
		t.Fatalf("round trip differs:\n got  %s\n want %s", canonTree(got), canonTree(art))
	}
}

func changedArtifact(t *testing.T) map[string]any {
	art2 := artifactFixture(t)
	an := art2["roles"].([]any)[1].(map[string]any)
	an["description"] = "updated"
	g := an["grants"].([]any)
	an["grants"] = []any{g[0], g[2], map[string]any{"effect": "ALLOW", "action": "INSERT",
		"entity": map[string]any{"category": "TABLES", "catalog": "hive", "schema": "s"}}}
	an["assignments"] = []any{map[string]any{"subject": map[string]any{"type": "USER", "username": "bob"}, "roleAdmin": true}}
	art2["columnMaskExpressions"].([]any)[0].(map[string]any)["expression"] = "'XXX'"
	return art2
}

func TestImportSkipsExistingThenOverwrites(t *testing.T) {
	art := artifactFixture(t)
	f := newFake()
	doImport(t, f, art, false)
	art2 := changedArtifact(t)

	// Default: create attempts fail with 409 -> skipped; the target does not change.
	before := f.changes
	m := doImport(t, f, art2, false)
	if f.changes != before || m.counts["skipped roles (exist)"] != 2 {
		t.Fatalf("skip mode changed %d things; counts %v", f.changes-before, m.counts)
	}
	if m.counts["skipped columnMaskExpressions (DIFFERS from artifact)"] != 1 {
		t.Fatalf("a differing existing expression must be reported: %v", m.counts)
	}
	if canonTree(exportOf(t, f)) != canonTree(art) {
		t.Fatal("skip mode changed the target")
	}

	// Overwrite: syncs in place; same role ids (no delete/re-create).
	idsBefore := fmt.Sprint(f.roles)
	doImport(t, f, art2, true)
	if canonTree(exportOf(t, f)) != canonTree(art2) {
		t.Fatalf("overwrite did not converge:\n got  %s\n want %s", canonTree(exportOf(t, f)), canonTree(art2))
	}
	if !strings.Contains(fmt.Sprint(f.roles), "updated") || len(f.roles) != 2 {
		t.Fatalf("roles must be updated in place: %v (was %s)", f.roles, idsBefore)
	}
	for i, r := range f.roles {
		if fmt.Sprint(r["id"]) == "" || r["id"] == nil {
			t.Fatalf("role %d lost id", i)
		}
	}
	// Idempotent: a second overwrite changes nothing.
	before = f.changes
	doImport(t, f, art2, true)
	if f.changes != before {
		t.Fatalf("second overwrite changed %d things", f.changes-before)
	}
}

func TestDryRunAndCompareUseSnapshotOnly(t *testing.T) {
	art := artifactFixture(t)
	f := newFake()
	doImport(t, f, art, false)
	art2 := changedArtifact(t)

	before, attempts := f.changes, f.writes
	m := doDry(t, f, art2, true, false)
	if f.changes != before || f.writes != attempts {
		t.Fatal("dry-run sent writes")
	}
	if m.counts["deleted grants"] != 1 || m.counts["created grants"] != 1 || m.counts["deleted assignments"] != 2 {
		t.Fatalf("dry-run counts: %v", m.counts)
	}

	m = doDry(t, f, art2, false, true) // compare, skip mode
	if m.counts["skipped roles (DIFFERS from artifact)"] != 1 || m.counts["skipped roles (identical)"] != 1 {
		t.Fatalf("compare counts: %v warns=%v", m.counts, m.warns)
	}
	if f.changes != before || f.writes != attempts {
		t.Fatal("compare sent writes")
	}

	// Brand-new target: everything would be created.
	m = doDry(t, newFake(), art, false, false)
	if m.counts["created roles"] != 2 {
		t.Fatalf("empty-target dry-run: %v", m.counts)
	}
}

func TestImportDenyGrantsFirst(t *testing.T) {
	art := artifactFixture(t)
	f := newFake()
	doImport(t, f, art, false)
	var rid string
	for _, r := range f.roles {
		if r["name"] == "analyst" { // roles are created in parallel: do not rely on slice order
			rid = fmt.Sprint(r["id"])
		}
	}
	grants := f.child[rid]["grants"]
	if len(grants) == 0 || fmt.Sprint(grants[0]["effect"]) != "DENY" {
		t.Fatalf("DENY grant must be created first, got %v", grants)
	}
}

func TestRealFailureIsReportedNotSkipped(t *testing.T) {
	// A role whose create fails for a reason other than "exists" must be a FAILURE.
	f := newFake()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api/v1/biac/roles" {
			http.Error(w, `{"message":"denied"}`, 403)
			return
		}
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	s, p, _ := loadSpecPlan("", "")
	c, _ := newClient(clientConfig{BaseURL: srv.URL, User: "u", Pass: "p", AllowHTTP: true})
	m := newImporter(c, s, p, "fake", importOpts{Conc: 2}, nil)
	err := importArtifact(context.Background(), m, artifactFixture(t), nil)
	if err == nil || len(m.fails) != 2 {
		t.Fatalf("expected 2 failures, got err=%v fails=%v counts=%v", err, m.fails, m.counts)
	}
}

func TestSnapshotLifecycleViaCommand(t *testing.T) {
	f := newFake()
	var reqs int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs++
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	t.Setenv("STARBURST_USER", "u")
	t.Setenv("STARBURST_PASSWORD", "p")
	t.Setenv("STARBURST_URL", "")
	tree, _ := normalize(map[string]any{"v": formatVersion, "resources": artifactFixture(t)})
	if err := writeArtifact("art.biac", tree); err != nil {
		t.Fatal(err)
	}
	snapName := "target-" + unsafeName.ReplaceAllString(strings.TrimPrefix(srv.URL, "http://"), "_") + ".snapshot.biac"
	base := []string{"--url", srv.URL, "--allow-http", "--in", "art.biac", "--yes"}

	// 1) first compare reads the cluster once and writes the snapshot (0600).
	if err := runImport(append([]string{"--compare"}, base...)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(snapName)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot missing or wrong mode: %v %v", err, fi)
	}
	// 2) later compares are fully offline: no credentials, no requests.
	t.Setenv("STARBURST_USER", "")
	t.Setenv("STARBURST_PASSWORD", "")
	before := reqs
	if err := runImport(append([]string{"--compare"}, base...)); err != nil {
		t.Fatal(err)
	}
	if reqs != before {
		t.Fatalf("offline compare made %d requests", reqs-before)
	}
	// 3) a real run that writes removes the now-stale snapshot.
	t.Setenv("STARBURST_USER", "u")
	t.Setenv("STARBURST_PASSWORD", "p")
	if err := runImport(base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snapName); !os.IsNotExist(err) {
		t.Fatal("stale snapshot was not removed after writes")
	}
	if len(f.roles) != 2 {
		t.Fatalf("real run did not import: %v", f.roles)
	}
}

func TestLiveCompareReadsClusterAndWritesNoSnapshot(t *testing.T) {
	f := newFake()
	var reqs int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reqs++; f.ServeHTTP(w, r) }))
	defer srv.Close()
	t.Chdir(t.TempDir())
	t.Setenv("STARBURST_USER", "u")
	t.Setenv("STARBURST_PASSWORD", "p")
	t.Setenv("STARBURST_URL", "")
	tree, _ := normalize(map[string]any{"v": formatVersion, "resources": artifactFixture(t)})
	writeArtifact("art.biac", tree)
	args := []string{"--live", "--url", srv.URL, "--allow-http", "--in", "art.biac"}
	for i := 0; i < 2; i++ { // every run goes to the cluster
		before := reqs
		if err := runImport(args); err != nil {
			t.Fatal(err)
		}
		if reqs == before {
			t.Fatalf("run %d: --live made no requests", i)
		}
	}
	if m, _ := filepath.Glob("*.snapshot.biac"); len(m) != 0 {
		t.Fatalf("--live must not write a snapshot: %v", m)
	}
	if len(f.roles) != 0 || f.changes != 0 {
		t.Fatal("--live must not write")
	}
	if err := runImport(append(args, "--refresh-snapshot")); err == nil {
		t.Fatal("--live with --refresh-snapshot must be rejected")
	}
}
