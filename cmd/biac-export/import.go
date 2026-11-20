package main

// import: CREATE-or-SKIP by default; --overwrite syncs existing roles in place.
//
// Real run:   try to create; if that fails, ONE cached lookup decides "already exists"
//             (skip, or sync in place with --overwrite) versus a genuine failure (reported).
//             No up-front reads, no deletes of roles/expressions.
// Dry-run /   never write. Existence and differences come from a SNAPSHOT file (a full
// --compare: export of the target) in the run directory; it is read live once, then reused
//             offline until deleted or --refresh-snapshot. A real run that writes removes it
//             (it is stale then).
//
// Safety: creates run before deletes and DENY grants first, so an interrupted run is never
// more permissive than either state; confirmation required unless --yes.

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Operations the importer needs (resolved by operationId, verified against the spec).
var importOps = map[string]string{
	"createRole": "POST", "updateRole": "PUT",
	"createColumnMaskExpression": "POST", "updateColumnMaskExpression": "PUT",
	"createRowFilterExpression": "POST", "updateRowFilterExpression": "PUT",
	"createGrant": "POST", "deleteGrant": "DELETE",
	"addLocationGrant": "POST", "deleteLocationGrant": "DELETE",
	"addColumnMaskToRole": "POST", "deleteRoleColumnMask": "DELETE",
	"addRowFilterToRole": "POST", "deleteRoleRowFilter": "DELETE",
	"createRoleAssignmentForUser": "POST", "deleteRoleAssignmentFromUser": "DELETE",
	"createRoleAssignmentForGroup": "POST", "deleteRoleAssignmentFromGroup": "DELETE",
	"createRoleAssignmentForRole": "POST", "deleteRoleAssignmentFromRole": "DELETE",
}

// child resources handled by the importer (assignments are a later phase).
var knownChildren = []string{"grants", "locationGrants", "columnMasks", "rowFilters"}

var (
	createOp    = map[string]string{"grants": "createGrant", "locationGrants": "addLocationGrant", "columnMasks": "addColumnMaskToRole", "rowFilters": "addRowFilterToRole"}
	deleteOp    = map[string]string{"grants": "deleteGrant", "locationGrants": "deleteLocationGrant", "columnMasks": "deleteRoleColumnMask", "rowFilters": "deleteRoleRowFilter"}
	deleteParam = map[string]string{"grants": "grantId", "locationGrants": "locationGrantId", "columnMasks": "columnMaskId", "rowFilters": "rowFilterId"}
	exprKinds   = [2]string{"columnMaskExpressions", "rowFilterExpressions"}
)

type importOpts struct {
	Overwrite, Dry, Compare bool
	Conc                    int
}

type roleState struct {
	id      string
	created bool
	existed bool
	cur     map[string]any // target's current state (export shape), when known
}

// liveState is the lazily loaded view of the target, filled on the first conflict only.
type liveState struct {
	once     sync.Once
	err      error
	eng      *Engine
	rolesRes *Resource
	roleRaw  map[string]item
	exprRaw  [2]map[string]item
}

type importer struct {
	c         *Client
	spec      *Spec
	plan      *Plan
	host      string
	o         importOpts
	res       map[string]any // artifact resources
	snap      map[string]any // snapshot resources (dry-run/compare)
	snapRoles map[string]map[string]any
	mu        sync.Mutex
	counts    map[string]int
	warns     []string
	fails     []string
	warned    sync.Map
	fakeID    atomic.Int64
	wrote     atomic.Int64
	exprID    [2]map[string]string // name -> target id
	roleID    map[string]string
	state     map[string]*roleState
	live      liveState
}

func newImporter(c *Client, s *Spec, p *Plan, host string, o importOpts, snap map[string]any) *importer {
	m := &importer{c: c, spec: s, plan: p, host: host, o: o, snap: snap,
		counts: map[string]int{}, roleID: map[string]string{}, state: map[string]*roleState{},
		snapRoles: map[string]map[string]any{}, exprID: [2]map[string]string{{}, {}}}
	if o.Conc < 1 {
		m.o.Conc = 1
	}
	if o.Dry {
		for _, r := range toListAny(snap["roles"]) {
			n := fmt.Sprint(r["name"])
			m.snapRoles[n] = r
			m.roleID[n] = "snap"
		}
		for i, k := range exprKinds {
			for _, e := range toListAny(snap[k]) {
				m.exprID[i][fmt.Sprint(e["name"])] = "snap"
			}
		}
	}
	return m
}

func (m *importer) count(k string) { m.mu.Lock(); m.counts[k]++; m.mu.Unlock() }
func (m *importer) warn(key, msg string) {
	if _, dup := m.warned.LoadOrStore(key, true); !dup {
		m.mu.Lock()
		m.warns = append(m.warns, msg)
		m.mu.Unlock()
	}
}
func (m *importer) fail(format string, a ...any) {
	m.mu.Lock()
	m.fails = append(m.fails, fmt.Sprintf(format, a...))
	m.mu.Unlock()
}

// call executes one write op (or fakes it in dry-run). Returns the created id, if any.
func (m *importer) call(ctx context.Context, opID string, pathVals map[string]string, body any) (string, error) {
	op := m.spec.Ops[opID]
	path := op.Path
	for k, v := range pathVals {
		path = strings.ReplaceAll(path, "{"+k+"}", url.PathEscape(v))
	}
	if m.o.Dry {
		return fmt.Sprintf("dry-%d", m.fakeID.Add(1)), nil
	}
	var out map[string]any
	if err := m.c.send(ctx, op.Method, path, body, &out); err != nil {
		return "", err
	}
	m.wrote.Add(1)
	if v, ok := out["id"]; ok && v != nil {
		return fmt.Sprint(v), nil
	}
	return "", nil
}

// loadLive reads the target's top-level lists once (ids kept). Triggered by the first create conflict.
func (m *importer) loadLive(ctx context.Context) error {
	m.live.once.Do(func() {
		keep := *m.plan
		keep.Resources = append([]Resource(nil), m.plan.Resources...)
		for i := range keep.Resources {
			keep.Resources[i].Drop = nil // keep ids for updates/deletes
			if keep.Resources[i].Name == "roles" {
				m.live.rolesRes = &keep.Resources[i]
			}
		}
		if m.live.rolesRes == nil {
			m.live.err = fmt.Errorf("plan has no \"roles\" resource")
			return
		}
		_, skip, err := keep.validate(m.spec)
		if err != nil {
			m.live.err = err
			return
		}
		e := newEngine(m.c, m.spec, &keep, skip, m.o.Conc, nil)
		raws, _, err := e.loadTop(ctx)
		if err != nil {
			m.live.err = err
			return
		}
		m.live.eng = e
		m.live.roleRaw = map[string]item{}
		m.live.exprRaw = [2]map[string]item{{}, {}}
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, r := range raws["roles"] {
			n := fmt.Sprint(r["name"])
			m.live.roleRaw[n] = r
			if _, ok := m.roleID[n]; !ok {
				m.roleID[n] = fmt.Sprint(r["id"])
			}
		}
		for i, k := range exprKinds {
			for _, x := range raws[k] {
				n := fmt.Sprint(x["name"])
				m.live.exprRaw[i][n] = x
				if _, ok := m.exprID[i][n]; !ok {
					m.exprID[i][n] = fmt.Sprint(x["id"])
				}
			}
		}
	})
	return m.live.err
}

func (m *importer) roleIDOf(ctx context.Context, name string) (string, bool) {
	m.mu.Lock()
	id, ok := m.roleID[name]
	m.mu.Unlock()
	if ok || m.o.Dry {
		return id, ok
	}
	if m.loadLive(ctx) != nil {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok = m.roleID[name]
	return id, ok
}

func toList(v any) []map[string]any {
	var out []map[string]any
	if a, ok := v.([]any); ok {
		for _, x := range a {
			if mm, ok := x.(map[string]any); ok {
				out = append(out, mm)
			}
		}
	}
	return out
}

func toListAny(v any) []map[string]any {
	switch x := v.(type) {
	case []item:
		return x
	case []any:
		return toList(x)
	}
	return nil
}

func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func canon(it map[string]any) string {
	c := map[string]any{}
	for k, v := range it {
		if k != "id" {
			c[k] = v
		}
	}
	b, _ := json.Marshal(c)
	return string(b)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func isStatus(err error, code int) bool {
	he, ok := err.(*httpError)
	return ok && he.Status == code
}

// importArtifact is the testable core. res is the artifact's "resources" map.
func importArtifact(ctx context.Context, m *importer, res map[string]any, ask func(string) bool) error {
	m.res = res
	roles := toList(res["roles"])
	mode := "create-or-skip"
	if m.o.Overwrite {
		mode = "create-or-OVERWRITE (existing roles are synced in place; extra grants/masks/filters/assignments on them are removed)"
	}
	if m.o.Dry {
		mode = "DRY-RUN against snapshot, " + mode
		if m.o.Compare {
			mode += ", compare"
		}
	}
	fmt.Fprintf(os.Stderr, "target: %s | mode: %s | roles in artifact: %d\n", m.host, mode, len(roles))
	if !m.o.Dry && ask != nil && !ask("Proceed with writes to this cluster? [y/N] ") {
		return fmt.Errorf("aborted (no confirmation)")
	}
	m.expressions(ctx)
	m.rolesPhase(ctx, roles)
	m.assignmentsPhase(ctx, roles)
	for k := range res {
		if k != "roles" && k != "columnMaskExpressions" && k != "rowFilterExpressions" {
			m.warn("top-"+k, fmt.Sprintf("top-level resource %q in artifact is not supported by import; ignored", k))
		}
	}
	return m.report()
}

// ---- phase A: expressions ----

func (m *importer) expressions(ctx context.Context) {
	type kind struct {
		key, create, update, idParam string
		idx                          int
	}
	for _, k := range []kind{
		{"columnMaskExpressions", "createColumnMaskExpression", "updateColumnMaskExpression", "columnMaskExpressionId", 0},
		{"rowFilterExpressions", "createRowFilterExpression", "updateRowFilterExpression", "rowFilterExpressionId", 1},
	} {
		for _, e := range toList(m.res[k.key]) {
			name := fmt.Sprint(e["name"])
			body := map[string]any{"name": name, "expression": e["expression"]}
			if d, ok := e["description"]; ok {
				body["description"] = d
			}
			var cur map[string]any
			if m.o.Dry {
				for _, x := range toListAny(m.snap[k.key]) {
					if fmt.Sprint(x["name"]) == name {
						cur = x
					}
				}
				if cur == nil {
					id, _ := m.call(ctx, k.create, nil, body)
					m.mu.Lock()
					m.exprID[k.idx][name] = id
					m.mu.Unlock()
					m.count("created " + k.key)
					continue
				}
			} else {
				id, err := m.call(ctx, k.create, nil, body)
				if err == nil {
					m.mu.Lock()
					m.exprID[k.idx][name] = id
					m.mu.Unlock()
					m.count("created " + k.key)
					continue
				}
				if lerr := m.loadLive(ctx); lerr != nil {
					m.fail("expression %s/%s: create failed (%v); lookup failed (%v)", k.key, name, err, lerr)
					continue
				}
				raw, ok := m.live.exprRaw[k.idx][name]
				if !ok { // not visible either: a genuine failure (or the account cannot see it)
					m.fail("expression %s/%s: %v", k.key, name, err)
					continue
				}
				cur = raw
			}
			same := sameJSON(body, pick(cur, "name", "expression", "description"))
			switch {
			case !m.o.Overwrite && same:
				m.count("skipped " + k.key + " (identical)")
			case !m.o.Overwrite:
				m.count("skipped " + k.key + " (DIFFERS from artifact)")
				m.warn("diff-"+k.key+name, fmt.Sprintf("%s %q exists on target with different content; left unchanged (use --overwrite to update)", k.key, name))
			case same:
				m.count("unchanged " + k.key)
			default:
				m.mu.Lock()
				id := m.exprID[k.idx][name]
				m.mu.Unlock()
				if _, err := m.call(ctx, k.update, map[string]string{k.idParam: id}, body); err != nil {
					m.fail("expression %s/%s: %v", k.key, name, err)
					continue
				}
				m.count("updated " + k.key)
			}
		}
	}
}

// ---- phase B: roles and their grants/masks/filters ----

func (m *importer) rolesPhase(ctx context.Context, roles []map[string]any) {
	sem := make(chan struct{}, m.o.Conc)
	var wg sync.WaitGroup
	for _, r := range roles {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			name := fmt.Sprint(r["name"])
			if err := m.oneRole(ctx, name, r); err != nil {
				m.fail("role %s: %v", name, err)
			}
		}()
	}
	wg.Wait()
}

func (m *importer) oneRole(ctx context.Context, name string, r map[string]any) error {
	body := map[string]any{"name": name}
	if d, ok := r["description"]; ok {
		body["description"] = d
	}
	var id string
	var cur map[string]any
	exists := false
	if m.o.Dry {
		cur, exists = m.snapRoles[name]
		if exists {
			id = "snap"
		}
	} else {
		cid, err := m.call(ctx, "createRole", nil, body)
		if err == nil {
			id = cid
		} else {
			if lerr := m.loadLive(ctx); lerr != nil {
				return fmt.Errorf("create failed (%v); lookup failed (%v)", err, lerr)
			}
			raw, ok := m.live.roleRaw[name]
			if !ok {
				return err // not an "already exists": a real failure
			}
			exists, id = true, fmt.Sprint(raw["id"])
			if m.o.Overwrite {
				if cur, err = m.live.eng.build(ctx, m.live.rolesRes, raw); err != nil {
					return err
				}
			}
		}
	}
	st := &roleState{id: id, existed: exists, cur: cur}
	switch {
	case !exists:
		if m.o.Dry {
			id, _ = m.call(ctx, "createRole", nil, body)
			st.id = id
		}
		st.created = true
		m.mu.Lock()
		m.roleID[name] = st.id
		m.mu.Unlock()
		m.count("created roles")
	case !m.o.Overwrite:
		m.mu.Lock()
		m.state[name] = st
		m.mu.Unlock()
		switch {
		case m.o.Compare && cur != nil:
			if d := diffRole(r, cur); len(d) == 0 {
				m.count("skipped roles (identical)")
			} else {
				m.count("skipped roles (DIFFERS from artifact)")
				m.warn("rdiff-"+name, fmt.Sprintf("role %q exists and differs: %s; left unchanged (use --overwrite to sync)", name, strings.Join(d, "; ")))
			}
		default:
			m.count("skipped roles (exist)")
		}
		return nil
	default: // exists && overwrite
		if cur == nil {
			return fmt.Errorf("role exists on target but its current state could not be read")
		}
		if !sameJSON(pick(r, "name", "description"), pick(cur, "name", "description")) {
			if _, err := m.call(ctx, "updateRole", map[string]string{"roleId": id}, body); err != nil {
				return err
			}
			m.count("updated roles")
		} else {
			m.count("unchanged roles")
		}
	}
	m.mu.Lock()
	m.state[name] = st
	m.mu.Unlock()

	ids := map[string]string{"roleId": st.id}
	var deletes []func() error
	for _, kind := range knownChildren {
		want := toList(r[kind])
		if kind == "grants" { // DENY first: never a window with fewer denies
			sort.SliceStable(want, func(i, j int) bool {
				return fmt.Sprint(want[i]["effect"]) == "DENY" && fmt.Sprint(want[j]["effect"]) != "DENY"
			})
		}
		have := map[string]map[string]any{} // canonical key -> target item
		if st.cur != nil {
			for _, it := range toListAny(st.cur[kind]) {
				have[canon(it)] = it
			}
		}
		for _, w := range want {
			k := canon(w)
			if _, ok := have[k]; ok {
				delete(have, k)
				m.count("unchanged " + kind)
				continue
			}
			b, err := m.childBody(kind, w)
			if err != nil {
				return err
			}
			if _, err := m.call(ctx, createOp[kind], ids, b); err != nil {
				if kind == "locationGrants" && isStatus(err, 404) {
					m.warn("loc", "target does not support locationGrants; skipped")
					break
				}
				return fmt.Errorf("%s: %w", kind, err)
			}
			m.count("created " + kind)
		}
		for _, it := range have { // leftovers exist on target but not in artifact
			kind := kind
			deletes = append(deletes, func() error {
				pv := map[string]string{"roleId": st.id, deleteParam[kind]: fmt.Sprint(it["id"])}
				if _, err := m.call(ctx, deleteOp[kind], pv, nil); err != nil {
					return fmt.Errorf("delete %s: %w", kind, err)
				}
				m.count("deleted " + kind)
				return nil
			})
		}
	}
	for _, d := range deletes { // only after every create succeeded
		if err := d(); err != nil {
			return err
		}
	}
	for k := range r {
		if k != "name" && k != "description" && k != "assignments" && !contains(knownChildren, k) {
			m.warn("child-"+k, fmt.Sprintf("role field %q is not supported by import; ignored", k))
		}
	}
	return nil
}

// childBody turns an artifact item (names) into an API payload (target ids).
func (m *importer) childBody(kind string, w map[string]any) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	lookup := func(i int, name any) (string, error) {
		id, ok := m.exprID[i][fmt.Sprint(name)]
		if !ok {
			return "", fmt.Errorf("%s: expression %q not found on target", kind, name)
		}
		return id, nil
	}
	num := func(id string) any {
		if m.o.Dry {
			return id
		}
		return json.Number(id)
	}
	switch kind {
	case "grants":
		b := pick(w, "effect", "action", "entity")
		if n, ok := w["columnMaskExpression"]; ok {
			id, err := lookup(0, n)
			if err != nil {
				return nil, err
			}
			b["columnMaskExpressionId"] = num(id)
		}
		if n, ok := w["rowFilterExpression"]; ok {
			id, err := lookup(1, n)
			if err != nil {
				return nil, err
			}
			b["rowFilterExpressionId"] = num(id)
		}
		if ent, ok := w["entity"].(map[string]any); ok {
			if c := fmt.Sprint(ent["category"]); c == "ROLES" || c == "USERS" {
				m.warn("ent-"+c, fmt.Sprintf("grants on %s entities are imported verbatim; if their entityKey is an id it may not match the target", c))
			}
		}
		return b, nil
	case "locationGrants":
		return pick(w, "location", "grantOption"), nil
	case "columnMasks", "rowFilters":
		i := 0
		if kind == "rowFilters" {
			i = 1
		}
		id, err := lookup(i, w["expression"])
		if err != nil {
			return nil, err
		}
		if f, _ := w["forceNone"].(bool); f {
			m.warn("force-"+kind, fmt.Sprintf("%s with forceNone=true: the API payload cannot carry forceNone; imported without it", kind))
		}
		return map[string]any{"entity": w["entity"], "expressionId": num(id)}, nil
	}
	return nil, fmt.Errorf("unknown child kind %s", kind)
}

// diffRole describes how an existing target role differs from the artifact (read-only).
func diffRole(want, have map[string]any) []string {
	var out []string
	if !sameJSON(pick(want, "description"), pick(have, "description")) {
		out = append(out, "description")
	}
	for _, kind := range append(append([]string{}, knownChildren...), "assignments") {
		w, h := map[string]bool{}, map[string]bool{}
		for _, it := range toList(want[kind]) {
			w[canon(it)] = true
		}
		for _, it := range toListAny(have[kind]) {
			h[canon(it)] = true
		}
		missing, extra := 0, 0
		for k := range w {
			if !h[k] {
				missing++
			}
		}
		for k := range h {
			if !w[k] {
				extra++
			}
		}
		if missing+extra > 0 {
			out = append(out, fmt.Sprintf("%s: %d missing on target, %d extra on target", kind, missing, extra))
		}
	}
	return out
}

// ---- phase C: role assignments (after every role exists) ----

func (m *importer) assignmentsPhase(ctx context.Context, roles []map[string]any) {
	sem := make(chan struct{}, m.o.Conc)
	var wg sync.WaitGroup
	for _, r := range roles {
		name := fmt.Sprint(r["name"])
		m.mu.Lock()
		st := m.state[name]
		m.mu.Unlock()
		if st == nil || (st.existed && !m.o.Overwrite) {
			continue // failed earlier, or existing role skipped entirely
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := m.syncAssignments(ctx, r, st); err != nil {
				m.fail("assignments of role %s: %v", name, err)
			}
		}()
	}
	wg.Wait()
}

// subject -> (operation, path params) for create or delete
func (m *importer) subjectRoute(ctx context.Context, sub map[string]any, create bool) (string, map[string]string, error) {
	pickOp := func(c, d string) string {
		if create {
			return c
		}
		return d
	}
	switch fmt.Sprint(sub["type"]) {
	case "USER":
		return pickOp("createRoleAssignmentForUser", "deleteRoleAssignmentFromUser"), map[string]string{"username": fmt.Sprint(sub["username"])}, nil
	case "GROUP":
		return pickOp("createRoleAssignmentForGroup", "deleteRoleAssignmentFromGroup"), map[string]string{"groupName": fmt.Sprint(sub["groupName"])}, nil
	case "ROLE":
		id, ok := m.roleIDOf(ctx, fmt.Sprint(sub["role"]))
		if !ok {
			return "", nil, fmt.Errorf("subject role %q does not exist on target", sub["role"])
		}
		return pickOp("createRoleAssignmentForRole", "deleteRoleAssignmentFromRole"), map[string]string{"roleId": id}, nil
	}
	return "", nil, fmt.Errorf("unknown subject type %v", sub["type"])
}

func (m *importer) syncAssignments(ctx context.Context, r map[string]any, st *roleState) error {
	have := map[string]map[string]any{}
	if st.cur != nil {
		for _, it := range toListAny(st.cur["assignments"]) {
			have[canon(it)] = it
		}
	}
	for _, a := range toList(r["assignments"]) {
		k := canon(a)
		if _, ok := have[k]; ok {
			delete(have, k)
			m.count("unchanged assignments")
			continue
		}
		sub, _ := a["subject"].(map[string]any)
		op, pv, err := m.subjectRoute(ctx, sub, true)
		if err != nil {
			return err
		}
		var rid any = st.id
		if !m.o.Dry {
			rid = json.Number(st.id)
		}
		body := map[string]any{"roleId": rid}
		if ra, _ := a["roleAdmin"].(bool); ra {
			body["roleAdmin"] = true
		}
		if _, err := m.call(ctx, op, pv, body); err != nil {
			return err
		}
		m.count("created assignments")
	}
	for _, it := range have {
		sub, _ := it["subject"].(map[string]any)
		op, pv, err := m.subjectRoute(ctx, sub, false)
		if err != nil {
			return err
		}
		pv["assignmentId"] = fmt.Sprint(it["id"])
		if _, err := m.call(ctx, op, pv, nil); err != nil {
			return err
		}
		m.count("deleted assignments")
	}
	return nil
}

func (m *importer) report() error {
	keys := make([]string, 0, len(m.counts))
	for k := range m.counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tag := ""
	if m.o.Dry {
		tag = " (DRY RUN: nothing was written)"
	}
	fmt.Fprintf(os.Stderr, "\nimport summary%s\n", tag)
	for _, k := range keys {
		fmt.Fprintf(os.Stderr, "  %-44s %d\n", k, m.counts[k])
	}
	sort.Strings(m.warns)
	for _, w := range m.warns {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if len(m.fails) > 0 {
		sort.Strings(m.fails)
		for _, f := range m.fails {
			fmt.Fprintln(os.Stderr, "FAILED:", f)
		}
		return fmt.Errorf("%d failure(s); re-run with --overwrite to converge the affected roles", len(m.fails))
	}
	return nil
}

// ---- command ----

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9.-]`)

func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	var (
		urlF    = fs.String("url", os.Getenv("STARBURST_URL"), "TARGET SEP base URL (env STARBURST_URL)")
		in      = fs.String("in", "", "artifact to import (.biac, .json or .json.gz) [required]")
		role    = fs.String("role", os.Getenv("STARBURST_ROLE"), "system role to activate, e.g. sysadmin (env STARBURST_ROLE)")
		over    = fs.Bool("overwrite", false, "sync roles that already exist to the artifact, in place (default: skip them)")
		dry     = fs.Bool("dry-run", false, "simulate against the target snapshot; send no writes")
		compare = fs.Bool("compare", false, "like --dry-run, and report how existing roles/expressions differ from the artifact")
		snapF   = fs.String("snapshot", "", "snapshot file (default: ./target-<host>.snapshot.biac); created on first --dry-run/--compare, then reused offline")
		live    = fs.Bool("live", false, "online compare: read the target now for this run only (no snapshot file used or written); implies --compare")
		refresh = fs.Bool("refresh-snapshot", false, "re-read the target and replace the snapshot")
		yes     = fs.Bool("yes", false, "do not ask for confirmation")
		conc    = fs.Int("concurrency", 8, "roles processed in parallel")
		spec    = fs.String("spec", "", "OpenAPI spec file (default: embedded)")
		plan    = fs.String("plan", "", "export plan file (default: embedded)")
		ca      = fs.String("ca-cert", "", "extra PEM CA bundle")
		allow   = fs.Bool("allow-http", false, "permit plain http (local testing only)")
		to      = fs.Duration("timeout", 60*time.Second, "per-request timeout")
	)
	fs.Parse(args)
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	u, err := url.Parse(*urlF)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid or missing URL %q: pass --url https://host or `export STARBURST_URL=...` in THIS shell", *urlF)
	}
	host := u.Host
	art, err := loadArtifact(*in)
	if err != nil {
		return err
	}
	if v, _ := art["v"].(int64); v != formatVersion {
		return fmt.Errorf("unsupported artifact version %v (this build imports v%d)", art["v"], formatVersion)
	}
	res, _ := art["resources"].(map[string]any)
	if res == nil {
		return fmt.Errorf("artifact has no resources")
	}
	s, p, err := loadSpecPlan(*spec, *plan)
	if err != nil {
		return err
	}
	for id, method := range importOps {
		if o := s.Ops[id]; o == nil || o.Method != method {
			return fmt.Errorf("spec has no %s operation %q: cannot import with this API version (run spec-diff)", method, id)
		}
	}
	if *live {
		if *snapF != "" || *refresh {
			return fmt.Errorf("--live does not use snapshots: drop --snapshot/--refresh-snapshot")
		}
		*compare = true
	}
	isDry := *dry || *compare
	snapPath := *snapF
	if snapPath == "" {
		snapPath = "target-" + unsafeName.ReplaceAllString(host, "_") + ".snapshot.biac"
	}
	_, statErr := os.Stat(snapPath)
	needSnapshot := isDry && !*live && (*refresh || statErr != nil)
	var c *Client
	if !isDry || needSnapshot || *live { // the client is only needed for live reads/writes
		if c, err = newClient(clientConfig{BaseURL: *urlF, Token: os.Getenv("STARBURST_TOKEN"),
			User: os.Getenv("STARBURST_USER"), Pass: os.Getenv("STARBURST_PASSWORD"),
			Role: *role, CACertFile: *ca, AllowHTTP: *allow, Timeout: *to}); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var snap map[string]any
	if *live {
		fmt.Fprintln(os.Stderr, "reading target live for this run (no snapshot used or written) ...")
		tree, err := readTarget(ctx, c, s, p, *conc)
		if err != nil {
			return fmt.Errorf("reading target: %w", err)
		}
		snap, _ = tree["resources"].(map[string]any)
	} else if isDry {
		if needSnapshot {
			fmt.Fprintf(os.Stderr, "reading target once to create snapshot %s ...\n", snapPath)
			if err := writeSnapshot(ctx, c, s, p, *conc, snapPath); err != nil {
				return fmt.Errorf("creating snapshot: %w", err)
			}
		}
		sa, err := loadArtifact(snapPath)
		if err != nil {
			return err
		}
		if src, _ := sa["source"].(string); src != host {
			return fmt.Errorf("snapshot %s is of %q, not %q; delete it or use --snapshot", snapPath, src, host)
		}
		fmt.Fprintf(os.Stderr, "using snapshot %s (taken %v); delete it or pass --refresh-snapshot to re-read the cluster\n", snapPath, sa["exportedAt"])
		snap, _ = sa["resources"].(map[string]any)
	}
	m := newImporter(c, s, p, host, importOpts{Overwrite: *over, Dry: isDry, Compare: *compare, Conc: *conc}, snap)
	ask := func(q string) bool { return *yes || confirm(q) }
	runErr := importArtifact(ctx, m, res, ask)
	if m.wrote.Load() > 0 { // the target changed: any snapshot of it is now stale
		if err := os.Remove(snapPath); err == nil {
			fmt.Fprintf(os.Stderr, "removed stale snapshot %s (the target changed)\n", snapPath)
		}
	}
	return runErr
}

// readTarget exports the whole target (same format as `export`) as a generic tree.
func readTarget(ctx context.Context, c *Client, s *Spec, p *Plan, conc int) (map[string]any, error) {
	_, skip, err := p.validate(s)
	if err != nil {
		return nil, err
	}
	res, order, err := newEngine(c, s, p, skip, conc, nil).Run(ctx)
	if err != nil {
		return nil, err
	}
	tree, err := normalize(&Artifact{Version: formatVersion, ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Source: c.base.Host, SpecVer: s.Version, Order: order, Resources: res})
	if err != nil {
		return nil, err
	}
	return tree.(map[string]any), nil
}

// writeSnapshot stores a full export of the target for offline comparison.
func writeSnapshot(ctx context.Context, c *Client, s *Spec, p *Plan, conc int, path string) error {
	tree, err := readTarget(ctx, c, s, p, conc)
	if err != nil {
		return err
	}
	return writeArtifact(path, tree) // mode 0600: it contains the target's access policy
}

func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return err == nil && strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
}
