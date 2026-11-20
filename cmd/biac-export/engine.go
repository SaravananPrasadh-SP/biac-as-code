package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
)

type item = map[string]any

type Engine struct {
	c      *Client
	spec   *Spec
	plan   *Plan
	skip   map[string]bool
	sem    chan struct{} // bounds in-flight API calls
	sel    map[string]map[string]bool
	tables map[string]map[string]item // top-level resource -> id -> raw item
	kids   map[string][]*Resource
	warned sync.Map // resource -> already warned about 404 skip
}

func newEngine(c *Client, s *Spec, p *Plan, skip map[string]bool, conc int, sel map[string]map[string]bool) *Engine {
	e := &Engine{c: c, spec: s, plan: p, skip: skip, sel: sel,
		sem: make(chan struct{}, max(1, conc)), tables: map[string]map[string]item{}, kids: map[string][]*Resource{}}
	for i := range p.Resources {
		r := &p.Resources[i]
		if r.Per != "" {
			e.kids[r.Per] = append(e.kids[r.Per], r)
		}
	}
	return e
}

// loadTop fetches every top-level list once and builds the id->item tables used by rewrites.
func (e *Engine) loadTop(ctx context.Context) (map[string][]item, []string, error) {
	var order []string
	raws := map[string][]item{}
	for i := range e.plan.Resources { // pass 1: fetch all top-level lists, build ID tables
		r := &e.plan.Resources[i]
		if r.Per != "" || e.skip[r.Name] {
			continue
		}
		items, err := e.fetch(ctx, r, nil)
		if err != nil {
			if ie, ok := err.(*httpError); ok && ie.Status == 404 && r.Optional {
				e.warnSkip(r.Name)
				continue
			}
			return nil, nil, fmt.Errorf("%s: %w", r.Name, err)
		}
		idf := r.IDField
		if idf == "" {
			idf = "id"
		}
		t := map[string]item{}
		for _, it := range items {
			if v, ok := it[idf]; ok && v != nil {
				t[fmt.Sprint(v)] = it
			}
		}
		e.tables[r.Name] = t
		raws[r.Name] = items
		order = append(order, r.Name)
	}
	return raws, order, nil
}

// Run returns the artifact's resources (top-level plan resources, children nested).
func (e *Engine) Run(ctx context.Context) (map[string]any, []string, error) {
	raws, order, err := e.loadTop(ctx)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{}
	for _, name := range order { // pass 2: build (children + rewrites), items in parallel
		r := e.res(name)
		items := raws[name]
		if names, ok := e.sel[name]; ok { // present (even empty) => filter
			var f []item
			for _, it := range items {
				if names[fmt.Sprint(it[r.SelectKey])] {
					f = append(f, it)
					delete(names, fmt.Sprint(it[r.SelectKey]))
				}
			}
			for n := range names {
				return nil, nil, fmt.Errorf("--select %s: %q not found", name, n)
			}
			items = f
		}
		res := make([]item, len(items))
		errs := make([]error, len(items))
		var wg sync.WaitGroup
		for i := range items {
			wg.Add(1)
			go func() { defer wg.Done(); res[i], errs[i] = e.build(ctx, r, items[i]) }()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				return nil, nil, fmt.Errorf("%s[%d]: %w", name, i, err)
			}
		}
		out[name] = res
	}
	return out, order, nil
}

func (e *Engine) res(name string) *Resource {
	for i := range e.plan.Resources {
		if e.plan.Resources[i].Name == name {
			return &e.plan.Resources[i]
		}
	}
	return nil
}

// build attaches children (fetched with the RAW parent), then rewrites and drops.
func (e *Engine) build(ctx context.Context, r *Resource, raw item) (item, error) {
	out := item{}
	for k, v := range raw {
		out[k] = v
	}
	kids := e.kids[r.Name]
	type kr struct {
		items []item
		err   error
	}
	res := make([]kr, len(kids))
	var wg sync.WaitGroup
	for i, k := range kids {
		if e.skip[k.Name] {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			its, err := e.fetch(ctx, k, raw)
			if he, ok := err.(*httpError); ok && he.Status == 404 && k.Optional {
				e.warnSkip(k.Name)
				return
			}
			if err != nil {
				res[i].err = fmt.Errorf("%s: %w", k.Name, err)
				return
			}
			for _, it := range its {
				b, err := e.build(ctx, k, it)
				if err != nil {
					res[i].err = err
					return
				}
				res[i].items = append(res[i].items, b)
			}
		}()
	}
	wg.Wait()
	for i, k := range kids {
		if res[i].err != nil {
			return nil, res[i].err
		}
		if len(res[i].items) > 0 {
			out[k.Name] = res[i].items
		}
	}
	for _, rw := range r.Rewrite {
		v, ok := getPath(out, rw.Field)
		if !ok || v == nil {
			continue
		}
		ref, ok := e.tables[rw.From][fmt.Sprint(v)]
		if !ok {
			return nil, fmt.Errorf("%s: %s=%v matches no %s; the account probably lacks view access to it "+
				"(BIAC filters lists by privilege). Grant the export account read access to the %s entity category and retry",
				r.Name, rw.Field, v, rw.From, rw.From)
		}
		setPath(out, rw.To, ref[rw.Use])
		delPath(out, rw.Field)
	}
	for _, d := range r.Drop {
		delPath(out, d)
	}
	for k, v := range out { // omit nulls to keep the artifact small
		if v == nil {
			delete(out, k)
		}
	}
	return out, nil
}

// fetch calls the resource's operation (paginating) and returns its items.
func (e *Engine) fetch(ctx context.Context, r *Resource, parent item) ([]item, error) {
	op := e.spec.Ops[r.Op]
	path := op.Path
	for _, pn := range op.pathParams() {
		v, ok := getPath(parent, r.Params[pn])
		if !ok || v == nil {
			return nil, fmt.Errorf("parent has no field %q for {%s}", r.Params[pn], pn)
		}
		path = strings.ReplaceAll(path, "{"+pn+"}", url.PathEscape(fmt.Sprint(v)))
	}
	itemsKey, tokenKey := e.spec.pageShape(op)
	if itemsKey == "" {
		itemsKey = "result"
	}
	if tokenKey == "" {
		tokenKey = "nextPageToken"
	}
	paged := op.hasParam("pageToken", "query")
	var all []item
	token, seen := "", map[string]bool{}
	for {
		q := url.Values{}
		if op.hasParam("pageSize", "query") {
			q.Set("pageSize", "500")
		}
		if token != "" {
			q.Set("pageToken", token)
		}
		var body any
		e.sem <- struct{}{}
		err := e.c.get(ctx, path, q, &body)
		<-e.sem
		if err != nil {
			return nil, err
		}
		next := ""
		switch b := body.(type) {
		case []any:
			all = append(all, toItems(b)...)
		case map[string]any:
			if arr, ok := b[itemsKey].([]any); ok {
				all = append(all, toItems(arr)...)
				next, _ = b[tokenKey].(string)
			} else {
				all = append(all, b)
			}
		default:
			return nil, fmt.Errorf("unexpected response type %T", body)
		}
		if !paged || next == "" {
			return all, nil
		}
		if seen[next] {
			return nil, fmt.Errorf("pagination loop on token %q", next)
		}
		seen[next], token = true, next
	}
}

func toItems(a []any) []item {
	out := make([]item, 0, len(a))
	for _, v := range a {
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func getPath(m item, p string) (any, bool) {
	var cur any = m
	for _, seg := range strings.Split(p, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func setPath(m item, p string, v any) {
	segs := strings.Split(p, ".")
	for _, s := range segs[:len(segs)-1] {
		next, ok := m[s].(map[string]any)
		if !ok {
			next = item{}
			m[s] = next
		}
		m = next
	}
	m[segs[len(segs)-1]] = v
}

func delPath(m item, p string) {
	segs := strings.Split(p, ".")
	for _, s := range segs[:len(segs)-1] {
		next, ok := m[s].(map[string]any)
		if !ok {
			return
		}
		// copy-on-write so the raw table item is not mutated through a shared sub-map
		cp := item{}
		for k, v := range next {
			cp[k] = v
		}
		m[s] = cp
		m = cp
	}
	delete(m, segs[len(segs)-1])
}

// warnSkip reports (once) that an optional resource is not served by this cluster.
func (e *Engine) warnSkip(name string) {
	if _, dup := e.warned.LoadOrStore(name, true); !dup {
		fmt.Fprintf(os.Stderr, "warning: %q not available on this cluster (HTTP 404); skipped (optional)\n", name)
	}
}
