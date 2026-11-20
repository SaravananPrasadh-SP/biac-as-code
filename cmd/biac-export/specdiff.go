package main

import (
	"fmt"
	"sort"
	"strings"
)

// diffSpecs compares two spec versions and reports what matters to the plan.
func diffSpecs(a, b *Spec, p *Plan) (report string, impacted bool) {
	var sb strings.Builder
	used := map[string]string{} // opId -> resource
	for _, r := range p.Resources {
		used[r.Op] = r.Name
	}
	pr := func(format string, args ...any) { fmt.Fprintf(&sb, format+"\n", args...) }
	pr("spec version: %s -> %s", a.Version, b.Version)

	var removed, added, changed []string
	for id, oa := range a.Ops {
		ob := b.Ops[id]
		if ob == nil {
			removed = append(removed, id)
		} else if oa.Method != ob.Method || oa.Path != ob.Path || paramSig(oa) != paramSig(ob) {
			changed = append(changed, fmt.Sprintf("%s: %s %s [%s] -> %s %s [%s]", id, oa.Method, oa.Path, paramSig(oa), ob.Method, ob.Path, paramSig(ob)))
		}
	}
	for id, ob := range b.Ops {
		if a.Ops[id] == nil {
			added = append(added, fmt.Sprintf("%s (%s %s)", id, ob.Method, ob.Path))
		}
	}
	sort.Strings(removed)
	sort.Strings(added)
	sort.Strings(changed)

	pr("\n-- operations removed (%d)", len(removed))
	for _, id := range removed {
		if r, ok := used[id]; ok {
			opt := ""
			for _, rr := range p.Resources {
				if rr.Name == r && rr.Optional {
					opt = " (optional: will be skipped)"
				}
			}
			if opt == "" {
				impacted = true
			}
			pr("  %s   <-- USED BY PLAN resource %q%s", id, r, opt)
		} else {
			pr("  %s", id)
		}
	}
	pr("\n-- operations changed (%d)", len(changed))
	for _, c := range changed {
		id := strings.SplitN(c, ":", 2)[0]
		mark := ""
		if r, ok := used[id]; ok {
			impacted = true
			mark = fmt.Sprintf("   <-- USED BY PLAN resource %q", r)
		}
		pr("  %s%s", c, mark)
	}
	pr("\n-- operations added (%d): candidates for new plan entries", len(added))
	for _, x := range added {
		pr("  %s", x)
	}

	pr("\n-- response schema changes for operations in the plan")
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	none := true
	for _, id := range ids {
		oa, ob := a.Ops[id], b.Ops[id]
		if oa == nil || ob == nil {
			continue
		}
		fa, fb := a.flatten(oa.Resp), b.flatten(ob.Resp)
		for _, k := range sortedKeys(fa) {
			if _, ok := fb[k]; !ok {
				pr("  %s (%s): field removed: %s", used[id], id, k)
				impacted, none = true, false
			} else if fa[k] != fb[k] {
				pr("  %s (%s): type changed: %s %s -> %s", used[id], id, k, fa[k], fb[k])
				impacted, none = true, false
			}
		}
		for _, k := range sortedKeys(fb) {
			if _, ok := fa[k]; !ok {
				pr("  %s (%s): field added (new data, auto-exported): %s", used[id], id, k)
				none = false
			}
		}
	}
	if none {
		pr("  none")
	}
	if impacted {
		pr("\nRESULT: plan is IMPACTED; review the marked items and update the plan.")
	} else {
		pr("\nRESULT: plan is not impacted.")
	}
	return sb.String(), impacted
}

func paramSig(o *Operation) string {
	var s []string
	for _, p := range o.Params {
		r := ""
		if p.Required {
			r = "!"
		}
		s = append(s, p.In+":"+p.Name+r)
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

// flatten lists every reachable property path (with type) of a schema.
func (s *Spec) flatten(schema any) map[string]string {
	out := map[string]string{}
	s.walk(schema, "", 0, out)
	return out
}

func (s *Spec) walk(n any, prefix string, depth int, out map[string]string) {
	if depth > 8 {
		return
	}
	m, ok := s.resolve(n).(map[string]any)
	if !ok {
		return
	}
	for _, key := range []string{"allOf", "oneOf", "anyOf"} {
		if arr, ok := m[key].([]any); ok {
			for _, sub := range arr {
				s.walk(sub, prefix, depth+1, out)
			}
		}
	}
	if it, ok := m["items"]; ok {
		s.walk(it, prefix, depth+1, out)
	}
	props, _ := m["properties"].(map[string]any)
	for k, v := range props {
		pm, _ := s.resolve(v).(map[string]any)
		t, _ := pm["type"].(string)
		if t == "" {
			t = "object"
		}
		out[prefix+k] = t
		s.walk(v, prefix+k+".", depth+1, out)
	}
}

func sortedKeys(m map[string]string) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
