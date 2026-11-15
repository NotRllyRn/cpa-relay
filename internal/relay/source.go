package relay

import "strings"

// selectSources resolves exact host-reported physical basenames before any Get.
// Name and index ambiguity fail closed, including an unselected index alias:
// stock host Get resolves by index, not by the selected name.
func selectSources(entries []Entry, names []string) ([]Entry, error) {
	if len(names) == 0 {
		return entries, nil
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	selected := make(map[string]Entry, len(names))
	indexes := make(map[string]int, len(entries))
	for _, entry := range entries {
		indexes[entry.Index]++
		if !wanted[entry.Name] {
			continue
		}
		if _, exists := selected[entry.Name]; exists || !entry.Codex || entry.RuntimeOnly || entry.Index == "" || strings.TrimSpace(entry.Index) != entry.Index {
			return nil, ErrExport
		}
		selected[entry.Name] = entry
	}
	if len(selected) != len(names) {
		return nil, ErrExport
	}
	out := make([]Entry, 0, len(names))
	for _, name := range names {
		entry := selected[name]
		if indexes[entry.Index] != 1 {
			return nil, ErrExport
		}
		out = append(out, entry)
	}
	return out, nil
}
