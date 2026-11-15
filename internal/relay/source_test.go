package relay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type trackedSource struct {
	fakeSource
	gets      []string
	lists     int
	next      []Entry
	secondErr bool
	physical  map[string]bool
	removeErr bool
}

func (s *trackedSource) Removed(path string) (bool, error) {
	if s.removeErr {
		return false, ErrExport
	}
	if s.physical != nil {
		return !s.physical[path], nil
	}
	return s.fakeSource.Removed(path)
}

func (s *trackedSource) Get(entry Entry) ([]byte, error) {
	s.gets = append(s.gets, entry.Index)
	return s.fakeSource.Get(entry)
}
func (s *trackedSource) List() ([]Entry, error) {
	s.lists++
	if s.lists%2 == 0 {
		if s.secondErr {
			return nil, ErrExport
		}
		if s.next != nil {
			return s.next, nil
		}
	}
	return s.fakeSource.List()
}
func sourceEntry(index string) Entry {
	return Entry{Index: index, Name: index + ".json", Path: "/example/auth/" + index + ".json", Codex: true}
}

func TestDiscoverySharedWorkspaceAndRefresh(t *testing.T) {
	now := time.Now()
	src := &trackedSource{fakeSource: fakeSource{entries: []Entry{}, raw: map[string][]byte{}}}
	for i := 0; i < 7; i++ {
		index := fmt.Sprintf("source-%d", i)
		src.entries = append(src.entries, sourceEntry(index))
		a := account(now, "workspace")
		a.Email = fmt.Sprintf("login-%d@example.invalid", i)
		src.raw[index] = marshal(t, a)
	}
	// One unusable disabled login and one valid expired login do not prevent
	// usable credentials. Other providers/runtime-only entries are never read.
	src.entries = append(src.entries, sourceEntry("disabled"), sourceEntry("expired"), Entry{Index: "other-provider"}, Entry{Index: "runtime", Codex: true, RuntimeOnly: true})
	src.raw["disabled"] = []byte(`{"type":"codex","disabled":true,"access_token":123,"refresh_token":"DO-NOT-RELAY"}`)
	src.raw["expired"] = marshal(t, account(now.Add(-3*time.Hour), "workspace"))
	c := diskConfig(t, "exporter")
	e, err := New(c, secret(), src)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	read := func(at time.Time) Snapshot {
		t.Helper()
		raw, err := e.Export(at)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"source-", "/example/auth/", "refresh_token", "id_token"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatal("source/renewal material leaked")
			}
		}
		snap, err := DecodeSnapshot(raw, protocolConfig(), at)
		if err != nil {
			t.Fatal(err)
		}
		return snap
	}
	first := read(now)
	if len(first.Accounts) != 7 {
		t.Fatal("lost shared-workspace logins")
	}
	ids := map[string]Account{}
	for _, a := range first.Accounts {
		ids[a.CredentialID] = a
	}
	// Refresh in place, including changing email: neither is relay identity.
	a := account(now.Add(time.Minute), "workspace")
	a.Email = "changed@example.invalid"
	src.raw["source-3"] = marshal(t, a)
	refreshed := read(now.Add(time.Second))
	changed := 0
	for _, a := range refreshed.Accounts {
		if old, ok := ids[a.CredentialID]; !ok {
			t.Fatal("refresh changed identity")
		} else if old != a {
			changed++
		}
	}
	if changed != 1 {
		t.Fatal("refresh did not isolate one source")
	}
	src.entries = append(src.entries, sourceEntry("new"))
	src.raw["new"] = marshal(t, account(now, "workspace"))
	if len(read(now.Add(2*time.Second)).Accounts) != 8 {
		t.Fatal("not discovered next sync")
	}
	src.entries = src.entries[1:]
	if len(read(now.Add(3*time.Second)).Accounts) != 7 {
		t.Fatal("deletion not authoritative")
	}
	src.entries = []Entry{}
	if len(read(now.Add(4*time.Second)).Accounts) != 0 {
		t.Fatal("delete-all not authoritative")
	}
}

func TestDiscoveryRejectsAmbiguityAndInconsistentReads(t *testing.T) {
	good := sourceEntry("a")
	for _, tc := range []struct {
		name      string
		entries   []Entry
		next      []Entry
		secondErr bool
	}{
		{name: "nil list"},
		{name: "unclassified physical source", entries: []Entry{{Index: "unknown", UnknownProvider: true}}},
		{name: "duplicate index", entries: []Entry{good, {Index: "a"}}},
		{name: "duplicate physical path", entries: []Entry{good, {Index: "b", Name: good.Name, Path: good.Path, Codex: true}}},
		{name: "missing index", entries: []Entry{{Name: good.Name, Path: good.Path, Codex: true}}},
		{name: "trimmed index", entries: []Entry{{Index: " a ", Name: good.Name, Path: good.Path, Codex: true}}},
		{name: "disappears during get", entries: []Entry{good}, next: []Entry{}},
		{name: "new source during get", entries: []Entry{good}, next: []Entry{good, sourceEntry("b")}},
		{name: "second list error", entries: []Entry{good}, secondErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &trackedSource{fakeSource: fakeSource{entries: tc.entries, raw: map[string][]byte{"a": marshal(t, account(time.Now(), "workspace"))}}, next: tc.next, secondErr: tc.secondErr}
			e, err := New(diskConfig(t, "exporter"), secret(), src)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Stop()
			if _, err = e.Export(time.Now()); err != ErrExport {
				t.Fatal("ambiguous/inconsistent inventory exported")
			}
			if e.store.state.Watermark != 0 {
				t.Fatal("failed export advanced watermark")
			}
		})
	}
	for _, path := range []string{"", "a.json", "/auth/./a.json", "/auth/a.json/", "/auth/a.json ", " /auth/a.json", "/auth/\x00/a.json"} {
		entry := good
		entry.Path = path
		if _, err := discoverSources([]Entry{entry}); err == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	// Leading spaces in basenames are real physical identities, not selectors.
	spaced := good
	spaced.Index = "b"
	spaced.Path = "/example/auth/ a.json"
	entries, err := discoverSources([]Entry{good, spaced})
	if err != nil || len(entries) != 2 || credentialID(good.Path) == credentialID(spaced.Path) {
		t.Fatal("raw physical identity normalized")
	}
}

func TestDiscoveryFailuresDisabledExpiredAndCaps(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		raw   []byte
		count int
		ok    bool
	}{
		{"get failure", nil, 0, false},
		{"bad JSON", []byte(`{"type":"codex"`), 0, false},
		{"bad active token", []byte(`{"type":"codex","account_id":"workspace","access_token":123}`), 0, false},
		{"disabled unusable token", []byte(`{"type":"codex","disabled":true,"access_token":123}`), 0, true},
		{"wrong physical provider", []byte(`{"type":"other","disabled":true}`), 0, false},
		{"expired", marshal(t, account(now.Add(-3*time.Hour), "workspace")), 0, true},
		{"active", marshal(t, account(now, "workspace")), 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := fakeSource{entries: []Entry{sourceEntry("a")}, raw: map[string][]byte{}}
			if tc.raw != nil {
				src.raw["a"] = tc.raw
			}
			e, err := New(diskConfig(t, "exporter"), secret(), src)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Stop()
			raw, err := e.Export(now)
			if (err == nil) != tc.ok {
				t.Fatal("wrong export result")
			}
			if tc.ok {
				var s Snapshot
				json.Unmarshal(raw, &s)
				if len(s.Accounts) != tc.count {
					t.Fatal("wrong usable count")
				}
			}
		})
	}
	entries := make([]Entry, MaxAccounts+1)
	for i := range entries {
		entries[i] = sourceEntry(fmt.Sprint(i))
	}
	if _, err := discoverSources(entries); err == nil {
		t.Fatal("over-cap inventory truncated/accepted")
	}
	if _, err := discoverSources(make([]Entry, 4097)); err == nil {
		t.Fatal("list cap ignored")
	}
}

func TestLegacySettingsAndStateRequireExplicitMigration(t *testing.T) {
	t.Setenv("CPA_RELAY_TEST_SECRET", secret())
	base := "role: exporter\nsecret_env: CPA_RELAY_TEST_SECRET\nstate_dir: /var/lib/example-relay\n"
	if _, _, err := ParseConfig([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"accounts", "source_files"} {
		for _, value := range []string{"[]", "null", "[a]"} {
			if _, _, err := ParseConfig([]byte(base + key + ": " + value + "\n")); err != ErrLegacyConfig {
				t.Fatal("legacy config not explicitly rejected")
			}
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*diskState)
	}{
		{"v1 inventory", func(st *diskState) { st.Version = 1; st.Managed = []string{"old-workspace"} }},
		{"v1 cache in v2 state", func(st *diskState) { st.Snapshot.Version = 1 }},
		{"missing cached credential ID", func(st *diskState) { st.Snapshot.Accounts[0].CredentialID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := diskConfig(t, "receiver")
			s, err := openStore(c)
			if err != nil {
				t.Fatal(err)
			}
			st := s.state
			snap := snapshot(time.Now(), "workspace")
			st.Snapshot, st.Watermark = &snap, snap.Generation
			st.Managed = []string{snap.Accounts[0].CredentialID}
			tc.mutate(&st)
			if s.save(st) != nil {
				t.Fatal("fixture")
			}
			owned := filepath.Join(c.AuthDir, s.filename(st.Managed[0]))
			if os.WriteFile(owned, []byte("private-old-owned-file"), 0600) != nil {
				t.Fatal("fixture")
			}
			s.close()
			path := filepath.Join(c.StateDir, "state.json")
			before, _ := os.ReadFile(path)
			if _, err = openStore(c); err != ErrStorage {
				t.Fatal("legacy ownership/cache silently abandoned/adopted")
			}
			after, _ := os.ReadFile(path)
			file, err := os.ReadFile(owned)
			if string(before) != string(after) || err != nil || string(file) != "private-old-owned-file" {
				t.Fatal("legacy state/owned file mutated")
			}
		})
	}
}
