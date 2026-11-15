package relay

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type trackedSource struct {
	fakeSource
	gets []string
}

func (s *trackedSource) Get(index string) ([]byte, error) {
	s.gets = append(s.gets, index)
	return s.fakeSource.Get(index)
}

func TestSourceFilesDisambiguateSharedWorkspace(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
		ok    bool
		gets  []string
	}{
		{"omitted retains duplicate rejection", nil, false, []string{"a", "b"}},
		{"one login", []string{"chosen.json"}, true, []string{"a"}},
		{"both logins still ambiguous", []string{"chosen.json", "other.json"}, false, []string{"a", "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			a, b := account(now, "acct-a"), account(now, "acct-a")
			a.Email, b.Email = "chosen@example.invalid", "other@example.invalid"
			src := &trackedSource{fakeSource: fakeSource{
				entries: []Entry{{Index: "a", Name: "chosen.json", Codex: true}, {Index: "b", Name: "other.json", Codex: true}},
				raw:     map[string][]byte{"a": marshal(t, a), "b": marshal(t, b)},
			}}
			c := diskConfig(t, "exporter")
			c.SourceFiles = tc.files
			e, err := New(c, secret(), src)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Stop()
			raw, err := e.Export(now)
			if (err == nil) != tc.ok || !reflect.DeepEqual(src.gets, tc.gets) {
				t.Fatalf("success=%v reads=%v", err == nil, src.gets)
			}
			if tc.ok {
				var snap Snapshot
				if json.Unmarshal(raw, &snap) != nil || len(snap.Accounts) != 1 || snap.Accounts[0].Email != a.Email {
					t.Fatal("wrong selected login")
				}
				for _, forbidden := range []string{"chosen.json", "other.json", b.Email, "source_files"} {
					if strings.Contains(string(raw), forbidden) {
						t.Fatal("source selection metadata leaked")
					}
				}
			}
		})
	}
}

func TestSourceFilesPreflightAndFiltering(t *testing.T) {
	chosen := Entry{Index: "a", Name: "chosen.json", Codex: true}
	for _, tc := range []struct {
		name    string
		files   []string
		entries []Entry
		gets    []string
		ok      bool
	}{
		{"unreadable unrelated source", []string{"chosen.json"}, []Entry{{Index: "unreadable", Name: "unrelated.json", Codex: true}, chosen}, []string{"a"}, true},
		{"malformed unrelated JSON", []string{"chosen.json"}, []Entry{{Index: "bad-json", Name: "unrelated.json", Codex: true}, chosen}, []string{"a"}, true},
		{"malformed unrelated fields", []string{"chosen.json"}, []Entry{{Index: "bad-fields", Name: "unrelated.json", Codex: true}, chosen}, []string{"a"}, true},
		{"missing selected source", []string{"chosen.json", "missing.json"}, []Entry{chosen}, nil, false},
		{"duplicate name", []string{"chosen.json"}, []Entry{chosen, {Index: "b", Name: "chosen.json", Codex: true}}, nil, false},
		{"duplicate name on another provider", []string{"chosen.json"}, []Entry{chosen, {Index: "b", Name: "chosen.json"}}, nil, false},
		{"unselected index alias", []string{"chosen.json"}, []Entry{chosen, {Index: "a", Name: "other.json", Codex: true}}, nil, false},
		{"selected index alias", []string{"chosen.json", "other.json"}, []Entry{chosen, {Index: "a", Name: "other.json", Codex: true}}, nil, false},
		{"runtime only", []string{"chosen.json"}, []Entry{{Index: "a", Name: "chosen.json", Codex: true, RuntimeOnly: true}}, nil, false},
		{"wrong provider", []string{"chosen.json"}, []Entry{{Index: "a", Name: "chosen.json"}}, nil, false},
		{"empty index", []string{"chosen.json"}, []Entry{{Name: "chosen.json", Codex: true}}, nil, false},
		{"trimmed index alias", []string{"chosen.json"}, []Entry{{Index: " a ", Name: "chosen.json", Codex: true}}, nil, false},
		{"name is not a basename", []string{"chosen.json"}, []Entry{{Index: "a", Name: "../chosen.json", Codex: true}}, nil, false},
		{"no path normalization", []string{"chosen.json"}, []Entry{{Index: "a", Name: "./chosen.json", Codex: true}}, nil, false},
		{"case sensitive", []string{"chosen.json"}, []Entry{{Index: "a", Name: "Chosen.json", Codex: true}}, nil, false},
		{"account allowlist still required", []string{"other.json"}, []Entry{{Index: "b", Name: "other.json", Codex: true}}, []string{"b"}, false},
		{"selected malformed fields", []string{"chosen.json"}, []Entry{{Index: "bad-fields", Name: "chosen.json", Codex: true}}, []string{"bad-fields"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			src := &trackedSource{fakeSource: fakeSource{entries: tc.entries, raw: map[string][]byte{
				"a": marshal(t, account(now, "acct-a")), "b": marshal(t, account(now, "acct-b")),
				"bad-json": []byte(`{"account_id":`), "bad-fields": []byte(`{"type":"codex","account_id":"acct-a","access_token":123}`),
			}}}
			c := diskConfig(t, "exporter")
			c.Accounts, c.SourceFiles = []string{"acct-a"}, tc.files
			e, err := New(c, secret(), src)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Stop()
			_, err = e.Export(now)
			if (err == nil) != tc.ok || !reflect.DeepEqual(src.gets, tc.gets) {
				t.Fatalf("success=%v reads=%v", err == nil, src.gets)
			}
		})
	}
}

func TestSourceFilesConfig(t *testing.T) {
	t.Setenv("CPA_RELAY_TEST_SECRET", secret())
	base := "role: exporter\nsecret_env: CPA_RELAY_TEST_SECRET\naccounts: [acct-a]\nstate_dir: /var/lib/example-relay\n"
	for _, name := range []string{"chosen.json", "codex-person@example.invalid.json", "Codex_Person+test.JSON", strings.Repeat("a", 250) + ".json"} {
		if _, _, err := ParseConfig([]byte(base + "source_files: [" + name + "]\n")); err != nil {
			t.Fatal("valid basename rejected")
		}
	}
	for _, files := range [][]string{
		{"../chosen.json"}, {"/tmp/chosen.json"}, {"./chosen.json"}, {"dir/chosen.json"}, {`dir\chosen.json`},
		{"chosen.json "}, {" chosen.json"}, {".hidden.json"}, {"chosen.json\n"}, {"chosen.json\x00"},
		{"%2e%2e%2fchosen.json"}, {"*.json"}, {""}, {"chosen.txt"}, {"chosen.json", "chosen.json"},
		{strings.Repeat("a", 251) + ".json"}, make([]string, MaxAccounts+1),
	} {
		raw := string(marshal(t, files)) // JSON sequence syntax is valid YAML.
		if _, _, err := ParseConfig([]byte(base + "source_files: " + raw + "\n")); err == nil {
			t.Fatal("unsafe/duplicate source selector accepted")
		}
	}
	receiver := strings.Replace(base, "role: exporter", "role: receiver", 1) + "endpoint: https://primary.example.invalid" + SnapshotPath + "\nauth_dir: /var/lib/example-auth\nreceiver_id: secondary\n"
	for _, files := range []string{"[chosen.json]", "[]"} {
		if _, _, err := ParseConfig([]byte(receiver + "source_files: " + files + "\n")); err == nil {
			t.Fatal("receiver accepted exporter-only source selection")
		}
	}
}
