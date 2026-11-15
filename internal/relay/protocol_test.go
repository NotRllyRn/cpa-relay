package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func token(exp time.Time) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix()))) + ".test-signature"
}
func account(now time.Time, id string) Account {
	return Account{CredentialID: credentialID(id), Type: "codex", AccountID: id, AccessToken: token(now.Add(2 * time.Hour)), Expired: now.Add(time.Hour).UTC().Format(time.RFC3339Nano)}
}
func snapshot(now time.Time, ids ...string) Snapshot {
	s := Snapshot{Version: 2, Generation: now.UnixNano(), GeneratedAt: now.UTC(), Accounts: []Account{}}
	for _, id := range ids {
		s.Accounts = append(s.Accounts, account(now, id))
	}
	return s
}
func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func protocolConfig() Config {
	return Config{PollSeconds: 15, MaxStaleSeconds: 3600, ExpirySkewSeconds: 60}
}

func TestSanitizeNeverCopiesSecrets(t *testing.T) {
	now := time.Now()
	a := account(now, "acct-a")
	m := map[string]any{}
	json.Unmarshal(marshal(t, a), &m)
	m["refresh_token"] = "DO-NOT-RELAY"
	m["id_token"] = "DO-NOT-RELAY"
	m["last_refresh"] = "DO-NOT-RELAY"
	m["metadata"] = map[string]any{"access_token": "DO-NOT-RELAY"}
	m["api_key"] = "DO-NOT-RELAY"
	m["proxy_url"] = "DO-NOT-RELAY"
	got, err := Sanitize(marshal(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(marshal(t, got)), "DO-NOT-RELAY") {
		t.Fatal("secret leaked")
	}
	a.CredentialID = "" // Never trust a credential_id supplied by a physical source.
	if got != a {
		t.Fatal("allowed fields changed")
	}
}

func TestStrictSnapshot(t *testing.T) {
	now := time.Now().UTC()
	c := protocolConfig()
	valid := snapshot(now, "acct-a")
	if _, e := DecodeSnapshot(marshal(t, valid), c, now); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*Snapshot){
		"version":           func(s *Snapshot) { s.Version = 1 },
		"generation":        func(s *Snapshot) { s.Generation++ },
		"future":            func(s *Snapshot) { s.GeneratedAt = now.Add(6 * time.Second); s.Generation = s.GeneratedAt.UnixNano() },
		"stale":             func(s *Snapshot) { s.GeneratedAt = now.Add(-time.Hour); s.Generation = s.GeneratedAt.UnixNano() },
		"duplicate":         func(s *Snapshot) { s.Accounts = append(s.Accounts, s.Accounts[0]) },
		"missing source ID": func(s *Snapshot) { s.Accounts[0].CredentialID = "" },
		"unsafe source ID":  func(s *Snapshot) { s.Accounts[0].CredentialID = "../file" },
		"traversal":         func(s *Snapshot) { s.Accounts[0].AccountID = "../acct-a" },
		"type":              func(s *Snapshot) { s.Accounts[0].Type = "other" },
		"explicit expiry":   func(s *Snapshot) { s.Accounts[0].Expired = now.Add(60 * time.Second).Format(time.RFC3339Nano) },
		"jwt expiry":        func(s *Snapshot) { s.Accounts[0].AccessToken = token(now.Add(30 * time.Second)) },
		"non jwt":           func(s *Snapshot) { s.Accounts[0].AccessToken = "opaque-token" },
		"jwt whitespace": func(s *Snapshot) {
			s.Accounts[0].AccessToken = "bad header." + strings.Split(s.Accounts[0].AccessToken, ".")[1] + ".signature"
		},
		"control":      func(s *Snapshot) { s.Accounts[0].Email = "bad\nvalue" },
		"nil accounts": func(s *Snapshot) { s.Accounts = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := snapshot(now, "acct-a")
			change(&s)
			if _, e := DecodeSnapshot(marshal(t, s), c, now); e == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, raw := range []string{
		strings.Replace(string(marshal(t, valid)), `"version":2`, `"version":2,"version":2`, 1),
		strings.Replace(string(marshal(t, valid)), `"type":"codex"`, `"type":"codex","refresh_token":"not-allowed"`, 1),
		string(marshal(t, valid)) + ` {}`,
		string(marshal(t, valid)) + strings.Repeat(" ", MaxBody),
	} {
		if _, e := DecodeSnapshot([]byte(raw), c, now); e == nil {
			t.Fatal("malformed accepted")
		}
	}
}

func TestJWTConservativeExpiryAndBinding(t *testing.T) {
	now := time.Now()
	a := account(now, "acct-a")
	a.AccessToken = token(now.Add(90 * time.Second))
	expiry, e := a.expires()
	if e != nil || expiry.After(now.Add(91*time.Second)) {
		t.Fatal("JWT did not shorten expiry")
	}
	payload := fmt.Sprintf(`{"exp":%d,"https://api.openai.com/auth":{"chatgpt_account_id":"acct-b"}}`, now.Add(time.Hour).Unix())
	a.AccessToken = "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	if validateAccount(a, now, 60) == nil {
		t.Fatal("mismatched account claim accepted")
	}
	for _, payload := range []string{`{"exp":1,"exp":9999999999}`, `{"exp":null}`, `{"exp":1.5}`, `{}`, `{"exp":99999999999999999999999999}`} {
		a.AccessToken = "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
		if validateAccount(a, now, 60) == nil {
			t.Fatal("malformed expiry accepted")
		}
	}
}

func FuzzSanitize(f *testing.F) {
	f.Add([]byte(`{"type":"codex","refresh_token":"canary","metadata":{"id_token":"canary"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := Sanitize(b)
		if err != nil {
			return
		}
		raw := marshal(t, a)
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			t.Fatal("invalid output")
		}
		for k := range m {
			switch k {
			case "type", "access_token", "account_id", "expired", "email", "plan_type", "disabled":
			default:
				t.Fatal("unexpected field")
			}
		}
	})
}
