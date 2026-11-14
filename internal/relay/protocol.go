package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var ErrSnapshot = errors.New("invalid relay snapshot")

// Account is deliberately a fixed allowlist, never an arbitrary metadata map.
type Account struct {
	Type        string `json:"type"`
	AccessToken string `json:"access_token"`
	AccountID   string `json:"account_id"`
	Expired     string `json:"expired"`
	Email       string `json:"email,omitempty"`
	PlanType    string `json:"plan_type,omitempty"`
	Disabled    bool   `json:"disabled"`
}

type Snapshot struct {
	Version     int       `json:"version"`
	Generation  int64     `json:"generation"`
	GeneratedAt time.Time `json:"generated_at"`
	Accounts    []Account `json:"accounts"`
}

// strictJSON also rejects duplicate keys at every level (encoding/json alone does not).
func strictJSON(raw []byte, dst any) error {
	if len(raw) > MaxBody || !json.Valid(raw) {
		return ErrSnapshot
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if walkJSON(d) != nil {
		return ErrSnapshot
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrSnapshot
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrSnapshot
	}
	return nil
}

func walkJSON(d *json.Decoder) error { return walkDepth(d, 0) }
func walkDepth(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrSnapshot
	}
	t, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return ErrSnapshot
			}
			seen[s] = true
			if e = walkDepth(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = walkDepth(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return ErrSnapshot
	}
	_, e = d.Token()
	return e
}

func DecodeSnapshot(raw []byte, c Config, now time.Time) (Snapshot, error) {
	var s Snapshot
	if strictJSON(raw, &s) != nil || Validate(s, c, now) != nil {
		return Snapshot{}, ErrSnapshot
	}
	return s, nil
}

func Validate(s Snapshot, c Config, now time.Time) error {
	if s.Version != 1 || s.Generation <= 0 || s.GeneratedAt.IsZero() || s.Generation != s.GeneratedAt.UnixNano() || s.GeneratedAt.After(now.Add(5*time.Second)) || !now.Before(s.GeneratedAt.Add(time.Duration(c.MaxStaleSeconds)*time.Second)) || s.Accounts == nil || len(s.Accounts) > MaxAccounts {
		return ErrSnapshot
	}
	seen := map[string]bool{}
	for _, a := range s.Accounts {
		if !c.selected(a.AccountID) || seen[a.AccountID] || validateAccount(a, now, c.ExpirySkewSeconds) != nil {
			return ErrSnapshot
		}
		seen[a.AccountID] = true
	}
	return nil
}

func textOK(s string, max int) bool {
	return len(s) <= max && !strings.ContainsFunc(s, unicode.IsControl)
}

func validateAccount(a Account, now time.Time, skew int) error {
	if a.Type != "codex" || !idPattern.MatchString(a.AccountID) || !textOK(a.Email, 320) || !textOK(a.PlanType, 64) || len(a.AccessToken) > 16384 || !textOK(a.AccessToken, 16384) {
		return ErrSnapshot
	}
	expiry, e := a.expires()
	if e != nil || !now.Add(time.Duration(skew)*time.Second).Before(expiry) {
		return ErrSnapshot
	}
	return nil
}

func (a Account) expires() (time.Time, error) {
	explicit, e := time.Parse(time.RFC3339Nano, a.Expired)
	if e != nil {
		return time.Time{}, ErrSnapshot
	}
	if strings.ContainsFunc(a.AccessToken, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.')
	}) {
		return time.Time{}, ErrSnapshot
	}
	parts := strings.Split(a.AccessToken, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return time.Time{}, ErrSnapshot
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || len(payload) > 12288 {
		return time.Time{}, ErrSnapshot
	}
	// Only inspect claims to shorten lifetime, never to establish authenticity.
	var claims map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(payload))
	if walkJSON(d) != nil || json.Unmarshal(payload, &claims) != nil {
		return time.Time{}, ErrSnapshot
	}
	sec, e := strconv.ParseInt(string(claims["exp"]), 10, 64)
	if e != nil || sec <= 0 || sec > 253402300799 {
		return time.Time{}, ErrSnapshot
	}
	if auth, ok := claims["https://api.openai.com/auth"]; ok {
		var obj map[string]json.RawMessage
		if json.Unmarshal(auth, &obj) != nil {
			return time.Time{}, ErrSnapshot
		}
		if raw, ok := obj["chatgpt_account_id"]; ok {
			var id string
			if json.Unmarshal(raw, &id) != nil || id != a.AccountID {
				return time.Time{}, ErrSnapshot
			}
		}
	}
	jwt := time.Unix(sec, 0)
	if jwt.Before(explicit) {
		return jwt, nil
	}
	return explicit, nil
}

// Sanitize reads only top-level allowed fields from the physical CPA credential.
// Unknown source metadata is discarded, never copied into the protocol or cache.
func Sanitize(raw []byte) (Account, error) {
	var a Account
	if len(raw) > MaxBody || !json.Valid(raw) {
		return a, ErrSnapshot
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if walkJSON(d) != nil {
		return a, ErrSnapshot
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return a, ErrSnapshot
	}
	for key, dst := range map[string]any{"type": &a.Type, "access_token": &a.AccessToken, "account_id": &a.AccountID, "expired": &a.Expired, "email": &a.Email, "plan_type": &a.PlanType, "disabled": &a.Disabled} {
		if v, ok := m[key]; ok {
			if json.Unmarshal(v, dst) != nil {
				return Account{}, ErrSnapshot
			}
		}
	}
	return a, nil
}
