package relay

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func diskConfig(t *testing.T, role string) Config {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	auth := filepath.Join(base, "auth")
	if e := os.Mkdir(auth, 0700); e != nil {
		t.Fatal(e)
	}
	c := protocolConfig()
	c.Role = role
	c.StateDir = state
	if role == "receiver" {
		c.AuthDir = auth
		c.ReceiverID = "secondary"
		c.Endpoint = "https://primary.example.invalid" + SnapshotPath
	}
	return c
}
func secret() string { return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32))) }

func TestConfigValidation(t *testing.T) {
	t.Setenv("CPA_RELAY_TEST_SECRET", secret())
	base := `enabled: true
role: receiver
secret_env: CPA_RELAY_TEST_SECRET
endpoint: https://primary.example.invalid/v0/resource/plugins/cpa-relay/snapshot
state_dir: /var/lib/example-relay
auth_dir: /var/lib/example-cpa-auth
receiver_id: secondary
`
	c, s, err := ParseConfig([]byte(base))
	if err != nil || s != secret() || c.PollSeconds != 15 {
		t.Fatal("valid settings rejected")
	}
	for _, raw := range []string{
		strings.Replace(base, "https:", "http:", 1),
		strings.Replace(base, "primary.example.invalid/", "user:password@primary.example.invalid/", 1),
		strings.Replace(base, "/snapshot", "/snapshot?token=bad", 1),
		strings.Replace(base, "/snapshot", "/snapshot#fragment", 1),
		base + "accounts: []\n", base + "source_files: []\n",
		strings.Replace(base, "state_dir: /var/lib/example-relay", "state_dir: relative", 1),
		strings.Replace(base, "state_dir: /var/lib/example-relay", "state_dir: /var/lib/example-cpa-auth/nested", 1),
		base + "poll_seconds: 0\n", base + "max_stale_seconds: 10\n", base + "expiry_skew_seconds: 0\n", base + "secret: inline-not-allowed\n", base + "---\nrole: exporter\n",
	} {
		if _, _, e := ParseConfig([]byte(raw)); e == nil {
			t.Fatal("invalid config accepted")
		}
	}
	for _, value := range []string{"", strings.Repeat("a", 20), "not base64url!"} {
		t.Setenv("CPA_RELAY_TEST_SECRET", value)
		if _, _, e := ParseConfig([]byte(base)); e == nil {
			t.Fatal("weak secret accepted")
		}
	}
}

func TestStoreOwnershipAtomicCacheAndRestart(t *testing.T) {
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snap := snapshot(now, "acct-a")
	unrelated := filepath.Join(c.AuthDir, "manual.json")
	os.WriteFile(unrelated, []byte(`{"manual":true}`), 0600)
	if err = s.accept(snap); err != nil {
		t.Fatal(err)
	}
	if err = s.reconcile(snap, diskHost(c.AuthDir)); err != nil {
		t.Fatal(err)
	}
	name := s.filename(credentialID("acct-a"))
	if !ReservedNames(c.ReceiverID, name) || strings.Contains(name, "acct-a") {
		t.Fatal("unsafe filename")
	}
	raw, err := os.ReadFile(filepath.Join(c.AuthDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "refresh_token") {
		t.Fatal("unexpected credential field")
	}
	s.close()
	s, err = openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if s.state.Watermark != now.UnixNano() || !s.state.Snapshot.GeneratedAt.Equal(now) {
		t.Fatal("cache rejuvenated")
	}
	if err = s.withdrawRuntime(diskHost(c.AuthDir)); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(c.AuthDir, name)); !os.IsNotExist(err) {
		t.Fatal("managed file remains")
	}
	if _, err = os.Stat(unrelated); err != nil {
		t.Fatal("unrelated file deleted")
	}
	if st, err := os.Stat(filepath.Join(c.StateDir, "state.json")); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("insecure cache")
	}
	if _, err = openStore(c); err == nil {
		t.Fatal("second store obtained lock")
	}
}

func TestStoreRejectsCollisionSymlinkCorruptionAndAuthorityChange(t *testing.T) {
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	name := s.filename(credentialID("acct-a"))
	path := filepath.Join(c.AuthDir, name)
	os.WriteFile(path, []byte("manual"), 0600)
	if s.accept(snapshot(time.Now(), "acct-a")) == nil {
		t.Fatal("claimed existing manual file")
	}
	if len(s.state.Managed) != 0 {
		t.Fatal("collision became owned")
	}
	s.withdrawRuntime(diskHost(c.AuthDir))
	raw, _ := os.ReadFile(path)
	if string(raw) != "manual" {
		t.Fatal("manual file removed")
	}
	os.Remove(path)
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("untouched"), 0600)
	os.Symlink(outside, path)
	if s.accept(snapshot(time.Now(), "acct-a")) == nil {
		t.Fatal("symlink accepted")
	}
	s.close()
	c.Endpoint = "https://different.example.invalid" + SnapshotPath
	// Persist original binding first, then test the authority fence.
	original := c
	original.Endpoint = "https://primary.example.invalid" + SnapshotPath
	s, err = openStore(original)
	if err != nil {
		t.Fatal(err)
	}
	if s.save(s.state) != nil {
		t.Fatal("save")
	}
	s.close()
	if _, err = openStore(c); err == nil {
		t.Fatal("authority silently changed")
	}
	os.WriteFile(filepath.Join(c.StateDir, "state.json"), []byte("broken"), 0600)
	if _, err = openStore(original); err == nil {
		t.Fatal("corrupt cache accepted")
	}
	raw, _ = os.ReadFile(outside)
	if string(raw) != "untouched" {
		t.Fatal("escaped root")
	}
}

func TestStorePartialWriteFailureKeepsInventory(t *testing.T) {
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	snap := snapshot(time.Now(), "acct-a", "acct-b")
	if s.accept(snap) != nil {
		t.Fatal("accept")
	}
	// Simulate a path becoming unwritable after durable write-ahead inventory.
	os.Mkdir(filepath.Join(c.AuthDir, s.filename(credentialID("acct-b"))), 0700)
	if s.reconcile(snap, diskHost(c.AuthDir)) == nil {
		t.Fatal("write failure not reported")
	}
	if s.state.Watermark != snap.Generation || len(s.state.Managed) != 2 {
		t.Fatal("lost crash-recovery inventory")
	}
	if s.withdrawRuntime(diskHost(c.AuthDir)) == nil {
		t.Fatal("cleanup failure not reported")
	}
	os.Remove(filepath.Join(c.AuthDir, s.filename(credentialID("acct-b"))))
	if s.withdrawRuntime(diskHost(c.AuthDir)) != nil {
		t.Fatal("cleanup retry failed")
	}
}

func TestStorePrivateDirectoriesAndCacheSymlink(t *testing.T) {
	insecureParent := t.TempDir()
	os.Chmod(insecureParent, 0777)
	if _, err := secureDir(filepath.Join(insecureParent, "state"), true, true); err == nil {
		t.Fatal("writable ancestor accepted")
	}
	c := diskConfig(t, "exporter")
	os.Mkdir(c.StateDir, 0755)
	if _, err := openStore(c); err == nil {
		t.Fatal("public state directory accepted")
	}
	os.Chmod(c.StateDir, 0700)
	outside := filepath.Join(t.TempDir(), "outside")
	os.WriteFile(outside, []byte("outside"), 0600)
	os.Symlink(outside, filepath.Join(c.StateDir, "state.json"))
	if _, err := openStore(c); err == nil {
		t.Fatal("cache symlink accepted")
	}
}
