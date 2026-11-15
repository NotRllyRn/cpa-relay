package relay

import (
	"testing"
	"time"
)

func TestOmittedPhysicalSourceMustBeProvenDeletedAcrossRestart(t *testing.T) {
	now := time.Now()
	entry := sourceEntry("a")
	src := &trackedSource{fakeSource: fakeSource{entries: []Entry{entry}, raw: map[string][]byte{"a": marshal(t, account(now, "workspace"))}}}
	c := diskConfig(t, "exporter")
	e, err := New(c, secret(), src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Export(now); err != nil {
		t.Fatal(err)
	}
	watermark := e.store.state.Watermark
	src.entries = []Entry{}
	src.physical = map[string]bool{entry.Path: true}
	for _, fault := range []bool{false, true} {
		src.removeErr = fault
		if _, err = e.Export(now.Add(time.Second)); err != ErrExport {
			t.Fatal("omitted/unreadable existing physical source became authoritative deletion")
		}
		if e.store.state.Watermark != watermark || len(e.store.state.SourcePaths) != 1 {
			t.Fatal("failure forgot source inventory/watermark")
		}
	}
	src.removeErr = false
	if e.Stop() != nil {
		t.Fatal("stop")
	}
	e, err = New(c, secret(), src)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	if _, err = e.Export(now.Add(2 * time.Second)); err != ErrExport {
		t.Fatal("restart forgot omitted physical source")
	}
	// Only a confirmed missing file in an accessible parent permits deletion.
	src.physical[entry.Path] = false
	raw, err := e.Export(now.Add(3 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := DecodeSnapshot(raw, protocolConfig(), now.Add(3*time.Second))
	if err != nil || len(snap.Accounts) != 0 || len(e.store.state.SourcePaths) != 0 {
		t.Fatal("valid delete-all not authoritative")
	}
}

func TestSameWorkspaceReceiverUpdatesOnlyCredentialIdentity(t *testing.T) {
	now := time.Now()
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	h := diskHost(c.AuthDir)
	a := account(now, "workspace")
	a.CredentialID = credentialID("/source/a.json")
	b := a
	b.CredentialID = credentialID("/source/b.json")
	b.Email = "second@example.invalid"
	snap := snapshot(now)
	snap.Accounts = []Account{a, b}
	if Validate(snap, c, now) != nil || s.accept(snap) != nil || s.reconcile(snap, h) != nil {
		t.Fatal("same workspace not supported")
	}
	h.mu.Lock()
	first := h.saves
	h.mu.Unlock()
	if s.accept(snap) != nil || s.reconcile(snap, h) != nil {
		t.Fatal("unchanged")
	}
	h.mu.Lock()
	unchanged := h.saves
	h.mu.Unlock()
	if first != unchanged {
		t.Fatal("unchanged credentials rewritten")
	}
	a.Email = "refreshed@example.invalid"
	a.AccessToken = account(now.Add(time.Minute), "workspace").AccessToken
	snap.Accounts = []Account{a, b}
	if s.accept(snap) != nil || s.reconcile(snap, h) != nil {
		t.Fatal("refresh")
	}
	h.mu.Lock()
	after := h.saves
	h.mu.Unlock()
	if after-unchanged != 2 {
		t.Fatal("refresh should only disable+replace changed credential")
	}
	snap.Accounts = []Account{b}
	if s.accept(snap) != nil || s.reconcile(snap, h) != nil {
		t.Fatal("remove one")
	}
	if s.audit(&snap) != nil || len(s.state.Managed) != 1 || s.state.Managed[0] != b.CredentialID {
		t.Fatal("wrong source removed")
	}
	snap.Accounts = []Account{}
	if s.accept(snap) != nil || s.reconcile(snap, h) != nil || len(s.state.Managed) != 0 {
		t.Fatal("delete-all")
	}
}
