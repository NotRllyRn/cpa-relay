package relay

import (
	"testing"
	"time"
)

func TestUnchangedSnapshotAuditsWithoutRuntimeChurn(t *testing.T) {
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	h := diskHost(c.AuthDir)
	initial := snapshot(time.Now(), "acct-a")
	if s.accept(initial) != nil || s.reconcile(initial, h) != nil {
		t.Fatal("initial snapshot")
	}
	newer := initial
	newer.GeneratedAt = newer.GeneratedAt.Add(time.Nanosecond)
	newer.Generation++
	h.failActive = true
	h.failDisabled = true
	if s.accept(newer) != nil || s.reconcile(newer, h) != nil {
		t.Fatal("unchanged credentials unnecessarily rewritten")
	}
}

func TestSuccessfulRemovalRetiresInventoryAcrossSelectorChanges(t *testing.T) {
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	h := diskHost(c.AuthDir)
	initial := snapshot(time.Now(), "acct-a")
	if s.accept(initial) != nil || s.reconcile(initial, h) != nil {
		t.Fatal("initial snapshot")
	}
	empty := snapshot(initial.GeneratedAt.Add(time.Second))
	if s.accept(empty) != nil || s.reconcile(empty, h) != nil {
		t.Fatal("removal")
	}
	if len(s.state.Managed) != 0 {
		t.Fatal("removed ownership accumulated forever")
	}
	if s.state.Watermark != empty.Generation {
		t.Fatal("inventory retirement lost replay protection")
	}
}
