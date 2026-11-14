package relay

import (
	"sync/atomic"
	"testing"
	"time"
)

type panicOnceHost struct {
	*mockHost
	panicNext atomic.Bool
}

func (h *panicOnceHost) Save(name string, raw []byte) (string, error) {
	if h.panicNext.Swap(false) {
		panic("test callback panic")
	}
	return h.mockHost.Save(name, raw)
}

func TestStartupCallbackPanicReleasesLockAndKeepsGateClosed(t *testing.T) {
	c := diskConfig(t, "receiver")
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.accept(snapshot(time.Now(), "acct-a")) != nil {
		t.Fatal("seed inventory")
	}
	s.close()
	h := &panicOnceHost{mockHost: diskHost(c.AuthDir)}
	h.panicNext.Store(true)
	e, err := New(c, secret(), h)
	if err != nil {
		t.Fatal(err)
	}
	// Use done rather than Status (which intentionally serializes with callbacks):
	// a bad panic-unwind lock would otherwise hang the test indefinitely.
	select {
	case <-e.done:
	case <-time.After(2 * time.Second):
		t.Fatal("panic unwind left worker locked")
	}
	if e.Ready() || !e.Gate() {
		t.Fatal("panic opened admission")
	}
	if e.Status().LastAttempt != "internal_error" {
		t.Fatal("panic not contained")
	}
	if e.Stop() != nil {
		t.Fatal("cleanup after recovered callback panic")
	}
}
