//go:build ignore

// Run with stock_readiness_repro.sh: uses the pinned CPA manager/selector without
// adding their dependency tree to the relay module. All credentials synthetic.
package main

import (
	"context"
	"fmt"
	"time"

	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func main() {
	ctx := context.Background()
	manager := auth.NewManager(nil, nil, nil)
	const id = "synthetic"
	_, err := manager.Register(ctx, &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "synthetic-access-only"}})
	require(err == nil, "register fixture")
	current := func() *auth.Auth { a, ok := manager.GetByID(id); require(ok, "missing fixture"); return a }
	candidate := func(a *auth.Auth) bool {
		_, err := (&auth.FillFirstSelector{}).Pick(ctx, "codex", "test-model", executor.Options{}, []*auth.Auth{a})
		return err == nil
	}
	// Simulate elapsed wall time by moving only the recorded retry deadlines on
	// real manager clones, then committing via Update. No production callbacks.
	past := time.Unix(1700000000, 0).UTC()
	expire := func() {
		a := current()
		a.NextRetryAfter = past
		a.Quota.NextRecoverAt = past
		for _, s := range a.ModelStates {
			s.NextRetryAfter = past
			s.Quota.NextRecoverAt = past
		}
		_, err := manager.Update(ctx, a)
		require(err == nil, "advance retry clock")
	}
	fail := func(code int) {
		retry := time.Second
		manager.MarkResult(ctx, auth.Result{AuthID: id, Provider: "codex", Model: "test-model", Error: &auth.Error{HTTPStatus: code, Message: "synthetic upstream failure"}, RetryAfter: &retry})
	}
	require(candidate(current()), "active credential blocked")
	var transient *auth.Auth
	for _, code := range []int{429, 502} {
		fail(code)
		require(!candidate(current()), "future transient cooldown ignored")
		expire()
		transient = current()
		require(transient.Status == auth.StatusError && transient.Unavailable && transient.NextRetryAfter.Equal(past), "stock raw state unexpectedly normalized")
		require(candidate(transient), "expired transient not schedulable")
		clone := manager.List()[0]
		clone.Status = auth.StatusActive
		clone.Unavailable = false
		require(current().Status == auth.StatusError && current().Unavailable, "List mutated manager state")
		fmt.Printf("PASS %d: scheduler permits elapsed cooldown; raw plugin fields retain error/unavailable\n", code)
	}
	fail(401)
	require(!candidate(current()), "rejected token unexpectedly schedulable")
	expire()
	rejected := current()
	require(rejected.Status == transient.Status && rejected.Unavailable == transient.Unavailable && rejected.NextRetryAfter.Equal(transient.NextRetryAfter), "readiness tuple differs; revisit reproduction")
	require(rejected.RejectedAccessToken != "" && !candidate(rejected), "expired retry admitted rejected token")
	fmt.Println("PASS transient -> 401: same readiness tuple after retry expiry, scheduler still rejects token")
	_, err = manager.Register(ctx, &auth.Auth{ID: "healthy", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "synthetic-independent"}})
	require(err == nil, "register healthy fixture")
	picked, err := (&auth.FillFirstSelector{}).Pick(ctx, "codex", "test-model", executor.Options{}, manager.List())
	require(err == nil && picked.ID == "healthy", "failed credential blocked healthy pool")
	fmt.Println("PASS mixed pool: rejected credential does not block independent healthy route")
	replacement := current()
	replacement.Metadata = map[string]any{"access_token": "synthetic-replacement"}
	replacement.Status = auth.StatusActive
	replacement.Unavailable = false
	replacement.LastError = nil
	replacement.StatusMessage = ""
	replacement.ModelStates = nil
	_, err = manager.Update(ctx, replacement)
	require(err == nil, "replace token")
	require(current().RejectedAccessToken == "" && candidate(current()), "new token did not recover")
	fmt.Println("PASS new token: rejection clears and scheduler permits route")
}
