// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

type scriptedSource struct {
	calls  int
	answer string
	err    error
}

func (s *scriptedSource) UserEnabled(context.Context, string) (string, error) {
	s.calls++
	return s.answer, s.err
}

func TestCachedUserState_RemembersDefiniteAnswersForTTL(t *testing.T) {
	inner := &scriptedSource{answer: KCStateTrue}
	now := time.Unix(1_000, 0)
	c := NewCachedUserState(inner, 5*time.Second)
	c.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if st, _ := c.UserEnabled(context.Background(), "u1"); st != KCStateTrue {
			t.Fatalf("call %d: %s", i, st)
		}
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls within ttl = %d, want 1", inner.calls)
	}
	// Another user is its own entry.
	c.UserEnabled(context.Background(), "u2") //nolint:errcheck
	if inner.calls != 2 {
		t.Fatalf("inner calls after a second user = %d, want 2", inner.calls)
	}
	// After ttl the answer is fetched again, so a disable is seen within ttl.
	now = now.Add(6 * time.Second)
	inner.answer = KCStateFalse
	if st, _ := c.UserEnabled(context.Background(), "u1"); st != KCStateFalse || inner.calls != 3 {
		t.Fatalf("after ttl: state=%s calls=%d, want false and 3", st, inner.calls)
	}
}

func TestCachedUserState_NeverCachesUnknown(t *testing.T) {
	inner := &scriptedSource{answer: KCStateUnknown, err: errors.New("keycloak down")}
	c := NewCachedUserState(inner, time.Minute)
	for i := 0; i < 2; i++ {
		if st, err := c.UserEnabled(context.Background(), "u1"); st != KCStateUnknown || err == nil {
			t.Fatalf("call %d: %s %v", i, st, err)
		}
	}
	if inner.calls != 2 {
		t.Fatalf("unknown must be asked again every time, calls = %d", inner.calls)
	}
	zero := NewCachedUserState(&scriptedSource{answer: KCStateTrue}, 0)
	zero.UserEnabled(context.Background(), "u1") //nolint:errcheck
	zero.UserEnabled(context.Background(), "u1") //nolint:errcheck
	if zero.inner.(*scriptedSource).calls != 2 {
		t.Fatal("ttl 0 must disable caching")
	}
}
