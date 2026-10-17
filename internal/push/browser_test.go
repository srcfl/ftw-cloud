package push

import (
	"context"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
	"testing"
	"time"
)

func TestBrowserOfflineNoticesUseTheExistingTimerWithoutAnAPNsKey(t *testing.T) {
	r := newRig(t)
	r.svc.sender = nil
	calls := 0
	retry := true
	r.svc.BrowserUnreachable = func(context.Context, string) (int, bool) {
		calls++
		if retry {
			return 0, true
		}
		return 1, false
	}
	r.connected()
	r.gone("")
	r.clock.advance(599 * time.Second)
	r.drain()
	if calls != 0 {
		t.Fatal("before grace")
	}
	r.clock.advance(2 * time.Second)
	r.drain()
	if calls != 1 {
		t.Fatal(calls)
	}
	retry = false
	r.clock.advance(10 * time.Second)
	r.drain()
	if calls != 2 {
		t.Fatal("browser retry", calls)
	}
	r.clock.advance(time.Hour)
	r.drain()
	if calls != 2 {
		t.Fatal("duplicate", calls)
	}
	r.connected()
	r.gone(cloudwire.ByeUpdate)
	r.clock.advance(11 * time.Minute)
	r.drain()
	if calls != 2 {
		t.Fatal("ignored update grace")
	}
	r.connected()
	r.clock.advance(time.Hour)
	r.drain()
	if calls != 2 {
		t.Fatal("sent after return")
	}
}

func TestBrowserRetryDoesNotResendAnAcceptedAppleAlert(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "token")
	calls := 0
	r.svc.BrowserUnreachable = func(context.Context, string) (int, bool) { calls++; return 0, calls == 1 }
	r.connected()
	r.gone("")
	r.clock.advance(601 * time.Second)
	r.drain()
	if len(r.apple.notifications()) != 1 || calls != 1 {
		t.Fatal("first delivery")
	}
	r.clock.advance(10 * time.Second)
	r.drain()
	if len(r.apple.notifications()) != 1 || calls != 2 {
		t.Fatal("resending accepted APNs", calls)
	}
}
