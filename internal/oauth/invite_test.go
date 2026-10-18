package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
)

func TestInvitationRequiresTheOriginalBrowserAndDoesNotApproveByItself(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, ScopeLiveRead)
	code, err := (protocol.AgentInviteCode{V: 1, Home: "abcdefghijklmnopqrstuvwx23", Box: bytes.Repeat([]byte{0x31}, 32), Secret: bytes.Repeat([]byte{0x52}, 32)}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"code": code})
	called := 0
	g.s.ClaimInvite = func(ctx context.Context, m InviteClaim) error {
		called++
		if m.Kid != g.kidOf(f) || !bytes.Equal(m.Key, f.agentKey(t)) {
			t.Fatal("claim did not use this browser's own pending key")
		}
		if _, err := protocol.ParseAgentInviteClaim(m.Payload); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	for _, cookie := range []bool{false, true} {
		r, _ := http.NewRequest(http.MethodPost, g.srv.URL+"/oauth/requests/"+f.rid+"/invite", bytes.NewReader(body))
		r.Header.Set("Origin", Issuer)
		r.Header.Set("Content-Type", "application/json")
		if cookie {
			r.AddCookie(f.cookie)
		}
		resp, err := noFollow.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		want := http.StatusForbidden
		if cookie {
			want = http.StatusAccepted
		}
		if resp.StatusCode != want {
			t.Fatalf("browser=%v status=%d", cookie, resp.StatusCode)
		}
	}
	if called != 1 || g.details(f.rid).Status != statusPending {
		t.Fatal("claim minted approval before a signed roster")
	}
}

func TestApprovalRetriesWhenKeepSucceededButDatabaseSaveFailed(t *testing.T) {
	old := keepRetry
	keepRetry = 20 * time.Millisecond
	t.Cleanup(func() { keepRetry = old })
	g := newRig(t)
	f := g.start(cimdID, cimdBack, ScopeLiveRead)
	_, err := g.s.st.db.Exec(`CREATE TRIGGER fail_approval BEFORE UPDATE OF status ON requests WHEN NEW.status='approved' BEGIN SELECT RAISE(FAIL,'temporary write failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	g.roster(home, agentFor(f.agentKey(t), cimdID, g.now().Add(24*time.Hour), ScopeLiveRead))
	if !g.opens(g.kidOf(f)) || g.details(f.rid).Status != statusPending {
		t.Fatal("fixture did not leave Keep ahead of failed approval")
	}
	if _, err := g.s.st.db.Exec(`DROP TRIGGER fail_approval`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if g.details(f.rid).Status == statusApproved {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("saved roster was not retried after database recovered")
}
