package relay

import (
	"testing"
	"time"
)

func TestBucketRefusesPastItsCapacity(t *testing.T) {
	b := newBucket(3, 1, time.Unix(0, 0))
	now := time.Unix(0, 0)
	for i := 0; i < 3; i++ {
		if !b.take(1, now) {
			t.Fatal("capacity")
		}
	}
	if b.take(1, now) {
		t.Fatal("spent bucket allowed another")
	}
	if b.take(1, now.Add(50*time.Millisecond)) {
		t.Fatal("a refill that has not arrived was spent")
	}
	if !b.take(1, now.Add(time.Second)) {
		t.Fatal("a second did not refill one token")
	}
	if !b.take(3, now.Add(time.Hour)) {
		t.Fatal("an idle hour did not refill to capacity")
	}
	if b.take(1, now.Add(time.Hour)) {
		t.Fatal("an idle hour bought more than the capacity")
	}
}

func TestAttemptsForgetTheWindowAndKeepNoList(t *testing.T) {
	a := newAttempts(3, time.Second, 1024, time.Unix(0, 0))
	now := time.Unix(0, 0)
	for i := 0; i < 3; i++ {
		if !a.allow("198.51.100.1", now) {
			t.Fatal("within the window")
		}
	}
	if a.allow("198.51.100.1", now) {
		t.Fatal("over the window")
	}
	if !a.allow("198.51.100.1", now.Add(time.Second)) {
		t.Fatal("the next window did not start clean")
	}

	fresh := newAttempts(1, time.Second, 1024, now)
	allowed := 0
	for i := 0; i < 100; i++ {
		if fresh.allow("198.51.100."+itoa(i), now) {
			allowed++
		}
	}
	if allowed < 85 {
		t.Fatalf("distinct callers allowed %d, want most of them in their own slots", allowed)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
