package registry

import (
	"testing"
	"time"
)

func reg(home, device string, epoch uint64, token string, at time.Time) PushReg {
	return PushReg{Home: home, DeviceID: device, Epoch: epoch, Token: []byte(token),
		Environment: "sandbox", Kind: "alert", At: at}
}

func TestARegistrationBelongsToARosterEntryAndGoesWithIt(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	if err := r.Claim("h1", []byte("pk"), now); err != nil {
		t.Fatal(err)
	}
	for _, x := range []PushReg{reg("h1", "phone-a", 1, "tok-a", now), reg("h1", "phone-b", 2, "tok-b", now)} {
		if err := r.PushRegister(x); err != nil {
			t.Fatal(err)
		}
	}
	got, err := r.PushRegs("h1", "alert")
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}

	// The roster drops phone-b and moves phone-a's epoch: both go.
	if err := r.PushPrune("h1", func(id string, epoch uint64, _ string) bool { return id == "phone-a" && epoch == 2 }); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.PushRegs("h1", "alert"); len(got) != 0 {
		t.Fatalf("kept %v", got)
	}
}

func TestATokenMovesToTheDeviceThatRegistersIt(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	_ = r.Claim("h1", []byte("pk"), now)
	_ = r.PushRegister(reg("h1", "phone-a", 1, "tok", now))
	_ = r.PushRegister(reg("h1", "phone-a2", 3, "tok", now.Add(time.Minute)))
	got, _ := r.PushRegs("h1", "alert")
	if len(got) != 1 || got[0].DeviceID != "phone-a2" || got[0].Epoch != 3 {
		t.Fatalf("%+v", got)
	}
	if err := r.PushUnregister("h1", "phone-a", []byte("tok")); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.PushRegs("h1", "alert"); len(got) != 1 {
		t.Fatal("another device unregistered a token that is not its own")
	}
	_ = r.PushUnregister("h1", "phone-a2", []byte("tok"))
	if got, _ := r.PushRegs("h1", "alert"); len(got) != 0 {
		t.Fatal("unregister kept the token")
	}
}

func TestAGoneTokenGoesUnlessRegisteredSince(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	_ = r.Claim("h1", []byte("pk"), now)
	_ = r.PushRegister(reg("h1", "phone-a", 1, "tok", now))
	if err := r.PushGone("h1", []byte("tok"), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.PushRegs("h1", "alert"); len(got) != 1 {
		t.Fatal("a token registered after Apple last knew it was dropped")
	}
	_ = r.PushGone("h1", []byte("tok"), now.Add(time.Hour))
	if got, _ := r.PushRegs("h1", "alert"); len(got) != 0 {
		t.Fatal("a gone token was kept")
	}
}

func TestAPurgedOrSilentHomeTakesItsRegistrationsWithIt(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	for _, h := range []string{"h1", "h2", "h3"} {
		_ = r.Claim(h, []byte("pk-"+h), now)
		_ = r.SetRoster(h, 1, []byte("g"), []byte("roster"), now)
		_ = r.PushRegister(reg(h, "phone", 1, "tok-"+h, now))
	}
	if err := r.Purge("h1", []byte("g"), now); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.PushRegs("h1", "alert"); len(got) != 0 {
		t.Fatal("a purged home kept its registrations")
	}
	// h3's box keeps sending its roster; h2's went quiet a month ago.
	later := now.Add(PushKeptWithoutBox + time.Hour)
	_ = r.SetRoster("h3", 2, []byte("g"), []byte("roster"), later)
	n, err := r.PushExpire(later)
	if err != nil || n != 1 {
		t.Fatalf("expired %d, %v", n, err)
	}
	if got, _ := r.PushRegs("h2", "alert"); len(got) != 0 {
		t.Fatal("a home silent for a month kept its registrations")
	}
	if got, _ := r.PushRegs("h3", "alert"); len(got) != 1 {
		t.Fatal("a home whose box is there lost its registrations")
	}
}

func TestARegistrationNeedsAHome(t *testing.T) {
	r := open(t)
	if err := r.PushRegister(reg("nowhere", "phone", 1, "tok", time.Now())); err == nil {
		t.Fatal("registered a token for a home that does not exist")
	}
}
