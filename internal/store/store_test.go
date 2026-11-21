package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDomainLifecycle(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, err := st.AddDomain(NewDomain{Name: "foobar123.lu", UName: "foobar123.lu", Suffix: "lu", MonitorEnabled: true, MonitorInterval: 3600, CatchInterval: 60, CatchDuration: 10, CatchRegistrars: []string{"dynadot", "porkbun"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddDomain(NewDomain{Name: "foobar123.lu"}); err != ErrExists {
		t.Fatalf("duplicate: %v", err)
	}
	exp := time.Date(2027, 3, 12, 6, 40, 45, 0, time.UTC)
	info := &Info{Source: "whois", Registrar: "GoDaddy", Expires: exp, Statuses: []string{"Client Hold", "Pending Delete"}, Nameservers: []string{"a.ns", "b.ns"}, PendingDelete: true}
	if err := st.SaveObservation(id, StatusPendingDelete, "whois", "", info); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveObservation(id, "", "", "boom", nil); err != nil {
		t.Fatal(err)
	}
	d, err := st.GetDomain(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != StatusPendingDelete || !d.Expires.Equal(exp) || len(d.Statuses) != 2 || d.ErrorStreak != 1 || d.LastError != "boom" || !d.PendingDelete {
		t.Fatalf("unexpected: %+v", d)
	}
	// auto-catch on pending delete arms the domain even with catch switched off
	d.AutoCatchPD = true
	if !d.Armed(time.Now()) {
		t.Fatal("auto-PD should arm")
	}
	d.AutoCatchPD, d.CatchEnabled = false, true
	d.CatchStart = time.Now().Add(time.Hour)
	if d.Armed(time.Now()) || d.ArmReason(time.Now()) != "window not started" {
		t.Fatalf("window not started: %q", d.ArmReason(time.Now()))
	}
	d.CatchStart, d.CatchEnd = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if !d.Armed(time.Now()) {
		t.Fatal("inside window should arm")
	}
	d.CatchRegistrars = nil
	if d.Armed(time.Now()) {
		t.Fatal("no registrar must not arm")
	}

	if err := st.SaveObservation(id, StatusAvailable, "cloudean", "", nil); err != nil {
		t.Fatal(err)
	}
	d, _ = st.GetDomain(id)
	if d.Status != StatusAvailable || d.PendingDelete || d.ErrorStreak != 0 || d.StatusSource != "cloudean" {
		t.Fatalf("after available: %+v", d)
	}
	st.StartCatch(id, time.Now().Add(10*time.Minute))
	st.IncCatchAttempts(id)
	st.AddOrder(Order{DomainID: id, Registrar: "porkbun", Attempt: 1, Outcome: "unavailable"})
	st.EndCatch(id, CatchLost, "taken", "")
	d, _ = st.GetDomain(id)
	if d.CatchState != CatchLost || d.CatchAttempts != 1 || len(st.ListOrders(id, 10)) != 1 {
		t.Fatalf("catch: %+v", d)
	}
	if err := st.DeleteDomain(id); err != nil {
		t.Fatal(err)
	}
	if len(st.ListOrders(id, 10)) != 0 {
		t.Fatal("orders should be deleted with the domain")
	}
}
