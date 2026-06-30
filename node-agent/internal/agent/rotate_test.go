package agent

import (
	"testing"
	"time"
)

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	// 90-day cert issued now: renew window is the last 30 days.
	nb, na := now, now.Add(90*24*time.Hour)
	if needsRenewal(nb, na, now) {
		t.Error("a freshly issued cert should not need renewal")
	}
	if needsRenewal(nb, na, now.Add(50*24*time.Hour)) {
		t.Error("at 40 days remaining it should not renew yet")
	}
	if !needsRenewal(nb, na, now.Add(65*24*time.Hour)) {
		t.Error("at 25 days remaining (last third) it should renew")
	}
	if !needsRenewal(nb, na, now.Add(100*24*time.Hour)) {
		t.Error("an expired cert should renew")
	}
	// Degenerate window => renew.
	if !needsRenewal(now, now, now) {
		t.Error("zero-length window should renew")
	}
}
