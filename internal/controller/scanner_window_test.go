/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"testing"
	"time"
)

func TestIsWithinScanWindow_NoWindow(t *testing.T) {
	ok, err := isWithinScanWindow(time.Now(), "", "", "UTC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true when no window is configured")
	}
}

func TestIsWithinScanWindow_InsideWindow(t *testing.T) {
	// 03:00 UTC — inside 02:00–06:00
	now := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	ok, err := isWithinScanWindow(now, "02:00", "06:00", "UTC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true: 03:00 is inside 02:00–06:00")
	}
}

func TestIsWithinScanWindow_OutsideWindow(t *testing.T) {
	// 10:00 UTC — outside 02:00–06:00
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	ok, err := isWithinScanWindow(now, "02:00", "06:00", "UTC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false: 10:00 is outside 02:00–06:00")
	}
}

func TestIsWithinScanWindow_AtWindowStart(t *testing.T) {
	now := time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)
	ok, err := isWithinScanWindow(now, "02:00", "06:00", "UTC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true: 02:00 is exactly the window start (inclusive)")
	}
}

func TestIsWithinScanWindow_AtWindowEnd(t *testing.T) {
	// Window is [start, end) — end is exclusive.
	now := time.Date(2026, 1, 1, 6, 0, 0, 0, time.UTC)
	ok, err := isWithinScanWindow(now, "02:00", "06:00", "UTC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false: 06:00 is exactly the window end (exclusive)")
	}
}

func TestIsWithinScanWindow_OvernightInsideWindow(t *testing.T) {
	// 23:30 UTC — inside 22:00–02:00 overnight window
	now := time.Date(2026, 1, 1, 23, 30, 0, 0, time.UTC)
	ok, err := isWithinScanWindow(now, "22:00", "02:00", "UTC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true: 23:30 is inside overnight window 22:00–02:00")
	}
}

func TestIsWithinScanWindow_OvernightOutsideWindow(t *testing.T) {
	// 10:00 UTC — outside 22:00–02:00 overnight window
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	ok, err := isWithinScanWindow(now, "22:00", "02:00", "UTC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected false: 10:00 is outside overnight window 22:00–02:00")
	}
}

func TestIsWithinScanWindow_WithNonUTCTimezone(t *testing.T) {
	// 03:00 UTC = 23:00 America/New_York (UTC-4 in summer).
	// Window 22:00–04:00 Eastern should contain 23:00 Eastern.
	now := time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC)
	ok, err := isWithinScanWindow(now, "22:00", "04:00", "America/New_York")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected true: 23:00 Eastern is inside overnight window 22:00–04:00 Eastern")
	}
}

func TestIsWithinScanWindow_InvalidTimezone(t *testing.T) {
	_, err := isWithinScanWindow(time.Now(), "02:00", "06:00", "Not/ATimezone")
	if err == nil {
		t.Error("expected error for invalid timezone")
	}
}

func TestIsWithinScanWindow_InvalidStartFormat(t *testing.T) {
	now := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	_, err := isWithinScanWindow(now, "bad", "06:00", "UTC")
	if err == nil {
		t.Error("expected error for invalid start time format")
	}
}

func TestIsWithinScanWindow_InvalidEndFormat(t *testing.T) {
	now := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	_, err := isWithinScanWindow(now, "02:00", "nope", "UTC")
	if err == nil {
		t.Error("expected error for invalid end time format")
	}
}
