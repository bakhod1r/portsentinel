package config

import "testing"

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("80, 22,20-23")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{20, 21, 22, 23, 80}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	for _, bad := range []string{"0", "70000", "10-5", "abc", ""} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestDefaultValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	c := Default()
	c.Mode = "yolo"
	c.Targets = nil
	if err := c.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}
