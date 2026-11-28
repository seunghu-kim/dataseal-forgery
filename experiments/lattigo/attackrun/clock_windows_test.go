package attackrun

import "testing"

func TestClockTickConversion(t *testing.T) {
	for _, x := range []struct{ ticks, hz, ns int64 }{{1, 10000000, 100}, {123456789, 10000000, 12345678900}, {10000001, 10000000, 1000000100}, {3, 3, 1000000000}} {
		if got := ticksNS(x.ticks, x.hz); got != x.ns {
			t.Fatalf("%+v got %d", x, got)
		}
	}
}
