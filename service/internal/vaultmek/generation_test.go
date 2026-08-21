package vaultmek

import "testing"

func TestNextGeneration(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "apps.privasys.org/ab12/data/cd34/mek/v1", want: "apps.privasys.org/ab12/data/cd34/mek/v2"},
		{in: "apps.privasys.org/ab12/data/cd34/mek/v9", want: "apps.privasys.org/ab12/data/cd34/mek/v10"},
		{in: "apps.privasys.org/ab12/data/cd34/mek/v10", want: "apps.privasys.org/ab12/data/cd34/mek/v11"},
		{in: "apps.privasys.org/ab12/data/cd34/mek", wantErr: true},
		{in: "apps.privasys.org/ab12/data/cd34/mek/vx", wantErr: true},
		{in: "apps.privasys.org/ab12/data/cd34/mek/v0", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, c := range cases {
		got, err := NextGeneration(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NextGeneration(%q): want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NextGeneration(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}
