package ssh

import (
	"strings"
	"testing"
)

func TestParseSettingsSortsAndCanonicalizes(t *testing.T) {
	got, err := ParseSettings(map[string]any{
		"x11forwarding":          "NO",
		"PasswordAuthentication": "no",
		"maxauthtries":           float64(4),
		"LogLevel":               "verbose",
	})
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}

	want := []Setting{
		{Keyword: "LogLevel", Value: "VERBOSE"},
		{Keyword: "MaxAuthTries", Value: "4"},
		{Keyword: "PasswordAuthentication", Value: "no"},
		{Keyword: "X11Forwarding", Value: "no"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d settings, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("setting %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseSettingsRejects(t *testing.T) {
	cases := []struct {
		name     string
		settings map[string]any
		contains string
	}{
		{"empty", map[string]any{}, "at least one keyword"},
		{"unknown keyword", map[string]any{"Protocol": "2"}, "not one this plugin can verify"},
		{"port is not offered", map[string]any{"Port": float64(22)}, "not one this plugin can verify"},
		{"bad enum", map[string]any{"PermitRootLogin": "maybe"}, "is not one of"},
		{"bad bool", map[string]any{"X11Forwarding": "off"}, "is not one of"},
		{"json bool", map[string]any{"X11Forwarding": true}, "got bool"},
		{"int out of range", map[string]any{"MaxAuthTries": float64(99)}, "outside the accepted range"},
		{"fractional int", map[string]any{"MaxAuthTries": 4.5}, "not a whole number"},
		{"non numeric int", map[string]any{"MaxAuthTries": "four"}, "not an integer"},
		{"bool for int", map[string]any{"MaxAuthTries": true}, "got a boolean"},
		{"duplicate spelling", map[string]any{"X11Forwarding": "no", "x11forwarding": "yes"}, "declared twice"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSettings(tc.settings)
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error %q does not contain %q", err, tc.contains)
			}
		})
	}
}

func TestParseSettingsAcceptsIntegerAsString(t *testing.T) {
	got, err := ParseSettings(map[string]any{"MaxAuthTries": "4"})
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	if got[0].Value != "4" {
		t.Fatalf("value = %q, want \"4\"", got[0].Value)
	}
}

func TestRenderIsStable(t *testing.T) {
	settings, err := ParseSettings(map[string]any{
		"X11Forwarding":          "no",
		"PasswordAuthentication": "no",
	})
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}

	want := "# Managed by hardline. Changes here are overwritten.\nPasswordAuthentication no\nX11Forwarding no\n"
	if got := string(Render(settings)); got != want {
		t.Fatalf("Render() = %q, want %q", got, want)
	}
}

func TestKeywordsAreSortedAndCanonical(t *testing.T) {
	list := Keywords()
	if len(list) != len(keywords) {
		t.Fatalf("Keywords() returned %d entries, want %d", len(list), len(keywords))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1] >= list[i] {
			t.Fatalf("Keywords() is not sorted at %d: %q then %q", i, list[i-1], list[i])
		}
	}
	for _, name := range list {
		spec, ok := keywords[strings.ToLower(name)]
		if !ok {
			t.Fatalf("keyword %q is not reachable by its lowercased name", name)
		}
		if spec.canonical != name {
			t.Fatalf("keyword %q maps to canonical %q", name, spec.canonical)
		}
	}
}

func TestParseEffective(t *testing.T) {
	out := "passwordauthentication no\nloglevel VERBOSE\nhostkey /etc/ssh/ssh_host_rsa_key\nhostkey /etc/ssh/ssh_host_ed25519_key\nauthorizedprincipalsfile none\n\npermitlisten\n"
	effective := ParseEffective(out)

	if got := effective["passwordauthentication"]; len(got) != 1 || got[0] != "no" {
		t.Fatalf("passwordauthentication = %v", got)
	}
	if got := effective["hostkey"]; len(got) != 2 {
		t.Fatalf("hostkey = %v, want two values", got)
	}
	if got, ok := effective["permitlisten"]; !ok || len(got) != 1 || got[0] != "" {
		t.Fatalf("valueless keyword = %v (present=%v)", got, ok)
	}
}

func TestDivergentSettings(t *testing.T) {
	want := []Setting{
		{Keyword: "PasswordAuthentication", Value: "no"},
		{Keyword: "LogLevel", Value: "VERBOSE"},
		{Keyword: "X11Forwarding", Value: "no"},
		{Keyword: "MaxSessions", Value: "10"},
	}
	effective := map[string][]string{
		"passwordauthentication": {"yes"},
		"loglevel":               {"verbose"},
		"maxsessions":            {"10", "10"},
	}

	drift := DivergentSettings(effective, want)
	if len(drift) != 3 {
		t.Fatalf("expected 3 divergences, got %d: %v", len(drift), drift)
	}
	joined := strings.Join(drift, "\n")
	for _, fragment := range []string{
		`PasswordAuthentication: effective value is "yes"`,
		"X11Forwarding: sshd does not report this keyword",
		"MaxSessions: sshd reports 2 values",
	} {
		if !strings.Contains(joined, fragment) {
			t.Errorf("drift %q does not contain %q", joined, fragment)
		}
	}
	if strings.Contains(joined, "LogLevel") {
		t.Errorf("LogLevel reported as divergent: %q", joined)
	}
}

func TestDivergentSettingsCleanWhenAligned(t *testing.T) {
	want := []Setting{{Keyword: "PasswordAuthentication", Value: "no"}}
	if drift := DivergentSettings(map[string][]string{"passwordauthentication": {"no"}}, want); len(drift) != 0 {
		t.Fatalf("expected no divergence, got %v", drift)
	}
}
